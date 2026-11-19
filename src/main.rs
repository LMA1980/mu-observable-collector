use mu_observable_collector::{
    apply_collector_startup_sandbox, build_otlp_router, env_var_first_with, resolve_preferred_path,
    serve_muob_tcp_listener, CollectorIngestState, CollectorSandboxConfig, EdgeRingWal,
    EdgeSecretScrubber, IngestConfig, MtlsForwarder, MtlsForwarderConfig,
    DEFAULT_COLLECTOR_CONFIG_DIR, DEFAULT_COLLECTOR_STATE_DIR, DEFAULT_MAX_AGE_SECS,
    DEFAULT_MAX_WAL_BYTES, DEFAULT_WAL_MAX_MB, LEGACY_COLLECTOR_CONFIG_DIR,
    LEGACY_COLLECTOR_STATE_DIR,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const DEFAULT_TLS_CA_PATH: &str = "/etc/mu-observable-collector/tls/ca.crt";
const LEGACY_TLS_CA_PATH: &str = "/etc/muobserve-collector/tls/ca.crt";
const DEFAULT_TLS_CERT_PATH: &str = "/etc/mu-observable-collector/tls/client.crt";
const LEGACY_TLS_CERT_PATH: &str = "/etc/muobserve-collector/tls/client.crt";
const DEFAULT_TLS_KEY_PATH: &str = "/etc/mu-observable-collector/tls/client.key";
const LEGACY_TLS_KEY_PATH: &str = "/etc/muobserve-collector/tls/client.key";

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectorBootstrapConfig {
    node_id: String,
    enforce_landlock: bool,
    state_dir: PathBuf,
    config_dir: PathBuf,
    wal_path: Option<PathBuf>,
    upstream_addr: Option<String>,
    server_name: String,
    ca_cert_path: PathBuf,
    client_cert_path: PathBuf,
    client_key_path: PathBuf,
    log_files: Vec<PathBuf>,
}

impl CollectorBootstrapConfig {
    fn from_env() -> Self {
        Self::resolve_with(
            |k| std::env::var(k).ok(),
            Path::new(DEFAULT_COLLECTOR_STATE_DIR),
            Path::new(LEGACY_COLLECTOR_STATE_DIR),
            Path::new(DEFAULT_COLLECTOR_CONFIG_DIR),
            Path::new(LEGACY_COLLECTOR_CONFIG_DIR),
            Path::new(DEFAULT_TLS_CA_PATH),
            Path::new(LEGACY_TLS_CA_PATH),
            Path::new(DEFAULT_TLS_CERT_PATH),
            Path::new(LEGACY_TLS_CERT_PATH),
            Path::new(DEFAULT_TLS_KEY_PATH),
            Path::new(LEGACY_TLS_KEY_PATH),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_with<F>(
        mut lookup: F,
        default_state_dir: &Path,
        legacy_state_dir: &Path,
        default_config_dir: &Path,
        legacy_config_dir: &Path,
        default_tls_ca: &Path,
        legacy_tls_ca: &Path,
        default_tls_cert: &Path,
        legacy_tls_cert: &Path,
        default_tls_key: &Path,
        legacy_tls_key: &Path,
    ) -> Self
    where
        F: FnMut(&str) -> Option<String>,
    {
        let node_id = env_var_first_with(
            &["MU_OBSERVABLE_COLLECTOR_NODE_ID", "MUOBSERVE_NODE_ID"],
            &mut lookup,
        )
        .unwrap_or_else(|| "worker-node".to_string());

        let enforce_landlock = env_var_first_with(
            &[
                "MU_OBSERVABLE_COLLECTOR_ENFORCE_LANDLOCK",
                "MUOBSERVE_ENFORCE_LANDLOCK",
            ],
            &mut lookup,
        )
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));

        let state_dir = env_var_first_with(
            &["MU_OBSERVABLE_COLLECTOR_STATE_DIR", "MUOBSERVE_STATE_DIR"],
            &mut lookup,
        )
        .map(PathBuf::from)
        .unwrap_or_else(|| resolve_preferred_path(default_state_dir, legacy_state_dir));

        let config_dir = env_var_first_with(
            &["MU_OBSERVABLE_COLLECTOR_CONFIG_DIR", "MUOBSERVE_CONFIG_DIR"],
            &mut lookup,
        )
        .map(PathBuf::from)
        .unwrap_or_else(|| resolve_preferred_path(default_config_dir, legacy_config_dir));

        let wal_path = env_var_first_with(
            &["MU_OBSERVABLE_COLLECTOR_WAL_PATH", "MUOBSERVE_WAL_PATH"],
            &mut lookup,
        )
        .map(PathBuf::from);

        let upstream_addr = env_var_first_with(
            &[
                "MU_OBSERVABLE_COLLECTOR_UPSTREAM_ADDR",
                "MU_OBSERVABLE_COLLECTOR_UPSTREAM_URL",
                "MUOBSERVE_UPSTREAM_ADDR",
                "MUOBSERVE_UPSTREAM_URL",
            ],
            &mut lookup,
        )
        .map(|raw| {
            let trimmed = raw.trim();
            let stripped = trimmed
                .strip_prefix("https://")
                .or_else(|| trimmed.strip_prefix("http://"))
                .unwrap_or(trimmed);
            stripped.trim_end_matches('/').to_string()
        });

        let server_name = env_var_first_with(
            &[
                "MU_OBSERVABLE_COLLECTOR_SERVER_NAME",
                "MUOBSERVE_SERVER_NAME",
            ],
            &mut lookup,
        )
        .unwrap_or_else(|| "node-a".to_string());

        let ca_cert_path = env_var_first_with(
            &[
                "MU_OBSERVABLE_COLLECTOR_TLS_CA",
                "MUOBSERVE_TLS_CA",
                "MUOBSERVE_CA_CERT",
            ],
            &mut lookup,
        )
        .map(PathBuf::from)
        .unwrap_or_else(|| resolve_preferred_path(default_tls_ca, legacy_tls_ca));

        let client_cert_path = env_var_first_with(
            &[
                "MU_OBSERVABLE_COLLECTOR_TLS_CERT",
                "MUOBSERVE_TLS_CERT",
                "MUOBSERVE_CLIENT_CERT",
            ],
            &mut lookup,
        )
        .map(PathBuf::from)
        .unwrap_or_else(|| resolve_preferred_path(default_tls_cert, legacy_tls_cert));

        let client_key_path = env_var_first_with(
            &[
                "MU_OBSERVABLE_COLLECTOR_TLS_KEY",
                "MUOBSERVE_TLS_KEY",
                "MUOBSERVE_CLIENT_KEY",
            ],
            &mut lookup,
        )
        .map(PathBuf::from)
        .unwrap_or_else(|| resolve_preferred_path(default_tls_key, legacy_tls_key));

        let log_files = env_var_first_with(
            &[
                "MU_OBSERVABLE_COLLECTOR_LOG_FILES",
                "MU_OBSERVABLE_COLLECTOR_TAIL_FILES",
                "MUOBSERVE_LOG_FILES",
                "MUOBSERVE_TAIL_FILES",
            ],
            &mut lookup,
        )
        .map(|files_str| {
            files_str
                .split(&[',', ';', ' '][..])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default();

        Self {
            node_id,
            enforce_landlock,
            state_dir,
            config_dir,
            wal_path,
            upstream_addr,
            server_name,
            ca_cert_path,
            client_cert_path,
            client_key_path,
            log_files,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let boot = CollectorBootstrapConfig::from_env();
    let default_sandbox = CollectorSandboxConfig::default();
    let arch = default_sandbox.arch.clone();

    let sandbox_cfg = CollectorSandboxConfig {
        node_id: boot.node_id.clone(),
        state_dir: boot.state_dir.clone(),
        config_dir: boot.config_dir.clone(),
        enforce_landlock_on_linux: boot.enforce_landlock,
        ..default_sandbox
    };
    let plan = apply_collector_startup_sandbox(&sandbox_cfg)?;
    tracing::info!(
        node_id = %boot.node_id,
        arch = %arch,
        landlock_rules = plan.landlock_rules.len(),
        wal_ceiling_mib = DEFAULT_WAL_MAX_MB,
        "mu-observable-collector v{} initialized under MuIsolation KernelSandbox",
        env!("CARGO_PKG_VERSION")
    );

    let has_explicit_subcommand = std::env::args()
        .nth(1)
        .is_some_and(|a| matches!(a.as_str(), "--help" | "-h" | "--version" | "-V"));
    let serve_mode = !has_explicit_subcommand;

    if serve_mode {
        let wal = if let Some(ref path) = boot.wal_path {
            EdgeRingWal::open(path, DEFAULT_MAX_WAL_BYTES, DEFAULT_MAX_AGE_SECS)?
        } else {
            EdgeRingWal::in_memory(DEFAULT_MAX_WAL_BYTES, DEFAULT_MAX_AGE_SECS)
        };
        let wal = Arc::new(Mutex::new(wal));

        if let Some(upstream_addr) = boot.upstream_addr {
            let fwd_cfg = MtlsForwarderConfig {
                upstream_addr: upstream_addr.clone(),
                server_name: boot.server_name,
                ca_cert_path: boot.ca_cert_path,
                client_cert_path: boot.client_cert_path,
                client_key_path: boot.client_key_path,
                initial_backoff_ms: 100,
                max_backoff_ms: 5_000,
                max_retries: 4,
            };
            match MtlsForwarder::new(fwd_cfg, wal.clone()) {
                Ok(forwarder) => {
                    tracing::info!(%upstream_addr, "Spawned step-ca mTLS upstream batch forwarder");
                    tokio::spawn(async move {
                        let mut interval = tokio::time::interval(Duration::from_secs(2));
                        loop {
                            interval.tick().await;
                            if let Err(e) = forwarder.forward_with_backoff().await {
                                tracing::debug!(error = %e, "Upstream WAL flush deferred");
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        %upstream_addr,
                        "Failed to initialize step-ca mTLS upstream batch forwarder"
                    );
                }
            }
        }

        let scrubber = EdgeSecretScrubber::from_env_vars([
            "GITHUB_WEBHOOK_SECRET",
            "GITHUB_TOKEN",
            "MU_OBSERVABLE_COLLECTOR_SECRET_TOKEN",
            "MUOBSERVE_SECRET_TOKEN",
        ]);
        let state = CollectorIngestState::new(wal, Arc::new(scrubber), boot.node_id, arch);

        for log_path in boot.log_files {
            spawn_log_file_tailer(log_path, state.clone());
        }

        let ingest_cfg = IngestConfig::from_env();

        let http_listener = tokio::net::TcpListener::bind(&ingest_cfg.otlp_http_addr).await?;
        let muob_listener = tokio::net::TcpListener::bind(&ingest_cfg.muob_tcp_addr).await?;

        tracing::info!(
            otlp_http_addr = %ingest_cfg.otlp_http_addr,
            "Listening for OTLP/HTTP telemetry"
        );
        tracing::info!(
            muob_tcp_addr = %ingest_cfg.muob_tcp_addr,
            "Listening for native MUOB Arrow IPC telemetry"
        );

        let http_server = axum::serve(http_listener, build_otlp_router(state.clone()));
        let muob_server = serve_muob_tcp_listener(muob_listener, state);

        tokio::select! {
            res = http_server => {
                if let Err(e) = res {
                    tracing::error!(error = %e, "OTLP/HTTP server terminated with error");
                }
            }
            res = muob_server => {
                if let Err(e) = res {
                    tracing::error!(error = %e, "MUOB Arrow IPC TCP server terminated with error");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received shutdown signal; stopping mu-observable-collector");
            }
        }
    }

    Ok(())
}

fn spawn_log_file_tailer(path: PathBuf, state: CollectorIngestState) {
    tokio::spawn(async move {
        use std::io::SeekFrom;
        use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("tail")
            .to_string();
        tracing::info!(path = %path.display(), "Starting background local log tailer");

        let mut offset = 0u64;
        let mut interval = tokio::time::interval(Duration::from_millis(500));

        loop {
            interval.tick().await;

            let file = match tokio::fs::File::open(&path).await {
                Ok(f) => f,
                Err(_) => continue,
            };

            let metadata = match file.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };

            let len = metadata.len();
            if len < offset {
                offset = 0;
            }

            if len == offset {
                continue;
            }

            let mut reader = BufReader::new(file);
            if reader.seek(SeekFrom::Start(offset)).await.is_err() {
                continue;
            }

            let mut entries = Vec::new();
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line).await {
                if n == 0 {
                    break;
                }
                let trimmed = line.trim_end();
                if !trimmed.is_empty() {
                    let now_ns = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as i64)
                        .unwrap_or(0);
                    let (sev_num, sev_txt) =
                        if trimmed.contains("ERROR") || trimmed.contains("FATAL") {
                            (17, "ERROR")
                        } else if trimmed.contains("WARN") {
                            (13, "WARN")
                        } else {
                            (9, "INFO")
                        };
                    entries.push(mu_observable_collector::OtelLogEntry {
                        timestamp_unix_nano: now_ns,
                        trace_id: String::new(),
                        span_id: String::new(),
                        severity_number: sev_num,
                        severity_text: sev_txt.to_string(),
                        service_name: file_name.clone(),
                        node_id: state.default_node_id.clone(),
                        body: trimmed.to_string(),
                        attributes_json: serde_json::json!({
                            "log.file.path": path.to_string_lossy(),
                        })
                        .to_string(),
                        job_id: None,
                        stage_id: None,
                    });
                }
                line.clear();
            }

            if let Ok(new_pos) = reader.seek(SeekFrom::Current(0)).await {
                offset = new_pos;
            }

            if !entries.is_empty() {
                let mut logs = state.normalize_and_dedup_logs(entries);
                if !logs.is_empty() {
                    state.scrubber.scrub_log_batch(&mut logs);
                    let high_sev = logs
                        .iter()
                        .any(mu_observable_collector::is_high_priority_log);
                    let priority = if high_sev {
                        mu_observable_collector::WalSignalPriority::HighCritical
                    } else {
                        mu_observable_collector::WalSignalPriority::LowDebugLog
                    };
                    let flags = if high_sev {
                        mu_observable_collector::FLAG_HIGH_PRIORITY
                    } else {
                        0
                    };
                    if let Ok(encoded) = mu_observable_ipc::encode_log_batch(&logs) {
                        let mut wal = state.wal.lock().await;
                        let _ = wal.append(
                            mu_observable_collector::MSG_TYPE_ARROW_OTEL_LOGS,
                            flags,
                            priority,
                            encoded,
                        );
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::tempdir;

    #[test]
    fn test_collector_bootstrap_env_precedence_and_on_disk_fallback() {
        let dir = tempdir().expect("tempdir");
        let canon_state = dir.path().join("var/lib/mu-observable-collector");
        let legacy_state = dir.path().join("var/lib/muobserve-collector");
        let canon_cfg = dir.path().join("etc/mu-observable-collector");
        let legacy_cfg = dir.path().join("etc/muobserve-collector");
        let canon_ca = canon_cfg.join("tls/ca.crt");
        let legacy_ca = legacy_cfg.join("tls/ca.crt");
        let canon_cert = canon_cfg.join("tls/client.crt");
        let legacy_cert = legacy_cfg.join("tls/client.crt");
        let canon_key = canon_cfg.join("tls/client.key");
        let legacy_key = legacy_cfg.join("tls/client.key");

        // 1. Neither canonical nor legacy exists -> canonical paths preferred
        let empty: HashMap<&str, &str> = HashMap::new();
        let cfg_default = CollectorBootstrapConfig::resolve_with(
            |k| empty.get(k).map(|v| (*v).to_string()),
            &canon_state,
            &legacy_state,
            &canon_cfg,
            &legacy_cfg,
            &canon_ca,
            &legacy_ca,
            &canon_cert,
            &legacy_cert,
            &canon_key,
            &legacy_key,
        );
        assert_eq!(cfg_default.state_dir, canon_state);
        assert_eq!(cfg_default.config_dir, canon_cfg);
        assert_eq!(cfg_default.ca_cert_path, canon_ca);
        assert_eq!(cfg_default.client_cert_path, canon_cert);
        assert_eq!(cfg_default.client_key_path, canon_key);

        // 2. Only legacy files/dirs exist -> falls back to legacy on disk
        std::fs::create_dir_all(&legacy_state).unwrap();
        std::fs::create_dir_all(legacy_ca.parent().unwrap()).unwrap();
        std::fs::write(&legacy_ca, "ca").unwrap();
        std::fs::write(&legacy_cert, "cert").unwrap();
        std::fs::write(&legacy_key, "key").unwrap();

        let cfg_legacy_disk = CollectorBootstrapConfig::resolve_with(
            |k| empty.get(k).map(|v| (*v).to_string()),
            &canon_state,
            &legacy_state,
            &canon_cfg,
            &legacy_cfg,
            &canon_ca,
            &legacy_ca,
            &canon_cert,
            &legacy_cert,
            &canon_key,
            &legacy_key,
        );
        assert_eq!(cfg_legacy_disk.state_dir, legacy_state);
        assert_eq!(cfg_legacy_disk.config_dir, legacy_cfg);
        assert_eq!(cfg_legacy_disk.ca_cert_path, legacy_ca);
        assert_eq!(cfg_legacy_disk.client_cert_path, legacy_cert);
        assert_eq!(cfg_legacy_disk.client_key_path, legacy_key);

        // 3. Legacy env vars work when canonical env vars are unset
        let legacy_env: HashMap<&str, &str> = HashMap::from([
            ("MUOBSERVE_NODE_ID", "legacy-worker"),
            ("MUOBSERVE_WAL_PATH", "/tmp/legacy.duckdb"),
            (
                "MUOBSERVE_UPSTREAM_URL",
                "https://hub.cluster.internal:9443/",
            ),
            ("MUOBSERVE_SERVER_NAME", "legacy-node"),
            ("MUOBSERVE_CA_CERT", "/legacy/ca.crt"),
            ("MUOBSERVE_CLIENT_CERT", "/legacy/client.crt"),
            ("MUOBSERVE_CLIENT_KEY", "/legacy/client.key"),
            ("MUOBSERVE_LOG_FILES", "/var/log/a.log,/var/log/b.log"),
            ("MUOBSERVE_ENFORCE_LANDLOCK", "true"),
        ]);
        let cfg_legacy_env = CollectorBootstrapConfig::resolve_with(
            |k| legacy_env.get(k).map(|v| (*v).to_string()),
            &canon_state,
            &legacy_state,
            &canon_cfg,
            &legacy_cfg,
            &canon_ca,
            &legacy_ca,
            &canon_cert,
            &legacy_cert,
            &canon_key,
            &legacy_key,
        );
        assert_eq!(cfg_legacy_env.node_id, "legacy-worker");
        assert_eq!(
            cfg_legacy_env.wal_path,
            Some(PathBuf::from("/tmp/legacy.duckdb"))
        );
        assert_eq!(
            cfg_legacy_env.upstream_addr.as_deref(),
            Some("hub.cluster.internal:9443")
        );
        assert_eq!(cfg_legacy_env.server_name, "legacy-node");
        assert_eq!(cfg_legacy_env.ca_cert_path, PathBuf::from("/legacy/ca.crt"));
        assert_eq!(
            cfg_legacy_env.client_cert_path,
            PathBuf::from("/legacy/client.crt")
        );
        assert_eq!(
            cfg_legacy_env.client_key_path,
            PathBuf::from("/legacy/client.key")
        );
        assert_eq!(
            cfg_legacy_env.log_files,
            vec![
                PathBuf::from("/var/log/a.log"),
                PathBuf::from("/var/log/b.log")
            ]
        );
        assert!(cfg_legacy_env.enforce_landlock);

        // 4. MU_OBSERVABLE_COLLECTOR_* overrides MUOBSERVE_* everywhere
        let canon_env: HashMap<&str, &str> = HashMap::from([
            ("MU_OBSERVABLE_COLLECTOR_NODE_ID", "worker-riscv64"),
            ("MUOBSERVE_NODE_ID", "legacy-worker"),
            ("MU_OBSERVABLE_COLLECTOR_WAL_PATH", "/tmp/canon.duckdb"),
            ("MUOBSERVE_WAL_PATH", "/tmp/legacy.duckdb"),
            (
                "MU_OBSERVABLE_COLLECTOR_UPSTREAM_ADDR",
                "hub-canon.cluster.internal:9443",
            ),
            (
                "MUOBSERVE_UPSTREAM_ADDR",
                "hub-legacy.cluster.internal:9443",
            ),
            ("MU_OBSERVABLE_COLLECTOR_SERVER_NAME", "node-b"),
            ("MUOBSERVE_SERVER_NAME", "legacy-node"),
            ("MU_OBSERVABLE_COLLECTOR_TLS_CA", "/canon/ca.crt"),
            ("MUOBSERVE_TLS_CA", "/legacy/ca.crt"),
            ("MU_OBSERVABLE_COLLECTOR_TLS_CERT", "/canon/client.crt"),
            ("MUOBSERVE_TLS_CERT", "/legacy/client.crt"),
            ("MU_OBSERVABLE_COLLECTOR_TLS_KEY", "/canon/client.key"),
            ("MUOBSERVE_TLS_KEY", "/legacy/client.key"),
            ("MU_OBSERVABLE_COLLECTOR_LOG_FILES", "/var/log/canon.log"),
            ("MUOBSERVE_LOG_FILES", "/var/log/legacy.log"),
            ("MU_OBSERVABLE_COLLECTOR_ENFORCE_LANDLOCK", "false"),
            ("MUOBSERVE_ENFORCE_LANDLOCK", "true"),
        ]);
        let cfg_canon_env = CollectorBootstrapConfig::resolve_with(
            |k| canon_env.get(k).map(|v| (*v).to_string()),
            &canon_state,
            &legacy_state,
            &canon_cfg,
            &legacy_cfg,
            &canon_ca,
            &legacy_ca,
            &canon_cert,
            &legacy_cert,
            &canon_key,
            &legacy_key,
        );
        assert_eq!(cfg_canon_env.node_id, "worker-riscv64");
        assert_eq!(
            cfg_canon_env.wal_path,
            Some(PathBuf::from("/tmp/canon.duckdb"))
        );
        assert_eq!(
            cfg_canon_env.upstream_addr.as_deref(),
            Some("hub-canon.cluster.internal:9443")
        );
        assert_eq!(cfg_canon_env.server_name, "node-b");
        assert_eq!(cfg_canon_env.ca_cert_path, PathBuf::from("/canon/ca.crt"));
        assert_eq!(
            cfg_canon_env.client_cert_path,
            PathBuf::from("/canon/client.crt")
        );
        assert_eq!(
            cfg_canon_env.client_key_path,
            PathBuf::from("/canon/client.key")
        );
        assert_eq!(
            cfg_canon_env.log_files,
            vec![PathBuf::from("/var/log/canon.log")]
        );
        assert!(!cfg_canon_env.enforce_landlock);
    }
}
