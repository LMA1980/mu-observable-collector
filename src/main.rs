use mu_observable_collector::{
    apply_collector_startup_sandbox, build_otlp_router, serve_muob_tcp_listener,
    CollectorIngestState, CollectorSandboxConfig, EdgeRingWal, EdgeSecretScrubber, IngestConfig,
    MtlsForwarder, MtlsForwarderConfig, DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_WAL_BYTES,
    DEFAULT_WAL_MAX_MB,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let node_id = std::env::var("MUOBSERVE_NODE_ID").unwrap_or_else(|_| "worker-node".to_string());
    let default_sandbox = CollectorSandboxConfig::default();
    let arch = default_sandbox.arch.clone();

    let sandbox_cfg = CollectorSandboxConfig {
        node_id: node_id.clone(),
        enforce_landlock_on_linux: std::env::var("MUOBSERVE_ENFORCE_LANDLOCK")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        ..default_sandbox
    };
    let plan = apply_collector_startup_sandbox(&sandbox_cfg)?;
    tracing::info!(
        node_id = %node_id,
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
        let wal = if let Ok(path) = std::env::var("MUOBSERVE_WAL_PATH") {
            EdgeRingWal::open(path, DEFAULT_MAX_WAL_BYTES, DEFAULT_MAX_AGE_SECS)?
        } else {
            EdgeRingWal::in_memory(DEFAULT_MAX_WAL_BYTES, DEFAULT_MAX_AGE_SECS)
        };
        let wal = Arc::new(Mutex::new(wal));

        let upstream_addr_opt = std::env::var("MUOBSERVE_UPSTREAM_ADDR")
            .or_else(|_| std::env::var("MUOBSERVE_UPSTREAM_URL"))
            .ok()
            .map(|raw| {
                let trimmed = raw.trim();
                let stripped = trimmed
                    .strip_prefix("https://")
                    .or_else(|| trimmed.strip_prefix("http://"))
                    .unwrap_or(trimmed);
                stripped.trim_end_matches('/').to_string()
            });

        if let Some(upstream_addr) = upstream_addr_opt {
            let server_name =
                std::env::var("MUOBSERVE_SERVER_NAME").unwrap_or_else(|_| "node-a".to_string());
            let ca_cert_path = std::env::var("MUOBSERVE_TLS_CA")
                .or_else(|_| std::env::var("MUOBSERVE_CA_CERT"))
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/muobserve-collector/tls/ca.crt"));
            let client_cert_path = std::env::var("MUOBSERVE_TLS_CERT")
                .or_else(|_| std::env::var("MUOBSERVE_CLIENT_CERT"))
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/muobserve-collector/tls/client.crt"));
            let client_key_path = std::env::var("MUOBSERVE_TLS_KEY")
                .or_else(|_| std::env::var("MUOBSERVE_CLIENT_KEY"))
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/muobserve-collector/tls/client.key"));

            let fwd_cfg = MtlsForwarderConfig {
                upstream_addr: upstream_addr.clone(),
                server_name,
                ca_cert_path,
                client_cert_path,
                client_key_path,
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
            "MUOBSERVE_SECRET_TOKEN",
        ]);
        let state = CollectorIngestState::new(wal, Arc::new(scrubber), node_id, arch);

        let tail_files_str = std::env::var("MUOBSERVE_LOG_FILES")
            .or_else(|_| std::env::var("MUOBSERVE_TAIL_FILES"))
            .ok();
        if let Some(files_str) = tail_files_str {
            for raw_path in files_str.split(&[',', ';', ' '][..]) {
                let trimmed = raw_path.trim();
                if !trimmed.is_empty() {
                    spawn_log_file_tailer(PathBuf::from(trimmed), state.clone());
                }
            }
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
                tracing::info!("Received shutdown signal; stopping MuObserve-collector");
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
