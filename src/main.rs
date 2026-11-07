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

    let serve_mode = std::env::args().any(|a| a == "serve" || a == "--serve")
        || std::env::var("MUOBSERVE_COLLECTOR_SERVE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    if serve_mode {
        let wal = if let Ok(path) = std::env::var("MUOBSERVE_WAL_PATH") {
            EdgeRingWal::open(path, DEFAULT_MAX_WAL_BYTES, DEFAULT_MAX_AGE_SECS)?
        } else {
            EdgeRingWal::in_memory(DEFAULT_MAX_WAL_BYTES, DEFAULT_MAX_AGE_SECS)
        };
        let wal = Arc::new(Mutex::new(wal));

        if let Ok(upstream_addr) = std::env::var("MUOBSERVE_UPSTREAM_ADDR") {
            let server_name =
                std::env::var("MUOBSERVE_SERVER_NAME").unwrap_or_else(|_| "node-a".to_string());
            let ca_cert_path = std::env::var("MUOBSERVE_CA_CERT")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/muobserve-collector/tls/ca.crt"));
            let client_cert_path = std::env::var("MUOBSERVE_CLIENT_CERT")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/muobserve-collector/tls/client.crt"));
            let client_key_path = std::env::var("MUOBSERVE_CLIENT_KEY")
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
            if let Ok(forwarder) = MtlsForwarder::new(fwd_cfg, wal.clone()) {
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
        }

        let scrubber = EdgeSecretScrubber::from_env_vars([
            "GITHUB_WEBHOOK_SECRET",
            "GITHUB_TOKEN",
            "MUOBSERVE_SECRET_TOKEN",
        ]);
        let state = CollectorIngestState::new(wal, Arc::new(scrubber), node_id, arch);
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
