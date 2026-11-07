//! `step-ca` mTLS batch forwarder and `MuIsolation` `KernelSandbox` startup confinement (`M3.030`).

use crate::error::CollectorError;
use crate::wal::EdgeRingWal;
use mu_ci_isolation::{
    EffectiveSandboxPolicy, IsolationBackend, KernelSandbox, LandlockRuleBuilder,
    NetworkEgressMode, SandboxBackendKind, SandboxExecutionPlan,
};
use mu_observable_ipc::{
    create_fory_registry, decode_control_envelope, read_frame, write_frame, ControlRpcEnvelope,
    IpcHeader, WalBatchAck, MSG_TYPE_FORY_CONTROL, MSG_TYPE_WAL_ACK,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use std::ffi::OsString;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

/// Canonical state directory allowlisted for read-write access by `MuObserve-collector`.
pub const DEFAULT_COLLECTOR_STATE_DIR: &str = "/var/lib/muobserve-collector";

/// Canonical configuration directory allowlisted for read-only access by `MuObserve-collector`.
pub const DEFAULT_COLLECTOR_CONFIG_DIR: &str = "/etc/muobserve-collector";

/// Startup confinement configuration for `MuObserve-collector` backed by `MuIsolation` [`KernelSandbox`].
#[derive(Debug, Clone)]
pub struct CollectorSandboxConfig {
    pub node_id: String,
    pub arch: String,
    pub state_dir: PathBuf,
    pub config_dir: PathBuf,
    pub memlock_limit_kb: u64,
    pub max_pids: u32,
    pub max_memory_mb: u64,
    pub max_cpu_cores: u32,
    pub enforce_landlock_on_linux: bool,
}

impl Default for CollectorSandboxConfig {
    fn default() -> Self {
        let host_arch = std::env::consts::ARCH;
        let arch = if matches!(host_arch, "x86_64" | "riscv64" | "riscv64gc") {
            host_arch.to_string()
        } else {
            "riscv64gc".to_string()
        };
        Self {
            node_id: "worker-riscv64".to_string(),
            arch,
            state_dir: PathBuf::from(DEFAULT_COLLECTOR_STATE_DIR),
            config_dir: PathBuf::from(DEFAULT_COLLECTOR_CONFIG_DIR),
            memlock_limit_kb: 65_536, // 64 MiB bounded memlock ceiling
            max_pids: 64,
            max_memory_mb: 512,
            max_cpu_cores: 2,
            enforce_landlock_on_linux: false,
        }
    }
}

/// Builds the [`EffectiveSandboxPolicy`] for `MuObserve-collector` allowlisting
/// `/var/lib/muobserve-collector` (read/write) and `/etc/muobserve-collector` (read-only)
/// along with bounded cgroupv2 and `RLIMIT_MEMLOCK` ceilings.
#[must_use]
pub fn build_collector_sandbox_policy(cfg: &CollectorSandboxConfig) -> EffectiveSandboxPolicy {
    EffectiveSandboxPolicy {
        node_id: cfg.node_id.clone(),
        arch: cfg.arch.clone(),
        backend: SandboxBackendKind::Kernel,
        read_paths: vec![
            cfg.config_dir.clone(),
            cfg.state_dir.clone(),
            PathBuf::from("/usr"),
            PathBuf::from("/lib"),
        ],
        write_paths: vec![cfg.state_dir.clone()],
        exec_paths: vec![PathBuf::from("/usr/local/bin"), PathBuf::from("/usr/bin")],
        network_mode: NetworkEgressMode::RestrictedCidrs(vec!["192.0.2.0/24".to_string()]),
        memlock_limit_kb: cfg.memlock_limit_kb,
        max_pids: cfg.max_pids,
        max_memory_mb: cfg.max_memory_mb,
        max_cpu_cores: cfg.max_cpu_cores,
        cpu_affinity_mask: Some(0x00FF),
        require_set_ai_thread: false,
    }
}

/// Validates and lowers the `MuIsolation` [`KernelSandbox`] startup confinement plan
/// (Landlock V3+ ruleset allowlisting `/var/lib/muobserve-collector` and `/etc/muobserve-collector`
/// + cgroupv2 resource ceilings + seccomp-BPF plan).
pub fn apply_collector_startup_sandbox(
    cfg: &CollectorSandboxConfig,
) -> Result<SandboxExecutionPlan, CollectorError> {
    let policy = build_collector_sandbox_policy(cfg);
    let sandbox = KernelSandbox::new();
    let argv = vec![OsString::from("/usr/local/bin/mu-observable-collector")];
    let plan = sandbox.build_execution_plan(&policy, &argv)?;

    if cfg.enforce_landlock_on_linux {
        LandlockRuleBuilder::apply_rules(&plan.landlock_rules)?;
    } else {
        // Validate rule normalization invariants without mutating the test runner process
        #[cfg(not(target_os = "linux"))]
        LandlockRuleBuilder::apply_rules(&plan.landlock_rules)?;
    }

    Ok(plan)
}

/// Configuration for the `step-ca` mutual TLS upstream batch forwarder.
#[derive(Debug, Clone)]
pub struct MtlsForwarderConfig {
    pub upstream_addr: String,
    pub server_name: String,
    pub ca_cert_path: PathBuf,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub max_retries: u32,
}

impl Default for MtlsForwarderConfig {
    fn default() -> Self {
        Self {
            upstream_addr: "127.0.0.1:9443".to_string(),
            server_name: "node-a".to_string(),
            ca_cert_path: PathBuf::from("/etc/muobserve-collector/ca.crt"),
            client_cert_path: PathBuf::from("/etc/muobserve-collector/client.crt"),
            client_key_path: PathBuf::from("/etc/muobserve-collector/client.key"),
            initial_backoff_ms: 50,
            max_backoff_ms: 2_000,
            max_retries: 4,
        }
    }
}

/// Builds a [`rustls::ClientConfig`] configured with the `step-ca` root CA certificate
/// and the node's client certificate + private key for mutual TLS authentication.
pub fn build_tls_client_config(
    ca_cert_path: impl AsRef<Path>,
    client_cert_path: impl AsRef<Path>,
    client_key_path: impl AsRef<Path>,
) -> Result<rustls::ClientConfig, CollectorError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca_file = File::open(ca_cert_path.as_ref())?;
    let mut ca_reader = BufReader::new(ca_file);
    let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CollectorError::Tls(format!("Failed to parse CA cert PEM: {e}")))?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert).map_err(|e| {
            CollectorError::Tls(format!("Failed to add CA cert to root store: {e}"))
        })?;
    }

    let cert_file = File::open(client_cert_path.as_ref())?;
    let mut cert_reader = BufReader::new(cert_file);
    let client_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CollectorError::Tls(format!("Failed to parse client cert PEM: {e}")))?;

    let key_file = File::open(client_key_path.as_ref())?;
    let mut key_reader = BufReader::new(key_file);
    let client_key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(&mut key_reader)
        .map_err(|e| CollectorError::Tls(format!("Failed to parse client private key PEM: {e}")))?;

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|e| CollectorError::Tls(format!("Failed to configure mTLS client auth: {e}")))?;

    Ok(client_config)
}

/// Builds a [`rustls::ServerConfig`] enforcing mutual TLS client certificate verification
/// against `ca_cert_path`.
pub fn build_tls_server_config(
    ca_cert_path: impl AsRef<Path>,
    server_cert_path: impl AsRef<Path>,
    server_key_path: impl AsRef<Path>,
) -> Result<rustls::ServerConfig, CollectorError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca_file = File::open(ca_cert_path.as_ref())?;
    let mut ca_reader = BufReader::new(ca_file);
    let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CollectorError::Tls(format!("Failed to parse CA cert PEM: {e}")))?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert).map_err(|e| {
            CollectorError::Tls(format!("Failed to add CA cert to root store: {e}"))
        })?;
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| CollectorError::Tls(format!("Failed to build mTLS client verifier: {e}")))?;

    let srv_file = File::open(server_cert_path.as_ref())?;
    let mut srv_reader = BufReader::new(srv_file);
    let srv_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut srv_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CollectorError::Tls(format!("Failed to parse server cert PEM: {e}")))?;

    let key_file = File::open(server_key_path.as_ref())?;
    let mut key_reader = BufReader::new(key_file);
    let srv_key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(&mut key_reader)
        .map_err(|e| CollectorError::Tls(format!("Failed to parse server private key PEM: {e}")))?;

    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(srv_certs, srv_key)
        .map_err(|e| CollectorError::Tls(format!("Failed to configure mTLS server cert: {e}")))?;

    Ok(server_config)
}

/// Streams unacknowledged batches from [`EdgeRingWal`] over `tokio-rustls` mutual TLS to `MuObserve`,
/// truncating acknowledged batches upon receiving [`WalBatchAck`].
pub struct MtlsForwarder {
    config: MtlsForwarderConfig,
    wal: Arc<Mutex<EdgeRingWal>>,
    tls_connector: TlsConnector,
}

impl MtlsForwarder {
    /// Creates a new [`MtlsForwarder`] loading client mTLS credentials from `config`.
    pub fn new(
        config: MtlsForwarderConfig,
        wal: Arc<Mutex<EdgeRingWal>>,
    ) -> Result<Self, CollectorError> {
        let client_cfg = build_tls_client_config(
            &config.ca_cert_path,
            &config.client_cert_path,
            &config.client_key_path,
        )?;
        Ok(Self {
            config,
            wal,
            tls_connector: TlsConnector::from(Arc::new(client_cfg)),
        })
    }

    /// Returns a reference to the forwarder configuration.
    #[must_use]
    pub const fn config(&self) -> &MtlsForwarderConfig {
        &self.config
    }

    /// Streams all currently pending WAL batches over an established bidirectional stream,
    /// reading a [`WalBatchAck`] for each batch and truncating acknowledged entries from the WAL.
    pub async fn forward_over_stream<S>(&self, stream: &mut S) -> Result<usize, CollectorError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let pending = {
            let wal = self.wal.lock().await;
            wal.pending_batches()
        };

        if pending.is_empty() {
            return Ok(0);
        }

        let fory = create_fory_registry()?;
        let mut acked_count = 0usize;

        for batch in pending {
            let payload_len = u32::try_from(batch.payload.len()).map_err(|_| {
                CollectorError::InvalidPayload("Batch payload exceeds u32::MAX".to_string())
            })?;
            let header = IpcHeader::new(batch.msg_type, payload_len, batch.flags, batch.seq_no);
            write_frame(stream, &header, &batch.payload).await?;

            let (ack_hdr, ack_payload) = read_frame(stream).await?;
            let ack = decode_wal_ack_frame(&fory, ack_hdr.msg_type, &ack_payload)?;

            if !ack.ok {
                return Err(CollectorError::UpstreamRejected(
                    ack.error_message
                        .unwrap_or_else(|| format!("Upstream rejected batch seq {}", batch.seq_no)),
                ));
            }

            let target_seq = if ack.sequence == 0 {
                batch.seq_no
            } else {
                ack.sequence
            };

            let mut wal = self.wal.lock().await;
            wal.acknowledge_and_truncate(target_seq)?;
            acked_count += 1;
        }

        Ok(acked_count)
    }

    /// Connects once over `tokio-rustls` mTLS to `upstream_addr` and drains all pending WAL batches.
    pub async fn forward_pending_once(&self) -> Result<usize, CollectorError> {
        let has_pending = {
            let wal = self.wal.lock().await;
            !wal.pending_batches().is_empty()
        };
        if !has_pending {
            return Ok(0);
        }

        let tcp = TcpStream::connect(&self.config.upstream_addr).await?;
        let server_name = ServerName::try_from(self.config.server_name.clone())
            .map_err(|e| CollectorError::Tls(format!("Invalid TLS server name: {e}")))?;
        let mut tls_stream = self
            .tls_connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| CollectorError::Tls(format!("mTLS handshake failed: {e}")))?;

        self.forward_over_stream(&mut tls_stream).await
    }

    /// Drains all pending WAL batches over mTLS, retrying transient connection or I/O errors
    /// with exponential backoff (`initial_backoff_ms * 2^attempt`, capped at `max_backoff_ms`).
    pub async fn forward_with_backoff(&self) -> Result<usize, CollectorError> {
        let mut attempt = 0u32;
        let mut backoff_ms = self.config.initial_backoff_ms.max(1);

        loop {
            match self.forward_pending_once().await {
                Ok(acked) => return Ok(acked),
                Err(err) => {
                    if attempt >= self.config.max_retries {
                        return Err(err);
                    }
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms.saturating_mul(2)).min(self.config.max_backoff_ms);
                }
            }
        }
    }
}

/// Decodes a [`WalBatchAck`] from either a direct `MSG_TYPE_WAL_ACK` Fory payload,
/// a `MSG_TYPE_FORY_CONTROL` [`ControlRpcEnvelope::WalAck`] payload, or JSON fallback.
pub fn decode_wal_ack_frame(
    fory: &fory::Fory,
    msg_type: u16,
    payload: &[u8],
) -> Result<WalBatchAck, CollectorError> {
    if msg_type != MSG_TYPE_WAL_ACK && msg_type != MSG_TYPE_FORY_CONTROL {
        return Err(CollectorError::InvalidPayload(format!(
            "Expected MSG_TYPE_WAL_ACK or MSG_TYPE_FORY_CONTROL, got {msg_type:#06x}"
        )));
    }

    if let Ok(ack) = fory.deserialize::<WalBatchAck>(payload) {
        return Ok(ack);
    }

    if let Ok(ControlRpcEnvelope::WalAck(ack)) = decode_control_envelope(payload) {
        return Ok(ack);
    }

    if let Ok(ack) = serde_json::from_slice::<WalBatchAck>(payload) {
        return Ok(ack);
    }

    Err(CollectorError::InvalidPayload(
        "Failed to decode WalBatchAck from upstream frame".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::WalSignalPriority;
    use mu_ci_isolation::{EXEC_ACCESS, READ_ACCESS, WRITE_ACCESS};
    use mu_observable_ipc::{
        decode_log_batch, encode_log_batch, OtelLogEntry, FLAG_HIGH_PRIORITY,
        MSG_TYPE_ARROW_OTEL_LOGS,
    };
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    use std::fs;
    use tempfile::tempdir;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    struct EphemeralMtlsPki {
        ca_path: PathBuf,
        server_cert_path: PathBuf,
        server_key_path: PathBuf,
        client_cert_path: PathBuf,
        client_key_path: PathBuf,
    }

    fn generate_ephemeral_mtls_pki(dir: &Path) -> EphemeralMtlsPki {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(vec!["step-ca.internal".to_string()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "MuObserve Test Step-CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-signed");
        let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

        let srv_key = KeyPair::generate().expect("server key");
        let srv_params =
            CertificateParams::new(vec!["node-a".to_string(), "localhost".to_string()]).unwrap();
        let srv_cert = srv_params
            .signed_by(&srv_key, &ca_issuer)
            .expect("server cert signed by CA");

        let cli_key = KeyPair::generate().expect("client key");
        let cli_params = CertificateParams::new(vec!["worker-riscv64".to_string()]).unwrap();
        let cli_cert = cli_params
            .signed_by(&cli_key, &ca_issuer)
            .expect("client cert signed by CA");

        let ca_path = dir.join("ca.crt");
        let server_cert_path = dir.join("server.crt");
        let server_key_path = dir.join("server.key");
        let client_cert_path = dir.join("client.crt");
        let client_key_path = dir.join("client.key");

        fs::write(&ca_path, ca_cert.pem()).unwrap();
        fs::write(&server_cert_path, srv_cert.pem()).unwrap();
        fs::write(&server_key_path, srv_key.serialize_pem()).unwrap();
        fs::write(&client_cert_path, cli_cert.pem()).unwrap();
        fs::write(&client_key_path, cli_key.serialize_pem()).unwrap();

        EphemeralMtlsPki {
            ca_path,
            server_cert_path,
            server_key_path,
            client_cert_path,
            client_key_path,
        }
    }

    #[test]
    fn test_muisolation_kernel_sandbox_startup_confinement_rules() {
        let cfg = CollectorSandboxConfig {
            node_id: "worker-riscv64".to_string(),
            arch: "riscv64gc".to_string(),
            ..Default::default()
        };
        let plan = apply_collector_startup_sandbox(&cfg).expect("build collector sandbox plan");
        assert_eq!(plan.backend, SandboxBackendKind::Kernel);
        assert_eq!(plan.memlock_bytes, 65_536 * 1024);

        let etc_rule = plan
            .landlock_rules
            .iter()
            .find(|r| r.path == Path::new("/etc/muobserve-collector"))
            .expect("/etc/muobserve-collector Landlock rule");
        assert_eq!(etc_rule.access_mask, READ_ACCESS);

        let var_rule = plan
            .landlock_rules
            .iter()
            .find(|r| r.path == Path::new("/var/lib/muobserve-collector"))
            .expect("/var/lib/muobserve-collector Landlock rule");
        assert_eq!(var_rule.access_mask, READ_ACCESS | WRITE_ACCESS);

        let bin_rule = plan
            .landlock_rules
            .iter()
            .find(|r| r.path == Path::new("/usr/local/bin"))
            .expect("/usr/local/bin Landlock rule");
        assert_eq!(bin_rule.access_mask, EXEC_ACCESS);
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn test_mtls_forwarder_drains_wal_and_truncates_on_ack_with_backoff() {
        let dir = tempdir().expect("tempdir");
        let pki = generate_ephemeral_mtls_pki(dir.path());

        let wal_path = dir.path().join("wal.duckdb");
        let mut wal = EdgeRingWal::open(&wal_path, 1024 * 1024, 3600).expect("open wal");

        let sample_log = OtelLogEntry {
            timestamp_unix_nano: 1_700_000_000_000_000_000,
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            span_id: "00f067aa0ba902b7".to_string(),
            severity_number: 17,
            severity_text: "ERROR".to_string(),
            service_name: "action-runner-worker".to_string(),
            node_id: "worker-riscv64".to_string(),
            body: "build failed on stage clippy-check".to_string(),
            attributes_json: r#"{"stage":"clippy-check"}"#.to_string(),
            job_id: Some("job-500".to_string()),
            stage_id: Some("clippy-check".to_string()),
        };
        let encoded_batch = encode_log_batch(std::slice::from_ref(&sample_log)).unwrap();

        wal.append(
            MSG_TYPE_ARROW_OTEL_LOGS,
            FLAG_HIGH_PRIORITY,
            WalSignalPriority::HighCritical,
            encoded_batch.clone(),
        )
        .unwrap();
        wal.append(
            MSG_TYPE_ARROW_OTEL_LOGS,
            FLAG_HIGH_PRIORITY,
            WalSignalPriority::HighCritical,
            encoded_batch,
        )
        .unwrap();
        assert_eq!(wal.pending_batches().len(), 2);

        let wal = Arc::new(Mutex::new(wal));

        // Bind a local TCP port to reserve an ephemeral port, then delay accepting or spawn mTLS server
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();

        let server_tls_cfg =
            build_tls_server_config(&pki.ca_path, &pki.server_cert_path, &pki.server_key_path)
                .expect("server tls config");
        let acceptor = TlsAcceptor::from(Arc::new(server_tls_cfg));

        let server_task = tokio::spawn(async move {
            let (tcp, _peer) = listener.accept().await.expect("accept");
            let mut tls = acceptor.accept(tcp).await.expect("tls accept");

            // Verify client certificate was presented and verified by WebPkiClientVerifier
            let (_, conn) = tls.get_ref();
            let peer_certs = conn
                .peer_certificates()
                .expect("client must present mTLS cert");
            assert!(!peer_certs.is_empty());

            let fory = create_fory_registry().unwrap();
            let mut received_seqs = Vec::new();

            for expected_seq in 1..=2u64 {
                let (hdr, payload) = read_frame(&mut tls).await.expect("read frame");
                assert_eq!(hdr.msg_type, MSG_TYPE_ARROW_OTEL_LOGS);
                assert_eq!(hdr.sequence, expected_seq);
                let logs = decode_log_batch(&payload).expect("decode logs");
                assert_eq!(logs.len(), 1);
                assert_eq!(logs[0].job_id.as_deref(), Some("job-500"));
                received_seqs.push(hdr.sequence);

                let ack = WalBatchAck {
                    sequence: hdr.sequence,
                    accepted_rows: 1,
                    ok: true,
                    error_message: None,
                };
                let ack_bytes = fory.serialize(&ack).unwrap();
                let ack_hdr = IpcHeader::new(
                    MSG_TYPE_WAL_ACK,
                    u32::try_from(ack_bytes.len()).unwrap(),
                    0,
                    hdr.sequence,
                );
                write_frame(&mut tls, &ack_hdr, &ack_bytes)
                    .await
                    .expect("write ack");
            }
            received_seqs
        });

        let fwd_cfg = MtlsForwarderConfig {
            upstream_addr: addr.to_string(),
            server_name: "node-a".to_string(),
            ca_cert_path: pki.ca_path,
            client_cert_path: pki.client_cert_path,
            client_key_path: pki.client_key_path,
            initial_backoff_ms: 20,
            max_backoff_ms: 200,
            max_retries: 3,
        };
        let forwarder = MtlsForwarder::new(fwd_cfg, wal.clone()).expect("create forwarder");

        let acked = forwarder
            .forward_with_backoff()
            .await
            .expect("forward with backoff");
        assert_eq!(acked, 2);

        let received_seqs = server_task.await.expect("server join");
        assert_eq!(received_seqs, vec![1, 2]);

        // Verify WAL was completely drained and truncated after receiving ACKs!
        let wal_guard = wal.lock().await;
        assert!(wal_guard.pending_batches().is_empty());
        assert_eq!(wal_guard.used_bytes(), 0);
        assert_eq!(wal_guard.evicted_acked_count(), 2);
    }
}
