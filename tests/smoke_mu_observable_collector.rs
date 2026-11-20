#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mu_observable_collector::{
    apply_collector_startup_sandbox, build_otlp_router, CollectorIngestState,
    CollectorSandboxConfig, EdgeRingWal, EdgeSecretScrubber, OtlpIngestResponse,
    DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_WAL_BYTES,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

const DEFAULT_SMOKE_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone)]
struct SmokeConfig {
    target_url: Option<String>,
    tls_ca_file: Option<PathBuf>,
    tls_cert_file: Option<PathBuf>,
    tls_key_file: Option<PathBuf>,
    server_name: Option<String>,
    bearer_token: Option<String>,
    timeout: Duration,
}

impl SmokeConfig {
    fn from_env() -> Result<Self, String> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup<F>(lookup: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let tls_ca_file = non_empty_path(&lookup, "MU_SMOKE_TLS_CA_FILE")?;
        let tls_cert_file = non_empty_path(&lookup, "MU_SMOKE_TLS_CERT_FILE")?;
        let tls_key_file = non_empty_path(&lookup, "MU_SMOKE_TLS_KEY_FILE")?;

        if tls_cert_file.is_some() != tls_key_file.is_some() {
            return Err(
                "MU_SMOKE_TLS_CERT_FILE and MU_SMOKE_TLS_KEY_FILE must both be set when configuring client mTLS"
                    .to_string(),
            );
        }

        if let Some(ref ca_path) = tls_ca_file {
            load_certs(ca_path, "MU_SMOKE_TLS_CA_FILE")?;
        }
        if let (Some(ref cert_path), Some(ref key_path)) = (&tls_cert_file, &tls_key_file) {
            load_certs(cert_path, "MU_SMOKE_TLS_CERT_FILE")?;
            load_key(key_path, "MU_SMOKE_TLS_KEY_FILE")?;
        }

        let bearer_token = match non_empty_path(&lookup, "MU_SMOKE_BEARER_TOKEN_FILE")? {
            Some(path) => Some(read_trimmed_secret(&path, "MU_SMOKE_BEARER_TOKEN_FILE")?),
            None => None,
        };

        let timeout_secs = match non_empty_var(&lookup, "MU_SMOKE_TIMEOUT_SECS") {
            Some(raw) => {
                let parsed = raw
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid MU_SMOKE_TIMEOUT_SECS '{raw}': {e}"))?;
                if parsed == 0 {
                    return Err("MU_SMOKE_TIMEOUT_SECS must be greater than 0".to_string());
                }
                parsed
            }
            None => DEFAULT_SMOKE_TIMEOUT_SECS,
        };

        let has_tls = tls_ca_file.is_some() || tls_cert_file.is_some();
        let target_url = match non_empty_var(&lookup, "MU_SMOKE_TARGET_URL") {
            Some(url) => Some(url.trim_end_matches('/').to_string()),
            None => non_empty_var(&lookup, "MU_SMOKE_TARGET_ADDR").map(|addr| {
                let trimmed = addr.trim_end_matches('/');
                if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                    trimmed.to_string()
                } else if has_tls {
                    format!("https://{trimmed}")
                } else {
                    format!("http://{trimmed}")
                }
            }),
        };

        let server_name = non_empty_var(&lookup, "MU_SMOKE_TLS_SERVER_NAME");

        Ok(Self {
            target_url,
            tls_ca_file,
            tls_cert_file,
            tls_key_file,
            server_name,
            bearer_token,
            timeout: Duration::from_secs(timeout_secs),
        })
    }
}

fn non_empty_var<F>(lookup: &F, key: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn non_empty_path<F>(lookup: &F, key: &str) -> Result<Option<PathBuf>, String>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(key) {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                Err(format!("{key} was set but empty"))
            } else {
                Ok(Some(PathBuf::from(trimmed)))
            }
        }
        None => Ok(None),
    }
}

fn read_trimmed_secret(path: &Path, var_name: &str) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "Failed to read {var_name} at '{}': {e} (fail closed)",
            path.display()
        )
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "{var_name} at '{}' is empty after trimming (fail closed)",
            path.display()
        ));
    }
    Ok(trimmed.to_string())
}

fn load_certs(path: &Path, var_name: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = File::open(path).map_err(|e| {
        format!(
            "Failed to open {var_name} at '{}': {e} (fail closed)",
            path.display()
        )
    })?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            format!(
                "Invalid PEM certificate in {var_name} at '{}': {e}",
                path.display()
            )
        })?;
    if certs.is_empty() {
        return Err(format!(
            "{var_name} at '{}' contains zero certificates",
            path.display()
        ));
    }
    Ok(certs)
}

fn load_key(path: &Path, var_name: &str) -> Result<PrivateKeyDer<'static>, String> {
    let file = File::open(path).map_err(|e| {
        format!(
            "Failed to open {var_name} at '{}': {e} (fail closed)",
            path.display()
        )
    })?;
    let mut reader = BufReader::new(file);
    PrivateKeyDer::from_pem_reader(&mut reader).map_err(|e| {
        format!(
            "Invalid PEM private key in {var_name} at '{}': {e}",
            path.display()
        )
    })
}

fn build_tls_connector(
    ca_path: Option<&Path>,
    client_identity: Option<(&Path, &Path)>,
) -> Result<TlsConnector, String> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    let mut root_store = rustls::RootCertStore::empty();
    let ca = ca_path.ok_or_else(|| {
        "MU_SMOKE_TLS_CA_FILE is required for https:// OTLP collector probes".to_string()
    })?;
    for cert in load_certs(ca, "MU_SMOKE_TLS_CA_FILE")? {
        root_store
            .add(cert)
            .map_err(|e| format!("Failed adding CA cert: {e}"))?;
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);
    let client_cfg = match client_identity {
        Some((cert_path, key_path)) => {
            let certs = load_certs(cert_path, "MU_SMOKE_TLS_CERT_FILE")?;
            let key = load_key(key_path, "MU_SMOKE_TLS_KEY_FILE")?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("Invalid client mTLS cert/key pair: {e}"))?
        }
        None => builder.with_no_client_auth(),
    };

    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

async fn send_http_request(
    base_url: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    cfg: &SmokeConfig,
) -> Result<(u16, Vec<u8>), String> {
    let is_https = base_url.starts_with("https://");
    let authority_and_prefix = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .ok_or_else(|| format!("Unsupported URL scheme in '{base_url}'"))?;
    let (authority, base_path) = match authority_and_prefix.find('/') {
        Some(idx) => (&authority_and_prefix[..idx], &authority_and_prefix[idx..]),
        None => (authority_and_prefix, ""),
    };
    let connect_addr = if authority.contains(':') {
        authority.to_string()
    } else if is_https {
        format!("{authority}:443")
    } else {
        format!("{authority}:80")
    };
    let full_path = format!("{}{}", base_path.trim_end_matches('/'), path);

    let mut req =
        format!("{method} {full_path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n");
    if let Some(tok) = cfg.bearer_token.as_deref() {
        req.push_str(&format!("Authorization: Bearer {tok}\r\n"));
    }
    if let Some(bytes) = body {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", bytes.len()));
    }
    req.push_str("\r\n");

    let tcp = tokio::time::timeout(cfg.timeout, TcpStream::connect(&connect_addr))
        .await
        .map_err(|_| format!("Timed out connecting to {connect_addr}"))?
        .map_err(|e| format!("TCP connect to {connect_addr} failed: {e}"))?;

    if is_https {
        let client_id = cfg
            .tls_cert_file
            .as_deref()
            .zip(cfg.tls_key_file.as_deref());
        let connector = build_tls_connector(cfg.tls_ca_file.as_deref(), client_id)?;
        let host = cfg
            .server_name
            .as_deref()
            .unwrap_or_else(|| authority.split(':').next().unwrap_or(authority));
        let sni = ServerName::try_from(host.to_string())
            .map_err(|e| format!("Invalid TLS server name '{host}': {e}"))?;
        let mut tls = tokio::time::timeout(cfg.timeout, connector.connect(sni, tcp))
            .await
            .map_err(|_| format!("TLS handshake timeout for {connect_addr}"))?
            .map_err(|e| format!("TLS handshake failed for {connect_addr}: {e}"))?;
        exchange_http1(&mut tls, req.as_bytes(), body.unwrap_or(&[]), cfg.timeout).await
    } else {
        let mut stream = tcp;
        exchange_http1(
            &mut stream,
            req.as_bytes(),
            body.unwrap_or(&[]),
            cfg.timeout,
        )
        .await
    }
}

async fn exchange_http1<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    head: &[u8],
    body: &[u8],
    timeout: Duration,
) -> Result<(u16, Vec<u8>), String> {
    tokio::time::timeout(timeout, async {
        stream
            .write_all(head)
            .await
            .map_err(|e| format!("HTTP write header failed: {e}"))?;
        if !body.is_empty() {
            stream
                .write_all(body)
                .await
                .map_err(|e| format!("HTTP write body failed: {e}"))?;
        }
        stream
            .flush()
            .await
            .map_err(|e| format!("HTTP flush failed: {e}"))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .map_err(|e| format!("HTTP read failed: {e}"))?;
        parse_http_response(&raw)
    })
    .await
    .map_err(|_| "HTTP exchange timed out".to_string())?
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Malformed HTTP response: missing header terminator".to_string())?;
    let header_str = std::str::from_utf8(&raw[..sep])
        .map_err(|e| format!("Invalid UTF-8 in HTTP response headers: {e}"))?;
    let status_line = header_str.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("Invalid HTTP status line '{status_line}'"))?;
    let body_raw = &raw[sep + 4..];

    let is_chunked = header_str.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });
    let body = if is_chunked {
        decode_chunked(body_raw)?
    } else {
        body_raw.to_vec()
    };
    Ok((status, body))
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "Malformed chunked response".to_string())?;
        let size_str = std::str::from_utf8(&input[..line_end])
            .map_err(|e| format!("Invalid chunk size UTF-8: {e}"))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|e| format!("Invalid chunk hex size '{size_str}': {e}"))?;
        input = &input[line_end + 2..];
        if size == 0 {
            break;
        }
        if input.len() < size + 2 {
            return Err("Truncated chunked HTTP body".to_string());
        }
        out.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
    Ok(out)
}

async fn run_collector_otlp_smoke(base_url: &str, cfg: &SmokeConfig, is_ephemeral: bool) {
    // 1. Read-only /healthz probe
    let (status, health_body) = send_http_request(base_url, "GET", "/healthz", None, cfg)
        .await
        .expect("GET /healthz");
    assert_eq!(status, 200, "GET /healthz must return 200 OK");
    let health_before: serde_json::Value =
        serde_json::from_slice(&health_body).expect("parse /healthz JSON");
    assert_eq!(health_before["status"], "ok");
    if is_ephemeral {
        assert_eq!(health_before["wal_used_bytes"], 0);
        assert_eq!(health_before["wal_pending_batches"], 0);
    }

    // 2. Non-polluting empty OTLP/HTTP probes across traces, metrics, and logs
    for (path, payload) in [
        ("/v1/traces", br#"{"resourceSpans":[]}"#.as_slice()),
        ("/v1/metrics", br#"{"resourceMetrics":[]}"#.as_slice()),
        ("/v1/logs", br#"{"resourceLogs":[]}"#.as_slice()),
    ] {
        let (st, resp_body) = send_http_request(base_url, "POST", path, Some(payload), cfg)
            .await
            .expect("empty OTLP probe");
        assert_eq!(st, 200, "{path} empty probe must return 200 OK");
        let parsed: OtlpIngestResponse =
            serde_json::from_slice(&resp_body).expect("parse OtlpIngestResponse");
        assert_eq!(parsed.accepted_records, 0);
        assert_eq!(parsed.wal_sequence, None);
        assert!(!parsed.dropped_backpressure);
    }

    // 3. Malformed OTLP payload must fail closed (400 Bad Request) without mutating WAL
    let (bad_st, _) = send_http_request(base_url, "POST", "/v1/traces", Some(b"{"), cfg)
        .await
        .expect("malformed OTLP probe");
    assert_eq!(bad_st, 400);

    // 4. Re-verify /healthz shows zero WAL growth in ephemeral mode (and healthy in live mode)
    let (after_st, after_body) = send_http_request(base_url, "GET", "/healthz", None, cfg)
        .await
        .expect("second GET /healthz");
    assert_eq!(after_st, 200);
    let health_after: serde_json::Value = serde_json::from_slice(&after_body).unwrap();
    assert_eq!(health_after["status"], "ok");
    if is_ephemeral {
        assert_eq!(health_after["wal_used_bytes"], 0);
        assert_eq!(health_after["wal_pending_batches"], 0);
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn smoke_config_enforces_fail_closed_credentials_and_sandbox_plan() {
    let temp = tempfile::tempdir().unwrap();
    let token_path = temp.path().join("collector.token");
    std::fs::write(&token_path, " collector-token-99 \n").unwrap();

    let mut ca_params = CertificateParams::new(vec!["smoke-ca".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "smoke-ca");
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);
    let cli_params = CertificateParams::new(vec!["smoke-client".to_string()]).unwrap();
    let cli_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cli_cert = cli_params.signed_by(&cli_key, &ca_issuer).unwrap();

    let ca_path = temp.path().join("ca.crt");
    let cert_path = temp.path().join("cli.crt");
    let key_path = temp.path().join("cli.key");
    std::fs::write(&ca_path, ca_cert.pem()).unwrap();
    std::fs::write(&cert_path, cli_cert.pem()).unwrap();
    std::fs::write(&key_path, cli_key.serialize_pem()).unwrap();

    let ok_env = HashMap::from([
        ("MU_SMOKE_TARGET_URL", "http://127.0.0.1:4318/".to_string()),
        (
            "MU_SMOKE_BEARER_TOKEN_FILE",
            token_path.to_string_lossy().into_owned(),
        ),
        (
            "MU_SMOKE_TLS_CA_FILE",
            ca_path.to_string_lossy().into_owned(),
        ),
        (
            "MU_SMOKE_TLS_CERT_FILE",
            cert_path.to_string_lossy().into_owned(),
        ),
        (
            "MU_SMOKE_TLS_KEY_FILE",
            key_path.to_string_lossy().into_owned(),
        ),
    ]);
    let cfg = SmokeConfig::from_lookup(|k| ok_env.get(k).cloned()).unwrap();
    assert_eq!(cfg.target_url.as_deref(), Some("http://127.0.0.1:4318"));
    assert_eq!(cfg.bearer_token.as_deref(), Some("collector-token-99"));
    assert_eq!(cfg.timeout, Duration::from_secs(10));

    // Unreadable bearer token file fails closed
    let missing_tok = HashMap::from([(
        "MU_SMOKE_BEARER_TOKEN_FILE",
        temp.path()
            .join("missing.token")
            .to_string_lossy()
            .into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| missing_tok.get(k).cloned()).is_err());

    // Unreadable TLS CA file fails closed
    let missing_ca = HashMap::from([(
        "MU_SMOKE_TLS_CA_FILE",
        temp.path()
            .join("missing.ca")
            .to_string_lossy()
            .into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| missing_ca.get(k).cloned()).is_err());

    // Startup sandbox plan validates cleanly
    let plan = apply_collector_startup_sandbox(&CollectorSandboxConfig::default())
        .expect("collector startup sandbox plan");
    assert!(!plan.landlock_rules.is_empty());
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn smoke_mu_observable_collector_otlp_healthz_and_non_polluting_probes() {
    let cfg = SmokeConfig::from_env().expect("valid MU_SMOKE_* environment configuration");

    if let Some(ref target_url) = cfg.target_url {
        run_collector_otlp_smoke(target_url, &cfg, false).await;
        return;
    }

    // Ephemeral mode: spin up local 127.0.0.1:0 OTLP/HTTP collector listener
    let wal = Arc::new(Mutex::new(EdgeRingWal::in_memory(
        DEFAULT_MAX_WAL_BYTES,
        DEFAULT_MAX_AGE_SECS,
    )));
    let scrubber = Arc::new(EdgeSecretScrubber::default());
    let state = CollectorIngestState::new(wal.clone(), scrubber, "node-a", "x86_64");
    let router = build_otlp_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let base_url = format!("http://{addr}");
    run_collector_otlp_smoke(&base_url, &cfg, true).await;

    let wal_guard = wal.lock().await;
    assert_eq!(wal_guard.used_bytes(), 0);
    assert!(wal_guard.pending_batches().is_empty());

    server_handle.abort();
}
