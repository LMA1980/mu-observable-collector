//! End-to-end integration tests for `mu-observable-collector` (`M3.022`–`M3.030`).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mu_observable_collector::{
    apply_collector_startup_sandbox, build_otlp_router, build_tls_server_config,
    handle_muob_connection, BenchmarkRunEntry, CollectorBatchAck, CollectorIngestState,
    CollectorSandboxConfig, EdgeRingWal, EdgeSecretScrubber, IpcHeader, MtlsForwarder,
    MtlsForwarderConfig, OtelLogEntry, OtelMetricEntry, OtelSpanEntry, TestCaseRunEntry,
    WalSignalPriority, FLAG_HIGH_PRIORITY, MSG_TYPE_ARROW_BENCH_RUNS, MSG_TYPE_ARROW_LOGS,
    MSG_TYPE_ARROW_METRICS, MSG_TYPE_ARROW_SPANS, MSG_TYPE_ARROW_TEST_RUNS, MSG_TYPE_WAL_ACK,
    REDACTED_PLACEHOLDER,
};
use mu_observable_ipc::{
    create_fory_registry, decode_benchmark_run_batch, decode_log_batch, decode_metric_batch,
    decode_span_batch, decode_test_run_batch, encode_benchmark_run_batch, encode_log_batch,
    encode_metric_batch, encode_span_batch, encode_test_run_batch, read_frame, write_frame,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

struct TestPki {
    ca: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

fn setup_pki(dir: &Path) -> TestPki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec!["step-ca.internal".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "MuObserve E2E Step-CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

    let srv_key = KeyPair::generate().unwrap();
    let srv_params = CertificateParams::new(vec!["node-a".to_string()]).unwrap();
    let srv_cert = srv_params.signed_by(&srv_key, &ca_issuer).unwrap();

    let cli_key = KeyPair::generate().unwrap();
    let cli_params = CertificateParams::new(vec!["worker-riscv64".to_string()]).unwrap();
    let cli_cert = cli_params.signed_by(&cli_key, &ca_issuer).unwrap();

    let ca = dir.join("ca.crt");
    let server_cert = dir.join("server.crt");
    let server_key = dir.join("server.key");
    let client_cert = dir.join("client.crt");
    let client_key = dir.join("client.key");

    fs::write(&ca, ca_cert.pem()).unwrap();
    fs::write(&server_cert, srv_cert.pem()).unwrap();
    fs::write(&server_key, srv_key.serialize_pem()).unwrap();
    fs::write(&client_cert, cli_cert.pem()).unwrap();
    fs::write(&client_key, cli_key.serialize_pem()).unwrap();

    TestPki {
        ca,
        server_cert,
        server_key,
        client_cert,
        client_key,
    }
}

#[tokio::test]
async fn test_full_pipeline_ingest_scrub_wal_mtls_drain() {
    let dir = tempdir().unwrap();
    let pki = setup_pki(dir.path());

    // 1. Verify MuIsolation KernelSandbox startup confinement plan
    let sandbox_plan = apply_collector_startup_sandbox(&CollectorSandboxConfig::default())
        .expect("startup sandbox plan");
    assert!(!sandbox_plan.landlock_rules.is_empty());

    // 2. Initialize file-backed EdgeRingWal and EdgeSecretScrubber
    let wal_path = dir.path().join("wal.duckdb");
    let wal = Arc::new(Mutex::new(
        EdgeRingWal::open(&wal_path, 4 * 1024 * 1024, 86_400).unwrap(),
    ));
    let scrubber = Arc::new(EdgeSecretScrubber::with_secret_values([
        "ci_webhook_secret_token_xyz987",
    ]));
    let state =
        CollectorIngestState::new(wal.clone(), scrubber.clone(), "worker-riscv64", "riscv64gc");

    // 3. Ingest OTLP HTTP logs with embedded secrets
    let router = build_otlp_router(state.clone());
    let logs_payload = vec![OtelLogEntry {
        timestamp_unix_nano: 1_700_000_100_000_000_000,
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
        span_id: "00f067aa0ba902b7".to_string(),
        severity_number: 17,
        severity_text: "ERROR".to_string(),
        service_name: "action-runner-worker".to_string(),
        node_id: "worker-riscv64".to_string(),
        body: "Failed auth with ghp_secret1122334455 and ci_webhook_secret_token_xyz987"
            .to_string(),
        attributes_json: r#"{"token":"github_pat_99887766_55443322"}"#.to_string(),
        job_id: Some("job-e2e-1".to_string()),
        stage_id: Some("test".to_string()),
    }];
    let req = Request::builder()
        .method("POST")
        .uri("/v1/logs")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&logs_payload).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 4. Ingest native MUOB Arrow batches (Spans, Metrics, TestCaseRuns, BenchmarkRuns)
    let (mut muob_client, muob_server) = tokio::io::duplex(128 * 1024);
    let state_clone = state.clone();
    let ingest_task = tokio::spawn(async move {
        handle_muob_connection(muob_server, state_clone)
            .await
            .unwrap()
    });

    let spans = vec![OtelSpanEntry {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
        span_id: "00f067aa0ba902b7".to_string(),
        parent_span_id: None,
        service_name: "action-runner-worker".to_string(),
        node_id: "worker-riscv64".to_string(),
        span_name: "ci.stage.test".to_string(),
        span_kind: "INTERNAL".to_string(),
        start_time_unix_nano: 1_700_000_100_000_000_000,
        end_time_unix_nano: 1_700_000_105_000_000_000,
        duration_ns: 5_000_000_000,
        status_code: "ERROR".to_string(),
        status_message: Some("Bearer super_secret_bearer_token".to_string()),
        attributes_json: r#"{"secret":"my_span_secret"}"#.to_string(),
    }];
    let span_bytes = encode_span_batch(&spans).unwrap();
    write_frame(
        &mut muob_client,
        &IpcHeader::new(
            MSG_TYPE_ARROW_SPANS,
            u32::try_from(span_bytes.len()).unwrap(),
            0,
            10,
        ),
        &span_bytes,
    )
    .await
    .unwrap();
    let _ = read_frame(&mut muob_client).await.unwrap();

    let metrics = vec![OtelMetricEntry {
        timestamp_unix_nano: 1_700_000_106_000_000_000,
        service_name: "k3-manager".to_string(),
        node_id: "worker-riscv64".to_string(),
        metric_name: "k3.matvec.gbps".to_string(),
        metric_unit: "GB/s".to_string(),
        value_f64: 810.0,
        arch: "riscv64gc".to_string(),
        cpu_cluster: Some("A100".to_string()),
        vlen_bits: Some(1024),
        memlock_used_bytes: Some(1024 * 1024),
        memlock_limit_bytes: Some(28 * 1024 * 1024 * 1024),
        trace_id: None,
        span_id: None,
        attributes_json: r#"{"api_key":"sk_live_secret_metric"}"#.to_string(),
    }];
    let metric_bytes = encode_metric_batch(&metrics).unwrap();
    write_frame(
        &mut muob_client,
        &IpcHeader::new(
            MSG_TYPE_ARROW_METRICS,
            u32::try_from(metric_bytes.len()).unwrap(),
            0,
            11,
        ),
        &metric_bytes,
    )
    .await
    .unwrap();
    let _ = read_frame(&mut muob_client).await.unwrap();

    let test_runs = vec![TestCaseRunEntry {
        job_id: "job-e2e-1".to_string(),
        repo_key: "lma1980/k3-kernels-rvv".to_string(),
        branch_key: "main".to_string(),
        commit_sha: "deadbeef".to_string(),
        crate_name: "k3-kernels-rvv".to_string(),
        test_binary: "k3_kernels_rvv".to_string(),
        test_name: "test_a100_vmadot".to_string(),
        status: "failed".to_string(),
        duration_ms: 3.25,
        failure_summary: Some(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----".to_string(),
        ),
        timestamp_unix_nano: 1_700_000_107_000_000_000,
        node_id: "worker-riscv64".to_string(),
        arch: "riscv64gc".to_string(),
    }];
    let test_bytes = encode_test_run_batch(&test_runs).unwrap();
    write_frame(
        &mut muob_client,
        &IpcHeader::new(
            MSG_TYPE_ARROW_TEST_RUNS,
            u32::try_from(test_bytes.len()).unwrap(),
            FLAG_HIGH_PRIORITY,
            12,
        ),
        &test_bytes,
    )
    .await
    .unwrap();
    let _ = read_frame(&mut muob_client).await.unwrap();

    let benches = vec![BenchmarkRunEntry {
        job_id: "job-e2e-1".to_string(),
        repo_key: "lma1980/k3-kernels-rvv".to_string(),
        branch_key: "main".to_string(),
        commit_sha: "deadbeef".to_string(),
        crate_name: "k3-kernels-rvv".to_string(),
        bench_name: "q8_0_matvec".to_string(),
        ns_per_iter: 41_000.0,
        std_dev_ns: 200.0,
        mad_ns: 120.0,
        p50_ns: 40_950.0,
        p95_ns: 41_400.0,
        p99_ns: 41_700.0,
        throughput_value: Some(815.2),
        throughput_unit: Some("GB/s token=ghp_benchSecret123".to_string()),
        arch: "riscv64gc".to_string(),
        cpu_cluster: "A100".to_string(),
        vlen_bits: 1024,
        timestamp_unix_nano: 1_700_000_108_000_000_000,
        node_id: "worker-riscv64".to_string(),
    }];
    let bench_bytes = encode_benchmark_run_batch(&benches).unwrap();
    write_frame(
        &mut muob_client,
        &IpcHeader::new(
            MSG_TYPE_ARROW_BENCH_RUNS,
            u32::try_from(bench_bytes.len()).unwrap(),
            FLAG_HIGH_PRIORITY,
            13,
        ),
        &bench_bytes,
    )
    .await
    .unwrap();
    let _ = read_frame(&mut muob_client).await.unwrap();

    drop(muob_client);
    assert_eq!(ingest_task.await.unwrap(), 4);

    // 5. Stream all 5 WAL batches over step-ca mTLS to mock MuObserve server & verify zero secret leakage
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let srv_tls = build_tls_server_config(&pki.ca, &pki.server_cert, &pki.server_key).unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(srv_tls));

    let upstream_server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let fory = create_fory_registry().unwrap();

        for expected_seq in 1..=5u64 {
            let (hdr, payload) = read_frame(&mut tls).await.unwrap();
            assert_eq!(hdr.sequence, expected_seq);
            match hdr.msg_type {
                MSG_TYPE_ARROW_LOGS => {
                    let dec = decode_log_batch(&payload).unwrap();
                    assert!(!dec[0].body.contains("ghp_secret1122334455"));
                    assert!(!dec[0].body.contains("ci_webhook_secret_token_xyz987"));
                    assert!(!dec[0].attributes_json.contains("github_pat_99887766"));
                    assert!(dec[0].body.contains(REDACTED_PLACEHOLDER));
                }
                MSG_TYPE_ARROW_SPANS => {
                    let dec = decode_span_batch(&payload).unwrap();
                    assert!(!dec[0]
                        .status_message
                        .as_deref()
                        .unwrap()
                        .contains("super_secret_bearer_token"));
                    assert!(!dec[0].attributes_json.contains("my_span_secret"));
                }
                MSG_TYPE_ARROW_METRICS => {
                    let dec = decode_metric_batch(&payload).unwrap();
                    assert!(!dec[0].attributes_json.contains("sk_live_secret_metric"));
                }
                MSG_TYPE_ARROW_TEST_RUNS => {
                    let dec = decode_test_run_batch(&payload).unwrap();
                    assert!(!dec[0]
                        .failure_summary
                        .as_deref()
                        .unwrap()
                        .contains("BEGIN RSA PRIVATE KEY"));
                }
                MSG_TYPE_ARROW_BENCH_RUNS => {
                    let dec = decode_benchmark_run_batch(&payload).unwrap();
                    assert!(!dec[0]
                        .throughput_unit
                        .as_deref()
                        .unwrap()
                        .contains("ghp_benchSecret123"));
                }
                other => panic!("unexpected msg_type: {other:#06x}"),
            }

            let ack = CollectorBatchAck {
                sequence: hdr.sequence,
                accepted_rows: 1,
                ok: true,
                error_message: None,
            };
            let ack_bytes = fory.serialize(&ack).unwrap();
            write_frame(
                &mut tls,
                &IpcHeader::new(
                    MSG_TYPE_WAL_ACK,
                    u32::try_from(ack_bytes.len()).unwrap(),
                    0,
                    hdr.sequence,
                ),
                &ack_bytes,
            )
            .await
            .unwrap();
        }
    });

    let forwarder = MtlsForwarder::new(
        MtlsForwarderConfig {
            upstream_addr: upstream_addr.to_string(),
            server_name: "node-a".to_string(),
            ca_cert_path: pki.ca,
            client_cert_path: pki.client_cert,
            client_key_path: pki.client_key,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
            max_retries: 3,
        },
        wal.clone(),
    )
    .unwrap();

    let drained = forwarder.forward_with_backoff().await.unwrap();
    assert_eq!(drained, 5);
    upstream_server.await.unwrap();

    let wal_guard = wal.lock().await;
    assert!(wal_guard.is_empty());
    assert_eq!(wal_guard.used_bytes(), 0);
    assert_eq!(
        WalSignalPriority::classify(MSG_TYPE_ARROW_BENCH_RUNS, 0, false),
        WalSignalPriority::HighCritical
    );
    let _ = encode_log_batch(&[]);
}

#[tokio::test]
async fn test_serve_mode_concurrent_listeners_and_muob_tcp_ingestion() {
    let dir = tempdir().unwrap();
    let pki = setup_pki(dir.path());

    // 1. Initialize file-backed EdgeRingWal and EdgeSecretScrubber
    let wal_path = dir.path().join("wal_serve.duckdb");
    let wal = Arc::new(Mutex::new(
        EdgeRingWal::open(&wal_path, 4 * 1024 * 1024, 86_400).unwrap(),
    ));
    let scrubber = Arc::new(EdgeSecretScrubber::with_secret_values([
        "super_secret_ci_token_abc999",
    ]));
    let state =
        CollectorIngestState::new(wal.clone(), scrubber.clone(), "worker-riscv64", "riscv64gc");

    // 2. Bind concurrent listeners on loopback ephemeral ports (simulating :4318 and :4319)
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();

    let muob_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let muob_addr = muob_listener.local_addr().unwrap();

    // Verify IngestConfig default constant values match specifications
    let default_cfg = mu_observable_collector::IngestConfig::default();
    assert_eq!(default_cfg.otlp_http_addr, "127.0.0.1:4318");
    assert_eq!(default_cfg.muob_tcp_addr, "127.0.0.1:4319");

    // 3. Spawn concurrent servers in background
    let state_http = state.clone();
    let http_task =
        tokio::spawn(
            async move { axum::serve(http_listener, build_otlp_router(state_http)).await },
        );

    let state_muob = state.clone();
    let muob_task = tokio::spawn(async move {
        mu_observable_collector::serve_muob_tcp_listener(muob_listener, state_muob).await
    });

    // 4. Send OTLP HTTP log to HTTP listener
    let client_http = tokio::net::TcpStream::connect(http_addr).await.unwrap();
    let (mut http_read, mut http_write) = client_http.into_split();
    let http_payload = serde_json::to_vec(&vec![OtelLogEntry {
        timestamp_unix_nano: 1_700_000_200_000_000_000,
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
        span_id: "00f067aa0ba902b7".to_string(),
        severity_number: 9,
        severity_text: "INFO".to_string(),
        service_name: "action-runner-worker".to_string(),
        node_id: "worker-riscv64".to_string(),
        body: "HTTP log line with super_secret_ci_token_abc999".to_string(),
        attributes_json: "{}".to_string(),
        job_id: Some("job-http-1".to_string()),
        stage_id: Some("build".to_string()),
    }])
    .unwrap();

    let http_req = format!(
        "POST /v1/logs HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        http_addr,
        http_payload.len()
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    http_write.write_all(http_req.as_bytes()).await.unwrap();
    http_write.write_all(&http_payload).await.unwrap();
    http_write.flush().await.unwrap();

    let mut http_resp_buf = Vec::new();
    http_read.read_to_end(&mut http_resp_buf).await.unwrap();
    let http_resp_str = String::from_utf8_lossy(&http_resp_buf);
    assert!(
        http_resp_str.contains("200 OK") || http_resp_str.contains("accepted_records"),
        "HTTP response was: {http_resp_str}"
    );

    // 5. Connect to native MUOB Arrow TCP listener and stream multiple sequential frames
    let mut muob_stream = tokio::net::TcpStream::connect(muob_addr).await.unwrap();

    // 5a. Stream Spans frame
    let spans = vec![OtelSpanEntry {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
        span_id: "00f067aa0ba902b7".to_string(),
        parent_span_id: None,
        service_name: "action-runner-worker".to_string(),
        node_id: "worker-riscv64".to_string(),
        span_name: "ci.stage.compile".to_string(),
        span_kind: "INTERNAL".to_string(),
        start_time_unix_nano: 1_700_000_200_000_000_000,
        end_time_unix_nano: 1_700_000_205_000_000_000,
        duration_ns: 5_000_000_000,
        status_code: "OK".to_string(),
        status_message: Some("token=super_secret_ci_token_abc999".to_string()),
        attributes_json: "{}".to_string(),
    }];
    let span_bytes = encode_span_batch(&spans).unwrap();
    let hdr = IpcHeader::new(
        MSG_TYPE_ARROW_SPANS,
        u32::try_from(span_bytes.len()).unwrap(),
        0,
        101,
    );
    write_frame(&mut muob_stream, &hdr, &span_bytes)
        .await
        .unwrap();

    let (ack_hdr, ack_bytes) = read_frame(&mut muob_stream).await.unwrap();
    assert_eq!(ack_hdr.msg_type, MSG_TYPE_WAL_ACK);
    assert_eq!(ack_hdr.sequence, 101);
    let fory = create_fory_registry().unwrap();
    let ack: CollectorBatchAck = fory.deserialize(&ack_bytes).unwrap();
    assert!(ack.ok);
    assert_eq!(ack.accepted_rows, 1);

    // 5b. Stream Test Runs frame over the same persistent connection
    let test_runs = vec![TestCaseRunEntry {
        job_id: "job-tcp-2".to_string(),
        repo_key: "lma1980/k3-core".to_string(),
        branch_key: "main".to_string(),
        commit_sha: "beef1234".to_string(),
        crate_name: "k3-core".to_string(),
        test_binary: "k3_core".to_string(),
        test_name: "test_arrow_ipc".to_string(),
        status: "passed".to_string(),
        duration_ms: 12.0,
        failure_summary: None,
        timestamp_unix_nano: 1_700_000_210_000_000_000,
        node_id: "worker-riscv64".to_string(),
        arch: "riscv64gc".to_string(),
    }];
    let test_bytes = encode_test_run_batch(&test_runs).unwrap();
    let hdr2 = IpcHeader::new(
        MSG_TYPE_ARROW_TEST_RUNS,
        u32::try_from(test_bytes.len()).unwrap(),
        FLAG_HIGH_PRIORITY,
        102,
    );
    write_frame(&mut muob_stream, &hdr2, &test_bytes)
        .await
        .unwrap();

    let (ack_hdr2, ack_bytes2) = read_frame(&mut muob_stream).await.unwrap();
    assert_eq!(ack_hdr2.msg_type, MSG_TYPE_WAL_ACK);
    assert_eq!(ack_hdr2.sequence, 102);
    let ack2: CollectorBatchAck = fory.deserialize(&ack_bytes2).unwrap();
    assert!(ack2.ok);

    drop(muob_stream);

    // 6. Verify WAL contains all 3 scrubbed batches (1 HTTP log + 2 MUOB Arrow batches)
    let wal_guard = wal.lock().await;
    let pending = wal_guard.pending_batches();
    assert_eq!(pending.len(), 3);
    for batch in &pending {
        assert!(!String::from_utf8_lossy(&batch.payload).contains("super_secret_ci_token_abc999"));
    }
    drop(wal_guard);

    // 7. Drain WAL to mock upstream step-ca mTLS server
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let srv_tls = build_tls_server_config(&pki.ca, &pki.server_cert, &pki.server_key).unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(srv_tls));

    let upstream_server = tokio::spawn(async move {
        let (tcp, _) = upstream_listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let fory = create_fory_registry().unwrap();

        for seq in 1..=3u64 {
            let (hdr, _payload) = read_frame(&mut tls).await.unwrap();
            assert_eq!(hdr.sequence, seq);
            let ack = CollectorBatchAck {
                sequence: hdr.sequence,
                accepted_rows: 1,
                ok: true,
                error_message: None,
            };
            let ack_bytes = fory.serialize(&ack).unwrap();
            write_frame(
                &mut tls,
                &IpcHeader::new(
                    MSG_TYPE_WAL_ACK,
                    u32::try_from(ack_bytes.len()).unwrap(),
                    0,
                    hdr.sequence,
                ),
                &ack_bytes,
            )
            .await
            .unwrap();
        }
    });

    let forwarder = MtlsForwarder::new(
        MtlsForwarderConfig {
            upstream_addr: upstream_addr.to_string(),
            server_name: "node-a".to_string(),
            ca_cert_path: pki.ca,
            client_cert_path: pki.client_cert,
            client_key_path: pki.client_key,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
            max_retries: 3,
        },
        wal.clone(),
    )
    .unwrap();

    let drained = forwarder.forward_with_backoff().await.unwrap();
    assert_eq!(drained, 3);
    upstream_server.await.unwrap();

    let wal_guard = wal.lock().await;
    assert!(wal_guard.is_empty());

    http_task.abort();
    muob_task.abort();
}
