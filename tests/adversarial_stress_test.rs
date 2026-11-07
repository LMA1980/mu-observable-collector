//! Adversarial stress test harness for `MuObserve-collector` Issue #14 fix:
//! Arrow IPC TCP :4319 Listener & Concurrent Serve Mode.
//!
//! Evaluates:
//! 1. High-throughput continuous streaming of framed Arrow batches over persistent TCP connection.
//! 2. Abrupt client disconnection / RST fault injection at arbitrary frame boundaries.
//! 3. Malformed frame headers (magic, version, oversized, zero-length, corrupted Arrow IPC).
//! 4. Concurrent HTTP (:4318) and TCP (:4319) traffic without listener starvation.
//! 5. Shutdown signal handling under in-flight TCP/HTTP connection load.

use mu_observable_collector::{
    build_otlp_router, serve_muob_tcp_listener, CollectorBatchAck, CollectorIngestState,
    EdgeRingWal, EdgeSecretScrubber, IpcHeader, OtelLogEntry, OtelSpanEntry, TestCaseRunEntry,
    FLAG_HIGH_PRIORITY, MSG_TYPE_ARROW_SPANS, MSG_TYPE_ARROW_TEST_RUNS, MSG_TYPE_WAL_ACK,
};
use mu_observable_ipc::{
    create_fory_registry, encode_span_batch, encode_test_run_batch, read_frame, write_frame,
    MAX_FRAME_SIZE,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Helper to serialize `IpcHeader` to raw 24-byte wire array.
fn header_to_bytes(hdr: &IpcHeader) -> [u8; 24] {
    // Safety: IpcHeader is #[repr(C, align(8))] with exactly 24 bytes and no padding
    unsafe { std::mem::transmute(*hdr) }
}

/// Helper to create a test `CollectorIngestState` with in-memory WAL and secret scrubber.
fn create_test_state() -> (CollectorIngestState, Arc<Mutex<EdgeRingWal>>) {
    let wal = Arc::new(Mutex::new(EdgeRingWal::in_memory(32 * 1024 * 1024, 86_400)));
    let scrubber = Arc::new(EdgeSecretScrubber::with_secret_values([
        "super_secret_ci_token_abc999",
        "ghp_adversarial_test_token_xyz123",
    ]));
    let state = CollectorIngestState::new(wal.clone(), scrubber, "test-node", "x86_64");
    (state, wal)
}

/// Helper to create a sample Arrow IPC span batch.
fn make_span_batch(seq: u64, secret_token: &str) -> (Vec<u8>, IpcHeader) {
    let spans = vec![OtelSpanEntry {
        trace_id: format!("trace_{seq:032x}"),
        span_id: format!("span_{seq:016x}"),
        parent_span_id: None,
        service_name: "stress-test-worker".to_string(),
        node_id: "test-node".to_string(),
        span_name: format!("stress_span_{seq}"),
        span_kind: "INTERNAL".to_string(),
        start_time_unix_nano: 1_700_000_000_000_000_000i64 + (seq as i64),
        end_time_unix_nano: 1_700_000_001_000_000_000i64 + (seq as i64),
        duration_ns: 1_000_000_000,
        status_code: "OK".to_string(),
        status_message: Some(format!("token={secret_token}")),
        attributes_json: "{}".to_string(),
    }];
    let bytes = encode_span_batch(&spans).expect("encode span batch");
    let hdr = IpcHeader::new(
        MSG_TYPE_ARROW_SPANS,
        u32::try_from(bytes.len()).unwrap(),
        0,
        seq,
    );
    (bytes, hdr)
}

/// Helper to create a sample Arrow IPC test run batch.
fn make_test_run_batch(seq: u64, secret_token: &str) -> (Vec<u8>, IpcHeader) {
    let runs = vec![TestCaseRunEntry {
        job_id: format!("job_{seq}"),
        repo_key: "lma1980/mu-observable".to_string(),
        branch_key: "main".to_string(),
        commit_sha: "abcd1234ef567890".to_string(),
        crate_name: "mu-observable-collector".to_string(),
        test_binary: "adversarial_stress".to_string(),
        test_name: format!("stress_test_{seq}"),
        status: "passed".to_string(),
        duration_ms: 42.0,
        failure_summary: Some(format!("failed token={secret_token}")),
        timestamp_unix_nano: 1_700_000_000_000_000_000i64 + (seq as i64),
        node_id: "test-node".to_string(),
        arch: "x86_64".to_string(),
    }];
    let bytes = encode_test_run_batch(&runs).expect("encode test run batch");
    let hdr = IpcHeader::new(
        MSG_TYPE_ARROW_TEST_RUNS,
        u32::try_from(bytes.len()).unwrap(),
        FLAG_HIGH_PRIORITY,
        seq,
    );
    (bytes, hdr)
}

// ============================================================================
// STRESS TEST 1: High-throughput Burst & Continuous Streaming
// ============================================================================

#[tokio::test]
async fn test_stress_high_throughput_burst_and_continuous_streaming() {
    let (state, wal) = create_test_state();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(serve_muob_tcp_listener(listener, state));

    const NUM_CLIENTS: usize = 5;
    const BATCHES_PER_CLIENT: usize = 50;
    let mut client_handles = Vec::new();

    for client_id in 0..NUM_CLIENTS {
        let handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.expect("connect");
            let fory = create_fory_registry().expect("fory");

            for b in 0..BATCHES_PER_CLIENT {
                let seq = (client_id * 1000 + b + 1) as u64;
                let (payload, hdr) = if b % 2 == 0 {
                    make_span_batch(seq, "super_secret_ci_token_abc999")
                } else {
                    make_test_run_batch(seq, "ghp_adversarial_test_token_xyz123")
                };

                write_frame(&mut stream, &hdr, &payload)
                    .await
                    .expect("write_frame");

                let (ack_hdr, ack_bytes) = read_frame(&mut stream).await.expect("read_frame");
                assert_eq!(ack_hdr.msg_type, MSG_TYPE_WAL_ACK);
                assert_eq!(ack_hdr.sequence, seq);

                let ack: CollectorBatchAck = fory.deserialize(&ack_bytes).expect("deserialize ack");
                assert!(ack.ok, "batch {seq} failed: {:?}", ack.error_message);
                assert_eq!(ack.accepted_rows, 1);
            }
        });
        client_handles.push(handle);
    }

    for handle in client_handles {
        handle.await.expect("client worker finished");
    }

    // Verify all 250 batches arrived and were persisted in WAL
    let wal_guard = wal.lock().await;
    let pending = wal_guard.pending_batches();
    assert_eq!(pending.len(), NUM_CLIENTS * BATCHES_PER_CLIENT);

    // Verify secret scrubbing across all batches
    for batch in &pending {
        let payload_str = String::from_utf8_lossy(&batch.payload);
        assert!(
            !payload_str.contains("super_secret_ci_token_abc999"),
            "unredacted secret found in batch {}",
            batch.seq_no
        );
        assert!(
            !payload_str.contains("ghp_adversarial_test_token_xyz123"),
            "unredacted secret found in batch {}",
            batch.seq_no
        );
    }

    server_task.abort();
}

// ============================================================================
// STRESS TEST 2: Abrupt Client Disconnections & Chaos / Fault Injection
// ============================================================================

#[tokio::test]
async fn test_stress_abrupt_client_disconnections_and_fault_injection() {
    let (state, _) = create_test_state();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(serve_muob_tcp_listener(listener, state));

    // Case 2a: Connect and immediately disconnect (0 bytes transferred)
    for _ in 0..10 {
        let stream = TcpStream::connect(addr).await.unwrap();
        drop(stream);
    }

    // Case 2b: Connect, send partial header (1 to 23 bytes), and immediately drop
    for len in [1, 5, 12, 23] {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let partial_hdr = [0x55u8; 24];
        let _ = stream.write_all(&partial_hdr[..len]).await;
        drop(stream);
    }

    // Case 2c: Connect, send full 24-byte header specifying 500 byte payload, send only 50 bytes, then drop
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let hdr = IpcHeader::new(MSG_TYPE_ARROW_SPANS, 500, 0, 9999);
        let _ = stream.write_all(&header_to_bytes(&hdr)).await;
        let _ = stream.write_all(&[0x42u8; 50]).await;
        drop(stream);
    }

    // Case 2d: Connect, send valid batch, receive ACK, then send TCP RST (SO_LINGER=0)
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let (payload, hdr) = make_span_batch(1, "test_secret");
        write_frame(&mut stream, &hdr, &payload).await.unwrap();
        let (ack_hdr, _) = read_frame(&mut stream).await.unwrap();
        assert_eq!(ack_hdr.sequence, 1);

        // Send half of the next header then abruptly close socket
        let _ = stream.write_all(&header_to_bytes(&hdr)[..10]).await;
        drop(stream);
    }

    // Case 2e: Verify listener is still alive and accepting healthy connections after all faults
    {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("listener still healthy");
        let (payload, hdr) = make_span_batch(100, "clean_secret");
        write_frame(&mut stream, &hdr, &payload).await.unwrap();
        let (ack_hdr, _) = read_frame(&mut stream).await.unwrap();
        assert_eq!(ack_hdr.sequence, 100);
    }

    server_task.abort();
}

// ============================================================================
// STRESS TEST 3: Malformed Frame Headers & Payload Fuzzing
// ============================================================================

#[tokio::test]
async fn test_stress_malformed_headers_and_payload_fuzzing() {
    let (state, _) = create_test_state();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(serve_muob_tcp_listener(listener, state));

    fn assert_closed(res: Result<usize, std::io::Error>) {
        match res {
            Ok(0) => {}
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ) => {}
            other => panic!("expected connection close or reset, got {other:?}"),
        }
    }

    // Case 3a: Invalid magic bytes (e.g. b"FAIL")
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut hdr = IpcHeader::new(MSG_TYPE_ARROW_SPANS, 10, 0, 1);
        hdr.magic = *b"FAIL";
        stream.write_all(&header_to_bytes(&hdr)).await.unwrap();
        stream.write_all(&[0u8; 10]).await.unwrap();

        let mut buf = [0u8; 10];
        assert_closed(stream.read(&mut buf).await);
    }

    // Case 3b: Unsupported version (e.g. version 99)
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut hdr = IpcHeader::new(MSG_TYPE_ARROW_SPANS, 10, 0, 2);
        hdr.version = 99;
        stream.write_all(&header_to_bytes(&hdr)).await.unwrap();
        stream.write_all(&[0u8; 10]).await.unwrap();

        let mut buf = [0u8; 10];
        assert_closed(stream.read(&mut buf).await);
    }

    // Case 3c: Excessive payload length (> MAX_FRAME_SIZE = 16 MiB)
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let hdr = IpcHeader::new(MSG_TYPE_ARROW_SPANS, (MAX_FRAME_SIZE as u32) + 1024, 0, 3);
        stream.write_all(&header_to_bytes(&hdr)).await.unwrap();

        let mut buf = [0u8; 10];
        assert_closed(stream.read(&mut buf).await);
    }

    // Case 3d: Zero payload length on Arrow message type
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let hdr = IpcHeader::new(MSG_TYPE_ARROW_SPANS, 0, 0, 4);
        stream.write_all(&header_to_bytes(&hdr)).await.unwrap();

        let mut buf = [0u8; 10];
        assert_closed(stream.read(&mut buf).await);
    }

    // Case 3e: Corrupted Arrow payload (valid header, invalid Arrow stream bytes)
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let hdr = IpcHeader::new(MSG_TYPE_ARROW_SPANS, 64, 0, 5);
        stream.write_all(&header_to_bytes(&hdr)).await.unwrap();
        stream.write_all(&[0xDE, 0xAD, 0xBE, 0xEF]).await.unwrap();
        stream.write_all(&[0xFF; 60]).await.unwrap();

        let mut buf = [0u8; 10];
        assert_closed(stream.read(&mut buf).await);
    }

    // Case 3f: Unsupported message type
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let hdr = IpcHeader::new(0x9999, 16, 0, 6);
        stream.write_all(&header_to_bytes(&hdr)).await.unwrap();
        stream.write_all(&[0xAA; 16]).await.unwrap();

        let mut buf = [0u8; 10];
        assert_closed(stream.read(&mut buf).await);
    }

    // Case 3g: Verify listener is still fully functional after all attack frames
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let (payload, hdr) = make_span_batch(200, "recovery_secret");
        write_frame(&mut stream, &hdr, &payload).await.unwrap();
        let (ack_hdr, _) = read_frame(&mut stream).await.unwrap();
        assert_eq!(ack_hdr.sequence, 200);
    }

    server_task.abort();
}

// ============================================================================
// STRESS TEST 4: Concurrent HTTP (:4318) and TCP (:4319) Zero Starvation
// ============================================================================

#[tokio::test]
async fn test_stress_concurrent_http_otlp_and_tcp_arrow_starvation() {
    let (state, wal) = create_test_state();

    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();

    let muob_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let muob_addr = muob_listener.local_addr().unwrap();

    let state_http = state.clone();
    let http_server =
        tokio::spawn(
            async move { axum::serve(http_listener, build_otlp_router(state_http)).await },
        );

    let state_muob = state.clone();
    let muob_server =
        tokio::spawn(async move { serve_muob_tcp_listener(muob_listener, state_muob).await });

    const CONCURRENT_CLIENTS: usize = 4;
    const OPERATIONS_PER_CLIENT: usize = 25;

    let mut handles = Vec::new();

    // Spawn HTTP clients hammering /healthz and /v1/logs
    for client_id in 0..CONCURRENT_CLIENTS {
        let handle = tokio::spawn(async move {
            for i in 0..OPERATIONS_PER_CLIENT {
                if i % 2 == 0 {
                    // Test /healthz
                    let req = format!(
                        "GET /healthz HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        http_addr
                    );
                    let mut stream = TcpStream::connect(http_addr).await.unwrap();
                    stream.write_all(req.as_bytes()).await.unwrap();
                    let mut resp = Vec::new();
                    stream.read_to_end(&mut resp).await.unwrap();
                    let resp_str = String::from_utf8_lossy(&resp);
                    assert!(resp_str.contains("200 OK"));
                } else {
                    // Test POST /v1/logs
                    let body = serde_json::to_vec(&vec![OtelLogEntry {
                        timestamp_unix_nano: 1_700_000_000_000_000_000i64
                            + (client_id * 100 + i) as i64,
                        trace_id: "0123456789abcdef0123456789abcdef".to_string(),
                        span_id: "0123456789abcdef".to_string(),
                        severity_number: 9,
                        severity_text: "INFO".to_string(),
                        service_name: "http-stress".to_string(),
                        node_id: "test-node".to_string(),
                        body: format!("log entry from client {client_id} iter {i}"),
                        attributes_json: "{}".to_string(),
                        job_id: None,
                        stage_id: None,
                    }])
                    .unwrap();

                    let req = format!(
                        "POST /v1/logs HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        http_addr,
                        body.len()
                    );
                    let mut stream = TcpStream::connect(http_addr).await.unwrap();
                    stream.write_all(req.as_bytes()).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                    let mut resp = Vec::new();
                    stream.read_to_end(&mut resp).await.unwrap();
                    let resp_str = String::from_utf8_lossy(&resp);
                    assert!(resp_str.contains("200 OK") || resp_str.contains("accepted_records"));
                }
            }
        });
        handles.push(handle);
    }

    // Spawn TCP clients streaming Arrow IPC batches
    for client_id in 0..CONCURRENT_CLIENTS {
        let handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(muob_addr).await.unwrap();
            let fory = create_fory_registry().unwrap();
            for i in 0..OPERATIONS_PER_CLIENT {
                let seq = (5000 + client_id * 100 + i) as u64;
                let (payload, hdr) = make_span_batch(seq, "concurrent_secret");
                write_frame(&mut stream, &hdr, &payload).await.unwrap();
                let (ack_hdr, ack_bytes) = read_frame(&mut stream).await.unwrap();
                assert_eq!(ack_hdr.sequence, seq);
                let ack: CollectorBatchAck = fory.deserialize(&ack_bytes).unwrap();
                assert!(ack.ok);
            }
        });
        handles.push(handle);
    }

    // Wait for all concurrent workers to complete
    for handle in handles {
        handle.await.expect("worker finished without panic");
    }

    // Verify WAL holds both HTTP and TCP ingested telemetry
    let wal_guard = wal.lock().await;
    let pending = wal_guard.pending_batches();
    assert!(
        pending.len() >= CONCURRENT_CLIENTS * OPERATIONS_PER_CLIENT,
        "WAL should contain all concurrent batches; found {}",
        pending.len()
    );

    http_server.abort();
    muob_server.abort();
}

// ============================================================================
// STRESS TEST 5: Graceful Shutdown Signal Handling with Active In-flight TCP Connections
// ============================================================================

#[tokio::test]
async fn test_stress_shutdown_signal_handling_with_active_connections() {
    let (state, _) = create_test_state();

    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let muob_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let muob_addr = muob_listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_task = tokio::spawn(async move {
        let http_server = axum::serve(http_listener, build_otlp_router(state.clone()));
        let muob_server = serve_muob_tcp_listener(muob_listener, state);

        tokio::select! {
            res = http_server => {
                let _ = res;
            }
            res = muob_server => {
                let _ = res;
            }
            _ = shutdown_rx => {
                // Emulated ctrl_c() shutdown signal
            }
        }
    });

    // Establish persistent TCP connection and start streaming batches
    let mut stream = TcpStream::connect(muob_addr).await.unwrap();
    let (payload, hdr) = make_span_batch(1, "secret");
    write_frame(&mut stream, &hdr, &payload).await.unwrap();
    let (ack_hdr, _) = read_frame(&mut stream).await.unwrap();
    assert_eq!(ack_hdr.sequence, 1);

    // Trigger shutdown while TCP connection is still open and idling
    shutdown_tx.send(()).expect("send shutdown signal");

    // Server select block should resolve promptly within 1 second
    let shutdown_result = tokio::time::timeout(Duration::from_secs(1), server_task).await;
    assert!(
        shutdown_result.is_ok(),
        "Server failed to terminate promptly upon shutdown signal"
    );

    // Subsequent connection attempts to the listeners should now fail
    let subsequent_conn = TcpStream::connect(muob_addr).await;
    assert!(
        subsequent_conn.is_err(),
        "Listener should no longer accept connections after shutdown"
    );
}

fn make_debug_log_batch(seq: u64) -> (Vec<u8>, IpcHeader) {
    let logs = vec![OtelLogEntry {
        timestamp_unix_nano: 1_700_000_000_000_000_000i64 + (seq as i64),
        trace_id: format!("trace_{seq:032x}"),
        span_id: format!("span_{seq:016x}"),
        severity_number: 9, // INFO (LowDebugLog)
        severity_text: "INFO".to_string(),
        service_name: "stress-test-worker".to_string(),
        node_id: "test-node".to_string(),
        body: format!("debug log body for sequence {seq}"),
        attributes_json: "{}".to_string(),
        job_id: None,
        stage_id: None,
    }];
    let bytes = mu_observable_ipc::encode_log_batch(&logs).expect("encode log batch");
    let hdr = IpcHeader::new(
        mu_observable_collector::MSG_TYPE_ARROW_LOGS,
        u32::try_from(bytes.len()).unwrap(),
        0, // Not FLAG_HIGH_PRIORITY
        seq,
    );
    (bytes, hdr)
}

// ============================================================================
// STRESS TEST 6: WAL Backpressure & Negative ACK Under Memory Saturation
// ============================================================================

#[tokio::test]
async fn test_stress_wal_backpressure_and_ack_under_memory_exhaustion() {
    // Construct a tiny in-memory WAL (only 8 KiB) to trigger backpressure quickly
    let tiny_wal = Arc::new(Mutex::new(EdgeRingWal::in_memory(8 * 1024, 86_400)));
    let scrubber = Arc::new(EdgeSecretScrubber::new());
    let state = CollectorIngestState::new(tiny_wal.clone(), scrubber, "test-node", "x86_64");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(serve_muob_tcp_listener(listener, state));

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let fory = create_fory_registry().unwrap();

    // 1. Fill WAL with StandardSignal spans until the 8 KiB WAL is full
    for seq in 1..=10u64 {
        let (payload, hdr) = make_span_batch(seq, "token");
        write_frame(&mut stream, &hdr, &payload).await.unwrap();
        let (ack_hdr, ack_bytes) = read_frame(&mut stream).await.unwrap();
        assert_eq!(ack_hdr.sequence, seq);
        let ack: CollectorBatchAck = fory.deserialize(&ack_bytes).unwrap();
        assert!(ack.ok);
    }

    // 2. Stream LowDebugLog entries. Since WAL is full of higher-priority spans,
    // debug logs must be dropped due to backpressure.
    let (log_payload, log_hdr) = make_debug_log_batch(200);
    write_frame(&mut stream, &log_hdr, &log_payload)
        .await
        .unwrap();
    let (log_ack_hdr, log_ack_bytes) = read_frame(&mut stream).await.unwrap();
    assert_eq!(log_ack_hdr.sequence, 200);
    let log_ack: CollectorBatchAck = fory.deserialize(&log_ack_bytes).unwrap();

    assert!(
        !log_ack.ok,
        "low-priority log should be rejected under backpressure"
    );
    assert_eq!(log_ack.accepted_rows, 0);
    assert!(
        log_ack
            .error_message
            .as_deref()
            .unwrap_or("")
            .contains("backpressure"),
        "expected backpressure message, got {:?}",
        log_ack.error_message
    );

    // 3. High priority test runs should evict low-priority items or succeed
    let (hp_payload, hp_hdr) = make_test_run_batch(999, "token");
    write_frame(&mut stream, &hp_hdr, &hp_payload)
        .await
        .unwrap();
    let (hp_ack_hdr, hp_ack_bytes) = read_frame(&mut stream).await.unwrap();
    assert_eq!(hp_ack_hdr.sequence, 999);
    let hp_ack: CollectorBatchAck = fory.deserialize(&hp_ack_bytes).unwrap();
    assert!(hp_ack.ok, "high-priority batch must succeed");

    server_task.abort();
}

// ============================================================================
// STRESS TEST 7: IngestConfig Environment Variable Resolution
// ============================================================================

#[test]
fn test_ingest_config_environment_variable_resolution() {
    use mu_observable_collector::IngestConfig;

    // Test default configuration
    let default_cfg = IngestConfig::default();
    assert_eq!(default_cfg.otlp_http_addr, "127.0.0.1:4318");
    assert_eq!(default_cfg.muob_tcp_addr, "127.0.0.1:4319");

    // Test environment overrides
    std::env::set_var("MUOBSERVE_OTLP_HTTP_ADDR", "0.0.0.0:14318");
    std::env::set_var("MUOBSERVE_MUOB_TCP_ADDR", "0.0.0.0:14319");
    let env_cfg = IngestConfig::from_env();
    assert_eq!(env_cfg.otlp_http_addr, "0.0.0.0:14318");
    assert_eq!(env_cfg.muob_tcp_addr, "0.0.0.0:14319");

    // Clean up environment variables
    std::env::remove_var("MUOBSERVE_OTLP_HTTP_ADDR");
    std::env::remove_var("MUOBSERVE_MUOB_TCP_ADDR");
}
