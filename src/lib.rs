//! `mu-observable-collector`: Sandboxed node-level edge telemetry collector daemon (`M3.022`–`M3.030`).
//!
//! Provides:
//! - Dual local ingestion (`src/ingest.rs`): loopback OTLP HTTP (`/v1/traces`, `/v1/metrics`, `/v1/logs`, `/healthz`)
//!   and native `MUOB`-framed Apache Arrow IPC streams (`MSG_TYPE_ARROW_OTEL_LOGS`, `MSG_TYPE_ARROW_OTEL_SPANS`,
//!   `MSG_TYPE_ARROW_OTEL_METRICS`, `MSG_TYPE_ARROW_TEST_RUNS`, `MSG_TYPE_ARROW_BENCH_RUNS`).
//! - Streaming edge secret redaction (`src/scrubber.rs`): [`EdgeSecretScrubber`] implementing
//!   [`mu_observable_ipc::SecretRedactor`] to scrub Bearer tokens, GitHub PATs (`ghp_`/`github_pat_`),
//!   webhook secrets, PEM private keys, and registered secret environment values prior to WAL persistence.
//! - Bounded `256 MiB` Edge Ring-Buffer WAL (`src/wal.rs`): [`EdgeRingWal`] enforcing `max_wal_bytes`
//!   (`256 MiB` default) and `max_age_secs` (`86400s`), evicting acknowledged and expired batches first
//!   and dropping low-priority debug logs before error logs, spans, metrics, test runs, or benchmarks.
//! - `step-ca` mTLS upstream batch forwarder & `MuIsolation` startup confinement (`src/forwarder.rs`):
//!   [`MtlsForwarder`] streaming unacknowledged WAL batches over `tokio-rustls` with exponential backoff
//!   and truncating upon [`WalBatchAck`], confined by [`mu_ci_isolation::KernelSandbox`].

#![deny(unsafe_code)]

pub mod error;
pub mod forwarder;
pub mod ingest;
pub mod scrubber;
pub mod wal;

pub use error::CollectorError;
pub use forwarder::{
    apply_collector_startup_sandbox, build_collector_sandbox_policy, build_tls_client_config,
    build_tls_server_config, decode_wal_ack_frame, CollectorSandboxConfig, MtlsForwarder,
    MtlsForwarderConfig, DEFAULT_COLLECTOR_CONFIG_DIR, DEFAULT_COLLECTOR_STATE_DIR,
};
#[cfg(unix)]
pub use ingest::serve_muob_unix_once;
pub use ingest::{
    build_otlp_router, handle_muob_connection, parse_otlp_logs_json, parse_otlp_metrics_json,
    parse_otlp_traces_json, serve_muob_tcp_listener, serve_muob_tcp_once, CollectorIngestState,
    IngestConfig, OtlpIngestResponse, DEFAULT_MUOB_TCP_ADDR, DEFAULT_OTLP_HTTP_ADDR,
};
pub use scrubber::{is_high_priority_log, EdgeSecretScrubber, ScrubbedArrowBatch};
pub use wal::{
    now_unix_secs, EdgeRingWal, EdgeRingWalConfig, WalBatchEntry, WalSignalPriority,
    DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_WAL_BYTES, DEFAULT_WAL_PATH,
};

// Re-exports & compatibility aliases for `mu-observable-ipc` wire types
pub use mu_observable_ipc::{
    BenchmarkRunEntry, DeterministicSecretRedactor,
    DeterministicSecretRedactor as RegexSecretRedactor, IpcHeader, OtelLogEntry, OtelMetricEntry,
    OtelSpanEntry, SecretRedactor, TestCaseRunEntry, TraceContext, TraceContext as W3cTraceContext,
    WalBatchAck, WalBatchAck as CollectorBatchAck, FLAG_COMPRESSED, FLAG_END_OF_STREAM,
    FLAG_HIGH_PRIORITY, MSG_TYPE_ARROW_BENCH_RUNS, MSG_TYPE_ARROW_OTEL_LOGS,
    MSG_TYPE_ARROW_OTEL_LOGS as MSG_TYPE_ARROW_LOGS, MSG_TYPE_ARROW_OTEL_METRICS,
    MSG_TYPE_ARROW_OTEL_METRICS as MSG_TYPE_ARROW_METRICS, MSG_TYPE_ARROW_OTEL_SPANS,
    MSG_TYPE_ARROW_OTEL_SPANS as MSG_TYPE_ARROW_SPANS, MSG_TYPE_ARROW_TEST_RUNS, MSG_TYPE_WAL_ACK,
    REDACTED_PLACEHOLDER,
};

/// Default maximum Edge WAL capacity in megabytes (`256 MiB`).
pub const DEFAULT_WAL_MAX_MB: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_wal_ceiling() {
        assert_eq!(DEFAULT_WAL_MAX_MB, 256);
        assert_eq!(DEFAULT_MAX_WAL_BYTES, DEFAULT_WAL_MAX_MB * 1024 * 1024);
    }
}
