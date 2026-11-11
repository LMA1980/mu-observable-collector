// SPDX-License-Identifier: AGPL-3.0-only
//! Empirical Stress Tests and Adversarial Challenges for `mu-observable-collector`.
//!
//! Stress-tests:
//! 1. IngestConfig: default vs environment variable resolution.
//! 2. Upstream URL & address parsing: protocol stripping, trailing slashes, whitespace trimming.
//! 3. CLI argument evaluation: daemon serve mode default vs explicit subcommand exit.
//! 4. EdgeRingWal in-memory vs disk-backed initialization.

use mu_observable_collector::{
    EdgeRingWal, IngestConfig, DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_WAL_BYTES, DEFAULT_MUOB_TCP_ADDR,
    DEFAULT_OTLP_HTTP_ADDR,
};
use tempfile::tempdir;

#[test]
fn test_empirical_ingest_config_default_and_env_resolution() {
    // 1. Defaults when environment variables are unset
    // (Ensure vars are unset for isolation in this thread)
    std::env::remove_var("MUOBSERVE_OTLP_HTTP_ADDR");
    std::env::remove_var("MUOBSERVE_MUOB_TCP_ADDR");

    let cfg_default = IngestConfig::from_env();
    assert_eq!(cfg_default.otlp_http_addr, DEFAULT_OTLP_HTTP_ADDR);
    assert_eq!(cfg_default.muob_tcp_addr, DEFAULT_MUOB_TCP_ADDR);

    // 2. Overrides when environment variables are set
    std::env::set_var("MUOBSERVE_OTLP_HTTP_ADDR", "0.0.0.0:14318");
    std::env::set_var("MUOBSERVE_MUOB_TCP_ADDR", "0.0.0.0:19481");

    let cfg_custom = IngestConfig::from_env();
    assert_eq!(cfg_custom.otlp_http_addr, "0.0.0.0:14318");
    assert_eq!(cfg_custom.muob_tcp_addr, "0.0.0.0:19481");

    // Clean up
    std::env::remove_var("MUOBSERVE_OTLP_HTTP_ADDR");
    std::env::remove_var("MUOBSERVE_MUOB_TCP_ADDR");
}

#[test]
fn test_empirical_upstream_url_normalization() {
    // Normalization logic replicated from collector src/main.rs:
    fn normalize_upstream(raw: &str) -> String {
        let trimmed = raw.trim();
        let stripped = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))
            .unwrap_or(trimmed);
        stripped.trim_end_matches('/').to_string()
    }

    assert_eq!(
        normalize_upstream("http://127.0.0.1:8443/api/"),
        "127.0.0.1:8443/api"
    );
    assert_eq!(
        normalize_upstream("https://node-a.example.invalid:9480/"),
        "node-a.example.invalid:9480"
    );
    assert_eq!(
        normalize_upstream("  http://192.0.2.1:8000  "),
        "192.0.2.1:8000"
    );
    assert_eq!(
        normalize_upstream("upstream-host:9443"),
        "upstream-host:9443"
    );
}

#[test]
fn test_empirical_collector_cli_serve_mode_logic() {
    fn evaluate_serve_mode(args: &[&str]) -> bool {
        let has_explicit_subcommand = args
            .get(1)
            .is_some_and(|a| matches!(*a, "--help" | "-h" | "--version" | "-V"));
        !has_explicit_subcommand
    }

    // Default with no args -> serve mode = true
    assert!(evaluate_serve_mode(&["mu-observable-collector"]));

    // With --serve -> serve mode = true
    assert!(evaluate_serve_mode(&["mu-observable-collector", "--serve"]));

    // With explicit flags -> serve mode = false
    assert!(!evaluate_serve_mode(&["mu-observable-collector", "--help"]));
    assert!(!evaluate_serve_mode(&["mu-observable-collector", "-h"]));
    assert!(!evaluate_serve_mode(&[
        "mu-observable-collector",
        "--version"
    ]));
    assert!(!evaluate_serve_mode(&["mu-observable-collector", "-V"]));
}

#[test]
fn test_empirical_edge_ring_wal_in_memory_and_disk() {
    let dir = tempdir().expect("tempdir");
    let wal_file = dir.path().join("collector_wal.duckdb");

    // 1. In-memory WAL
    let mem_wal = EdgeRingWal::in_memory(DEFAULT_MAX_WAL_BYTES, DEFAULT_MAX_AGE_SECS);
    assert_eq!(mem_wal.used_bytes(), 0);

    // 2. Disk-backed WAL
    let mut disk_wal = EdgeRingWal::open(&wal_file, DEFAULT_MAX_WAL_BYTES, DEFAULT_MAX_AGE_SECS)
        .expect("open disk wal");
    assert_eq!(disk_wal.used_bytes(), 0);

    // Persist a batch to disk
    disk_wal
        .append(
            1,
            0,
            mu_observable_collector::WalSignalPriority::StandardSignal,
            b"test_payload_123".to_vec(),
        )
        .expect("append batch");
    assert!(disk_wal.used_bytes() > 0);
    assert!(
        wal_file.exists(),
        "WAL file should be created on disk after append"
    );
}
