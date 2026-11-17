# mu-observable-collector

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs">
    <img src="https://hook.lma1980.duckdns.org/cards/LMA1980/mu-observable-collector/card.svg" alt="mu-observable-collector Factory Scorecard" width="520"/>
  </a>
</p>

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-observable-collector/status.svg" alt="CI Status"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-observable-collector/score.svg" alt="Quality Score"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-observable-collector/coverage.svg" alt="Coverage"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-observable-collector/benchmark.svg" alt="Benchmark"/></a>
</p>

______________________________________________________________________

Sandboxed node-level edge telemetry collector for the [`mu-observable`](https://github.com/LMA1980/mu-observable) distributed observability platform.

## Architectural Scope

- **Multi-Transport Ingestion (`OTLP/HTTP` + Native `MUOB` Arrow IPC + Log Tailing)**:
  - Local `OTLP/HTTP` listener (`127.0.0.1:4318`, `/v1/{traces,metrics,logs}` and `/healthz`) accepting standard OpenTelemetry JSON and Apache Arrow IPC payloads (`application/vnd.apache.arrow.stream`) from local agents including [`mu-observable-sentinel`](https://github.com/LMA1980/mu-observable-sentinel).
  - High-throughput zero-copy native `MUOB` Apache Arrow IPC listener over loopback TCP (`127.0.0.1:4319`) and Unix domain sockets using [`mu-observable-ipc`](https://github.com/LMA1980/mu-observable-ipc) framing for [`mu-ci-worker`](https://github.com/LMA1980/mu-ci-worker), [`mu-ci-tools`](https://github.com/LMA1980/mu-ci-tools), [`mu-cd-agent`](https://github.com/LMA1980/mu-cd-agent), and [`jero-manager`](https://github.com/LMA1980/jero-manager).
  - Optional local log file tailing configured via `MUOBSERVE_LOG_FILES` (or `MUOBSERVE_TAIL_FILES`).
- **Streaming Edge Secret Redaction**:
  - Deterministic scrubbing of bearer tokens, webhook secrets, API keys, and PEM private keys before any record touches the local Edge WAL or leaves the node.
- **Single-Line Normalization & Bounded FIFO Line Deduplication**:
  - Splits multi-line log payloads on `\n` into single-line `OtelLogEntry` records with `"line_no"` and `"stream"` metadata in `attributes_json` and deduplicates repeated lines via a 64-bit FNV-1a `dedup_hash` ring (`16,384` entries) before hitting the local WAL.
- **Bounded Edge Ring-Buffer WAL & Strict FIFO Disk-Space Eviction**:
  - Local write-ahead ring buffer (`/var/lib/muobserve-collector/wal.duckdb`, default `<= 256 MiB` / `24h`) enforcing strict FIFO (`pop_front`) eviction by TTL, `max_wal_bytes`, and remaining physical disk space (`libc::statvfs` vs `MUOBSERVE_MIN_FREE_DISK_BYTES`, default `512 MiB`), with zero-byte direct truncation when all batches are acknowledged. See [`specs/edge-line-dedup-and-fifo-wal-eviction.md`](specs/edge-line-dedup-and-fifo-wal-eviction.md).
- **Zero-Trust `step-ca` mTLS Upstream Streaming & [`mu-ci-isolation`](https://github.com/LMA1980/mu-ci-isolation)**:
  - Streams compressed Arrow & Fory batches over `rustls` mutual TLS to [`mu-observable-hub`](https://github.com/LMA1980/mu-observable-hub) with cryptographic client certificate SAN attribution, confined under [`mu-ci-isolation`](https://github.com/LMA1980/mu-ci-isolation) (`KernelSandbox`: Landlock V3+ & `cgroupv2`).

## Testing & Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
cargo build --workspace --all-targets
cargo test --workspace
cargo llvm-cov --workspace --summary-only
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test --workspace --lib
```

## License

Licensed under `AGPL-3.0-only`. See [`LICENSE`](LICENSE) for details.
