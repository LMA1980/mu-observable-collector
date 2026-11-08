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

---

Sandboxed node-level edge telemetry collector for the **MuObserve** distributed observability platform.

## Architectural Scope

- **Dual Ingestion (`OTLP` + Native `Apache Arrow IPC`)**:
  - Local `OTLP/gRPC` and `OTLP/HTTP` listeners for standard OpenTelemetry traces, metrics, and logs.
  - High-throughput zero-copy Apache Arrow IPC ingestion for `ActionRunner-rs`, `ActionRunner-tools`, `MuConDe-agent`, and `k3-manager`.
- **Streaming Edge Secret Redaction**:
  - Deterministic scrubbing of bearer tokens, webhook secrets, API keys, and PEM private keys before any record touches the local Edge WAL or leaves the node.
- **Single-Line Normalization & Bounded FIFO Line Deduplication**:
  - Splits multi-line log payloads on `\n` into single-line `OtelLogEntry` records with `"line_no"` and `"stream"` metadata in `attributes_json` and deduplicates repeated lines via a 64-bit FNV-1a `dedup_hash` ring (`16,384` entries) before hitting the local WAL.
- **Bounded Edge Ring-Buffer WAL & Strict FIFO Disk-Space Eviction**:
  - Local write-ahead ring buffer (`/var/lib/muobserve-collector/wal.duckdb`, default `<= 256 MiB` / `24h`) enforcing strict FIFO (`pop_front`) eviction by TTL, `max_wal_bytes`, and remaining physical disk space (`libc::statvfs` vs `MUOBSERVE_MIN_FREE_DISK_BYTES`, default `512 MiB`), with zero-byte direct truncation when all batches are acknowledged. See [`specs/edge-line-dedup-and-fifo-wal-eviction.md`](specs/edge-line-dedup-and-fifo-wal-eviction.md).
- **Zero-Trust `step-ca` mTLS Upstream Streaming & `MuIsolation`**:
  - Streams compressed Arrow & Fory batches over `rustls` mutual TLS to the central `MuObserve` server with cryptographic client certificate SAN attribution, confined under `MuIsolation` (`KernelSandbox`: Landlock V3+ & `cgroupv2`).

## License

Licensed under `AGPL-3.0-only`. See [`LICENSE`](LICENSE) for details.
