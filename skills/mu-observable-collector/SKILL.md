---
name: mu-observable-collector
description: "Configure and maintain the mu-observable-collector edge telemetry daemon, bounded DuckDB ring-buffer WAL, secret scrubbing, and mTLS forwarding."
---

# `mu-observable-collector` Edge Telemetry Agent Invariants

## 1. Self-Confining Startup Sandbox (`mu-ci-isolation`)

- `mu-observable-collector` confines itself at startup via `KernelSandbox` (Landlock V3+ allowlisting `/var/lib/muobserve-collector` read/write and `/etc/muobserve-collector` read-only, bounded `64 MiB` `RLIMIT_MEMLOCK`).

## 2. Edge Secret Scrubbing, Single-Line Deduplication & Strict FIFO WAL Eviction

- Scrub all incoming OTLP/HTTP JSON (`127.0.0.1:4318/v1/{logs,traces,metrics}`) and `MUOB` Arrow streams through `DeterministicSecretRedactor` **before** writing to the bounded `256 MiB` `/var/lib/muobserve-collector/wal.duckdb` ring-buffer WAL or forwarding over mTLS.
- Normalize multi-line `OtelLogEntry` payloads into single-line records with `"line_no"` and `"stream"` in `attributes_json` and deduplicate via the bounded 16,384-entry FIFO `LineDeduplicator` (`compute_log_dedup_hash`).
- Enforce strict FIFO (`pop_front`) WAL eviction on TTL expiration (`max_age_secs`), `max_wal_bytes`, and physical disk-space pressure (`libc::statvfs` vs `MUOBSERVE_MIN_FREE_DISK_BYTES`, default `512 MiB`), truncating the WAL directly to `0` bytes when empty.
