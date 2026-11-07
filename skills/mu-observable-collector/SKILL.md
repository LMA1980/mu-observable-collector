---
name: mu-observable-collector
description: "Configure and maintain the mu-observable-collector edge telemetry daemon, bounded DuckDB ring-buffer WAL, secret scrubbing, and mTLS forwarding."
---

# `mu-observable-collector` Edge Telemetry Agent Invariants

## 1. Self-Confining Startup Sandbox (`mu-ci-isolation`)

- `mu-observable-collector` confines itself at startup via `KernelSandbox` (Landlock V3+ allowlisting `/var/lib/muobserve-collector` read/write and `/etc/muobserve-collector` read-only, bounded `64 MiB` `RLIMIT_MEMLOCK`).

## 2. Edge Secret Scrubbing Before WAL Persistence

- Scrub all incoming OTLP/HTTP JSON (`127.0.0.1:4318/v1/{logs,traces,metrics}`) and `MUOB` Arrow streams through `DeterministicSecretRedactor` **before** writing to the bounded `256 MiB` `/var/lib/muobserve-collector/wal.duckdb` ring-buffer WAL or forwarding over mTLS.
