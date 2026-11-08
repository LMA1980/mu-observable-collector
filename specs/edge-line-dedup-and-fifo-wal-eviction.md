# Spec: Edge Single-Line Log Normalization, Bounded FIFO Deduplication & Disk-Space WAL Eviction

## Location: `specs/edge-line-dedup-and-fifo-wal-eviction.md`

### 1. Overview

`mu-observable-collector` enforces single-line log normalization (`1 line = 1 OtelLogEntry`), bounded FIFO line deduplication (`LineDeduplicator`), single-write WAL compaction, and strict FIFO eviction governed by retention TTL (`max_age_secs`), WAL byte ceiling (`max_wal_bytes`), and available physical disk space (`libc::statvfs` vs `min_free_disk_bytes`).

---

### 2. Single-Line Normalization & Deterministic Deduplication (`src/ingest.rs`)

#### 2.1 Multi-Line Splitting (`normalize_single_line_logs`)

When `CollectorIngestState` receives log batches via `OTLP/HTTP` (`/v1/logs`), `OTLP/gRPC`, or native `MUOB` Arrow IPC (`MSG_TYPE_ARROW_OTEL_LOGS`):
- Each `OtelLogEntry` is scrubbed in-place via `DeterministicSecretRedactor`.
- Any `OtelLogEntry` whose `body` contains newline characters (`\n`) is split into individual 1-line `OtelLogEntry` records (trimming trailing `\r` and dropping empty trailing newlines).
- `attributes_json` is enriched with deterministic `"line_no"` (`base_line_no + idx`, starting at `1` when unspecified) and `"stream"` (`"stdout"` or `"stderr"`).

#### 2.2 Bounded FIFO Deduplication Ring (`LineDeduplicator`)

Each normalized 1-line record is hashed via 64-bit FNV-1a (`compute_log_dedup_hash`):
- For CI job lines (`job_id.is_some() && line_no > 0`):
  $$\text{dedup\_hash} = \text{FNV1a}_{64}(\text{node\_id}, \text{service\_name}, \text{job\_id}, \text{stage\_id}, \text{line\_no}, \text{stream}, 0, \text{trim\_end}(\text{body}))$$
- For daemon and kernel lines:
  $$\text{dedup\_hash} = \text{FNV1a}_{64}(\text{node\_id}, \text{service\_name}, \text{job\_id}, \text{stage\_id}, \text{line\_no}, \text{stream}, \lfloor\text{timestamp\_unix\_nano} / 10^9\rfloor, \text{trim\_end}(\text{body}))$$

`LineDeduplicator` maintains a bounded FIFO ring (`VecDeque<u64>` + `HashSet<u64>`, default `DEFAULT_LOG_DEDUP_CAPACITY = 16,384`). Duplicate lines are dropped before `EdgeRingWal` persistence or upstream mTLS transmission. If all lines in an incoming batch are duplicates, ingestion returns `Ok(())` without writing an empty WAL batch.

---

### 3. Strict FIFO WAL Eviction & Write-Amplification Elimination (`src/wal.rs`)

#### 3.1 Strict FIFO Eviction (`EdgeRingWal::append_at`)

`EdgeRingWal` evicts the oldest queued batches strictly in FIFO order (`self.entries.pop_front()`) whenever any of the following conditions hold:
1. **TTL Expiration**: `now_unix_secs.saturating_sub(front.created_at_unix_secs) > self.max_age_secs` (default `86,400s` / `24h`).
2. **Physical Disk-Space Pressure (`libc::statvfs`)**: `available_disk_bytes(&self.storage_path) < self.min_free_disk_bytes` (`MUOBSERVE_MIN_FREE_DISK_BYTES`, default `512 MiB`).
3. **WAL Byte Ceiling**: `self.used_bytes + batch_len > self.max_wal_bytes` (default `256 MiB`).

#### 3.2 Single-Write Compaction (`acknowledge_and_truncate`)

When upstream `mu-observable-hub` acknowledges `up_to_seq_id`:
- `acknowledge_and_truncate` removes all entries with `seq_id <= up_to_seq_id` and persists to disk at most **once**.
- When `self.entries.is_empty()`, the WAL file is truncated directly to `0` bytes (`fs::File::create(&self.storage_path)`) without serializing or rewriting JSON envelopes.
