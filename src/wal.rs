//! Bounded `256 MiB` Edge Ring-Buffer Write-Ahead Log (`EdgeRingWal`) with priority backpressure eviction (`M3.029`).

use crate::error::CollectorError;
use mu_observable_ipc::{
    FLAG_HIGH_PRIORITY, MSG_TYPE_ARROW_BENCH_RUNS, MSG_TYPE_ARROW_OTEL_LOGS,
    MSG_TYPE_ARROW_OTEL_METRICS, MSG_TYPE_ARROW_OTEL_SPANS, MSG_TYPE_ARROW_TEST_RUNS,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default maximum Edge WAL capacity in bytes (`256 MiB` = `268_435_456` bytes).
pub const DEFAULT_MAX_WAL_BYTES: usize = 256 * 1024 * 1024;

/// Default maximum retention age in seconds (`24 hours` = `86_400` seconds).
pub const DEFAULT_MAX_AGE_SECS: u64 = 86_400;

/// Canonical production Edge WAL path on `MuObserve-collector` nodes.
pub const DEFAULT_WAL_PATH: &str = "/var/lib/muobserve-collector/wal.duckdb";

/// Priority class governing backpressure eviction order when `EdgeRingWal` reaches `max_wal_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WalSignalPriority {
    /// Debug, trace, and info logs (`severity_number < 13`) — evicted/dropped first under backpressure.
    LowDebugLog = 0,
    /// Standard OpenTelemetry spans and metrics — preserved over debug logs.
    StandardSignal = 1,
    /// Error/warn logs (`severity_number >= 13`), `test_case_runs`, and `benchmark_runs` — highest preservation priority.
    HighCritical = 2,
}

impl WalSignalPriority {
    /// Derives the [`WalSignalPriority`] from the wire `msg_type`, frame `flags`, and whether the batch
    /// contains high-severity records.
    #[must_use]
    pub const fn classify(msg_type: u16, flags: u32, high_severity: bool) -> Self {
        if (flags & FLAG_HIGH_PRIORITY) != 0 {
            return Self::HighCritical;
        }
        match msg_type {
            MSG_TYPE_ARROW_TEST_RUNS | MSG_TYPE_ARROW_BENCH_RUNS => Self::HighCritical,
            MSG_TYPE_ARROW_OTEL_LOGS => {
                if high_severity {
                    Self::HighCritical
                } else {
                    Self::LowDebugLog
                }
            }
            MSG_TYPE_ARROW_OTEL_SPANS | MSG_TYPE_ARROW_OTEL_METRICS => Self::StandardSignal,
            _ => Self::StandardSignal,
        }
    }
}

/// A single scrubbed Arrow IPC batch buffered in the [`EdgeRingWal`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalBatchEntry {
    pub seq_no: u64,
    pub msg_type: u16,
    pub flags: u32,
    pub priority: WalSignalPriority,
    pub created_at_secs: u64,
    pub acked: bool,
    pub payload: Vec<u8>,
}

/// Configuration for [`EdgeRingWal`].
#[derive(Debug, Clone)]
pub struct EdgeRingWalConfig {
    pub storage_path: Option<PathBuf>,
    pub max_wal_bytes: usize,
    pub max_age_secs: u64,
}

impl Default for EdgeRingWalConfig {
    fn default() -> Self {
        Self {
            storage_path: None,
            max_wal_bytes: DEFAULT_MAX_WAL_BYTES,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
        }
    }
}

/// On-disk snapshot envelope persisted when `storage_path` is configured.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedWalState {
    next_seq_no: u64,
    entries: Vec<WalBatchEntry>,
}

/// Bounded node-local ring-buffer WAL storing scrubbed Arrow IPC batches across network partitions.
#[derive(Debug)]
pub struct EdgeRingWal {
    config: EdgeRingWalConfig,
    next_seq_no: u64,
    used_bytes: usize,
    entries: VecDeque<WalBatchEntry>,
    evicted_acked_count: u64,
    evicted_expired_count: u64,
    dropped_low_priority_count: u64,
}

impl EdgeRingWal {
    /// Initializes an [`EdgeRingWal`] from `config`, reloading any existing persisted WAL entries from disk.
    pub fn new(config: EdgeRingWalConfig) -> Result<Self, CollectorError> {
        let mut wal = Self {
            config,
            next_seq_no: 1,
            used_bytes: 0,
            entries: VecDeque::new(),
            evicted_acked_count: 0,
            evicted_expired_count: 0,
            dropped_low_priority_count: 0,
        };

        if let Some(ref path) = wal.config.storage_path {
            if path.exists() {
                let bytes = fs::read(path)?;
                if !bytes.is_empty() {
                    let state: PersistedWalState = serde_json::from_slice(&bytes)?;
                    wal.next_seq_no = state.next_seq_no.max(1);
                    for entry in state.entries {
                        wal.used_bytes += entry.payload.len();
                        if entry.seq_no >= wal.next_seq_no {
                            wal.next_seq_no = entry.seq_no + 1;
                        }
                        wal.entries.push_back(entry);
                    }
                }
            }
        }

        Ok(wal)
    }

    /// Creates an in-memory [`EdgeRingWal`] with the specified capacity and retention bounds.
    #[must_use]
    pub fn in_memory(max_wal_bytes: usize, max_age_secs: u64) -> Self {
        Self {
            config: EdgeRingWalConfig {
                storage_path: None,
                max_wal_bytes,
                max_age_secs,
            },
            next_seq_no: 1,
            used_bytes: 0,
            entries: VecDeque::new(),
            evicted_acked_count: 0,
            evicted_expired_count: 0,
            dropped_low_priority_count: 0,
        }
    }

    /// Opens a file-backed [`EdgeRingWal`] at `path`.
    pub fn open(
        path: impl Into<PathBuf>,
        max_wal_bytes: usize,
        max_age_secs: u64,
    ) -> Result<Self, CollectorError> {
        Self::new(EdgeRingWalConfig {
            storage_path: Some(path.into()),
            max_wal_bytes,
            max_age_secs,
        })
    }

    /// Appends a scrubbed batch using the current system wall-clock timestamp.
    pub fn append(
        &mut self,
        msg_type: u16,
        flags: u32,
        priority: WalSignalPriority,
        payload: Vec<u8>,
    ) -> Result<Option<u64>, CollectorError> {
        self.append_at(msg_type, flags, priority, payload, now_unix_secs())
    }

    /// Appends a scrubbed batch at `now_secs`, enforcing `max_wal_bytes` and `max_age_secs`.
    ///
    /// Returns `Ok(Some(seq_no))` when the batch is persisted, or `Ok(None)` if the incoming batch
    /// is low-priority (`LowDebugLog`) and dropped under backpressure to preserve higher-priority batches.
    pub fn append_at(
        &mut self,
        msg_type: u16,
        flags: u32,
        priority: WalSignalPriority,
        payload: Vec<u8>,
        now_secs: u64,
    ) -> Result<Option<u64>, CollectorError> {
        let batch_len = payload.len();
        if batch_len > self.config.max_wal_bytes {
            return Err(CollectorError::WalCapacityExceeded(format!(
                "Single batch size ({batch_len} bytes) exceeds max_wal_bytes ({} bytes)",
                self.config.max_wal_bytes
            )));
        }

        // Step 1: Always prune acknowledged and expired batches first when space is needed.
        if self.used_bytes + batch_len > self.config.max_wal_bytes {
            self.evict_acknowledged();
        }
        if self.used_bytes + batch_len > self.config.max_wal_bytes {
            self.evict_expired(now_secs);
        }

        // Step 2: Priority-aware backpressure eviction.
        if self.used_bytes + batch_len > self.config.max_wal_bytes {
            if priority == WalSignalPriority::LowDebugLog {
                // Incoming debug log may only evict older LowDebugLog entries, never spans/metrics/errors/tests/benchmarks.
                let reclaimable_low: usize = self
                    .entries
                    .iter()
                    .filter(|e| e.priority == WalSignalPriority::LowDebugLog)
                    .map(|e| e.payload.len())
                    .sum();
                let available_after_low =
                    self.config.max_wal_bytes.saturating_sub(self.used_bytes) + reclaimable_low;
                if available_after_low < batch_len {
                    self.dropped_low_priority_count += 1;
                    return Ok(None);
                }
                while self.used_bytes + batch_len > self.config.max_wal_bytes {
                    if !self.evict_oldest_with_priority(WalSignalPriority::LowDebugLog) {
                        self.dropped_low_priority_count += 1;
                        return Ok(None);
                    }
                }
            } else {
                // Higher-priority incoming batch: evict LowDebugLog first, then StandardSignal, then oldest HighCritical.
                while self.used_bytes + batch_len > self.config.max_wal_bytes {
                    if self.evict_oldest_with_priority(WalSignalPriority::LowDebugLog) {
                        continue;
                    }
                    if self.evict_oldest_with_priority(WalSignalPriority::StandardSignal) {
                        continue;
                    }
                    if !self.evict_oldest_with_priority(WalSignalPriority::HighCritical) {
                        break;
                    }
                }
            }
        }

        let seq_no = self.next_seq_no;
        self.next_seq_no += 1;
        let effective_flags = if priority == WalSignalPriority::HighCritical {
            flags | FLAG_HIGH_PRIORITY
        } else {
            flags
        };

        self.used_bytes += batch_len;
        self.entries.push_back(WalBatchEntry {
            seq_no,
            msg_type,
            flags: effective_flags,
            priority,
            created_at_secs: now_secs,
            acked: false,
            payload,
        });

        self.persist_to_disk()?;
        Ok(Some(seq_no))
    }

    /// Marks the batch with `seq_no` as acknowledged (`acked = true`).
    pub fn acknowledge(&mut self, seq_no: u64) -> Result<bool, CollectorError> {
        let mut found = false;
        for entry in &mut self.entries {
            if entry.seq_no == seq_no {
                entry.acked = true;
                found = true;
                break;
            }
        }
        if found {
            self.persist_to_disk()?;
        }
        Ok(found)
    }

    /// Marks `seq_no` as acknowledged and immediately truncates all acknowledged batches from the WAL.
    pub fn acknowledge_and_truncate(&mut self, seq_no: u64) -> Result<bool, CollectorError> {
        let found = self.acknowledge(seq_no)?;
        if found {
            self.evict_acknowledged();
            self.persist_to_disk()?;
        }
        Ok(found)
    }

    /// Truncates all acknowledged batches (`acked == true`) and persists the updated WAL state.
    pub fn truncate_acknowledged(&mut self) -> Result<usize, CollectorError> {
        let removed = self.evict_acknowledged();
        if removed > 0 {
            self.persist_to_disk()?;
        }
        Ok(removed)
    }

    /// Prunes batches older than `max_age_secs` relative to `now_secs`.
    pub fn prune_expired(&mut self, now_secs: u64) -> Result<usize, CollectorError> {
        let removed = self.evict_expired(now_secs);
        if removed > 0 {
            self.persist_to_disk()?;
        }
        Ok(removed)
    }

    /// Returns all unacknowledged (`!acked`) batches in ascending sequence order.
    #[must_use]
    pub fn pending_batches(&self) -> Vec<WalBatchEntry> {
        self.entries.iter().filter(|e| !e.acked).cloned().collect()
    }

    /// Returns all entries currently stored in the ring buffer (both pending and acknowledged).
    #[must_use]
    pub fn all_entries(&self) -> Vec<WalBatchEntry> {
        self.entries.iter().cloned().collect()
    }

    /// Total payload bytes currently buffered in the WAL.
    #[must_use]
    pub const fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    /// Configured maximum WAL byte ceiling.
    #[must_use]
    pub const fn max_wal_bytes(&self) -> usize {
        self.config.max_wal_bytes
    }

    /// Number of batches currently in the WAL.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the WAL contains no batches.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Next monotonically increasing sequence number to be assigned.
    #[must_use]
    pub const fn next_seq_no(&self) -> u64 {
        self.next_seq_no
    }

    /// Count of low-priority debug log batches dropped or evicted due to backpressure.
    #[must_use]
    pub const fn dropped_low_priority_count(&self) -> u64 {
        self.dropped_low_priority_count
    }

    /// Count of acknowledged batches evicted.
    #[must_use]
    pub const fn evicted_acked_count(&self) -> u64 {
        self.evicted_acked_count
    }

    /// Count of expired batches evicted.
    #[must_use]
    pub const fn evicted_expired_count(&self) -> u64 {
        self.evicted_expired_count
    }

    /// Optional disk path backing this WAL.
    #[must_use]
    pub fn storage_path(&self) -> Option<&Path> {
        self.config.storage_path.as_deref()
    }

    fn evict_acknowledged(&mut self) -> usize {
        let mut removed = 0usize;
        let mut retained = VecDeque::with_capacity(self.entries.len());
        while let Some(entry) = self.entries.pop_front() {
            if entry.acked {
                self.used_bytes = self.used_bytes.saturating_sub(entry.payload.len());
                self.evicted_acked_count += 1;
                removed += 1;
            } else {
                retained.push_back(entry);
            }
        }
        self.entries = retained;
        removed
    }

    fn evict_expired(&mut self, now_secs: u64) -> usize {
        let mut removed = 0usize;
        let max_age = self.config.max_age_secs;
        let mut retained = VecDeque::with_capacity(self.entries.len());
        while let Some(entry) = self.entries.pop_front() {
            if now_secs.saturating_sub(entry.created_at_secs) > max_age {
                self.used_bytes = self.used_bytes.saturating_sub(entry.payload.len());
                self.evicted_expired_count += 1;
                removed += 1;
            } else {
                retained.push_back(entry);
            }
        }
        self.entries = retained;
        removed
    }

    fn evict_oldest_with_priority(&mut self, target: WalSignalPriority) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| e.priority == target) {
            if let Some(removed) = self.entries.remove(pos) {
                self.used_bytes = self.used_bytes.saturating_sub(removed.payload.len());
                if target == WalSignalPriority::LowDebugLog {
                    self.dropped_low_priority_count += 1;
                }
                return true;
            }
        }
        false
    }

    fn persist_to_disk(&self) -> Result<(), CollectorError> {
        let Some(ref path) = self.config.storage_path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let state = PersistedWalState {
            next_seq_no: self.next_seq_no,
            entries: self.entries.iter().cloned().collect(),
        };
        let encoded = serde_json::to_vec(&state)?;
        let tmp_path = path.with_extension("duckdb.tmp");
        fs::write(&tmp_path, &encoded)?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }
}

/// Returns the current UNIX timestamp in seconds.
#[must_use]
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_wal_constants_256_mib() {
        assert_eq!(DEFAULT_MAX_WAL_BYTES, 256 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_AGE_SECS, 86_400);
    }

    #[test]
    fn test_wal_evicts_acknowledged_and_expired_first() {
        let mut wal = EdgeRingWal::in_memory(100, 60);

        let s1 = wal
            .append_at(
                MSG_TYPE_ARROW_OTEL_SPANS,
                0,
                WalSignalPriority::StandardSignal,
                vec![1u8; 40],
                1000,
            )
            .expect("append s1")
            .expect("seq 1");
        let _s2 = wal
            .append_at(
                MSG_TYPE_ARROW_OTEL_SPANS,
                0,
                WalSignalPriority::StandardSignal,
                vec![2u8; 40],
                1000,
            )
            .expect("append s2")
            .expect("seq 2");

        // Mark s1 as acknowledged (without truncating yet)
        wal.acknowledge(s1).expect("ack s1");
        assert_eq!(wal.used_bytes(), 80);

        // Appending 40 bytes exceeds 100 bytes -> must evict acknowledged s1 first
        let s3 = wal
            .append_at(
                MSG_TYPE_ARROW_OTEL_SPANS,
                0,
                WalSignalPriority::StandardSignal,
                vec![3u8; 40],
                1010,
            )
            .expect("append s3")
            .expect("seq 3");
        assert_eq!(s3, 3);
        assert_eq!(wal.evicted_acked_count(), 1);
        assert_eq!(wal.len(), 2);

        // Advance time past max_age_secs (60s) so s2 (created at 1000) expires at 1065
        let s4 = wal
            .append_at(
                MSG_TYPE_ARROW_OTEL_SPANS,
                0,
                WalSignalPriority::StandardSignal,
                vec![4u8; 40],
                1065,
            )
            .expect("append s4")
            .expect("seq 4");
        assert_eq!(s4, 4);
        assert_eq!(wal.evicted_expired_count(), 1);
        let pending = wal.pending_batches();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].seq_no, 3);
        assert_eq!(pending[1].seq_no, 4);
    }

    #[test]
    fn test_wal_priority_backpressure_drops_debug_logs_before_errors_tests_and_benchmarks() {
        let mut wal = EdgeRingWal::in_memory(120, 86_400);

        // 1. Enqueue a low-priority debug log batch (40 bytes)
        let debug_seq = wal
            .append_at(
                MSG_TYPE_ARROW_OTEL_LOGS,
                0,
                WalSignalPriority::LowDebugLog,
                vec![0xAA; 40],
                2000,
            )
            .expect("append debug")
            .expect("seq 1");
        assert_eq!(debug_seq, 1);

        // 2. Enqueue a high-priority error log batch (40 bytes)
        let err_seq = wal
            .append_at(
                MSG_TYPE_ARROW_OTEL_LOGS,
                FLAG_HIGH_PRIORITY,
                WalSignalPriority::HighCritical,
                vec![0xBB; 40],
                2001,
            )
            .expect("append error log")
            .expect("seq 2");
        assert_eq!(err_seq, 2);

        // 3. Enqueue a high-priority test_case_runs batch (40 bytes) -> WAL is now at 120 / 120 bytes
        let test_seq = wal
            .append_at(
                MSG_TYPE_ARROW_TEST_RUNS,
                FLAG_HIGH_PRIORITY,
                WalSignalPriority::HighCritical,
                vec![0xCC; 40],
                2002,
            )
            .expect("append test runs")
            .expect("seq 3");
        assert_eq!(test_seq, 3);
        assert_eq!(wal.used_bytes(), 120);

        // 4. Enqueue a high-priority benchmark_runs batch (40 bytes) -> must evict debug_seq (1), preserving err_seq (2) & test_seq (3)!
        let bench_seq = wal
            .append_at(
                MSG_TYPE_ARROW_BENCH_RUNS,
                FLAG_HIGH_PRIORITY,
                WalSignalPriority::HighCritical,
                vec![0xDD; 40],
                2003,
            )
            .expect("append benchmark runs")
            .expect("seq 4");
        assert_eq!(bench_seq, 4);
        assert_eq!(wal.used_bytes(), 120);

        let pending_seqs: Vec<u64> = wal
            .pending_batches()
            .into_iter()
            .map(|b| b.seq_no)
            .collect();
        assert_eq!(pending_seqs, vec![2, 3, 4]);

        // 5. Now WAL is 100% full of HighCritical batches (seqs 2, 3, 4).
        // Attempt to append a LowDebugLog batch -> must be dropped (`Ok(None)`) without evicting any HighCritical batch!
        let dropped = wal
            .append_at(
                MSG_TYPE_ARROW_OTEL_LOGS,
                0,
                WalSignalPriority::LowDebugLog,
                vec![0xEE; 40],
                2004,
            )
            .expect("append low debug under full critical WAL");
        assert_eq!(dropped, None);
        assert_eq!(wal.dropped_low_priority_count(), 2);
        let still_pending: Vec<u64> = wal
            .pending_batches()
            .into_iter()
            .map(|b| b.seq_no)
            .collect();
        assert_eq!(still_pending, vec![2, 3, 4]);
    }

    #[test]
    fn test_wal_disk_persistence_and_reload() {
        let dir = tempdir().expect("tempdir");
        let wal_path = dir.path().join("wal.duckdb");

        {
            let mut wal = EdgeRingWal::open(&wal_path, 1024, 3600).expect("open wal");
            let s1 = wal
                .append_at(
                    MSG_TYPE_ARROW_TEST_RUNS,
                    FLAG_HIGH_PRIORITY,
                    WalSignalPriority::HighCritical,
                    b"batch-1".to_vec(),
                    500,
                )
                .unwrap()
                .unwrap();
            let _s2 = wal
                .append_at(
                    MSG_TYPE_ARROW_BENCH_RUNS,
                    FLAG_HIGH_PRIORITY,
                    WalSignalPriority::HighCritical,
                    b"batch-2".to_vec(),
                    501,
                )
                .unwrap()
                .unwrap();
            wal.acknowledge_and_truncate(s1)
                .expect("ack and truncate s1");
        }

        let reloaded = EdgeRingWal::open(&wal_path, 1024, 3600).expect("reload wal");
        let pending = reloaded.pending_batches();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].seq_no, 2);
        assert_eq!(pending[0].payload, b"batch-2");
        assert_eq!(reloaded.next_seq_no(), 3);
    }
}
