//! Streaming edge secret redaction prior to Edge WAL persistence (`M3.026`).

use crate::error::CollectorError;
use mu_observable_ipc::{
    decode_benchmark_run_batch, decode_log_batch, decode_metric_batch, decode_span_batch,
    decode_test_run_batch, encode_benchmark_run_batch, encode_log_batch, encode_metric_batch,
    encode_span_batch, encode_test_run_batch, BenchmarkRunEntry, DeterministicSecretRedactor,
    OtelLogEntry, OtelMetricEntry, OtelSpanEntry, SecretRedactor, TestCaseRunEntry,
    MSG_TYPE_ARROW_BENCH_RUNS, MSG_TYPE_ARROW_OTEL_LOGS, MSG_TYPE_ARROW_OTEL_METRICS,
    MSG_TYPE_ARROW_OTEL_SPANS, MSG_TYPE_ARROW_TEST_RUNS, REDACTED_PLACEHOLDER,
};

/// Result of scrubbing an incoming `MUOB` Arrow IPC payload prior to WAL persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrubbedArrowBatch {
    /// Re-encoded Apache Arrow IPC stream bytes with all secrets replaced by [`REDACTED_PLACEHOLDER`].
    pub payload: Vec<u8>,
    /// Number of records in the decoded and re-encoded batch.
    pub row_count: u32,
    /// True if the batch contains high-priority signals (warn/error logs, spans, metrics, tests, or benchmarks).
    pub high_priority: bool,
}

/// Edge-level secret scrubber implementing [`SecretRedactor`].
///
/// Combines [`DeterministicSecretRedactor`] (covering PEM private keys, Bearer tokens,
/// GitHub PATs `ghp_`/`github_pat_`, AWS keys, and key-value assignments such as `webhook_secret`)
/// with exact literal redaction of registered runtime secret environment values.
#[derive(Debug, Clone, Default)]
pub struct EdgeSecretScrubber {
    inner: DeterministicSecretRedactor,
    registered_secrets: Vec<String>,
}

impl EdgeSecretScrubber {
    /// Creates a new [`EdgeSecretScrubber`] with default pattern redaction.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: DeterministicSecretRedactor::new(),
            registered_secrets: Vec::new(),
        }
    }

    /// Creates an [`EdgeSecretScrubber`] pre-populated with literal secret values.
    #[must_use]
    pub fn with_secret_values<I, S>(secrets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut scrubber = Self::new();
        for secret in secrets {
            scrubber.register_secret_value(secret);
        }
        scrubber
    }

    /// Creates an [`EdgeSecretScrubber`] by reading and trimming the values of the specified
    /// environment variable names if present in the process environment.
    #[must_use]
    pub fn from_env_vars<I, S>(env_keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut scrubber = Self::new();
        for key in env_keys {
            if let Ok(val) = std::env::var(key.as_ref()) {
                scrubber.register_secret_value(val);
            }
        }
        scrubber
    }

    /// Registers a literal runtime secret value to be scrubbed before WAL persistence.
    /// Values shorter than 4 characters after trimming are ignored to avoid accidental false positives.
    pub fn register_secret_value(&mut self, secret: impl Into<String>) {
        let trimmed = secret.into().trim().to_string();
        if trimmed.len() >= 4 && !self.registered_secrets.contains(&trimmed) {
            self.registered_secrets.push(trimmed);
            // Sort longest-first so composite secrets are scrubbed before substrings.
            self.registered_secrets
                .sort_by_key(|s| std::cmp::Reverse(s.len()));
        }
    }

    /// Returns the number of registered literal secret values.
    #[must_use]
    pub fn registered_secret_count(&self) -> usize {
        self.registered_secrets.len()
    }

    /// Scrubs an [`OtelLogEntry`] (`body` and `attributes_json`) in place.
    pub fn scrub_log_entry(&self, entry: &mut OtelLogEntry) {
        entry.redact_in_place(self);
    }

    /// Scrubs a slice of [`OtelLogEntry`] records in place.
    pub fn scrub_log_batch(&self, entries: &mut [OtelLogEntry]) {
        for entry in entries {
            self.scrub_log_entry(entry);
        }
    }

    /// Scrubs an [`OtelSpanEntry`] (`status_message` and `attributes_json`) in place.
    pub fn scrub_span_entry(&self, entry: &mut OtelSpanEntry) {
        entry.redact_in_place(self);
    }

    /// Scrubs a slice of [`OtelSpanEntry`] records in place.
    pub fn scrub_span_batch(&self, entries: &mut [OtelSpanEntry]) {
        for entry in entries {
            self.scrub_span_entry(entry);
        }
    }

    /// Scrubs an [`OtelMetricEntry`] (`attributes_json`) in place.
    pub fn scrub_metric_entry(&self, entry: &mut OtelMetricEntry) {
        entry.attributes_json = self.redact(&entry.attributes_json);
    }

    /// Scrubs a slice of [`OtelMetricEntry`] records in place.
    pub fn scrub_metric_batch(&self, entries: &mut [OtelMetricEntry]) {
        for entry in entries {
            self.scrub_metric_entry(entry);
        }
    }

    /// Scrubs a [`TestCaseRunEntry`] (`failure_summary`) in place.
    pub fn scrub_test_run_entry(&self, entry: &mut TestCaseRunEntry) {
        if let Some(ref summary) = entry.failure_summary {
            entry.failure_summary = Some(self.redact(summary));
        }
    }

    /// Scrubs a slice of [`TestCaseRunEntry`] records in place.
    pub fn scrub_test_run_batch(&self, entries: &mut [TestCaseRunEntry]) {
        for entry in entries {
            self.scrub_test_run_entry(entry);
        }
    }

    /// Scrubs a [`BenchmarkRunEntry`] (`cpu_cluster` and `throughput_unit`) in place.
    pub fn scrub_benchmark_run_entry(&self, entry: &mut BenchmarkRunEntry) {
        entry.cpu_cluster = self.redact(&entry.cpu_cluster);
        if let Some(ref unit) = entry.throughput_unit {
            entry.throughput_unit = Some(self.redact(unit));
        }
    }

    /// Scrubs a slice of [`BenchmarkRunEntry`] records in place.
    pub fn scrub_benchmark_run_batch(&self, entries: &mut [BenchmarkRunEntry]) {
        for entry in entries {
            self.scrub_benchmark_run_entry(entry);
        }
    }

    /// Decodes an incoming Arrow IPC frame payload according to `msg_type`, scrubs all sensitive fields
    /// in place, and re-encodes the scrubbed Arrow IPC stream for Edge WAL persistence.
    pub fn scrub_arrow_frame_payload(
        &self,
        msg_type: u16,
        payload: &[u8],
    ) -> Result<ScrubbedArrowBatch, CollectorError> {
        match msg_type {
            MSG_TYPE_ARROW_OTEL_LOGS => {
                let mut logs = decode_log_batch(payload)?;
                self.scrub_log_batch(&mut logs);
                let high_priority = logs.iter().any(is_high_priority_log);
                let row_count = u32::try_from(logs.len()).unwrap_or(u32::MAX);
                let scrubbed = encode_log_batch(&logs)?;
                Ok(ScrubbedArrowBatch {
                    payload: scrubbed,
                    row_count,
                    high_priority,
                })
            }
            MSG_TYPE_ARROW_OTEL_SPANS => {
                let mut spans = decode_span_batch(payload)?;
                self.scrub_span_batch(&mut spans);
                let row_count = u32::try_from(spans.len()).unwrap_or(u32::MAX);
                let scrubbed = encode_span_batch(&spans)?;
                Ok(ScrubbedArrowBatch {
                    payload: scrubbed,
                    row_count,
                    high_priority: true,
                })
            }
            MSG_TYPE_ARROW_OTEL_METRICS => {
                let mut metrics = decode_metric_batch(payload)?;
                self.scrub_metric_batch(&mut metrics);
                let row_count = u32::try_from(metrics.len()).unwrap_or(u32::MAX);
                let scrubbed = encode_metric_batch(&metrics)?;
                Ok(ScrubbedArrowBatch {
                    payload: scrubbed,
                    row_count,
                    high_priority: true,
                })
            }
            MSG_TYPE_ARROW_TEST_RUNS => {
                let mut tests = decode_test_run_batch(payload)?;
                self.scrub_test_run_batch(&mut tests);
                let row_count = u32::try_from(tests.len()).unwrap_or(u32::MAX);
                let scrubbed = encode_test_run_batch(&tests)?;
                Ok(ScrubbedArrowBatch {
                    payload: scrubbed,
                    row_count,
                    high_priority: true,
                })
            }
            MSG_TYPE_ARROW_BENCH_RUNS => {
                let mut benches = decode_benchmark_run_batch(payload)?;
                self.scrub_benchmark_run_batch(&mut benches);
                let row_count = u32::try_from(benches.len()).unwrap_or(u32::MAX);
                let scrubbed = encode_benchmark_run_batch(&benches)?;
                Ok(ScrubbedArrowBatch {
                    payload: scrubbed,
                    row_count,
                    high_priority: true,
                })
            }
            other => Err(CollectorError::InvalidPayload(format!(
                "Unsupported Arrow message type for scrubbing: {other:#06x}"
            ))),
        }
    }
}

impl SecretRedactor for EdgeSecretScrubber {
    fn redact(&self, input: &str) -> String {
        if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(input) {
            self.redact_json_value(&mut json_val);
            if let Ok(serialized) = serde_json::to_string(&json_val) {
                return serialized;
            }
        }
        self.redact_plain_str(input)
    }
}

impl EdgeSecretScrubber {
    fn redact_plain_str(&self, input: &str) -> String {
        let mut current = self.inner.redact(input);
        for secret in &self.registered_secrets {
            if current.contains(secret.as_str()) {
                current = current.replace(secret.as_str(), REDACTED_PLACEHOLDER);
            }
        }
        current
    }

    fn redact_json_value(&self, val: &mut serde_json::Value) {
        match val {
            serde_json::Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    if is_sensitive_json_key(k) {
                        if v.is_string() {
                            *v = serde_json::Value::String(REDACTED_PLACEHOLDER.to_string());
                        } else {
                            self.redact_json_value(v);
                        }
                    } else {
                        self.redact_json_value(v);
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.redact_json_value(item);
                }
            }
            serde_json::Value::String(s) => {
                *s = self.redact_plain_str(s);
            }
            _ => {}
        }
    }
}

fn is_sensitive_json_key(key: &str) -> bool {
    let lower = key.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "webhook_secret"
            | "client_secret"
            | "password"
            | "api_key"
            | "apikey"
            | "secret"
            | "token"
            | "private_key"
            | "authorization"
    )
}

/// Returns `true` if a log entry has `WARN`, `ERROR`, or `FATAL` severity (`severity_number >= 13`).
#[must_use]
pub fn is_high_priority_log(entry: &OtelLogEntry) -> bool {
    if entry.severity_number >= 13 {
        return true;
    }
    let sev = entry.severity_text.trim();
    sev.eq_ignore_ascii_case("WARN")
        || sev.eq_ignore_ascii_case("WARNING")
        || sev.eq_ignore_ascii_case("ERROR")
        || sev.eq_ignore_ascii_case("FATAL")
        || sev.eq_ignore_ascii_case("CRITICAL")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_scrubber_redacts_patterns_and_registered_env_secrets() {
        let scrubber = EdgeSecretScrubber::with_secret_values([
            "whsec_custom_ci_webhook_998877",
            "step_ca_provisioner_pass_xyz123",
        ]);
        assert_eq!(scrubber.registered_secret_count(), 2);

        let raw = "Header Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig \
                   pat=ghp_1234567890abcdefABCDEF \
                   fine=github_pat_11AA22BB_33CC44DD \
                   webhook=whsec_custom_ci_webhook_998877 \
                   ca=step_ca_provisioner_pass_xyz123 \
                   -----BEGIN EC PRIVATE KEY-----\nMHcCAQEE...\n-----END EC PRIVATE KEY-----";

        let scrubbed = scrubber.redact(raw);
        assert!(!scrubbed.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(!scrubbed.contains("ghp_1234567890abcdefABCDEF"));
        assert!(!scrubbed.contains("github_pat_11AA22BB_33CC44DD"));
        assert!(!scrubbed.contains("whsec_custom_ci_webhook_998877"));
        assert!(!scrubbed.contains("step_ca_provisioner_pass_xyz123"));
        assert!(!scrubbed.contains("BEGIN EC PRIVATE KEY"));
        assert!(scrubbed.contains(REDACTED_PLACEHOLDER));
    }

    #[test]
    fn test_scrub_arrow_batches_zero_raw_leakage() {
        let scrubber = EdgeSecretScrubber::with_secret_values(["custom_env_token_secret_42"]);

        let logs = vec![OtelLogEntry {
            timestamp_unix_nano: 1_700_000_000_000_000_000,
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            span_id: "00f067aa0ba902b7".to_string(),
            severity_number: 17,
            severity_text: "ERROR".to_string(),
            service_name: "action-runner-worker".to_string(),
            node_id: "worker-riscv64".to_string(),
            body: "clone failed with ghp_secretToken999 and custom_env_token_secret_42".to_string(),
            attributes_json: r#"{"webhook_secret":"topsecret123"}"#.to_string(),
            job_id: Some("job-1".to_string()),
            stage_id: Some("build".to_string()),
        }];
        let raw_log_bytes = encode_log_batch(&logs).expect("encode logs");
        let res = scrubber
            .scrub_arrow_frame_payload(MSG_TYPE_ARROW_OTEL_LOGS, &raw_log_bytes)
            .expect("scrub log batch");
        assert_eq!(res.row_count, 1);
        assert!(res.high_priority);

        let decoded_logs = decode_log_batch(&res.payload).expect("decode scrubbed logs");
        assert!(!decoded_logs[0].body.contains("ghp_secretToken999"));
        assert!(!decoded_logs[0].body.contains("custom_env_token_secret_42"));
        assert!(!decoded_logs[0].attributes_json.contains("topsecret123"));
        assert!(decoded_logs[0].body.contains(REDACTED_PLACEHOLDER));

        let tests = vec![TestCaseRunEntry {
            job_id: "job-1".to_string(),
            repo_key: "lma1980/k3-core".to_string(),
            branch_key: "main".to_string(),
            commit_sha: "abcdef12".to_string(),
            crate_name: "k3-core".to_string(),
            test_binary: "k3_core".to_string(),
            test_name: "test_auth".to_string(),
            status: "failed".to_string(),
            duration_ms: 4.5,
            failure_summary: Some(
                "panicked with Bearer secret_jwt_token_value and custom_env_token_secret_42"
                    .to_string(),
            ),
            timestamp_unix_nano: 1_700_000_001_000_000_000,
            node_id: "worker-riscv64".to_string(),
            arch: "riscv64gc".to_string(),
        }];
        let raw_test_bytes = encode_test_run_batch(&tests).expect("encode tests");
        let scrubbed_test = scrubber
            .scrub_arrow_frame_payload(MSG_TYPE_ARROW_TEST_RUNS, &raw_test_bytes)
            .expect("scrub test batch");
        let decoded_tests =
            decode_test_run_batch(&scrubbed_test.payload).expect("decode scrubbed tests");
        let summary = decoded_tests[0].failure_summary.as_deref().unwrap();
        assert!(!summary.contains("secret_jwt_token_value"));
        assert!(!summary.contains("custom_env_token_secret_42"));
        assert!(summary.contains(REDACTED_PLACEHOLDER));
    }
}
