//! Local OTLP (`/v1/traces`, `/v1/metrics`, `/v1/logs`, `/healthz`) and native `MUOB`
//! Apache Arrow IPC ingestion listeners (`M3.025`).

use crate::error::CollectorError;
use crate::scrubber::{is_high_priority_log, EdgeSecretScrubber};
use crate::wal::{EdgeRingWal, WalSignalPriority};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use mu_observable_ipc::{
    create_fory_registry, encode_log_batch, encode_metric_batch, encode_span_batch, read_frame,
    write_frame, IpcHeader, OtelLogEntry, OtelMetricEntry, OtelSpanEntry, WalBatchAck,
    FLAG_HIGH_PRIORITY, MSG_TYPE_ARROW_OTEL_LOGS, MSG_TYPE_ARROW_OTEL_METRICS,
    MSG_TYPE_ARROW_OTEL_SPANS, MSG_TYPE_WAL_ACK,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Default loopback OTLP HTTP address (`127.0.0.1:4318`).
pub const DEFAULT_OTLP_HTTP_ADDR: &str = "127.0.0.1:4318";

/// Default loopback native Arrow IPC TCP address (`127.0.0.1:4319`).
pub const DEFAULT_MUOB_TCP_ADDR: &str = "127.0.0.1:4319";

/// Configuration for the node-local OTLP HTTP and native `MUOB` Arrow IPC ingestion listeners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestConfig {
    pub otlp_http_addr: String,
    pub muob_tcp_addr: String,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            otlp_http_addr: DEFAULT_OTLP_HTTP_ADDR.to_string(),
            muob_tcp_addr: DEFAULT_MUOB_TCP_ADDR.to_string(),
        }
    }
}

impl IngestConfig {
    /// Resolves [`IngestConfig`] from `MUOBSERVE_OTLP_HTTP_ADDR` and `MUOBSERVE_MUOB_TCP_ADDR`,
    /// falling back to defaults [`DEFAULT_OTLP_HTTP_ADDR`] and [`DEFAULT_MUOB_TCP_ADDR`].
    #[must_use]
    pub fn from_env() -> Self {
        let otlp_http_addr = std::env::var("MUOBSERVE_OTLP_HTTP_ADDR")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_OTLP_HTTP_ADDR.to_string());
        let muob_tcp_addr = std::env::var("MUOBSERVE_MUOB_TCP_ADDR")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_MUOB_TCP_ADDR.to_string());
        Self {
            otlp_http_addr,
            muob_tcp_addr,
        }
    }
}

/// Shared state for the node-local `MuObserve-collector` ingestion endpoints.
#[derive(Clone)]
pub struct CollectorIngestState {
    pub wal: Arc<Mutex<EdgeRingWal>>,
    pub scrubber: Arc<EdgeSecretScrubber>,
    pub default_node_id: String,
    pub default_arch: String,
}

impl CollectorIngestState {
    /// Creates a new [`CollectorIngestState`] sharing the provided [`EdgeRingWal`] and [`EdgeSecretScrubber`].
    #[must_use]
    pub fn new(
        wal: Arc<Mutex<EdgeRingWal>>,
        scrubber: Arc<EdgeSecretScrubber>,
        default_node_id: impl Into<String>,
        default_arch: impl Into<String>,
    ) -> Self {
        Self {
            wal,
            scrubber,
            default_node_id: default_node_id.into(),
            default_arch: default_arch.into(),
        }
    }
}

/// JSON response returned by `/v1/traces`, `/v1/metrics`, and `/v1/logs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtlpIngestResponse {
    pub accepted_records: u32,
    pub wal_sequence: Option<u64>,
    pub dropped_backpressure: bool,
}

/// Builds the Axum [`Router`] serving `/healthz`, `/v1/traces`, `/v1/metrics`, and `/v1/logs`.
pub fn build_otlp_router(state: CollectorIngestState) -> Router {
    Router::new()
        .route("/healthz", get(handle_healthz))
        .route("/v1/traces", post(handle_otlp_traces))
        .route("/v1/metrics", post(handle_otlp_metrics))
        .route("/v1/logs", post(handle_otlp_logs))
        .with_state(state)
}

async fn handle_healthz(State(state): State<CollectorIngestState>) -> impl IntoResponse {
    let wal = state.wal.lock().await;
    let body = serde_json::json!({
        "status": "ok",
        "node_id": state.default_node_id,
        "wal_used_bytes": wal.used_bytes(),
        "wal_max_bytes": wal.max_wal_bytes(),
        "wal_pending_batches": wal.pending_batches().len(),
    });
    (StatusCode::OK, Json(body))
}

async fn handle_otlp_traces(
    State(state): State<CollectorIngestState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<OtlpIngestResponse>), (StatusCode, String)> {
    let is_arrow = is_arrow_content_type(&headers);
    let mut spans = if is_arrow {
        mu_observable_ipc::decode_span_batch(&body).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid Arrow span batch: {e}"),
            )
        })?
    } else {
        parse_otlp_traces_json(&body, &state.default_node_id)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    };

    if spans.is_empty() {
        return Ok((
            StatusCode::OK,
            Json(OtlpIngestResponse {
                accepted_records: 0,
                wal_sequence: None,
                dropped_backpressure: false,
            }),
        ));
    }

    state.scrubber.scrub_span_batch(&mut spans);
    let accepted_records = u32::try_from(spans.len()).unwrap_or(u32::MAX);
    let encoded = encode_span_batch(&spans)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut wal = state.wal.lock().await;
    let seq = wal
        .append(
            MSG_TYPE_ARROW_OTEL_SPANS,
            0,
            WalSignalPriority::StandardSignal,
            encoded,
        )
        .map_err(|e| (StatusCode::INSUFFICIENT_STORAGE, e.to_string()))?;

    Ok((
        StatusCode::OK,
        Json(OtlpIngestResponse {
            accepted_records,
            wal_sequence: seq,
            dropped_backpressure: seq.is_none(),
        }),
    ))
}

async fn handle_otlp_metrics(
    State(state): State<CollectorIngestState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<OtlpIngestResponse>), (StatusCode, String)> {
    let is_arrow = is_arrow_content_type(&headers);
    let mut metrics = if is_arrow {
        mu_observable_ipc::decode_metric_batch(&body).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid Arrow metric batch: {e}"),
            )
        })?
    } else {
        parse_otlp_metrics_json(&body, &state.default_node_id, &state.default_arch)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    };

    if metrics.is_empty() {
        return Ok((
            StatusCode::OK,
            Json(OtlpIngestResponse {
                accepted_records: 0,
                wal_sequence: None,
                dropped_backpressure: false,
            }),
        ));
    }

    state.scrubber.scrub_metric_batch(&mut metrics);
    let accepted_records = u32::try_from(metrics.len()).unwrap_or(u32::MAX);
    let encoded = encode_metric_batch(&metrics)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut wal = state.wal.lock().await;
    let seq = wal
        .append(
            MSG_TYPE_ARROW_OTEL_METRICS,
            0,
            WalSignalPriority::StandardSignal,
            encoded,
        )
        .map_err(|e| (StatusCode::INSUFFICIENT_STORAGE, e.to_string()))?;

    Ok((
        StatusCode::OK,
        Json(OtlpIngestResponse {
            accepted_records,
            wal_sequence: seq,
            dropped_backpressure: seq.is_none(),
        }),
    ))
}

async fn handle_otlp_logs(
    State(state): State<CollectorIngestState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<OtlpIngestResponse>), (StatusCode, String)> {
    let is_arrow = is_arrow_content_type(&headers);
    let mut logs = if is_arrow {
        mu_observable_ipc::decode_log_batch(&body).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid Arrow log batch: {e}"),
            )
        })?
    } else {
        parse_otlp_logs_json(&body, &state.default_node_id)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    };

    if logs.is_empty() {
        return Ok((
            StatusCode::OK,
            Json(OtlpIngestResponse {
                accepted_records: 0,
                wal_sequence: None,
                dropped_backpressure: false,
            }),
        ));
    }

    state.scrubber.scrub_log_batch(&mut logs);
    let high_sev = logs.iter().any(is_high_priority_log);
    let priority = if high_sev {
        WalSignalPriority::HighCritical
    } else {
        WalSignalPriority::LowDebugLog
    };
    let flags = if high_sev { FLAG_HIGH_PRIORITY } else { 0 };
    let accepted_records = u32::try_from(logs.len()).unwrap_or(u32::MAX);
    let encoded =
        encode_log_batch(&logs).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut wal = state.wal.lock().await;
    let seq = wal
        .append(MSG_TYPE_ARROW_OTEL_LOGS, flags, priority, encoded)
        .map_err(|e| (StatusCode::INSUFFICIENT_STORAGE, e.to_string()))?;

    Ok((
        StatusCode::OK,
        Json(OtlpIngestResponse {
            accepted_records: if seq.is_some() { accepted_records } else { 0 },
            wal_sequence: seq,
            dropped_backpressure: seq.is_none(),
        }),
    ))
}

fn is_arrow_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("arrow") || ct.contains("octet-stream"))
}

/// Parses either a direct JSON array of [`OtelSpanEntry`] or a standard OTLP/HTTP JSON
/// `ExportTraceServiceRequest` (`{"resourceSpans": [...]}`) into canonical [`OtelSpanEntry`] records.
pub fn parse_otlp_traces_json(
    bytes: &[u8],
    default_node_id: &str,
) -> Result<Vec<OtelSpanEntry>, CollectorError> {
    if let Ok(direct) = serde_json::from_slice::<Vec<OtelSpanEntry>>(bytes) {
        return Ok(direct);
    }
    let root: Value = serde_json::from_slice(bytes)?;
    if let Some(arr) = root.get("spans").and_then(Value::as_array) {
        if let Ok(direct) = serde_json::from_value::<Vec<OtelSpanEntry>>(Value::Array(arr.clone()))
        {
            return Ok(direct);
        }
    }

    let mut out = Vec::new();
    let Some(res_spans) = root.get("resourceSpans").and_then(Value::as_array) else {
        return Err(CollectorError::InvalidPayload(
            "Expected OTLP resourceSpans or Vec<OtelSpanEntry> JSON".to_string(),
        ));
    };

    for rs in res_spans {
        let res_attrs = extract_otlp_attributes(rs.pointer("/resource/attributes"));
        let service_name = res_attrs
            .get("service.name")
            .and_then(Value::as_str)
            .unwrap_or("unknown-service")
            .to_string();
        let node_id = res_attrs
            .get("node.id")
            .or_else(|| res_attrs.get("host.name"))
            .and_then(Value::as_str)
            .unwrap_or(default_node_id)
            .to_string();

        if let Some(scope_spans) = rs.get("scopeSpans").and_then(Value::as_array) {
            for ss in scope_spans {
                if let Some(spans) = ss.get("spans").and_then(Value::as_array) {
                    for s in spans {
                        let trace_id = s
                            .get("traceId")
                            .and_then(Value::as_str)
                            .unwrap_or("00000000000000000000000000000000")
                            .to_string();
                        let span_id = s
                            .get("spanId")
                            .and_then(Value::as_str)
                            .unwrap_or("0000000000000000")
                            .to_string();
                        let parent_span_id = s
                            .get("parentSpanId")
                            .and_then(Value::as_str)
                            .filter(|p| !p.is_empty())
                            .map(ToString::to_string);
                        let span_name = s
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("unnamed-span")
                            .to_string();
                        let span_kind = match s.get("kind") {
                            Some(Value::String(k)) => k.clone(),
                            Some(Value::Number(n)) => match n.as_u64() {
                                Some(2) => "SERVER".to_string(),
                                Some(3) => "CLIENT".to_string(),
                                Some(4) => "PRODUCER".to_string(),
                                Some(5) => "CONSUMER".to_string(),
                                _ => "INTERNAL".to_string(),
                            },
                            _ => "INTERNAL".to_string(),
                        };
                        let start_time_unix_nano =
                            parse_unix_nano(s.get("startTimeUnixNano")).unwrap_or(0);
                        let end_time_unix_nano = parse_unix_nano(s.get("endTimeUnixNano"))
                            .unwrap_or(start_time_unix_nano);
                        let duration_ns = end_time_unix_nano
                            .saturating_sub(start_time_unix_nano)
                            .try_into()
                            .unwrap_or(0);
                        let status_code = s
                            .pointer("/status/code")
                            .and_then(|v| match v {
                                Value::String(c) => Some(c.clone()),
                                Value::Number(n) => match n.as_u64() {
                                    Some(1) => Some("OK".to_string()),
                                    Some(2) => Some("ERROR".to_string()),
                                    _ => Some("UNSET".to_string()),
                                },
                                _ => None,
                            })
                            .unwrap_or_else(|| "OK".to_string());
                        let status_message = s
                            .pointer("/status/message")
                            .and_then(Value::as_str)
                            .filter(|m| !m.is_empty())
                            .map(ToString::to_string);
                        let span_attrs = extract_otlp_attributes(s.get("attributes"));
                        let attributes_json =
                            serde_json::to_string(&span_attrs).unwrap_or_else(|_| "{}".to_string());

                        out.push(OtelSpanEntry {
                            trace_id,
                            span_id,
                            parent_span_id,
                            service_name: service_name.clone(),
                            node_id: node_id.clone(),
                            span_name,
                            span_kind,
                            start_time_unix_nano,
                            end_time_unix_nano,
                            duration_ns,
                            status_code,
                            status_message,
                            attributes_json,
                        });
                    }
                }
            }
        }
    }

    Ok(out)
}

/// Parses either a direct JSON array of [`OtelMetricEntry`] or a standard OTLP/HTTP JSON
/// `ExportMetricsServiceRequest` (`{"resourceMetrics": [...]}`) into canonical [`OtelMetricEntry`] records.
pub fn parse_otlp_metrics_json(
    bytes: &[u8],
    default_node_id: &str,
    default_arch: &str,
) -> Result<Vec<OtelMetricEntry>, CollectorError> {
    if let Ok(direct) = serde_json::from_slice::<Vec<OtelMetricEntry>>(bytes) {
        return Ok(direct);
    }
    let root: Value = serde_json::from_slice(bytes)?;
    if let Some(arr) = root.get("metrics").and_then(Value::as_array) {
        if let Ok(direct) =
            serde_json::from_value::<Vec<OtelMetricEntry>>(Value::Array(arr.clone()))
        {
            return Ok(direct);
        }
    }

    let mut out = Vec::new();
    let Some(res_metrics) = root.get("resourceMetrics").and_then(Value::as_array) else {
        return Err(CollectorError::InvalidPayload(
            "Expected OTLP resourceMetrics or Vec<OtelMetricEntry> JSON".to_string(),
        ));
    };

    for rm in res_metrics {
        let res_attrs = extract_otlp_attributes(rm.pointer("/resource/attributes"));
        let service_name = res_attrs
            .get("service.name")
            .and_then(Value::as_str)
            .unwrap_or("unknown-service")
            .to_string();
        let node_id = res_attrs
            .get("node.id")
            .or_else(|| res_attrs.get("host.name"))
            .and_then(Value::as_str)
            .unwrap_or(default_node_id)
            .to_string();
        let res_arch = res_attrs
            .get("host.arch")
            .or_else(|| res_attrs.get("arch"))
            .and_then(Value::as_str)
            .unwrap_or(default_arch)
            .to_string();

        if let Some(scope_metrics) = rm.get("scopeMetrics").and_then(Value::as_array) {
            for sm in scope_metrics {
                if let Some(metrics) = sm.get("metrics").and_then(Value::as_array) {
                    for m in metrics {
                        let metric_name = m
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("unnamed-metric")
                            .to_string();
                        let metric_unit = m
                            .get("unit")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();

                        let data_points = m
                            .pointer("/gauge/dataPoints")
                            .or_else(|| m.pointer("/sum/dataPoints"))
                            .and_then(Value::as_array);

                        if let Some(points) = data_points {
                            for dp in points {
                                let dp_attrs = extract_otlp_attributes(dp.get("attributes"));
                                let timestamp_unix_nano =
                                    parse_unix_nano(dp.get("timeUnixNano")).unwrap_or(0);
                                let value_f64 = dp
                                    .get("asDouble")
                                    .and_then(Value::as_f64)
                                    .or_else(|| {
                                        dp.get("asInt").and_then(|v| {
                                            v.as_i64()
                                                .map(|i| i as f64)
                                                .or_else(|| v.as_str()?.parse::<f64>().ok())
                                        })
                                    })
                                    .unwrap_or(0.0);
                                let arch = dp_attrs
                                    .get("arch")
                                    .and_then(Value::as_str)
                                    .unwrap_or(&res_arch)
                                    .to_string();
                                let cpu_cluster = dp_attrs
                                    .get("cpu_cluster")
                                    .or_else(|| res_attrs.get("cpu_cluster"))
                                    .and_then(Value::as_str)
                                    .map(ToString::to_string);
                                let vlen_bits = dp_attrs
                                    .get("vlen_bits")
                                    .or_else(|| res_attrs.get("vlen_bits"))
                                    .and_then(Value::as_u64)
                                    .and_then(|v| u32::try_from(v).ok());
                                let memlock_used_bytes =
                                    dp_attrs.get("memlock_used_bytes").and_then(Value::as_u64);
                                let memlock_limit_bytes =
                                    dp_attrs.get("memlock_limit_bytes").and_then(Value::as_u64);
                                let trace_id = dp_attrs
                                    .get("trace_id")
                                    .and_then(Value::as_str)
                                    .map(ToString::to_string);
                                let span_id = dp_attrs
                                    .get("span_id")
                                    .and_then(Value::as_str)
                                    .map(ToString::to_string);
                                let attributes_json = serde_json::to_string(&dp_attrs)
                                    .unwrap_or_else(|_| "{}".to_string());

                                out.push(OtelMetricEntry {
                                    timestamp_unix_nano,
                                    service_name: service_name.clone(),
                                    node_id: node_id.clone(),
                                    metric_name: metric_name.clone(),
                                    metric_unit: metric_unit.clone(),
                                    value_f64,
                                    arch,
                                    cpu_cluster,
                                    vlen_bits,
                                    memlock_used_bytes,
                                    memlock_limit_bytes,
                                    trace_id,
                                    span_id,
                                    attributes_json,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(out)
}

/// Parses either a direct JSON array of [`OtelLogEntry`] or a standard OTLP/HTTP JSON
/// `ExportLogsServiceRequest` (`{"resourceLogs": [...]}`) into canonical [`OtelLogEntry`] records.
pub fn parse_otlp_logs_json(
    bytes: &[u8],
    default_node_id: &str,
) -> Result<Vec<OtelLogEntry>, CollectorError> {
    if let Ok(direct) = serde_json::from_slice::<Vec<OtelLogEntry>>(bytes) {
        return Ok(direct);
    }
    let root: Value = serde_json::from_slice(bytes)?;
    if let Some(arr) = root.get("logs").and_then(Value::as_array) {
        if let Ok(direct) = serde_json::from_value::<Vec<OtelLogEntry>>(Value::Array(arr.clone())) {
            return Ok(direct);
        }
    }

    let mut out = Vec::new();
    let Some(res_logs) = root.get("resourceLogs").and_then(Value::as_array) else {
        return Err(CollectorError::InvalidPayload(
            "Expected OTLP resourceLogs or Vec<OtelLogEntry> JSON".to_string(),
        ));
    };

    for rl in res_logs {
        let res_attrs = extract_otlp_attributes(rl.pointer("/resource/attributes"));
        let service_name = res_attrs
            .get("service.name")
            .and_then(Value::as_str)
            .unwrap_or("unknown-service")
            .to_string();
        let node_id = res_attrs
            .get("node.id")
            .or_else(|| res_attrs.get("host.name"))
            .and_then(Value::as_str)
            .unwrap_or(default_node_id)
            .to_string();

        if let Some(scope_logs) = rl.get("scopeLogs").and_then(Value::as_array) {
            for sl in scope_logs {
                if let Some(records) = sl.get("logRecords").and_then(Value::as_array) {
                    for lr in records {
                        let timestamp_unix_nano = parse_unix_nano(lr.get("timeUnixNano"))
                            .or_else(|| parse_unix_nano(lr.get("observedTimeUnixNano")))
                            .unwrap_or(0);
                        let trace_id = lr
                            .get("traceId")
                            .and_then(Value::as_str)
                            .unwrap_or("00000000000000000000000000000000")
                            .to_string();
                        let span_id = lr
                            .get("spanId")
                            .and_then(Value::as_str)
                            .unwrap_or("0000000000000000")
                            .to_string();
                        let severity_number = lr
                            .get("severityNumber")
                            .and_then(Value::as_i64)
                            .and_then(|n| i32::try_from(n).ok())
                            .unwrap_or(9);
                        let severity_text = lr
                            .get("severityText")
                            .and_then(Value::as_str)
                            .unwrap_or("INFO")
                            .to_string();
                        let body = lr
                            .pointer("/body/stringValue")
                            .or_else(|| lr.get("body"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        let log_attrs = extract_otlp_attributes(lr.get("attributes"));
                        let job_id = log_attrs
                            .get("job_id")
                            .or_else(|| log_attrs.get("job.id"))
                            .and_then(Value::as_str)
                            .map(ToString::to_string);
                        let stage_id = log_attrs
                            .get("stage_id")
                            .or_else(|| log_attrs.get("stage.id"))
                            .and_then(Value::as_str)
                            .map(ToString::to_string);
                        let attributes_json =
                            serde_json::to_string(&log_attrs).unwrap_or_else(|_| "{}".to_string());

                        out.push(OtelLogEntry {
                            timestamp_unix_nano,
                            trace_id,
                            span_id,
                            severity_number,
                            severity_text,
                            service_name: service_name.clone(),
                            node_id: node_id.clone(),
                            body,
                            attributes_json,
                            job_id,
                            stage_id,
                        });
                    }
                }
            }
        }
    }

    Ok(out)
}

fn parse_unix_nano(val: Option<&Value>) -> Option<i64> {
    match val? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse::<i64>().ok(),
        _ => None,
    }
}

fn extract_otlp_attributes(attrs_val: Option<&Value>) -> Map<String, Value> {
    let mut map = Map::new();
    let Some(arr) = attrs_val.and_then(Value::as_array) else {
        if let Some(obj) = attrs_val.and_then(Value::as_object) {
            return obj.clone();
        }
        return map;
    };
    for item in arr {
        let Some(key) = item.get("key").and_then(Value::as_str) else {
            continue;
        };
        let Some(val_obj) = item.get("value") else {
            continue;
        };
        let extracted = if let Some(s) = val_obj.get("stringValue") {
            s.clone()
        } else if let Some(i) = val_obj.get("intValue") {
            if let Some(s_int) = i.as_str().and_then(|s| s.parse::<i64>().ok()) {
                Value::from(s_int)
            } else {
                i.clone()
            }
        } else if let Some(d) = val_obj.get("doubleValue") {
            d.clone()
        } else if let Some(b) = val_obj.get("boolValue") {
            b.clone()
        } else {
            val_obj.clone()
        };
        map.insert(key.to_string(), extracted);
    }
    map
}

/// Handles a single bidirectional `MUOB`-framed Arrow IPC connection stream, scrubbing each
/// incoming batch via [`EdgeSecretScrubber`], appending it to [`EdgeRingWal`], and returning
/// a [`WalBatchAck`] (`MSG_TYPE_WAL_ACK`) frame for each ingested batch.
pub async fn handle_muob_connection<S>(
    mut stream: S,
    state: CollectorIngestState,
) -> Result<u64, CollectorError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let fory = create_fory_registry()?;
    let mut processed_frames = 0u64;

    loop {
        let (header, payload) = match read_frame(&mut stream).await {
            Ok(pair) => pair,
            Err(mu_observable_ipc::IpcError::Io(ref e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(processed_frames);
            }
            Err(e) => return Err(CollectorError::Ipc(e)),
        };

        let scrubbed = state
            .scrubber
            .scrub_arrow_frame_payload(header.msg_type, &payload)?;
        let priority =
            WalSignalPriority::classify(header.msg_type, header.flags, scrubbed.high_priority);

        let wal_seq = {
            let mut wal = state.wal.lock().await;
            wal.append(header.msg_type, header.flags, priority, scrubbed.payload)?
        };

        let ack = WalBatchAck {
            sequence: wal_seq.unwrap_or(header.sequence),
            accepted_rows: if wal_seq.is_some() {
                scrubbed.row_count
            } else {
                0
            },
            ok: wal_seq.is_some(),
            error_message: if wal_seq.is_some() {
                None
            } else {
                Some("Dropped low-priority batch due to WAL backpressure".to_string())
            },
        };

        let ack_bytes = fory
            .serialize(&ack)
            .map_err(mu_observable_ipc::IpcError::Fory)?;
        let ack_len = u32::try_from(ack_bytes.len()).unwrap_or(u32::MAX);
        let ack_hdr = IpcHeader::new(MSG_TYPE_WAL_ACK, ack_len, 0, header.sequence);
        write_frame(&mut stream, &ack_hdr, &ack_bytes).await?;
        processed_frames += 1;
    }
}

/// Accepts and processes connections from a loopback TCP listener speaking the `MUOB` Arrow IPC protocol.
pub async fn serve_muob_tcp_once(
    listener: &TcpListener,
    state: CollectorIngestState,
) -> Result<u64, CollectorError> {
    let (stream, _peer) = listener.accept().await?;
    handle_muob_connection(stream, state).await
}

/// Accepts and processes connections from a loopback TCP listener speaking the `MUOB` Arrow IPC protocol in an accept loop.
///
/// Spawns a Tokio task for each accepted connection running [`handle_muob_connection`], ensuring
/// concurrent streams from local worker daemons (such as `ActionRunner-rs` `TelemetryEmitter`) are ingested
/// without blocking the accept loop.
pub async fn serve_muob_tcp_listener(
    listener: TcpListener,
    state: CollectorIngestState,
) -> Result<(), CollectorError> {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let state_clone = state.clone();
                tokio::spawn(async move {
                    tracing::debug!(%peer_addr, "Accepted MUOB Arrow IPC connection");
                    if let Err(e) = handle_muob_connection(stream, state_clone).await {
                        tracing::debug!(
                            %peer_addr,
                            error = %e,
                            "MUOB Arrow IPC stream finished or client disconnected"
                        );
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to accept MUOB Arrow IPC TCP connection; retrying");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

/// Binds a Unix domain socket listener at `socket_path` and handles a single `MUOB` Arrow IPC connection.
#[cfg(unix)]
pub async fn serve_muob_unix_once(
    socket_path: impl AsRef<Path>,
    state: CollectorIngestState,
) -> Result<u64, CollectorError> {
    let path = socket_path.as_ref();
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    let (stream, _addr) = listener.accept().await?;
    handle_muob_connection(stream, state).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use mu_observable_ipc::{
        decode_log_batch, decode_metric_batch, decode_span_batch, decode_test_run_batch,
        encode_test_run_batch, TestCaseRunEntry, MSG_TYPE_ARROW_TEST_RUNS, REDACTED_PLACEHOLDER,
    };
    use tower::ServiceExt;

    fn test_state() -> CollectorIngestState {
        let wal = Arc::new(Mutex::new(EdgeRingWal::in_memory(1024 * 1024, 3600)));
        let scrubber = Arc::new(EdgeSecretScrubber::with_secret_values([
            "env_secret_token_alpha",
        ]));
        CollectorIngestState::new(wal, scrubber, "worker-riscv64", "riscv64gc")
    }

    #[tokio::test]
    async fn test_otlp_http_traces_metrics_logs_and_healthz() {
        let state = test_state();
        let app = build_otlp_router(state.clone());

        // 1. POST /v1/traces with OTLP JSON
        let trace_json = serde_json::json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "action-runner-worker"}},
                        {"key": "node.id", "value": {"stringValue": "worker-riscv64"}}
                    ]
                },
                "scopeSpans": [{
                    "spans": [{
                        "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                        "spanId": "00f067aa0ba902b7",
                        "name": "ci.stage.compile",
                        "kind": 2,
                        "startTimeUnixNano": "1700000000000000000",
                        "endTimeUnixNano": "1700000002000000000",
                        "status": {"code": 1, "message": "used ghp_secretToken123456"},
                        "attributes": [
                            {"key": "auth", "value": {"stringValue": "Bearer secret_jwt_abc"}}
                        ]
                    }]
                }]
            }]
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/traces")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&trace_json).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let trace_resp: OtlpIngestResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(trace_resp.accepted_records, 1);
        assert_eq!(trace_resp.wal_sequence, Some(1));

        // 2. POST /v1/metrics with OTLP JSON (including K3 A100 VLEN=1024 attributes)
        let metric_json = serde_json::json!({
            "resourceMetrics": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "k3-manager"}},
                        {"key": "node.id", "value": {"stringValue": "worker-riscv64"}},
                        {"key": "host.arch", "value": {"stringValue": "riscv64gc"}}
                    ]
                },
                "scopeMetrics": [{
                    "metrics": [{
                        "name": "k3.decode.tok_per_s",
                        "unit": "tok/s",
                        "gauge": {
                            "dataPoints": [{
                                "timeUnixNano": "1700000005000000000",
                                "asDouble": 52.5,
                                "attributes": [
                                    {"key": "cpu_cluster", "value": {"stringValue": "A100"}},
                                    {"key": "vlen_bits", "value": {"intValue": "1024"}},
                                    {"key": "token", "value": {"stringValue": "env_secret_token_alpha"}}
                                ]
                            }]
                        }
                    }]
                }]
            }]
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/metrics")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&metric_json).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 3. POST /v1/logs with OTLP JSON
        let log_json = serde_json::json!({
            "resourceLogs": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "action-runner-worker"}}
                    ]
                },
                "scopeLogs": [{
                    "logRecords": [{
                        "timeUnixNano": "1700000006000000000",
                        "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                        "spanId": "00f067aa0ba902b7",
                        "severityNumber": 17,
                        "severityText": "ERROR",
                        "body": {"stringValue": "deploy failed with env_secret_token_alpha"},
                        "attributes": [
                            {"key": "job_id", "value": {"stringValue": "job-42"}}
                        ]
                    }]
                }]
            }]
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/logs")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&log_json).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 4. GET /healthz
        let req = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify all 3 WAL batches are scrubbed before WAL persistence
        let wal = state.wal.lock().await;
        let pending = wal.pending_batches();
        assert_eq!(pending.len(), 3);

        let spans = decode_span_batch(&pending[0].payload).unwrap();
        assert!(!spans[0]
            .status_message
            .as_deref()
            .unwrap()
            .contains("ghp_secretToken123456"));
        assert!(!spans[0].attributes_json.contains("secret_jwt_abc"));
        assert!(spans[0].attributes_json.contains(REDACTED_PLACEHOLDER));

        let metrics = decode_metric_batch(&pending[1].payload).unwrap();
        assert_eq!(metrics[0].cpu_cluster.as_deref(), Some("A100"));
        assert_eq!(metrics[0].vlen_bits, Some(1024));
        assert!(!metrics[0]
            .attributes_json
            .contains("env_secret_token_alpha"));

        let logs = decode_log_batch(&pending[2].payload).unwrap();
        assert_eq!(logs[0].job_id.as_deref(), Some("job-42"));
        assert!(!logs[0].body.contains("env_secret_token_alpha"));
        assert!(logs[0].body.contains(REDACTED_PLACEHOLDER));
    }

    #[tokio::test]
    async fn test_muob_arrow_ipc_stream_listener_and_ack() {
        let state = test_state();
        let (mut client, server) = tokio::io::duplex(64 * 1024);

        let state_clone = state.clone();
        let server_task =
            tokio::spawn(async move { handle_muob_connection(server, state_clone).await.unwrap() });

        let test_runs = vec![TestCaseRunEntry {
            job_id: "job-77".to_string(),
            repo_key: "lma1980/k3-kernels-rvv".to_string(),
            branch_key: "main".to_string(),
            commit_sha: "1234567890abcdef".to_string(),
            crate_name: "k3-kernels-rvv".to_string(),
            test_binary: "k3_kernels_rvv".to_string(),
            test_name: "test_vmadot".to_string(),
            status: "failed".to_string(),
            duration_ms: 9.2,
            failure_summary: Some("token=ghp_superSecret987654321".to_string()),
            timestamp_unix_nano: 1_700_000_010_000_000_000,
            node_id: "worker-riscv64".to_string(),
            arch: "riscv64gc".to_string(),
        }];
        let payload = encode_test_run_batch(&test_runs).unwrap();
        let hdr = IpcHeader::new(
            MSG_TYPE_ARROW_TEST_RUNS,
            u32::try_from(payload.len()).unwrap(),
            FLAG_HIGH_PRIORITY,
            55,
        );
        write_frame(&mut client, &hdr, &payload).await.unwrap();

        let (ack_hdr, ack_payload) = read_frame(&mut client).await.unwrap();
        assert_eq!(ack_hdr.msg_type, MSG_TYPE_WAL_ACK);
        let fory = create_fory_registry().unwrap();
        let ack: WalBatchAck = fory.deserialize(&ack_payload).unwrap();
        assert!(ack.ok);
        assert_eq!(ack.accepted_rows, 1);
        assert_eq!(ack.sequence, 1);

        drop(client);
        let processed = server_task.await.unwrap();
        assert_eq!(processed, 1);

        let wal = state.wal.lock().await;
        let pending = wal.pending_batches();
        assert_eq!(pending.len(), 1);
        let decoded = decode_test_run_batch(&pending[0].payload).unwrap();
        assert!(!decoded[0]
            .failure_summary
            .as_deref()
            .unwrap()
            .contains("ghp_superSecret987654321"));
    }
}
