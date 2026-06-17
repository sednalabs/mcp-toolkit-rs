//! # Query Evidence
//!
//! Compact provider-response evidence helpers for MCP tools that need to expose
//! bounded query cost and mutation-safety metadata without becoming raw query
//! surfaces.
//!
//! ## Ownership
//! This module owns generic response-metadata extraction for provider-shaped
//! query responses. It does not own provider clients, SQL execution, or
//! service-specific query semantics.
//!
//! ## Security Boundaries
//! * Pure JSON metadata extraction only; no network I/O or SQL execution.
//! * Extracts cost and mutation evidence, not row payload content.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Compact cost and mutation evidence for one read-only query response.
///
/// Use this in MCP tool responses so operators can see whether a query stayed
/// read-only and how expensive it was without inspecting raw provider output.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct QueryCostEvidence {
    /// Whether provider metadata says the query changed database state.
    pub changed_db: Option<bool>,
    /// Provider-reported rows read, summed across result statements when present.
    pub rows_read: Option<u64>,
    /// Provider-reported rows written, summed across result statements when present.
    pub rows_written: Option<u64>,
    /// Provider-reported change count, summed across result statements when present.
    pub changes: Option<u64>,
    /// Provider-reported execution duration in milliseconds, summed across statements.
    pub duration_ms: Option<f64>,
    /// Provider-reported total attempts, summed across statements when present.
    pub total_attempts: Option<u64>,
    /// Number of result rows visible in the provider response.
    pub result_count: Option<u64>,
    /// Whether the calling MCP/tool layer marked the result set truncated.
    pub truncated: Option<bool>,
}

impl QueryCostEvidence {
    /// Extracts query evidence from a Cloudflare D1 query-style JSON response.
    ///
    /// The extractor accepts the direct Cloudflare API shape as well as common
    /// MCP wrappers that carry a top-level `truncated` flag. It deliberately
    /// ignores row payload contents except for counting result rows.
    pub fn from_cloudflare_d1_response(raw: &Value) -> Self {
        if let Some(results) = raw.as_array() {
            let mut evidence = Self::default();
            evidence.result_count = sum_result_counts(results);
            for item in results {
                if let Some(meta) = item.get("meta") {
                    evidence.merge_meta(meta);
                }
            }
            return evidence;
        }

        let mut evidence = Self {
            truncated: raw.get("truncated").and_then(Value::as_bool),
            ..Self::default()
        };

        if let Some(results) = raw.get("result").and_then(Value::as_array) {
            evidence.result_count = sum_result_counts(results);
            for item in results {
                if let Some(meta) = item.get("meta") {
                    evidence.merge_meta(meta);
                }
            }
            return evidence;
        }

        if let Some(meta) = raw.get("meta") {
            evidence.merge_meta(meta);
        }

        evidence.result_count = result_count(raw);
        evidence
    }

    /// Returns `true` when no evidence fields were present.
    pub fn is_empty(&self) -> bool {
        self.changed_db.is_none()
            && self.rows_read.is_none()
            && self.rows_written.is_none()
            && self.changes.is_none()
            && self.duration_ms.is_none()
            && self.total_attempts.is_none()
            && self.result_count.is_none()
            && self.truncated.is_none()
    }

    /// Serializes the evidence as a compact JSON object.
    pub fn to_value(&self) -> Value {
        json!({
            "changed_db": self.changed_db,
            "rows_read": self.rows_read,
            "rows_written": self.rows_written,
            "changes": self.changes,
            "duration_ms": self.duration_ms,
            "total_attempts": self.total_attempts,
            "result_count": self.result_count,
            "truncated": self.truncated,
        })
    }

    fn merge_meta(&mut self, meta: &Value) {
        self.changed_db = merge_bool_or(
            self.changed_db,
            meta.get("changed_db").and_then(Value::as_bool),
        );
        self.rows_read = merge_sum(self.rows_read, value_u64(meta, "rows_read"));
        self.rows_written = merge_sum(self.rows_written, value_u64(meta, "rows_written"));
        self.changes = merge_sum(self.changes, value_u64(meta, "changes"));
        self.duration_ms = merge_sum_f64(
            self.duration_ms,
            value_f64(meta, "duration").or_else(|| value_f64(meta, "duration_ms")),
        );
        self.total_attempts = merge_sum(self.total_attempts, value_u64(meta, "total_attempts"));
    }
}

fn merge_bool_or(current: Option<bool>, next: Option<bool>) -> Option<bool> {
    match (current, next) {
        (Some(left), Some(right)) => Some(left || right),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn merge_sum(current: Option<u64>, next: Option<u64>) -> Option<u64> {
    match (current, next) {
        (Some(left), Some(right)) => Some(left.saturating_add(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn merge_sum_f64(current: Option<f64>, next: Option<f64>) -> Option<f64> {
    match (current, next) {
        (Some(left), Some(right)) => Some(left + right),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn value_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(|field| match field {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_i64().and_then(|value| u64::try_from(value).ok()))
            .or_else(|| {
                number
                    .as_f64()
                    .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
                    .map(|value| value as u64)
            }),
        Value::String(text) => text.parse::<u64>().ok(),
        _ => None,
    })
}

fn value_f64(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(|value| match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.parse::<f64>().ok(),
        _ => None,
    })
}

fn sum_result_counts(results: &[Value]) -> Option<u64> {
    let mut count = 0_u64;
    let mut found = false;
    for item in results {
        if let Some(item_count) = result_count(item) {
            count = count.saturating_add(item_count);
            found = true;
        }
    }
    found.then_some(count)
}

fn result_count(value: &Value) -> Option<u64> {
    value
        .get("results")
        .or_else(|| value.get("rows"))
        .or_else(|| value.get("data"))
        .and_then(Value::as_array)
        .map(|rows| rows.len() as u64)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::QueryCostEvidence;

    #[test]
    fn extracts_cloudflare_d1_result_metadata() {
        let evidence = QueryCostEvidence::from_cloudflare_d1_response(&json!({
            "success": true,
            "result": [{
                "meta": {
                    "changed_db": false,
                    "changes": 0,
                    "duration": 2.487,
                    "rows_read": 153,
                    "rows_written": 0,
                    "total_attempts": 1
                },
                "results": [{"tracking_id": "ITW-1"}, {"tracking_id": "ITW-2"}],
                "success": true
            }]
        }));

        assert_eq!(evidence.changed_db, Some(false));
        assert_eq!(evidence.rows_read, Some(153));
        assert_eq!(evidence.rows_written, Some(0));
        assert_eq!(evidence.changes, Some(0));
        assert_eq!(evidence.duration_ms, Some(2.487));
        assert_eq!(evidence.total_attempts, Some(1));
        assert_eq!(evidence.result_count, Some(2));
        assert_eq!(evidence.truncated, None);
    }

    #[test]
    fn aggregates_multiple_cloudflare_d1_result_metadata_blocks() {
        let evidence = QueryCostEvidence::from_cloudflare_d1_response(&json!({
            "truncated": false,
            "result": [
                {
                    "meta": {
                        "changed_db": false,
                        "rows_read": 4,
                        "rows_written": 0,
                        "duration": "1.5",
                        "total_attempts": 1
                    },
                    "results": [{"id": 1}]
                },
                {
                    "meta": {
                        "changed_db": true,
                        "rows_read": 6,
                        "rows_written": 2,
                        "duration_ms": 2.0,
                        "total_attempts": 2
                    },
                    "results": [{"id": 2}, {"id": 3}]
                }
            ]
        }));

        assert_eq!(evidence.changed_db, Some(true));
        assert_eq!(evidence.rows_read, Some(10));
        assert_eq!(evidence.rows_written, Some(2));
        assert_eq!(evidence.duration_ms, Some(3.5));
        assert_eq!(evidence.total_attempts, Some(3));
        assert_eq!(evidence.result_count, Some(3));
        assert_eq!(evidence.truncated, Some(false));
    }

    #[test]
    fn supports_raw_result_arrays_and_float_backed_integers() {
        let evidence = QueryCostEvidence::from_cloudflare_d1_response(&json!([
            {
                "meta": {
                    "changed_db": false,
                    "rows_read": 4.0,
                    "rows_written": 0.0,
                    "duration_ms": 1.25,
                    "total_attempts": 1.0
                },
                "results": [{"id": 1}]
            },
            {
                "meta": {
                    "changed_db": false,
                    "rows_read": "6",
                    "rows_written": 0,
                    "changes": 0.0,
                    "duration": 2.0
                },
                "results": [{"id": 2}, {"id": 3}]
            }
        ]));

        assert_eq!(evidence.changed_db, Some(false));
        assert_eq!(evidence.rows_read, Some(10));
        assert_eq!(evidence.rows_written, Some(0));
        assert_eq!(evidence.changes, Some(0));
        assert_eq!(evidence.duration_ms, Some(3.25));
        assert_eq!(evidence.total_attempts, Some(1));
        assert_eq!(evidence.result_count, Some(3));
    }

    #[test]
    fn empty_response_has_no_evidence() {
        let evidence = QueryCostEvidence::from_cloudflare_d1_response(&json!({}));

        assert!(evidence.is_empty());
        assert_eq!(
            evidence.to_value(),
            json!({
                "changed_db": null,
                "rows_read": null,
                "rows_written": null,
                "changes": null,
                "duration_ms": null,
                "total_attempts": null,
                "result_count": null,
                "truncated": null,
            })
        );
    }
}
