//! # Metrics Facade
//!
//! Canonical MCP metrics helpers with sanitization and bounded-label safeguards.
//!
//! ## Rationale
//! Provide a stable, shared metrics vocabulary for MCP servers without requiring
//! every server to hand-roll label conventions and cardinality protections.
//!
//! ## Security Boundaries
//! * Label values are sanitized and bounded before emission.
//! * High-cardinality operation labels are bucketed to `other`.
//! * When metrics feature is disabled, helpers are no-op and side-effect free.
//!
//! ## References
//! * `crate::sanitize`
//! * `crate::redaction`

use std::time::Duration;

use crate::redaction::redact_telemetry_text;
use crate::sanitize::sanitize_log_value_with_limit;

const LABEL_MAX_LEN: usize = 48;
const UNKNOWN_LABEL: &str = "unknown";

pub const METRIC_TOOL_CALLS_TOTAL: &str = "mcp_tool_calls_total";
pub const METRIC_TOOL_CALL_DURATION_SECONDS: &str = "mcp_tool_call_duration_seconds";
pub const METRIC_REQUESTS_TOTAL: &str = "mcp_requests_total";
pub const METRIC_REQUEST_DURATION_SECONDS: &str = "mcp_request_duration_seconds";

#[allow(dead_code)]
const KNOWN_OPERATIONS: &[&str] = &[
    "initialize",
    "list_tools",
    "call_tool",
    "list_resources",
    "read_resource",
    "list_tasks",
    "create_task",
    "get_task_info",
    "get_task_result",
];

/// Outcome class for MCP operations, with bounded cardinality.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OutcomeClass {
    Success,
    Error,
    Denied,
    Timeout,
    Canceled,
}

impl OutcomeClass {
    /// Maps outcome enum variants to stable label values.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Denied => "denied",
            Self::Timeout => "timeout",
            Self::Canceled => "canceled",
        }
    }
}

/// Transport classification for MCP request paths.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TransportMode {
    StreamableHttp,
    Sse,
    Stdio,
    Other,
}

impl TransportMode {
    /// Maps transport enum variants to stable label values.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StreamableHttp => "streamable_http",
            Self::Sse => "sse",
            Self::Stdio => "stdio",
            Self::Other => "other",
        }
    }
}

/// Records baseline metrics for a tool call.
pub fn record_tool_call(
    tool_name: &str,
    outcome: OutcomeClass,
    transport: TransportMode,
    duration: Duration,
) {
    #[cfg(feature = "metrics-facade")]
    {
        let tool = normalize_label_value(tool_name);
        let outcome = outcome.as_str();
        let transport = transport.as_str();

        metrics::counter!(
            METRIC_TOOL_CALLS_TOTAL,
            "tool" => tool.clone(),
            "outcome" => outcome,
            "transport" => transport,
        )
        .increment(1);

        metrics::histogram!(
            METRIC_TOOL_CALL_DURATION_SECONDS,
            "tool" => tool,
            "outcome" => outcome,
            "transport" => transport,
        )
        .record(duration.as_secs_f64());
    }

    #[cfg(not(feature = "metrics-facade"))]
    {
        let _ = (tool_name, outcome, transport, duration);
    }
}

/// Records baseline metrics for a request operation.
pub fn record_request(
    operation: &str,
    outcome: OutcomeClass,
    transport: TransportMode,
    duration: Duration,
) {
    #[cfg(feature = "metrics-facade")]
    {
        let operation = normalize_operation_label(operation);
        let outcome = outcome.as_str();
        let transport = transport.as_str();

        metrics::counter!(
            METRIC_REQUESTS_TOTAL,
            "operation" => operation.clone(),
            "outcome" => outcome,
            "transport" => transport,
        )
        .increment(1);

        metrics::histogram!(
            METRIC_REQUEST_DURATION_SECONDS,
            "operation" => operation,
            "outcome" => outcome,
            "transport" => transport,
        )
        .record(duration.as_secs_f64());
    }

    #[cfg(not(feature = "metrics-facade"))]
    {
        let _ = (operation, outcome, transport, duration);
    }
}

/// Normalizes, sanitizes, and redacts dynamic label values.
pub fn normalize_label_value(raw: &str) -> String {
    let cleaned = sanitize_log_value_with_limit(raw, LABEL_MAX_LEN);
    let redacted = redact_telemetry_text(&cleaned);
    let trimmed = redacted.trim();
    if trimmed.is_empty() {
        return UNKNOWN_LABEL.to_string();
    }

    let mut normalized = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
            normalized.push(ch);
        } else {
            normalized.push('_');
        }
    }

    if normalized.is_empty() {
        UNKNOWN_LABEL.to_string()
    } else {
        normalized
    }
}

#[allow(dead_code)]
fn normalize_operation_label(operation: &str) -> String {
    let normalized = normalize_label_value(operation);
    if KNOWN_OPERATIONS.contains(&normalized.as_str()) {
        normalized
    } else {
        "other".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_normalization_redacts_and_sanitizes() {
        let label = normalize_label_value("Bearer topsecret\n");
        assert!(label.contains("REDACTED"));
        assert!(!label.contains('\n'));
        assert!(!label.contains("topsecret"));
    }

    #[test]
    fn empty_label_becomes_unknown() {
        assert_eq!(normalize_label_value("\n"), UNKNOWN_LABEL);
    }

    #[test]
    fn operation_labels_are_bucketed() {
        assert_eq!(normalize_operation_label("call_tool"), "call_tool");
        assert_eq!(
            normalize_operation_label("user_defined_operation_123"),
            "other"
        );
    }

    #[test]
    fn metrics_helpers_are_safe_without_recorder() {
        record_tool_call(
            "build.start",
            OutcomeClass::Success,
            TransportMode::StreamableHttp,
            Duration::from_millis(42),
        );
        record_request(
            "call_tool",
            OutcomeClass::Error,
            TransportMode::StreamableHttp,
            Duration::from_millis(5),
        );
    }
}
