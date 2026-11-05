//! # Compact Tool Results
//!
//! Opt-in RMCP adapters for a bounded text projection beside unchanged structured
//! content. Domain envelopes, error taxonomies, and actionable summaries remain
//! caller-owned; the typed outcome selects MCP's `isError` flag.
//!
//! ## Security Boundaries
//! Inputs must already be safe for the caller. This module does not redact,
//! inspect `ok` fields, or turn arbitrary provider errors into safe messages.
//! Bounds cover UTF-8 summary bytes, serialized structured content, and the
//! serialized result (including metadata), not the enclosing JSON-RPC message.
//! They are admission limits, not a limit on memory already allocated by callers.
//! Do not mutate the returned result without rechecking your transport budget.

use std::io::{self, Write};

use rmcp::model::{CallToolResult, ContentBlock, MetaObject};
use serde_json::Value;

/// Select MCP success or failure independently of domain-specific payload fields.
pub enum ToolOutcome {
    /// The tool completed successfully; emits `isError: false`.
    Success(Value),
    /// The tool ran but failed; emits `isError: true`.
    Error(Value),
}

/// Set explicit byte budgets; no payload or metadata is silently truncated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseLimits {
    /// Maximum UTF-8 bytes in the caller's text projection.
    pub text_bytes: usize,
    /// Maximum serialized JSON bytes in structured content.
    pub structured_bytes: usize,
    /// Maximum serialized JSON bytes in the complete result, including `_meta`.
    pub result_bytes: usize,
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self {
            text_bytes: 12 * 1024,
            structured_bytes: 48 * 1024,
            result_bytes: 64 * 1024,
        }
    }
}

/// Report a rejected projection without echoing any caller data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseBuildError {
    /// The text projection exceeds its UTF-8 byte budget.
    TextLimit,
    /// The serialized structured content exceeds its byte budget.
    StructuredLimit,
    /// The serialized result exceeds its byte budget.
    ResultLimit,
    /// JSON serialization failed for a reason other than a byte limit.
    Serialization,
}

impl std::fmt::Display for ResponseBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TextLimit => "tool result text exceeds byte limit",
            Self::StructuredLimit => "structured tool result exceeds byte limit",
            Self::ResultLimit => "complete tool result exceeds byte limit",
            Self::Serialization => "tool result serialization failed",
        })
    }
}

impl std::error::Error for ResponseBuildError {}

/// Build one text projection and an unchanged structured payload.
///
/// Protocol metadata goes only in `_meta`; payload fields (including `meta` or
/// `_meta`) are preserved in structured content and are never merged or replaced.
/// An explicit JSON null remains present. Empty text is permitted; callers should
/// normally supply an actionable summary for clients that display only text.
///
/// # Errors
/// Rejects over-budget text, structured content, or complete results. Rejection
/// never returns partial output and its diagnostic never includes input data.
///
/// # Security
/// Use allowlisted error messages and sanitize every input, including metadata,
/// before calling. Heuristic redaction alone is not proof of safe output.
///
/// ```
/// use mcp_toolkit_server::response::{compact_result, ResponseLimits, ToolOutcome};
/// use serde_json::json;
///
/// let result = compact_result(
///     ToolOutcome::Error(json!({"ok": false, "code": "not_found"})),
///     "No matching item. Try a different identifier.",
///     None,
///     ResponseLimits::default(),
/// )?;
/// assert_eq!(result.is_error, Some(true));
/// # Ok::<(), mcp_toolkit_server::response::ResponseBuildError>(())
/// ```
pub fn compact_result(
    outcome: ToolOutcome,
    summary: &str,
    meta: Option<MetaObject>,
    limits: ResponseLimits,
) -> Result<CallToolResult, ResponseBuildError> {
    if summary.len() > limits.text_bytes {
        return Err(ResponseBuildError::TextLimit);
    }
    let (payload, is_error) = match outcome {
        ToolOutcome::Success(payload) => (payload, false),
        ToolOutcome::Error(payload) => (payload, true),
    };
    measure_json(
        limits.structured_bytes,
        ResponseBuildError::StructuredLimit,
        |writer| serde_json::to_writer(writer, &payload),
    )?;
    // Avoid structured()/structured_error(): those duplicate the full JSON in text.
    let content = vec![ContentBlock::text(summary)];
    let mut result = if is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    };
    result.structured_content = Some(payload);
    result.meta = meta;
    measure_json(
        limits.result_bytes,
        ResponseBuildError::ResultLimit,
        |writer| serde_json::to_writer(writer, &result),
    )?;
    Ok(result)
}

// Count serialization without allocating a second JSON string or retaining data.
fn measure_json(
    limit: usize,
    limit_error: ResponseBuildError,
    serialize: impl FnOnce(&mut ByteBudget) -> serde_json::Result<()>,
) -> Result<(), ResponseBuildError> {
    let mut writer = ByteBudget {
        remaining: limit,
        exceeded: false,
    };
    match serialize(&mut writer) {
        Ok(()) => Ok(()),
        Err(_) if writer.exceeded => Err(limit_error),
        Err(_) => Err(ResponseBuildError::Serialization),
    }
}

struct ByteBudget {
    remaining: usize,
    exceeded: bool,
}

impl Write for ByteBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other("JSON byte limit exceeded"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn wire_flags_follow_typed_outcome_without_changing_payload() {
        for (outcome, payload, failed) in [
            (
                ToolOutcome::Success(json!({"data": []})),
                json!({"data": []}),
                false,
            ),
            (
                ToolOutcome::Error(json!({"ok": false})),
                json!({"ok": false}),
                true,
            ),
        ] {
            let result = compact_result(outcome, "summary", None, ResponseLimits::default()).unwrap();
            let wire = serde_json::to_value(result).unwrap();
            assert_eq!(wire["isError"], failed);
            assert_eq!(wire["structuredContent"], payload);
            assert_eq!(
                wire["content"],
                json!([{"type": "text", "text": "summary"}])
            );
        }
    }

    #[test]
    fn null_empty_and_large_payloads_are_not_duplicated_into_text() {
        for payload in [
            Value::Null,
            json!({}),
            json!([]),
            json!({"rows": "x".repeat(32 * 1024)}),
        ] {
            let result = compact_result(
                ToolOutcome::Success(payload.clone()),
                "",
                None,
                ResponseLimits::default(),
            )
            .unwrap();
            let wire = serde_json::to_value(&result).unwrap();
            assert!(wire.as_object().unwrap().contains_key("structuredContent"));
            assert_eq!(wire["structuredContent"], payload);
            assert_eq!(wire["content"][0]["text"], "");
            let roundtrip: CallToolResult = serde_json::from_value(wire).unwrap();
            assert_eq!(roundtrip.structured_content, Some(payload));
        }
    }

    #[test]
    fn summary_budget_counts_utf8_bytes_without_truncating() {
        let mut limits = ResponseLimits {
            text_bytes: 4,
            ..ResponseLimits::default()
        };
        assert!(compact_result(ToolOutcome::Success(Value::Null), "🦀", None, limits).is_ok());
        limits.text_bytes = 3;
        assert_eq!(
            compact_result(ToolOutcome::Success(Value::Null), "🦀", None, limits).unwrap_err(),
            ResponseBuildError::TextLimit
        );
    }

    #[test]
    fn structured_budget_counts_json_escaping_at_exact_boundary() {
        let payload = json!("\n\"\\");
        let size = serde_json::to_vec(&payload).unwrap().len();
        let mut limits = ResponseLimits {
            structured_bytes: size,
            ..ResponseLimits::default()
        };
        assert!(compact_result(ToolOutcome::Success(payload.clone()), "", None, limits).is_ok());
        limits.structured_bytes -= 1;
        assert_eq!(
            compact_result(ToolOutcome::Success(payload), "", None, limits).unwrap_err(),
            ResponseBuildError::StructuredLimit
        );
    }

    #[test]
    fn metadata_does_not_collide_and_counts_toward_whole_result_budget() {
        let payload = json!({"meta": {"source": "domain"}, "_meta": "domain"});
        let meta: MetaObject =
            serde_json::from_value(json!({"source": "protocol", "large": "y".repeat(100)})).unwrap();
        let result = compact_result(
            ToolOutcome::Success(payload.clone()),
            "\n",
            Some(meta.clone()),
            ResponseLimits::default(),
        )
        .unwrap();
        let wire = serde_json::to_value(&result).unwrap();
        assert_eq!(wire["structuredContent"], payload);
        assert_eq!(wire["_meta"]["source"], "protocol");
        let mut limits = ResponseLimits {
            result_bytes: serde_json::to_vec(&result).unwrap().len(),
            ..ResponseLimits::default()
        };
        assert!(compact_result(
            ToolOutcome::Success(payload.clone()),
            "\n",
            Some(meta.clone()),
            limits
        )
        .is_ok());
        limits.result_bytes -= 1;
        assert_eq!(
            compact_result(ToolOutcome::Success(payload), "\n", Some(meta), limits).unwrap_err(),
            ResponseBuildError::ResultLimit
        );
    }

    #[test]
    fn rejection_diagnostics_do_not_echo_synthetic_secret() {
        let limits = ResponseLimits {
            text_bytes: 0,
            structured_bytes: 0,
            result_bytes: 0,
        };
        let error = compact_result(
            ToolOutcome::Error(json!({"secret": "synthetic-canary"})),
            "",
            None,
            limits,
        )
        .unwrap_err();
        assert_eq!(error, ResponseBuildError::StructuredLimit);
        assert!(!format!("{error:?}: {error}").contains("synthetic-canary"));
    }
}
