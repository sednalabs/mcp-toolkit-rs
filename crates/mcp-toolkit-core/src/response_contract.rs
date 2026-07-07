//! # MCP Response Contracts
//!
//! Shared structured response payloads for MCP tools.
//!
//! ## Rationale
//! Downstream servers should not need to reinvent common JSON envelopes for
//! machine-readable tool responses. This module keeps those small, transport-
//! agnostic payloads in `mcp-toolkit-core` so stdio, HTTP, and hosted servers can
//! share the same external contract without depending on each other.
//!
//! ## Security Boundaries
//! * Pure data types only; no transport, filesystem, or network I/O.
//! * Callers are responsible for ensuring extra metadata does not contain
//!   secrets before returning it to an MCP client.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Represents a structured MCP tool error payload.
///
/// Use this payload when a tool returns an MCP `CallToolResult` error with a
/// JSON object body. The stable fields make errors easy for agents to classify,
/// while flattened `extra` metadata lets servers preserve domain-specific
/// fields such as hints, resource names, or upstream status codes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolErrorPayload {
    pub status: String,
    pub code: String,
    pub message: String,
    pub request_id: String,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl ToolErrorPayload {
    /// Creates a structured error payload with the standard required fields.
    #[must_use]
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            status: "error".to_string(),
            code: code.into(),
            message: message.into(),
            request_id: request_id.into(),
            extra: BTreeMap::new(),
        }
    }

    /// Attaches one extra machine-readable metadata field.
    ///
    /// Existing fields with the same key are replaced.
    #[must_use]
    pub fn with_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    /// Attaches a user-facing remediation hint.
    #[must_use]
    pub fn with_hint(self, hint: impl Into<String>) -> Self {
        self.with_extra("hint", Value::String(hint.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::ToolErrorPayload;
    use serde_json::json;

    #[test]
    fn tool_error_payload_serializes_standard_fields() {
        let payload = ToolErrorPayload::new("clients.not_found", "Client not found.", "req-1");

        assert_eq!(
            serde_json::to_value(payload).expect("serialize payload"),
            json!({
                "status": "error",
                "code": "clients.not_found",
                "message": "Client not found.",
                "request_id": "req-1"
            })
        );
    }

    #[test]
    fn tool_error_payload_flattens_extra_metadata() {
        let payload = ToolErrorPayload::new("auth.missing_scope", "Missing scope.", "req-2")
            .with_hint("Request the missing scope.")
            .with_extra("scope", json!("keycloak-admin:clients:read"));

        assert_eq!(
            serde_json::to_value(payload).expect("serialize payload"),
            json!({
                "status": "error",
                "code": "auth.missing_scope",
                "message": "Missing scope.",
                "request_id": "req-2",
                "hint": "Request the missing scope.",
                "scope": "keycloak-admin:clients:read"
            })
        );
    }
}
