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

/// Classifies the result of an idempotent mutation request.
///
/// Use this enum when a tool accepts add, remove, replace, or ensure-style
/// writes and needs to report whether it changed state, previewed a change, or
/// found the target already in the requested state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationOutcome {
    Added,
    Removed,
    Updated,
    WouldAdd,
    WouldRemove,
    WouldUpdate,
    AlreadyBound,
    AlreadyUnbound,
    AlreadyMatch,
}

impl MutationOutcome {
    /// Returns the stable JSON string for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Updated => "updated",
            Self::WouldAdd => "would_add",
            Self::WouldRemove => "would_remove",
            Self::WouldUpdate => "would_update",
            Self::AlreadyBound => "already_bound",
            Self::AlreadyUnbound => "already_unbound",
            Self::AlreadyMatch => "already_match",
        }
    }

    /// Returns true when the outcome represents an applied mutation.
    #[must_use]
    pub const fn changed(self) -> bool {
        matches!(self, Self::Added | Self::Removed | Self::Updated)
    }

    /// Returns true when the outcome represents a dry-run mutation preview.
    #[must_use]
    pub const fn is_preview(self) -> bool {
        matches!(self, Self::WouldAdd | Self::WouldRemove | Self::WouldUpdate)
    }
}

#[cfg(test)]
mod tests {
    use super::{MutationOutcome, ToolErrorPayload};
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

    #[test]
    fn mutation_outcome_serializes_stable_snake_case_labels() {
        assert_eq!(
            serde_json::to_value(MutationOutcome::WouldUpdate).expect("serialize outcome"),
            json!("would_update")
        );
        assert_eq!(MutationOutcome::AlreadyBound.as_str(), "already_bound");
    }

    #[test]
    fn mutation_outcome_classifies_applied_preview_and_noop_states() {
        assert!(MutationOutcome::Added.changed());
        assert!(!MutationOutcome::WouldAdd.changed());
        assert!(MutationOutcome::WouldRemove.is_preview());
        assert!(!MutationOutcome::AlreadyMatch.is_preview());
    }
}
