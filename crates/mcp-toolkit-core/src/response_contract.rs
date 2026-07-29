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

/// Classifies what is known about an individual mutation attempt after its
/// admission and dispatch boundaries.
///
/// This is intentionally separate from [`MutationOutcome`]. An outcome
/// describes the semantic result a domain reports (such as `added` or
/// `already_match`); this status describes whether this particular request was
/// rejected before it could apply, confirmed by its immediate result, supported
/// by caller-defined evidence, or left uncertain after dispatch.
///
/// Neither [`Self::Applied`] nor [`Self::Proven`] makes a persistence or
/// durability claim. `Proven` means only that the caller has supplied evidence
/// appropriate to its own domain and verification boundary.
///
/// ```
/// use mcp_toolkit_core::response_contract::MutationApplyStatus;
///
/// let status = MutationApplyStatus::UncertainAfterDispatch;
/// assert!(status.requires_effect_check());
/// assert!(status.may_have_applied());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationApplyStatus {
    /// The request was rejected before the mutation application boundary.
    RejectedBeforeApply,
    /// The immediate mutation result confirms application for this request.
    Applied,
    /// Caller-defined evidence confirms the intended effect for this request.
    Proven,
    /// The request crossed the dispatch boundary, but its effect is unknown.
    UncertainAfterDispatch,
}

impl MutationApplyStatus {
    /// Returns the stable JSON string for this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RejectedBeforeApply => "rejected_before_apply",
            Self::Applied => "applied",
            Self::Proven => "proven",
            Self::UncertainAfterDispatch => "uncertain_after_dispatch",
        }
    }

    /// Returns whether this request crossed the mutation application boundary.
    #[must_use]
    pub const fn crossed_apply_boundary(self) -> bool {
        !matches!(self, Self::RejectedBeforeApply)
    }

    /// Returns whether the immediate result or caller-defined evidence confirms
    /// the effect without asserting any persistence guarantee.
    #[must_use]
    pub const fn is_confirmed(self) -> bool {
        matches!(self, Self::Applied | Self::Proven)
    }

    /// Returns whether this request might have applied and therefore must not
    /// be assumed absent solely from this status.
    #[must_use]
    pub const fn may_have_applied(self) -> bool {
        self.crossed_apply_boundary()
    }

    /// Returns whether callers need an effect check before deciding how to
    /// proceed with an uncertain dispatched request.
    #[must_use]
    pub const fn requires_effect_check(self) -> bool {
        matches!(self, Self::UncertainAfterDispatch)
    }
}

#[cfg(test)]
mod tests {
    use super::{MutationApplyStatus, MutationOutcome, ToolErrorPayload};
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

    #[test]
    fn mutation_apply_status_serializes_a_complete_transport_neutral_contract() {
        let statuses = [
            MutationApplyStatus::RejectedBeforeApply,
            MutationApplyStatus::Applied,
            MutationApplyStatus::Proven,
            MutationApplyStatus::UncertainAfterDispatch,
        ];

        assert_eq!(
            serde_json::to_value(statuses).expect("serialize statuses"),
            json!([
                "rejected_before_apply",
                "applied",
                "proven",
                "uncertain_after_dispatch"
            ])
        );
    }

    #[test]
    fn mutation_apply_status_keeps_effect_uncertainty_separate_from_outcome() {
        let status = MutationApplyStatus::UncertainAfterDispatch;

        assert!(status.crossed_apply_boundary());
        assert!(status.may_have_applied());
        assert!(!status.is_confirmed());
        assert!(status.requires_effect_check());
        assert_eq!(status.as_str(), "uncertain_after_dispatch");

        let rejected = MutationApplyStatus::RejectedBeforeApply;
        assert!(!rejected.crossed_apply_boundary());
        assert!(!rejected.may_have_applied());
        assert!(!rejected.is_confirmed());
        assert!(!rejected.requires_effect_check());

        assert!(MutationApplyStatus::Applied.is_confirmed());
        assert!(MutationApplyStatus::Proven.is_confirmed());
    }
}
