//! # Sensitive Read Policy
//!
//! Generic policy helpers for read-only tools that may return unredacted
//! sensitive output after an explicit runtime gate and caller acknowledgement.
//!
//! ## Ownership
//! This module owns only the cross-service decision envelope for sensitive
//! reads. Service crates own domain allowlists, resource lookup, secret
//! classification, and final output shaping.
//!
//! ## Security Boundaries
//! * Fails closed when runtime enablement is disabled.
//! * Requires explicit caller acknowledgement for sensitive output.
//! * Applies generic boundary limits before any service-specific backend read.

use crate::{list_within_boundary_limits, Decision, DecisionCode};

/// Evaluates the generic sensitive-read preflight policy.
///
/// # Security
/// This helper does not determine whether a field is safe to reveal. It only
/// enforces the shared gate that a sensitive-read tool must pass before a
/// service performs exact domain-specific reads.
pub fn sensitive_read_policy_decision(
    runtime_enabled: bool,
    acknowledged_sensitive_output: bool,
    requested_fields: &[String],
) -> Decision {
    if !runtime_enabled {
        return Decision::deny(
            DecisionCode::CapabilityMissing,
            Some("sensitive_read_runtime_disabled"),
        );
    }
    if !acknowledged_sensitive_output {
        return Decision::deny(
            DecisionCode::InvalidInput,
            Some("sensitive_output_acknowledgement_required"),
        );
    }
    if requested_fields.is_empty() {
        return Decision::deny(DecisionCode::InvalidInput, Some("fields_required"));
    }
    if !list_within_boundary_limits(requested_fields) {
        return Decision::deny(DecisionCode::InvalidInput, Some("boundary_limit_exceeded"));
    }
    Decision::allow()
}

#[cfg(test)]
mod tests {
    use super::sensitive_read_policy_decision;

    #[test]
    fn sensitive_read_policy_fails_closed_without_runtime_gate() {
        let decision = sensitive_read_policy_decision(false, true, &["smtp_server".to_string()]);

        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("CAPABILITY_MISSING"));
        assert_eq!(
            decision.reason.as_deref(),
            Some("sensitive_read_runtime_disabled")
        );
    }

    #[test]
    fn sensitive_read_policy_requires_acknowledgement() {
        let decision = sensitive_read_policy_decision(true, false, &["smtp_server".to_string()]);

        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("INVALID_INPUT"));
        assert_eq!(
            decision.reason.as_deref(),
            Some("sensitive_output_acknowledgement_required")
        );
    }

    #[test]
    fn sensitive_read_policy_accepts_bounded_acknowledged_requests() {
        let decision = sensitive_read_policy_decision(true, true, &["smtp_server".to_string()]);

        assert!(decision.allow);
        assert!(decision.code.is_none());
        assert!(decision.reason.is_none());
    }
}
