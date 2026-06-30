//! # No-Mutation Proof Policy
//!
//! Generic policy helpers for tools that intentionally approach a hazardous
//! action boundary to prove state while prohibiting the final mutation.
//!
//! ## Ownership
//! This module owns only the cross-service decision envelope for no-mutation
//! proof tools. Service crates own domain allowlists, before/after readback,
//! and exact evidence shaping.
//!
//! ## Security Boundaries
//! * Fails closed when the proof was not actually performed.
//! * Fails closed if the response admits any mutation or production action
//!   authorization.
//! * Requires bounded evidence notes so proof-only responses cannot silently
//!   become empty success receipts.

use crate::{list_within_boundary_limits, Decision, DecisionCode};

/// Evaluates the generic no-mutation proof policy.
///
/// # Security
/// This helper does not prove that a provider-specific route is safe. It only
/// enforces the shared response contract after the service has performed its
/// own allowlisted proof and before/after invariant readback.
pub fn no_mutation_proof_policy_decision(
    proof_performed: bool,
    mutation_performed: bool,
    production_action_authorized: bool,
    evidence_notes: &[String],
) -> Decision {
    if mutation_performed {
        return Decision::deny(DecisionCode::InvalidInput, Some("mutation_performed"));
    }
    if production_action_authorized {
        return Decision::deny(
            DecisionCode::InvalidInput,
            Some("production_action_authorized"),
        );
    }
    if !proof_performed {
        return Decision::deny(DecisionCode::InvalidInput, Some("proof_not_performed"));
    }
    if evidence_notes.is_empty() {
        return Decision::deny(DecisionCode::InvalidInput, Some("evidence_required"));
    }
    if !list_within_boundary_limits(evidence_notes) {
        return Decision::deny(DecisionCode::InvalidInput, Some("boundary_limit_exceeded"));
    }
    Decision::allow()
}

#[cfg(test)]
mod tests {
    use super::no_mutation_proof_policy_decision;

    #[test]
    fn no_mutation_proof_policy_accepts_bounded_non_mutating_proof() {
        let notes = vec!["final form rendered without submitting".to_string()];
        let decision = no_mutation_proof_policy_decision(true, false, false, &notes);

        assert!(decision.allow);
        assert!(decision.code.is_none());
        assert!(decision.reason.is_none());
    }

    #[test]
    fn no_mutation_proof_policy_rejects_mutation_or_authorization_flags() {
        let notes = vec!["proof attempted".to_string()];
        let mutated = no_mutation_proof_policy_decision(true, true, false, &notes);
        let authorized = no_mutation_proof_policy_decision(true, false, true, &notes);

        assert!(!mutated.allow);
        assert_eq!(mutated.reason.as_deref(), Some("mutation_performed"));
        assert!(!authorized.allow);
        assert_eq!(
            authorized.reason.as_deref(),
            Some("production_action_authorized")
        );
    }

    #[test]
    fn no_mutation_proof_policy_requires_proof_and_evidence() {
        let missing_proof =
            no_mutation_proof_policy_decision(false, false, false, &["note".to_string()]);
        let missing_evidence = no_mutation_proof_policy_decision(true, false, false, &[]);

        assert!(!missing_proof.allow);
        assert_eq!(missing_proof.reason.as_deref(), Some("proof_not_performed"));
        assert!(!missing_evidence.allow);
        assert_eq!(
            missing_evidence.reason.as_deref(),
            Some("evidence_required")
        );
    }

    #[test]
    fn no_mutation_proof_policy_rejects_oversized_evidence_notes() {
        let notes = vec!["x".repeat(crate::BOUNDARY_MAX_STRING_LENGTH + 1)];
        let decision = no_mutation_proof_policy_decision(true, false, false, &notes);

        assert!(!decision.allow);
        assert_eq!(decision.reason.as_deref(), Some("boundary_limit_exceeded"));
    }
}
