//! # Break-glass Policy Validation
//!
//! Primitives for validating emergency access ("break-glass") policy constraints.
//!
//! ## Ownership
//! This module owns the validation logic for break-glass policy contracts,
//! ensuring that emergency overrides are accompanied by required metadata.
//!
//! ## Non-ownership
//! This module does not perform I/O or persist emergency status. It acts as
//! a pure validation layer for the policy state.
//!
//! ## Policy & Guarantees
//! * **Policy Enforcement**: Ensures that enabled break-glass scenarios provide
//!   an explicit reason and TTL to aid in auditability.
//! * **Production Safety**: Guards against unconfigured production environments
//!   running without an explicit allowlist.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying accurate policy state information.
//! * Ensuring that break-glass events are properly logged/audited in the host service.
//!
//! ## References
//! * Policy Kernel: `mcp-policy-kernel` emergency access patterns.

/// Input contract for validating open-allowlist break-glass policy.
#[derive(Debug, Clone)]
pub struct BreakGlassAllowlistPolicy<'a> {
    pub production_mode: bool,
    pub break_glass_enabled: bool,
    pub break_glass_reason: Option<&'a str>,
    pub break_glass_ttl_s: Option<u64>,
    pub allowlist_configured: bool,
    pub reason_required_error: &'a str,
    pub ttl_required_error: &'a str,
    pub production_allowlist_error: &'a str,
}

/// Validates allowlist/break-glass policy constraints.
///
/// # Policy
/// * Rejects production environments missing both an allowlist and a valid break-glass override.
/// * Rejects enabled break-glass overrides missing a reason or TTL.
pub fn validate_break_glass_allowlist_policy(
    policy: &BreakGlassAllowlistPolicy<'_>,
) -> Result<(), String> {
    if policy.break_glass_enabled {
        if policy
            .break_glass_reason
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(policy.reason_required_error.to_string());
        }
        if policy.break_glass_ttl_s.unwrap_or(0) == 0 {
            return Err(policy.ttl_required_error.to_string());
        }
    }

    if policy.production_mode && !policy.break_glass_enabled && !policy.allowlist_configured {
        return Err(policy.production_allowlist_error.to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_break_glass_allowlist_policy, BreakGlassAllowlistPolicy};

    fn base_policy() -> BreakGlassAllowlistPolicy<'static> {
        BreakGlassAllowlistPolicy {
            production_mode: true,
            break_glass_enabled: false,
            break_glass_reason: None,
            break_glass_ttl_s: None,
            allowlist_configured: false,
            reason_required_error: "reason_required",
            ttl_required_error: "ttl_required",
            production_allowlist_error: "allowlist_required",
        }
    }

    #[test]
    fn rejects_open_production_without_allowlist() {
        let err = validate_break_glass_allowlist_policy(&base_policy())
            .expect_err("missing allowlists should fail in production");
        assert_eq!(err, "allowlist_required");
    }

    #[test]
    fn accepts_when_allowlist_present() {
        let mut policy = base_policy();
        policy.allowlist_configured = true;
        validate_break_glass_allowlist_policy(&policy)
            .expect("configured allowlist should satisfy production policy");
    }

    #[test]
    fn accepts_break_glass_when_reason_and_ttl_set() {
        let mut policy = base_policy();
        policy.break_glass_enabled = true;
        policy.break_glass_reason = Some("temporary emergency rollout");
        policy.break_glass_ttl_s = Some(3600);
        validate_break_glass_allowlist_policy(&policy)
            .expect("break-glass override should bypass allowlist requirement");
    }

    #[test]
    fn break_glass_requires_reason() {
        let mut policy = base_policy();
        policy.break_glass_enabled = true;
        policy.break_glass_ttl_s = Some(3600);
        let err = validate_break_glass_allowlist_policy(&policy)
            .expect_err("break-glass should require reason");
        assert_eq!(err, "reason_required");
    }

    #[test]
    fn break_glass_requires_ttl() {
        let mut policy = base_policy();
        policy.break_glass_enabled = true;
        policy.break_glass_reason = Some("temporary emergency rollout");
        let err = validate_break_glass_allowlist_policy(&policy)
            .expect_err("break-glass should require ttl");
        assert_eq!(err, "ttl_required");
    }
}
