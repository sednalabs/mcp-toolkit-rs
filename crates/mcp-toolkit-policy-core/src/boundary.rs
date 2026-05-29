//! # Boundary Limits
//!
//! Helpers for enforcing payload size constraints defined by the policy kernel.
//!
//! ## Ownership
//! This module owns the validation helpers that enforce string length and list-size
//! constraints based on `mcp-policy-kernel` artifacts.
//!
//! ## Non-ownership
//! This module does not define the limits itself; it consumes values generated
//! from upstream policy kernel artifacts (`pk_boundary.rs`).
//!
//! ## Policy & Guarantees
//! * **Payload Bounding**: Mitigates resource exhaustion by rejecting inputs
//!   exceeding established contract limits.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Integrating these validation helpers at appropriate policy-enforcement boundaries.
//! * Handling validation failures (e.g., rejecting requests) when these limits are exceeded.
//!
//! ## References
//! * Policy Kernel: `mcp-policy-kernel` (upstream boundary definition)

include!(concat!(env!("OUT_DIR"), "/pk_boundary.rs"));

/// Validates that a string length fits within the boundary contract.
pub fn string_within_boundary_limit(value: &str) -> bool {
    value.len() <= BOUNDARY_MAX_STRING_LENGTH
}

/// Validates that an optional string length fits within the boundary contract.
pub fn optional_string_within_boundary_limit(value: Option<&str>) -> bool {
    value.map(string_within_boundary_limit).unwrap_or(true)
}

/// Validates that list length and item sizes fit within the boundary contract.
pub fn list_within_boundary_limits(values: &[String]) -> bool {
    values.len() <= BOUNDARY_MAX_LIST_LENGTH
        && values
            .iter()
            .all(|value| string_within_boundary_limit(value.as_str()))
}
