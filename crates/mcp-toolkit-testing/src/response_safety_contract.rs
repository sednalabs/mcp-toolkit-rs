//! # Response Safety Contract Assertions
//!
//! Test helpers for asserting structured MCP response safety contracts.
//!
//! ## Rationale
//! Downstream MCP servers often need the same regression checks: no raw secret
//! substrings, no accidental mutation flags, and no production action
//! authorization in proof-only responses.
//!
//! ## Security Boundaries
//! * Test-only helpers; they do not sanitize production output.
//! * Assertions operate on serialized JSON so callers test the external
//!   response contract, not internal Rust-only state.

use serde::Serialize;
use serde_json::Value;

/// Asserts that a serializable payload does not contain forbidden substrings.
///
/// # Panics
/// Panics when serialization fails or a forbidden substring is present.
pub fn assert_payload_excludes_substrings<T, S>(payload: &T, forbidden: &[S])
where
    T: Serialize,
    S: AsRef<str>,
{
    let rendered = serde_json::to_string(payload)
        .unwrap_or_else(|err| panic!("failed to serialize payload for leak assertion: {err}"));
    for needle in forbidden {
        let needle = needle.as_ref();
        assert!(
            !rendered.contains(needle),
            "serialized payload contained forbidden substring: {needle}"
        );
    }
}

/// Asserts that a serialized object field is exactly boolean `false`.
///
/// # Panics
/// Panics when serialization fails, the payload is not an object, the field is
/// missing, or the field is not `false`.
pub fn assert_json_bool_field_false<T>(payload: &T, field: &str)
where
    T: Serialize,
{
    let value = serde_json::to_value(payload)
        .unwrap_or_else(|err| panic!("failed to serialize payload for field assertion: {err}"));
    assert_value_bool_field_false(&value, field);
}

/// Asserts the standard no-mutation proof response flags.
///
/// # Panics
/// Panics when `mutation_performed` or `production_action_authorized` is absent
/// or not exactly boolean `false`.
pub fn assert_no_mutation_proof_flags<T>(payload: &T)
where
    T: Serialize,
{
    assert_json_bool_field_false(payload, "mutation_performed");
    assert_json_bool_field_false(payload, "production_action_authorized");
}

fn assert_value_bool_field_false(value: &Value, field: &str) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("payload must serialize to a JSON object"));
    assert_eq!(
        object.get(field),
        Some(&Value::Bool(false)),
        "payload field `{field}` must be boolean false"
    );
}

#[cfg(test)]
mod tests {
    use super::{
        assert_json_bool_field_false, assert_no_mutation_proof_flags,
        assert_payload_excludes_substrings,
    };
    use serde::Serialize;

    #[derive(Debug, Serialize)]
    struct ProofPayload {
        mutation_performed: bool,
        production_action_authorized: bool,
        redacted_email: String,
    }

    #[test]
    fn excludes_forbidden_substrings_from_serialized_payload() {
        let payload = ProofPayload {
            mutation_performed: false,
            production_action_authorized: false,
            redacted_email: "p***@example.invalid".to_string(),
        };

        assert_payload_excludes_substrings(&payload, &["person@example.invalid"]);
    }

    #[test]
    fn asserts_standard_no_mutation_flags() {
        let payload = ProofPayload {
            mutation_performed: false,
            production_action_authorized: false,
            redacted_email: "p***@example.invalid".to_string(),
        };

        assert_json_bool_field_false(&payload, "mutation_performed");
        assert_no_mutation_proof_flags(&payload);
    }
}
