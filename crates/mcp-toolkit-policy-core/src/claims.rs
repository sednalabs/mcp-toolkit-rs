//! Shared bearer and OIDC-claim policy checks.
//!
//! ## Rationale
//! Centralizes OIDC claim validation and bearer token processing. Ensures tokens
//! are verified against expected invariants (`iss`, `aud`, `azp`) before being
//! processed by downstream services.
//!
//! ## Security Boundaries
//! * Validates bearer header format to prevent injection or malformed input.
//! * Normalizes OIDC claims and enforces strict type checking to prevent bypasses via unexpected JSON structures.
//! * Implements boundary limits on claim values to prevent resource exhaustion attacks.
//! * Fails closed on all validation mismatches or malformed inputs.
//!
//! ## References
//! * [RFC 7519] JSON Web Token (JWT) Claim definitions.
//! * [OpenID Connect Core 1.0] OIDC claim validation requirements.
//!
//! ## Notes
//! * This module assumes claims are pre-verified (e.g. signature-verified by JWT middleware).
//! * Logic focuses solely on claim-content policy.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::boundary::{
    list_within_boundary_limits, optional_string_within_boundary_limit,
    string_within_boundary_limit, BOUNDARY_MAX_LIST_LENGTH,
};
use crate::{Decision, DecisionCode};

pub const MALFORMED_CLAIMS_REASON: &str = "malformed_claims";

/// Configuration for OIDC claims validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimsCfg {
    #[serde(default)]
    pub expected_issuer: Option<String>,
    #[serde(default)]
    pub expected_audience: Option<String>,
    #[serde(default)]
    pub allowed_azp: Vec<String>,
}

/// Input for bearer-header validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BearerInput {
    pub raw_bearer: String,
}

/// Input for claim validation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimsInput {
    pub cfg: ClaimsCfg,
    pub claims: serde_json::Map<String, Value>,
}

/// Validates that a bearer header is well-formed.
///
/// # Security
/// * Strictly enforces the 'Bearer <token>' format.
/// * Denies inputs with control characters, multiple spaces, or missing schemes
///   to prevent header-injection or parsing ambiguities.
pub fn validate_bearer_header(raw: &str) -> Decision {
    if !string_within_boundary_limit(raw) {
        return Decision::deny(DecisionCode::InvalidInput, Some("boundary_limits"));
    }

    if raw.trim() != raw || raw.chars().any(|ch| ch.is_control()) || raw.matches(' ').count() != 1 {
        return Decision::deny(DecisionCode::MissingToken, Some("invalid_bearer"));
    }

    let (scheme, token) = match raw.split_once(' ') {
        Some(parts) => parts,
        None => return Decision::deny(DecisionCode::MissingToken, Some("invalid_bearer")),
    };

    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return Decision::deny(DecisionCode::MissingToken, Some("invalid_bearer"));
    }

    Decision::allow()
}

/// Enforces OIDC claim invariants (`iss`, `aud`, `azp`).
///
/// # Security
/// * Validates that claims conform to expected types (e.g., string-only `iss`).
/// * Verifies that the issuer and audience match the configured security policy.
/// * If `allowed_azp` is configured, strictly validates the authorized party claim (`azp` or `client_id`).
/// * Fails closed if claim structure is malformed or types are unexpected.
pub fn enforce_claims(cfg: &ClaimsCfg, claims: &serde_json::Map<String, Value>) -> Decision {
    if !claims_input_within_boundary_limits(cfg, claims) {
        return Decision::deny(DecisionCode::InvalidInput, Some("boundary_limits"));
    }
    if !claims_have_valid_types(claims) {
        return Decision::deny(DecisionCode::InvalidInput, Some(MALFORMED_CLAIMS_REASON));
    }

    if let Some(expected) = cfg.expected_issuer.as_ref() {
        let issuer = claims
            .get("iss")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if issuer != Some(expected.as_str()) {
            return Decision::deny(DecisionCode::IssuerMismatch, None);
        }
    }

    if let Some(expected_aud) = cfg.expected_audience.as_ref() {
        let audiences = extract_audiences(claims);
        if audiences.is_empty() || !audiences.iter().any(|aud| aud == expected_aud) {
            return Decision::deny(DecisionCode::AudienceMismatch, None);
        }
    }

    if !cfg.allowed_azp.is_empty() {
        let azp = claims
            .get("azp")
            .and_then(|value| value.as_str())
            .or_else(|| claims.get("client_id").and_then(|value| value.as_str()))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let allowed = azp
            .as_ref()
            .map(|value| cfg.allowed_azp.iter().any(|allowed| allowed == value))
            .unwrap_or(false);
        if !allowed {
            return Decision::deny(DecisionCode::AzpNotAllowed, None);
        }
    }

    Decision::allow()
}

fn claims_have_valid_types(claims: &serde_json::Map<String, Value>) -> bool {
    for key in ["iss", "azp", "client_id"] {
        if let Some(value) = claims.get(key) {
            if !value.is_string() {
                return false;
            }
        }
    }

    match claims.get("aud") {
        None => true,
        Some(Value::String(_)) => true,
        Some(Value::Array(values)) => values.iter().all(|value| value.is_string()),
        _ => false,
    }
}

fn extract_audiences(claims: &serde_json::Map<String, Value>) -> Vec<String> {
    match claims.get("aud") {
        Some(Value::String(value)) => value
            .split_whitespace()
            .filter(|part| !part.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_str())
            .map(ToOwned::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn normalized_claim_string_within_limits(
    claims: &serde_json::Map<String, Value>,
    key: &str,
) -> bool {
    optional_string_within_boundary_limit(
        claims
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty()),
    )
}

fn normalized_claim_audience_within_limits(claims: &serde_json::Map<String, Value>) -> bool {
    match claims.get("aud") {
        None => true,
        Some(Value::String(value)) => {
            let audiences = value
                .split_whitespace()
                .filter(|segment| !segment.is_empty())
                .collect::<Vec<_>>();
            audiences.len() <= BOUNDARY_MAX_LIST_LENGTH
                && audiences
                    .iter()
                    .all(|aud| string_within_boundary_limit(aud))
        }
        Some(Value::Array(values)) => {
            let mut count = 0usize;
            for value in values {
                let Some(aud) = value.as_str() else {
                    continue;
                };
                let aud = aud.trim();
                if aud.is_empty() {
                    continue;
                }
                count += 1;
                if count > BOUNDARY_MAX_LIST_LENGTH || !string_within_boundary_limit(aud) {
                    return false;
                }
            }
            true
        }
        _ => true,
    }
}

fn claims_cfg_within_boundary_limits(cfg: &ClaimsCfg) -> bool {
    optional_string_within_boundary_limit(cfg.expected_issuer.as_deref())
        && optional_string_within_boundary_limit(cfg.expected_audience.as_deref())
        && list_within_boundary_limits(&cfg.allowed_azp)
}

fn claims_input_within_boundary_limits(
    cfg: &ClaimsCfg,
    claims: &serde_json::Map<String, Value>,
) -> bool {
    claims_cfg_within_boundary_limits(cfg)
        && normalized_claim_string_within_limits(claims, "iss")
        && normalized_claim_string_within_limits(claims, "azp")
        && normalized_claim_string_within_limits(claims, "client_id")
        && normalized_claim_audience_within_limits(claims)
}

#[cfg(test)]
mod tests {
    use super::{
        claims_have_valid_types, enforce_claims, normalized_claim_audience_within_limits,
        validate_bearer_header, ClaimsCfg, MALFORMED_CLAIMS_REASON,
    };
    use crate::boundary::{BOUNDARY_MAX_LIST_LENGTH, BOUNDARY_MAX_STRING_LENGTH};
    use serde_json::json;

    #[test]
    fn bearer_validation_accepts_standard_value() {
        let decision = validate_bearer_header("Bearer abc123");
        assert!(decision.allow);
    }

    #[test]
    fn bearer_validation_rejects_bad_spacing() {
        let decision = validate_bearer_header("Bearer  abc123");
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("MISSING_TOKEN"));
        assert_eq!(decision.reason.as_deref(), Some("invalid_bearer"));
    }

    #[test]
    fn claims_enforcement_accepts_matching_claims() {
        let cfg = ClaimsCfg {
            expected_issuer: Some("https://issuer.example".to_string()),
            expected_audience: Some("mcp".to_string()),
            allowed_azp: vec!["client-a".to_string()],
        };
        let claims = json!({
            "iss": "https://issuer.example",
            "aud": ["mcp"],
            "azp": "client-a"
        })
        .as_object()
        .expect("claims object")
        .clone();

        let decision = enforce_claims(&cfg, &claims);
        assert!(decision.allow);
    }

    #[test]
    fn claims_enforcement_rejects_audience_mismatch() {
        let cfg = ClaimsCfg {
            expected_issuer: None,
            expected_audience: Some("mcp".to_string()),
            allowed_azp: Vec::new(),
        };
        let claims = json!({ "aud": ["other"] })
            .as_object()
            .expect("claims object")
            .clone();

        let decision = enforce_claims(&cfg, &claims);
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("AUDIENCE_MISMATCH"));
    }

    #[test]
    fn claims_enforcement_rejects_non_string_claim_shapes() {
        let cfg = ClaimsCfg {
            expected_issuer: None,
            expected_audience: None,
            allowed_azp: Vec::new(),
        };
        let claims = json!({
            "iss": 123,
            "azp": false,
            "client_id": null,
            "aud": ["mcp", 2, "", "   "]
        })
        .as_object()
        .expect("claims object")
        .clone();

        let decision = enforce_claims(&cfg, &claims);
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("INVALID_INPUT"));
        assert_eq!(decision.reason.as_deref(), Some(MALFORMED_CLAIMS_REASON));
    }

    #[test]
    fn claims_shape_validation_rejects_non_string_client_id() {
        let claims = json!({ "client_id": 77 })
            .as_object()
            .expect("claims object")
            .clone();
        assert!(!claims_have_valid_types(&claims));
    }

    #[test]
    fn claims_shape_validation_rejects_non_string_audience() {
        let claims = json!({ "aud": { "value": "mcp" } })
            .as_object()
            .expect("claims object")
            .clone();
        assert!(!claims_have_valid_types(&claims));
    }

    #[test]
    fn claims_shape_validation_accepts_string_audience_list() {
        let claims = json!({ "aud": ["mcp", "ops"] })
            .as_object()
            .expect("claims object")
            .clone();
        assert!(claims_have_valid_types(&claims));
    }

    #[test]
    fn normalized_audience_enforces_string_limits() {
        let oversized_string = "a".repeat(BOUNDARY_MAX_STRING_LENGTH + 1);
        let claims = json!({ "aud": oversized_string })
            .as_object()
            .expect("claims object")
            .clone();
        assert!(!normalized_claim_audience_within_limits(&claims));
    }

    #[test]
    fn normalized_audience_ignores_non_strings() {
        let claims = json!({ "aud": ["mcp", 3, "other", "", "   "] })
            .as_object()
            .expect("claims object")
            .clone();
        assert!(normalized_claim_audience_within_limits(&claims));
    }

    #[test]
    fn normalized_audience_enforces_list_length_after_filtering() {
        let mut entries = Vec::new();
        for _ in 0..(BOUNDARY_MAX_LIST_LENGTH + 1) {
            entries.push(json!("valid"));
        }
        let claims = json!({ "aud": entries })
            .as_object()
            .expect("claims object")
            .clone();
        assert!(!normalized_claim_audience_within_limits(&claims));
    }
}
