//! # Auth Claim Primitives
//!
//! Shared OIDC/JWT claim validation logic.
//!
//! ## Ownership
//! This module owns the claim extraction logic, issuer/audience validation, and
//! role/scope normalization for OIDC and bearer tokens.
//!
//! ## Non-ownership
//! This module does not perform cryptographic signature verification; it assumes
//! claims have been pre-verified by a preceding auth provider.
//!
//! ## Policy & Guarantees
//! * **Claim Normalization**: Standardizes extraction of roles and scopes to
//!   ensure consistent authorization context.
//! * **Invariant Enforcement**: Validates that OIDC claims conform to standard
//!   invariants (e.g., issuer, audience) before processing.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying claims that have already undergone signature verification.
//! * Providing the correct `AuthConfig` reflecting their environment security policy.
//!
//! ## References
//! * [RFC 7519] JSON Web Token (JWT).
//! * [OpenID Connect Core 1.0].

use std::collections::HashSet;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::errors::ErrorKind;
use serde_json::Value;
use tracing::debug;

use crate::{AuthConfig, AuthError};

const JWT_CLAIMS_MAX_BYTES: usize = 128 * 1024;

/// Validates that the token issuer and audience match the security configuration.
pub(crate) fn validate_issuer_audience(
    claims: &Value,
    config: &AuthConfig,
) -> Result<(), AuthError> {
    if let Some(expected_issuer) = config.issuer.as_ref() {
        let issuer = claims
            .get("iss")
            .and_then(|value| value.as_str())
            .map(|value| value.trim())
            .filter(|value| !value.is_empty());
        if issuer != Some(expected_issuer.as_str()) {
            return Err(AuthError::InvalidToken);
        }
    }

    if let Some(expected_audience) = config.audience.as_ref() {
        let audiences = extract_audiences(claims);
        if audiences.is_empty() || !audiences.iter().any(|aud| aud == expected_audience) {
            return Err(AuthError::InvalidToken);
        }
    }

    Ok(())
}

fn extract_audiences(claims: &Value) -> Vec<String> {
    let Some(audience) = claims.get("aud") else {
        return Vec::new();
    };

    match audience {
        Value::String(value) => value
            .split_whitespace()
            .map(|aud| aud.trim().to_string())
            .filter(|aud| !aud.is_empty())
            .collect(),
        Value::Array(values) => values
            .iter()
            .filter_map(|value| value.as_str())
            .map(|aud| aud.trim().to_string())
            .filter(|aud| !aud.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn required_claims() -> HashSet<String> {
    [
        "exp".to_string(),
        "sub".to_string(),
        "aud".to_string(),
        "iss".to_string(),
    ]
    .into_iter()
    .collect()
}

pub(crate) fn auth_error_from_jwt(err: jsonwebtoken::errors::Error) -> AuthError {
    if tracing::enabled!(tracing::Level::DEBUG) {
        debug!(error = %err, kind = ?err.kind(), "JWT validation failed");
    }
    match err.kind() {
        ErrorKind::ExpiredSignature => AuthError::TokenExpired,
        ErrorKind::InvalidAudience => {
            AuthError::new("Invalid bearer token.").with_reason("invalid_audience")
        }
        ErrorKind::InvalidIssuer => {
            AuthError::new("Invalid bearer token.").with_reason("invalid_issuer")
        }
        ErrorKind::InvalidSubject => {
            AuthError::new("Invalid bearer token.").with_reason("invalid_subject")
        }
        ErrorKind::MissingRequiredClaim(_) => {
            AuthError::new("Invalid bearer token.").with_reason("missing_claim")
        }
        ErrorKind::ImmatureSignature => {
            AuthError::new("Invalid bearer token.").with_reason("immature_signature")
        }
        ErrorKind::InvalidSignature => {
            AuthError::new("Invalid bearer token.").with_reason("invalid_signature")
        }
        ErrorKind::InvalidAlgorithm
        | ErrorKind::InvalidAlgorithmName
        | ErrorKind::MissingAlgorithm => {
            AuthError::new("Invalid bearer token.").with_reason("invalid_algorithm")
        }
        ErrorKind::InvalidKeyFormat
        | ErrorKind::InvalidEcdsaKey
        | ErrorKind::InvalidEddsaKey
        | ErrorKind::InvalidRsaKey(_)
        | ErrorKind::Provider(_)
        | ErrorKind::RsaFailedSigning
        | ErrorKind::Signing(_) => {
            AuthError::new("Invalid bearer token.").with_reason("invalid_key")
        }
        ErrorKind::InvalidToken
        | ErrorKind::Base64(_)
        | ErrorKind::Json(_)
        | ErrorKind::Utf8(_) => {
            AuthError::new("Invalid bearer token.").with_reason("invalid_token")
        }
        _ => AuthError::InvalidToken,
    }
}

pub(crate) fn extract_scopes(claims: &Value) -> Vec<String> {
    let scope = claims
        .get("scope")
        .or_else(|| claims.get("scp"))
        .or_else(|| claims.get("scopes"));
    match scope {
        Some(Value::String(value)) => value
            .split_whitespace()
            .map(|scope| scope.trim().to_string())
            .filter(|scope| !scope.is_empty())
            .collect(),
        Some(Value::Array(list)) => list
            .iter()
            .filter_map(|value| value.as_str())
            .map(|scope| scope.trim().to_string())
            .filter(|scope| !scope.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn extract_roles(claims: &Value) -> Vec<String> {
    let mut roles: Vec<String> = Vec::new();

    if let Some(realm_access) = claims
        .get("realm_access")
        .and_then(|value| value.as_object())
    {
        if let Some(role_list) = realm_access.get("roles").and_then(|value| value.as_array()) {
            for role in role_list {
                if let Some(value) = role.as_str() {
                    let trimmed = value.trim();
                    if !trimmed.is_empty() {
                        roles.push(trimmed.to_string());
                    }
                }
            }
        }
    }

    if let Some(resource_access) = claims
        .get("resource_access")
        .and_then(|value| value.as_object())
    {
        for client_access in resource_access.values() {
            if let Some(role_list) = client_access
                .get("roles")
                .and_then(|value| value.as_array())
            {
                for role in role_list {
                    if let Some(value) = role.as_str() {
                        let trimmed = value.trim();
                        if !trimmed.is_empty() {
                            roles.push(trimmed.to_string());
                        }
                    }
                }
            }
        }
    }

    roles.sort();
    roles.dedup();
    roles
}

pub(crate) fn supplemental_jwt_claims(token: &str) -> Option<Value> {
    let token = token.trim();
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    if parts.next().is_some() || header.is_empty() || payload.is_empty() || signature.is_empty() {
        return None;
    }

    let header = decode_jwt_part(header)?;
    let header = header.as_object()?;
    let alg = header
        .get("alg")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if alg.eq_ignore_ascii_case("none") {
        return None;
    }

    let payload = decode_jwt_part(payload)?;
    payload.is_object().then_some(payload)
}

fn decode_jwt_part(part: &str) -> Option<Value> {
    let part = part.trim_end_matches('=');
    if part.len() > JWT_CLAIMS_MAX_BYTES {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(part).ok()?;
    if decoded.len() > JWT_CLAIMS_MAX_BYTES {
        return None;
    }
    serde_json::from_slice::<Value>(&decoded).ok()
}

pub(crate) fn merge_claims(primary: &Value, secondary: &Value) -> Value {
    match (primary.as_object(), secondary.as_object()) {
        (Some(primary_map), Some(secondary_map)) => {
            let mut merged = primary_map.clone();
            for (key, value) in secondary_map {
                merged.insert(key.clone(), value.clone());
            }
            Value::Object(merged)
        }
        _ => primary.clone(),
    }
}
