//! # Bearer Authentication Challenges
//!
//! Utilities for building RFC-compliant `WWW-Authenticate: Bearer` headers.
//!
//! ## Ownership
//! This module owns the logic for constructing and normalizing challenge headers,
//! ensuring that dynamic components are safe for HTTP transport.
//!
//! ## Non-ownership
//! This module does not manage the overall authentication flow or transport-layer security.
//!
//! ## Policy & Guarantees
//! * **Injection Mitigation**: Sanitizes and escapes header values (quotes, backslashes,
//!   control characters) to mitigate header-injection risks.
//! * **Standard Compliance**: Constructs challenges per RFC 6750 / MCP Authorization specs.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying accurate, well-formed challenge parameters (e.g., realm, metadata).
//! * Providing transport-layer security (TLS) for the authentication surface.
//!
//! ## References
//! * [RFC 6750 (OAuth 2.0 Bearer Token Usage)](https://tools.ietf.org/html/rfc6750)
//! * [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization.md)

use http::header::HeaderValue;

/// Structured inputs for building a Bearer `WWW-Authenticate` challenge.
#[derive(Debug, Clone, Default)]
pub struct BearerChallenge<'a> {
    pub realm: &'a str,
    pub resource_metadata: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub error: Option<&'a str>,
    pub error_description: Option<&'a str>,
    pub error_uri: Option<&'a str>,
}

impl<'a> BearerChallenge<'a> {
    pub fn resource_metadata(realm: &'a str, resource_metadata: &'a str) -> Self {
        Self {
            realm,
            resource_metadata: Some(resource_metadata),
            ..Default::default()
        }
    }
}

/// Builds a Bearer `WWW-Authenticate` header value with RFC-compliant parameters.
///
/// # Security
/// * Performs best-effort sanitization and escaping of input parameters to mitigate
///   attribute-value injection.
pub fn build_bearer_challenge(challenge: &BearerChallenge<'_>) -> HeaderValue {
    let mut parts = Vec::new();
    let realm = escape_quoted(sanitize_value(challenge.realm));
    parts.push(format!("Bearer realm=\"{realm}\""));

    if let Some(value) = challenge.resource_metadata {
        push_param(&mut parts, "resource_metadata", value);
    }
    if let Some(value) = challenge.scope {
        push_param(&mut parts, "scope", value);
    }
    if let Some(value) = challenge.error {
        push_param(&mut parts, "error", value);
    }
    if let Some(value) = challenge.error_description {
        push_param(&mut parts, "error_description", value);
    }
    if let Some(value) = challenge.error_uri {
        push_param(&mut parts, "error_uri", value);
    }

    let value = parts.join(", ");
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
}

/// Builds a Bearer challenge header string.
pub fn build_bearer_challenge_value(challenge: &BearerChallenge<'_>) -> Option<String> {
    build_bearer_challenge(challenge)
        .to_str()
        .ok()
        .map(|value| value.to_string())
}

fn push_param(parts: &mut Vec<String>, name: &str, value: &str) {
    let sanitized = sanitize_value(value);
    if sanitized.is_empty() {
        return;
    }
    let escaped = escape_quoted(sanitized);
    parts.push(format!("{name}=\"{escaped}\""));
}

fn sanitize_value(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

fn escape_quoted(value: String) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::{build_bearer_challenge, build_bearer_challenge_value, BearerChallenge};

    #[test]
    fn builds_resource_metadata_challenge() {
        let challenge = BearerChallenge::resource_metadata(
            "kc-admin-mcp",
            "http://localhost/.well-known/oauth-protected-resource/mcp",
        );
        let header = build_bearer_challenge(&challenge);
        let value = header.to_str().expect("header");
        assert!(value.contains("Bearer realm=\"kc-admin-mcp\""));
        assert!(value.contains(
            "resource_metadata=\"http://localhost/.well-known/oauth-protected-resource/mcp\""
        ));
    }

    #[test]
    fn escapes_quotes_in_values() {
        let challenge = BearerChallenge {
            realm: "kc\"admin",
            resource_metadata: Some("http://localhost/\"mcp\""),
            scope: None,
            error: None,
            error_description: None,
            error_uri: None,
        };
        let header = build_bearer_challenge(&challenge);
        let value = header.to_str().expect("header");
        assert!(value.contains("realm=\"kc\\\"admin\""));
        assert!(value.contains("resource_metadata=\"http://localhost/\\\"mcp\\\"\""));
    }

    #[test]
    fn build_bearer_challenge_value_round_trip() {
        let challenge = BearerChallenge::resource_metadata(
            "kc-admin-mcp",
            "http://localhost/.well-known/oauth-protected-resource/mcp",
        );
        let value = build_bearer_challenge_value(&challenge).expect("header");
        assert!(value.contains("Bearer realm=\"kc-admin-mcp\""));
    }
}
