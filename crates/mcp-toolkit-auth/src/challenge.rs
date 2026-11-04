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

/// Build the OAuth challenge metadata used by MCP Apps tool-level errors.
///
/// This returns the `_meta` JSON object, not an HTTP response and not a
/// `CallToolResult`. The caller remains responsible for marking the result
/// `isError=true`, enforcing the request's OAuth permissions and attaching
/// this metadata to the actual tool response.
///
/// Returns `None` for missing or blank resource metadata or descriptions,
/// missing or unsupported bearer errors, missing or blank insufficient-scope
/// hints, or control characters in any supplied field. URL syntax and scope
/// token validity remain the caller's responsibility.
///
/// ```
/// use mcp_toolkit_auth::challenge::{
///     BearerChallenge, build_mcp_apps_tool_authenticate_meta
/// };
/// let challenge = BearerChallenge {
///     realm: "example-mcp",
///     resource_metadata: Some("https://example.com/.well-known/oauth-protected-resource/mcp"),
///     scope: Some("items.write"),
///     error: Some("insufficient_scope"),
///     error_description: Some("Additional write permission is required."),
///     error_uri: None,
/// };
/// let meta = build_mcp_apps_tool_authenticate_meta(&challenge).unwrap();
/// assert_eq!(meta["mcp/www_authenticate"].as_array().unwrap().len(), 1);
/// ```
///
/// # Security
///
/// The resource metadata URL and required scopes must be derived from trusted
/// deployment/auth context, never from an untrusted tool argument or message.
/// Callers must validate URL syntax and trust; this helper only checks that
/// resource metadata is nonempty and all supplied fields are control-free.
/// This helper is presentation only; it never grants access or invokes login.
pub fn build_mcp_apps_tool_authenticate_meta(
    challenge: &BearerChallenge<'_>,
) -> Option<serde_json::Value> {
    let metadata = challenge.resource_metadata?;
    let error = challenge.error?;
    let description = challenge.error_description?;
    let has_control = [
        Some(challenge.realm),
        Some(metadata),
        Some(error),
        Some(description),
        challenge.scope,
        challenge.error_uri,
    ]
    .iter()
    .flatten()
    .any(|value| value.chars().any(char::is_control));
    if metadata.trim().is_empty()
        || !matches!(
            error,
            "invalid_request" | "invalid_token" | "insufficient_scope"
        )
        || description.trim().is_empty()
        || has_control
    {
        return None;
    }
    if error == "insufficient_scope" && challenge.scope.is_none_or(|scope| scope.trim().is_empty())
    {
        return None;
    }
    let value = build_bearer_challenge_value(challenge)?;
    Some(serde_json::json!({ "mcp/www_authenticate": [value] }))
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
    use super::{
        build_bearer_challenge, build_bearer_challenge_value,
        build_mcp_apps_tool_authenticate_meta, BearerChallenge,
    };
    use mcp_toolkit_testing::openai_apps_contract::OpenAiAppsConformanceProfile;

    fn apps_challenge() -> BearerChallenge<'static> {
        BearerChallenge {
            realm: "example",
            resource_metadata: Some(
                "https://example.test/.well-known/oauth-protected-resource/mcp",
            ),
            scope: Some("irc.write"),
            error: Some("insufficient_scope"),
            error_description: Some("Permission to send messages is required."),
            error_uri: None,
        }
    }

    #[test]
    fn apps_challenge_passes_existing_chatgpt_contract() {
        let meta = build_mcp_apps_tool_authenticate_meta(&apps_challenge()).unwrap();
        let issuers = ["https://issuer.example"];
        let scopes = ["irc.write"];
        OpenAiAppsConformanceProfile::new("https://example.test/mcp", &issuers)
            .with_required_scopes(&scopes)
            .assert_tool_result_authenticate_meta(&meta);
    }

    #[test]
    fn apps_challenge_fails_closed_without_required_ui_fields() {
        let mut c = apps_challenge();
        c.resource_metadata = None;
        assert!(build_mcp_apps_tool_authenticate_meta(&c).is_none());
        c = apps_challenge();
        c.error = None;
        assert!(build_mcp_apps_tool_authenticate_meta(&c).is_none());
        c = apps_challenge();
        c.error = Some("not_a_bearer_error");
        assert!(build_mcp_apps_tool_authenticate_meta(&c).is_none());
        c = apps_challenge();
        c.error_description = Some("   ");
        assert!(build_mcp_apps_tool_authenticate_meta(&c).is_none());
        c = apps_challenge();
        c.scope = None;
        assert!(build_mcp_apps_tool_authenticate_meta(&c).is_none());
    }

    #[test]
    fn apps_challenge_rejects_injected_newlines() {
        let mut c = apps_challenge();
        c.resource_metadata = Some("https://example.test/mcp\nX-Attack: yes");
        assert!(build_mcp_apps_tool_authenticate_meta(&c).is_none());
        c = apps_challenge();
        c.error_description = Some("Please login\r\nX-Attack: yes");
        assert!(build_mcp_apps_tool_authenticate_meta(&c).is_none());
        c = apps_challenge();
        c.scope = Some("irc.write\nextra");
        assert!(build_mcp_apps_tool_authenticate_meta(&c).is_none());
    }

    #[test]
    fn apps_challenge_rejects_controls_in_remaining_fields() {
        let mut c = apps_challenge();
        c.realm = "example\nother";
        assert!(build_mcp_apps_tool_authenticate_meta(&c).is_none());
        c = apps_challenge();
        c.error_uri = Some("https://example.test/help\r\nother");
        assert!(build_mcp_apps_tool_authenticate_meta(&c).is_none());
        for error in ["invalid_token", "invalid_request"] {
            c = apps_challenge();
            c.error = Some(error);
            c.scope = Some("items.read\nadmin");
            assert!(build_mcp_apps_tool_authenticate_meta(&c).is_none());
        }
    }

    #[test]
    fn apps_challenge_preserves_valid_optional_fields() {
        for error in ["invalid_token", "invalid_request", "insufficient_scope"] {
            let mut c = apps_challenge();
            c.error = Some(error);
            c.error_uri = Some("https://example.test/help");
            let meta = build_mcp_apps_tool_authenticate_meta(&c).unwrap();
            let value = meta["mcp/www_authenticate"][0].as_str().unwrap();
            assert!(value.contains(r#"realm="example""#));
            assert!(value.contains(r#"scope="irc.write""#));
            assert!(value.contains(r#"error_uri="https://example.test/help""#));
            let issuers = ["https://issuer.example"];
            let scopes = ["irc.write"];
            OpenAiAppsConformanceProfile::new("https://example.test/mcp", &issuers)
                .with_required_scopes(&scopes)
                .assert_tool_result_authenticate_meta(&meta);
            c.scope = None;
            if error != "insufficient_scope" {
                assert!(build_mcp_apps_tool_authenticate_meta(&c).is_some());
            }
        }
    }

    #[test]
    fn apps_challenge_escapes_header_metacharacters() {
        let mut c = apps_challenge();
        c.error_description = Some("Permission for \"IRC write\" is required.");
        let meta = build_mcp_apps_tool_authenticate_meta(&c).unwrap();
        let serialized = meta["mcp/www_authenticate"][0].as_str().unwrap();
        assert!(
            serialized.contains(r#"error_description="Permission for \"IRC write\" is required.""#)
        );
    }

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
