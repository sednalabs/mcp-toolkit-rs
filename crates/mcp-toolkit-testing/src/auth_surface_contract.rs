//! Shared contract assertions for toolkit auth-surface tests.
//!
//! The goal is to keep auth-surface integration tests focused on the public
//! PRM discovery and core missing-token bearer-challenge semantics rather than on
//! service-specific policy or transport wiring.

use mcp_toolkit_http::oauth::{resource_metadata_hint, BEARER_METHOD_HEADER};
use serde_json::Value;
use std::collections::HashMap;

use http::{header, HeaderMap, StatusCode};

/// Contract assertions for a single auth-surface PRM discovery and core missing-token case.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat the supplied values as trusted test fixtures.
///
/// # Panics
/// * Panics when the configured resource URL cannot be converted into PRM metadata.
#[derive(Debug, Clone)]
pub struct AuthSurfaceContract<'a> {
    resource_url: &'a str,
    authorization_servers: &'a [&'a str],
    scopes_supported: &'a [&'a str],
    realm: &'a str,
}

impl<'a> AuthSurfaceContract<'a> {
    /// Build a new auth-surface contract assertion case.
    ///
    /// # Errors
    /// * This function does not return errors.
    ///
    /// # Security
    /// * Treat the supplied values as trusted test fixtures.
    ///
    /// # Panics
    /// * None.
    pub fn new(
        resource_url: &'a str,
        authorization_servers: &'a [&'a str],
        scopes_supported: &'a [&'a str],
        realm: &'a str,
    ) -> Self {
        Self {
            resource_url,
            authorization_servers,
            scopes_supported,
            realm,
        }
    }

    /// Return the expected PRM URL for the configured resource.
    ///
    /// # Errors
    /// * This function does not return errors.
    ///
    /// # Security
    /// * Treat the configured resource URL as trusted test input.
    ///
    /// # Panics
    /// * Panics if the configured resource URL is invalid.
    pub fn resource_metadata_url(&self) -> String {
        resource_metadata_hint(self.resource_url).unwrap_or_else(|| {
            panic!(
                "invalid resource URL for auth-surface contract: {}",
                self.resource_url
            )
        })
    }

    /// Assert the RFC 9728 JSON payload returned by the PRM endpoint.
    ///
    /// # Errors
    /// * This function does not return errors.
    ///
    /// # Security
    /// * Treat all supplied values as trusted test fixtures.
    ///
    /// # Panics
    /// * Panics when the payload does not match the configured contract.
    pub fn assert_resource_metadata(&self, payload: &Value) {
        assert_eq!(payload["resource"].as_str(), Some(self.resource_url));
        assert_eq!(
            strings_from_value(payload.get("authorization_servers")),
            self.authorization_servers
                .iter()
                .copied()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            strings_from_value(payload.get("scopes_supported")),
            self.scopes_supported
                .iter()
                .copied()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            strings_from_value(payload.get("bearer_methods_supported")),
            vec![BEARER_METHOD_HEADER.to_string()]
        );
    }

    /// Assert the bearer challenge returned for the current first-slice auth-surface contract.
    ///
    /// When scopes are configured, this slice checks that the emitted scope
    /// hint matches the toolkit's current `scopes_supported.join(" ")`
    /// behavior instead of accepting any arbitrary non-empty hint.
    /// RFC 6750 `error` and `error_description` fields remain optional for
    /// missing-token challenges in this shared slice.
    ///
    /// # Errors
    /// * This function does not return errors.
    ///
    /// # Security
    /// * Treat all supplied values as trusted test fixtures.
    ///
    /// # Panics
    /// * Panics when the challenge does not match the configured contract.
    pub fn assert_missing_token_challenge(&self, challenge: &str) {
        let resource_metadata = self.resource_metadata_url();
        let params = bearer_challenge_params(challenge);

        assert_eq!(params.get("realm").map(String::as_str), Some(self.realm));
        assert_eq!(
            params.get("resource_metadata").map(String::as_str),
            Some(resource_metadata.as_str())
        );

        if !self.scopes_supported.is_empty() {
            let scope = params
                .get("scope")
                .unwrap_or_else(|| panic!("expected bearer scope hint for configured scopes"));
            let expected_scope = self.scopes_supported.join(" ");
            assert!(
                is_space_delimited_scope_hint(scope),
                "expected a non-empty space-delimited bearer scope hint"
            );
            assert_eq!(
                scope, &expected_scope,
                "expected bearer scope hint to match configured scopes"
            );
        }
    }

    /// Assert that HTTP response headers include the expected missing-token
    /// bearer challenge.
    ///
    /// # Panics
    /// Panics when `WWW-Authenticate` is missing or malformed.
    pub fn assert_missing_token_challenge_headers(&self, headers: &HeaderMap) {
        let challenge = headers
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .expect("expected bearer challenge header");
        self.assert_missing_token_challenge(challenge);
    }

    /// Assert that an HTTP response is a missing-token challenge for this auth
    /// surface contract.
    ///
    /// # Panics
    /// Panics when the status is not `401 Unauthorized` or the challenge
    /// headers do not match the contract.
    pub fn assert_missing_token_response(&self, status: StatusCode, headers: &HeaderMap) {
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        self.assert_missing_token_challenge_headers(headers);
    }
}

/// Expected OAuth authorization-server metadata for one issuer.
#[derive(Debug, Clone)]
pub struct AuthorizationServerMetadataContract<'a> {
    issuer: &'a str,
    authorization_endpoint: &'a str,
    token_endpoint: &'a str,
    registration_endpoint: Option<&'a str>,
    jwks_uri: Option<&'a str>,
    introspection_endpoint: Option<&'a str>,
    device_authorization_endpoint: Option<&'a str>,
    grant_types_supported: &'a [&'a str],
    client_id_metadata_document_supported: Option<bool>,
    token_endpoint_auth_methods_supported: &'a [&'a str],
    code_challenge_methods_supported: &'a [&'a str],
}

impl<'a> AuthorizationServerMetadataContract<'a> {
    /// Build a new authorization-server metadata contract with required
    /// endpoint fields.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(issuer: &'a str, authorization_endpoint: &'a str, token_endpoint: &'a str) -> Self {
        Self {
            issuer,
            authorization_endpoint,
            token_endpoint,
            registration_endpoint: None,
            jwks_uri: None,
            introspection_endpoint: None,
            device_authorization_endpoint: None,
            grant_types_supported: &[],
            client_id_metadata_document_supported: None,
            token_endpoint_auth_methods_supported: &[],
            code_challenge_methods_supported: &[],
        }
    }

    /// Expect a dynamic client registration endpoint.
    #[must_use]
    pub fn with_registration_endpoint(mut self, endpoint: &'a str) -> Self {
        self.registration_endpoint = Some(endpoint);
        self
    }

    /// Expect a JWK set URI.
    #[must_use]
    pub fn with_jwks_uri(mut self, uri: &'a str) -> Self {
        self.jwks_uri = Some(uri);
        self
    }

    /// Expect an introspection endpoint.
    #[must_use]
    pub fn with_introspection_endpoint(mut self, endpoint: &'a str) -> Self {
        self.introspection_endpoint = Some(endpoint);
        self
    }

    /// Expect an OAuth device authorization endpoint.
    #[must_use]
    pub fn with_device_authorization_endpoint(mut self, endpoint: &'a str) -> Self {
        self.device_authorization_endpoint = Some(endpoint);
        self
    }

    /// Expect the exact ordered grant type list emitted by the server.
    #[must_use]
    pub fn with_grant_types_supported(mut self, grant_types: &'a [&'a str]) -> Self {
        self.grant_types_supported = grant_types;
        self
    }

    /// Expect the Client ID Metadata Document support flag.
    #[must_use]
    pub fn with_client_id_metadata_document_supported(mut self, supported: bool) -> Self {
        self.client_id_metadata_document_supported = Some(supported);
        self
    }

    /// Expect the exact ordered token endpoint authentication method list emitted by the server.
    #[must_use]
    pub fn with_token_endpoint_auth_methods_supported(mut self, methods: &'a [&'a str]) -> Self {
        self.token_endpoint_auth_methods_supported = methods;
        self
    }

    /// Expect the exact ordered PKCE code challenge method list emitted by the server.
    #[must_use]
    pub fn with_code_challenge_methods_supported(mut self, methods: &'a [&'a str]) -> Self {
        self.code_challenge_methods_supported = methods;
        self
    }

    /// Assert the authorization-server metadata JSON object.
    ///
    /// # Panics
    /// Panics when the payload differs from the configured contract.
    pub fn assert_metadata(&self, payload: &Value) {
        assert_eq!(
            payload.get("issuer").and_then(Value::as_str),
            Some(self.issuer)
        );
        assert_eq!(
            payload
                .get("authorization_endpoint")
                .and_then(Value::as_str),
            Some(self.authorization_endpoint)
        );
        assert_eq!(
            payload.get("token_endpoint").and_then(Value::as_str),
            Some(self.token_endpoint)
        );
        assert_optional_string(payload, "registration_endpoint", self.registration_endpoint);
        assert_optional_string(payload, "jwks_uri", self.jwks_uri);
        assert_optional_string(
            payload,
            "introspection_endpoint",
            self.introspection_endpoint,
        );
        assert_optional_string(
            payload,
            "device_authorization_endpoint",
            self.device_authorization_endpoint,
        );
        if self.grant_types_supported.is_empty() {
            assert!(
                payload.get("grant_types_supported").is_none(),
                "did not expect grant_types_supported in metadata"
            );
        } else {
            assert_eq!(
                strings_from_value(payload.get("grant_types_supported")),
                self.grant_types_supported
                    .iter()
                    .copied()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            );
        }
        if let Some(supported) = self.client_id_metadata_document_supported {
            assert_eq!(
                payload
                    .get("client_id_metadata_document_supported")
                    .and_then(Value::as_bool),
                Some(supported)
            );
        } else {
            assert!(
                payload
                    .get("client_id_metadata_document_supported")
                    .is_none(),
                "did not expect client_id_metadata_document_supported in metadata"
            );
        }
        if self.token_endpoint_auth_methods_supported.is_empty() {
            assert!(
                payload
                    .get("token_endpoint_auth_methods_supported")
                    .is_none(),
                "did not expect token_endpoint_auth_methods_supported in metadata"
            );
        } else {
            assert_eq!(
                strings_from_value(payload.get("token_endpoint_auth_methods_supported")),
                self.token_endpoint_auth_methods_supported
                    .iter()
                    .copied()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            );
        }
        if self.code_challenge_methods_supported.is_empty() {
            assert!(
                payload.get("code_challenge_methods_supported").is_none(),
                "did not expect code_challenge_methods_supported in metadata"
            );
        } else {
            assert_eq!(
                strings_from_value(payload.get("code_challenge_methods_supported")),
                self.code_challenge_methods_supported
                    .iter()
                    .copied()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            );
        }
    }
}

/// Assert that a response has no bearer challenge header.
///
/// This is useful for host-guard tests that should fail before auth runs.
///
/// # Panics
/// Panics when `WWW-Authenticate` is present.
pub fn assert_no_bearer_challenge(headers: &HeaderMap) {
    assert!(
        !headers.contains_key(header::WWW_AUTHENTICATE),
        "expected no WWW-Authenticate header"
    );
}

/// Assert that a request was rejected by a pre-auth guard.
///
/// # Panics
/// Panics when the response is not `403 Forbidden` or includes a bearer
/// challenge.
pub fn assert_forbidden_without_bearer_challenge(status: StatusCode, headers: &HeaderMap) {
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_no_bearer_challenge(headers);
}

fn bearer_challenge_params(challenge: &str) -> HashMap<String, String> {
    let trimmed = challenge.trim();
    let scheme_end = trimmed
        .find(char::is_whitespace)
        .unwrap_or_else(|| panic!("expected a Bearer challenge"));
    let scheme = &trimmed[..scheme_end];
    if !scheme.eq_ignore_ascii_case("bearer") {
        panic!("expected a Bearer challenge");
    }

    let params = trimmed[scheme_end..]
        .strip_prefix(' ')
        .unwrap_or_else(|| panic!("expected a Bearer challenge"))
        .trim_start_matches(' ');
    if params.starts_with(char::is_whitespace) {
        panic!("expected a Bearer challenge");
    }
    if params.is_empty() {
        panic!("expected bearer challenge parameters");
    }

    let mut parsed = HashMap::new();
    for part in split_bearer_params(params) {
        if part.is_empty() {
            panic!("expected bearer challenge parameter");
        }

        let (name, value) = part
            .split_once('=')
            .unwrap_or_else(|| panic!("expected bearer challenge parameter: {part}"));
        let name = name.trim();
        if !is_bearer_token(name) {
            panic!("expected bearer challenge parameter: {part}");
        }

        let value = parse_bearer_value(value, part);
        let normalized_name = name.to_ascii_lowercase();
        if parsed.insert(normalized_name, value).is_some() {
            panic!("duplicate bearer challenge parameter: {name}");
        }
    }

    parsed
}

fn is_space_delimited_scope_hint(scope: &str) -> bool {
    if scope.trim().is_empty() || scope.trim() != scope {
        return false;
    }

    let mut saw_token = false;
    let mut previous_was_space = false;

    for ch in scope.chars() {
        match ch {
            ' ' => {
                if previous_was_space {
                    return false;
                }
                previous_was_space = true;
            }
            ch if ch.is_whitespace() => return false,
            _ => {
                saw_token = true;
                previous_was_space = false;
            }
        }
    }

    saw_token
}

fn split_bearer_params(params: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;

    for (idx, ch) in params.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                parts.push(params[start..idx].trim());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }

    if in_quotes || escaped {
        panic!("unterminated quoted bearer challenge parameter");
    }

    parts.push(params[start..].trim());
    parts
}

fn unquote_bearer_value(value: &str) -> Option<String> {
    let inner = value.trim().strip_prefix('"')?.strip_suffix('"')?;
    let mut unescaped = String::with_capacity(inner.len());
    let mut chars = inner.chars();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            unescaped.push(chars.next()?);
        } else {
            unescaped.push(ch);
        }
    }

    Some(unescaped)
}

fn parse_bearer_value(value: &str, part: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with('"') {
        return unquote_bearer_value(trimmed)
            .unwrap_or_else(|| panic!("expected quoted bearer challenge parameter: {part}"));
    }

    if !is_bearer_token(trimmed) {
        panic!("expected bearer challenge parameter: {part}");
    }

    trimmed.to_string()
}

fn is_bearer_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_bearer_token_char)
}

fn is_bearer_token_char(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

fn strings_from_value(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .unwrap_or_else(|| {
                            panic!("expected auth-surface contract array to contain strings")
                        })
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn assert_optional_string(payload: &Value, key: &str, expected: Option<&str>) {
    match (payload.get(key), expected) {
        (None, None) => {}
        (Some(value), Some(expected)) => {
            assert_eq!(value.as_str(), Some(expected), "{key}");
        }
        (None, Some(expected)) => panic!("expected metadata field {key}={expected:?}"),
        (Some(value), None) => panic!("did not expect metadata field {key}: {value}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        assert_forbidden_without_bearer_challenge, bearer_challenge_params, AuthSurfaceContract,
        AuthorizationServerMetadataContract,
    };
    use http::{header, HeaderMap, HeaderValue, StatusCode};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn missing_token_challenge_requires_configured_scope_hint_to_match_toolkit_behavior() {
        let contract = AuthSurfaceContract::new(
            "https://example.test/mcp",
            &["https://issuer.example"],
            &["tool:read", "tool:write"],
            "toolkit-test",
        );

        contract.assert_missing_token_challenge(
            "Bearer realm=\"toolkit-test\", resource_metadata=\"https://example.test/.well-known/oauth-protected-resource/mcp\", scope=\"tool:read tool:write\"",
        );
    }

    #[test]
    fn missing_token_response_asserts_status_and_header_contract() {
        let contract = AuthSurfaceContract::new(
            "https://example.test/mcp",
            &["https://issuer.example"],
            &["tool:read"],
            "toolkit-test",
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(
                "Bearer realm=\"toolkit-test\", resource_metadata=\"https://example.test/.well-known/oauth-protected-resource/mcp\", scope=\"tool:read\"",
            ),
        );

        contract.assert_missing_token_response(StatusCode::UNAUTHORIZED, &headers);
    }

    #[test]
    fn forbidden_without_bearer_challenge_rejects_auth_headers() {
        let mut headers = HeaderMap::new();
        assert_forbidden_without_bearer_challenge(StatusCode::FORBIDDEN, &headers);

        headers.insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"toolkit-test\""),
        );
        assert!(catch_unwind(AssertUnwindSafe(|| {
            assert_forbidden_without_bearer_challenge(StatusCode::FORBIDDEN, &headers);
        }))
        .is_err());
    }

    #[test]
    fn authorization_server_metadata_contract_checks_device_grants() {
        let payload = serde_json::json!({
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/oauth/authorize",
            "token_endpoint": "https://issuer.example/oauth/token",
            "device_authorization_endpoint": "https://issuer.example/oauth/device",
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:device_code"
            ],
            "client_id_metadata_document_supported": true,
            "token_endpoint_auth_methods_supported": [
                "none",
                "private_key_jwt"
            ],
            "code_challenge_methods_supported": [
                "S256"
            ]
        });

        AuthorizationServerMetadataContract::new(
            "https://issuer.example",
            "https://issuer.example/oauth/authorize",
            "https://issuer.example/oauth/token",
        )
        .with_device_authorization_endpoint("https://issuer.example/oauth/device")
        .with_grant_types_supported(&[
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:device_code",
        ])
        .with_client_id_metadata_document_supported(true)
        .with_token_endpoint_auth_methods_supported(&["none", "private_key_jwt"])
        .with_code_challenge_methods_supported(&["S256"])
        .assert_metadata(&payload);
    }

    #[test]
    fn authorization_server_metadata_contract_rejects_unexpected_optional_shapes() {
        for unexpected in [
            serde_json::Value::Null,
            serde_json::json!({"href": "https://issuer.example/register"}),
        ] {
            let payload = serde_json::json!({
                "issuer": "https://issuer.example",
                "authorization_endpoint": "https://issuer.example/oauth/authorize",
                "token_endpoint": "https://issuer.example/oauth/token",
                "registration_endpoint": unexpected,
            });

            assert!(catch_unwind(AssertUnwindSafe(|| {
                AuthorizationServerMetadataContract::new(
                    "https://issuer.example",
                    "https://issuer.example/oauth/authorize",
                    "https://issuer.example/oauth/token",
                )
                .assert_metadata(&payload);
            }))
            .is_err());
        }
    }

    #[test]
    fn missing_token_challenge_rejects_mismatched_scope_hint() {
        let contract = AuthSurfaceContract::new(
            "https://example.test/mcp",
            &["https://issuer.example"],
            &["tool:read", "tool:write"],
            "toolkit-test",
        );

        assert!(catch_unwind(AssertUnwindSafe(|| {
            contract.assert_missing_token_challenge(
                "Bearer realm=\"toolkit-test\", resource_metadata=\"https://example.test/.well-known/oauth-protected-resource/mcp\", scope=\"tool:inspect\"",
            );
        }))
        .is_err());
    }

    #[test]
    fn bearer_challenge_params_accepts_case_insensitive_scheme() {
        let params = bearer_challenge_params(
            "bEaReR realm=\"toolkit-test\", resource_metadata=\"https://example.test/.well-known/oauth-protected-resource/mcp\"",
        );

        assert_eq!(
            params.get("realm").map(String::as_str),
            Some("toolkit-test")
        );
        assert_eq!(
            params.get("resource_metadata").map(String::as_str),
            Some("https://example.test/.well-known/oauth-protected-resource/mcp")
        );
    }

    #[test]
    fn bearer_challenge_params_unescapes_quoted_values_without_splitting_on_commas() {
        let params = bearer_challenge_params(
            "Bearer realm=\"toolkit-test\", error_description=\"missing token, \\\"quoted\\\" value\", error_uri=\"https://example.test/docs\\\\bearer\"",
        );

        assert_eq!(
            params.get("error_description").map(String::as_str),
            Some("missing token, \"quoted\" value")
        );
        assert_eq!(
            params.get("error_uri").map(String::as_str),
            Some("https://example.test/docs\\bearer")
        );
    }

    #[test]
    fn bearer_challenge_params_rejects_duplicate_parameters() {
        assert!(catch_unwind(AssertUnwindSafe(|| {
            bearer_challenge_params(
                "Bearer realm=\"toolkit-test\", realm=\"duplicate\", error=\"invalid_request\"",
            );
        }))
        .is_err());
    }

    #[test]
    fn bearer_challenge_params_rejects_case_insensitive_duplicate_parameters() {
        assert!(catch_unwind(AssertUnwindSafe(|| {
            bearer_challenge_params(
                "Bearer realm=\"toolkit-test\", REALM=\"duplicate\", error=\"invalid_request\"",
            );
        }))
        .is_err());
    }

    #[test]
    fn bearer_challenge_params_accepts_multiple_spaces_after_scheme() {
        let params =
            bearer_challenge_params("Bearer   realm=\"toolkit-test\", error=\"invalid_request\"");

        assert_eq!(
            params.get("realm").map(String::as_str),
            Some("toolkit-test")
        );
        assert_eq!(
            params.get("error").map(String::as_str),
            Some("invalid_request")
        );
    }

    #[test]
    fn bearer_challenge_params_rejects_tab_or_newline_after_scheme() {
        assert!(catch_unwind(AssertUnwindSafe(|| {
            bearer_challenge_params("Bearer\trealm=\"toolkit-test\", error=\"invalid_request\"");
        }))
        .is_err());

        assert!(catch_unwind(AssertUnwindSafe(|| {
            bearer_challenge_params("Bearer\nrealm=\"toolkit-test\", error=\"invalid_request\"");
        }))
        .is_err());
    }

    #[test]
    fn bearer_challenge_params_rejects_trailing_commas() {
        assert!(catch_unwind(AssertUnwindSafe(|| {
            bearer_challenge_params("Bearer realm=\"toolkit-test\", error=\"invalid_request\", ");
        }))
        .is_err());
    }

    #[test]
    fn bearer_challenge_params_rejects_appended_auth_scheme_garbage() {
        assert!(catch_unwind(AssertUnwindSafe(|| {
            bearer_challenge_params(
                "Bearer realm=\"toolkit-test\", error=\"invalid_request\", Digest realm=\"example\"",
            );
        }))
        .is_err());
    }

    #[test]
    fn missing_token_challenge_rejects_tab_delimited_scope_hint() {
        let contract = AuthSurfaceContract::new(
            "https://example.test/mcp",
            &["https://issuer.example"],
            &["tool:read", "tool:write"],
            "toolkit-test",
        );

        assert!(catch_unwind(AssertUnwindSafe(|| {
            contract.assert_missing_token_challenge(
                "Bearer realm=\"toolkit-test\", resource_metadata=\"https://example.test/.well-known/oauth-protected-resource/mcp\", scope=\"tool:inspect\ttool:write\"",
            );
        }))
        .is_err());
    }
}
