//! Shared contract assertions for toolkit auth-surface tests.
//!
//! The goal is to keep auth-surface integration tests focused on the public
//! PRM discovery and core missing-token bearer-challenge semantics rather than on
//! service-specific policy or transport wiring.

use mcp_toolkit_http::oauth::{resource_metadata_hint, BEARER_METHOD_HEADER};
use serde_json::Value;
use std::collections::HashMap;

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

#[cfg(test)]
mod tests {
    use super::{bearer_challenge_params, AuthSurfaceContract};
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
