//! Contract assertions for MCP servers exposed as OpenAI Apps.
//!
//! This module layers OpenAI Apps and ChatGPT-specific expectations over the
//! generic MCP auth-surface helpers. It is intended for server test suites that
//! want one high-signal gate covering protected-resource metadata,
//! authorization-server metadata, Apps tool descriptors, and runtime OAuth
//! challenges.

use mcp_toolkit_core::mcp_apps::{
    MCP_APPS_NOAUTH_SECURITY_SCHEME_TYPE, MCP_APPS_OAUTH2_SECURITY_SCHEME_TYPE,
    MCP_APPS_SECURITY_SCHEMES_META_KEY,
};
use mcp_toolkit_http::oauth::resource_metadata_hint;
use serde_json::Value;
use std::collections::HashMap;

/// Apps runtime `_meta` key used to trigger ChatGPT OAuth UI.
pub const OPENAI_APPS_WWW_AUTHENTICATE_META_KEY: &str = "mcp/www_authenticate";

/// PKCE method ChatGPT uses and MCP clients must verify from metadata.
pub const OPENAI_APPS_PKCE_METHOD: &str = "S256";

/// Token endpoint auth methods commonly supported by ChatGPT Apps connectors.
pub const OPENAI_APPS_COMPATIBLE_TOKEN_ENDPOINT_AUTH_METHODS: &[&str] = &[
    "none",
    "private_key_jwt",
    "client_secret_post",
    "client_secret_basic",
];

/// OAuth client registration mode expected for an OpenAI Apps connector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenAiAppsClientRegistrationMode {
    /// The connector creator supplies a pre-existing OAuth client.
    PredefinedClient,
    /// ChatGPT identifies itself with a Client ID Metadata Document URL.
    ClientIdMetadataDocument,
    /// ChatGPT registers a client through Dynamic Client Registration.
    DynamicClientRegistration,
}

/// OpenAI Apps conformance profile for one protected MCP server.
///
/// ```
/// use mcp_toolkit_testing::openai_apps_contract::{
///     OpenAiAppsClientRegistrationMode, OpenAiAppsConformanceProfile,
/// };
/// use serde_json::json;
///
/// let authorization_servers = ["https://issuer.example"];
/// let required_scopes = ["items:read"];
/// let profile = OpenAiAppsConformanceProfile::new(
///     "https://example.test/mcp",
///     &authorization_servers,
/// )
/// .with_required_scopes(&required_scopes)
/// .with_client_registration(OpenAiAppsClientRegistrationMode::ClientIdMetadataDocument);
///
/// profile.assert_resource_metadata(&json!({
///     "resource": "https://example.test/mcp",
///     "authorization_servers": ["https://issuer.example"],
///     "scopes_supported": ["items:read"]
/// }));
/// ```
#[derive(Debug, Clone)]
pub struct OpenAiAppsConformanceProfile<'a> {
    resource_url: &'a str,
    authorization_servers: &'a [&'a str],
    required_scopes: &'a [&'a str],
    client_registration: OpenAiAppsClientRegistrationMode,
    accepted_token_endpoint_auth_methods: &'a [&'a str],
}

impl<'a> OpenAiAppsConformanceProfile<'a> {
    /// Builds a new OpenAI Apps conformance profile.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Treat the resource URL and authorization server list as trusted test
    /// fixtures that describe the public deployment contract under test.
    #[must_use]
    pub fn new(resource_url: &'a str, authorization_servers: &'a [&'a str]) -> Self {
        Self {
            resource_url,
            authorization_servers,
            required_scopes: &[],
            client_registration: OpenAiAppsClientRegistrationMode::PredefinedClient,
            accepted_token_endpoint_auth_methods:
                OPENAI_APPS_COMPATIBLE_TOKEN_ENDPOINT_AUTH_METHODS,
        }
    }

    /// Requires the supplied OAuth scopes across metadata, descriptors, and challenges.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Scope strings are compared literally. Keep them aligned with the scopes
    /// enforced by the server under test.
    #[must_use]
    pub fn with_required_scopes(mut self, scopes: &'a [&'a str]) -> Self {
        self.required_scopes = scopes;
        self
    }

    /// Selects how ChatGPT should identify or register its OAuth client.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// The selected mode controls which authorization-server metadata fields
    /// are considered mandatory by the profile.
    #[must_use]
    pub fn with_client_registration(mut self, mode: OpenAiAppsClientRegistrationMode) -> Self {
        self.client_registration = mode;
        self
    }

    /// Replaces the accepted token endpoint authentication method allowlist.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Use this only when the connector is intentionally configured for a
    /// narrower token endpoint auth method set.
    #[must_use]
    pub fn with_accepted_token_endpoint_auth_methods(mut self, methods: &'a [&'a str]) -> Self {
        self.accepted_token_endpoint_auth_methods = methods;
        self
    }

    /// Returns the expected protected-resource metadata URL.
    ///
    /// # Panics
    /// Panics if the configured resource URL cannot be converted into an MCP
    /// protected-resource metadata URL.
    ///
    /// # Security
    /// The returned URL is used as the OAuth discovery pointer in runtime
    /// bearer challenges.
    #[must_use]
    pub fn resource_metadata_url(&self) -> String {
        resource_metadata_hint(self.resource_url).unwrap_or_else(|| {
            panic!(
                "invalid resource URL for OpenAI Apps conformance profile: {}",
                self.resource_url
            )
        })
    }

    /// Asserts the OAuth Protected Resource Metadata document.
    ///
    /// # Panics
    /// Panics when the payload does not expose the configured resource URL,
    /// authorization servers, or required scopes.
    ///
    /// # Security
    /// This assertion protects the resource binding ChatGPT uses when it sends
    /// the OAuth `resource` parameter.
    pub fn assert_resource_metadata(&self, payload: &Value) {
        assert_eq!(
            payload.get("resource").and_then(Value::as_str),
            Some(self.resource_url),
            "protected-resource metadata must publish the canonical MCP resource URL"
        );
        assert_string_array_equals(payload, "authorization_servers", self.authorization_servers);
        assert_string_array_contains_all(payload, "scopes_supported", self.required_scopes);
    }

    /// Asserts authorization-server metadata needed by ChatGPT Apps.
    ///
    /// # Panics
    /// Panics when required OAuth endpoints, PKCE support, client registration
    /// metadata, or token endpoint auth methods are missing.
    ///
    /// # Security
    /// This assertion keeps the authorization-code + PKCE flow explicit before
    /// a server is exercised through ChatGPT.
    pub fn assert_authorization_server_metadata(&self, payload: &Value) {
        let issuer = required_string(payload, "issuer");
        assert!(
            self.authorization_servers
                .iter()
                .any(|expected| expected == &issuer),
            "authorization-server metadata issuer {issuer:?} was not advertised by protected-resource metadata"
        );
        required_string(payload, "authorization_endpoint");
        required_string(payload, "token_endpoint");
        assert_string_array_contains_all(
            payload,
            "code_challenge_methods_supported",
            &[OPENAI_APPS_PKCE_METHOD],
        );

        match self.client_registration {
            OpenAiAppsClientRegistrationMode::PredefinedClient => {}
            OpenAiAppsClientRegistrationMode::ClientIdMetadataDocument => {
                assert_eq!(
                    payload
                        .get("client_id_metadata_document_supported")
                        .and_then(Value::as_bool),
                    Some(true),
                    "CIMD mode requires client_id_metadata_document_supported=true"
                );
            }
            OpenAiAppsClientRegistrationMode::DynamicClientRegistration => {
                required_string(payload, "registration_endpoint");
            }
        }

        let token_methods = string_array(payload, "token_endpoint_auth_methods_supported");
        assert!(
            token_methods.iter().any(|method| {
                self.accepted_token_endpoint_auth_methods
                    .iter()
                    .any(|accepted| accepted == method)
            }),
            "token_endpoint_auth_methods_supported must include one accepted ChatGPT-compatible method"
        );
    }

    /// Asserts an Apps tool descriptor's security scheme projection.
    ///
    /// # Panics
    /// Panics when descriptor-level `securitySchemes` are missing, differ from
    /// `_meta["securitySchemes"]`, contain unsupported scheme types, or omit
    /// required OAuth scopes.
    ///
    /// # Security
    /// This assertion guards the metadata ChatGPT uses before deciding whether
    /// tool-level OAuth is available for a tool.
    pub fn assert_tool_descriptor(&self, descriptor: &Value) {
        let security_schemes = required_array(descriptor, MCP_APPS_SECURITY_SCHEMES_META_KEY);
        let meta = descriptor
            .get("_meta")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("tool descriptor must include _meta object"));
        let meta_security_schemes = meta
            .get(MCP_APPS_SECURITY_SCHEMES_META_KEY)
            .unwrap_or_else(|| panic!("tool descriptor must mirror securitySchemes into _meta"));
        assert_eq!(
            meta_security_schemes,
            &Value::Array(security_schemes.to_vec()),
            "tool descriptor securitySchemes must match _meta.securitySchemes"
        );

        let mut saw_noauth = false;
        let mut oauth_scopes = Vec::new();
        for scheme in security_schemes {
            let object = scheme
                .as_object()
                .unwrap_or_else(|| panic!("security scheme entries must be JSON objects"));
            let scheme_type = object
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("security scheme entries must include type"));
            match scheme_type {
                MCP_APPS_NOAUTH_SECURITY_SCHEME_TYPE => {
                    saw_noauth = true;
                }
                MCP_APPS_OAUTH2_SECURITY_SCHEME_TYPE => {
                    let scopes = object
                        .get("scopes")
                        .and_then(Value::as_array)
                        .unwrap_or_else(|| {
                            panic!("oauth2 security scheme must include scopes array")
                        });
                    for scope in scopes {
                        let scope = scope.as_str().unwrap_or_else(|| {
                            panic!("oauth2 security scheme scopes must be strings")
                        });
                        assert!(
                            !scope.trim().is_empty() && scope.trim() == scope,
                            "oauth2 security scheme scopes must be non-empty trimmed strings"
                        );
                        oauth_scopes.push(scope);
                    }
                }
                other => panic!("unsupported Apps security scheme type: {other}"),
            }
        }

        if self.required_scopes.is_empty() {
            assert!(
                saw_noauth || !oauth_scopes.is_empty(),
                "tool descriptor must expose noauth or oauth2 security"
            );
        } else {
            assert!(
                !oauth_scopes.is_empty(),
                "tool descriptor must include oauth2 security for scoped tools"
            );
            assert_contains_all(
                &oauth_scopes,
                self.required_scopes,
                "tool descriptor scopes",
            );
        }
    }

    /// Asserts every Apps tool descriptor in a tool list.
    ///
    /// # Panics
    /// Panics when any descriptor fails `assert_tool_descriptor`.
    ///
    /// # Security
    /// Use this when a server exports several tools under the same Apps auth
    /// profile.
    pub fn assert_tool_descriptors(&self, descriptors: &[Value]) {
        assert!(
            !descriptors.is_empty(),
            "OpenAI Apps conformance requires at least one tool descriptor"
        );
        for descriptor in descriptors {
            self.assert_tool_descriptor(descriptor);
        }
    }

    /// Asserts a runtime `WWW-Authenticate` Bearer challenge.
    ///
    /// # Panics
    /// Panics when the challenge is not Bearer, does not point at the expected
    /// protected-resource metadata URL, omits required scopes, or lacks OAuth
    /// error detail.
    ///
    /// # Security
    /// This assertion checks the runtime signal ChatGPT uses to open the
    /// tool-level OAuth linking UI.
    pub fn assert_www_authenticate_challenge(&self, challenge: &str) {
        let params = parse_bearer_challenge(challenge)
            .unwrap_or_else(|err| panic!("invalid WWW-Authenticate challenge: {err}"));
        let resource_metadata_url = self.resource_metadata_url();
        assert_eq!(
            params.get("resource_metadata").map(String::as_str),
            Some(resource_metadata_url.as_str()),
            "WWW-Authenticate challenge must point at protected-resource metadata"
        );
        let error = params
            .get("error")
            .map(String::as_str)
            .unwrap_or_else(|| panic!("WWW-Authenticate challenge must include error"));
        assert!(
            matches!(
                error,
                "invalid_request" | "invalid_token" | "insufficient_scope"
            ),
            "WWW-Authenticate error must be an RFC 6750 bearer error"
        );
        let error_description = params
            .get("error_description")
            .map(String::as_str)
            .unwrap_or_else(|| panic!("WWW-Authenticate challenge must include error_description"));
        assert!(
            !error_description.trim().is_empty(),
            "WWW-Authenticate error_description must be non-empty"
        );

        if !self.required_scopes.is_empty() {
            let scope_hint = params
                .get("scope")
                .map(String::as_str)
                .unwrap_or_else(|| panic!("WWW-Authenticate challenge must include scope"));
            let scope_values = split_space_delimited(scope_hint);
            assert_contains_all(
                &scope_values,
                self.required_scopes,
                "WWW-Authenticate scope",
            );
        }
    }

    /// Asserts tool-result `_meta["mcp/www_authenticate"]` challenge metadata.
    ///
    /// # Panics
    /// Panics when the supplied `_meta` object has no challenge string or any
    /// of its challenge strings fails this profile.
    ///
    /// # Security
    /// This assertion validates the Apps runtime error metadata that prompts
    /// ChatGPT to start or repeat OAuth.
    pub fn assert_tool_result_authenticate_meta(&self, meta: &Value) {
        let challenges = challenge_strings_from_meta(meta);
        assert!(
            !challenges.is_empty(),
            "tool result _meta must include mcp/www_authenticate"
        );
        for challenge in challenges {
            self.assert_www_authenticate_challenge(challenge);
        }
    }
}

fn challenge_strings_from_meta(meta: &Value) -> Vec<&str> {
    match meta.get(OPENAI_APPS_WWW_AUTHENTICATE_META_KEY) {
        Some(Value::String(challenge)) => vec![challenge.as_str()],
        Some(Value::Array(challenges)) => challenges
            .iter()
            .map(|challenge| {
                challenge.as_str().unwrap_or_else(|| {
                    panic!("mcp/www_authenticate entries must be challenge strings")
                })
            })
            .collect(),
        Some(_) => panic!("mcp/www_authenticate must be a string or string array"),
        None => Vec::new(),
    }
}

fn required_string<'a>(payload: &'a Value, key: &str) -> &'a str {
    payload
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("metadata field {key} must be a string"))
}

fn required_array<'a>(payload: &'a Value, key: &str) -> &'a [Value] {
    payload
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("metadata field {key} must be an array"))
}

fn assert_string_array_equals(payload: &Value, key: &str, expected: &[&str]) {
    let actual = string_array(payload, key);
    let expected = expected.to_vec();
    assert_eq!(actual, expected, "metadata field {key} mismatch");
}

fn assert_string_array_contains_all(payload: &Value, key: &str, expected: &[&str]) {
    if expected.is_empty() && payload.get(key).is_none() {
        return;
    }
    let actual = string_array(payload, key);
    assert_contains_all(&actual, expected, key);
}

fn assert_contains_all(actual: &[&str], expected: &[&str], label: &str) {
    for expected_value in expected {
        assert!(
            actual
                .iter()
                .any(|actual_value| actual_value == expected_value),
            "{label} missing required value {expected_value:?}"
        );
    }
}

fn string_array<'a>(payload: &'a Value, key: &str) -> Vec<&'a str> {
    required_array(payload, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("metadata field {key} must contain only strings"))
        })
        .collect()
}

fn split_space_delimited(value: &str) -> Vec<&str> {
    assert!(
        !value.trim().is_empty() && value.trim() == value,
        "space-delimited scope value must be non-empty and trimmed"
    );
    let values = value.split(' ').collect::<Vec<_>>();
    assert!(
        values.iter().all(|entry| !entry.is_empty()),
        "space-delimited scope value must not contain empty entries"
    );
    values
}

fn parse_bearer_challenge(challenge: &str) -> Result<HashMap<String, String>, String> {
    let trimmed = challenge.trim();
    let scheme_end = trimmed
        .find(char::is_whitespace)
        .ok_or_else(|| "expected Bearer challenge with parameters".to_string())?;
    let scheme = &trimmed[..scheme_end];
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err("expected Bearer challenge".to_string());
    }
    let separator_and_params = &trimmed[scheme_end..];
    let space_count = separator_and_params
        .chars()
        .take_while(|ch| *ch == ' ')
        .count();
    if space_count == 0 {
        return Err("expected spaces after Bearer scheme".to_string());
    }

    let params = &separator_and_params[space_count..];
    if params
        .chars()
        .next()
        .map(char::is_whitespace)
        .unwrap_or(false)
    {
        return Err("expected only spaces after Bearer scheme".to_string());
    }
    if params.is_empty() {
        return Err("expected bearer challenge parameters".to_string());
    }

    let mut parsed = HashMap::new();
    for part in split_bearer_params(params)? {
        if part.is_empty() {
            return Err("expected bearer challenge parameter".to_string());
        }

        let (name, value) = part
            .split_once('=')
            .ok_or_else(|| format!("expected bearer challenge parameter: {part}"))?;
        let name = name.trim();
        if !is_bearer_token(name) {
            return Err(format!("expected bearer challenge parameter name: {part}"));
        }

        let value = parse_bearer_value(value, part)?;
        let normalized_name = name.to_ascii_lowercase();
        if parsed.insert(normalized_name, value).is_some() {
            return Err(format!("duplicate bearer challenge parameter: {name}"));
        }
    }

    Ok(parsed)
}

fn split_bearer_params(params: &str) -> Result<Vec<&str>, String> {
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
        return Err("unterminated quoted bearer challenge parameter".to_string());
    }

    parts.push(params[start..].trim());
    Ok(parts)
}

fn parse_bearer_value(value: &str, part: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.starts_with('"') {
        return unquote_bearer_value(trimmed)
            .ok_or_else(|| format!("expected quoted bearer challenge parameter: {part}"));
    }

    if !is_bearer_token(trimmed) {
        return Err(format!("expected bearer challenge parameter value: {part}"));
    }

    Ok(trimmed.to_string())
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

#[cfg(test)]
mod tests {
    use super::{OpenAiAppsClientRegistrationMode, OpenAiAppsConformanceProfile};
    use serde_json::json;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const AUTHORIZATION_SERVERS: &[&str] = &["https://issuer.example"];
    const REQUIRED_SCOPES: &[&str] = &["items:read", "items:write"];

    fn profile() -> OpenAiAppsConformanceProfile<'static> {
        OpenAiAppsConformanceProfile::new("https://example.test/mcp", AUTHORIZATION_SERVERS)
            .with_required_scopes(REQUIRED_SCOPES)
            .with_client_registration(OpenAiAppsClientRegistrationMode::ClientIdMetadataDocument)
    }

    #[test]
    fn openai_apps_profile_accepts_complete_metadata_and_descriptor() {
        let profile = profile();

        profile.assert_resource_metadata(&json!({
            "resource": "https://example.test/mcp",
            "authorization_servers": ["https://issuer.example"],
            "scopes_supported": ["items:read", "items:write", "offline_access"]
        }));
        profile.assert_authorization_server_metadata(&json!({
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/oauth/authorize",
            "token_endpoint": "https://issuer.example/oauth/token",
            "client_id_metadata_document_supported": true,
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
            "code_challenge_methods_supported": ["S256"]
        }));
        profile.assert_tool_descriptor(&json!({
            "name": "items.write",
            "securitySchemes": [
                {"type": "oauth2", "scopes": ["items:read", "items:write"]}
            ],
            "_meta": {
                "securitySchemes": [
                    {"type": "oauth2", "scopes": ["items:read", "items:write"]}
                ]
            }
        }));
        profile.assert_tool_result_authenticate_meta(&json!({
            "mcp/www_authenticate": [
                "Bearer resource_metadata=\"https://example.test/.well-known/oauth-protected-resource/mcp\", scope=\"items:read items:write\", error=\"insufficient_scope\", error_description=\"User authorization required\""
            ]
        }));
    }

    #[test]
    fn openai_apps_profile_requires_descriptor_meta_mirror() {
        let profile = profile();
        let descriptor = json!({
            "securitySchemes": [
                {"type": "oauth2", "scopes": ["items:read", "items:write"]}
            ],
            "_meta": {
                "securitySchemes": [
                    {"type": "oauth2", "scopes": ["items:read"]}
                ]
            }
        });

        assert!(catch_unwind(AssertUnwindSafe(|| {
            profile.assert_tool_descriptor(&descriptor);
        }))
        .is_err());
    }

    #[test]
    fn openai_apps_profile_requires_pkce_s256() {
        let profile = profile();
        let metadata = json!({
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/oauth/authorize",
            "token_endpoint": "https://issuer.example/oauth/token",
            "client_id_metadata_document_supported": true,
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
            "code_challenge_methods_supported": ["plain"]
        });

        assert!(catch_unwind(AssertUnwindSafe(|| {
            profile.assert_authorization_server_metadata(&metadata);
        }))
        .is_err());
    }

    #[test]
    fn openai_apps_profile_requires_runtime_error_detail() {
        let profile = profile();
        let meta = json!({
            "mcp/www_authenticate": [
                "Bearer resource_metadata=\"https://example.test/.well-known/oauth-protected-resource/mcp\", scope=\"items:read items:write\""
            ]
        });

        assert!(catch_unwind(AssertUnwindSafe(|| {
            profile.assert_tool_result_authenticate_meta(&meta);
        }))
        .is_err());
    }

    #[test]
    fn dynamic_client_registration_requires_registration_endpoint() {
        let profile =
            OpenAiAppsConformanceProfile::new("https://example.test/mcp", AUTHORIZATION_SERVERS)
                .with_client_registration(
                    OpenAiAppsClientRegistrationMode::DynamicClientRegistration,
                );
        let metadata = json!({
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/oauth/authorize",
            "token_endpoint": "https://issuer.example/oauth/token",
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"]
        });

        assert!(catch_unwind(AssertUnwindSafe(|| {
            profile.assert_authorization_server_metadata(&metadata);
        }))
        .is_err());
    }
}
