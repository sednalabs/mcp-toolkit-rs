//! # OAuth HTTP Helpers
//!
//! Shared types and URL builders for OAuth 2.0 Protected Resource Metadata (PRM)
//! and Authorization Server Metadata (RFC 8414).
//!
//! ## Rationale
//! Standardizes the layout of well-known OAuth paths to ensure that MCP servers
//! expose discovery metadata in a way that is compatible with RFC 9728 and RFC 8414.
//!
//! ## Security Boundaries
//! * **URL Construction**: Ensures that sensitive fragments and query parameters
//!   are stripped when deriving metadata URLs.
//!
//! ## References
//! * **SPEC**: [RFC 9728 (OAuth 2.0 Protected Resource Metadata)](https://datatracker.ietf.org/doc/html/rfc9728)

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;
use url::Url;

pub const PRM_WELL_KNOWN_PATH: &str = "/.well-known/oauth-protected-resource";
pub const OAUTH_AUTHZ_WELL_KNOWN_PATH: &str = "/.well-known/oauth-authorization-server";
pub const OIDC_WELL_KNOWN_PATH: &str = "/.well-known/openid-configuration";
/// Standard bearer method for HTTP Authorization headers.
pub const BEARER_METHOD_HEADER: &str = "header";

/// OAuth 2.0 Authorization Server metadata (RFC 8414).
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationServerMetadata {
    /// Authorization server issuer identifier.
    pub issuer: String,
    /// OAuth authorization endpoint.
    pub authorization_endpoint: String,
    /// OAuth token endpoint.
    pub token_endpoint: String,
    /// Optional dynamic client registration endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// Optional JWKS URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// Optional introspection endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
}

/// URL validation failures for OAuth metadata configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlValidationError {
    Empty,
    Invalid,
    MissingHost,
    InsecureScheme,
}

impl fmt::Display for UrlValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            UrlValidationError::Empty => "empty URL",
            UrlValidationError::Invalid => "invalid URL",
            UrlValidationError::MissingHost => "missing host",
            UrlValidationError::InsecureScheme => "insecure scheme (https required)",
        };
        f.write_str(message)
    }
}

/// Validate that a URL is absolute and uses an allowed scheme.
///
/// # Errors
/// Returns `UrlValidationError` if parsing fails, the host is missing, or the
/// scheme is insecure and `allow_insecure_http` is false.
///
/// # Security
/// Enforces HTTPS by default to reduce metadata spoofing risk.
///
/// # Panics
/// This function does not panic.
pub fn validate_absolute_url(
    value: &str,
    allow_insecure_http: bool,
) -> Result<(), UrlValidationError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(UrlValidationError::Empty);
    }
    let url = Url::parse(trimmed).map_err(|_| UrlValidationError::Invalid)?;
    match url.scheme() {
        "https" => {}
        "http" if allow_insecure_http => {}
        _ => return Err(UrlValidationError::InsecureScheme),
    }
    if let Some((_, rest)) = trimmed.split_once("://") {
        if rest.is_empty() || rest.starts_with('/') {
            return Err(UrlValidationError::MissingHost);
        }
    }
    let host = url.host_str().unwrap_or("");
    if host.is_empty() {
        return Err(UrlValidationError::MissingHost);
    }
    Ok(())
}

/// Build RFC 8414-style well-known paths for a given resource path.
///
/// When the resource path is non-root, this returns:
/// - `/.well-known/{name}/{path}`
///
/// For root resources, this returns the canonical path only.
///
/// # Security
/// * **Determinism**: Normalizes the input path to avoid ambiguous routes.
/// * **Canonical routing**: Emits a single deterministic discovery path.
pub fn well_known_paths(resource_path: &str, well_known_name: &str) -> Vec<String> {
    let trimmed = resource_path
        .trim()
        .trim_start_matches('/')
        .trim_end_matches('/');
    let canonical = format!("/.well-known/{well_known_name}");

    if trimmed.is_empty() {
        return vec![canonical];
    }

    vec![format!("{canonical}/{trimmed}")]
}

/// RFC 8414 well-known paths for OAuth 2.0 Authorization Server metadata.
pub fn authorization_server_well_known_paths(resource_path: &str) -> Vec<String> {
    well_known_paths(resource_path, "oauth-authorization-server")
}

/// RFC 8414 well-known paths for OpenID Provider metadata.
pub fn oidc_well_known_paths(resource_path: &str) -> Vec<String> {
    well_known_paths(resource_path, "openid-configuration")
}

/// RFC 9728 well-known paths for OAuth 2.0 Protected Resource Metadata.
pub fn protected_resource_well_known_paths(resource_path: &str) -> Vec<String> {
    well_known_paths(resource_path, "oauth-protected-resource")
}

/// OAuth 2.0 protected resource metadata (RFC 9728).
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Panics
/// * None.
///
/// ```rust,no_run
/// # use std::any::TypeId;
/// let _ = TypeId::of::<mcp_toolkit_http::oauth::ResourceMetadata>();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceMetadata {
    /// The canonical URL of the resource.
    pub resource: String,
    /// List of authorization server base URLs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_servers: Vec<String>,
    /// List of scopes supported by the resource.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
    /// List of bearer methods supported (e.g. "header").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bearer_methods_supported: Vec<String>,
}

impl ResourceMetadata {
    /// Return the JSON representation of the metadata.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = mcp_toolkit_http::oauth::ResourceMetadata::json_bytes;
    /// ```
    pub fn json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_else(|_| b"{}".to_vec())
    }
}

/// Build a resource URL by joining a base URL with a resource path.
///
/// # Errors
/// This function does not return errors.
///
/// # Security
/// Callers must validate that the inputs are trusted URLs; this helper does not
/// perform URL validation or normalization beyond trimming slashes.
///
/// # Panics
/// This function does not panic.
///
/// # Examples
/// ```
/// use mcp_toolkit_http::oauth::resource_url_from_base;
///
/// let url = resource_url_from_base("http://localhost:9411", "/mcp");
/// assert_eq!(url, "http://localhost:9411/mcp");
/// ```
pub fn resource_url_from_base(base_url: &str, resource_path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let path = resource_path.trim_start_matches('/');
    if path.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{path}")
    }
}

/// Build a canonical public base URL from a bind address and TLS mode.
///
/// This is useful for servers that need a deterministic fallback public base
/// URL before any explicit external resource URL override has been applied.
///
/// # Errors
/// This function does not return errors.
///
/// # Security
/// Callers should prefer explicit public resource URLs for production
/// deployments behind reverse proxies or TLS termination.
///
/// # Panics
/// This function does not panic.
pub fn public_base_url_from_bind_addr(bind_addr: &SocketAddr, tls_enabled: bool) -> String {
    let scheme = if tls_enabled { "https" } else { "http" };
    format!("{scheme}://{bind_addr}")
}

/// Derive a canonical public base URL from a full resource URL and resource path.
///
/// This is useful when a service has an externally configured resource URL
/// such as `https://example.com/mcp` and needs to recover the canonical public
/// base URL (`https://example.com`) for discovery metadata.
///
/// Returns `Ok(None)` when the resource URL does not end with the supplied
/// resource path after trimming a trailing slash.
///
/// # Errors
/// Returns the underlying `url::ParseError` when `resource_url` is not a valid
/// absolute URL.
///
/// # Security
/// Query and fragment components are stripped from the derived base URL.
///
/// # Panics
/// This function does not panic.
pub fn public_base_url_from_resource_url(
    resource_url: &str,
    resource_path: &str,
) -> Result<Option<String>, url::ParseError> {
    let mut parsed = Url::parse(resource_url)?;
    parsed.set_query(None);
    parsed.set_fragment(None);

    let expected_suffix = format!("/{}", resource_path.trim().trim_matches('/'));
    let path = parsed.path().trim_end_matches('/').to_string();
    let Some(prefix) = path.strip_suffix(&expected_suffix) else {
        return Ok(None);
    };

    if prefix.is_empty() {
        parsed.set_path("/");
    } else {
        parsed.set_path(prefix);
    }

    let mut value = parsed.to_string();
    while value.ends_with('/') {
        value.pop();
    }
    Ok(Some(value))
}

/// Build resource metadata with the standard Bearer "header" method.
///
/// # Errors
/// This function does not return errors.
///
/// # Security
/// Callers must ensure the supplied URLs and scopes are trusted inputs.
///
/// # Panics
/// This function does not panic.
///
/// # Examples
/// ```
/// use mcp_toolkit_http::oauth::{resource_metadata_default, BEARER_METHOD_HEADER};
///
/// let metadata = resource_metadata_default(
///     "https://example.com/mcp",
///     ["https://example.com"],
///     ["search"],
/// );
/// assert_eq!(metadata.resource, "https://example.com/mcp");
/// assert_eq!(metadata.authorization_servers, vec!["https://example.com"]);
/// assert_eq!(metadata.bearer_methods_supported, vec![BEARER_METHOD_HEADER.to_string()]);
/// ```
pub fn resource_metadata_default<I, J, K>(
    resource: I,
    authorization_servers: J,
    scopes_supported: K,
) -> ResourceMetadata
where
    I: Into<String>,
    J: IntoIterator,
    J::Item: Into<String>,
    K: IntoIterator,
    K::Item: Into<String>,
{
    ResourceMetadata {
        resource: resource.into(),
        authorization_servers: authorization_servers.into_iter().map(Into::into).collect(),
        scopes_supported: scopes_supported.into_iter().map(Into::into).collect(),
        bearer_methods_supported: vec![BEARER_METHOD_HEADER.to_string()],
    }
}

/// Build the PRM hint URL from a resource URL string.
///
/// # Errors
/// Returns `None` if the resource URL cannot be parsed.
///
/// # Security
/// The returned value strips query/fragment components per RFC 9728.
///
/// # Panics
/// This function does not panic.
///
/// # Examples
/// ```
/// use mcp_toolkit_http::oauth::resource_metadata_hint;
///
/// let hint = resource_metadata_hint("https://example.com/mcp").expect("hint");
/// assert!(hint.ends_with("/.well-known/oauth-protected-resource/mcp"));
/// ```
pub fn resource_metadata_hint(resource_url: &str) -> Option<String> {
    Url::parse(resource_url)
        .ok()
        .map(|url| resource_metadata_url(&url))
}

/// Build the PRM URL for a resource URL by inserting `/.well-known/oauth-protected-resource`.
///
/// # Security
/// * **Stripping**: Always removes query and fragment components from the output URL.
///
/// # Errors
/// * Does not return errors.
///
/// # Panics
/// * None.
///
/// ```rust,no_run
/// let _ = mcp_toolkit_http::oauth::resource_metadata_url;
/// ```
pub fn resource_metadata_url(resource_url: &Url) -> String {
    let mut url = resource_url.clone();
    url.set_query(None);
    url.set_fragment(None);
    let path = resource_url.path().trim_start_matches('/');
    if path.is_empty() {
        url.set_path(PRM_WELL_KNOWN_PATH);
    } else {
        url.set_path(&format!("{PRM_WELL_KNOWN_PATH}/{path}"));
    }
    url.to_string()
}

/// Build the authorization-server metadata URL for an issuer.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Panics
/// * None.
///
/// ```rust,no_run
/// let _ = mcp_toolkit_http::oauth::authorization_server_metadata_url;
/// ```
pub fn authorization_server_metadata_url(issuer: &str) -> String {
    format!(
        "{}{OAUTH_AUTHZ_WELL_KNOWN_PATH}",
        issuer.trim_end_matches('/')
    )
}

/// Build the OIDC metadata URL for an issuer.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Panics
/// * None.
///
/// ```rust,no_run
/// let _ = mcp_toolkit_http::oauth::oidc_metadata_url;
/// ```
pub fn oidc_metadata_url(issuer: &str) -> String {
    format!("{}{OIDC_WELL_KNOWN_PATH}", issuer.trim_end_matches('/'))
}

/// Build fallback OAuth authorization and token endpoints from an issuer URL.
///
/// This helper is useful when a service has a trusted issuer URL but no richer
/// discovery document yet. It preserves the common Keycloak realm path shape
/// and otherwise falls back to generic `/oauth/authorize` and `/oauth/token`
/// endpoints.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
/// * Prefer explicit metadata or trusted OIDC discovery when available.
///
/// # Panics
/// * None.
pub fn fallback_oauth_endpoints(issuer: &str) -> (String, String) {
    let trimmed = issuer.trim_end_matches('/');
    if trimmed.contains("/realms/") {
        return (
            format!("{trimmed}/protocol/openid-connect/auth"),
            format!("{trimmed}/protocol/openid-connect/token"),
        );
    }
    (
        format!("{trimmed}/oauth/authorize"),
        format!("{trimmed}/oauth/token"),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        authorization_server_metadata_url, authorization_server_well_known_paths,
        fallback_oauth_endpoints, oidc_metadata_url, oidc_well_known_paths,
        protected_resource_well_known_paths, public_base_url_from_bind_addr,
        public_base_url_from_resource_url, resource_metadata_default, resource_metadata_hint,
        resource_metadata_url, resource_url_from_base, validate_absolute_url, UrlValidationError,
        BEARER_METHOD_HEADER, OAUTH_AUTHZ_WELL_KNOWN_PATH, OIDC_WELL_KNOWN_PATH,
        PRM_WELL_KNOWN_PATH,
    };
    use std::net::SocketAddr;
    use url::Url;

    /// Executes resource_metadata_url_for_root.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = resource_metadata_url_for_root;
    /// ```
    #[test]
    fn resource_metadata_url_for_root() {
        let url = Url::parse("https://example.com/").expect("url");
        let metadata = resource_metadata_url(&url);
        assert_eq!(
            metadata,
            format!("https://example.com{PRM_WELL_KNOWN_PATH}")
        );
    }

    /// Executes resource_metadata_url_for_path.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = resource_metadata_url_for_path;
    /// ```
    #[test]
    fn resource_metadata_url_for_path() {
        let url = Url::parse("https://example.com/mcp").expect("url");
        let metadata = resource_metadata_url(&url);
        assert_eq!(
            metadata,
            format!("https://example.com{PRM_WELL_KNOWN_PATH}/mcp")
        );
    }

    /// Executes resource_metadata_url_preserves_trailing_slash.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = resource_metadata_url_preserves_trailing_slash;
    /// ```
    #[test]
    fn resource_metadata_url_preserves_trailing_slash() {
        let url = Url::parse("https://example.com/mcp/").expect("url");
        let metadata = resource_metadata_url(&url);
        assert_eq!(
            metadata,
            format!("https://example.com{PRM_WELL_KNOWN_PATH}/mcp/")
        );
    }

    /// Executes resource_metadata_url_strips_query_and_fragment.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = resource_metadata_url_strips_query_and_fragment;
    /// ```
    #[test]
    fn resource_metadata_url_strips_query_and_fragment() {
        let url = Url::parse("https://example.com/mcp?x=1#y").expect("url");
        let metadata = resource_metadata_url(&url);
        assert_eq!(
            metadata,
            format!("https://example.com{PRM_WELL_KNOWN_PATH}/mcp")
        );
    }

    #[test]
    fn public_base_url_from_bind_addr_uses_http_without_tls() {
        let bind_addr: SocketAddr = "127.0.0.1:9411".parse().expect("socket addr");
        let value = public_base_url_from_bind_addr(&bind_addr, false);
        assert_eq!(value, "http://127.0.0.1:9411");
    }

    #[test]
    fn public_base_url_from_bind_addr_uses_https_with_tls() {
        let bind_addr: SocketAddr = "127.0.0.1:9443".parse().expect("socket addr");
        let value = public_base_url_from_bind_addr(&bind_addr, true);
        assert_eq!(value, "https://127.0.0.1:9443");
    }

    /// Executes authorization_server_metadata_url_trims_slash.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = authorization_server_metadata_url_trims_slash;
    /// ```
    #[test]
    fn authorization_server_metadata_url_trims_slash() {
        let issuer = "http://localhost:8080/realms/example-realm/";
        let metadata = authorization_server_metadata_url(issuer);
        assert_eq!(
            metadata,
            format!("http://localhost:8080/realms/example-realm{OAUTH_AUTHZ_WELL_KNOWN_PATH}")
        );
    }

    /// Executes oidc_metadata_url_trims_slash.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = oidc_metadata_url_trims_slash;
    /// ```
    #[test]
    fn oidc_metadata_url_trims_slash() {
        let issuer = "http://localhost:8080/realms/example-realm/";
        let metadata = oidc_metadata_url(issuer);
        assert_eq!(
            metadata,
            format!("http://localhost:8080/realms/example-realm{OIDC_WELL_KNOWN_PATH}")
        );
    }

    /// Executes fallback_oauth_endpoints_use_keycloak_realm_protocol_paths.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = fallback_oauth_endpoints_use_keycloak_realm_protocol_paths;
    /// ```
    #[test]
    fn fallback_oauth_endpoints_use_keycloak_realm_protocol_paths() {
        let issuer = "https://issuer.example.com/realms/example";
        let (authz, token) = fallback_oauth_endpoints(issuer);
        assert_eq!(
            authz,
            "https://issuer.example.com/realms/example/protocol/openid-connect/auth"
        );
        assert_eq!(
            token,
            "https://issuer.example.com/realms/example/protocol/openid-connect/token"
        );
    }

    /// Executes fallback_oauth_endpoints_use_generic_oauth_paths_otherwise.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = fallback_oauth_endpoints_use_generic_oauth_paths_otherwise;
    /// ```
    #[test]
    fn fallback_oauth_endpoints_use_generic_oauth_paths_otherwise() {
        let issuer = "https://issuer.example.com/";
        let (authz, token) = fallback_oauth_endpoints(issuer);
        assert_eq!(authz, "https://issuer.example.com/oauth/authorize");
        assert_eq!(token, "https://issuer.example.com/oauth/token");
    }

    /// Executes resource_url_from_base_trims_slashes.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = resource_url_from_base_trims_slashes;
    /// ```
    #[test]
    fn resource_url_from_base_trims_slashes() {
        let url = resource_url_from_base("http://localhost:9411/", "/mcp");
        assert_eq!(url, "http://localhost:9411/mcp");
        let url = resource_url_from_base("http://localhost:9411", "mcp");
        assert_eq!(url, "http://localhost:9411/mcp");
    }

    /// Executes public_base_url_from_resource_url_extracts_expected_prefix.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = public_base_url_from_resource_url_extracts_expected_prefix;
    /// ```
    #[test]
    fn public_base_url_from_resource_url_extracts_expected_prefix() {
        let value = public_base_url_from_resource_url("https://mcp.example.com/mcp", "/mcp")
            .expect("url parse");
        assert_eq!(value.as_deref(), Some("https://mcp.example.com"));
    }

    /// Executes public_base_url_from_resource_url_strips_query_and_fragment.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = public_base_url_from_resource_url_strips_query_and_fragment;
    /// ```
    #[test]
    fn public_base_url_from_resource_url_strips_query_and_fragment() {
        let value =
            public_base_url_from_resource_url("https://mcp.example.com/mcp?x=1#fragment", "/mcp")
                .expect("url parse");
        assert_eq!(value.as_deref(), Some("https://mcp.example.com"));
    }

    /// Executes public_base_url_from_resource_url_rejects_non_matching_path.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = public_base_url_from_resource_url_rejects_non_matching_path;
    /// ```
    #[test]
    fn public_base_url_from_resource_url_rejects_non_matching_path() {
        let value = public_base_url_from_resource_url("https://mcp.example.com/health", "/mcp")
            .expect("url parse");
        assert!(value.is_none());
    }

    /// Executes resource_metadata_default_sets_header_method.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = resource_metadata_default_sets_header_method;
    /// ```
    #[test]
    fn resource_metadata_default_sets_header_method() {
        let metadata = resource_metadata_default(
            "https://example.com/mcp",
            ["https://example.com"],
            ["search"],
        );
        assert_eq!(
            metadata.bearer_methods_supported,
            vec![BEARER_METHOD_HEADER.to_string()]
        );
    }

    /// Executes resource_metadata_hint_handles_invalid_url.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = resource_metadata_hint_handles_invalid_url;
    /// ```
    #[test]
    fn resource_metadata_hint_handles_invalid_url() {
        assert!(resource_metadata_hint("not-a-url").is_none());
    }

    /// Executes oauth_well_known_paths_root.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = oauth_well_known_paths_root;
    /// ```
    #[test]
    fn oauth_well_known_paths_root() {
        let paths = authorization_server_well_known_paths("/");
        assert_eq!(
            paths,
            vec!["/.well-known/oauth-authorization-server".to_string()]
        );
    }

    /// Executes oauth_well_known_paths_with_suffix.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = oauth_well_known_paths_with_suffix;
    /// ```
    #[test]
    fn oauth_well_known_paths_with_suffix() {
        let paths = authorization_server_well_known_paths("/mcp");
        assert_eq!(
            paths,
            vec!["/.well-known/oauth-authorization-server/mcp".to_string()]
        );
    }

    /// Executes oauth_well_known_paths_trailing_slash.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = oauth_well_known_paths_trailing_slash;
    /// ```
    #[test]
    fn oauth_well_known_paths_trailing_slash() {
        let paths = authorization_server_well_known_paths("/v1/mcp/");
        assert_eq!(
            paths,
            vec!["/.well-known/oauth-authorization-server/v1/mcp".to_string()]
        );
    }

    /// Executes oidc_well_known_paths_with_suffix.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = oidc_well_known_paths_with_suffix;
    /// ```
    #[test]
    fn oidc_well_known_paths_with_suffix() {
        let paths = oidc_well_known_paths("/mcp");
        assert_eq!(
            paths,
            vec!["/.well-known/openid-configuration/mcp".to_string()]
        );
    }

    /// Executes prm_well_known_paths_with_suffix.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = prm_well_known_paths_with_suffix;
    /// ```
    #[test]
    fn prm_well_known_paths_with_suffix() {
        let paths = protected_resource_well_known_paths("/mcp");
        assert_eq!(
            paths,
            vec!["/.well-known/oauth-protected-resource/mcp".to_string()]
        );
    }

    /// Executes validate_absolute_url_accepts_https.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = validate_absolute_url_accepts_https;
    /// ```
    #[test]
    fn validate_absolute_url_accepts_https() {
        let result = validate_absolute_url("https://example.com/mcp", false);
        assert!(result.is_ok());
    }

    /// Executes validate_absolute_url_accepts_http_when_allowed.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = validate_absolute_url_accepts_http_when_allowed;
    /// ```
    #[test]
    fn validate_absolute_url_accepts_http_when_allowed() {
        let result = validate_absolute_url("http://localhost:9411/mcp", true);
        assert!(result.is_ok());
    }

    /// Executes validate_absolute_url_rejects_http_when_disallowed.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = validate_absolute_url_rejects_http_when_disallowed;
    /// ```
    #[test]
    fn validate_absolute_url_rejects_http_when_disallowed() {
        let result = validate_absolute_url("http://localhost:9411/mcp", false);
        assert_eq!(result, Err(UrlValidationError::InsecureScheme));
    }

    /// Executes validate_absolute_url_rejects_relative.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = validate_absolute_url_rejects_relative;
    /// ```
    #[test]
    fn validate_absolute_url_rejects_relative() {
        let result = validate_absolute_url("/mcp", false);
        assert_eq!(result, Err(UrlValidationError::Invalid));
    }

    /// Executes validate_absolute_url_rejects_missing_host.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// let _ = validate_absolute_url_rejects_missing_host;
    /// ```
    #[test]
    fn validate_absolute_url_rejects_missing_host() {
        let result = validate_absolute_url("https:///mcp", false);
        assert_eq!(result, Err(UrlValidationError::MissingHost));
    }
}
