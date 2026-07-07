//! # Upstream OAuth
//!
//! Browser OAuth helpers for MCP servers that call an upstream API on behalf of
//! a local operator or end user.
//!
//! ## Rationale
//! Keeps upstream API authorization separate from inbound MCP client
//! authentication while sharing the fragile parts of OAuth implementation:
//! PKCE generation, loopback redirects, token exchange, token caching, and
//! redaction.
//!
//! ## Security Boundaries
//! * Secrets use redacted wrapper types for `Debug` output.
//! * Loopback flows validate `state` before exchanging authorization codes.
//! * File-backed refresh tokens reject group/world-readable files on Unix.
//! * Google client helpers only accept Google's HTTPS token endpoints.
//!
//! ## References
//! * RFC 6749: OAuth 2.0 Authorization Framework.
//! * RFC 7636: Proof Key for Code Exchange.

use oauth2::basic::{BasicErrorResponse, BasicTokenType};
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    EndpointSet, ExtraTokenFields, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    RefreshToken as OAuth2RefreshToken, RequestTokenError, RevocationErrorResponseType, Scope,
    StandardErrorResponse, StandardRevocableToken, StandardTokenIntrospectionResponse,
    StandardTokenResponse, TokenResponse, TokenUrl,
};
use oauth2_reqwest::ReqwestClient;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::time;

const GOOGLE_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_LEGACY_TOKEN_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/token";
const GOOGLE_LEGACY_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/auth";
const DEFAULT_LOOPBACK_PATH: &str = "/oauth/callback";
const DEFAULT_LOOPBACK_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const ACCESS_TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(60);

/// A secret string that redacts itself in formatted output.
///
/// Use `expose_secret` only at the last possible boundary, such as an HTTP form
/// field or Authorization header.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps a secret-bearing value.
    ///
    /// # Security
    /// The input remains in memory as a normal Rust `String`; this wrapper only
    /// prevents accidental formatted output.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the raw secret value.
    ///
    /// # Security
    /// Callers must not log or return the exposed value.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Returns true when the wrapped secret is empty after trimming whitespace.
    pub fn is_empty(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Errors returned by upstream OAuth helpers.
#[derive(Debug, Error)]
pub enum UpstreamOAuthError {
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid OAuth JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("OAuth client JSON must contain an installed or web client object")]
    MissingClientObject,
    #[error("OAuth client field {0} is required")]
    MissingField(&'static str),
    #[error("OAuth scope list must not be empty")]
    EmptyScopes,
    #[error("invalid OAuth URL in {field}: {value}")]
    InvalidUrl { field: &'static str, value: String },
    #[error("OAuth endpoint {field} must use https unless explicit loopback HTTP is enabled")]
    InsecureEndpoint { field: &'static str },
    #[error("OAuth loopback listener must bind to a loopback address")]
    NonLoopbackBindAddress,
    #[error("Google OAuth token_uri must be one of the supported Google HTTPS token endpoints")]
    DisallowedGoogleTokenEndpoint,
    #[error(
        "Google OAuth auth_uri must be one of the supported Google HTTPS authorization endpoints"
    )]
    DisallowedGoogleAuthEndpoint,
    #[error("Google ADC file must contain an authorized_user credential")]
    UnsupportedGoogleAdcCredentialType,
    #[error("OAuth HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("OAuth token endpoint returned {status}: {error}")]
    TokenEndpoint { status: StatusCode, error: String },
    #[error("OAuth token exchange failed: {0}")]
    TokenExchange(String),
    #[error("{label} response exceeded {max_bytes} bytes")]
    ResponseTooLarge {
        label: &'static str,
        max_bytes: usize,
    },
    #[error("OAuth token response did not include an access token")]
    MissingAccessToken,
    #[error("OAuth response did not include a refresh token")]
    MissingRefreshToken,
    #[error("OAuth grant is missing requested scopes: {0:?}")]
    MissingRequestedScopes(Vec<String>),
    #[error("OAuth loopback callback timed out")]
    CallbackTimeout,
    #[error("OAuth loopback callback did not include an authorization code")]
    CallbackMissingCode,
    #[error("OAuth loopback callback returned error: {0}")]
    CallbackError(String),
    #[error("OAuth loopback state mismatch")]
    StateMismatch,
    #[error("OAuth redirect URI is not registered for this client: {0}")]
    RedirectUriNotRegistered(String),
    #[error("unable to launch browser: {0}")]
    BrowserLaunch(String),
    #[error("stored refresh token file has unsafe permissions or path type")]
    UnsafeTokenFilePermissions,
    #[error("stored token cache version {0} is not supported")]
    UnsupportedTokenCacheVersion(u8),
}

fn io_error(context: &'static str, source: std::io::Error) -> UpstreamOAuthError {
    UpstreamOAuthError::Io { context, source }
}

/// The OAuth client object flavor selected from a Google client-secret file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GoogleOAuthClientKind {
    /// A desktop/native installed-application client.
    Installed,
    /// A web-application client.
    Web,
}

/// How a client authenticates to an upstream OAuth token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OAuthClientAuthMethod {
    /// Send `client_id` and `client_secret` in the request body.
    RequestBody,
    /// Send `client_id` and `client_secret` with HTTP Basic authentication.
    Basic,
}

/// OAuth client configuration used by upstream browser and refresh flows.
#[derive(Clone)]
pub struct OAuthClientConfig {
    client_id: String,
    client_secret: Option<SecretString>,
    authorization_endpoint: String,
    token_endpoint: String,
    token_auth_method: OAuthClientAuthMethod,
    redirect_uris: Vec<String>,
    kind: Option<GoogleOAuthClientKind>,
}

impl fmt::Debug for OAuthClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthClientConfig")
            .field("client_id", &self.client_id)
            .field("client_secret_present", &self.client_secret_present())
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("token_auth_method", &self.token_auth_method)
            .field("redirect_uris", &self.redirect_uris)
            .field("kind", &self.kind)
            .finish()
    }
}

impl OAuthClientConfig {
    /// Builds a provider-neutral OAuth client config.
    ///
    /// # Errors
    /// Returns `MissingField` when the client id is blank, `InvalidUrl` if either
    /// endpoint is not an absolute URL, and `InsecureEndpoint` if either endpoint
    /// is not HTTPS.
    ///
    /// # Security
    /// Requires HTTPS endpoints. Use `new_allow_insecure_loopback` only for
    /// local tests or provider emulators.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<SecretString>,
        authorization_endpoint: impl Into<String>,
        token_endpoint: impl Into<String>,
    ) -> Result<Self, UpstreamOAuthError> {
        let client_id = client_id.into();
        if client_id.trim().is_empty() {
            return Err(UpstreamOAuthError::MissingField("client_id"));
        }
        let authorization_endpoint = authorization_endpoint.into();
        validate_endpoint_url("authorization_endpoint", &authorization_endpoint, false)?;
        let token_endpoint = token_endpoint.into();
        validate_endpoint_url("token_endpoint", &token_endpoint, false)?;
        Ok(Self {
            client_id,
            client_secret,
            authorization_endpoint,
            token_endpoint,
            token_auth_method: OAuthClientAuthMethod::RequestBody,
            redirect_uris: Vec::new(),
            kind: None,
        })
    }

    /// Builds a provider-neutral OAuth client config allowing HTTP loopback
    /// endpoints.
    ///
    /// # Errors
    /// Returns `MissingField` when the client id is blank, `InvalidUrl` for
    /// malformed URLs, and `InsecureEndpoint` when an HTTP endpoint is not
    /// loopback.
    ///
    /// # Security
    /// Intended for local emulators and tests. Production providers should use
    /// HTTPS endpoints through `new`.
    pub fn new_allow_insecure_loopback(
        client_id: impl Into<String>,
        client_secret: Option<SecretString>,
        authorization_endpoint: impl Into<String>,
        token_endpoint: impl Into<String>,
    ) -> Result<Self, UpstreamOAuthError> {
        let client_id = client_id.into();
        if client_id.trim().is_empty() {
            return Err(UpstreamOAuthError::MissingField("client_id"));
        }
        let authorization_endpoint = authorization_endpoint.into();
        validate_endpoint_url("authorization_endpoint", &authorization_endpoint, true)?;
        let token_endpoint = token_endpoint.into();
        validate_endpoint_url("token_endpoint", &token_endpoint, true)?;
        Ok(Self {
            client_id,
            client_secret,
            authorization_endpoint,
            token_endpoint,
            token_auth_method: OAuthClientAuthMethod::RequestBody,
            redirect_uris: Vec::new(),
            kind: None,
        })
    }

    /// Returns the OAuth client id.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Returns whether a non-empty client secret is configured.
    pub fn client_secret_present(&self) -> bool {
        self.client_secret
            .as_ref()
            .map(|secret| !secret.is_empty())
            .unwrap_or(false)
    }

    /// Returns the configured authorization endpoint.
    pub fn authorization_endpoint(&self) -> &str {
        &self.authorization_endpoint
    }

    /// Returns the configured token endpoint.
    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }

    /// Returns how this client authenticates to the token endpoint.
    pub fn token_auth_method(&self) -> OAuthClientAuthMethod {
        self.token_auth_method
    }

    /// Sets how this client authenticates to the token endpoint.
    ///
    /// Google's downloaded client files use request-body client authentication
    /// by default. Use `OAuthClientAuthMethod::Basic` for providers that require
    /// HTTP Basic client authentication.
    pub fn with_token_auth_method(mut self, method: OAuthClientAuthMethod) -> Self {
        self.token_auth_method = method;
        self
    }

    /// Returns redirect URIs declared in the source client file, if any.
    pub fn redirect_uris(&self) -> &[String] {
        &self.redirect_uris
    }

    /// Returns the Google client object kind when this config came from a
    /// Google client-secret file.
    pub fn kind(&self) -> Option<GoogleOAuthClientKind> {
        self.kind
    }
}

#[derive(Debug, Deserialize)]
struct GoogleClientSecretFile {
    #[serde(default)]
    installed: Option<RawGoogleOAuthClient>,
    #[serde(default)]
    web: Option<RawGoogleOAuthClient>,
}

#[derive(Debug, Deserialize)]
struct RawGoogleOAuthClient {
    client_id: Option<String>,
    client_secret: Option<String>,
    auth_uri: Option<String>,
    token_uri: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawGoogleAuthorizedUserAdc {
    #[serde(rename = "type")]
    credential_type: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    refresh_token: Option<String>,
    token_uri: Option<String>,
    quota_project_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct WritableGoogleAuthorizedUserAdc {
    #[serde(rename = "type")]
    credential_type: &'static str,
    client_id: String,
    client_secret: String,
    refresh_token: String,
    token_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    quota_project_id: Option<String>,
}

/// Google authorized-user ADC metadata and refresh configuration.
#[derive(Clone)]
pub struct GoogleAuthorizedUserAdc {
    refresh_config: OAuthRefreshConfig,
    quota_project_id: Option<String>,
}

impl fmt::Debug for GoogleAuthorizedUserAdc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleAuthorizedUserAdc")
            .field("refresh_config", &self.refresh_config)
            .field("quota_project_id", &self.quota_project_id)
            .finish()
    }
}

impl GoogleAuthorizedUserAdc {
    /// Returns the OAuth refresh-token exchange config.
    pub fn refresh_config(&self) -> &OAuthRefreshConfig {
        &self.refresh_config
    }

    /// Converts this ADC record into its OAuth refresh-token exchange config.
    pub fn into_refresh_config(self) -> OAuthRefreshConfig {
        self.refresh_config
    }

    /// Returns the ADC quota project id, when the file declares one.
    pub fn quota_project_id(&self) -> Option<&str> {
        self.quota_project_id.as_deref()
    }

    /// Returns the OAuth client id embedded in the ADC file.
    pub fn client_id(&self) -> &str {
        self.refresh_config.client().client_id()
    }
}

/// Parses a Google OAuth client-secret JSON file.
///
/// # Errors
/// Returns an error when the file cannot be read, is malformed, lacks a client
/// object, or references unsupported Google OAuth endpoints.
///
/// # Security
/// The returned config redacts client-secret values in debug output.
pub fn google_oauth_client_from_file(
    path: impl AsRef<Path>,
) -> Result<OAuthClientConfig, UpstreamOAuthError> {
    let bytes = fs::read(path).map_err(|err| io_error("read OAuth client file", err))?;
    google_oauth_client_from_slice(&bytes)
}

/// Parses Google OAuth client-secret JSON bytes.
///
/// # Errors
/// Returns an error when JSON is malformed, lacks a client object, lacks a
/// required client id, or references unsupported Google OAuth endpoints.
///
/// # Security
/// The returned config redacts client-secret values in debug output.
pub fn google_oauth_client_from_slice(
    bytes: &[u8],
) -> Result<OAuthClientConfig, UpstreamOAuthError> {
    let parsed: GoogleClientSecretFile = serde_json::from_slice(bytes)?;
    let (kind, client) = if let Some(installed) = parsed.installed {
        (GoogleOAuthClientKind::Installed, installed)
    } else if let Some(web) = parsed.web {
        (GoogleOAuthClientKind::Web, web)
    } else {
        return Err(UpstreamOAuthError::MissingClientObject);
    };

    let client_id = required_field(client.client_id, "client_id")?;
    let authorization_endpoint = client
        .auth_uri
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| GOOGLE_AUTH_ENDPOINT.to_string());
    validate_google_authorization_endpoint(&authorization_endpoint)?;
    let token_endpoint = client
        .token_uri
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| GOOGLE_TOKEN_ENDPOINT.to_string());
    validate_google_token_endpoint(&token_endpoint)?;
    let client_secret = client
        .client_secret
        .filter(|value| !value.trim().is_empty())
        .map(SecretString::new);

    Ok(OAuthClientConfig {
        client_id,
        client_secret,
        authorization_endpoint,
        token_endpoint,
        token_auth_method: OAuthClientAuthMethod::RequestBody,
        redirect_uris: client.redirect_uris,
        kind: Some(kind),
    })
}

/// Parses a Google authorized-user ADC file.
///
/// # Errors
/// Returns file, JSON, unsupported-credential-type, missing-field, endpoint,
/// empty-scope, or blank-refresh-token errors.
///
/// # Security
/// The returned config redacts client-secret and refresh-token values in
/// formatted output. Prefer server-specific ADC files so one MCP server's
/// login cannot replace another server's grant.
pub fn google_authorized_user_adc_from_file(
    path: impl AsRef<Path>,
    scopes: Vec<String>,
) -> Result<GoogleAuthorizedUserAdc, UpstreamOAuthError> {
    let bytes = fs::read(path).map_err(|err| io_error("read Google ADC file", err))?;
    google_authorized_user_adc_from_slice(&bytes, scopes)
}

/// Parses Google authorized-user ADC JSON bytes.
///
/// # Errors
/// Returns JSON, unsupported-credential-type, missing-field, endpoint,
/// empty-scope, or blank-refresh-token errors.
///
/// # Security
/// The returned config redacts client-secret and refresh-token values in
/// formatted output. The ADC input bytes are secret-bearing and must not be
/// logged.
pub fn google_authorized_user_adc_from_slice(
    bytes: &[u8],
    scopes: Vec<String>,
) -> Result<GoogleAuthorizedUserAdc, UpstreamOAuthError> {
    let parsed: RawGoogleAuthorizedUserAdc = serde_json::from_slice(bytes)?;
    let credential_type = parsed
        .credential_type
        .as_deref()
        .map(str::trim)
        .unwrap_or("");
    if credential_type != "authorized_user" {
        return Err(UpstreamOAuthError::UnsupportedGoogleAdcCredentialType);
    }

    let client_id = required_field(parsed.client_id, "client_id")?;
    let client_secret = SecretString::new(required_field(parsed.client_secret, "client_secret")?);
    let refresh_token = SecretString::new(required_field(parsed.refresh_token, "refresh_token")?);
    let token_endpoint = parsed
        .token_uri
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| GOOGLE_TOKEN_ENDPOINT.to_string());
    validate_google_token_endpoint(&token_endpoint)?;

    let client = OAuthClientConfig::new(
        client_id,
        Some(client_secret),
        GOOGLE_AUTH_ENDPOINT,
        token_endpoint,
    )?;
    let refresh_config = OAuthRefreshConfig::new(client, refresh_token, scopes)?;
    Ok(GoogleAuthorizedUserAdc {
        refresh_config,
        quota_project_id: parsed
            .quota_project_id
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
    })
}

/// Saves a Google authorized-user ADC file from a browser OAuth token response.
///
/// # Errors
/// Returns `MissingRefreshToken` if the token response has no refresh token,
/// `MissingField("client_secret")` if the OAuth client file lacks a client
/// secret, or I/O/permission errors while writing the credential file.
///
/// # Security
/// Writes through the same owner-only, non-symlink file path checks used by the
/// refresh-token cache. The generated JSON contains a refresh token and client
/// secret; callers must keep the path outside repositories and public sync
/// folders.
pub fn save_google_authorized_user_adc(
    path: impl AsRef<Path>,
    client: &OAuthClientConfig,
    token_set: OAuthTokenSet,
    quota_project_id: Option<&str>,
) -> Result<(), UpstreamOAuthError> {
    let refresh_token = token_set
        .refresh_token
        .filter(|token| !token.is_empty())
        .ok_or(UpstreamOAuthError::MissingRefreshToken)?;
    let client_secret = client
        .client_secret
        .as_ref()
        .filter(|secret| !secret.is_empty())
        .ok_or(UpstreamOAuthError::MissingField("client_secret"))?;
    let raw = WritableGoogleAuthorizedUserAdc {
        credential_type: "authorized_user",
        client_id: client.client_id.clone(),
        client_secret: client_secret.expose_secret().to_string(),
        refresh_token: refresh_token.expose_secret().to_string(),
        token_uri: client.token_endpoint.clone(),
        quota_project_id: quota_project_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
    };
    let bytes = serde_json::to_vec_pretty(&raw)?;
    write_secret_json_file(path.as_ref(), &bytes)
}

fn required_field(
    value: Option<String>,
    field: &'static str,
) -> Result<String, UpstreamOAuthError> {
    match value {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(UpstreamOAuthError::MissingField(field)),
    }
}

fn validate_endpoint_url(
    field: &'static str,
    value: &str,
    allow_http_loopback: bool,
) -> Result<Url, UpstreamOAuthError> {
    let url = Url::parse(value).map_err(|_| UpstreamOAuthError::InvalidUrl {
        field,
        value: value.to_string(),
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(UpstreamOAuthError::InvalidUrl {
            field,
            value: value.to_string(),
        });
    }
    if url.scheme() == "http" {
        let is_allowed = allow_http_loopback && url_host_is_loopback(&url);
        if !is_allowed {
            return Err(UpstreamOAuthError::InsecureEndpoint { field });
        }
    }
    Ok(url)
}

fn url_host_is_loopback(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => normalized_ip_host(host)
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false),
        None => false,
    }
}

fn normalized_ip_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|trimmed| trimmed.strip_suffix(']'))
        .unwrap_or(host)
}

fn validate_google_token_endpoint(value: &str) -> Result<(), UpstreamOAuthError> {
    let url = validate_endpoint_url("token_uri", value, false)?;
    let supported = url.scheme() == "https"
        && matches!(
            url.as_str().trim_end_matches('/'),
            GOOGLE_TOKEN_ENDPOINT | GOOGLE_LEGACY_TOKEN_ENDPOINT
        );
    if supported {
        Ok(())
    } else {
        Err(UpstreamOAuthError::DisallowedGoogleTokenEndpoint)
    }
}

fn validate_google_authorization_endpoint(value: &str) -> Result<(), UpstreamOAuthError> {
    let url = validate_endpoint_url("auth_uri", value, false)?;
    let supported = url.scheme() == "https"
        && matches!(
            url.as_str().trim_end_matches('/'),
            GOOGLE_AUTH_ENDPOINT | GOOGLE_LEGACY_AUTH_ENDPOINT
        );
    if supported {
        Ok(())
    } else {
        Err(UpstreamOAuthError::DisallowedGoogleAuthEndpoint)
    }
}

/// A refresh-token based upstream OAuth token provider.
pub struct RefreshTokenProvider {
    http: ReqwestClient,
    config: OAuthRefreshConfig,
    current_refresh_token: RwLock<SecretString>,
    replacement_refresh_token: RwLock<Option<ReplacementRefreshToken>>,
    cached_access_token: RwLock<Option<CachedAccessToken>>,
}

impl RefreshTokenProvider {
    /// Creates a refresh-token provider with a toolkit-owned token client.
    ///
    /// # Errors
    /// Returns HTTP client construction errors or `EmptyScopes`.
    ///
    /// # Security
    /// Token endpoint requests use a no-redirect HTTP client so refresh-token
    /// values are never replayed to redirect targets.
    pub fn new(config: OAuthRefreshConfig) -> Result<Self, UpstreamOAuthError> {
        Self::with_timeout(config, DEFAULT_TOKEN_REQUEST_TIMEOUT)
    }

    /// Creates a refresh-token provider with a toolkit-owned token client.
    ///
    /// # Errors
    /// Returns HTTP client construction errors or `EmptyScopes`.
    ///
    /// # Security
    /// This is an alias for `new` kept so server setup code can read as
    /// "provider from config" without accepting an arbitrary HTTP client.
    pub fn from_config(config: OAuthRefreshConfig) -> Result<Self, UpstreamOAuthError> {
        Self::new(config)
    }

    /// Creates a refresh-token provider with an explicit token request timeout.
    ///
    /// # Errors
    /// Returns HTTP client construction errors or `EmptyScopes`.
    ///
    /// # Security
    /// Use a bounded timeout so token refresh cannot hang tool execution
    /// indefinitely. Token endpoint redirects are always disabled.
    pub fn with_timeout(
        config: OAuthRefreshConfig,
        timeout: Duration,
    ) -> Result<Self, UpstreamOAuthError> {
        if config.scopes.is_empty() {
            return Err(UpstreamOAuthError::EmptyScopes);
        }
        let http = token_http_client(timeout)?;
        Ok(Self {
            http,
            current_refresh_token: RwLock::new(config.refresh_token.clone()),
            replacement_refresh_token: RwLock::new(None),
            config,
            cached_access_token: RwLock::new(None),
        })
    }

    /// Returns the latest provider-issued replacement refresh token.
    ///
    /// # Security
    /// Callers must persist this value through `RefreshTokenFileStore` or another
    /// secret-safe store before the provider invalidates the previous refresh
    /// token.
    pub async fn replacement_refresh_token(&self) -> Option<ReplacementRefreshToken> {
        self.replacement_refresh_token.read().await.clone()
    }

    /// Takes the latest provider-issued replacement refresh token.
    ///
    /// Use this after `access_token` succeeds when adopting providers that rotate
    /// refresh tokens during refresh.
    ///
    /// # Security
    /// Callers must not log or return the exposed token.
    pub async fn take_replacement_refresh_token(&self) -> Option<ReplacementRefreshToken> {
        self.replacement_refresh_token.write().await.take()
    }

    /// Returns an access token, refreshing and caching it when needed.
    ///
    /// # Errors
    /// Returns token endpoint, HTTP, or malformed-response errors.
    ///
    /// # Security
    /// Callers must not log or return the exposed token.
    pub async fn access_token(&self) -> Result<SecretString, UpstreamOAuthError> {
        if let Some(cached) = self.cached_access_token.read().await.as_ref() {
            if Instant::now() < cached.refresh_after {
                return Ok(cached.value.clone());
            }
        }

        let mut writer = self.cached_access_token.write().await;
        if let Some(cached) = writer.as_ref() {
            if Instant::now() < cached.refresh_after {
                return Ok(cached.value.clone());
            }
        }

        let refresh_token = self.current_refresh_token.read().await.clone();
        let token_set =
            refresh_access_token_with_token(&self.http, &self.config, &refresh_token).await?;
        let granted_scopes = granted_scopes_from_token_set(
            self.config.expected_response_scopes(),
            token_set.scope.as_deref(),
        )?;
        let access_token = token_set
            .access_token
            .filter(|token| !token.is_empty())
            .ok_or(UpstreamOAuthError::MissingAccessToken)?;
        if let Some(replacement) = token_set
            .refresh_token
            .clone()
            .filter(|token| !token.is_empty())
        {
            let replacement_metadata = ReplacementRefreshToken {
                refresh_token: replacement.clone(),
                scopes: granted_scopes,
                token_type: token_set.token_type.clone(),
                refresh_token_expires_at_unix_seconds: token_set
                    .refresh_token_expires_in
                    .and_then(refresh_expiration_timestamp),
            };
            let mut current_refresh_token = self.current_refresh_token.write().await;
            let mut replacement_refresh_token = self.replacement_refresh_token.write().await;
            *current_refresh_token = replacement.clone();
            *replacement_refresh_token = Some(replacement_metadata);
        }
        let now = Instant::now();
        let refresh_after = token_set
            .expires_in
            .and_then(|expires| Duration::from_secs(expires).checked_sub(ACCESS_TOKEN_REFRESH_SKEW))
            .and_then(|duration| now.checked_add(duration))
            .unwrap_or(now);
        *writer = Some(CachedAccessToken {
            value: access_token.clone(),
            refresh_after,
        });
        Ok(access_token)
    }
}

#[derive(Clone)]
struct CachedAccessToken {
    value: SecretString,
    refresh_after: Instant,
}

/// Configuration for exchanging a refresh token for access tokens.
#[derive(Clone)]
pub struct OAuthRefreshConfig {
    client: OAuthClientConfig,
    refresh_token: SecretString,
    scopes: Vec<String>,
    refresh_request_scopes: Vec<String>,
}

impl fmt::Debug for OAuthRefreshConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthRefreshConfig")
            .field("client", &self.client)
            .field("refresh_token", &"<redacted>")
            .field("scopes", &self.scopes)
            .field("refresh_request_scopes", &self.refresh_request_scopes)
            .finish()
    }
}

impl OAuthRefreshConfig {
    /// Builds a refresh-token exchange config.
    ///
    /// # Errors
    /// Returns `EmptyScopes` when the scope list is empty and
    /// `MissingRefreshToken` when the refresh token is blank.
    ///
    /// # Security
    /// The refresh token is redacted in formatted output. `scopes` should be
    /// the scopes known to be associated with the stored refresh token. They
    /// are used for validation and replacement-token metadata; they are not
    /// sent to the token endpoint during refresh unless
    /// `with_refresh_request_scopes` is used.
    pub fn new(
        client: OAuthClientConfig,
        refresh_token: SecretString,
        scopes: Vec<String>,
    ) -> Result<Self, UpstreamOAuthError> {
        if scopes.is_empty() {
            return Err(UpstreamOAuthError::EmptyScopes);
        }
        if refresh_token.is_empty() {
            return Err(UpstreamOAuthError::MissingRefreshToken);
        }
        Ok(Self {
            client,
            refresh_token,
            scopes,
            refresh_request_scopes: Vec::new(),
        })
    }

    /// Creates a Google refresh-token config from a client-secret file.
    ///
    /// # Errors
    /// Returns file, JSON, endpoint validation, missing field, empty scope, or
    /// blank refresh-token errors.
    ///
    /// # Security
    /// The refresh token and client secret are redacted in formatted output.
    pub fn google_from_client_file(
        path: impl AsRef<Path>,
        refresh_token: SecretString,
        scopes: Vec<String>,
    ) -> Result<Self, UpstreamOAuthError> {
        Self::new(google_oauth_client_from_file(path)?, refresh_token, scopes)
    }

    /// Returns the client config.
    pub fn client(&self) -> &OAuthClientConfig {
        &self.client
    }

    /// Returns the stored grant scope list.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Returns scopes explicitly requested on refresh-token exchange.
    pub fn refresh_request_scopes(&self) -> &[String] {
        &self.refresh_request_scopes
    }

    /// Sends an explicit scope list during refresh-token exchange.
    ///
    /// # Errors
    /// Returns `EmptyScopes` when the explicit scope list is empty.
    ///
    /// # Security
    /// Most providers should refresh the existing grant without a `scope`
    /// parameter. Use this only for providers or workflows that intentionally
    /// request a narrower access-token scope set during refresh.
    pub fn with_refresh_request_scopes(
        mut self,
        scopes: Vec<String>,
    ) -> Result<Self, UpstreamOAuthError> {
        if scopes.is_empty() {
            return Err(UpstreamOAuthError::EmptyScopes);
        }
        self.refresh_request_scopes = scopes;
        Ok(self)
    }

    fn expected_response_scopes(&self) -> &[String] {
        if self.refresh_request_scopes.is_empty() {
            &self.scopes
        } else {
            &self.refresh_request_scopes
        }
    }
}

/// OAuth token response values.
#[derive(Clone)]
pub struct OAuthTokenSet {
    /// Short-lived access token, if returned by the exchange.
    pub access_token: Option<SecretString>,
    /// Long-lived refresh token, if returned by the exchange.
    pub refresh_token: Option<SecretString>,
    /// Access-token lifetime in seconds.
    pub expires_in: Option<u64>,
    /// Granted scopes as returned by the provider.
    pub scope: Option<String>,
    /// Token type, usually `Bearer`.
    pub token_type: Option<String>,
    /// Refresh-token lifetime in seconds, when the provider returns one.
    pub refresh_token_expires_in: Option<u64>,
}

impl fmt::Debug for OAuthTokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthTokenSet")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("token_type", &self.token_type)
            .field("refresh_token_expires_in", &self.refresh_token_expires_in)
            .finish()
    }
}

fn non_empty_secret(value: Option<String>) -> Option<SecretString> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(SecretString::new)
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct UpstreamOAuth2ExtraTokenFields {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token_expires_in: Option<u64>,
}

impl ExtraTokenFields for UpstreamOAuth2ExtraTokenFields {}

type UpstreamOAuth2TokenResponse =
    StandardTokenResponse<UpstreamOAuth2ExtraTokenFields, BasicTokenType>;

type UpstreamOAuth2ClientBase = oauth2::Client<
    BasicErrorResponse,
    UpstreamOAuth2TokenResponse,
    StandardTokenIntrospectionResponse<UpstreamOAuth2ExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
>;

type UpstreamOAuth2Client = oauth2::Client<
    BasicErrorResponse,
    UpstreamOAuth2TokenResponse,
    StandardTokenIntrospectionResponse<UpstreamOAuth2ExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

type OAuth2TokenRequestError =
    RequestTokenError<oauth2::HttpClientError<reqwest::Error>, BasicErrorResponse>;

/// Exchanges a refresh token for an access token.
///
/// # Errors
/// Returns HTTP, token endpoint, or malformed-response errors.
///
/// # Security
/// Token endpoint requests use a toolkit-owned no-redirect HTTP client. The
/// returned access token is secret-bearing and must not be logged.
pub async fn refresh_access_token(
    config: &OAuthRefreshConfig,
) -> Result<OAuthTokenSet, UpstreamOAuthError> {
    refresh_access_token_with_timeout(config, DEFAULT_TOKEN_REQUEST_TIMEOUT).await
}

/// Exchanges a refresh token for an access token with an explicit timeout.
///
/// # Errors
/// Returns HTTP client construction, token endpoint, or malformed-response
/// errors.
///
/// # Security
/// Token endpoint redirects are always disabled.
pub async fn refresh_access_token_with_timeout(
    config: &OAuthRefreshConfig,
    timeout: Duration,
) -> Result<OAuthTokenSet, UpstreamOAuthError> {
    let http = token_http_client(timeout)?;
    let token_set = refresh_access_token_with_token(&http, config, &config.refresh_token).await;
    token_set
}

async fn refresh_access_token_with_token(
    http: &ReqwestClient,
    config: &OAuthRefreshConfig,
    refresh_token: &SecretString,
) -> Result<OAuthTokenSet, UpstreamOAuthError> {
    let client = oauth2_client(&config.client, None)?;
    let refresh_token = OAuth2RefreshToken::new(refresh_token.expose_secret().to_string());
    let mut redacted_secrets = token_error_secrets(&config.client);
    redacted_secrets.push(refresh_token.secret());
    let mut request = client.exchange_refresh_token(&refresh_token);
    if !config.refresh_request_scopes.is_empty() {
        request = request.add_scopes(
            config
                .refresh_request_scopes
                .iter()
                .cloned()
                .map(Scope::new),
        );
    }
    let token_response = request
        .request_async(http)
        .await
        .map_err(|error| map_oauth2_token_error(error, &redacted_secrets))?;
    Ok(oauth2_token_response_into_token_set(token_response))
}

async fn exchange_authorization_code(
    client: &OAuthClientConfig,
    code: &str,
    code_verifier: PkceCodeVerifier,
    redirect_uri: &str,
) -> Result<OAuthTokenSet, UpstreamOAuthError> {
    let http = token_http_client(DEFAULT_TOKEN_REQUEST_TIMEOUT)?;
    let oauth_client = oauth2_client(client, Some(redirect_uri))?;
    let mut redacted_secrets = token_error_secrets(client);
    redacted_secrets.push(code);
    let token_response = oauth_client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .set_pkce_verifier(code_verifier)
        .request_async(&http)
        .await
        .map_err(|error| map_oauth2_token_error(error, &redacted_secrets))?;
    Ok(oauth2_token_response_into_token_set(token_response))
}

fn oauth2_client(
    client: &OAuthClientConfig,
    redirect_uri: Option<&str>,
) -> Result<UpstreamOAuth2Client, UpstreamOAuthError> {
    let auth_url = AuthUrl::new(client.authorization_endpoint.clone()).map_err(|_| {
        UpstreamOAuthError::InvalidUrl {
            field: "authorization_endpoint",
            value: client.authorization_endpoint.clone(),
        }
    })?;
    let token_url = TokenUrl::new(client.token_endpoint.clone()).map_err(|_| {
        UpstreamOAuthError::InvalidUrl {
            field: "token_endpoint",
            value: client.token_endpoint.clone(),
        }
    })?;
    let auth_type = match client.token_auth_method {
        OAuthClientAuthMethod::RequestBody => AuthType::RequestBody,
        OAuthClientAuthMethod::Basic => AuthType::BasicAuth,
    };
    let mut oauth_client = UpstreamOAuth2ClientBase::new(ClientId::new(client.client_id.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_auth_type(auth_type);
    if let Some(secret) = client
        .client_secret
        .as_ref()
        .filter(|secret| !secret.is_empty())
    {
        oauth_client =
            oauth_client.set_client_secret(ClientSecret::new(secret.expose_secret().to_string()));
    }
    if let Some(redirect_uri) = redirect_uri {
        let redirect_url = RedirectUrl::new(redirect_uri.to_string()).map_err(|_| {
            UpstreamOAuthError::InvalidUrl {
                field: "redirect_uri",
                value: redirect_uri.to_string(),
            }
        })?;
        oauth_client = oauth_client.set_redirect_uri(redirect_url);
    }
    Ok(oauth_client)
}

fn token_http_client(timeout: Duration) -> Result<ReqwestClient, UpstreamOAuthError> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    Ok(ReqwestClient::from(client))
}

fn oauth2_token_response_into_token_set(response: UpstreamOAuth2TokenResponse) -> OAuthTokenSet {
    OAuthTokenSet {
        access_token: non_empty_secret(Some(response.access_token().secret().to_string())),
        refresh_token: response
            .refresh_token()
            .and_then(|token| non_empty_secret(Some(token.secret().to_string()))),
        expires_in: response.expires_in().map(|duration| duration.as_secs()),
        scope: response.scopes().map(|scopes| {
            scopes
                .iter()
                .map(|scope| scope.as_ref())
                .collect::<Vec<_>>()
                .join(" ")
        }),
        token_type: Some(oauth2_token_type_label(response.token_type())),
        refresh_token_expires_in: response.extra_fields().refresh_token_expires_in,
    }
}

fn oauth2_token_type_label(token_type: &BasicTokenType) -> String {
    match token_type {
        BasicTokenType::Bearer => "Bearer".to_string(),
        BasicTokenType::Mac => "MAC".to_string(),
        BasicTokenType::Extension(value) => value.clone(),
    }
}

fn token_error_secrets(client: &OAuthClientConfig) -> Vec<&str> {
    client
        .client_secret
        .as_ref()
        .filter(|secret| !secret.is_empty())
        .map(|secret| vec![secret.expose_secret()])
        .unwrap_or_default()
}

fn map_oauth2_token_error(
    error: OAuth2TokenRequestError,
    redacted_secrets: &[&str],
) -> UpstreamOAuthError {
    match error {
        RequestTokenError::ServerResponse(response) => UpstreamOAuthError::TokenExchange(format!(
            "provider rejected token request: {}",
            redacted_oauth2_error_response(&response, redacted_secrets)
        )),
        RequestTokenError::Request(oauth2::HttpClientError::Reqwest(source)) => {
            UpstreamOAuthError::Http(*source)
        }
        RequestTokenError::Request(source) => UpstreamOAuthError::TokenExchange(
            redact_oauth_text_with_secrets(&source.to_string(), redacted_secrets),
        ),
        RequestTokenError::Parse(_, _) => UpstreamOAuthError::TokenExchange(
            "OAuth token endpoint returned a malformed JSON response".to_string(),
        ),
        RequestTokenError::Other(message) => UpstreamOAuthError::TokenExchange(
            redact_oauth_text_with_secrets(&message, redacted_secrets),
        ),
    }
}

fn redacted_oauth2_error_response(
    response: &BasicErrorResponse,
    redacted_secrets: &[&str],
) -> String {
    let mut message = response.error().to_string();
    if let Some(description) = response.error_description() {
        message.push_str(": ");
        message.push_str(&redact_oauth_text_with_secrets(
            description,
            redacted_secrets,
        ));
    }
    if let Some(uri) = response.error_uri() {
        message.push_str(" (see ");
        message.push_str(&redact_oauth_text_with_secrets(uri, redacted_secrets));
        message.push(')');
    }
    message
}

fn redact_oauth_text(input: &str) -> String {
    redact_oauth_text_with_secrets(input, &[])
}

fn redact_oauth_text_with_secrets(input: &str, secrets: &[&str]) -> String {
    let mut redacted = input.to_string();
    for secret in secrets
        .iter()
        .copied()
        .filter(|secret| !secret.trim().is_empty())
    {
        redacted = redacted.replace(secret, "<redacted>");
    }
    redacted
        .split_whitespace()
        .map(|part| {
            let lower = part.to_ascii_lowercase();
            if lower.contains("access_token")
                || lower.contains("refresh_token")
                || lower.contains("client_secret")
                || lower.starts_with("ya29.")
            {
                "<redacted>"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A file-backed refresh-token cache.
#[derive(Debug, Clone)]
pub struct RefreshTokenFileStore {
    path: PathBuf,
}

impl RefreshTokenFileStore {
    /// Creates a refresh-token file store at an explicit path.
    ///
    /// # Security
    /// Prefer application-specific config directories and never place this file
    /// in a synced public folder.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Returns the configured cache path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads a stored refresh token when the cache exists.
    ///
    /// # Errors
    /// Returns I/O, JSON, unsupported-version, blank refresh-token, or
    /// unsafe-permission errors.
    ///
    /// # Security
    /// On Unix, group/world-readable cache files and symlinked ancestor
    /// directories are rejected before parsing.
    pub fn load(&self) -> Result<Option<StoredRefreshToken>, UpstreamOAuthError> {
        ensure_token_cache_ancestors_safe(&self.path)?;
        if !token_cache_file_exists(&self.path)? {
            return Ok(None);
        }
        let mut file = open_token_file_for_read(&self.path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|err| io_error("read token cache", err))?;
        let raw: StoredRefreshTokenFile = serde_json::from_slice(&bytes)?;
        if raw.version != 1 {
            return Err(UpstreamOAuthError::UnsupportedTokenCacheVersion(
                raw.version,
            ));
        }
        let refresh_token = SecretString::new(raw.refresh_token);
        if refresh_token.is_empty() {
            return Err(UpstreamOAuthError::MissingRefreshToken);
        }
        Ok(Some(StoredRefreshToken {
            provider: raw.provider,
            client_id: raw.client_id,
            refresh_token,
            scopes: raw.scopes,
            token_type: raw.token_type,
            refresh_token_expires_at_unix_seconds: raw.refresh_token_expires_at_unix_seconds,
        }))
    }

    /// Saves a refresh token with owner-only file permissions on Unix.
    ///
    /// # Errors
    /// Returns blank refresh-token, I/O, JSON, or unsafe-existing-file-permission
    /// errors.
    ///
    /// # Security
    /// On Unix, existing cache files with group/world permissions and symlinked
    /// ancestor directories are rejected rather than silently reused. Newly
    /// created cache directories are hardened to owner-only permissions, but
    /// existing parent directories are validated rather than chmodded. On other
    /// platforms, the helper rejects visible symlink and non-file paths but does
    /// not manage account ACLs.
    pub fn save(&self, token: &StoredRefreshToken) -> Result<(), UpstreamOAuthError> {
        if token.refresh_token.is_empty() {
            return Err(UpstreamOAuthError::MissingRefreshToken);
        }
        let raw = StoredRefreshTokenFile {
            version: 1,
            provider: token.provider.clone(),
            client_id: token.client_id.clone(),
            refresh_token: token.refresh_token.expose_secret().to_string(),
            scopes: token.scopes.clone(),
            token_type: token.token_type.clone(),
            refresh_token_expires_at_unix_seconds: token.refresh_token_expires_at_unix_seconds,
        };
        let bytes = serde_json::to_vec_pretty(&raw)?;
        write_secret_json_file(&self.path, &bytes)
    }

    /// Removes the token cache if it exists.
    ///
    /// # Errors
    /// Returns I/O errors except for missing-file removal.
    ///
    /// # Security
    /// This does not revoke the upstream grant; callers should surface that as a
    /// separate provider-specific step when needed.
    pub fn clear(&self) -> Result<(), UpstreamOAuthError> {
        ensure_token_cache_ancestors_safe(&self.path)?;
        if !token_cache_file_exists(&self.path)? {
            return Ok(());
        }
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(io_error("remove token cache", err)),
        }
    }

    /// Returns redaction-safe cache status.
    ///
    /// # Errors
    /// Returns I/O, JSON, unsupported-version, or unsafe-permission errors.
    pub fn status(&self) -> Result<TokenCacheStatus, UpstreamOAuthError> {
        let loaded = self.load()?;
        Ok(TokenCacheStatus {
            path: self.path.clone(),
            exists: loaded.is_some(),
            refresh_token_present: loaded
                .as_ref()
                .map(|token| !token.refresh_token.is_empty())
                .unwrap_or(false),
            client_id: loaded.as_ref().map(|token| token.client_id.clone()),
            provider: loaded.as_ref().map(|token| token.provider.clone()),
            scopes: loaded
                .as_ref()
                .map(|token| token.scopes.clone())
                .unwrap_or_default(),
            refresh_token_expires_at_unix_seconds: loaded
                .and_then(|token| token.refresh_token_expires_at_unix_seconds),
        })
    }
}

fn token_cache_file_exists(path: &Path) -> Result<bool, UpstreamOAuthError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                Err(UpstreamOAuthError::UnsafeTokenFilePermissions)
            } else {
                Ok(true)
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(io_error("stat token cache", err)),
    }
}

#[cfg(unix)]
fn open_token_file_for_read(path: &Path) -> Result<File, UpstreamOAuthError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|err| io_error("open token cache", err))?;
    ensure_owner_only_regular_file(&file)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_token_file_for_read(path: &Path) -> Result<File, UpstreamOAuthError> {
    ensure_regular_non_symlink_path(path)?;
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|err| io_error("open token cache", err))?;
    ensure_regular_file_handle(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn open_token_file_for_write(path: &Path) -> Result<File, UpstreamOAuthError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|err| io_error("open token cache", err))?;
    ensure_owner_only_regular_file(&file)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_token_file_for_write(path: &Path) -> Result<File, UpstreamOAuthError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| io_error("open token cache", err))?;
    ensure_regular_file_handle(&file)?;
    Ok(file)
}

fn token_cache_path_exists(path: &Path) -> Result<bool, UpstreamOAuthError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(io_error("stat token cache directory", err)),
    }
}

fn write_secret_json_file(path: &Path, bytes: &[u8]) -> Result<(), UpstreamOAuthError> {
    ensure_token_cache_ancestors_safe(path)?;
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        let parent_preexisting = token_cache_path_exists(parent)?;
        fs::create_dir_all(parent).map_err(|err| io_error("create token cache directory", err))?;
        if !parent_preexisting {
            harden_token_cache_directory(parent)?;
        }
        ensure_token_cache_directory(parent)?;
    }
    if token_cache_file_exists(path)? {
        let _ = open_token_file_for_read(path)?;
    }
    let temp_path = temporary_token_cache_path(path);
    let mut file = open_token_file_for_write(&temp_path)?;
    let write_result = file
        .write_all(bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|err| io_error("write token cache", err));
    if let Err(err) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    drop(file);
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(io_error("rename token cache", err));
    }
    Ok(())
}

fn ensure_token_cache_ancestors_safe(path: &Path) -> Result<(), UpstreamOAuthError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    for ancestor in parent.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    return Err(UpstreamOAuthError::UnsafeTokenFilePermissions);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(io_error("stat token cache directory", err)),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_owner_only_regular_file(file: &File) -> Result<(), UpstreamOAuthError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = file
        .metadata()
        .map_err(|err| io_error("stat token cache", err))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(UpstreamOAuthError::UnsafeTokenFilePermissions);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(UpstreamOAuthError::UnsafeTokenFilePermissions);
    }
    if metadata.nlink() != 1 {
        return Err(UpstreamOAuthError::UnsafeTokenFilePermissions);
    }
    Ok(())
}

#[cfg(unix)]
fn harden_token_cache_directory(path: &Path) -> Result<(), UpstreamOAuthError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata =
        fs::symlink_metadata(path).map_err(|err| io_error("stat token cache directory", err))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(UpstreamOAuthError::UnsafeTokenFilePermissions);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| io_error("harden token cache directory", err))
}

#[cfg(not(unix))]
fn harden_token_cache_directory(path: &Path) -> Result<(), UpstreamOAuthError> {
    ensure_directory_non_symlink_path(path)
}

#[cfg(unix)]
fn ensure_token_cache_directory(path: &Path) -> Result<(), UpstreamOAuthError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata =
        fs::symlink_metadata(path).map_err(|err| io_error("stat token cache directory", err))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(UpstreamOAuthError::UnsafeTokenFilePermissions);
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(UpstreamOAuthError::UnsafeTokenFilePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_token_cache_directory(path: &Path) -> Result<(), UpstreamOAuthError> {
    ensure_directory_non_symlink_path(path)
}

#[cfg(not(unix))]
fn ensure_regular_non_symlink_path(path: &Path) -> Result<(), UpstreamOAuthError> {
    let metadata = fs::symlink_metadata(path).map_err(|err| io_error("stat token cache", err))?;
    if metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(UpstreamOAuthError::UnsafeTokenFilePermissions)
    }
}

#[cfg(not(unix))]
fn ensure_directory_non_symlink_path(path: &Path) -> Result<(), UpstreamOAuthError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|err| io_error("stat token cache directory", err))?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(UpstreamOAuthError::UnsafeTokenFilePermissions)
    }
}

#[cfg(not(unix))]
fn ensure_regular_file_handle(file: &File) -> Result<(), UpstreamOAuthError> {
    let metadata = file
        .metadata()
        .map_err(|err| io_error("stat token cache", err))?;
    if metadata.file_type().is_file() {
        Ok(())
    } else {
        Err(UpstreamOAuthError::UnsafeTokenFilePermissions)
    }
}

fn temporary_token_cache_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("token-cache");
    let temp_name = format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        rand::random::<u64>()
    );
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.join(&temp_name))
        .unwrap_or_else(|| PathBuf::from(temp_name))
}

/// Provider-issued replacement refresh-token metadata.
#[derive(Clone)]
pub struct ReplacementRefreshToken {
    /// Replacement refresh token.
    pub refresh_token: SecretString,
    /// Effective scopes associated with the replacement token.
    pub scopes: Vec<String>,
    /// Token type returned by the provider.
    pub token_type: Option<String>,
    /// Refresh-token expiration timestamp when known.
    pub refresh_token_expires_at_unix_seconds: Option<u64>,
}

impl ReplacementRefreshToken {
    /// Converts this replacement token into a stored refresh-token record.
    ///
    /// # Security
    /// The returned record still contains a refresh token and must only be saved
    /// through `RefreshTokenFileStore` or another secret-safe store.
    pub fn into_stored_token(
        self,
        provider: impl Into<String>,
        client_id: impl Into<String>,
    ) -> StoredRefreshToken {
        StoredRefreshToken {
            provider: provider.into(),
            client_id: client_id.into(),
            refresh_token: self.refresh_token,
            scopes: self.scopes,
            token_type: self.token_type,
            refresh_token_expires_at_unix_seconds: self.refresh_token_expires_at_unix_seconds,
        }
    }
}

impl fmt::Debug for ReplacementRefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplacementRefreshToken")
            .field("refresh_token", &"<redacted>")
            .field("scopes", &self.scopes)
            .field("token_type", &self.token_type)
            .field(
                "refresh_token_expires_at_unix_seconds",
                &self.refresh_token_expires_at_unix_seconds,
            )
            .finish()
    }
}

/// Redaction-safe refresh-token cache status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenCacheStatus {
    /// Cache file path.
    pub path: PathBuf,
    /// Whether a parseable cache exists.
    pub exists: bool,
    /// Whether a non-empty refresh token is present.
    pub refresh_token_present: bool,
    /// Cached OAuth client id.
    pub client_id: Option<String>,
    /// Provider label, such as `google`.
    pub provider: Option<String>,
    /// Cached granted scopes.
    pub scopes: Vec<String>,
    /// Refresh-token expiration timestamp when known.
    pub refresh_token_expires_at_unix_seconds: Option<u64>,
}

/// A stored refresh token and associated public metadata.
#[derive(Clone)]
pub struct StoredRefreshToken {
    /// Provider label, such as `google`.
    pub provider: String,
    /// OAuth client id associated with the stored token.
    pub client_id: String,
    /// Refresh token.
    pub refresh_token: SecretString,
    /// Scopes associated with the grant.
    pub scopes: Vec<String>,
    /// Token type returned by the provider.
    pub token_type: Option<String>,
    /// Refresh-token expiration timestamp when known.
    pub refresh_token_expires_at_unix_seconds: Option<u64>,
}

impl fmt::Debug for StoredRefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredRefreshToken")
            .field("provider", &self.provider)
            .field("client_id", &self.client_id)
            .field("refresh_token", &"<redacted>")
            .field("scopes", &self.scopes)
            .field("token_type", &self.token_type)
            .field(
                "refresh_token_expires_at_unix_seconds",
                &self.refresh_token_expires_at_unix_seconds,
            )
            .finish()
    }
}

impl StoredRefreshToken {
    /// Builds a stored token from a successful OAuth exchange.
    ///
    /// # Errors
    /// Returns `MissingRefreshToken` if the exchange did not produce one or
    /// `MissingRequestedScopes` if the provider reports a narrower scope set.
    ///
    /// # Security
    /// The refresh token is retained for persistent storage and redacted in
    /// formatted output.
    pub fn from_google_token_set(
        client: &OAuthClientConfig,
        scopes: Vec<String>,
        token_set: OAuthTokenSet,
    ) -> Result<Self, UpstreamOAuthError> {
        let granted_scopes = granted_scopes_from_token_set(&scopes, token_set.scope.as_deref())?;
        let refresh_token = token_set
            .refresh_token
            .filter(|token| !token.is_empty())
            .ok_or(UpstreamOAuthError::MissingRefreshToken)?;
        Ok(Self {
            provider: "google".to_string(),
            client_id: client.client_id.clone(),
            refresh_token,
            scopes: granted_scopes,
            token_type: token_set.token_type,
            refresh_token_expires_at_unix_seconds: token_set
                .refresh_token_expires_in
                .and_then(refresh_expiration_timestamp),
        })
    }
}

fn granted_scopes_from_token_set(
    requested: &[String],
    granted_scope: Option<&str>,
) -> Result<Vec<String>, UpstreamOAuthError> {
    let Some(granted_scope) = granted_scope else {
        return Ok(requested.to_vec());
    };
    let granted = granted_scope
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let granted_set = granted
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let missing = requested
        .iter()
        .filter(|scope| !granted_set.contains(scope.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(granted)
    } else {
        Err(UpstreamOAuthError::MissingRequestedScopes(missing))
    }
}

fn refresh_expiration_timestamp(expires_in: u64) -> Option<u64> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    now.checked_add(expires_in)
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRefreshTokenFile {
    version: u8,
    provider: String,
    client_id: String,
    refresh_token: String,
    scopes: Vec<String>,
    token_type: Option<String>,
    refresh_token_expires_at_unix_seconds: Option<u64>,
}

/// Browser launch behavior for a loopback authorization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum BrowserLaunchMode {
    /// Do not attempt to open a browser; callers can display the URL.
    #[default]
    Disabled,
    /// Try the platform default browser and continue if launching fails.
    BestEffortSystem,
    /// Require the platform default browser to launch successfully.
    RequiredSystem,
    /// Run an explicit browser-launch command.
    Command { program: String, args: Vec<String> },
}

/// Options for a loopback browser authorization.
#[derive(Debug, Clone)]
pub struct LoopbackOAuthOptions {
    /// Loopback bind IP address.
    pub bind_addr: IpAddr,
    /// Optional fixed port; random OS-assigned port when `None`.
    pub port: Option<u16>,
    /// Callback request path.
    pub callback_path: String,
    /// Maximum time to wait for the browser callback.
    pub timeout: Duration,
    /// Browser launch behavior.
    pub browser: BrowserLaunchMode,
    /// Extra authorization query parameters.
    pub extra_authorization_params: Vec<(String, String)>,
    /// HTML body returned after successful callback.
    pub success_html: String,
    /// HTML body returned after failed callback.
    pub error_html: String,
}

impl Default for LoopbackOAuthOptions {
    fn default() -> Self {
        Self {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: None,
            callback_path: DEFAULT_LOOPBACK_PATH.to_string(),
            timeout: DEFAULT_LOOPBACK_TIMEOUT,
            browser: BrowserLaunchMode::Disabled,
            extra_authorization_params: Vec::new(),
            success_html: "Authentication complete. You can close this window.".to_string(),
            error_html: "Authentication failed. You can close this window.".to_string(),
        }
    }
}

impl LoopbackOAuthOptions {
    /// Returns Google browser-login defaults for a durable offline grant.
    ///
    /// # Security
    /// Requests `access_type=offline` so a refresh token can be stored via a
    /// `RefreshTokenFileStore`; callers should request the narrowest scopes.
    pub fn google_login() -> Self {
        let mut options = Self::default();
        options
            .extra_authorization_params
            .push(("access_type".to_string(), "offline".to_string()));
        options
    }

    /// Returns Google reauthorization defaults that force a fresh consent grant.
    ///
    /// # Security
    /// Use this only when an existing refresh token is missing, invalidated, or
    /// needs to be replaced; forced consent is intentionally more intrusive.
    pub fn google_reauth() -> Self {
        let mut options = Self::google_login();
        options
            .extra_authorization_params
            .push(("prompt".to_string(), "consent".to_string()));
        options
    }
}

/// A prepared loopback authorization waiting for browser completion.
pub struct PendingLoopbackAuthorization {
    listener: TcpListener,
    client: OAuthClientConfig,
    scopes: Vec<String>,
    state: CsrfToken,
    code_verifier: PkceCodeVerifier,
    redirect_uri: String,
    authorization_url: String,
    timeout: Duration,
    browser: BrowserLaunchMode,
    success_html: String,
    error_html: String,
}

impl PendingLoopbackAuthorization {
    /// Returns the URL that the operator should open in a system browser.
    pub fn authorization_url(&self) -> &str {
        &self.authorization_url
    }

    /// Returns the loopback redirect URI for this authorization.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Returns the requested scope list.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Attempts to launch the configured browser.
    ///
    /// # Errors
    /// Returns `BrowserLaunch` when browser launch is required or explicit and
    /// the command cannot be spawned.
    ///
    /// # Security
    /// The authorization URL contains request metadata and a CSRF state value,
    /// but no access or refresh token.
    pub fn launch_browser(&self) -> Result<bool, UpstreamOAuthError> {
        launch_browser(&self.browser, &self.authorization_url)
    }

    /// Waits for the loopback callback and exchanges the authorization code.
    ///
    /// # Errors
    /// Returns callback, state, HTTP, or token endpoint errors.
    ///
    /// # Security
    /// Validates the callback `state` before exchanging the code.
    pub async fn finish(self) -> Result<OAuthTokenSet, UpstreamOAuthError> {
        let callback = self.wait_for_callback().await?;
        self.finish_callback(callback).await
    }

    /// Exchanges a pasted loopback callback URL for tokens.
    ///
    /// Use this for SSH or headless environments where the browser cannot reach
    /// the loopback listener. The operator opens `authorization_url`, copies the
    /// final `http://127.0.0.1:...` redirect URL from the browser address bar,
    /// and the caller passes that URL here.
    ///
    /// # Errors
    /// Returns URL parsing, callback, state, HTTP, or token endpoint errors.
    ///
    /// # Security
    /// Validates the callback `state` before exchanging the authorization code.
    /// The pasted URL contains a secret authorization code and must not be
    /// logged.
    pub async fn finish_with_callback_url(
        self,
        callback_url: &str,
    ) -> Result<OAuthTokenSet, UpstreamOAuthError> {
        let callback = parse_loopback_callback_url(callback_url)?;
        self.finish_callback(callback).await
    }

    async fn finish_callback(
        self,
        callback: LoopbackCallback,
    ) -> Result<OAuthTokenSet, UpstreamOAuthError> {
        if callback.state.as_deref() != Some(self.state.secret()) {
            return Err(UpstreamOAuthError::StateMismatch);
        }
        if let Some(error) = callback.error {
            return Err(UpstreamOAuthError::CallbackError(redact_oauth_text(&error)));
        }
        let code = callback
            .code
            .ok_or(UpstreamOAuthError::CallbackMissingCode)?;
        exchange_authorization_code(&self.client, &code, self.code_verifier, &self.redirect_uri)
            .await
    }

    async fn wait_for_callback(&self) -> Result<LoopbackCallback, UpstreamOAuthError> {
        let started_at = Instant::now();
        loop {
            let remaining = self
                .timeout
                .checked_sub(started_at.elapsed())
                .ok_or(UpstreamOAuthError::CallbackTimeout)?;
            let callback = time::timeout(remaining, self.accept_loopback_callback())
                .await
                .map_err(|_| UpstreamOAuthError::CallbackTimeout)??;
            if let Some(callback) = callback {
                return Ok(callback);
            }
        }
    }

    async fn accept_loopback_callback(
        &self,
    ) -> Result<Option<LoopbackCallback>, UpstreamOAuthError> {
        let (mut stream, _) = self
            .listener
            .accept()
            .await
            .map_err(|err| io_error("accept OAuth loopback callback", err))?;
        let mut buffer = vec![0_u8; 8192];
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(|err| io_error("read OAuth loopback callback", err))?;
        let request = String::from_utf8_lossy(&buffer[..read]);
        let callback = parse_loopback_request(&request);
        let should_finish = callback
            .as_ref()
            .map(|item| {
                item.state.as_deref() == Some(self.state.secret())
                    && (item.error.is_some() || item.code.is_some())
            })
            .unwrap_or(false);
        let html = if callback
            .as_ref()
            .map(|item| {
                item.error.is_none()
                    && item.code.is_some()
                    && item.state.as_deref() == Some(self.state.secret())
            })
            .unwrap_or(false)
        {
            &self.success_html
        } else {
            &self.error_html
        };
        write_loopback_response(&mut stream, html).await?;
        match callback {
            Ok(callback) if should_finish => Ok(Some(callback)),
            Ok(_) | Err(UpstreamOAuthError::CallbackMissingCode) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

/// Starts a loopback OAuth authorization and returns a pending flow.
///
/// # Errors
/// Returns binding, URL-building, or scope validation errors.
///
/// # Security
/// Uses PKCE S256 and a random state value. The caller must display the
/// authorization URL only to the intended operator.
pub async fn start_loopback_authorization(
    client: OAuthClientConfig,
    scopes: Vec<String>,
    options: LoopbackOAuthOptions,
) -> Result<PendingLoopbackAuthorization, UpstreamOAuthError> {
    if scopes.is_empty() {
        return Err(UpstreamOAuthError::EmptyScopes);
    }
    if !options.bind_addr.is_loopback() {
        return Err(UpstreamOAuthError::NonLoopbackBindAddress);
    }
    let bind = SocketAddr::new(options.bind_addr, options.port.unwrap_or(0));
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|err| io_error("bind OAuth loopback listener", err))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| io_error("read OAuth loopback listener address", err))?;
    let redirect_uri = format_loopback_redirect_uri(local_addr, &options.callback_path);
    validate_client_redirect_uri(&client, &redirect_uri)?;
    let oauth_client = oauth2_client(&client, Some(&redirect_uri))?;
    let (code_challenge, code_verifier) = PkceCodeChallenge::new_random_sha256();
    let mut authorization_request = oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes.iter().cloned().map(Scope::new))
        .set_pkce_challenge(code_challenge);
    for (key, value) in &options.extra_authorization_params {
        authorization_request = authorization_request.add_extra_param(key.as_str(), value.as_str());
    }
    let (authorization_url, state) = authorization_request.url();

    Ok(PendingLoopbackAuthorization {
        listener,
        client,
        scopes,
        state,
        code_verifier,
        redirect_uri,
        authorization_url: authorization_url.to_string(),
        timeout: options.timeout,
        browser: options.browser,
        success_html: options.success_html,
        error_html: options.error_html,
    })
}

fn validate_client_redirect_uri(
    client: &OAuthClientConfig,
    redirect_uri: &str,
) -> Result<(), UpstreamOAuthError> {
    if client.kind != Some(GoogleOAuthClientKind::Web) {
        return Ok(());
    }
    if client
        .redirect_uris
        .iter()
        .any(|registered| google_web_redirect_uri_matches(registered, redirect_uri))
    {
        Ok(())
    } else {
        Err(UpstreamOAuthError::RedirectUriNotRegistered(
            redirect_uri.to_string(),
        ))
    }
}

fn google_web_redirect_uri_matches(registered: &str, runtime: &str) -> bool {
    if registered == runtime {
        return true;
    }
    let (Ok(registered_url), Ok(runtime_url)) = (Url::parse(registered), Url::parse(runtime))
    else {
        return false;
    };
    registered_url.scheme() == "http"
        && runtime_url.scheme() == "http"
        && registered_url.port().is_none()
        && runtime_url.port().is_some()
        && loopback_hosts_match(&registered_url, &runtime_url)
        && url_path_or_slash(&registered_url) == url_path_or_slash(&runtime_url)
        && registered_url.query() == runtime_url.query()
}

fn loopback_hosts_match(registered_url: &Url, runtime_url: &Url) -> bool {
    let (Some(registered_host), Some(runtime_host)) =
        (registered_url.host_str(), runtime_url.host_str())
    else {
        return false;
    };
    if registered_host.eq_ignore_ascii_case(runtime_host) {
        return url_host_is_loopback(registered_url) && url_host_is_loopback(runtime_url);
    }
    canonical_loopback_host_alias(registered_host) && canonical_loopback_host_alias(runtime_host)
}

fn canonical_loopback_host_alias(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match normalized_ip_host(host).parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip == Ipv4Addr::LOCALHOST,
        Ok(IpAddr::V6(ip)) => ip == Ipv6Addr::LOCALHOST,
        Err(_) => false,
    }
}

fn url_path_or_slash(url: &Url) -> &str {
    let path = url.path();
    if path.is_empty() {
        "/"
    } else {
        path
    }
}

fn normalize_callback_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn format_loopback_redirect_uri(local_addr: SocketAddr, callback_path: &str) -> String {
    let loopback_scheme = "http://"; // DevSkim: ignore DS137138 OAuth loopback redirect URI
    format!(
        "{loopback_scheme}{}{}",
        local_addr,
        normalize_callback_path(callback_path)
    )
}

fn launch_browser(mode: &BrowserLaunchMode, url: &str) -> Result<bool, UpstreamOAuthError> {
    match mode {
        BrowserLaunchMode::Disabled => Ok(false),
        BrowserLaunchMode::BestEffortSystem => Ok(spawn_system_browser(url).is_ok()),
        BrowserLaunchMode::RequiredSystem => spawn_system_browser(url).map(|()| true),
        BrowserLaunchMode::Command { program, args } => {
            if program.trim().is_empty() {
                return Err(UpstreamOAuthError::BrowserLaunch(
                    "browser command is empty".to_string(),
                ));
            }
            let mut command = Command::new(program);
            let mut passed_url = false;
            for arg in args {
                if arg.contains("{url}") {
                    passed_url = true;
                    command.arg(arg.replace("{url}", url));
                } else {
                    command.arg(arg);
                }
            }
            if !passed_url {
                command.arg(url);
            }
            command
                .spawn()
                .map(|_| true)
                .map_err(|err| UpstreamOAuthError::BrowserLaunch(err.to_string()))
        }
    }
}

fn spawn_system_browser(url: &str) -> Result<(), UpstreamOAuthError> {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("open");
        command.arg(url);
        command
    };

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("rundll32");
        command.arg("url.dll,FileProtocolHandler").arg(url);
        command
    };

    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    };

    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = url;
        return Err(UpstreamOAuthError::BrowserLaunch(
            "system browser launch is unsupported on this platform".to_string(),
        ));
    }

    #[cfg(any(unix, target_os = "windows"))]
    command
        .spawn()
        .map(|_| ())
        .map_err(|err| UpstreamOAuthError::BrowserLaunch(err.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoopbackCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn parse_loopback_request(request: &str) -> Result<LoopbackCallback, UpstreamOAuthError> {
    let request_line = request
        .lines()
        .next()
        .ok_or(UpstreamOAuthError::CallbackMissingCode)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    if method != "GET" || target.is_empty() {
        return Err(UpstreamOAuthError::CallbackMissingCode);
    }
    let loopback_url = format!("http://127.0.0.1{target}"); // DevSkim: ignore DS137138 loopback callback parser
    let url = Url::parse(&loopback_url).map_err(|_| UpstreamOAuthError::InvalidUrl {
        field: "loopback_callback",
        value: target.to_string(),
    })?;
    let mut callback = LoopbackCallback {
        code: None,
        state: None,
        error: None,
    };
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => callback.code = Some(value.into_owned()),
            "state" => callback.state = Some(value.into_owned()),
            "error" => callback.error = Some(value.into_owned()),
            _ => {}
        }
    }
    Ok(callback)
}

fn parse_loopback_callback_url(raw: &str) -> Result<LoopbackCallback, UpstreamOAuthError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(UpstreamOAuthError::CallbackMissingCode);
    }
    let url = Url::parse(trimmed).map_err(|_| UpstreamOAuthError::InvalidUrl {
        field: "loopback_callback",
        value: "<redacted>".to_string(),
    })?;
    if url.scheme() != "http" || !url_host_is_loopback(&url) {
        return Err(UpstreamOAuthError::InvalidUrl {
            field: "loopback_callback",
            value: "<redacted>".to_string(),
        });
    }
    let mut callback = LoopbackCallback {
        code: None,
        state: None,
        error: None,
    };
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => callback.code = Some(value.into_owned()),
            "state" => callback.state = Some(value.into_owned()),
            "error" => callback.error = Some(value.into_owned()),
            _ => {}
        }
    }
    Ok(callback)
}

async fn write_loopback_response(
    stream: &mut tokio::net::TcpStream,
    body: &str,
) -> Result<(), UpstreamOAuthError> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|err| io_error("write OAuth loopback response", err))
}

/// Builds a conventional local token-cache path.
///
/// # Security
/// This helper only computes a path. Callers must still use
/// `RefreshTokenFileStore` so platform cache protections are enforced.
pub fn local_config_token_cache_path(app_name: &str, file_name: &str) -> Option<PathBuf> {
    let safe_app = safe_config_path_part(app_name)?;
    let safe_file = safe_config_path_part(file_name)?;
    local_config_base_path().map(|base| base.join(safe_app).join(safe_file))
}

fn safe_config_path_part(value: &str) -> Option<&str> {
    let trimmed = value.trim().trim_matches('/').trim_matches('\\');
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
    {
        None
    } else {
        Some(trimmed)
    }
}

#[cfg(target_os = "windows")]
fn local_config_base_path() -> Option<PathBuf> {
    std::env::var("LOCALAPPDATA")
        .or_else(|_| std::env::var("APPDATA"))
        .ok()
        .filter(|base| !base.trim().is_empty())
        .map(PathBuf::from)
}

#[cfg(target_os = "macos")]
fn local_config_base_path() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .filter(|home| !home.trim().is_empty())
        .map(|home| {
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
        })
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn local_config_base_path() -> Option<PathBuf> {
    if let Ok(base) = std::env::var("XDG_CONFIG_HOME") {
        if !base.trim().is_empty() {
            return Some(PathBuf::from(base));
        }
    }
    std::env::var("HOME")
        .ok()
        .filter(|home| !home.trim().is_empty())
        .map(|home| PathBuf::from(home).join(".config"))
}

/// Returns whether all requested scopes were granted.
///
/// A missing `granted_scope` is treated as an unchanged grant, matching OAuth
/// token responses that omit `scope` when the granted scopes equal the request.
///
/// # Security
/// Scope strings are not secret-bearing, but callers should still avoid
/// over-requesting scopes.
pub fn scopes_satisfied(requested: &[String], granted_scope: Option<&str>) -> bool {
    let Some(granted_scope) = granted_scope else {
        return true;
    };
    let granted = granted_scope
        .split_whitespace()
        .collect::<std::collections::BTreeSet<_>>();
    requested
        .iter()
        .map(String::as_str)
        .all(|scope| granted.contains(scope))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener as StdTcpListener;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn parses_google_installed_client_and_redacts_secret() {
        let json = br#"{
            "installed": {
                "client_id": "client-id.apps.googleusercontent.com",
                "client_secret": "client-secret",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://127.0.0.1"]
            }
        }"#;

        let config = google_oauth_client_from_slice(json).expect("parse client");

        assert_eq!(config.client_id(), "client-id.apps.googleusercontent.com");
        assert!(config.client_secret_present());
        assert_eq!(config.kind(), Some(GoogleOAuthClientKind::Installed));
        assert!(!format!("{config:?}").contains("client-secret"));
    }

    #[test]
    fn parses_google_authorized_user_adc_and_redacts_secrets() {
        let json = br#"{
            "type": "authorized_user",
            "client_id": "client-id.apps.googleusercontent.com",
            "client_secret": "client-secret",
            "refresh_token": "refresh-secret",
            "quota_project_id": " quota-project ",
            "token_uri": "https://accounts.google.com/o/oauth2/token"
        }"#;

        let adc = google_authorized_user_adc_from_slice(
            json,
            vec!["https://www.googleapis.com/auth/example".to_string()],
        )
        .expect("parse adc");

        assert_eq!(adc.client_id(), "client-id.apps.googleusercontent.com");
        assert_eq!(adc.quota_project_id(), Some("quota-project"));
        assert_eq!(
            adc.refresh_config().client().token_endpoint(),
            "https://accounts.google.com/o/oauth2/token"
        );
        assert_eq!(
            adc.refresh_config().scopes(),
            &["https://www.googleapis.com/auth/example".to_string()]
        );
        let debug = format!("{adc:?}");
        assert!(!debug.contains("client-secret"));
        assert!(!debug.contains("refresh-secret"));
    }

    #[test]
    fn saves_google_authorized_user_adc_with_quota_project() {
        let temp = unique_temp_dir("google-adc-save");
        let path = temp.join("app").join("application_default_credentials.json");
        let client = google_oauth_client_from_slice(
            br#"{
                "installed": {
                    "client_id": "client-id.apps.googleusercontent.com",
                    "client_secret": "client-secret",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": ["http://127.0.0.1"]
                }
            }"#,
        )
        .expect("client");
        let token_set = OAuthTokenSet {
            access_token: Some(SecretString::new("access-secret")),
            refresh_token: Some(SecretString::new("refresh-secret")),
            expires_in: Some(3600),
            scope: Some("scope-a".to_string()),
            token_type: Some("Bearer".to_string()),
            refresh_token_expires_in: None,
        };

        save_google_authorized_user_adc(&path, &client, token_set, Some(" quota-project "))
            .expect("save adc");
        let parsed = google_authorized_user_adc_from_file(&path, vec!["scope-a".to_string()])
            .expect("parse saved adc");

        assert_eq!(parsed.client_id(), "client-id.apps.googleusercontent.com");
        assert_eq!(parsed.quota_project_id(), Some("quota-project"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn save_google_authorized_user_adc_requires_refresh_token() {
        let temp = unique_temp_dir("google-adc-missing-refresh");
        let path = temp.join("application_default_credentials.json");
        let client = google_oauth_client_from_slice(
            br#"{
                "installed": {
                    "client_id": "client-id.apps.googleusercontent.com",
                    "client_secret": "client-secret",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }
            }"#,
        )
        .expect("client");
        let token_set = OAuthTokenSet {
            access_token: Some(SecretString::new("access-secret")),
            refresh_token: None,
            expires_in: Some(3600),
            scope: Some("scope-a".to_string()),
            token_type: Some("Bearer".to_string()),
            refresh_token_expires_in: None,
        };

        let err = save_google_authorized_user_adc(&path, &client, token_set, None)
            .expect_err("missing refresh token");

        assert!(matches!(err, UpstreamOAuthError::MissingRefreshToken));
    }

    #[test]
    fn rejects_non_authorized_user_adc_credentials() {
        let json = br#"{
            "type": "service_account",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "refresh_token": "refresh-secret"
        }"#;

        let err = google_authorized_user_adc_from_slice(json, vec!["scope-a".to_string()])
            .expect_err("reject service account adc");

        assert!(matches!(
            err,
            UpstreamOAuthError::UnsupportedGoogleAdcCredentialType
        ));
    }

    #[test]
    fn rejects_google_adc_credentials_without_type() {
        let json = br#"{
            "client_id": "client-id",
            "client_secret": "client-secret",
            "refresh_token": "refresh-secret"
        }"#;

        let err = google_authorized_user_adc_from_slice(json, vec!["scope-a".to_string()])
            .expect_err("reject missing adc type");

        assert!(matches!(
            err,
            UpstreamOAuthError::UnsupportedGoogleAdcCredentialType
        ));
    }

    #[test]
    fn rejects_non_google_token_endpoint() {
        let json = br#"{
            "installed": {
                "client_id": "client-id",
                "client_secret": "client-secret",
                "token_uri": "https://example.com/token"
            }
        }"#;

        let err = google_oauth_client_from_slice(json).expect_err("reject endpoint");

        assert!(matches!(
            err,
            UpstreamOAuthError::DisallowedGoogleTokenEndpoint
        ));
    }

    #[test]
    fn generic_client_requires_https_by_default() {
        let err = OAuthClientConfig::new(
            "client-id",
            None,
            "https://example.com/auth",
            "http://127.0.0.1/token", // DevSkim: ignore DS137138 loopback test fixture
        )
        .expect_err("plain http endpoint");

        assert!(matches!(
            err,
            UpstreamOAuthError::InsecureEndpoint {
                field: "token_endpoint"
            }
        ));

        OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            "https://example.com/auth",
            "http://127.0.0.1/token", // DevSkim: ignore DS137138 loopback test fixture
        )
        .expect("loopback emulator endpoint");
    }

    #[test]
    fn generic_client_rejects_non_loopback_http_even_when_insecure_loopback_enabled() {
        let err = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            "https://example.com/auth",
            "http://192.0.2.1/token", // DevSkim: ignore DS137138 rejected negative test fixture
        )
        .expect_err("off-host http endpoint");

        assert!(matches!(
            err,
            UpstreamOAuthError::InsecureEndpoint {
                field: "token_endpoint"
            }
        ));
    }

    #[test]
    fn token_set_debug_redacts_tokens() {
        let token_set = OAuthTokenSet {
            access_token: Some(SecretString::new("ya29.secret")),
            refresh_token: Some(SecretString::new("refresh-secret")),
            expires_in: Some(3600),
            scope: Some("scope".to_string()),
            token_type: Some("Bearer".to_string()),
            refresh_token_expires_in: None,
        };

        let rendered = format!("{token_set:?}");

        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("ya29.secret"));
        assert!(!rendered.contains("refresh-secret"));
    }

    #[test]
    fn token_store_round_trips_and_status_is_redacted() {
        let temp = unique_temp_dir("round-trip");
        let store = RefreshTokenFileStore::new(temp.join("tokens.json"));
        let token = StoredRefreshToken {
            provider: "google".to_string(),
            client_id: "client-id".to_string(),
            refresh_token: SecretString::new("refresh-secret"),
            scopes: vec!["scope-a".to_string()],
            token_type: Some("Bearer".to_string()),
            refresh_token_expires_at_unix_seconds: Some(123),
        };

        store.save(&token).expect("save token");
        let loaded = store.load().expect("load token").expect("token present");
        let status = store.status().expect("status");

        assert_eq!(loaded.refresh_token.expose_secret(), "refresh-secret");
        assert!(status.refresh_token_present);
        assert_eq!(status.client_id.as_deref(), Some("client-id"));
        assert!(!format!("{status:?}").contains("refresh-secret"));
    }

    #[cfg(unix)]
    #[test]
    fn token_store_does_not_chmod_existing_parent_directory() {
        use std::os::unix::fs::PermissionsExt;
        let temp = unique_temp_dir("existing-parent-mode");
        let parent = temp.join("existing");
        fs::create_dir_all(&parent).expect("create existing parent");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).expect("chmod parent");
        let store = RefreshTokenFileStore::new(parent.join("tokens.json"));
        let token = StoredRefreshToken {
            provider: "google".to_string(),
            client_id: "client-id".to_string(),
            refresh_token: SecretString::new("refresh-secret"),
            scopes: vec!["scope-a".to_string()],
            token_type: Some("Bearer".to_string()),
            refresh_token_expires_at_unix_seconds: None,
        };

        store.save(&token).expect("save token");
        let mode = fs::symlink_metadata(&parent)
            .expect("stat parent")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o755);
    }

    #[test]
    fn token_store_rejects_empty_refresh_token_on_save() {
        let temp = unique_temp_dir("empty-token-save");
        let store = RefreshTokenFileStore::new(temp.join("tokens.json"));
        let token = StoredRefreshToken {
            provider: "google".to_string(),
            client_id: "client-id".to_string(),
            refresh_token: SecretString::new(" "),
            scopes: vec!["scope-a".to_string()],
            token_type: Some("Bearer".to_string()),
            refresh_token_expires_at_unix_seconds: None,
        };

        let err = store.save(&token).expect_err("empty refresh token");

        assert!(matches!(err, UpstreamOAuthError::MissingRefreshToken));
    }

    #[test]
    fn token_store_rejects_empty_refresh_token_on_load() {
        let temp = unique_temp_dir("empty-token-load");
        let path = temp.join("tokens.json");
        fs::write(
            &path,
            r#"{"version":1,"provider":"google","client_id":"client","refresh_token":" ","scopes":["scope-a"],"token_type":"Bearer","refresh_token_expires_at_unix_seconds":null}"#,
        )
        .expect("write token cache");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        let store = RefreshTokenFileStore::new(path);

        let err = store.load().expect_err("empty refresh token");

        assert!(matches!(err, UpstreamOAuthError::MissingRefreshToken));
    }

    #[test]
    fn stored_google_token_uses_granted_scopes() {
        let client = OAuthClientConfig::new(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            GOOGLE_TOKEN_ENDPOINT,
        )
        .expect("client config");
        let token = OAuthTokenSet {
            access_token: Some(SecretString::new("access-secret")),
            refresh_token: Some(SecretString::new("refresh-secret")),
            expires_in: Some(3600),
            scope: Some("scope-a scope-b scope-extra".to_string()),
            token_type: Some("Bearer".to_string()),
            refresh_token_expires_in: None,
        };

        let stored = StoredRefreshToken::from_google_token_set(
            &client,
            vec!["scope-a".to_string(), "scope-b".to_string()],
            token,
        )
        .expect("stored token");

        assert_eq!(
            stored.scopes,
            vec![
                "scope-a".to_string(),
                "scope-b".to_string(),
                "scope-extra".to_string()
            ]
        );
    }

    #[test]
    fn stored_google_token_uses_requested_scopes_when_provider_omits_unchanged_scope() {
        let client = OAuthClientConfig::new(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            GOOGLE_TOKEN_ENDPOINT,
        )
        .expect("client config");
        let token = OAuthTokenSet {
            access_token: Some(SecretString::new("access-secret")),
            refresh_token: Some(SecretString::new("refresh-secret")),
            expires_in: Some(3600),
            scope: None,
            token_type: Some("Bearer".to_string()),
            refresh_token_expires_in: None,
        };

        let stored = StoredRefreshToken::from_google_token_set(
            &client,
            vec!["scope-a".to_string(), "scope-b".to_string()],
            token,
        )
        .expect("stored token");

        assert_eq!(
            stored.scopes,
            vec!["scope-a".to_string(), "scope-b".to_string()]
        );
    }

    #[test]
    fn stored_google_token_rejects_missing_requested_scopes() {
        let client = OAuthClientConfig::new(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            GOOGLE_TOKEN_ENDPOINT,
        )
        .expect("client config");
        let token = OAuthTokenSet {
            access_token: Some(SecretString::new("access-secret")),
            refresh_token: Some(SecretString::new("refresh-secret")),
            expires_in: Some(3600),
            scope: Some("scope-a".to_string()),
            token_type: Some("Bearer".to_string()),
            refresh_token_expires_in: None,
        };

        let err =
            StoredRefreshToken::from_google_token_set(&client, vec!["scope-b".to_string()], token)
                .expect_err("missing requested scope");

        assert!(matches!(
            err,
            UpstreamOAuthError::MissingRequestedScopes(scopes) if scopes == vec!["scope-b".to_string()]
        ));
    }

    #[test]
    fn stored_google_token_rejects_empty_refresh_token() {
        let client = OAuthClientConfig::new(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            GOOGLE_TOKEN_ENDPOINT,
        )
        .expect("client config");
        let token = OAuthTokenSet {
            access_token: Some(SecretString::new("access-secret")),
            refresh_token: Some(SecretString::new("   ")),
            expires_in: Some(3600),
            scope: Some("scope-a".to_string()),
            token_type: Some("Bearer".to_string()),
            refresh_token_expires_in: None,
        };

        let err =
            StoredRefreshToken::from_google_token_set(&client, vec!["scope-a".to_string()], token)
                .expect_err("empty refresh token");

        assert!(matches!(err, UpstreamOAuthError::MissingRefreshToken));
    }

    #[cfg(unix)]
    #[test]
    fn token_store_rejects_group_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let temp = unique_temp_dir("unsafe-permissions");
        let path = temp.join("tokens.json");
        fs::write(&path, "{}").expect("write token");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        let store = RefreshTokenFileStore::new(path);

        let err = store.load().expect_err("reject unsafe permissions");

        assert!(matches!(
            err,
            UpstreamOAuthError::UnsafeTokenFilePermissions
        ));
    }

    #[cfg(unix)]
    #[test]
    fn token_store_rejects_symlink_cache_file() {
        use std::os::unix::fs::symlink;
        let temp = unique_temp_dir("symlink-cache");
        let target = temp.join("target.json");
        let link = temp.join("tokens.json");
        fs::write(
            &target,
            r#"{"version":1,"provider":"google","client_id":"client","refresh_token":"refresh","scopes":[],"token_type":null,"refresh_token_expires_at_unix_seconds":null}"#,
        )
        .expect("write target");
        symlink(&target, &link).expect("symlink");
        let store = RefreshTokenFileStore::new(link);

        let err = store.load().expect_err("reject symlink");

        assert!(matches!(
            err,
            UpstreamOAuthError::UnsafeTokenFilePermissions
        ));
    }

    #[cfg(unix)]
    #[test]
    fn token_store_rejects_broken_symlink_cache_file_on_load() {
        use std::os::unix::fs::symlink;
        let temp = unique_temp_dir("broken-symlink-cache-load");
        let missing_target = temp.join("missing.json");
        let link = temp.join("tokens.json");
        symlink(&missing_target, &link).expect("symlink");
        let store = RefreshTokenFileStore::new(link);

        let err = store.load().expect_err("reject broken symlink");

        assert!(matches!(
            err,
            UpstreamOAuthError::UnsafeTokenFilePermissions
        ));
    }

    #[cfg(unix)]
    #[test]
    fn token_store_rejects_broken_symlink_cache_file_on_save() {
        use std::os::unix::fs::symlink;
        let temp = unique_temp_dir("broken-symlink-cache-save");
        let missing_target = temp.join("missing.json");
        let link = temp.join("tokens.json");
        symlink(&missing_target, &link).expect("symlink");
        let store = RefreshTokenFileStore::new(&link);
        let token = StoredRefreshToken {
            provider: "google".to_string(),
            client_id: "client-id".to_string(),
            refresh_token: SecretString::new("refresh-secret"),
            scopes: vec!["scope-a".to_string()],
            token_type: Some("Bearer".to_string()),
            refresh_token_expires_at_unix_seconds: None,
        };

        let err = store.save(&token).expect_err("reject broken symlink");

        assert!(matches!(
            err,
            UpstreamOAuthError::UnsafeTokenFilePermissions
        ));
        assert!(fs::symlink_metadata(&link)
            .expect("stat link")
            .file_type()
            .is_symlink());
        assert!(!missing_target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn token_store_rejects_symlink_parent_directory_on_load() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = unique_temp_dir("symlink-parent-load");
        let real_config = temp.join("real-config");
        let app_dir = real_config.join("app");
        let link = temp.join("config-link");
        let token_path = app_dir.join("tokens.json");
        fs::create_dir_all(&app_dir).expect("create app dir");
        fs::write(
            &token_path,
            r#"{"version":1,"provider":"google","client_id":"client","refresh_token":"refresh","scopes":[],"token_type":null,"refresh_token_expires_at_unix_seconds":null}"#,
        )
        .expect("write token");
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).expect("chmod");
        symlink(&real_config, &link).expect("symlink parent");
        let store = RefreshTokenFileStore::new(link.join("app").join("tokens.json"));

        let err = store.load().expect_err("reject symlink parent");

        assert!(matches!(
            err,
            UpstreamOAuthError::UnsafeTokenFilePermissions
        ));
    }

    #[cfg(unix)]
    #[test]
    fn token_store_rejects_symlink_parent_directory_on_save() {
        use std::os::unix::fs::symlink;
        let temp = unique_temp_dir("symlink-parent-save");
        let real_config = temp.join("real-config");
        let link = temp.join("config-link");
        fs::create_dir_all(&real_config).expect("create real config");
        symlink(&real_config, &link).expect("symlink parent");
        let store = RefreshTokenFileStore::new(link.join("app").join("tokens.json"));
        let token = StoredRefreshToken {
            provider: "google".to_string(),
            client_id: "client-id".to_string(),
            refresh_token: SecretString::new("refresh-secret"),
            scopes: vec!["scope-a".to_string()],
            token_type: Some("Bearer".to_string()),
            refresh_token_expires_at_unix_seconds: None,
        };

        let err = store.save(&token).expect_err("reject symlink parent");

        assert!(matches!(
            err,
            UpstreamOAuthError::UnsafeTokenFilePermissions
        ));
        assert!(!real_config.join("app").join("tokens.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn token_store_rejects_symlink_parent_directory_on_clear() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = unique_temp_dir("symlink-parent-clear");
        let real_config = temp.join("real-config");
        let app_dir = real_config.join("app");
        let link = temp.join("config-link");
        let token_path = app_dir.join("tokens.json");
        fs::create_dir_all(&app_dir).expect("create app dir");
        fs::write(&token_path, "{}").expect("write token");
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).expect("chmod");
        symlink(&real_config, &link).expect("symlink parent");
        let store = RefreshTokenFileStore::new(link.join("app").join("tokens.json"));

        let err = store.clear().expect_err("reject symlink parent");

        assert!(matches!(
            err,
            UpstreamOAuthError::UnsafeTokenFilePermissions
        ));
        assert!(token_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn token_store_rejects_symlink_cache_file_on_clear() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = unique_temp_dir("symlink-cache-clear");
        let target = temp.join("target.json");
        let link = temp.join("tokens.json");
        fs::write(&target, "{}").expect("write target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("chmod");
        symlink(&target, &link).expect("symlink");
        let store = RefreshTokenFileStore::new(&link);

        let err = store.clear().expect_err("reject symlink cache file");

        assert!(matches!(
            err,
            UpstreamOAuthError::UnsafeTokenFilePermissions
        ));
        assert!(fs::symlink_metadata(&link)
            .expect("stat link")
            .file_type()
            .is_symlink());
        assert!(target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn token_store_rejects_broken_symlink_cache_file_on_clear() {
        use std::os::unix::fs::symlink;
        let temp = unique_temp_dir("broken-symlink-cache-clear");
        let missing_target = temp.join("missing.json");
        let link = temp.join("tokens.json");
        symlink(&missing_target, &link).expect("symlink");
        let store = RefreshTokenFileStore::new(&link);

        let err = store.clear().expect_err("reject broken symlink cache file");

        assert!(matches!(
            err,
            UpstreamOAuthError::UnsafeTokenFilePermissions
        ));
        assert!(fs::symlink_metadata(&link)
            .expect("stat link")
            .file_type()
            .is_symlink());
        assert!(!missing_target.exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_provider_exchanges_and_caches_access_token() {
        let (endpoint, requests) = spawn_token_endpoint();
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let config = OAuthRefreshConfig::new(
            client,
            SecretString::new("refresh-secret"),
            vec!["scope-a".to_string()],
        )
        .expect("refresh config");
        let provider = RefreshTokenProvider::new(config).expect("provider");

        let first = provider.access_token().await.expect("first token");
        let second = provider.access_token().await.expect("cached token");

        assert_eq!(first.expose_secret(), "access-secret");
        assert_eq!(second.expose_secret(), "access-secret");
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_provider_uses_and_exposes_replacement_refresh_tokens() {
        let (endpoint, requests) = spawn_token_endpoint_sequence(vec![
            r#"{"access_token":"access-one","refresh_token":"refresh-rotated","expires_in":0,"token_type":"Bearer","scope":"scope-a scope-extra","refresh_token_expires_in":60}"#.to_string(),
            r#"{"access_token":"access-two","expires_in":3600,"token_type":"Bearer","scope":"scope-a"}"#.to_string(),
        ]);
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let config = OAuthRefreshConfig::new(
            client,
            SecretString::new("refresh-secret"),
            vec!["scope-a".to_string()],
        )
        .expect("refresh config");
        let provider = RefreshTokenProvider::new(config).expect("provider");

        let first = provider.access_token().await.expect("first token");
        let replacement = provider
            .take_replacement_refresh_token()
            .await
            .expect("replacement refresh token");
        let second = provider.access_token().await.expect("second token");
        let bodies = requests.lock().expect("requests");

        assert_eq!(first.expose_secret(), "access-one");
        assert_eq!(replacement.refresh_token.expose_secret(), "refresh-rotated");
        assert_eq!(
            replacement.scopes,
            vec!["scope-a".to_string(), "scope-extra".to_string()]
        );
        assert_eq!(replacement.token_type.as_deref(), Some("Bearer"));
        assert!(replacement.refresh_token_expires_at_unix_seconds.is_some());
        let stored = replacement.into_stored_token("google", "client-id");
        assert_eq!(stored.refresh_token.expose_secret(), "refresh-rotated");
        assert_eq!(stored.provider, "google");
        assert_eq!(stored.client_id, "client-id");
        assert_eq!(second.expose_secret(), "access-two");
        assert!(bodies[0].contains("refresh_token=refresh-secret"));
        assert!(bodies[1].contains("refresh_token=refresh-rotated"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_provider_rejects_narrowed_refresh_scopes() {
        let (endpoint, _) = spawn_token_endpoint_with_body(
            r#"{"access_token":"access-secret","expires_in":3600,"token_type":"Bearer","scope":"scope-a"}"#
                .to_string(),
            1,
        );
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let config = OAuthRefreshConfig::new(
            client,
            SecretString::new("refresh-secret"),
            vec!["scope-a".to_string(), "scope-b".to_string()],
        )
        .expect("refresh config");
        let provider = RefreshTokenProvider::new(config).expect("provider");

        let err = provider.access_token().await.expect_err("narrowed scope");

        assert!(matches!(
            err,
            UpstreamOAuthError::MissingRequestedScopes(scopes)
                if scopes == vec!["scope-b".to_string()]
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_provider_rejects_empty_access_token() {
        let (endpoint, _) = spawn_token_endpoint_with_body(
            r#"{"access_token":"","expires_in":3600,"token_type":"Bearer","scope":"scope-a"}"#
                .to_string(),
            1,
        );
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let config = OAuthRefreshConfig::new(
            client,
            SecretString::new("refresh-secret"),
            vec!["scope-a".to_string()],
        )
        .expect("refresh config");
        let provider = RefreshTokenProvider::new(config).expect("provider");

        let err = provider
            .access_token()
            .await
            .expect_err("empty access token");

        assert!(matches!(err, UpstreamOAuthError::MissingAccessToken));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_provider_ignores_empty_replacement_refresh_tokens() {
        let (endpoint, requests) = spawn_token_endpoint_sequence(vec![
            r#"{"access_token":"access-one","refresh_token":" ","expires_in":0,"token_type":"Bearer","scope":"scope-a"}"#.to_string(),
            r#"{"access_token":"access-two","expires_in":3600,"token_type":"Bearer","scope":"scope-a"}"#.to_string(),
        ]);
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let config = OAuthRefreshConfig::new(
            client,
            SecretString::new("refresh-secret"),
            vec!["scope-a".to_string()],
        )
        .expect("refresh config");
        let provider = RefreshTokenProvider::new(config).expect("provider");

        provider.access_token().await.expect("first token");
        let replacement = provider.take_replacement_refresh_token().await;
        provider.access_token().await.expect("second token");
        let bodies = requests.lock().expect("requests");

        assert!(replacement.is_none());
        assert!(bodies[0].contains("refresh_token=refresh-secret"));
        assert!(bodies[1].contains("refresh_token=refresh-secret"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_provider_can_own_http_client() {
        let (endpoint, _) = spawn_token_endpoint();
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let config = OAuthRefreshConfig::new(
            client,
            SecretString::new("refresh-secret"),
            vec!["scope-a".to_string()],
        )
        .expect("refresh config");
        let provider =
            RefreshTokenProvider::with_timeout(config, Duration::from_secs(5)).expect("provider");

        let token = provider.access_token().await.expect("token");

        assert_eq!(token.expose_secret(), "access-secret");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_provider_omits_scope_on_refresh_by_default() {
        let (endpoint, requests) = spawn_token_endpoint_sequence(vec![
            r#"{"access_token":"access-secret","expires_in":3600,"token_type":"Bearer"}"#
                .to_string(),
        ]);
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let config = OAuthRefreshConfig::new(
            client,
            SecretString::new("refresh-secret"),
            vec!["scope-a".to_string(), "scope-b".to_string()],
        )
        .expect("refresh config");
        let provider = RefreshTokenProvider::new(config).expect("provider");

        let token = provider.access_token().await.expect("token");
        let bodies = requests.lock().expect("requests");

        assert_eq!(token.expose_secret(), "access-secret");
        assert!(!bodies[0].contains("scope="));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_provider_can_explicitly_request_refresh_scopes() {
        let (endpoint, requests) = spawn_token_endpoint_sequence(vec![
            r#"{"access_token":"access-secret","expires_in":3600,"token_type":"Bearer","scope":"scope-a"}"#
                .to_string(),
        ]);
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let config = OAuthRefreshConfig::new(
            client,
            SecretString::new("refresh-secret"),
            vec!["scope-a".to_string(), "scope-b".to_string()],
        )
        .expect("refresh config")
        .with_refresh_request_scopes(vec!["scope-a".to_string()])
        .expect("refresh request scopes");
        let provider = RefreshTokenProvider::new(config).expect("provider");

        let token = provider.access_token().await.expect("token");
        let bodies = requests.lock().expect("requests");

        assert_eq!(token.expose_secret(), "access-secret");
        assert!(bodies[0].contains("scope=scope-a"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_provider_can_use_basic_client_auth() {
        let (endpoint, requests) = spawn_token_endpoint_sequence(vec![
            r#"{"access_token":"access-secret","expires_in":3600,"token_type":"Bearer","scope":"scope-a"}"#
                .to_string(),
        ]);
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            Some(SecretString::new("client-secret")),
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config")
        .with_token_auth_method(OAuthClientAuthMethod::Basic);
        let config = OAuthRefreshConfig::new(
            client,
            SecretString::new("refresh-secret"),
            vec!["scope-a".to_string()],
        )
        .expect("refresh config");
        let provider = RefreshTokenProvider::new(config).expect("provider");

        let token = provider.access_token().await.expect("token");
        let bodies = requests.lock().expect("requests");

        assert_eq!(token.expose_secret(), "access-secret");
        assert!(bodies[0]
            .to_ascii_lowercase()
            .contains("authorization: basic "));
        assert!(!bodies[0].contains("client_secret=client-secret"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_provider_does_not_follow_token_endpoint_redirects() {
        let (redirect_target, target_requests, target_thread) = spawn_redirect_target();
        let (endpoint, redirect_requests) = spawn_redirecting_token_endpoint(redirect_target);
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let config = OAuthRefreshConfig::new(
            client,
            SecretString::new("refresh-secret"),
            vec!["scope-a".to_string()],
        )
        .expect("refresh config");
        let provider = RefreshTokenProvider::new(config).expect("provider");

        let err = provider
            .access_token()
            .await
            .expect_err("redirect is not a token response");
        target_thread.join().expect("redirect target thread");

        assert!(matches!(err, UpstreamOAuthError::TokenExchange(_)));
        assert_eq!(
            redirect_requests.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(target_requests.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_provider_redacts_non_json_token_errors() {
        let (endpoint, _) = spawn_token_endpoint_with_response(
            "invalid client_secret=secret ya29.secret".to_string(),
            "400 Bad Request",
            1,
        );
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let config = OAuthRefreshConfig::new(
            client,
            SecretString::new("refresh-secret"),
            vec!["scope-a".to_string()],
        )
        .expect("refresh config");
        let provider = RefreshTokenProvider::new(config).expect("provider");

        let err = provider.access_token().await.expect_err("token error");

        let rendered = err.to_string();
        assert!(matches!(err, UpstreamOAuthError::TokenExchange(_)));
        assert!(rendered.contains("malformed JSON response"));
        assert!(!rendered.contains("client_secret"));
        assert!(!rendered.contains("ya29.secret"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_provider_redacts_json_token_errors() {
        let (endpoint, _) = spawn_token_endpoint_with_response(
            r#"{"error":"invalid_grant","error_description":"client_secret=secret client-secret refresh_token=refresh refresh-secret ya29.secret","error_uri":"https://example.test/error?client_secret=x"}"#.to_string(),
            "400 Bad Request",
            1,
        );
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            Some(SecretString::new("client-secret")),
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let config = OAuthRefreshConfig::new(
            client,
            SecretString::new("refresh-secret"),
            vec!["scope-a".to_string()],
        )
        .expect("refresh config");
        let provider = RefreshTokenProvider::new(config).expect("provider");

        let err = provider.access_token().await.expect_err("token error");
        let rendered = err.to_string();

        assert!(matches!(err, UpstreamOAuthError::TokenExchange(_)));
        assert!(rendered.contains("invalid_grant"));
        assert!(!rendered.contains("client_secret"));
        assert!(!rendered.contains("refresh_token"));
        assert!(!rendered.contains("client-secret"));
        assert!(!rendered.contains("refresh-secret"));
        assert!(!rendered.contains("ya29.secret"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("refresh"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_provider_handles_extreme_expires_in_without_panicking() {
        let body = format!(
            r#"{{"access_token":"access-secret","expires_in":{},"token_type":"Bearer","scope":"scope-a"}}"#,
            u64::MAX
        );
        let (endpoint, _) = spawn_token_endpoint_with_body(body, 1);
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let config = OAuthRefreshConfig::new(
            client,
            SecretString::new("refresh-secret"),
            vec!["scope-a".to_string()],
        )
        .expect("refresh config");
        let provider = RefreshTokenProvider::new(config).expect("provider");

        let token = provider.access_token().await.expect("token");

        assert_eq!(token.expose_secret(), "access-secret");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn loopback_authorization_builds_url_and_finishes() {
        let (endpoint, _) = spawn_token_endpoint();
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let pending = start_loopback_authorization(
            client,
            vec!["scope-a".to_string()],
            LoopbackOAuthOptions::default(),
        )
        .await
        .expect("start auth");
        let auth_url = Url::parse(pending.authorization_url()).expect("auth url");
        let state = auth_url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned())
            .expect("state");
        assert_eq!(
            auth_url
                .query_pairs()
                .find(|(key, _)| key == "code_challenge_method")
                .map(|(_, value)| value.into_owned())
                .as_deref(),
            Some("S256")
        );

        let redirect = pending.redirect_uri().to_string();
        let callback = thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(
                redirect
                    .strip_prefix("http://")
                    .and_then(|value| value.split('/').next())
                    .expect("host port"),
            )
            .expect("connect callback");
            let request = format!(
                "GET /oauth/callback?code=auth-code&state={state} HTTP/1.1\r\nHost: localhost\r\n\r\n"
            );
            stream.write_all(request.as_bytes()).expect("write request");
            let mut response = String::new();
            stream.read_to_string(&mut response).expect("read response");
            response
        });

        let token_set = pending.finish().await.expect("finish auth");
        let response = callback.join().expect("callback thread");

        assert_eq!(
            token_set
                .access_token
                .as_ref()
                .map(SecretString::expose_secret),
            Some("access-secret")
        );
        assert_eq!(
            token_set
                .refresh_token
                .as_ref()
                .map(SecretString::expose_secret),
            Some("refresh-secret")
        );
        assert!(response.contains("Authentication complete"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn loopback_authorization_finishes_with_pasted_callback_url() {
        let (endpoint, _) = spawn_token_endpoint();
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let pending = start_loopback_authorization(
            client,
            vec!["scope-a".to_string()],
            LoopbackOAuthOptions::default(),
        )
        .await
        .expect("start auth");
        let callback_url = format!(
            "{}?code=auth-code&state={}",
            pending.redirect_uri(),
            pending.state.secret()
        );

        let token_set = pending
            .finish_with_callback_url(&callback_url)
            .await
            .expect("finish pasted callback");

        assert_eq!(
            token_set
                .access_token
                .as_ref()
                .map(SecretString::expose_secret),
            Some("access-secret")
        );
        assert_eq!(
            token_set
                .refresh_token
                .as_ref()
                .map(SecretString::expose_secret),
            Some("refresh-secret")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pasted_loopback_callback_rejects_wrong_state() {
        let (endpoint, token_requests) = spawn_token_endpoint();
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let pending = start_loopback_authorization(
            client,
            vec!["scope-a".to_string()],
            LoopbackOAuthOptions::default(),
        )
        .await
        .expect("start auth");
        let callback_url = format!("{}?code=auth-code&state=wrong", pending.redirect_uri());

        let err = pending
            .finish_with_callback_url(&callback_url)
            .await
            .expect_err("wrong state rejected");

        assert!(matches!(err, UpstreamOAuthError::StateMismatch));
        assert_eq!(token_requests.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn loopback_callback_with_wrong_state_gets_error_page_and_waits_for_valid_callback() {
        let (endpoint, token_requests) = spawn_token_endpoint();
        let client = OAuthClientConfig::new_allow_insecure_loopback(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            endpoint,
        )
        .expect("client config");
        let pending = start_loopback_authorization(
            client,
            vec!["scope-a".to_string()],
            LoopbackOAuthOptions::default(),
        )
        .await
        .expect("start auth");
        let auth_url = Url::parse(pending.authorization_url()).expect("auth url");
        let state = auth_url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned())
            .expect("state");
        let redirect = pending.redirect_uri().to_string();
        let token_requests_for_callback = Arc::clone(&token_requests);
        let callback = thread::spawn(move || {
            let host = redirect
                .strip_prefix("http://")
                .and_then(|value| value.split('/').next())
                .expect("host port")
                .to_string();
            let mut stream =
                std::net::TcpStream::connect(&host).expect("connect wrong-state callback");
            stream
                .write_all(b"GET /oauth/callback?code=wrong-code&state=wrong HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .expect("write wrong-state request");
            let mut wrong_response = String::new();
            stream
                .read_to_string(&mut wrong_response)
                .expect("read wrong-state response");
            assert!(wrong_response.contains("Authentication failed"));
            assert!(!wrong_response.contains("Authentication complete"));
            assert_eq!(
                token_requests_for_callback.load(std::sync::atomic::Ordering::SeqCst),
                0
            );

            let mut stream = std::net::TcpStream::connect(&host).expect("connect valid callback");
            let request = format!(
                "GET /oauth/callback?code=auth-code&state={state} HTTP/1.1\r\nHost: localhost\r\n\r\n"
            );
            stream
                .write_all(request.as_bytes())
                .expect("write valid request");
            let mut response = String::new();
            stream.read_to_string(&mut response).expect("read response");
            response
        });

        let token_set = pending.finish().await.expect("finish auth");
        let response = callback.join().expect("callback thread");

        assert_eq!(
            token_set
                .access_token
                .as_ref()
                .map(SecretString::expose_secret),
            Some("access-secret")
        );
        assert!(response.contains("Authentication complete"));
        assert_eq!(token_requests.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn scopes_satisfied_requires_every_explicitly_granted_scope() {
        let requested = vec!["a".to_string(), "b".to_string()];

        assert!(scopes_satisfied(&requested, Some("a b c")));
        assert!(!scopes_satisfied(&requested, Some("a")));
        assert!(scopes_satisfied(&requested, None));
    }

    #[test]
    fn local_config_token_cache_path_rejects_path_traversal_parts() {
        assert_eq!(safe_config_path_part(" app "), Some("app"));
        assert_eq!(safe_config_path_part("../app"), None);
        assert_eq!(safe_config_path_part("nested/tokens.json"), None);
        assert_eq!(safe_config_path_part("..tokens.json"), None);
    }

    #[test]
    fn google_loopback_options_request_offline_and_reauth_consent() {
        let login = LoopbackOAuthOptions::google_login();
        let reauth = LoopbackOAuthOptions::google_reauth();

        assert!(login
            .extra_authorization_params
            .contains(&("access_type".to_string(), "offline".to_string())));
        assert!(reauth
            .extra_authorization_params
            .contains(&("access_type".to_string(), "offline".to_string())));
        assert!(reauth
            .extra_authorization_params
            .contains(&("prompt".to_string(), "consent".to_string())));
    }

    #[test]
    fn loopback_redirect_uri_brackets_ipv6_addresses() {
        let addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 8091);

        let redirect = format_loopback_redirect_uri(addr, "oauth/callback");

        assert_eq!(
            redirect,
            "http://[::1]:8091/oauth/callback" // DevSkim: ignore DS137138 loopback test fixture
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn loopback_authorization_rejects_non_loopback_bind_addr() {
        let client = OAuthClientConfig::new(
            "client-id",
            None,
            GOOGLE_AUTH_ENDPOINT,
            GOOGLE_TOKEN_ENDPOINT,
        )
        .expect("client config");
        let options = LoopbackOAuthOptions {
            bind_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            ..LoopbackOAuthOptions::default()
        };

        let err = match start_loopback_authorization(client, vec!["scope-a".to_string()], options)
            .await
        {
            Ok(_) => panic!("non-loopback bind unexpectedly succeeded"),
            Err(err) => err,
        };

        assert!(matches!(err, UpstreamOAuthError::NonLoopbackBindAddress));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn web_client_requires_registered_loopback_redirect_uri() {
        let json = br#"{
            "web": {
                "client_id": "client-id",
                "client_secret": "client-secret",
                "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://127.0.0.1:9999/oauth/callback"]
            }
        }"#;
        let client = google_oauth_client_from_slice(json).expect("web client");

        let err = match start_loopback_authorization(
            client,
            vec!["scope-a".to_string()],
            LoopbackOAuthOptions::default(),
        )
        .await
        {
            Ok(_) => panic!("unregistered redirect unexpectedly succeeded"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            UpstreamOAuthError::RedirectUriNotRegistered(uri)
                if uri.starts_with("http://127.0.0.1:")
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn web_client_accepts_google_loopback_redirect_registered_without_port() {
        let json = br#"{
            "web": {
                "client_id": "client-id",
                "client_secret": "client-secret",
                "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://127.0.0.1/oauth/callback"]
            }
        }"#;
        let client = google_oauth_client_from_slice(json).expect("web client");

        let pending = start_loopback_authorization(
            client,
            vec!["scope-a".to_string()],
            LoopbackOAuthOptions::default(),
        )
        .await
        .expect("registered loopback redirect");

        assert!(pending.redirect_uri().starts_with("http://127.0.0.1:"));
        assert!(pending.redirect_uri().ends_with("/oauth/callback"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn web_client_accepts_localhost_loopback_redirect_registered_without_port() {
        let json = br#"{
            "web": {
                "client_id": "client-id",
                "client_secret": "client-secret",
                "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://localhost/oauth/callback"]
            }
        }"#;
        let client = google_oauth_client_from_slice(json).expect("web client");

        let pending = start_loopback_authorization(
            client,
            vec!["scope-a".to_string()],
            LoopbackOAuthOptions::default(),
        )
        .await
        .expect("registered localhost loopback redirect");

        assert!(pending.redirect_uri().starts_with("http://127.0.0.1:"));
        assert!(pending.redirect_uri().ends_with("/oauth/callback"));
    }

    #[test]
    fn web_client_loopback_redirect_matcher_accepts_canonical_aliases() {
        assert!(google_web_redirect_uri_matches(
            "http://localhost/oauth/callback", // DevSkim: ignore DS137138 loopback test fixture
            "http://[::1]:49152/oauth/callback"  // DevSkim: ignore DS137138 loopback test fixture
        ));
        assert!(google_web_redirect_uri_matches(
            "http://[::1]/oauth/callback", // DevSkim: ignore DS137138 loopback test fixture
            "http://127.0.0.1:49152/oauth/callback" // DevSkim: ignore DS137138 loopback test fixture
        ));
        assert!(!google_web_redirect_uri_matches(
            "http://127.0.0.2/oauth/callback", // DevSkim: ignore DS137138 negative loopback test fixture
            "http://127.0.0.1:49152/oauth/callback" // DevSkim: ignore DS137138 loopback test fixture
        ));
        assert!(!google_web_redirect_uri_matches(
            "http://localhost/oauth/callback", // DevSkim: ignore DS137138 loopback test fixture
            "http://127.0.0.1:49152/other"     // DevSkim: ignore DS137138 loopback test fixture
        ));
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "mcp-toolkit-upstream-oauth-{label}-{}",
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod temp dir");
        }
        path
    }

    fn spawn_token_endpoint() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        spawn_token_endpoint_with_body(
            r#"{"access_token":"access-secret","refresh_token":"refresh-secret","expires_in":3600,"token_type":"Bearer","scope":"scope-a"}"#.to_string(),
            2,
        )
    }

    fn spawn_token_endpoint_with_body(
        body: String,
        max_requests: usize,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        spawn_token_endpoint_with_response(body, "200 OK", max_requests)
    }

    fn spawn_token_endpoint_with_response(
        body: String,
        status: &'static str,
        max_requests: usize,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind token endpoint");
        let addr = listener.local_addr().expect("token endpoint addr");
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let request_count = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming().take(max_requests) {
                let Ok(mut stream) = stream else {
                    continue;
                };
                request_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buffer = [0_u8; 4096];
                let _ = stream.read(&mut buffer);
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{addr}/token"), requests) // DevSkim: ignore DS137138 loopback test fixture
    }

    fn spawn_token_endpoint_sequence(
        bodies: Vec<String>,
    ) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind token endpoint");
        let addr = listener.local_addr().expect("token endpoint addr");
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let request_bodies = Arc::clone(&requests);
        thread::spawn(move || {
            for (index, stream) in listener.incoming().take(bodies.len()).enumerate() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let mut buffer = [0_u8; 4096];
                let read = stream.read(&mut buffer).unwrap_or(0);
                request_bodies
                    .lock()
                    .expect("request bodies")
                    .push(String::from_utf8_lossy(&buffer[..read]).to_string());
                let body = bodies.get(index).cloned().unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{addr}/token"), requests) // DevSkim: ignore DS137138 loopback test fixture
    }

    fn spawn_redirecting_token_endpoint(
        location: String,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind redirect endpoint");
        let addr = listener.local_addr().expect("redirect endpoint addr");
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let request_count = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming().take(1) {
                let Ok(mut stream) = stream else {
                    continue;
                };
                request_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buffer = [0_u8; 4096];
                let _ = stream.read(&mut buffer);
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{addr}/token"), requests) // DevSkim: ignore DS137138 loopback test fixture
    }

    fn spawn_redirect_target() -> (
        String,
        Arc<std::sync::atomic::AtomicUsize>,
        thread::JoinHandle<()>,
    ) {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind redirect target");
        listener
            .set_nonblocking(true)
            .expect("nonblocking redirect target");
        let addr = listener.local_addr().expect("redirect target addr");
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let request_count = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(250);
            while Instant::now() < deadline {
                let accept_result = listener.accept();
                match accept_result {
                    Ok((mut stream, _)) => {
                        request_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let mut buffer = [0_u8; 4096];
                        let _ = stream.read(&mut buffer);
                        let body = r#"{"access_token":"leaked","token_type":"Bearer"}"#;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes());
                        return;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                };
            }
        });
        (format!("http://{addr}/redirect-target"), requests, handle) // DevSkim: ignore DS137138 loopback test fixture
    }
}
