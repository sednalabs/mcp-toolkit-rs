//! # Auth Configuration
//!
//! Primitives for configuring MCP authentication and authorization policies.
//!
//! ## Ownership
//! This module owns the definitions for `AuthConfig`, `AuthMode`, and `AuthSecurityProfile`,
//! providing a structured schema for authentication settings.
//!
//! ## Non-ownership
//! This module does not manage secret retrieval or runtime application of auth policies;
//! it strictly defines the configuration data structures.
//!
//! ## Policy & Guarantees
//! * **Deterministic Profile Application**: Provides standardized security profiles
//!   (L1–L3) to enforce consistent auth hardening across services.
//! * **Policy Validation**: Offers helpers for loading and normalizing execution configurations
//!   from environments.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying validated environment/configuration settings to construct `AuthConfig`.
//! * Ensuring that secret values (e.g., client secrets, delegation secrets) are
//!   handled according to organizational security policies.
//!
//! ## References
//! * RFC 6749: OAuth 2.0 Authorization Framework.
//! * [OpenID Connect Core 1.0].

use std::time::{Duration, SystemTime};

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::providers::read_body_limited;
use crate::AuthError;
use mcp_toolkit_http::oauth::authorization_server_discovery_urls;

const OIDC_DISCOVERY_MAX_BYTES: usize = 1024 * 1024;
const DISCOVERY_MAX_ATTEMPTS: u32 = 3;
const DISCOVERY_MAX_RETRY_AFTER: Duration = Duration::from_secs(120);

/// Defines the authentication validation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Delegation,
    Jwks,
    Introspection,
}

/// Supported client authentication methods for introspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientAuthMethod {
    #[default]
    ClientSecretBasic,
    ClientSecretPost,
}

/// Configuration structure for authentication policies.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub mode: AuthMode,
    pub strict_oauth: bool,
    pub jwks_url: Option<String>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub required_scopes: Vec<String>,
    pub actor_claim: String,
    pub introspection_url: Option<String>,
    pub introspection_client_id: Option<String>,
    pub introspection_client_secret: Option<String>,
    pub introspection_auth_method: ClientAuthMethod,
    pub introspection_cache_ttl_s: f64,
    pub introspection_force: bool,
    pub delegation_secret: Option<String>,
    pub delegation_issuer: String,
    pub delegation_audience: String,
    pub jti_ttl_s: f64,
    pub jti_cache_size: i64,
    pub jti_enforce_bearer: bool,
    pub clock_skew_s: f64,
}

/// Standard auth hardening profiles for MCP services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSecurityProfile {
    L1ReadOnly,
    L2Strong,
    L3Boundary,
}

impl AuthSecurityProfile {
    fn apply(self, config: &mut AuthConfig) {
        match self {
            AuthSecurityProfile::L1ReadOnly => {
                config.mode = AuthMode::Jwks;
                config.strict_oauth = true;
                config.introspection_cache_ttl_s = 0.0;
                config.introspection_force = false;
                config.jti_ttl_s = 0.0;
                config.jti_cache_size = 0;
                config.jti_enforce_bearer = false;
            }
            AuthSecurityProfile::L2Strong => {
                config.mode = AuthMode::Jwks;
                config.strict_oauth = true;
                config.introspection_cache_ttl_s = 60.0;
                config.introspection_force = false;
                config.jti_ttl_s = 300.0;
                config.jti_cache_size = 5000;
                config.jti_enforce_bearer = false;
            }
            AuthSecurityProfile::L3Boundary => {
                config.mode = AuthMode::Introspection;
                config.strict_oauth = true;
                config.introspection_cache_ttl_s = 30.0;
                config.introspection_force = false;
                config.jti_ttl_s = 300.0;
                config.jti_cache_size = 5000;
                config.jti_enforce_bearer = false;
            }
        }
    }
}

impl AuthConfig {
    pub fn with_profile(profile: AuthSecurityProfile) -> Self {
        let mut config = Self::default();
        profile.apply(&mut config);
        config
    }

    pub fn apply_profile(&mut self, profile: AuthSecurityProfile) {
        profile.apply(self);
    }
}

/// OIDC metadata discovered from an authorization server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcDiscovery {
    #[serde(rename = "issuer")]
    pub issuer: Option<String>,
    #[serde(rename = "authorization_endpoint")]
    pub authorization_endpoint: Option<String>,
    #[serde(rename = "token_endpoint")]
    pub token_endpoint: Option<String>,
    #[serde(rename = "registration_endpoint")]
    pub registration_endpoint: Option<String>,
    #[serde(rename = "jwks_uri")]
    pub jwks_uri: String,
    #[serde(rename = "introspection_endpoint")]
    pub introspection_endpoint: Option<String>,
    #[serde(rename = "device_authorization_endpoint")]
    pub device_authorization_endpoint: Option<String>,
    #[serde(rename = "grant_types_supported")]
    pub grant_types_supported: Option<Vec<String>>,
    #[serde(rename = "response_types_supported")]
    pub response_types_supported: Option<Vec<String>>,
    #[serde(rename = "client_id_metadata_document_supported")]
    pub client_id_metadata_document_supported: Option<bool>,
    #[serde(rename = "token_endpoint_auth_methods_supported")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(rename = "code_challenge_methods_supported")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// Performs OIDC discovery at the metadata URLs derived from an issuer.
///
/// # Errors
/// Returns an error when the issuer is empty or invalid, every derived metadata
/// endpoint fails, or the discovered metadata does not satisfy the OIDC
/// identity and endpoint contract.
///
/// # Security
/// The discovered `issuer` must exactly match `issuer_url`. Metadata endpoints
/// must use HTTPS, except for loopback HTTP used by local development.
pub async fn discover_oidc_metadata(
    issuer_url: &str,
    client: Option<&Client>,
) -> Result<OidcDiscovery, AuthError> {
    let issuer = issuer_url.trim().trim_end_matches('/');
    if issuer.is_empty() {
        return Err(AuthError::new("OIDC issuer URL is empty"));
    }
    let discovery_urls = authorization_server_discovery_urls(issuer).map_err(|e| {
        AuthError::new(format!("Discovery issuer URL is invalid: {e}"))
            .with_reason("invalid_issuer_url")
            .with_status(400)
    })?;
    let http = client.cloned().unwrap_or_else(Client::new);

    let mut failures = Vec::new();
    for discovery_url in discovery_urls {
        match fetch_oidc_metadata(&http, issuer, &discovery_url).await {
            Ok(metadata) => return Ok(metadata),
            Err(err) => {
                if matches!(
                    &err,
                    AuthError::Generic {
                        reason: Some("discovery_unavailable"),
                        ..
                    }
                ) {
                    return Err(err);
                }
                failures.push(format!("{discovery_url}: {err}"));
            }
        }
    }

    let detail = if failures.is_empty() {
        "no discovery endpoints were derived".to_string()
    } else {
        failures.join("; ")
    };
    Err(AuthError::new(format!(
        "Discovery failed for all metadata endpoints: {detail}"
    )))
}

/// Fetches OIDC metadata through an explicit transport URL for a canonical issuer.
///
/// Use this when an authorization server has a public issuer but its metadata is
/// reached through a private backchannel during startup.
///
/// # Errors
/// Returns an error when the issuer or discovery URL is empty or invalid, the
/// transport request fails, or the discovered metadata does not satisfy the
/// canonical issuer and endpoint contract.
///
/// # Security
/// The transport URL must use HTTPS, except for loopback HTTP. It affects only
/// where metadata is fetched: the returned `issuer` must still exactly match
/// `issuer_url`, so a private route cannot redefine token identity.
pub async fn discover_oidc_metadata_from_url(
    issuer_url: &str,
    discovery_url: &str,
    client: Option<&Client>,
) -> Result<OidcDiscovery, AuthError> {
    let issuer = issuer_url.trim().trim_end_matches('/');
    if issuer.is_empty() {
        return Err(AuthError::new("OIDC issuer URL is empty"));
    }
    validate_metadata_url("issuer", issuer)?;

    let discovery_url = discovery_url.trim();
    if discovery_url.is_empty() {
        return Err(AuthError::new("OIDC discovery URL is empty"));
    }
    validate_metadata_url("discovery_url", discovery_url)?;

    let http = client.cloned().unwrap_or_else(Client::new);
    let metadata = fetch_oidc_metadata(&http, issuer, discovery_url).await;
    metadata
}

async fn fetch_oidc_metadata(
    http: &Client,
    issuer: &str,
    discovery_url: &str,
) -> Result<OidcDiscovery, AuthError> {
    let mut attempt = 0;
    let response = loop {
        attempt += 1;
        let result = http
            .get(discovery_url)
            .timeout(Duration::from_secs(5))
            .send()
            .await;
        match result {
            Ok(response) => {
                let status = response.status();
                let transient = status == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || status == reqwest::StatusCode::REQUEST_TIMEOUT
                    || matches!(status.as_u16(), 500 | 502 | 503 | 504);
                if !transient {
                    break response;
                }
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(parse_retry_after)
                    .unwrap_or(Duration::ZERO);
                if retry_after > DISCOVERY_MAX_RETRY_AFTER {
                    break response;
                }
                if attempt == DISCOVERY_MAX_ATTEMPTS {
                    // Keep a supervisor from retrying before the server's minimum.
                    tokio::time::sleep(retry_after).await;
                    break response;
                }
                tokio::time::sleep(discovery_wait(attempt, retry_after)).await;
            }
            Err(error) => {
                if attempt == DISCOVERY_MAX_ATTEMPTS || !(error.is_connect() || error.is_timeout())
                {
                    let failure = AuthError::new(format!("Discovery fetch failed: {error}"));
                    return Err(if error.is_connect() || error.is_timeout() {
                        failure
                            .with_reason("discovery_unavailable")
                            .with_status(503)
                    } else {
                        failure
                    });
                }
                tokio::time::sleep(discovery_retry_delay(attempt)).await;
            }
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let failure = AuthError::new(format!("Discovery failed: status {status}"));
        return Err(
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS
                || status == reqwest::StatusCode::REQUEST_TIMEOUT
                || matches!(status.as_u16(), 500 | 502 | 503 | 504)
            {
                failure
                    .with_reason("discovery_unavailable")
                    .with_status(503)
            } else {
                failure
            },
        );
    }
    if response.content_length().unwrap_or(0) > OIDC_DISCOVERY_MAX_BYTES as u64 {
        return Err(AuthError::new("Discovery response too large").with_status(502));
    }
    let body = read_body_limited(response, OIDC_DISCOVERY_MAX_BYTES, "OIDC discovery").await?;
    let metadata: OidcDiscovery = serde_json::from_slice(&body)
        .map_err(|e| AuthError::new(format!("Discovery parse failed: {e}")))?;

    validate_oidc_metadata(issuer, &metadata)?;
    Ok(metadata)
}

// Bound retries per endpoint and decorrelate service restarts without shared state.
fn discovery_retry_delay(attempt: u32) -> Duration {
    let base_ms = 250_u64 << (attempt.saturating_sub(1).min(2));
    let random = uuid::Uuid::new_v4().as_u128() as u64;
    Duration::from_millis(base_ms + random % (base_ms + 1))
}

fn discovery_wait(attempt: u32, retry_after: Duration) -> Duration {
    retry_after + discovery_retry_delay(attempt)
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let date = httpdate::parse_http_date(value).ok()?;
    Some(
        date.duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO),
    )
}

fn validate_oidc_metadata(
    requested_issuer: &str,
    metadata: &OidcDiscovery,
) -> Result<(), AuthError> {
    let discovered_issuer = required_metadata_field(metadata.issuer.as_deref(), "issuer")?;
    if discovered_issuer.trim_end_matches('/') != requested_issuer {
        return Err(AuthError::new("Discovery issuer mismatch").with_reason("issuer_mismatch"));
    }

    validate_metadata_url("issuer", discovered_issuer)?;
    validate_metadata_url(
        "authorization_endpoint",
        required_metadata_field(
            metadata.authorization_endpoint.as_deref(),
            "authorization_endpoint",
        )?,
    )?;
    validate_metadata_url(
        "token_endpoint",
        required_metadata_field(metadata.token_endpoint.as_deref(), "token_endpoint")?,
    )?;
    validate_metadata_url(
        "jwks_uri",
        required_metadata_field(Some(&metadata.jwks_uri), "jwks_uri")?,
    )?;

    Ok(())
}

fn required_metadata_field<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str, AuthError> {
    let value = value.map(str::trim).unwrap_or("");
    if value.is_empty() {
        return Err(AuthError::new(format!(
            "Discovery metadata missing {field}"
        )));
    }
    Ok(value)
}

fn validate_metadata_url(field: &str, value: &str) -> Result<(), AuthError> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| AuthError::new(format!("Discovery metadata has invalid {field}")))?;
    if url.scheme() == "https" || (url.scheme() == "http" && is_loopback_url(&url)) {
        return Ok(());
    }
    Err(AuthError::new(format!(
        "Discovery metadata has unsupported {field} scheme"
    )))
}

fn is_loopback_url(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|addr| addr.is_loopback())
            .unwrap_or(false)
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Jwks,
            strict_oauth: true,
            jwks_url: None,
            issuer: None,
            audience: None,
            required_scopes: Vec::new(),
            actor_claim: "sub".to_string(),
            introspection_url: None,
            introspection_client_id: None,
            introspection_client_secret: None,
            introspection_auth_method: ClientAuthMethod::ClientSecretBasic,
            introspection_cache_ttl_s: 0.0,
            introspection_force: false,
            delegation_secret: None,
            delegation_issuer: "mcp-toolkit".to_string(),
            delegation_audience: "mcp-toolkit".to_string(),
            jti_ttl_s: 300.0,
            jti_cache_size: 5000,
            jti_enforce_bearer: false,
            clock_skew_s: 30.0,
        }
    }
}

#[cfg(test)]
mod profile_tests {
    use std::sync::Arc;

    use axum::{
        extract::{Request, State},
        response::{IntoResponse, Response},
        routing::any,
        Json, Router,
    };
    use http::StatusCode;
    use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};

    use super::{
        discover_oidc_metadata, discover_oidc_metadata_from_url, validate_oidc_metadata,
        AuthConfig, AuthMode, AuthSecurityProfile, OidcDiscovery,
    };

    #[test]
    fn l1_profile_defaults() {
        let cfg = AuthConfig::with_profile(AuthSecurityProfile::L1ReadOnly);
        assert!(matches!(cfg.mode, AuthMode::Jwks));
        assert!(cfg.strict_oauth);
        assert_eq!(cfg.jti_ttl_s, 0.0);
        assert_eq!(cfg.jti_cache_size, 0);
        assert!(!cfg.jti_enforce_bearer);
        assert_eq!(cfg.introspection_cache_ttl_s, 0.0);
    }

    #[test]
    fn l2_profile_defaults() {
        let cfg = AuthConfig::with_profile(AuthSecurityProfile::L2Strong);
        assert!(matches!(cfg.mode, AuthMode::Jwks));
        assert!(cfg.strict_oauth);
        assert_eq!(cfg.jti_ttl_s, 300.0);
        assert_eq!(cfg.jti_cache_size, 5000);
        assert!(!cfg.jti_enforce_bearer);
        assert_eq!(cfg.introspection_cache_ttl_s, 60.0);
    }

    #[test]
    fn l3_profile_defaults() {
        let cfg = AuthConfig::with_profile(AuthSecurityProfile::L3Boundary);
        assert!(matches!(cfg.mode, AuthMode::Introspection));
        assert!(cfg.strict_oauth);
        assert_eq!(cfg.jti_ttl_s, 300.0);
        assert_eq!(cfg.jti_cache_size, 5000);
        assert!(!cfg.jti_enforce_bearer);
        assert_eq!(cfg.introspection_cache_ttl_s, 30.0);
    }

    #[test]
    fn default_config_allows_reusable_bearer_tokens() {
        let cfg = AuthConfig::default();
        assert_eq!(cfg.jti_ttl_s, 300.0);
        assert_eq!(cfg.jti_cache_size, 5000);
        assert!(!cfg.jti_enforce_bearer);
    }

    #[test]
    fn oidc_metadata_validation_requires_matching_issuer_and_endpoints() {
        let metadata = OidcDiscovery {
            issuer: Some("https://issuer.example".to_string()),
            authorization_endpoint: Some("https://issuer.example/authorize".to_string()),
            token_endpoint: Some("https://issuer.example/token".to_string()),
            registration_endpoint: None,
            jwks_uri: "https://issuer.example/jwks".to_string(),
            introspection_endpoint: None,
            device_authorization_endpoint: None,
            grant_types_supported: None,
            response_types_supported: None,
            client_id_metadata_document_supported: None,
            token_endpoint_auth_methods_supported: None,
            code_challenge_methods_supported: None,
        };

        validate_oidc_metadata("https://issuer.example", &metadata)
            .expect("valid metadata should pass");

        let err = validate_oidc_metadata("https://other.example", &metadata)
            .expect_err("issuer mismatch should fail");
        assert!(err.to_string().contains("Discovery issuer mismatch"));

        let mut missing = metadata;
        missing.token_endpoint = Some("  ".to_string());
        let err = validate_oidc_metadata("https://issuer.example", &missing)
            .expect_err("missing token endpoint should fail");
        assert!(err
            .to_string()
            .contains("Discovery metadata missing token_endpoint"));
    }

    #[test]
    fn oidc_metadata_validation_rejects_non_loopback_http_endpoints() {
        let mut metadata = OidcDiscovery {
            issuer: Some("https://issuer.example".to_string()),
            authorization_endpoint: Some("https://issuer.example/authorize".to_string()),
            token_endpoint: Some("http://issuer.example/token".to_string()),
            registration_endpoint: None,
            jwks_uri: "https://issuer.example/jwks".to_string(),
            introspection_endpoint: None,
            device_authorization_endpoint: None,
            grant_types_supported: None,
            response_types_supported: None,
            client_id_metadata_document_supported: None,
            token_endpoint_auth_methods_supported: None,
            code_challenge_methods_supported: None,
        };

        let err = validate_oidc_metadata("https://issuer.example", &metadata)
            .expect_err("non-loopback http endpoint should fail");
        assert!(err
            .to_string()
            .contains("Discovery metadata has unsupported token_endpoint scheme"));

        metadata.issuer = Some("http://127.0.0.1:8080".to_string());
        metadata.authorization_endpoint = Some("http://127.0.0.1:8080/authorize".to_string());
        metadata.token_endpoint = Some("http://127.0.0.1:8080/token".to_string());
        metadata.jwks_uri = "http://127.0.0.1:8080/jwks".to_string();
        validate_oidc_metadata("http://127.0.0.1:8080", &metadata)
            .expect("loopback http metadata should pass");
    }

    #[tokio::test]
    async fn discover_oidc_metadata_tries_pathful_issuer_order_before_appended_fallback() {
        let fixture = DiscoveryFixture::spawn("/tenant/.well-known/openid-configuration").await;
        let metadata = discover_oidc_metadata(&fixture.issuer, None)
            .await
            .expect("discovery should fall back to appended OIDC metadata");

        assert_eq!(metadata.issuer.as_deref(), Some(fixture.issuer.as_str()));
        assert_eq!(
            fixture.observed_paths().await,
            vec![
                "/.well-known/oauth-authorization-server/tenant".to_string(),
                "/.well-known/openid-configuration/tenant".to_string(),
                "/tenant/.well-known/openid-configuration".to_string(),
            ]
        );
        fixture.shutdown();
    }

    #[tokio::test]
    async fn discover_oidc_metadata_accepts_path_inserted_authorization_metadata() {
        let fixture =
            DiscoveryFixture::spawn("/.well-known/oauth-authorization-server/tenant").await;
        let metadata = discover_oidc_metadata(&fixture.issuer, None)
            .await
            .expect("discovery should accept first path-inserted endpoint");

        assert_eq!(metadata.issuer.as_deref(), Some(fixture.issuer.as_str()));
        assert_eq!(
            fixture.observed_paths().await,
            vec!["/.well-known/oauth-authorization-server/tenant".to_string()]
        );
        fixture.shutdown();
    }

    #[tokio::test]
    async fn explicit_discovery_url_preserves_canonical_issuer_identity() {
        let canonical_issuer = "https://issuer.example/tenant";
        let fixture =
            DiscoveryFixture::spawn_for_issuer("/private/openid-configuration", canonical_issuer)
                .await;
        let discovery_url = fixture.url("/private/openid-configuration");

        let metadata = discover_oidc_metadata_from_url(canonical_issuer, &discovery_url, None)
            .await
            .expect("private transport should preserve public issuer identity");

        assert_eq!(
            metadata,
            OidcDiscovery {
                issuer: Some(canonical_issuer.to_string()),
                authorization_endpoint: Some(format!("{canonical_issuer}/authorize")),
                token_endpoint: Some(format!("{canonical_issuer}/token")),
                registration_endpoint: None,
                jwks_uri: format!("{canonical_issuer}/jwks"),
                introspection_endpoint: None,
                device_authorization_endpoint: None,
                grant_types_supported: None,
                response_types_supported: None,
                client_id_metadata_document_supported: None,
                token_endpoint_auth_methods_supported: None,
                code_challenge_methods_supported: None,
            }
        );
        assert_eq!(
            fixture.observed_paths().await,
            vec!["/private/openid-configuration".to_string()]
        );
        fixture.shutdown();
    }

    #[tokio::test]
    async fn explicit_discovery_url_rejects_issuer_substitution() {
        let fixture = DiscoveryFixture::spawn_for_issuer(
            "/private/openid-configuration",
            "https://unexpected.example/tenant",
        )
        .await;
        let discovery_url = fixture.url("/private/openid-configuration");

        let err =
            discover_oidc_metadata_from_url("https://issuer.example/tenant", &discovery_url, None)
                .await
                .expect_err("private transport must not redefine issuer identity");

        assert_eq!(
            err.to_string(),
            "Authentication failed: Discovery issuer mismatch"
        );
        fixture.shutdown();
    }

    #[tokio::test]
    async fn explicit_discovery_url_rejects_cleartext_remote_transport() {
        let err = discover_oidc_metadata_from_url(
            "https://issuer.example/tenant",
            "http://metadata.example/openid-configuration", // DevSkim: ignore DS137138 denial-path fixture
            None,
        )
        .await
        .expect_err("cleartext remote discovery must fail before fetching");

        assert_eq!(
            err.to_string(),
            "Authentication failed: Discovery metadata has unsupported discovery_url scheme"
        );
    }

    #[tokio::test]
    async fn explicit_discovery_retries_rate_limit_and_server_error_then_succeeds() {
        let (issuer, url, attempts, server) = retry_fixture(vec![429, 408, 200], false, "0").await;
        let metadata = discover_oidc_metadata_from_url(&issuer, &url, None)
            .await
            .expect("transient discovery failures should recover");
        assert_eq!(metadata.issuer.as_deref(), Some(issuer.as_str()));
        assert_eq!(*attempts.lock().await, 3);
        server.abort();

        let (issuer, url, attempts, server) = retry_fixture(vec![429, 200], false, "invalid").await;
        assert!(discover_oidc_metadata_from_url(&issuer, &url, None)
            .await
            .is_ok());
        assert_eq!(*attempts.lock().await, 2);
        server.abort();
    }

    #[tokio::test]
    async fn explicit_discovery_bounds_retries_and_does_not_retry_permanent_or_invalid_data() {
        for (statuses, invalid_issuer, retry_after, expected_attempts) in [
            (vec![503, 503, 503, 200], false, "0", 3),
            (vec![403, 200], false, "0", 1),
            (vec![429, 200], false, "121", 1),
            (vec![200], true, "0", 1),
        ] {
            let (issuer, url, attempts, server) =
                retry_fixture(statuses, invalid_issuer, retry_after).await;
            assert!(discover_oidc_metadata_from_url(&issuer, &url, None)
                .await
                .is_err());
            assert_eq!(*attempts.lock().await, expected_attempts);
            server.abort();
        }
    }

    #[tokio::test]
    async fn rate_limit_exhaustion_does_not_probe_other_metadata_paths() {
        let (issuer, _, attempts, server) =
            retry_fixture(vec![429, 429, 429, 200], false, "0").await;
        let error = discover_oidc_metadata(&issuer, None)
            .await
            .expect_err("rate limit must stop discovery");
        assert!(matches!(
            error,
            crate::AuthError::Generic {
                status_code: 503,
                reason: Some("discovery_unavailable"),
                ..
            }
        ));
        assert_eq!(*attempts.lock().await, 3);
        server.abort();
    }

    #[tokio::test]
    async fn final_rate_limit_waits_for_server_minimum_before_returning() {
        let (issuer, url, attempts, server) = retry_fixture(vec![429, 429, 429], false, "1").await;
        let started = std::time::Instant::now();
        assert!(discover_oidc_metadata_from_url(&issuer, &url, None)
            .await
            .is_err());
        assert_eq!(*attempts.lock().await, 3);
        assert!(started.elapsed() >= std::time::Duration::from_secs(3));
        server.abort();
    }

    #[test]
    fn retry_after_accepts_delta_and_http_date_and_bounds_waits() {
        assert_eq!(
            super::parse_retry_after("3"),
            Some(std::time::Duration::from_secs(3))
        );
        assert_eq!(
            super::parse_retry_after("Thu, 01 Jan 1970 00:00:00 GMT"),
            Some(std::time::Duration::ZERO)
        );
        assert!(super::parse_retry_after("nonsense").is_none());
        assert!(
            super::parse_retry_after("121").expect("valid delta")
                > super::DISCOVERY_MAX_RETRY_AFTER
        );
        for attempt in 1..=2 {
            let delay = super::discovery_retry_delay(attempt);
            let base = std::time::Duration::from_millis(250 << (attempt - 1));
            assert!(delay >= base && delay <= base * 2);
            let advertised = std::time::Duration::from_secs(3);
            assert!(super::discovery_wait(attempt, advertised) > advertised);
        }
    }

    async fn retry_fixture(
        statuses: Vec<u16>,
        invalid_issuer: bool,
        retry_after: &'static str,
    ) -> (String, String, Arc<Mutex<usize>>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixture");
        let issuer = format!("http://{}", listener.local_addr().expect("address")); // DevSkim: ignore DS137138 loopback test fixture
        let metadata_issuer = if invalid_issuer {
            "https://wrong.example".to_string()
        } else {
            issuer.clone()
        };
        let attempts = Arc::new(Mutex::new(0));
        let fixture_attempts = attempts.clone();
        let app = Router::new().route(
            "/{*path}",
            any(move || {
                let statuses = statuses.clone();
                let attempts = fixture_attempts.clone();
                let issuer = metadata_issuer.clone();
                async move {
                    let mut count = attempts.lock().await;
                    let status = statuses.get(*count).copied().unwrap_or(500);
                    *count += 1;
                    if status != 200 {
                        return (
                            StatusCode::from_u16(status).expect("status"),
                            [("retry-after", retry_after)],
                        )
                            .into_response();
                    }
                    Json(serde_json::json!({
                        "issuer": issuer,
                        "authorization_endpoint": format!("{issuer}/authorize"),
                        "token_endpoint": format!("{issuer}/token"),
                        "jwks_uri": format!("{issuer}/jwks")
                    }))
                    .into_response()
                }
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let url = format!("{issuer}/discovery");
        (issuer, url, attempts, server)
    }

    struct DiscoveryFixture {
        base_url: String,
        issuer: String,
        observed_paths: Arc<Mutex<Vec<String>>>,
        server: JoinHandle<()>,
    }

    impl DiscoveryFixture {
        async fn spawn(success_path: &'static str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind discovery fixture");
            let base_url = format!("http://{}", listener.local_addr().expect("local addr")); // DevSkim: ignore DS137138 loopback test fixture
            let issuer = format!("{base_url}/tenant");
            Self::spawn_with_listener(listener, base_url, issuer, success_path).await
        }

        async fn spawn_for_issuer(success_path: &'static str, issuer: &str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind discovery fixture");
            let base_url = format!("http://{}", listener.local_addr().expect("local addr")); // DevSkim: ignore DS137138 loopback test fixture
            Self::spawn_with_listener(listener, base_url, issuer.to_string(), success_path).await
        }

        async fn spawn_with_listener(
            listener: TcpListener,
            base_url: String,
            issuer: String,
            success_path: &'static str,
        ) -> Self {
            let observed_paths = Arc::new(Mutex::new(Vec::new()));
            let state = DiscoveryState {
                issuer: issuer.clone(),
                success_path,
                observed_paths: observed_paths.clone(),
            };
            let app = Router::new()
                .route("/{*path}", any(discovery_handler))
                .with_state(state);
            let server = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            Self {
                base_url,
                issuer,
                observed_paths,
                server,
            }
        }

        fn url(&self, path: &str) -> String {
            format!("{}{}", self.base_url, path)
        }

        async fn observed_paths(&self) -> Vec<String> {
            self.observed_paths.lock().await.clone()
        }

        fn shutdown(self) {
            self.server.abort();
        }
    }

    #[derive(Clone)]
    struct DiscoveryState {
        issuer: String,
        success_path: &'static str,
        observed_paths: Arc<Mutex<Vec<String>>>,
    }

    async fn discovery_handler(State(state): State<DiscoveryState>, req: Request) -> Response {
        let path = req.uri().path().to_string();
        state.observed_paths.lock().await.push(path.clone());
        if path != state.success_path {
            return StatusCode::NOT_FOUND.into_response();
        }

        Json(serde_json::json!({
            "issuer": state.issuer,
            "authorization_endpoint": format!("{}/authorize", state.issuer),
            "token_endpoint": format!("{}/token", state.issuer),
            "jwks_uri": format!("{}/jwks", state.issuer)
        }))
        .into_response()
    }
}
