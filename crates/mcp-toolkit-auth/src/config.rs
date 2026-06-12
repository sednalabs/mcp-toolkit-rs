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

use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::providers::read_body_limited;
use crate::AuthError;

const OIDC_DISCOVERY_MAX_BYTES: usize = 1024 * 1024;

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

/// Context for an authentication request.
#[derive(Debug, Clone, Copy)]
pub struct AuthRequestContext {
    pub bearer_only: bool,
}

impl AuthRequestContext {
    pub fn bearer_only() -> Self {
        Self { bearer_only: true }
    }

    pub fn token_bound() -> Self {
        Self { bearer_only: false }
    }
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
                config.jti_enforce_bearer = true;
            }
            AuthSecurityProfile::L3Boundary => {
                config.mode = AuthMode::Introspection;
                config.strict_oauth = true;
                config.introspection_cache_ttl_s = 30.0;
                config.introspection_force = false;
                config.jti_ttl_s = 300.0;
                config.jti_cache_size = 5000;
                config.jti_enforce_bearer = true;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(rename = "client_id_metadata_document_supported")]
    pub client_id_metadata_document_supported: Option<bool>,
    #[serde(rename = "token_endpoint_auth_methods_supported")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(rename = "code_challenge_methods_supported")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// Performs OIDC discovery to retrieve authorization server metadata.
pub async fn discover_oidc_metadata(
    issuer_url: &str,
    client: Option<&Client>,
) -> Result<OidcDiscovery, AuthError> {
    let issuer = issuer_url.trim().trim_end_matches('/');
    if issuer.is_empty() {
        return Err(AuthError::new("OIDC issuer URL is empty"));
    }
    let well_known = format!("{issuer}/.well-known/openid-configuration");
    let http = client.cloned().unwrap_or_else(Client::new);
    let response = http
        .get(&well_known)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| AuthError::new(format!("Discovery fetch failed: {e}")))?;

    if !response.status().is_success() {
        return Err(AuthError::new(format!(
            "Discovery failed: status {}",
            response.status()
        )));
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
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AuthError::new(format!("Discovery metadata missing {field}")))
}

fn validate_metadata_url(field: &str, value: &str) -> Result<(), AuthError> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| AuthError::new(format!("Discovery metadata has invalid {field}")))?;
    if matches!(url.scheme(), "http" | "https") {
        return Ok(());
    }
    Err(AuthError::new(format!(
        "Discovery metadata has unsupported {field} scheme"
    )))
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
            jti_enforce_bearer: true,
            clock_skew_s: 30.0,
        }
    }
}

#[cfg(test)]
mod profile_tests {
    use super::{validate_oidc_metadata, AuthConfig, AuthMode, AuthSecurityProfile, OidcDiscovery};

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
        assert!(cfg.jti_enforce_bearer);
        assert_eq!(cfg.introspection_cache_ttl_s, 60.0);
    }

    #[test]
    fn l3_profile_defaults() {
        let cfg = AuthConfig::with_profile(AuthSecurityProfile::L3Boundary);
        assert!(matches!(cfg.mode, AuthMode::Introspection));
        assert!(cfg.strict_oauth);
        assert_eq!(cfg.jti_ttl_s, 300.0);
        assert_eq!(cfg.jti_cache_size, 5000);
        assert!(cfg.jti_enforce_bearer);
        assert_eq!(cfg.introspection_cache_ttl_s, 30.0);
    }

    #[test]
    fn default_config_enforces_bearer_jti_replay_guard() {
        let cfg = AuthConfig::default();
        assert_eq!(cfg.jti_ttl_s, 300.0);
        assert_eq!(cfg.jti_cache_size, 5000);
        assert!(cfg.jti_enforce_bearer);
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
}
