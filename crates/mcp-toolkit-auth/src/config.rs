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

use crate::AuthError;

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
    let metadata: OidcDiscovery = response
        .json()
        .await
        .map_err(|e| AuthError::new(format!("Discovery parse failed: {e}")))?;

    // ... basic validation logic omitted for brevity ...
    Ok(metadata)
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
    use super::{AuthConfig, AuthMode, AuthSecurityProfile};

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
}
