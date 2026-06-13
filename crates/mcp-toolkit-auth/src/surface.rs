//! # Auth Surface (HTTP)
//!
//! Opinionated HTTP integration for MCP OAuth discovery and auth enforcement.
//!
//! ## Ownership
//! This module owns the HTTP-facing authentication interface, managing RFC-compliant
//! discovery metadata (RFC 8414/9728) and the `AuthSurfaceLayer` middleware
//! for enforcing access control.
//!
//! ## Non-ownership
//! This module does not manage transport-layer TLS or application-level authorization
//! decisions (e.g., tool-specific permissions).
//!
//! ## Policy & Guarantees
//! * **Discovery Metadata**: Publishes standard discovery paths for authorization
//!   servers and protected resources, derived from issuer configuration.
//! * **Auth Enforcement**: Guards protected MCP paths by validating bearer tokens
//!   before requests reach the inner service.
//! * **Insecure Scheme Mitigation**: Enforces HTTPS-by-default for metadata URLs to reduce
//!   spoofing risk, with an explicit opt-in for local development.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Configuring the `AuthSurfaceConfig` with a valid, canonical public base URL.
//! * Ensuring that reverse proxies are correctly configured to terminate TLS and
//!   forward appropriate headers (e.g., `X-Forwarded-Proto`).
//! * Explicitly opting into pass-through handling if requests outside configured
//!   protected paths should reach the inner service.
//!
//! ## References
//! * RFC 8414: OAuth 2.0 Authorization Server Metadata.
//! * RFC 9728: OAuth 2.0 Protected Resource Metadata.
//! * [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization.md)

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::body::Body;
use futures_util::future::BoxFuture;
use http::header::{CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE};
use http::{HeaderMap, Request, Response, StatusCode};
use serde::Serialize;
use thiserror::Error;
use tower::Layer;

use crate::challenge::{build_bearer_challenge, BearerChallenge};
use crate::{AuthContext, AuthError, Authenticator};
use mcp_toolkit_http::oauth::{
    authorization_server_well_known_paths, oidc_metadata_url, oidc_well_known_paths,
    protected_resource_well_known_paths, resource_metadata_default, resource_metadata_hint,
    resource_url_from_base, validate_absolute_url, AuthorizationServerMetadata, ResourceMetadata,
    OAUTH_AUTHZ_WELL_KNOWN_PATH, OIDC_WELL_KNOWN_PATH, PRM_WELL_KNOWN_PATH,
};

/// Policy for handling root discovery aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RootAliasPolicy {
    /// Enable aliases if only one issuer exists or if resource path is root.
    #[default]
    Automatic,
    /// Always enable root discovery aliases.
    Enabled,
    /// Disable root discovery aliases.
    Disabled,
}

/// Policy for requests that do not match a protected resource path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnmatchedRoutePolicy {
    /// Allow request to pass through to the inner service.
    PassThrough,
    /// Reject unmatched routes with 404.
    #[default]
    Deny,
}

/// Source for authorization server metadata.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuthorizationServerMetadataSource {
    Explicit(AuthorizationServerMetadata),
    OidcDiscovery(crate::OidcDiscovery),
}

/// Configuration entry for an issuer/resource pair.
#[derive(Debug, Clone)]
pub struct IssuerEntry {
    pub resource_path: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub introspection_endpoint: Option<String>,
    pub device_authorization_endpoint: Option<String>,
    pub grant_types_supported: Option<Vec<String>>,
    pub client_id_metadata_document_supported: Option<bool>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
    pub realm: String,
    pub scopes_supported: Vec<String>,
    pub allowed_client_ids: HashSet<String>,
    pub authenticator: Arc<Authenticator>,
    pub resource_url_override: Option<String>,
}

impl IssuerEntry {
    /// Builds entry from metadata source.
    pub fn from_metadata_source(
        resource_path: impl Into<String>,
        metadata_source: AuthorizationServerMetadataSource,
        realm: impl Into<String>,
        scopes_supported: Vec<String>,
        allowed_client_ids: HashSet<String>,
        authenticator: Arc<Authenticator>,
        resource_url_override: Option<String>,
    ) -> Result<Self, AuthSurfaceError> {
        let metadata = resolve_authorization_server_metadata(&metadata_source)?;
        Ok(Self {
            resource_path: resource_path.into(),
            issuer: metadata.issuer,
            authorization_endpoint: metadata.authorization_endpoint,
            token_endpoint: metadata.token_endpoint,
            registration_endpoint: metadata.registration_endpoint,
            jwks_uri: metadata.jwks_uri,
            introspection_endpoint: metadata.introspection_endpoint,
            device_authorization_endpoint: metadata.device_authorization_endpoint,
            grant_types_supported: metadata.grant_types_supported,
            client_id_metadata_document_supported: metadata.client_id_metadata_document_supported,
            token_endpoint_auth_methods_supported: metadata.token_endpoint_auth_methods_supported,
            code_challenge_methods_supported: metadata.code_challenge_methods_supported,
            realm: realm.into(),
            scopes_supported,
            allowed_client_ids,
            authenticator,
            resource_url_override,
        })
    }
}

/// Top-level configuration for the auth surface.
#[derive(Debug, Clone)]
pub struct AuthSurfaceConfig {
    /// Canonical base URL for metadata (e.g. https://mcp.example.com).
    pub public_base_url: String,
    /// Issuer entries keyed by resource path.
    pub entries: Vec<IssuerEntry>,
    /// Policy for serving root well-known aliases.
    pub root_alias_policy: RootAliasPolicy,
    /// Public paths that bypass auth enforcement.
    pub public_paths: HashSet<String>,
    /// Public path prefixes that bypass auth enforcement.
    pub public_prefixes: Vec<String>,
    /// Allow insecure http:// URLs for metadata endpoints (default false).
    pub allow_insecure_http: bool,
}

impl AuthSurfaceConfig {
    /// Build a single-issuer configuration (Option A operational default).
    pub fn single_issuer(public_base_url: impl Into<String>, entry: IssuerEntry) -> Self {
        Self {
            public_base_url: public_base_url.into(),
            entries: vec![entry],
            root_alias_policy: RootAliasPolicy::Automatic,
            public_paths: HashSet::new(),
            public_prefixes: Vec::new(),
            allow_insecure_http: false,
        }
    }

    /// Return true when any configured auth-surface URL uses insecure `http://`.
    pub fn contains_insecure_http_urls(&self) -> bool {
        url_uses_insecure_http(&self.public_base_url)
            || self.entries.iter().any(|entry| {
                url_uses_insecure_http(&entry.issuer)
                    || url_uses_insecure_http(&entry.authorization_endpoint)
                    || url_uses_insecure_http(&entry.token_endpoint)
                    || entry
                        .registration_endpoint
                        .as_deref()
                        .is_some_and(url_uses_insecure_http)
                    || entry
                        .jwks_uri
                        .as_deref()
                        .is_some_and(url_uses_insecure_http)
                    || entry
                        .introspection_endpoint
                        .as_deref()
                        .is_some_and(url_uses_insecure_http)
                    || entry
                        .resource_url_override
                        .as_deref()
                        .is_some_and(url_uses_insecure_http)
            })
    }

    /// Enable `allow_insecure_http` when any configured auth-surface URL uses
    /// `http://`.
    pub fn with_detected_allow_insecure_http(mut self) -> Self {
        self.allow_insecure_http = self.contains_insecure_http_urls();
        self
    }

    /// Build an [`AuthSurfaceLayer`] after auto-detecting whether insecure HTTP
    /// URLs must be allowed.
    pub fn into_layer_with_detected_allow_insecure_http(
        self,
    ) -> Result<AuthSurfaceLayer, AuthSurfaceError> {
        AuthSurfaceLayer::from_config(self.with_detected_allow_insecure_http())
    }
}

fn url_uses_insecure_http(value: &str) -> bool {
    value.trim().starts_with("http://")
}

/// Errors raised when constructing the auth surface registry.
#[derive(Error, Debug)]
pub enum AuthSurfaceError {
    #[error("auth surface requires at least one issuer entry")]
    EmptyRegistry,
    #[error("issuer entry has an empty field: {0}")]
    EmptyField(&'static str),
    #[error("invalid resource URL: {0}")]
    InvalidResourceUrl(String),
    #[error("invalid url for {field}: {value} ({reason})")]
    InvalidUrl {
        field: &'static str,
        value: String,
        reason: String,
    },
    #[error("duplicate resource path: {0}")]
    DuplicateResourcePath(String),
    #[error("duplicate well-known route: {0}")]
    DuplicateWellKnownRoute(String),
}

/// Build authorization-server metadata from OIDC discovery output.
pub fn authorization_server_metadata_from_oidc(
    oidc: &crate::OidcDiscovery,
) -> Result<AuthorizationServerMetadata, AuthSurfaceError> {
    let issuer = oidc
        .issuer
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or(AuthSurfaceError::EmptyField("issuer"))?;
    let authorization_endpoint = oidc
        .authorization_endpoint
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or(AuthSurfaceError::EmptyField("authorization_endpoint"))?;
    let token_endpoint = oidc
        .token_endpoint
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or(AuthSurfaceError::EmptyField("token_endpoint"))?;
    let metadata = AuthorizationServerMetadata {
        issuer: issuer.to_string(),
        authorization_endpoint: authorization_endpoint.to_string(),
        token_endpoint: token_endpoint.to_string(),
        registration_endpoint: oidc.registration_endpoint.clone(),
        jwks_uri: Some(oidc.jwks_uri.clone()),
        introspection_endpoint: oidc.introspection_endpoint.clone(),
        device_authorization_endpoint: oidc.device_authorization_endpoint.clone(),
        grant_types_supported: oidc.grant_types_supported.clone(),
        client_id_metadata_document_supported: oidc.client_id_metadata_document_supported,
        token_endpoint_auth_methods_supported: oidc.token_endpoint_auth_methods_supported.clone(),
        code_challenge_methods_supported: oidc.code_challenge_methods_supported.clone(),
    };
    validate_authorization_server_metadata(&metadata)?;
    Ok(metadata)
}

/// Resolve a generic metadata source into authorization-server metadata.
pub fn resolve_authorization_server_metadata(
    source: &AuthorizationServerMetadataSource,
) -> Result<AuthorizationServerMetadata, AuthSurfaceError> {
    let metadata = match source {
        AuthorizationServerMetadataSource::Explicit(metadata) => Ok(metadata.clone()),
        AuthorizationServerMetadataSource::OidcDiscovery(oidc) => {
            authorization_server_metadata_from_oidc(oidc)
        }
    }?;
    validate_authorization_server_metadata(&metadata)?;
    Ok(metadata)
}

fn validate_authorization_server_metadata(
    metadata: &AuthorizationServerMetadata,
) -> Result<(), AuthSurfaceError> {
    if metadata.issuer.trim().is_empty() {
        return Err(AuthSurfaceError::EmptyField("issuer"));
    }
    if metadata.authorization_endpoint.trim().is_empty() {
        return Err(AuthSurfaceError::EmptyField("authorization_endpoint"));
    }
    if metadata.token_endpoint.trim().is_empty() {
        return Err(AuthSurfaceError::EmptyField("token_endpoint"));
    }
    if metadata
        .registration_endpoint
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(AuthSurfaceError::EmptyField("registration_endpoint"));
    }
    if metadata
        .jwks_uri
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(AuthSurfaceError::EmptyField("jwks_uri"));
    }
    if metadata
        .introspection_endpoint
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(AuthSurfaceError::EmptyField("introspection_endpoint"));
    }
    if metadata
        .device_authorization_endpoint
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(AuthSurfaceError::EmptyField(
            "device_authorization_endpoint",
        ));
    }
    if metadata
        .grant_types_supported
        .as_ref()
        .is_some_and(|values| values.iter().any(|value| value.trim().is_empty()))
    {
        return Err(AuthSurfaceError::EmptyField("grant_types_supported"));
    }
    if metadata
        .token_endpoint_auth_methods_supported
        .as_ref()
        .is_some_and(|values| values.iter().any(|value| value.trim().is_empty()))
    {
        return Err(AuthSurfaceError::EmptyField(
            "token_endpoint_auth_methods_supported",
        ));
    }
    if metadata
        .code_challenge_methods_supported
        .as_ref()
        .is_some_and(|values| values.iter().any(|value| value.trim().is_empty()))
    {
        return Err(AuthSurfaceError::EmptyField(
            "code_challenge_methods_supported",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct IssuerRuntime {
    resource_path: String,
    resource_url: String,
    resource_metadata_url: String,
    realm: String,
    scopes_supported: Vec<String>,
    allowed_client_ids: Arc<HashSet<String>>,
    authenticator: Arc<Authenticator>,
    auth_metadata: AuthorizationServerMetadata,
    resource_metadata: ResourceMetadata,
    issuer: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WellKnownKind {
    AuthorizationServer,
    OpenIdConfiguration,
    ProtectedResource,
}

#[derive(Debug, Clone)]
struct WellKnownRoute {
    kind: WellKnownKind,
    entry: Arc<IssuerRuntime>,
}

/// Registry of issuers keyed by resource path.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Registry lookups are path-based and deterministic.
///
/// # Panics
/// * None.
#[derive(Debug, Clone)]
pub struct IssuerRegistry {
    entries: Vec<Arc<IssuerRuntime>>,
    well_known: HashMap<String, WellKnownRoute>,
    public_paths: HashSet<String>,
    public_prefixes: Vec<String>,
    unmatched_route_policy: UnmatchedRoutePolicy,
}

impl IssuerRegistry {
    /// Build the issuer registry and precompute well-known routes.
    ///
    /// # Errors
    /// * Returns `AuthSurfaceError::EmptyRegistry` when no issuer entries are supplied.
    /// * Returns `AuthSurfaceError::DuplicateResourcePath` when paths overlap.
    /// * Returns `AuthSurfaceError::InvalidUrl` when metadata URLs are not absolute.
    ///
    /// # Security
    /// * Enforces deterministic issuer selection by path.
    /// * Validates URLs to reduce metadata spoofing risk.
    ///
    /// # Panics
    /// * None.
    pub fn new(config: AuthSurfaceConfig) -> Result<Self, AuthSurfaceError> {
        Self::new_with_unmatched_route_policy(config, UnmatchedRoutePolicy::Deny)
    }

    /// Build the issuer registry and precompute well-known routes with an explicit unmatched-route policy.
    ///
    /// # Errors
    /// * Returns `AuthSurfaceError::EmptyRegistry` when no issuer entries are supplied.
    /// * Returns `AuthSurfaceError::DuplicateResourcePath` when paths overlap.
    /// * Returns `AuthSurfaceError::InvalidUrl` when metadata URLs are not absolute.
    ///
    /// # Security
    /// * Enforces deterministic issuer selection by path.
    /// * Validates URLs to reduce metadata spoofing risk.
    ///
    /// # Panics
    /// * None.
    pub fn new_with_unmatched_route_policy(
        config: AuthSurfaceConfig,
        unmatched_route_policy: UnmatchedRoutePolicy,
    ) -> Result<Self, AuthSurfaceError> {
        let AuthSurfaceConfig {
            public_base_url,
            entries: config_entries,
            root_alias_policy,
            public_paths,
            public_prefixes,
            allow_insecure_http,
        } = config;

        if config_entries.is_empty() {
            return Err(AuthSurfaceError::EmptyRegistry);
        }

        validate_absolute_url(&public_base_url, allow_insecure_http).map_err(|err| {
            AuthSurfaceError::InvalidUrl {
                field: "public_base_url",
                value: public_base_url.clone(),
                reason: err.to_string(),
            }
        })?;

        let root_alias_allowed = match root_alias_policy {
            RootAliasPolicy::Enabled => true,
            RootAliasPolicy::Disabled => false,
            RootAliasPolicy::Automatic => config_entries.len() == 1,
        };

        let mut seen_paths = HashSet::new();
        let mut entries = Vec::new();
        let mut well_known = HashMap::new();

        for entry in config_entries {
            let resource_path = normalize_resource_path(&entry.resource_path);
            if resource_path.is_empty() {
                return Err(AuthSurfaceError::EmptyField("resource_path"));
            }
            if entry.issuer.trim().is_empty() {
                return Err(AuthSurfaceError::EmptyField("issuer"));
            }
            if entry.authorization_endpoint.trim().is_empty() {
                return Err(AuthSurfaceError::EmptyField("authorization_endpoint"));
            }
            if entry.token_endpoint.trim().is_empty() {
                return Err(AuthSurfaceError::EmptyField("token_endpoint"));
            }
            if !seen_paths.insert(resource_path.clone()) {
                return Err(AuthSurfaceError::DuplicateResourcePath(resource_path));
            }

            let resource_url = entry
                .resource_url_override
                .clone()
                .unwrap_or_else(|| resource_url_from_base(&public_base_url, &resource_path));

            validate_absolute_url(&entry.issuer, allow_insecure_http).map_err(|err| {
                AuthSurfaceError::InvalidUrl {
                    field: "issuer",
                    value: entry.issuer.clone(),
                    reason: err.to_string(),
                }
            })?;
            validate_absolute_url(&entry.authorization_endpoint, allow_insecure_http).map_err(
                |err| AuthSurfaceError::InvalidUrl {
                    field: "authorization_endpoint",
                    value: entry.authorization_endpoint.clone(),
                    reason: err.to_string(),
                },
            )?;
            validate_absolute_url(&entry.token_endpoint, allow_insecure_http).map_err(|err| {
                AuthSurfaceError::InvalidUrl {
                    field: "token_endpoint",
                    value: entry.token_endpoint.clone(),
                    reason: err.to_string(),
                }
            })?;
            if let Some(registration_endpoint) = &entry.registration_endpoint {
                validate_absolute_url(registration_endpoint, allow_insecure_http).map_err(
                    |err| AuthSurfaceError::InvalidUrl {
                        field: "registration_endpoint",
                        value: registration_endpoint.clone(),
                        reason: err.to_string(),
                    },
                )?;
            }
            if let Some(jwks_uri) = &entry.jwks_uri {
                validate_absolute_url(jwks_uri, allow_insecure_http).map_err(|err| {
                    AuthSurfaceError::InvalidUrl {
                        field: "jwks_uri",
                        value: jwks_uri.clone(),
                        reason: err.to_string(),
                    }
                })?;
            }
            if let Some(introspection_endpoint) = &entry.introspection_endpoint {
                validate_absolute_url(introspection_endpoint, allow_insecure_http).map_err(
                    |err| AuthSurfaceError::InvalidUrl {
                        field: "introspection_endpoint",
                        value: introspection_endpoint.clone(),
                        reason: err.to_string(),
                    },
                )?;
            }
            if let Some(device_authorization_endpoint) = &entry.device_authorization_endpoint {
                validate_absolute_url(device_authorization_endpoint, allow_insecure_http).map_err(
                    |err| AuthSurfaceError::InvalidUrl {
                        field: "device_authorization_endpoint",
                        value: device_authorization_endpoint.clone(),
                        reason: err.to_string(),
                    },
                )?;
            }
            validate_absolute_url(&resource_url, allow_insecure_http).map_err(|err| {
                AuthSurfaceError::InvalidUrl {
                    field: "resource_url",
                    value: resource_url.clone(),
                    reason: err.to_string(),
                }
            })?;
            let resource_metadata = resource_metadata_default(
                resource_url.clone(),
                [entry.issuer.clone()],
                entry.scopes_supported.clone(),
            );
            let resource_metadata_url = resource_metadata_hint(&resource_url)
                .ok_or_else(|| AuthSurfaceError::InvalidResourceUrl(resource_url.clone()))?;
            let auth_metadata = AuthorizationServerMetadata {
                issuer: entry.issuer.clone(),
                authorization_endpoint: entry.authorization_endpoint.clone(),
                token_endpoint: entry.token_endpoint.clone(),
                registration_endpoint: entry.registration_endpoint.clone(),
                jwks_uri: entry.jwks_uri.clone(),
                introspection_endpoint: entry.introspection_endpoint.clone(),
                device_authorization_endpoint: entry.device_authorization_endpoint.clone(),
                grant_types_supported: entry.grant_types_supported.clone(),
                client_id_metadata_document_supported: entry.client_id_metadata_document_supported,
                token_endpoint_auth_methods_supported: entry
                    .token_endpoint_auth_methods_supported
                    .clone(),
                code_challenge_methods_supported: entry.code_challenge_methods_supported.clone(),
            };
            validate_authorization_server_metadata(&auth_metadata)?;

            let runtime = Arc::new(IssuerRuntime {
                resource_path: resource_path.clone(),
                resource_url,
                resource_metadata_url,
                realm: entry.realm.clone(),
                scopes_supported: entry.scopes_supported.clone(),
                allowed_client_ids: Arc::new(entry.allowed_client_ids.clone()),
                authenticator: entry.authenticator.clone(),
                auth_metadata,
                resource_metadata,
                issuer: entry.issuer.clone(),
            });

            let allow_root_alias = root_alias_allowed || resource_path == "/";
            insert_well_known_routes(
                &mut well_known,
                authorization_server_well_known_paths(&resource_path),
                WellKnownKind::AuthorizationServer,
                runtime.clone(),
                allow_root_alias,
                OAUTH_AUTHZ_WELL_KNOWN_PATH,
            )?;
            insert_well_known_routes(
                &mut well_known,
                oidc_well_known_paths(&resource_path),
                WellKnownKind::OpenIdConfiguration,
                runtime.clone(),
                allow_root_alias,
                OIDC_WELL_KNOWN_PATH,
            )?;
            insert_well_known_routes(
                &mut well_known,
                protected_resource_well_known_paths(&resource_path),
                WellKnownKind::ProtectedResource,
                runtime.clone(),
                allow_root_alias,
                PRM_WELL_KNOWN_PATH,
            )?;

            entries.push(runtime);
        }

        let public_paths = normalize_public_paths(&public_paths);
        let public_prefixes = normalize_public_prefixes(&public_prefixes);

        Ok(Self {
            entries,
            well_known,
            public_paths,
            public_prefixes,
            unmatched_route_policy,
        })
    }

    /// Find the issuer entry that applies to the request path.
    fn match_entry(&self, path: &str) -> Option<Arc<IssuerRuntime>> {
        let mut best: Option<Arc<IssuerRuntime>> = None;
        let mut best_len = 0usize;
        for entry in &self.entries {
            if path_matches_resource(path, &entry.resource_path) {
                let len = entry.resource_path.len();
                if len >= best_len {
                    best = Some(entry.clone());
                    best_len = len;
                }
            }
        }
        best
    }

    /// Lookup a well-known route for the given path.
    fn well_known_route(&self, path: &str) -> Option<WellKnownRoute> {
        self.well_known.get(path).cloned()
    }

    fn is_public_path(&self, path: &str) -> bool {
        if self.public_paths.contains(path) {
            return true;
        }
        self.public_prefixes.iter().any(|prefix| {
            if prefix == "/" {
                return true;
            }
            path == prefix || path.starts_with(&format!("{prefix}/"))
        })
    }

    fn denies_unmatched_routes(&self) -> bool {
        self.unmatched_route_policy == UnmatchedRoutePolicy::Deny
    }
}

fn normalize_resource_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    let normalized = trimmed.trim_start_matches('/').trim_end_matches('/');
    if normalized.is_empty() {
        "/".to_string()
    } else {
        format!("/{normalized}")
    }
}

fn normalize_public_paths(paths: &HashSet<String>) -> HashSet<String> {
    paths
        .iter()
        .map(|path| normalize_resource_path(path))
        .collect()
}

fn normalize_public_prefixes(prefixes: &[String]) -> Vec<String> {
    prefixes
        .iter()
        .map(|prefix| normalize_resource_path(prefix))
        .collect()
}

fn path_matches_resource(path: &str, resource_path: &str) -> bool {
    if resource_path == "/" {
        return true;
    }
    if path == resource_path {
        return true;
    }
    if let Some(rest) = path.strip_prefix(resource_path) {
        return rest.starts_with('/');
    }
    false
}

fn normalize_request_path(path: &str) -> String {
    let mut decoded = String::with_capacity(path.len());
    let mut chars = path.chars();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            let hi = chars.next();
            let lo = chars.next();
            if let (Some(hi), Some(lo)) = (hi, lo) {
                match decode_hex_pair(hi, lo) {
                    Some(b'/') | Some(b'\\') => decoded.push('/'),
                    Some(b'.') => decoded.push('.'),
                    Some(_) | None => {
                        decoded.push('%');
                        decoded.push(hi);
                        decoded.push(lo);
                    }
                }
            } else {
                decoded.push('%');
                if let Some(hi) = hi {
                    decoded.push(hi);
                }
                if let Some(lo) = lo {
                    decoded.push(lo);
                }
            }
            continue;
        }

        if ch == '\\' {
            decoded.push('/');
        } else {
            decoded.push(ch);
        }
    }

    let mut segments = Vec::new();
    for segment in decoded.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            segments.pop();
            continue;
        }
        segments.push(segment);
    }

    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn decode_hex_pair(hi: char, lo: char) -> Option<u8> {
    let hi = hi.to_digit(16)? as u8;
    let lo = lo.to_digit(16)? as u8;
    Some((hi << 4) | lo)
}

fn insert_well_known_routes(
    map: &mut HashMap<String, WellKnownRoute>,
    mut paths: Vec<String>,
    kind: WellKnownKind,
    entry: Arc<IssuerRuntime>,
    allow_root_alias: bool,
    root_alias: &str,
) -> Result<(), AuthSurfaceError> {
    if !allow_root_alias {
        paths.retain(|path| path != root_alias);
    }
    for path in paths {
        if map.contains_key(&path) {
            return Err(AuthSurfaceError::DuplicateWellKnownRoute(path));
        }
        map.insert(
            path,
            WellKnownRoute {
                kind,
                entry: entry.clone(),
            },
        );
    }
    Ok(())
}

/// Auth surface context attached to requests after successful authentication.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all fields as derived from trusted server configuration.
///
/// # Panics
/// * None.
#[derive(Debug, Clone)]
pub struct AuthSurfaceContext {
    pub resource_path: String,
    pub resource_url: String,
    pub issuer: String,
}

/// Sanitized auth failure event emitted by [`AuthSurfaceLayer`].
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * `headers` may contain an `Authorization` header. Observers must never log
///   raw credentials; derive redacted token hints instead.
///
/// # Panics
/// * None.
pub struct AuthFailureEvent<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub resource_path: &'a str,
    pub resource_url: &'a str,
    pub issuer: &'a str,
    pub realm: &'a str,
    pub error: &'a AuthError,
    pub headers: &'a HeaderMap,
}

/// Observer hook for auth surface failures.
///
/// # Errors
/// * Implementations should handle their own failures and must not panic.
///
/// # Security
/// * Implementations must treat request headers as sensitive and avoid logging
///   bearer tokens, cookies, or other raw credentials.
///
/// # Panics
/// * This trait does not require panics; implementations should remain panic-free.
pub trait AuthFailureObserver: Send + Sync + 'static {
    fn observe_auth_failure(&self, event: AuthFailureEvent<'_>);
}

/// Tower layer that wraps an HTTP service with OAuth discovery + auth enforcement.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Wraps an inner service with auth enforcement.
///
/// # Panics
/// * None.
#[derive(Clone)]
pub struct AuthSurfaceLayer {
    registry: Arc<IssuerRegistry>,
    auth_failure_observer: Option<Arc<dyn AuthFailureObserver>>,
}

impl AuthSurfaceLayer {
    /// Create a new auth surface layer.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Callers must supply a validated registry.
    ///
    /// # Panics
    /// * None.
    pub fn new(registry: IssuerRegistry) -> Self {
        Self::new_with_observer(registry, None)
    }

    /// Create a new auth surface layer with an auth failure observer.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * The observer receives request headers and must not log raw credentials.
    ///
    /// # Panics
    /// * None.
    pub fn new_with_observer(
        registry: IssuerRegistry,
        auth_failure_observer: Option<Arc<dyn AuthFailureObserver>>,
    ) -> Self {
        Self {
            registry: Arc::new(registry),
            auth_failure_observer,
        }
    }

    /// Build a new auth surface layer from config.
    ///
    /// # Errors
    /// * Returns `AuthSurfaceError` when the registry fails validation.
    ///
    /// # Security
    /// * Validates URLs and enforces deterministic issuer selection.
    ///
    /// # Panics
    /// * None.
    pub fn from_config(config: AuthSurfaceConfig) -> Result<Self, AuthSurfaceError> {
        Self::from_config_with_unmatched_route_policy(config, UnmatchedRoutePolicy::Deny)
    }

    /// Build a new auth surface layer from config with an auth failure observer.
    ///
    /// # Errors
    /// * Returns `AuthSurfaceError` when the registry fails validation.
    ///
    /// # Security
    /// * The observer receives request headers and must not log raw credentials.
    ///
    /// # Panics
    /// * None.
    pub fn from_config_with_observer(
        config: AuthSurfaceConfig,
        auth_failure_observer: Arc<dyn AuthFailureObserver>,
    ) -> Result<Self, AuthSurfaceError> {
        Self::from_config_with_unmatched_route_policy_and_observer(
            config,
            UnmatchedRoutePolicy::Deny,
            Some(auth_failure_observer),
        )
    }

    /// Build a new auth surface layer from config with an explicit unmatched-route policy.
    ///
    /// # Errors
    /// * Returns `AuthSurfaceError` when the registry fails validation.
    ///
    /// # Security
    /// * Validates URLs and enforces deterministic issuer selection.
    ///
    /// # Panics
    /// * None.
    pub fn from_config_with_unmatched_route_policy(
        config: AuthSurfaceConfig,
        unmatched_route_policy: UnmatchedRoutePolicy,
    ) -> Result<Self, AuthSurfaceError> {
        Self::from_config_with_unmatched_route_policy_and_observer(
            config,
            unmatched_route_policy,
            None,
        )
    }

    /// Build a new auth surface layer from config with explicit route policy and observer.
    ///
    /// # Errors
    /// * Returns `AuthSurfaceError` when the registry fails validation.
    ///
    /// # Security
    /// * The observer receives request headers and must not log raw credentials.
    ///
    /// # Panics
    /// * None.
    pub fn from_config_with_unmatched_route_policy_and_observer(
        config: AuthSurfaceConfig,
        unmatched_route_policy: UnmatchedRoutePolicy,
        auth_failure_observer: Option<Arc<dyn AuthFailureObserver>>,
    ) -> Result<Self, AuthSurfaceError> {
        Ok(Self::new_with_observer(
            IssuerRegistry::new_with_unmatched_route_policy(config, unmatched_route_policy)?,
            auth_failure_observer,
        ))
    }
}

impl<S> Layer<S> for AuthSurfaceLayer {
    type Service = AuthSurfaceService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthSurfaceService {
            inner,
            registry: self.registry.clone(),
            auth_failure_observer: self.auth_failure_observer.clone(),
        }
    }
}

/// Service wrapper that enforces the auth surface contract.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Rejects unauthenticated requests for protected paths.
///
/// # Panics
/// * None.
#[derive(Clone)]
pub struct AuthSurfaceService<S> {
    inner: S,
    registry: Arc<IssuerRegistry>,
    auth_failure_observer: Option<Arc<dyn AuthFailureObserver>>,
}

impl<S> tower::Service<Request<Body>> for AuthSurfaceService<S>
where
    S: tower::Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response<Body>, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let path = normalize_request_path(req.uri().path());
        let registry = self.registry.clone();
        let auth_failure_observer = self.auth_failure_observer.clone();

        if let Some(route) = registry.well_known_route(&path) {
            let response = well_known_response(&route);
            return Box::pin(async move { Ok(response) });
        }

        if registry.is_public_path(&path) {
            let fut = self.inner.call(req);
            return Box::pin(fut);
        }

        if let Some(entry) = registry.match_entry(&path) {
            let headers = req.headers().clone();
            let method = req.method().as_str().to_string();
            let allowed_client_ids = entry.allowed_client_ids.clone();
            let realm = entry.realm.clone();
            let resource_metadata_url = entry.resource_metadata_url.clone();
            let scopes_supported = entry.scopes_supported.clone();
            let issuer = entry.issuer.clone();
            let resource_path = entry.resource_path.clone();
            let resource_url = entry.resource_url.clone();
            let authenticator = entry.authenticator.clone();
            let mut inner = self.inner.clone();

            return Box::pin(async move {
                match authenticator.authenticate_headers(&headers).await {
                    Ok(context) => {
                        if !allowed_client_ids.is_empty() {
                            let azp = context.azp.as_deref().unwrap_or_default();
                            if azp.is_empty() || !allowed_client_ids.contains(azp) {
                                let err =
                                    AuthError::new("client_id is not allowed for this service")
                                        .with_status(StatusCode::FORBIDDEN.as_u16())
                                        .with_code("AUTH_CLIENT_NOT_ALLOWED")
                                        .with_reason("client_not_allowed");
                                observe_auth_failure(
                                    auth_failure_observer.as_deref(),
                                    AuthFailureEvent {
                                        method: &method,
                                        path: &path,
                                        resource_path: &resource_path,
                                        resource_url: &resource_url,
                                        issuer: &issuer,
                                        realm: &realm,
                                        error: &err,
                                        headers: &headers,
                                    },
                                );
                                return Ok(auth_error_response(
                                    &realm,
                                    &resource_metadata_url,
                                    &scopes_supported,
                                    err,
                                ));
                            }
                        }
                        req.extensions_mut().insert::<AuthContext>(context);
                        req.extensions_mut()
                            .insert::<AuthSurfaceContext>(AuthSurfaceContext {
                                resource_path,
                                resource_url,
                                issuer,
                            });
                        inner.call(req).await
                    }
                    Err(err) => {
                        observe_auth_failure(
                            auth_failure_observer.as_deref(),
                            AuthFailureEvent {
                                method: &method,
                                path: &path,
                                resource_path: &resource_path,
                                resource_url: &resource_url,
                                issuer: &issuer,
                                realm: &realm,
                                error: &err,
                                headers: &headers,
                            },
                        );
                        Ok(auth_error_response(
                            &realm,
                            &resource_metadata_url,
                            &scopes_supported,
                            err,
                        ))
                    }
                }
            });
        }

        if registry.denies_unmatched_routes() {
            return Box::pin(async move { Ok(unmatched_route_response()) });
        }

        let fut = self.inner.call(req);
        Box::pin(fut)
    }
}

fn observe_auth_failure(observer: Option<&dyn AuthFailureObserver>, event: AuthFailureEvent<'_>) {
    if let Some(observer) = observer {
        observer.observe_auth_failure(event);
    }
}

fn well_known_response(route: &WellKnownRoute) -> Response<Body> {
    match route.kind {
        WellKnownKind::AuthorizationServer => json_response(&route.entry.auth_metadata),
        WellKnownKind::ProtectedResource => json_response(&route.entry.resource_metadata),
        WellKnownKind::OpenIdConfiguration => {
            redirect_response(&oidc_metadata_url(&route.entry.issuer))
        }
    }
}

fn json_response<T: Serialize>(value: &T) -> Response<Body> {
    let body = match serde_json::to_vec(value) {
        Ok(body) => body,
        Err(_) => b"{}".to_vec(),
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    if let Ok(value) = "application/json".parse() {
        response.headers_mut().insert(CONTENT_TYPE, value);
    }
    response
}

fn redirect_response(location: &str) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
    if let Ok(value) = location.parse() {
        response.headers_mut().insert(LOCATION, value);
    }
    response
}

fn unmatched_route_response() -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

/// Build a generic HTTP auth failure response for a protected resource.
///
/// # Errors
/// * This function does not return errors directly.
///
/// # Security
/// * Emits only generic auth failure details suitable for public HTTP responses.
///
/// # Panics
/// * None.
pub fn auth_error_response(
    realm: &str,
    resource_metadata_url: &str,
    scopes_supported: &[String],
    err: AuthError,
) -> Response<Body> {
    let status = StatusCode::from_u16(status_for_error(&err)).unwrap_or(StatusCode::UNAUTHORIZED);
    let mut response = Response::new(Body::from(error_body(&err)));
    *response.status_mut() = status;

    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        let scope = if scopes_supported.is_empty() {
            None
        } else {
            Some(scopes_supported.join(" "))
        };
        let challenge = BearerChallenge {
            realm,
            resource_metadata: Some(resource_metadata_url),
            scope: scope.as_deref(),
            error: error_code_for_error(&err),
            error_description: error_description_for_error(&err),
            error_uri: None,
        };
        let header = build_bearer_challenge(&challenge);
        response.headers_mut().insert(WWW_AUTHENTICATE, header);
    }

    response
}

fn status_for_error(err: &AuthError) -> u16 {
    match err {
        AuthError::Generic { status_code, .. } => *status_code,
        AuthError::MissingToken => StatusCode::UNAUTHORIZED.as_u16(),
        AuthError::InvalidToken => StatusCode::UNAUTHORIZED.as_u16(),
        AuthError::TokenExpired => StatusCode::UNAUTHORIZED.as_u16(),
        AuthError::ReplayDetected => StatusCode::UNAUTHORIZED.as_u16(),
        AuthError::MissingScopes => StatusCode::FORBIDDEN.as_u16(),
        AuthError::ConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
    }
}

fn error_code_for_error(err: &AuthError) -> Option<&'static str> {
    match err {
        AuthError::MissingToken => Some("invalid_request"),
        AuthError::InvalidToken | AuthError::TokenExpired | AuthError::ReplayDetected => {
            Some("invalid_token")
        }
        AuthError::MissingScopes => Some("insufficient_scope"),
        AuthError::Generic {
            status_code,
            reason,
            ..
        } => match (status_code, reason) {
            (_, Some("invalid_request")) => Some("invalid_request"),
            (_, Some("invalid_token")) => Some("invalid_token"),
            (_, Some("insufficient_scope")) => Some("insufficient_scope"),
            (401, Some(_)) | (401, None) => Some("invalid_token"),
            _ => None,
        },
        _ => None,
    }
}

fn error_description_for_error(err: &AuthError) -> Option<&'static str> {
    match err {
        AuthError::MissingToken => Some("missing token"),
        AuthError::TokenExpired => Some("token expired"),
        AuthError::ReplayDetected => Some("token replay detected"),
        AuthError::MissingScopes => Some("missing scopes"),
        AuthError::Generic { .. } => None,
        _ => None,
    }
}

fn error_body(err: &AuthError) -> String {
    match err {
        AuthError::Generic { message, .. } => message.clone(),
        AuthError::MissingToken => "missing token".to_string(),
        AuthError::InvalidToken => "invalid token".to_string(),
        AuthError::TokenExpired => "token expired".to_string(),
        AuthError::ReplayDetected => "token replay detected".to_string(),
        AuthError::MissingScopes => "missing scopes".to_string(),
        AuthError::ConfigError(message) => message.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{Request, Response, StatusCode};
    use std::convert::Infallible;
    use std::sync::Mutex;
    use tower::{service_fn, Service};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedAuthFailure {
        method: String,
        path: String,
        resource_path: String,
        resource_url: String,
        reason: Option<&'static str>,
        has_authorization: bool,
    }

    #[derive(Default)]
    struct RecordingAuthFailureObserver {
        events: Mutex<Vec<RecordedAuthFailure>>,
    }

    impl AuthFailureObserver for RecordingAuthFailureObserver {
        fn observe_auth_failure(&self, event: AuthFailureEvent<'_>) {
            let has_authorization = event.headers.contains_key(http::header::AUTHORIZATION);
            self.events
                .lock()
                .expect("lock")
                .push(RecordedAuthFailure {
                    method: event.method.to_string(),
                    path: event.path.to_string(),
                    resource_path: event.resource_path.to_string(),
                    resource_url: event.resource_url.to_string(),
                    reason: error_code_for_error(event.error),
                    has_authorization,
                });
        }
    }

    fn test_authenticator() -> Arc<Authenticator> {
        let cfg = crate::AuthConfig {
            mode: crate::AuthMode::Delegation,
            delegation_secret: Some("secret".to_string()),
            ..crate::AuthConfig::default()
        };
        match Authenticator::new(cfg) {
            Ok(auth) => Arc::new(auth),
            Err(err) => panic!("failed to build authenticator: {err}"),
        }
    }

    fn test_entry(resource_path: &str, resource_url_override: Option<&str>) -> IssuerEntry {
        IssuerEntry {
            resource_path: resource_path.to_string(),
            issuer: "https://issuer.test".to_string(),
            authorization_endpoint: "https://issuer.test/auth".to_string(),
            token_endpoint: "https://issuer.test/token".to_string(),
            registration_endpoint: None,
            jwks_uri: None,
            introspection_endpoint: None,
            device_authorization_endpoint: None,
            grant_types_supported: None,
            client_id_metadata_document_supported: None,
            token_endpoint_auth_methods_supported: None,
            code_challenge_methods_supported: None,
            realm: "test".to_string(),
            scopes_supported: Vec::new(),
            allowed_client_ids: HashSet::new(),
            authenticator: test_authenticator(),
            resource_url_override: resource_url_override.map(str::to_string),
        }
    }

    #[test]
    fn auth_surface_config_detects_insecure_http_urls() {
        let config = AuthSurfaceConfig {
            public_base_url: "https://example.com".to_string(),
            entries: vec![IssuerEntry {
                issuer: "http://issuer.test".to_string(),
                ..test_entry("/mcp", Some("https://example.com/mcp"))
            }],
            root_alias_policy: RootAliasPolicy::Automatic,
            public_paths: HashSet::new(),
            public_prefixes: Vec::new(),
            allow_insecure_http: false,
        };

        assert!(config.contains_insecure_http_urls());
    }

    #[test]
    fn auth_surface_config_ignores_all_https_urls() {
        let config = AuthSurfaceConfig {
            public_base_url: "https://example.com".to_string(),
            entries: vec![test_entry("/mcp", Some("https://example.com/mcp"))],
            root_alias_policy: RootAliasPolicy::Automatic,
            public_paths: HashSet::new(),
            public_prefixes: Vec::new(),
            allow_insecure_http: false,
        };

        assert!(!config.contains_insecure_http_urls());
    }

    #[test]
    fn registry_rejects_manual_entries_with_invalid_authorization_metadata() {
        let err = match IssuerRegistry::new(AuthSurfaceConfig {
            public_base_url: "https://example.com".to_string(),
            entries: vec![IssuerEntry {
                token_endpoint_auth_methods_supported: Some(vec![
                    "none".to_string(),
                    String::new(),
                ]),
                ..test_entry("/mcp", Some("https://example.com/mcp"))
            }],
            root_alias_policy: RootAliasPolicy::Automatic,
            public_paths: HashSet::new(),
            public_prefixes: Vec::new(),
            allow_insecure_http: false,
        }) {
            Ok(_) => panic!("registry should reject invalid metadata values"),
            Err(err) => err,
        };

        match err {
            AuthSurfaceError::EmptyField(field) => {
                assert_eq!(field, "token_endpoint_auth_methods_supported");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn auth_surface_config_enables_insecure_http_when_needed() {
        let config = AuthSurfaceConfig {
            public_base_url: "http://127.0.0.1:3000".to_string(),
            entries: vec![test_entry("/mcp", Some("http://127.0.0.1:3000/mcp"))],
            root_alias_policy: RootAliasPolicy::Automatic,
            public_paths: HashSet::new(),
            public_prefixes: Vec::new(),
            allow_insecure_http: false,
        };

        let adjusted = config.with_detected_allow_insecure_http();

        assert!(adjusted.allow_insecure_http);
    }

    #[test]
    fn auth_surface_config_into_layer_detects_insecure_http_before_validation() {
        let config = AuthSurfaceConfig {
            public_base_url: "http://127.0.0.1:3000".to_string(),
            entries: vec![test_entry("/mcp", Some("http://127.0.0.1:3000/mcp"))],
            root_alias_policy: RootAliasPolicy::Automatic,
            public_paths: HashSet::new(),
            public_prefixes: Vec::new(),
            allow_insecure_http: false,
        };

        let err = match AuthSurfaceLayer::from_config(config.clone()) {
            Ok(_) => panic!("raw config should reject insecure http URLs"),
            Err(err) => err,
        };
        match err {
            AuthSurfaceError::InvalidUrl { field, .. } => {
                assert_eq!(field, "public_base_url");
            }
            other => panic!("unexpected error: {other}"),
        }

        config
            .into_layer_with_detected_allow_insecure_http()
            .expect("helper should build a layer for local http auth surfaces");
    }

    #[test]
    fn registry_matches_longest_prefix() {
        let entry_root = test_entry("/", Some("https://example.com/"));
        let entry_mcp = test_entry("/mcp", Some("https://example.com/mcp"));
        let registry = match IssuerRegistry::new(AuthSurfaceConfig {
            public_base_url: "https://example.com".to_string(),
            entries: vec![entry_root, entry_mcp],
            root_alias_policy: RootAliasPolicy::Disabled,
            public_paths: HashSet::new(),
            public_prefixes: Vec::new(),
            allow_insecure_http: false,
        }) {
            Ok(registry) => registry,
            Err(err) => panic!("failed to build registry: {err}"),
        };

        let entry = match registry.match_entry("/mcp/tools") {
            Some(entry) => entry,
            None => panic!("expected registry match for /mcp/tools"),
        };
        assert_eq!(entry.resource_path, "/mcp");
    }

    #[test]
    fn registry_filters_root_alias_when_multiple_entries() {
        let entry_a = test_entry("/mcp", Some("https://example.com/mcp"));
        let entry_b = test_entry("/mcp/alt", Some("https://example.com/mcp/alt"));
        let registry = match IssuerRegistry::new(AuthSurfaceConfig {
            public_base_url: "https://example.com".to_string(),
            entries: vec![entry_a, entry_b],
            root_alias_policy: RootAliasPolicy::Automatic,
            public_paths: HashSet::new(),
            public_prefixes: Vec::new(),
            allow_insecure_http: false,
        }) {
            Ok(registry) => registry,
            Err(err) => panic!("failed to build registry: {err}"),
        };

        assert!(registry
            .well_known_route(OAUTH_AUTHZ_WELL_KNOWN_PATH)
            .is_none());
        assert!(registry.well_known_route(PRM_WELL_KNOWN_PATH).is_none());
        assert!(registry.well_known_route(OIDC_WELL_KNOWN_PATH).is_none());
    }

    #[test]
    fn registry_disables_root_alias_when_configured() {
        let entry = IssuerEntry {
            resource_path: "/mcp".to_string(),
            issuer: "https://issuer.test".to_string(),
            authorization_endpoint: "https://issuer.test/auth".to_string(),
            token_endpoint: "https://issuer.test/token".to_string(),
            registration_endpoint: None,
            jwks_uri: None,
            introspection_endpoint: None,
            device_authorization_endpoint: None,
            grant_types_supported: None,
            client_id_metadata_document_supported: None,
            token_endpoint_auth_methods_supported: None,
            code_challenge_methods_supported: None,
            realm: "test".to_string(),
            scopes_supported: Vec::new(),
            allowed_client_ids: HashSet::new(),
            authenticator: test_authenticator(),
            resource_url_override: Some("https://example.com/mcp".to_string()),
        };
        let registry = match IssuerRegistry::new(AuthSurfaceConfig {
            public_base_url: "https://example.com".to_string(),
            entries: vec![entry],
            root_alias_policy: RootAliasPolicy::Disabled,
            public_paths: HashSet::new(),
            public_prefixes: Vec::new(),
            allow_insecure_http: false,
        }) {
            Ok(registry) => registry,
            Err(err) => panic!("failed to build registry: {err}"),
        };

        assert!(registry
            .well_known_route(OAUTH_AUTHZ_WELL_KNOWN_PATH)
            .is_none());
        assert!(registry.well_known_route(PRM_WELL_KNOWN_PATH).is_none());
        assert!(registry.well_known_route(OIDC_WELL_KNOWN_PATH).is_none());
    }

    #[test]
    fn request_path_normalization_decodes_ambiguous_separators() {
        assert_eq!(normalize_request_path("/mcp%2Ftools"), "/mcp/tools");
        assert_eq!(normalize_request_path("//mcp///tools"), "/mcp/tools");
        assert_eq!(
            normalize_request_path("/public/%2E%2E/mcp/./tools"),
            "/mcp/tools"
        );
    }

    #[test]
    fn metadata_source_resolves_explicit_metadata() {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://issuer.test".to_string(),
            authorization_endpoint: "https://issuer.test/auth".to_string(),
            token_endpoint: "https://issuer.test/token".to_string(),
            registration_endpoint: Some("https://issuer.test/register".to_string()),
            jwks_uri: Some("https://issuer.test/jwks".to_string()),
            introspection_endpoint: Some("https://issuer.test/introspect".to_string()),
            device_authorization_endpoint: None,
            grant_types_supported: None,
            client_id_metadata_document_supported: Some(true),
            token_endpoint_auth_methods_supported: Some(vec![
                "none".to_string(),
                "private_key_jwt".to_string(),
            ]),
            code_challenge_methods_supported: Some(vec!["S256".to_string()]),
        };
        let resolved = resolve_authorization_server_metadata(
            &AuthorizationServerMetadataSource::Explicit(metadata.clone()),
        )
        .expect("resolve explicit metadata");
        assert_eq!(resolved, metadata);
    }

    #[test]
    fn metadata_source_rejects_blank_explicit_required_fields() {
        let err = resolve_authorization_server_metadata(
            &AuthorizationServerMetadataSource::Explicit(AuthorizationServerMetadata {
                issuer: "   ".to_string(),
                authorization_endpoint: "https://issuer.test/auth".to_string(),
                token_endpoint: "https://issuer.test/token".to_string(),
                registration_endpoint: None,
                jwks_uri: None,
                introspection_endpoint: None,
                device_authorization_endpoint: None,
                grant_types_supported: None,
                client_id_metadata_document_supported: None,
                token_endpoint_auth_methods_supported: None,
                code_challenge_methods_supported: None,
            }),
        )
        .expect_err("blank issuer should be rejected");
        assert!(matches!(err, AuthSurfaceError::EmptyField("issuer")));
    }

    #[test]
    fn metadata_source_resolves_oidc_discovery() {
        let oidc = crate::OidcDiscovery {
            issuer: Some("https://issuer.test".to_string()),
            authorization_endpoint: Some("https://issuer.test/auth".to_string()),
            token_endpoint: Some("https://issuer.test/token".to_string()),
            registration_endpoint: Some("https://issuer.test/register".to_string()),
            jwks_uri: "https://issuer.test/jwks".to_string(),
            introspection_endpoint: Some("https://issuer.test/introspect".to_string()),
            device_authorization_endpoint: Some("https://issuer.test/device".to_string()),
            grant_types_supported: Some(vec![
                "authorization_code".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ]),
            client_id_metadata_document_supported: Some(true),
            token_endpoint_auth_methods_supported: Some(vec![
                "none".to_string(),
                "private_key_jwt".to_string(),
            ]),
            code_challenge_methods_supported: Some(vec!["S256".to_string()]),
        };
        let resolved = resolve_authorization_server_metadata(
            &AuthorizationServerMetadataSource::OidcDiscovery(oidc),
        )
        .expect("resolve oidc metadata");
        assert_eq!(resolved.issuer, "https://issuer.test");
        assert_eq!(resolved.authorization_endpoint, "https://issuer.test/auth");
        assert_eq!(resolved.token_endpoint, "https://issuer.test/token");
        assert_eq!(
            resolved.registration_endpoint.as_deref(),
            Some("https://issuer.test/register")
        );
        assert_eq!(
            resolved.jwks_uri.as_deref(),
            Some("https://issuer.test/jwks")
        );
        assert_eq!(
            resolved.introspection_endpoint.as_deref(),
            Some("https://issuer.test/introspect")
        );
        assert_eq!(
            resolved.device_authorization_endpoint.as_deref(),
            Some("https://issuer.test/device")
        );
        assert_eq!(
            resolved.grant_types_supported,
            Some(vec![
                "authorization_code".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string()
            ])
        );
        assert_eq!(resolved.client_id_metadata_document_supported, Some(true));
        assert_eq!(
            resolved.token_endpoint_auth_methods_supported,
            Some(vec!["none".to_string(), "private_key_jwt".to_string()])
        );
        assert_eq!(
            resolved.code_challenge_methods_supported,
            Some(vec!["S256".to_string()])
        );
    }

    #[test]
    fn issuer_entry_can_be_built_from_metadata_source() {
        let entry = IssuerEntry::from_metadata_source(
            "/mcp",
            AuthorizationServerMetadataSource::Explicit(AuthorizationServerMetadata {
                issuer: "https://issuer.test".to_string(),
                authorization_endpoint: "https://issuer.test/auth".to_string(),
                token_endpoint: "https://issuer.test/token".to_string(),
                registration_endpoint: None,
                jwks_uri: Some("https://issuer.test/jwks".to_string()),
                introspection_endpoint: Some("https://issuer.test/introspect".to_string()),
                device_authorization_endpoint: Some("https://issuer.test/device".to_string()),
                grant_types_supported: Some(vec![
                    "authorization_code".to_string(),
                    "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                ]),
                client_id_metadata_document_supported: Some(true),
                token_endpoint_auth_methods_supported: Some(vec![
                    "none".to_string(),
                    "private_key_jwt".to_string(),
                ]),
                code_challenge_methods_supported: Some(vec!["S256".to_string()]),
            }),
            "test",
            vec!["ops:read".to_string()],
            HashSet::new(),
            test_authenticator(),
            Some("https://example.com/mcp".to_string()),
        )
        .expect("entry from metadata source");
        assert_eq!(entry.resource_path, "/mcp");
        assert_eq!(entry.issuer, "https://issuer.test");
        assert_eq!(entry.authorization_endpoint, "https://issuer.test/auth");
        assert_eq!(entry.token_endpoint, "https://issuer.test/token");
        assert_eq!(entry.jwks_uri.as_deref(), Some("https://issuer.test/jwks"));
        assert_eq!(
            entry.introspection_endpoint.as_deref(),
            Some("https://issuer.test/introspect")
        );
        assert_eq!(
            entry.device_authorization_endpoint.as_deref(),
            Some("https://issuer.test/device")
        );
        assert_eq!(
            entry.grant_types_supported,
            Some(vec![
                "authorization_code".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string()
            ])
        );
        assert_eq!(entry.client_id_metadata_document_supported, Some(true));
        assert_eq!(
            entry.token_endpoint_auth_methods_supported,
            Some(vec!["none".to_string(), "private_key_jwt".to_string()])
        );
        assert_eq!(
            entry.code_challenge_methods_supported,
            Some(vec!["S256".to_string()])
        );
    }

    #[test]
    fn metadata_source_explicit_accepts_registration_endpoint_from_caller() {
        let entry = IssuerEntry::from_metadata_source(
            "/mcp",
            AuthorizationServerMetadataSource::Explicit(AuthorizationServerMetadata {
                issuer: "https://issuer.test".to_string(),
                authorization_endpoint: "https://issuer.test/auth".to_string(),
                token_endpoint: "https://issuer.test/token".to_string(),
                registration_endpoint: Some("https://issuer.test/register".to_string()),
                jwks_uri: None,
                introspection_endpoint: None,
                device_authorization_endpoint: None,
                grant_types_supported: None,
                client_id_metadata_document_supported: None,
                token_endpoint_auth_methods_supported: None,
                code_challenge_methods_supported: None,
            }),
            "test",
            vec!["ops:read".to_string()],
            HashSet::new(),
            test_authenticator(),
            Some("https://example.com/mcp".to_string()),
        )
        .expect("entry from explicit metadata");
        assert_eq!(
            entry.registration_endpoint.as_deref(),
            Some("https://issuer.test/register")
        );
    }

    #[test]
    fn error_code_mapping_limits_to_rfc6750() {
        assert_eq!(
            error_code_for_error(&AuthError::MissingToken),
            Some("invalid_request")
        );
        assert_eq!(
            error_code_for_error(&AuthError::InvalidToken),
            Some("invalid_token")
        );
        assert_eq!(
            error_code_for_error(&AuthError::MissingScopes),
            Some("insufficient_scope")
        );

        let generic = AuthError::new("missing").with_reason("missing");
        assert_eq!(error_code_for_error(&generic), Some("invalid_token"));

        let generic_unknown = AuthError::new("nope").with_reason("other");
        assert_eq!(
            error_code_for_error(&generic_unknown),
            Some("invalid_token")
        );

        let generic_forbidden = AuthError::new("forbidden")
            .with_status(StatusCode::FORBIDDEN.as_u16())
            .with_reason("other");
        assert_eq!(error_code_for_error(&generic_forbidden), None);
    }

    #[tokio::test]
    async fn public_paths_and_prefixes_bypass_auth() {
        let entry = IssuerEntry {
            resource_path: "/mcp".to_string(),
            issuer: "https://issuer.test".to_string(),
            authorization_endpoint: "https://issuer.test/auth".to_string(),
            token_endpoint: "https://issuer.test/token".to_string(),
            registration_endpoint: None,
            jwks_uri: None,
            introspection_endpoint: None,
            device_authorization_endpoint: None,
            grant_types_supported: None,
            client_id_metadata_document_supported: None,
            token_endpoint_auth_methods_supported: None,
            code_challenge_methods_supported: None,
            realm: "test".to_string(),
            scopes_supported: Vec::new(),
            allowed_client_ids: HashSet::new(),
            authenticator: test_authenticator(),
            resource_url_override: Some("https://example.com/mcp".to_string()),
        };
        let mut public_paths = HashSet::new();
        public_paths.insert("/health".to_string());
        let public_prefixes = vec!["/metrics".to_string()];

        let registry = IssuerRegistry::new(AuthSurfaceConfig {
            public_base_url: "https://example.com".to_string(),
            entries: vec![entry],
            root_alias_policy: RootAliasPolicy::Disabled,
            public_paths,
            public_prefixes,
            allow_insecure_http: false,
        })
        .expect("registry");

        let counter = Arc::new(Mutex::new(0usize));
        let counter_clone = counter.clone();
        let inner = service_fn(move |_req: Request<Body>| {
            let counter = counter_clone.clone();
            async move {
                let mut guard = counter.lock().expect("lock");
                *guard += 1;
                Ok::<_, Infallible>(Response::new(Body::from("ok")))
            }
        });

        let mut service = AuthSurfaceLayer::new(registry).layer(inner);

        let response = service
            .call(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let response = service
            .call(
                Request::builder()
                    .uri("/metrics/snapshot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        assert_eq!(*counter.lock().expect("lock"), 2);
    }

    #[tokio::test]
    async fn encoded_protected_paths_still_require_auth() {
        let entry = IssuerEntry {
            resource_path: "/mcp".to_string(),
            issuer: "https://issuer.test".to_string(),
            authorization_endpoint: "https://issuer.test/auth".to_string(),
            token_endpoint: "https://issuer.test/token".to_string(),
            registration_endpoint: None,
            jwks_uri: None,
            introspection_endpoint: None,
            device_authorization_endpoint: None,
            grant_types_supported: None,
            client_id_metadata_document_supported: None,
            token_endpoint_auth_methods_supported: None,
            code_challenge_methods_supported: None,
            realm: "test".to_string(),
            scopes_supported: Vec::new(),
            allowed_client_ids: HashSet::new(),
            authenticator: test_authenticator(),
            resource_url_override: Some("https://example.com/mcp".to_string()),
        };

        let registry = IssuerRegistry::new(AuthSurfaceConfig {
            public_base_url: "https://example.com".to_string(),
            entries: vec![entry],
            root_alias_policy: RootAliasPolicy::Disabled,
            public_paths: HashSet::new(),
            public_prefixes: Vec::new(),
            allow_insecure_http: false,
        })
        .expect("registry");

        let counter = Arc::new(Mutex::new(0usize));
        let counter_clone = counter.clone();
        let inner = service_fn(move |_req: Request<Body>| {
            let counter = counter_clone.clone();
            async move {
                let mut guard = counter.lock().expect("lock");
                *guard += 1;
                Ok::<_, Infallible>(Response::new(Body::from("ok")))
            }
        });

        let mut service = AuthSurfaceLayer::new(registry).layer(inner);

        for path in ["/mcp%2Ftools", "//mcp///tools", "/public/%2E%2E/mcp/tools"] {
            let response = service
                .call(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }

        assert_eq!(*counter.lock().expect("lock"), 0);
    }

    #[tokio::test]
    async fn auth_failure_observer_receives_protected_route_failures() {
        let entry = IssuerEntry {
            resource_path: "/mcp".to_string(),
            issuer: "https://issuer.test".to_string(),
            authorization_endpoint: "https://issuer.test/auth".to_string(),
            token_endpoint: "https://issuer.test/token".to_string(),
            registration_endpoint: None,
            jwks_uri: None,
            introspection_endpoint: None,
            device_authorization_endpoint: None,
            grant_types_supported: None,
            client_id_metadata_document_supported: None,
            token_endpoint_auth_methods_supported: None,
            code_challenge_methods_supported: None,
            realm: "test".to_string(),
            scopes_supported: vec!["openid".to_string(), "profile".to_string()],
            allowed_client_ids: HashSet::new(),
            authenticator: test_authenticator(),
            resource_url_override: Some("https://example.com/mcp".to_string()),
        };
        let observer = Arc::new(RecordingAuthFailureObserver::default());
        let observer_for_assertion = observer.clone();
        let inner = service_fn(move |_req: Request<Body>| async {
            Ok::<_, Infallible>(Response::new(Body::from("ok")))
        });

        let mut service = AuthSurfaceLayer::from_config_with_observer(
            AuthSurfaceConfig {
                public_base_url: "https://example.com".to_string(),
                entries: vec![entry],
                root_alias_policy: RootAliasPolicy::Disabled,
                public_paths: HashSet::new(),
                public_prefixes: Vec::new(),
                allow_insecure_http: false,
            },
            observer,
        )
        .expect("layer")
        .layer(inner);

        let response = service
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            *observer_for_assertion.events.lock().expect("lock"),
            vec![RecordedAuthFailure {
                method: "POST".to_string(),
                path: "/mcp".to_string(),
                resource_path: "/mcp".to_string(),
                resource_url: "https://example.com/mcp".to_string(),
                reason: Some("invalid_request"),
                has_authorization: false,
            }]
        );
    }

    #[tokio::test]
    async fn unmatched_routes_are_denied_by_default() {
        let entry = IssuerEntry {
            resource_path: "/mcp".to_string(),
            issuer: "https://issuer.test".to_string(),
            authorization_endpoint: "https://issuer.test/auth".to_string(),
            token_endpoint: "https://issuer.test/token".to_string(),
            registration_endpoint: None,
            jwks_uri: None,
            introspection_endpoint: None,
            device_authorization_endpoint: None,
            grant_types_supported: None,
            client_id_metadata_document_supported: None,
            token_endpoint_auth_methods_supported: None,
            code_challenge_methods_supported: None,
            realm: "test".to_string(),
            scopes_supported: Vec::new(),
            allowed_client_ids: HashSet::new(),
            authenticator: test_authenticator(),
            resource_url_override: Some("https://example.com/mcp".to_string()),
        };
        let counter = Arc::new(Mutex::new(0usize));
        let counter_clone = counter.clone();
        let inner = service_fn(move |_req: Request<Body>| {
            let counter = counter_clone.clone();
            async move {
                let mut guard = counter.lock().expect("lock");
                *guard += 1;
                Ok::<_, Infallible>(Response::new(Body::from("ok")))
            }
        });

        let mut service = AuthSurfaceLayer::from_config(AuthSurfaceConfig {
            public_base_url: "https://example.com".to_string(),
            entries: vec![entry],
            root_alias_policy: RootAliasPolicy::Disabled,
            public_paths: HashSet::new(),
            public_prefixes: Vec::new(),
            allow_insecure_http: false,
        })
        .expect("layer")
        .layer(inner);
        let response = service
            .call(
                Request::builder()
                    .uri("/admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(*counter.lock().expect("lock"), 0);
    }

    #[tokio::test]
    async fn unmatched_routes_can_pass_through_explicitly() {
        let entry = IssuerEntry {
            resource_path: "/mcp".to_string(),
            issuer: "https://issuer.test".to_string(),
            authorization_endpoint: "https://issuer.test/auth".to_string(),
            token_endpoint: "https://issuer.test/token".to_string(),
            registration_endpoint: None,
            jwks_uri: None,
            introspection_endpoint: None,
            device_authorization_endpoint: None,
            grant_types_supported: None,
            client_id_metadata_document_supported: None,
            token_endpoint_auth_methods_supported: None,
            code_challenge_methods_supported: None,
            realm: "test".to_string(),
            scopes_supported: Vec::new(),
            allowed_client_ids: HashSet::new(),
            authenticator: test_authenticator(),
            resource_url_override: Some("https://example.com/mcp".to_string()),
        };
        let mut public_paths = HashSet::new();
        public_paths.insert("/health".to_string());

        let mut service = AuthSurfaceLayer::from_config_with_unmatched_route_policy(
            AuthSurfaceConfig {
                public_base_url: "https://example.com".to_string(),
                entries: vec![entry],
                root_alias_policy: RootAliasPolicy::Disabled,
                public_paths,
                public_prefixes: vec!["/metrics".to_string()],
                allow_insecure_http: false,
            },
            UnmatchedRoutePolicy::PassThrough,
        )
        .expect("layer")
        .layer(service_fn(|_req: Request<Body>| async move {
            Ok::<_, Infallible>(Response::new(Body::from("ok")))
        }));

        let response = service
            .call(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let response = service
            .call(
                Request::builder()
                    .uri("/metrics/snapshot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let response = service
            .call(
                Request::builder()
                    .uri("/admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn registry_deny_mode_rejects_unmatched_routes() {
        let entry = IssuerEntry {
            resource_path: "/mcp".to_string(),
            issuer: "https://issuer.test".to_string(),
            authorization_endpoint: "https://issuer.test/auth".to_string(),
            token_endpoint: "https://issuer.test/token".to_string(),
            registration_endpoint: None,
            jwks_uri: None,
            introspection_endpoint: None,
            device_authorization_endpoint: None,
            grant_types_supported: None,
            client_id_metadata_document_supported: None,
            token_endpoint_auth_methods_supported: None,
            code_challenge_methods_supported: None,
            realm: "test".to_string(),
            scopes_supported: Vec::new(),
            allowed_client_ids: HashSet::new(),
            authenticator: test_authenticator(),
            resource_url_override: Some("https://example.com/mcp".to_string()),
        };

        let registry = IssuerRegistry::new_with_unmatched_route_policy(
            AuthSurfaceConfig {
                public_base_url: "https://example.com".to_string(),
                entries: vec![entry],
                root_alias_policy: RootAliasPolicy::Disabled,
                public_paths: HashSet::new(),
                public_prefixes: Vec::new(),
                allow_insecure_http: false,
            },
            UnmatchedRoutePolicy::Deny,
        )
        .expect("registry");

        let counter = Arc::new(Mutex::new(0usize));
        let counter_clone = counter.clone();
        let inner = service_fn(move |_req: Request<Body>| {
            let counter = counter_clone.clone();
            async move {
                let mut guard = counter.lock().expect("lock");
                *guard += 1;
                Ok::<_, Infallible>(Response::new(Body::from("ok")))
            }
        });

        let mut service = AuthSurfaceLayer::new(registry).layer(inner);
        let response = service
            .call(
                Request::builder()
                    .uri("/admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(*counter.lock().expect("lock"), 0);
    }
}
