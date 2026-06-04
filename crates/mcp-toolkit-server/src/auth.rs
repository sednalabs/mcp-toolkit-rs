//! # Auth Surface Composition
//!
//! Builder helpers for turning caller-owned issuer metadata into an HTTP auth
//! surface layer.
//!
//! ## Rationale
//! Hosted MCP servers repeatedly normalize public paths, public prefixes,
//! insecure-local metadata policy, and unmatched-route behavior around
//! `AuthSurfaceConfig`.
//!
//! ## Security Boundaries
//! * This module does not create authenticators or choose issuer metadata.
//! * HTTPS is preserved by default; insecure HTTP is only enabled explicitly or
//!   through the same local-detection helper exposed by `mcp-toolkit-auth`.
//! * Tool-level authorization stays in service crates.
//!
//! ## References
//! * **AUTH**: `docs/auth-surface.md`

use std::collections::HashSet;

pub use mcp_toolkit_auth::surface::{
    AuthSurfaceConfig, AuthSurfaceError, AuthSurfaceLayer, IssuerEntry, RootAliasPolicy,
    UnmatchedRoutePolicy,
};

/// Builder for a single auth-surface configuration.
#[derive(Debug, Clone)]
pub struct AuthSurfaceBuilder {
    config: AuthSurfaceConfig,
    unmatched_route_policy: UnmatchedRoutePolicy,
    detect_insecure_http: bool,
}

impl AuthSurfaceBuilder {
    /// Builds an auth-surface builder from a complete configuration.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Callers must ensure the supplied issuer entries and authenticators match
    /// their deployment policy.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(config: AuthSurfaceConfig) -> Self {
        Self {
            config,
            unmatched_route_policy: UnmatchedRoutePolicy::Deny,
            detect_insecure_http: false,
        }
    }

    /// Builds a single-issuer auth-surface builder.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Callers must supply an issuer entry whose authenticator validates the
    /// configured issuer and audience.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn single_issuer(public_base_url: impl Into<String>, entry: IssuerEntry) -> Self {
        Self::new(AuthSurfaceConfig::single_issuer(public_base_url, entry))
    }

    /// Sets the root alias policy.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Root aliases make discovery easier but can expose additional well-known
    /// routes. Use `RootAliasPolicy::Disabled` for multi-resource surfaces that
    /// should avoid aliases.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn root_alias_policy(mut self, policy: RootAliasPolicy) -> Self {
        self.config.root_alias_policy = policy;
        self
    }

    /// Sets how unmatched routes are handled by the auth surface.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// `PassThrough` lets routes outside protected resources reach inner
    /// services. Use it only when another router layer owns those routes.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn unmatched_route_policy(mut self, policy: UnmatchedRoutePolicy) -> Self {
        self.unmatched_route_policy = policy;
        self
    }

    /// Replaces public bypass paths.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Public paths bypass bearer enforcement. Keep the list limited to health,
    /// readiness, or non-sensitive discovery routes.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn public_paths(mut self, paths: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.config.public_paths = paths.into_iter().map(Into::into).collect();
        self
    }

    /// Adds one public bypass path.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Public paths bypass bearer enforcement. Avoid placing MCP tool or data
    /// routes here.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn public_path(mut self, path: impl Into<String>) -> Self {
        self.config.public_paths.insert(path.into());
        self
    }

    /// Replaces public bypass prefixes.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Public prefixes bypass bearer enforcement for a route family. Prefer
    /// exact paths when possible.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn public_prefixes(
        mut self,
        prefixes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.config.public_prefixes = prefixes.into_iter().map(Into::into).collect();
        self
    }

    /// Allows insecure `http://` metadata URLs.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Insecure metadata should be limited to loopback development or trusted
    /// internal deployments.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.config.allow_insecure_http = allow;
        self.detect_insecure_http = false;
        self
    }

    /// Enables local-style detection of whether insecure HTTP metadata is needed.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Detection mirrors `AuthSurfaceConfig::with_detected_allow_insecure_http`.
    /// Production services should usually prefer explicit HTTPS metadata.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn detect_insecure_http(mut self) -> Self {
        self.detect_insecure_http = true;
        self
    }

    /// Returns the configured public bypass paths.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Use this for inspection and tests; do not log sensitive route context.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn public_path_set(&self) -> &HashSet<String> {
        &self.config.public_paths
    }

    /// Builds an auth surface layer.
    ///
    /// # Errors
    /// Returns `AuthSurfaceError` when issuer metadata, route configuration, or
    /// URL validation fails.
    ///
    /// # Security
    /// The resulting layer enforces bearer authentication for protected paths
    /// configured in the supplied issuer entries. Callers remain responsible for
    /// tool-level authorization after authentication succeeds.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn build(self) -> Result<AuthSurfaceLayer, AuthSurfaceError> {
        let config = if self.detect_insecure_http {
            self.config.with_detected_allow_insecure_http()
        } else {
            self.config
        };
        AuthSurfaceLayer::from_config_with_unmatched_route_policy(
            config,
            self.unmatched_route_policy,
        )
    }

    /// Returns the assembled configuration without building a layer.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// This exposes metadata configuration for tests or advanced callers. Avoid
    /// logging values that may include private issuer URLs.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn into_config(mut self) -> AuthSurfaceConfig {
        if self.detect_insecure_http {
            self.config = self.config.with_detected_allow_insecure_http();
        }
        self.config
    }
}
