//! # MCP Toolkit Auth
//!
//! Authentication and Authorization primitives for MCP servers.
//!
//! ## Ownership
//! This module owns the authentication lifecycle, including token validation (JWT/OIDC),
//! OAuth 2.0 flow orchestration, and authorization context generation.
//!
//! ## Non-ownership
//! This module does not manage long-term user identity stores, password hashing,
//! or TLS-layer transport security.
//!
//! ## Policy & Guarantees
//! * **Token Validation**: Enforces cryptographic signature checks and standard JWT
//!   invariants (issuer, audience, expiration).
//! * **Flow Orchestration**: Manages OAuth2 flows to reduce the risk of manual implementation errors.
//! * **Capability Enforcement**: Provides mechanisms to bind security context to tool calls.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying secure, environment-specific `AuthConfig` (e.g., secrets, OIDC metadata URLs).
//! * Enforcing context-based authorization decisions at the tool or resource level.
//! * Providing transport-layer security (TLS) for sensitive authentication exchanges.
//!
//! ## References
//! * RFC 6749: OAuth 2.0 Authorization Framework.
//! * [OpenID Connect Core 1.0].

pub mod bearer;
pub mod challenge;
pub mod surface;

mod authenticator;
mod claims;
mod config;
mod context;
mod error;
mod providers;
mod replay;
mod util;

pub use authenticator::Authenticator;
pub use bearer::{parse_strict_bearer_authorization, BearerParseError, BearerToken};
pub use config::{
    discover_oidc_metadata, AuthConfig, AuthMode, AuthRequestContext, AuthSecurityProfile,
    ClientAuthMethod, OidcDiscovery,
};
pub use context::{auth_context_from_parts, auth_context_ref_from_parts, AuthContext};
pub use error::{AuthError, AuthErrorContract};
pub use mcp_toolkit_http::oauth::AuthorizationServerMetadata;
pub use replay::{
    InMemoryJtiReplayStore, JtiCache, JtiReplayStore, JtiReplayStoreError, SharedJtiReplayStore,
};

#[cfg(test)]
mod internal_tests;
