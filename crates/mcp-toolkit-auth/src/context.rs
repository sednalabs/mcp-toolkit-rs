//! # Auth Context
//!
//! MCP request authentication and authorization context.
//!
//! ## Ownership
//! This module owns the `AuthContext` structure, representing the security state
//! (actor, scopes, roles) bound to an MCP request.
//!
//! ## Non-ownership
//! This module does not manage the underlying token verification; it acts as a
//! container for metadata extracted after successful authentication.
//!
//! ## Policy & Guarantees
//! * **Context Binding**: Provides standard accessors for binding auth state
//!   to HTTP `Extensions` in middleware.
//! * **Data Sensitivity**: `Debug` implementation avoids logging the `raw_token` field.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Injecting the `AuthContext` into HTTP request extensions after validation.
//! * Ensuring the context is not mutated after binding to the request.
//!
//! ## References
//! * `crate::authenticator::Authenticator`

use serde_json::Value;

/// Authentication and authorization metadata for an MCP request.
#[derive(Clone)]
pub struct AuthContext {
    pub actor: String,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub claims: Value,
    pub azp: Option<String>,
    pub subject: Option<String>,
    pub token_ref: String,
    pub raw_token: String,
}

impl std::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthContext")
            .field("actor", &self.actor)
            .field("scopes", &self.scopes)
            .field("roles", &self.roles)
            .field("azp", &self.azp)
            .field("subject", &self.subject)
            .field("token_ref", &self.token_ref)
            .finish()
    }
}

/// Retrieves a cloned `AuthContext` from request extensions.
pub fn auth_context_from_parts(parts: &http::request::Parts) -> Option<AuthContext> {
    parts.extensions.get::<AuthContext>().cloned()
}

/// Retrieves a reference to `AuthContext` from request extensions.
pub fn auth_context_ref_from_parts(parts: &http::request::Parts) -> Option<&AuthContext> {
    parts.extensions.get::<AuthContext>()
}
