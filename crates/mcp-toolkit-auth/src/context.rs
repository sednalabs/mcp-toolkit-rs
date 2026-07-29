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
//! * **Credential Provenance**: Distinguishes authenticator-issued results from
//!   context-shaped data supplied by another component.
//! * **Data Sensitivity**: `Debug` implementation avoids logging the `raw_token` field.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Treating bare `AuthContext` values as data rather than authentication proof.
//! * Using the auth surface's current request witness for HTTP policy decisions.
//!
//! ## References
//! * `crate::authenticator::Authenticator`

use std::sync::Arc;

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

/// Authentication context issued by [`crate::Authenticator`].
///
/// Unlike [`AuthContext`], this wrapper has no public constructor. It is a
/// provenance witness for callers that must distinguish an authenticator
/// result from context-shaped data supplied by another component. The wrapped
/// context remains available for ordinary authorization and routing; callers
/// must not treat a bare [`AuthContext`] as proof that authentication occurred.
///
/// # Security
/// Authenticator provenance is reusable credential-verification state, not
/// proof that a particular HTTP request passed the auth surface. HTTP policy
/// enforcement must consume the separate request-bound auth-surface witness.
#[derive(Clone)]
pub struct VerifiedAuthContext {
    context: AuthContext,
    authenticator_marker: Arc<u8>,
    request_marker: Option<Arc<()>>,
}

impl VerifiedAuthContext {
    pub(crate) fn from_authenticator(context: AuthContext, authenticator_marker: Arc<u8>) -> Self {
        Self {
            context,
            authenticator_marker,
            request_marker: None,
        }
    }

    pub(crate) fn bind_to_request(&mut self, request_marker: Arc<()>) {
        self.request_marker = Some(request_marker);
    }

    pub(crate) fn is_bound_to_request(&self, request_marker: &Arc<()>) -> bool {
        self.request_marker
            .as_ref()
            .is_some_and(|bound_marker| Arc::ptr_eq(bound_marker, request_marker))
    }

    /// Borrows the authenticated request data.
    ///
    /// # Security
    /// The returned [`AuthContext`] is useful for authorization and routing,
    /// but cloning or reconstructing it does not preserve this wrapper's
    /// authenticator-issued provenance.
    pub fn context(&self) -> &AuthContext {
        &self.context
    }

    /// Returns the authenticated request data while consuming its witness.
    ///
    /// # Security
    /// The returned [`AuthContext`] no longer carries authenticator-issued
    /// provenance. Retain `Self` when a downstream operation requires that
    /// provenance.
    pub fn into_context(self) -> AuthContext {
        self.context
    }

    /// Checks whether this context was issued by the supplied authenticator.
    ///
    /// # Security
    /// This proves only which authenticator issued the credential result. It
    /// does not prove that the current request passed through the auth surface.
    /// Request authorization must additionally consume the auth surface's
    /// request-bound witness.
    pub fn is_issued_by(&self, authenticator: &crate::Authenticator) -> bool {
        Arc::ptr_eq(&self.authenticator_marker, &authenticator.provenance_marker)
    }
}

impl std::fmt::Debug for VerifiedAuthContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("VerifiedAuthContext")
            .field(&self.context)
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

/// Retrieves a context issued by the expected authenticator.
///
/// # Security
/// Returns `None` for a bare [`AuthContext`] or for a witness issued by an
/// independent authenticator. Authenticator provenance alone is not a
/// request-authorization result; HTTP policy gates must additionally consume
/// the auth surface's request-bound witness.
pub fn verified_auth_context_from_parts(
    parts: &http::request::Parts,
    authenticator: &crate::Authenticator,
) -> Option<VerifiedAuthContext> {
    verified_auth_context_ref_from_parts(parts, authenticator).cloned()
}

/// Borrows a context issued by the expected authenticator.
///
/// # Security
/// Returns `None` for a bare [`AuthContext`] or for a witness issued by an
/// independent authenticator. Authenticator provenance alone is not a
/// request-authorization result; HTTP policy gates must additionally consume
/// the auth surface's request-bound witness.
pub fn verified_auth_context_ref_from_parts<'a>(
    parts: &'a http::request::Parts,
    authenticator: &crate::Authenticator,
) -> Option<&'a VerifiedAuthContext> {
    parts
        .extensions
        .get::<VerifiedAuthContext>()
        .filter(|context| context.is_issued_by(authenticator))
}
