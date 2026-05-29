//! Delegation Token Validation
//!
//! Internal provider for handling and validating delegation-based authentication
//! tokens.
//!
//! ## Rationale
//! Enables secure cross-service authentication where a primary service delegates
//! authorization to a downstream MCP component via a shared-secret signed token.
//!
//! ## Security Boundaries
//! * **Secret Enforcement**: Requires an explicit, server-side secret configuration for validation.
//! * **Policy Enforcement**: Strictly validates OIDC/JWT claims (issuer, audience, leeway) against pre-configured policy invariants.
//! * **Algorithm Restriction**: Hard-coded to `HS256` to prevent algorithm confusion attacks.
//!
//! ## References
//! * [RFC 7519] JSON Web Token (JWT).

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::Value;

use crate::claims::{auth_error_from_jwt, required_claims};
use crate::{AuthError, Authenticator};

impl Authenticator {
    /// Validates and decodes a delegation token using the configured secret.
    ///
    /// # Errors
    /// * Returns `AuthError::ConfigError` if the delegation secret is missing.
    /// * Returns `AuthError` if token signature verification fails, claims are invalid,
    ///   or the token is expired/not yet valid.
    ///
    /// # Security
    /// * **Algorithm Hard-coding**: Uses `HS256` to prevent algorithm confusion attacks.
    /// * **Invariant Validation**: Enforces issuer, audience, and time-leeway checks to ensure
    ///   the token is both authentic and intended for this service.
    pub(crate) fn decode_delegation(&self, token: &str) -> Result<Value, AuthError> {
        let secret = self.config.delegation_secret.as_ref().ok_or_else(|| {
            AuthError::ConfigError("Delegation secret not configured.".to_string())
        })?;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims = required_claims();
        validation.set_issuer(std::slice::from_ref(&self.config.delegation_issuer));
        validation.set_audience(std::slice::from_ref(&self.config.delegation_audience));
        validation.leeway = self.config.clock_skew_s as u64;
        decode::<Value>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .map(|data| data.claims)
        .map_err(auth_error_from_jwt)
    }
}
