//! # Auth Errors
//!
//! Error types for authentication and authorization failures.
//!
//! ## Ownership
//! This module owns the `AuthError` type, providing a standardized way to represent
//! and handle auth-related failures.
//!
//! ## Non-ownership
//! This module does not handle error reporting or logging; it strictly defines the
//! error vocabulary.
//!
//! ## Policy & Guarantees
//! * **Structured Errors**: Provides consistent status codes, error codes, and reason
//!   strings for downstream handling.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Mapping these errors to appropriate transport-level responses.
//! * Ensuring that detailed error messages are only exposed to appropriate logging
//!   or debugging endpoints.

use std::borrow::Cow;

use thiserror::Error;

/// Stable transport and policy contract for an authentication failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthErrorContract<'a> {
    /// HTTP status to emit for the failure.
    pub status_code: u16,
    /// Stable internal decision code for policy, logs, and observers.
    pub decision_code: &'static str,
    /// RFC 6750 Bearer `error` parameter, when the status supports a challenge.
    pub bearer_error: Option<&'static str>,
    /// Low-leakage Bearer `error_description`, when safe to expose.
    pub error_description: Option<&'static str>,
    /// Public response body text.
    pub public_message: Cow<'a, str>,
}

/// Authentication and authorization failures.
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Authentication failed: {message}")]
    Generic {
        message: String,
        status_code: u16,
        code: Option<&'static str>,
        reason: Option<&'static str>,
    },
    #[error("Missing bearer token")]
    MissingToken,
    #[error("Invalid bearer token")]
    InvalidToken,
    #[error("Token expired")]
    TokenExpired,
    #[error("Token replay detected")]
    ReplayDetected,
    #[error("Missing required scopes")]
    MissingScopes,
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl AuthError {
    /// Builds a generic authentication failure.
    pub fn new(message: impl Into<String>) -> Self {
        Self::Generic {
            message: message.into(),
            status_code: 401,
            code: None,
            reason: None,
        }
    }

    /// Attaches a stable internal decision code to a generic auth failure.
    pub fn with_code(self, new_code: &'static str) -> Self {
        match self {
            Self::Generic {
                message,
                status_code,
                code: _,
                reason,
            } => Self::Generic {
                message,
                status_code,
                code: Some(new_code),
                reason,
            },
            _ => self,
        }
    }

    /// Attaches a stable reason string to a generic auth failure.
    pub fn with_reason(self, new_reason: &'static str) -> Self {
        match self {
            Self::Generic {
                message,
                status_code,
                code,
                reason: _,
            } => Self::Generic {
                message,
                status_code,
                code,
                reason: Some(new_reason),
            },
            _ => self,
        }
    }

    /// Overrides the HTTP status for a generic auth failure.
    pub fn with_status(self, new_status: u16) -> Self {
        match self {
            Self::Generic {
                message,
                status_code: _,
                code,
                reason,
            } => Self::Generic {
                message,
                status_code: new_status,
                code,
                reason,
            },
            _ => self,
        }
    }

    /// Returns the stable auth error contract for this failure.
    pub fn contract(&self) -> AuthErrorContract<'_> {
        match self {
            Self::MissingToken => AuthErrorContract {
                status_code: 401,
                decision_code: "MISSING_BEARER_TOKEN",
                bearer_error: Some("invalid_request"),
                error_description: Some("missing token"),
                public_message: Cow::Borrowed("missing token"),
            },
            Self::InvalidToken => AuthErrorContract {
                status_code: 401,
                decision_code: "INVALID_BEARER_TOKEN",
                bearer_error: Some("invalid_token"),
                error_description: None,
                public_message: Cow::Borrowed("invalid token"),
            },
            Self::TokenExpired => AuthErrorContract {
                status_code: 401,
                decision_code: "TOKEN_EXPIRED",
                bearer_error: Some("invalid_token"),
                error_description: Some("token expired"),
                public_message: Cow::Borrowed("token expired"),
            },
            Self::ReplayDetected => AuthErrorContract {
                status_code: 401,
                decision_code: "TOKEN_REPLAY_DETECTED",
                bearer_error: Some("invalid_token"),
                error_description: Some("token replay detected"),
                public_message: Cow::Borrowed("token replay detected"),
            },
            Self::MissingScopes => AuthErrorContract {
                status_code: 403,
                decision_code: "INSUFFICIENT_SCOPE",
                bearer_error: Some("insufficient_scope"),
                error_description: Some("missing scopes"),
                public_message: Cow::Borrowed("missing scopes"),
            },
            Self::ConfigError(message) => AuthErrorContract {
                status_code: 500,
                decision_code: "AUTH_CONFIG_ERROR",
                bearer_error: None,
                error_description: None,
                public_message: Cow::Borrowed(message.as_str()),
            },
            Self::Generic {
                message,
                status_code,
                code,
                reason,
            } => AuthErrorContract {
                status_code: *status_code,
                decision_code: (*code)
                    .unwrap_or_else(|| decision_code_for_generic(*status_code, *reason)),
                bearer_error: bearer_error_for_generic(*status_code, *reason),
                error_description: None,
                public_message: Cow::Borrowed(message.as_str()),
            },
        }
    }

    /// Returns the HTTP status from the stable auth error contract.
    pub fn status_code(&self) -> u16 {
        self.contract().status_code
    }

    /// Returns the internal decision code from the stable auth error contract.
    pub fn decision_code(&self) -> &'static str {
        self.contract().decision_code
    }

    /// Returns the RFC 6750 Bearer `error` parameter, when applicable.
    pub fn bearer_error(&self) -> Option<&'static str> {
        self.contract().bearer_error
    }

    /// Returns a low-leakage Bearer `error_description`, when applicable.
    pub fn bearer_error_description(&self) -> Option<&'static str> {
        self.contract().error_description
    }

    /// Returns the public response body text.
    pub fn public_message(&self) -> Cow<'_, str> {
        self.contract().public_message
    }
}

fn decision_code_for_generic(status_code: u16, reason: Option<&'static str>) -> &'static str {
    match reason {
        Some("invalid_audience" | "invalid_issuer" | "issuer_mismatch") => {
            "TOKEN_ISSUER_OR_AUDIENCE_MISMATCH"
        }
        Some("invalid_token" | "invalid_signature" | "invalid_algorithm" | "invalid_key")
        | Some("missing_kid" | "kid_not_found" | "invalid_key_use" | "immature_signature") => {
            "INVALID_BEARER_TOKEN"
        }
        Some("invalid_subject" | "missing_claim") => "MALFORMED_BEARER_TOKEN",
        Some("insufficient_scope" | "missing_scopes") => "INSUFFICIENT_SCOPE",
        Some("client_not_allowed") => "AUTH_CLIENT_NOT_ALLOWED",
        Some("policy_denied" | "forbidden") => "AUTH_POLICY_DENIED",
        _ => match status_code {
            400 => "MALFORMED_BEARER_TOKEN",
            401 => "INVALID_BEARER_TOKEN",
            403 => "AUTH_POLICY_DENIED",
            500..=599 => "AUTH_INTERNAL_ERROR",
            _ => "AUTH_FAILURE",
        },
    }
}

fn bearer_error_for_generic(
    status_code: u16,
    reason: Option<&'static str>,
) -> Option<&'static str> {
    match reason {
        Some("invalid_request") => Some("invalid_request"),
        Some(
            "invalid_token" | "invalid_audience" | "invalid_issuer" | "issuer_mismatch"
            | "invalid_subject" | "missing_claim" | "immature_signature" | "invalid_signature"
            | "invalid_algorithm" | "invalid_key" | "missing_kid" | "kid_not_found"
            | "invalid_key_use",
        ) => Some("invalid_token"),
        Some(
            "insufficient_scope" | "missing_scopes" | "client_not_allowed" | "policy_denied"
            | "forbidden",
        ) => Some("insufficient_scope"),
        _ => match status_code {
            400 => Some("invalid_request"),
            401 => Some("invalid_token"),
            403 => Some("insufficient_scope"),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::AuthError;

    #[test]
    fn explicit_failures_have_stable_contract_codes() {
        let cases = [
            (
                AuthError::MissingToken,
                401,
                "MISSING_BEARER_TOKEN",
                Some("invalid_request"),
                Some("missing token"),
            ),
            (
                AuthError::InvalidToken,
                401,
                "INVALID_BEARER_TOKEN",
                Some("invalid_token"),
                None,
            ),
            (
                AuthError::TokenExpired,
                401,
                "TOKEN_EXPIRED",
                Some("invalid_token"),
                Some("token expired"),
            ),
            (
                AuthError::ReplayDetected,
                401,
                "TOKEN_REPLAY_DETECTED",
                Some("invalid_token"),
                Some("token replay detected"),
            ),
            (
                AuthError::MissingScopes,
                403,
                "INSUFFICIENT_SCOPE",
                Some("insufficient_scope"),
                Some("missing scopes"),
            ),
        ];

        for (error, status, decision_code, bearer_error, description) in cases {
            let contract = error.contract();
            assert_eq!(contract.status_code, status);
            assert_eq!(contract.decision_code, decision_code);
            assert_eq!(contract.bearer_error, bearer_error);
            assert_eq!(contract.error_description, description);
        }
    }

    #[test]
    fn generic_reasons_map_to_canonical_codes_without_null_placeholders() {
        let issuer = AuthError::new("Invalid bearer token.").with_reason("invalid_issuer");
        assert_eq!(issuer.decision_code(), "TOKEN_ISSUER_OR_AUDIENCE_MISMATCH");
        assert_eq!(issuer.bearer_error(), Some("invalid_token"));

        let malformed = AuthError::new("Invalid bearer token.").with_reason("missing_claim");
        assert_eq!(malformed.decision_code(), "MALFORMED_BEARER_TOKEN");
        assert_eq!(malformed.bearer_error(), Some("invalid_token"));

        let policy = AuthError::new("forbidden")
            .with_status(403)
            .with_reason("policy_denied");
        assert_eq!(policy.decision_code(), "AUTH_POLICY_DENIED");
        assert_eq!(policy.bearer_error(), Some("insufficient_scope"));
    }

    #[test]
    fn explicit_generic_code_wins_for_service_specific_denials() {
        let error = AuthError::new("client_id is not allowed for this service")
            .with_status(403)
            .with_code("AUTH_CLIENT_NOT_ALLOWED")
            .with_reason("client_not_allowed");
        let contract = error.contract();
        assert_eq!(contract.status_code, 403);
        assert_eq!(contract.decision_code, "AUTH_CLIENT_NOT_ALLOWED");
        assert_eq!(contract.bearer_error, Some("insufficient_scope"));
    }
}
