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

use thiserror::Error;

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
    pub fn new(message: impl Into<String>) -> Self {
        Self::Generic {
            message: message.into(),
            status_code: 401,
            code: None,
            reason: None,
        }
    }

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
}
