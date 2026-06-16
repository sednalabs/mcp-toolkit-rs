//! # Scratchpad Error Model
//!
//! Contract-friendly errors for reusable DuckDB scratchpad operations.

use thiserror::Error;

use super::sql_safety::ScratchpadSqlPolicyCode;

#[derive(Debug, Error)]
pub enum ScratchpadError {
    #[error("invalid {field}: {message}")]
    InvalidArgument {
        field: &'static str,
        message: String,
    },

    #[error("scratchpad engine error: {0}")]
    ScratchpadEngine(String),

    #[error("scratchpad limit exceeded for {field}: {message}")]
    ScratchpadLimitExceeded {
        field: &'static str,
        message: String,
    },

    #[error("scratchpad sql rejected ({policy_code}): {message}")]
    ScratchpadSqlRejected {
        policy_code: ScratchpadSqlPolicyCode,
        message: String,
    },

    #[error("scratchpad query timed out after {timeout_ms}ms")]
    ScratchpadQueryTimeout { timeout_ms: u64 },

    #[error("scratchpad query cancelled")]
    ScratchpadQueryCancelled,

    #[error("scratchpad session not found: {session_id}")]
    ScratchpadSessionNotFound { session_id: String },

    #[error("internal error: {0}")]
    Internal(String),
}

impl ScratchpadError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidArgument { .. } => "INVALID_PARAMS",
            Self::ScratchpadEngine(_) => "SCRATCHPAD_ENGINE_ERROR",
            Self::ScratchpadLimitExceeded { .. } => "SCRATCHPAD_LIMIT_EXCEEDED",
            Self::ScratchpadSqlRejected { .. } => "SCRATCHPAD_SQL_REJECTED",
            Self::ScratchpadQueryTimeout { .. } => "SCRATCHPAD_QUERY_TIMEOUT",
            Self::ScratchpadQueryCancelled => "SCRATCHPAD_QUERY_CANCELLED",
            Self::ScratchpadSessionNotFound { .. } => "SCRATCHPAD_SESSION_NOT_FOUND",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            Self::InvalidArgument { .. } => "invalid_params",
            Self::ScratchpadLimitExceeded { .. } => "scratchpad_limit_exceeded",
            Self::ScratchpadEngine(_) => "scratchpad_engine_error",
            Self::ScratchpadSqlRejected { .. } => "scratchpad_sql_restricted",
            Self::ScratchpadQueryTimeout { .. } => "scratchpad_timeout",
            Self::ScratchpadQueryCancelled => "scratchpad_cancelled",
            Self::ScratchpadSessionNotFound { .. } => "scratchpad_session_not_found",
            Self::Internal(_) => "internal_error",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            Self::InvalidArgument { .. } => "validation",
            Self::ScratchpadLimitExceeded { .. }
            | Self::ScratchpadEngine(_)
            | Self::ScratchpadSqlRejected { .. }
            | Self::ScratchpadQueryTimeout { .. }
            | Self::ScratchpadQueryCancelled
            | Self::ScratchpadSessionNotFound { .. } => "scratchpad",
            Self::Internal(_) => "internal",
        }
    }

    pub fn engine_code(&self) -> Option<String> {
        match self {
            Self::ScratchpadEngine(_) => Some("duckdb".to_string()),
            Self::ScratchpadSqlRejected { policy_code, .. } => {
                Some(policy_code.as_str().to_string())
            }
            _ => None,
        }
    }

    pub fn detail(&self) -> Option<String> {
        match self {
            Self::InvalidArgument { field, .. } => Some(format!("field={field}")),
            Self::ScratchpadLimitExceeded { field, .. } => Some(format!("field={field}")),
            Self::ScratchpadQueryTimeout { timeout_ms } => Some(format!("timeout_ms={timeout_ms}")),
            Self::ScratchpadSessionNotFound { session_id } => {
                Some(format!("session_id={session_id}"))
            }
            _ => None,
        }
    }

    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Self::InvalidArgument { .. } => Some("Check the tool argument schema and required fields."),
            Self::ScratchpadEngine(_) => {
                Some("Check DuckDB runtime availability and server scratchpad configuration.")
            }
            Self::ScratchpadLimitExceeded { .. } => {
                Some("Release sessions/tables or reduce input size before retrying.")
            }
            Self::ScratchpadSqlRejected { .. } => {
                Some("Use read-only SELECT/WITH/EXPLAIN/DESCRIBE/SUMMARIZE queries only.")
            }
            Self::ScratchpadQueryTimeout { .. } => {
                Some("Reduce query complexity or increase scratchpad query timeout.")
            }
            Self::ScratchpadQueryCancelled => {
                Some("Retry the query if cancellation was not intentional.")
            }
            Self::ScratchpadSessionNotFound { .. } => {
                Some("Open the scratchpad session before querying or listing tables.")
            }
            Self::Internal(_) => None,
        }
    }

    pub fn invalid(field: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidArgument {
            field,
            message: message.into(),
        }
    }

    pub fn scratchpad_limit(field: &'static str, message: impl Into<String>) -> Self {
        Self::ScratchpadLimitExceeded {
            field,
            message: message.into(),
        }
    }

    pub fn scratchpad_sql_rejected(
        policy_code: ScratchpadSqlPolicyCode,
        message: impl Into<String>,
    ) -> Self {
        Self::ScratchpadSqlRejected {
            policy_code,
            message: message.into(),
        }
    }

    pub fn scratchpad_query_timeout(timeout: std::time::Duration) -> Self {
        let timeout_ms = timeout.as_millis();
        let timeout_ms = u64::try_from(timeout_ms).unwrap_or(u64::MAX);
        Self::ScratchpadQueryTimeout { timeout_ms }
    }

    pub fn scratchpad_query_cancelled() -> Self {
        Self::ScratchpadQueryCancelled
    }

    pub fn scratchpad_session_not_found(session_id: impl Into<String>) -> Self {
        Self::ScratchpadSessionNotFound {
            session_id: session_id.into(),
        }
    }
}
