//! # Policy Decisions
//!
//! Primitives for representing and propagating authorization decisions.
//!
//! ## Ownership
//! This module owns the `Decision` envelope, `DecisionCode` taxonomy, and
//! typed decision code parsing.
//!
//! ## Non-ownership
//! This module does not evaluate policies or interact with persistent state; it
//! strictly provides the structural representation of policy results.
//!
//! ## Policy & Guarantees
//! * **Envelope Consistency**: Ensures all decisions contain a standard structure
//!   (`allow`, `code`, `reason`) for downstream enforcement.
//! * **Current API Shape**: Publishes the clean current decision envelope for new integrations.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Interpreting the returned `Decision` and applying the appropriate transport-level
//!   response (e.g., 401/403).
//! * Maintaining the `DecisionCode` catalog for shared domain failure types.
//!
//! ## References
//! * [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization.md)

use serde::{Deserialize, Serialize};

const WIRE_V1_ALLOW_CODE: &str = "ALLOW";
const WIRE_V1_ALLOW_REASON: &str = "allowed";
const WIRE_V1_FALLBACK_DENY_CODE: &str = "DENY";
const WIRE_V1_FALLBACK_DENY_REASON: &str = "denied";

/// Canonical taxonomy for policy decision codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionCode {
    MissingToken,
    MissingScopes,
    MissingRoles,
    IssuerMismatch,
    AudienceMismatch,
    AzpNotAllowed,
    InvalidPath,
    MissingRealm,
    SystemTokenForbidden,
    AllowlistDenied,
    CapabilityMissing,
    CapabilityMismatch,
    QuorumMissing,
    QuorumStale,
    EmptySql,
    UnterminatedToken,
    MultipleStatements,
    NotReadOnlyPrefix,
    ForbiddenKeyword,
    ForbiddenFunction,
    ExplainNotReadOnly,
    ClassifierUnavailable,
    SparkRuntimeUnavailable,
    InvalidInput,
}

const DECISION_CODE_CATALOG: [DecisionCode; 24] = [
    DecisionCode::MissingToken,
    DecisionCode::MissingScopes,
    DecisionCode::MissingRoles,
    DecisionCode::IssuerMismatch,
    DecisionCode::AudienceMismatch,
    DecisionCode::AzpNotAllowed,
    DecisionCode::InvalidPath,
    DecisionCode::MissingRealm,
    DecisionCode::SystemTokenForbidden,
    DecisionCode::AllowlistDenied,
    DecisionCode::CapabilityMissing,
    DecisionCode::CapabilityMismatch,
    DecisionCode::QuorumMissing,
    DecisionCode::QuorumStale,
    DecisionCode::EmptySql,
    DecisionCode::UnterminatedToken,
    DecisionCode::MultipleStatements,
    DecisionCode::NotReadOnlyPrefix,
    DecisionCode::ForbiddenKeyword,
    DecisionCode::ForbiddenFunction,
    DecisionCode::ExplainNotReadOnly,
    DecisionCode::ClassifierUnavailable,
    DecisionCode::SparkRuntimeUnavailable,
    DecisionCode::InvalidInput,
];

impl DecisionCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingToken => "MISSING_TOKEN",
            Self::MissingScopes => "MISSING_SCOPES",
            Self::MissingRoles => "MISSING_ROLES",
            Self::IssuerMismatch => "ISSUER_MISMATCH",
            Self::AudienceMismatch => "AUDIENCE_MISMATCH",
            Self::AzpNotAllowed => "AZP_NOT_ALLOWED",
            Self::InvalidPath => "INVALID_PATH",
            Self::MissingRealm => "MISSING_REALM",
            Self::SystemTokenForbidden => "SYSTEM_TOKEN_FORBIDDEN",
            Self::AllowlistDenied => "ALLOWLIST_DENIED",
            Self::CapabilityMissing => "CAPABILITY_MISSING",
            Self::CapabilityMismatch => "CAPABILITY_MISMATCH",
            Self::QuorumMissing => "QUORUM_MISSING",
            Self::QuorumStale => "QUORUM_STALE",
            Self::EmptySql => "EMPTY_SQL",
            Self::UnterminatedToken => "UNTERMINATED_TOKEN",
            Self::MultipleStatements => "MULTIPLE_STATEMENTS",
            Self::NotReadOnlyPrefix => "NOT_READ_ONLY_PREFIX",
            Self::ForbiddenKeyword => "FORBIDDEN_KEYWORD",
            Self::ForbiddenFunction => "FORBIDDEN_FUNCTION",
            Self::ExplainNotReadOnly => "EXPLAIN_NOT_READ_ONLY",
            Self::ClassifierUnavailable => "CLASSIFIER_UNAVAILABLE",
            Self::SparkRuntimeUnavailable => "SPARK_RUNTIME_UNAVAILABLE",
            Self::InvalidInput => "INVALID_INPUT",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "MISSING_TOKEN" => Some(Self::MissingToken),
            "MISSING_SCOPES" => Some(Self::MissingScopes),
            "MISSING_ROLES" => Some(Self::MissingRoles),
            "ISSUER_MISMATCH" => Some(Self::IssuerMismatch),
            "AUDIENCE_MISMATCH" => Some(Self::AudienceMismatch),
            "AZP_NOT_ALLOWED" => Some(Self::AzpNotAllowed),
            "INVALID_PATH" => Some(Self::InvalidPath),
            "MISSING_REALM" => Some(Self::MissingRealm),
            "SYSTEM_TOKEN_FORBIDDEN" => Some(Self::SystemTokenForbidden),
            "ALLOWLIST_DENIED" => Some(Self::AllowlistDenied),
            "CAPABILITY_MISSING" => Some(Self::CapabilityMissing),
            "CAPABILITY_MISMATCH" => Some(Self::CapabilityMismatch),
            "QUORUM_MISSING" => Some(Self::QuorumMissing),
            "QUORUM_STALE" => Some(Self::QuorumStale),
            "EMPTY_SQL" => Some(Self::EmptySql),
            "UNTERMINATED_TOKEN" => Some(Self::UnterminatedToken),
            "MULTIPLE_STATEMENTS" => Some(Self::MultipleStatements),
            "NOT_READ_ONLY_PREFIX" => Some(Self::NotReadOnlyPrefix),
            "FORBIDDEN_KEYWORD" => Some(Self::ForbiddenKeyword),
            "FORBIDDEN_FUNCTION" => Some(Self::ForbiddenFunction),
            "EXPLAIN_NOT_READ_ONLY" => Some(Self::ExplainNotReadOnly),
            "CLASSIFIER_UNAVAILABLE" => Some(Self::ClassifierUnavailable),
            "SPARK_RUNTIME_UNAVAILABLE" => Some(Self::SparkRuntimeUnavailable),
            "INVALID_INPUT" => Some(Self::InvalidInput),
            _ => None,
        }
    }
}

/// Returns the stable decision-code catalog.
pub fn decision_code_catalog() -> Vec<&'static str> {
    DECISION_CODE_CATALOG
        .iter()
        .map(|code| code.as_str())
        .collect()
}

/// Canonical policy decision envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub allow: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_scopes: Option<Vec<String>>,
}

/// Backward-compatible alias retained for existing policy integrations.
pub type PolicyDecision = Decision;

/// Legacy V1 wire envelope; prefer [`Decision`] for new integrations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionWireV1 {
    pub allow: bool,
    pub code: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_scopes: Option<Vec<String>>,
}

/// Error returned when a decision is denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionDenyError {
    pub code: Option<String>,
    pub reason: Option<String>,
}

impl std::fmt::Display for DecisionDenyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.code.as_deref(), self.reason.as_deref()) {
            (Some(code), Some(reason)) => write!(f, "policy denied: {code} ({reason})"),
            (Some(code), None) => write!(f, "policy denied: {code}"),
            (None, Some(reason)) => write!(f, "policy denied: {reason}"),
            (None, None) => write!(f, "policy denied"),
        }
    }
}

impl std::error::Error for DecisionDenyError {}

impl Decision {
    pub fn allow() -> Self {
        Self {
            allow: true,
            code: None,
            reason: None,
            required_scopes: None,
        }
    }

    pub fn deny(code: DecisionCode, reason: Option<&str>) -> Self {
        Self {
            allow: false,
            code: Some(code.as_str().to_string()),
            reason: reason.map(ToOwned::to_owned),
            required_scopes: None,
        }
    }

    pub fn deny_raw(code: &str, reason: Option<&str>) -> Self {
        if let Some(typed) = DecisionCode::parse(code) {
            return Self::deny(typed, reason);
        }
        Self {
            allow: false,
            code: Some(code.to_string()),
            reason: reason.map(ToOwned::to_owned),
            required_scopes: None,
        }
    }

    pub fn with_required_scopes(mut self, scopes: Vec<String>) -> Self {
        self.required_scopes = Some(scopes);
        self
    }

    pub fn ensure_allowed(self) -> Result<Self, DecisionDenyError> {
        if self.allow {
            Ok(self)
        } else {
            Err(DecisionDenyError {
                code: self.code.clone(),
                reason: self.reason.clone(),
            })
        }
    }

    pub fn to_wire_v1(&self) -> DecisionWireV1 {
        if self.allow {
            return DecisionWireV1 {
                allow: true,
                code: WIRE_V1_ALLOW_CODE.to_string(),
                reason: WIRE_V1_ALLOW_REASON.to_string(),
                required_scopes: self.required_scopes.clone(),
            };
        }

        DecisionWireV1 {
            allow: false,
            code: self
                .code
                .clone()
                .unwrap_or_else(|| WIRE_V1_FALLBACK_DENY_CODE.to_string()),
            reason: self
                .reason
                .clone()
                .unwrap_or_else(|| WIRE_V1_FALLBACK_DENY_REASON.to_string()),
            required_scopes: self.required_scopes.clone(),
        }
    }
}

impl From<DecisionWireV1> for Decision {
    fn from(value: DecisionWireV1) -> Self {
        if value.allow {
            return Self {
                allow: true,
                code: None,
                reason: None,
                required_scopes: value.required_scopes,
            };
        }

        Self {
            allow: false,
            code: Some(value.code).filter(|code| !code.is_empty()),
            reason: Some(value.reason).filter(|reason| !reason.is_empty()),
            required_scopes: value.required_scopes,
        }
    }
}
