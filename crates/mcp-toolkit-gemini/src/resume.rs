//! # Gemini Resume Provider
//!
//! Provider abstraction for conversation resume behavior across Gemini-backed
//! MCP tools.
//!
//! ## Rationale
//! Keep resume policy and error classification centralized so tool handlers can
//! stay focused on validation and response shaping.
//!
//! ## Security Boundaries
//! * Resume is opt-in per tool call and may be disabled globally by config.
//! * Provider logic classifies known resume/session misses without exposing
//!   process environment details.
//!
//! ## References
//! * Gemini CLI-backed MCP tools that accept resume selectors.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::GeminiExecutionConfig;
use crate::executor::GeminiExecutionError;

/// Summary: opt-in strategy for handling unavailable resume targets.
///
/// # Errors
/// * Parsing errors are handled by serde and surfaced as tool argument errors.
///
/// # Security
/// * `Inherit` and `Require` prevent implicit fallback to unrelated context.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResumeStrategy {
    /// Inherit prior conversation context. If unavailable, fail.
    #[default]
    Inherit,
    /// If the requested resume target is unavailable, run stateless instead.
    #[serde(alias = "fresh-if-missing")]
    FreshIfMissing,
    /// Strictly require resume target availability.
    Require,
}

impl ResumeStrategy {
    /// Summary: return the stable label used in telemetry records.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Uses fixed literals to keep ledger fields deterministic.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inherit => "inherit",
            Self::FreshIfMissing => "fresh_if_missing",
            Self::Require => "require",
        }
    }

    /// Summary: report whether this strategy allows stateless fallback.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Explicitly gates fallback behavior to avoid accidental context shifts.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn allows_fresh_fallback(self) -> bool {
        matches!(self, Self::FreshIfMissing)
    }
}

/// Summary: normalized resume execution decision for a single tool call.
///
/// # Errors
/// * Created by resume providers and may be rejected by policy checks.
///
/// # Security
/// * Encodes whether resume was explicitly requested and the selector used.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeExecutionPlan {
    pub requested: bool,
    pub selector: Option<String>,
    pub strategy: ResumeStrategy,
}

/// Summary: structured provider error while resolving resume policy.
///
/// # Errors
/// * Returned when resume is disabled or selector inputs are invalid.
///
/// # Security
/// * Contains user-facing hints and never includes environment secrets.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeResolutionError {
    pub code: &'static str,
    pub message: String,
    pub corrective_hint: String,
}

/// Summary: abstraction for mapping user resume intent into execution behavior.
///
/// # Errors
/// * `resolve` returns [`ResumeResolutionError`] for policy/config violations.
///
/// # Security
/// * Lets servers swap resume backends without changing tool contracts.
///
/// # Panics
/// * Does not panic.
pub trait ConversationResumeProvider: std::fmt::Debug + Send + Sync {
    /// Summary: resolve a requested resume selector into an execution plan.
    ///
    /// # Errors
    /// * Returns `Err` when resume is not permitted by policy.
    ///
    /// # Security
    /// * Must enforce global policy gates before execution.
    ///
    /// # Panics
    /// * Does not panic.
    fn resolve(
        &self,
        config: &GeminiExecutionConfig,
        selector: Option<String>,
        strategy: ResumeStrategy,
    ) -> Result<ResumeExecutionPlan, ResumeResolutionError>;

    /// Summary: classify whether an execution error indicates unavailable resume state.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Avoids over-broad matching by requiring resume/session context clues.
    ///
    /// # Panics
    /// * Does not panic.
    fn is_unavailable_error(&self, error: &GeminiExecutionError) -> bool;
}

/// Summary: resume provider that forwards selector semantics to Gemini CLI.
///
/// # Errors
/// * Enforces policy gates and returns structured errors from `resolve`.
///
/// # Security
/// * Keeps policy decisions in Rust while delegating selector semantics to CLI.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Default)]
pub struct GeminiCliResumeProvider;

impl ConversationResumeProvider for GeminiCliResumeProvider {
    fn resolve(
        &self,
        config: &GeminiExecutionConfig,
        selector: Option<String>,
        strategy: ResumeStrategy,
    ) -> Result<ResumeExecutionPlan, ResumeResolutionError> {
        let selector = selector
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if selector.is_none() {
            return Ok(ResumeExecutionPlan {
                requested: false,
                selector: None,
                strategy,
            });
        }

        if !config.enable_resume {
            return Err(ResumeResolutionError {
                code: "resume_disabled",
                message: "resume is disabled by server policy".to_string(),
                corrective_hint:
                    "Retry without `resume`, or set GEMINI_MCP_ENABLE_RESUME=true on the server."
                        .to_string(),
            });
        }

        Ok(ResumeExecutionPlan {
            requested: true,
            selector,
            strategy,
        })
    }

    fn is_unavailable_error(&self, error: &GeminiExecutionError) -> bool {
        let GeminiExecutionError::FailedExit { code, stderr } = error else {
            return false;
        };
        let lower = stderr.to_lowercase();
        let references_resume = ["resume", "session", "conversation"]
            .iter()
            .any(|needle| lower.contains(needle));
        if !references_resume {
            return false;
        }
        let missing_or_invalid = [
            "not found",
            "invalid",
            "expired",
            "unknown",
            "does not exist",
            "cannot resume",
            "failed to resume",
            "no such",
            "missing",
        ]
        .iter()
        .any(|needle| lower.contains(needle));

        missing_or_invalid || matches!(code, Some(42))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConversationResumeProvider, GeminiCliResumeProvider, ResumeExecutionPlan, ResumeStrategy,
    };
    use crate::config::GeminiExecutionConfig;
    use crate::executor::GeminiExecutionError;

    #[test]
    fn resolve_returns_non_requested_plan_when_selector_is_absent() {
        let provider = GeminiCliResumeProvider;
        let config = GeminiExecutionConfig::default();

        let plan = provider
            .resolve(&config, None, ResumeStrategy::Inherit)
            .expect("selector-free resolve should succeed");
        assert_eq!(
            plan,
            ResumeExecutionPlan {
                requested: false,
                selector: None,
                strategy: ResumeStrategy::Inherit,
            }
        );
    }

    #[test]
    fn resolve_rejects_resume_when_globally_disabled() {
        let provider = GeminiCliResumeProvider;
        let config = GeminiExecutionConfig {
            enable_resume: false,
            ..GeminiExecutionConfig::default()
        };

        let err = provider
            .resolve(
                &config,
                Some("latest".to_string()),
                ResumeStrategy::FreshIfMissing,
            )
            .expect_err("disabled resume should fail");
        assert_eq!(err.code, "resume_disabled");
    }

    #[test]
    fn unavailable_error_detection_matches_resume_session_miss() {
        let provider = GeminiCliResumeProvider;
        let error = GeminiExecutionError::FailedExit {
            code: Some(42),
            stderr: "Error resuming session: session not found".to_string(),
        };
        assert!(provider.is_unavailable_error(&error));
    }

    #[test]
    fn unavailable_error_detection_ignores_non_resume_failures() {
        let provider = GeminiCliResumeProvider;
        let error = GeminiExecutionError::FailedExit {
            code: Some(1),
            stderr: "status 429 resource_exhausted".to_string(),
        };
        assert!(!provider.is_unavailable_error(&error));
    }

    #[test]
    fn resolve_plan_is_invariant_under_heartbeat_observability_settings() {
        let provider = GeminiCliResumeProvider;
        let base = GeminiExecutionConfig::default();
        let mut heartbeat_enabled = base.clone();
        heartbeat_enabled.inspect_heartbeat_enabled = true;
        heartbeat_enabled.inspect_heartbeat_interval = std::time::Duration::from_secs(2);
        heartbeat_enabled.inspect_stall_threshold = std::time::Duration::from_secs(90);

        let base_plan = provider
            .resolve(
                &base,
                Some("latest".to_string()),
                ResumeStrategy::FreshIfMissing,
            )
            .expect("baseline resolve should succeed");
        let heartbeat_plan = provider
            .resolve(
                &heartbeat_enabled,
                Some("latest".to_string()),
                ResumeStrategy::FreshIfMissing,
            )
            .expect("heartbeat-enabled resolve should succeed");
        assert_eq!(base_plan, heartbeat_plan);
    }
}
