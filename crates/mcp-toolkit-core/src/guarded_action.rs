//! # Guarded Actions
//!
//! Small generic primitives for preview/apply, sensitive-read, and read-only
//! runtime gating.
//!
//! ## Ownership
//! This module owns repository-neutral metadata and helper types for services
//! that need to expose safe previews, fail-closed apply gates, sensitive
//! non-mutating output, or explicit read-only runtime modes.
//!
//! ## Non-ownership
//! This module does not parse provider-specific routes, submit mutations, or
//! decide service-specific allowlists. Service repositories still own domain
//! semantics, resource identifiers, and post-apply readback logic.
//!
//! ## Security Boundaries
//! * Runtime mode checks fail closed unless the caller explicitly enables a
//!   write-capable mode.
//! * Stable plan ids are built from caller-supplied non-secret identifiers; do
//!   not pass raw secrets or credential-bearing values as scope or target
//!   inputs.
//! * Preview/apply envelopes are generic response helpers only. They do not
//!   replace service-owned validation, authorization, or fresh readback.

use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

/// Operation class for a tool or HTTP/admin action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardedActionOperationClass {
    /// Non-mutating read or inspection path.
    Read,
    /// Non-mutating read path that may return unredacted sensitive output.
    SensitiveRead,
    /// Safe preview that prepares a plan without mutating upstream state.
    Preview,
    /// Apply path bound to a reviewed preview plan.
    GuardedApply,
    /// General mutating action without destructive semantics.
    Mutating,
    /// Destructive action with elevated impact.
    Destructive,
    /// Action that is adjacent to send/publish/trigger semantics.
    SendAdjacent,
}

impl GuardedActionOperationClass {
    /// Return the stable string label for external JSON surfaces.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::SensitiveRead => "sensitive_read",
            Self::Preview => "preview",
            Self::GuardedApply => "guarded_apply",
            Self::Mutating => "mutating",
            Self::Destructive => "destructive",
            Self::SendAdjacent => "send_adjacent",
        }
    }

    /// Return true when the class represents a destructive path.
    pub const fn destructive(self) -> bool {
        matches!(self, Self::Destructive)
    }

    /// Return true when the class is adjacent to send/publish/trigger behavior.
    pub const fn send_adjacent(self) -> bool {
        matches!(self, Self::SendAdjacent)
    }

    /// Return true when the class can mutate upstream state.
    pub const fn is_write_like(self) -> bool {
        matches!(
            self,
            Self::GuardedApply | Self::Mutating | Self::Destructive | Self::SendAdjacent
        )
    }
}

impl Display for GuardedActionOperationClass {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Metadata that describes how an action should be surfaced and gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardedActionPosture {
    pub operation_class: GuardedActionOperationClass,
    pub requires_runtime_enablement: bool,
    pub writes_enabled_by_default: bool,
    pub post_apply_readback_required: bool,
}

impl GuardedActionPosture {
    /// Create posture for a non-mutating read path.
    pub const fn read_only() -> Self {
        Self {
            operation_class: GuardedActionOperationClass::Read,
            requires_runtime_enablement: false,
            writes_enabled_by_default: false,
            post_apply_readback_required: false,
        }
    }

    /// Create posture for a preview path.
    pub const fn preview() -> Self {
        Self {
            operation_class: GuardedActionOperationClass::Preview,
            requires_runtime_enablement: false,
            writes_enabled_by_default: false,
            post_apply_readback_required: false,
        }
    }

    /// Create posture for a non-mutating read that can reveal sensitive output.
    ///
    /// Services still own exact field/resource allowlists and any
    /// environment-specific runtime gate. This posture records the shared
    /// contract: the action is read-only, but must not be exposed as an
    /// ordinary ambient read because returned values may be unredacted.
    pub const fn sensitive_read() -> Self {
        Self {
            operation_class: GuardedActionOperationClass::SensitiveRead,
            requires_runtime_enablement: true,
            writes_enabled_by_default: false,
            post_apply_readback_required: false,
        }
    }

    /// Create posture for a guarded apply path.
    pub const fn guarded_apply() -> Self {
        Self {
            operation_class: GuardedActionOperationClass::GuardedApply,
            requires_runtime_enablement: true,
            writes_enabled_by_default: false,
            post_apply_readback_required: true,
        }
    }

    /// Create posture for a non-destructive mutation.
    pub const fn mutating() -> Self {
        Self {
            operation_class: GuardedActionOperationClass::Mutating,
            requires_runtime_enablement: true,
            writes_enabled_by_default: false,
            post_apply_readback_required: false,
        }
    }

    /// Create posture for a destructive mutation.
    pub const fn destructive() -> Self {
        Self {
            operation_class: GuardedActionOperationClass::Destructive,
            requires_runtime_enablement: true,
            writes_enabled_by_default: false,
            post_apply_readback_required: true,
        }
    }

    /// Create posture for send-adjacent operations.
    pub const fn send_adjacent() -> Self {
        Self {
            operation_class: GuardedActionOperationClass::SendAdjacent,
            requires_runtime_enablement: true,
            writes_enabled_by_default: false,
            post_apply_readback_required: true,
        }
    }

    /// Override whether runtime enablement is required.
    #[must_use]
    pub const fn with_runtime_enablement(mut self, requires_runtime_enablement: bool) -> Self {
        self.requires_runtime_enablement = requires_runtime_enablement;
        self
    }

    /// Override whether writes are enabled by default for the service profile.
    #[must_use]
    pub const fn with_writes_enabled_by_default(mut self, writes_enabled_by_default: bool) -> Self {
        self.writes_enabled_by_default = writes_enabled_by_default;
        self
    }

    /// Override whether post-apply readback is required.
    #[must_use]
    pub const fn with_post_apply_readback_required(
        mut self,
        post_apply_readback_required: bool,
    ) -> Self {
        self.post_apply_readback_required = post_apply_readback_required;
        self
    }

    /// Return true when this posture is a read-only action.
    pub const fn is_read_only(self) -> bool {
        matches!(
            self.operation_class,
            GuardedActionOperationClass::Read | GuardedActionOperationClass::SensitiveRead
        )
    }

    /// Return true when this posture is destructive.
    pub const fn is_destructive(self) -> bool {
        self.operation_class.destructive()
    }

    /// Return true when this posture is send-adjacent.
    pub const fn is_send_adjacent(self) -> bool {
        self.operation_class.send_adjacent()
    }
}

impl Default for GuardedActionPosture {
    fn default() -> Self {
        Self::mutating()
    }
}

/// Runtime mode for read-only, preview-only, or apply-capable service profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardedActionRuntimeMode {
    /// Only read paths are allowed.
    ReadOnly,
    /// Read and preview paths are allowed.
    PreviewOnly,
    /// Read, preview, and apply paths are allowed.
    Enabled,
}

impl GuardedActionRuntimeMode {
    /// Assert that the runtime mode allows the requested posture.
    ///
    /// # Errors
    /// Returns [`GuardedActionError::ActionDisabled`] when the posture is not
    /// permitted in the current runtime mode.
    pub fn assert_allowed(
        self,
        action_name: &str,
        posture: GuardedActionPosture,
    ) -> Result<(), GuardedActionError> {
        if posture.requires_runtime_enablement && self != Self::Enabled {
            return Err(GuardedActionError::ActionDisabled {
                action_name: action_name.trim().to_string(),
                operation_class: posture.operation_class,
                runtime_mode: self,
            });
        }

        let allowed = match self {
            Self::ReadOnly => posture.is_read_only(),
            Self::PreviewOnly => {
                posture.is_read_only()
                    || matches!(
                        posture.operation_class,
                        GuardedActionOperationClass::Preview
                    )
            }
            Self::Enabled => true,
        };

        if allowed {
            Ok(())
        } else {
            Err(GuardedActionError::ActionDisabled {
                action_name: action_name.trim().to_string(),
                operation_class: posture.operation_class,
                runtime_mode: self,
            })
        }
    }

    /// Stable string label for JSON or logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::PreviewOnly => "preview_only",
            Self::Enabled => "enabled",
        }
    }
}

impl Display for GuardedActionRuntimeMode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Deterministic non-secret plan id seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedActionPlanSeed {
    action: String,
    scope: String,
    target: String,
}

impl GuardedActionPlanSeed {
    /// Build a normalized plan id seed from public-safe identifiers.
    ///
    /// # Errors
    /// Returns [`GuardedActionError::EmptyField`] when any field is blank after
    /// normalization.
    pub fn new(
        action: impl AsRef<str>,
        scope: impl AsRef<str>,
        target: impl AsRef<str>,
    ) -> Result<Self, GuardedActionError> {
        Ok(Self {
            action: normalize_segment("action", action.as_ref())?,
            scope: normalize_segment("scope", scope.as_ref())?,
            target: normalize_segment("target", target.as_ref())?,
        })
    }

    /// Return a deterministic plan id for preview/apply binding.
    pub fn stable_plan_id(&self) -> String {
        format!("gap.{}.{}.{}", self.action, self.scope, self.target)
    }
}

/// Preview response envelope for guarded actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardedActionPreview<TPreview, TEvidence> {
    pub plan_id: String,
    pub runtime_mode: GuardedActionRuntimeMode,
    pub posture: GuardedActionPosture,
    pub expires_at: Option<String>,
    pub preview: TPreview,
    pub evidence: TEvidence,
}

impl<TPreview, TEvidence> GuardedActionPreview<TPreview, TEvidence> {
    /// Create a preview response with the supplied plan id and posture.
    pub fn new(
        plan_id: impl Into<String>,
        runtime_mode: GuardedActionRuntimeMode,
        posture: GuardedActionPosture,
        preview: TPreview,
        evidence: TEvidence,
    ) -> Self {
        Self {
            plan_id: plan_id.into(),
            runtime_mode,
            posture,
            expires_at: None,
            preview,
            evidence,
        }
    }

    /// Attach an optional expiry timestamp.
    #[must_use]
    pub fn with_expires_at(mut self, expires_at: impl Into<String>) -> Self {
        self.expires_at = Some(expires_at.into());
        self
    }
}

/// Apply response envelope for guarded actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardedActionApply<TApplied, TEvidence> {
    pub plan_id: String,
    pub runtime_mode: GuardedActionRuntimeMode,
    pub posture: GuardedActionPosture,
    pub applied: TApplied,
    pub evidence: TEvidence,
}

impl<TApplied, TEvidence> GuardedActionApply<TApplied, TEvidence> {
    /// Create an apply response with the supplied plan id and posture.
    pub fn new(
        plan_id: impl Into<String>,
        runtime_mode: GuardedActionRuntimeMode,
        posture: GuardedActionPosture,
        applied: TApplied,
        evidence: TEvidence,
    ) -> Self {
        Self {
            plan_id: plan_id.into(),
            runtime_mode,
            posture,
            applied,
            evidence,
        }
    }
}

/// Error returned while building or checking guarded actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardedActionError {
    /// Required plan id seed input was blank.
    EmptyField { field: &'static str },
    /// Runtime mode denied the requested action class.
    ActionDisabled {
        action_name: String,
        operation_class: GuardedActionOperationClass,
        runtime_mode: GuardedActionRuntimeMode,
    },
}

impl Display for GuardedActionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyField { field } => {
                write!(formatter, "guarded action field `{field}` must not be empty")
            }
            Self::ActionDisabled {
                action_name,
                operation_class,
                runtime_mode,
            } => write!(
                formatter,
                "action '{action_name}' with class '{operation_class}' is disabled while runtime mode is '{runtime_mode}'"
            ),
        }
    }
}

impl std::error::Error for GuardedActionError {}

fn normalize_segment(field: &'static str, value: &str) -> Result<String, GuardedActionError> {
    let mut normalized = String::new();
    let mut previous_dash = false;

    for ch in value.trim().chars() {
        let mapped = match ch {
            'a'..='z' | '0'..='9' => ch,
            'A'..='Z' => ch.to_ascii_lowercase(),
            '.' | '_' => ch,
            _ => '-',
        };
        if mapped == '-' {
            if previous_dash {
                continue;
            }
            previous_dash = true;
        } else {
            previous_dash = false;
        }
        normalized.push(mapped);
    }

    let normalized = normalized.trim_matches('-').to_string();
    if normalized.is_empty() {
        return Err(GuardedActionError::EmptyField { field });
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::{
        GuardedActionApply, GuardedActionOperationClass, GuardedActionPlanSeed,
        GuardedActionPosture, GuardedActionPreview, GuardedActionRuntimeMode,
    };
    use serde_json::json;

    #[test]
    fn plan_ids_are_stable_and_normalized() {
        let seed =
            GuardedActionPlanSeed::new("Queue Control", "Tenant 42", "/jobs/pause").expect("seed");
        assert_eq!(
            seed.stable_plan_id(),
            "gap.queue-control.tenant-42.jobs-pause"
        );
    }

    #[test]
    fn read_only_mode_denies_apply_paths() {
        let err = GuardedActionRuntimeMode::ReadOnly
            .assert_allowed("queue_control_apply", GuardedActionPosture::guarded_apply())
            .expect_err("apply should be denied");
        assert!(err.to_string().contains("queue_control_apply"));
    }

    #[test]
    fn preview_only_mode_allows_preview_and_denies_send_adjacent() {
        GuardedActionRuntimeMode::PreviewOnly
            .assert_allowed("queue_control_preview", GuardedActionPosture::preview())
            .expect("preview should be allowed");
        let err = GuardedActionRuntimeMode::PreviewOnly
            .assert_allowed("broadcast_now", GuardedActionPosture::send_adjacent())
            .expect_err("send-adjacent action should be denied");
        assert!(err.to_string().contains("preview_only"));
    }

    #[test]
    fn runtime_enablement_requirement_denies_preview_until_enabled() {
        let guarded_preview = GuardedActionPosture::preview().with_runtime_enablement(true);

        let err = GuardedActionRuntimeMode::PreviewOnly
            .assert_allowed("queue_control_preview", guarded_preview)
            .expect_err("preview should require enabled runtime mode");
        assert!(err.to_string().contains("preview_only"));

        GuardedActionRuntimeMode::Enabled
            .assert_allowed("queue_control_preview", guarded_preview)
            .expect("enabled runtime mode should allow guarded preview");
    }

    #[test]
    fn preview_and_apply_envelopes_serialize_runtime_and_posture() {
        let posture = GuardedActionPosture::guarded_apply()
            .with_writes_enabled_by_default(false)
            .with_post_apply_readback_required(true);
        let preview = GuardedActionPreview::new(
            "gap.queue-control.tenant-42.jobs-pause",
            GuardedActionRuntimeMode::PreviewOnly,
            GuardedActionPosture::preview(),
            json!({"requested_state": "paused"}),
            json!({"queue": "jobs", "rows": 1}),
        )
        .with_expires_at("2026-06-29T00:00:00Z");
        let apply = GuardedActionApply::new(
            "gap.queue-control.tenant-42.jobs-pause",
            GuardedActionRuntimeMode::Enabled,
            posture,
            json!({"applied": true}),
            json!({"before": "running", "after": "paused"}),
        );

        let preview_value = serde_json::to_value(preview).expect("serialize preview");
        let apply_value = serde_json::to_value(apply).expect("serialize apply");

        assert_eq!(preview_value["runtime_mode"], json!("preview_only"));
        assert_eq!(
            apply_value["posture"]["operation_class"],
            json!(GuardedActionOperationClass::GuardedApply.as_str())
        );
        assert_eq!(
            apply_value["posture"]["post_apply_readback_required"],
            json!(true)
        );
    }

    #[test]
    fn sensitive_read_is_read_only_but_runtime_gated() {
        let posture = GuardedActionPosture::sensitive_read();

        assert!(posture.is_read_only());
        assert!(!posture.operation_class.is_write_like());
        assert!(posture.requires_runtime_enablement);

        let err = GuardedActionRuntimeMode::ReadOnly
            .assert_allowed("sensitive_field_query", posture)
            .expect_err("sensitive reads require explicit runtime enablement");
        assert!(err.to_string().contains("read_only"));

        GuardedActionRuntimeMode::Enabled
            .assert_allowed("sensitive_field_query", posture)
            .expect("enabled runtime mode should allow sensitive reads");
    }
}
