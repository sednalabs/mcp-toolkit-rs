//! Startup proof policy validation, artifact handling, and evaluation.
//!
//! Evaluation results describe evidence checks and do not enforce caller startup behavior.

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::provenance::{is_unknown, system_time_to_unix_ms, RuntimeProvenance};

pub const CODE_DISABLED: &str = "admission.disabled";
pub const CODE_OVERRIDE: &str = "admission.override.active";
pub const CODE_OVERRIDE_EXPIRED: &str = "admission.override.expired";
pub const CODE_MISSING: &str = "admission.gate.missing";
pub const CODE_EXPIRED: &str = "admission.gate.expired";
pub const CODE_STATUS_INVALID: &str = "admission.gate.status_invalid";
pub const CODE_COMPONENT_MISMATCH: &str = "admission.gate.component_mismatch";
pub const CODE_LEVEL_MISMATCH: &str = "admission.gate.level_mismatch";
pub const CODE_BUILD_MISMATCH: &str = "admission.gate.build_mismatch";
pub const CODE_SOURCE_MISMATCH: &str = "admission.gate.source_mismatch";
pub const CODE_MANIFEST_MISMATCH: &str = "admission.gate.manifest_mismatch";
pub const CODE_TIMESTAMP_INVALID: &str = "admission.gate.timestamp_invalid";
pub const CODE_PROVENANCE_UNAVAILABLE: &str = "admission.runtime.provenance_unavailable";
pub const CODE_EXPECTED_MANIFEST_UNAVAILABLE: &str = "admission.expected_manifest.unavailable";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Selects how an incomplete or invalid startup proof is handled.
pub enum StartupAdmissionMode {
    Off,
    Warn,
    Strict,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Names a supported test-gate strength.
pub enum TestGateLevel {
    Fast,
    Standard,
}

impl TestGateLevel {
    /// Returns the stable serialized name for this gate level.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Standard => "standard",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Describes a time-bounded operator bypass.
pub struct AdmissionBypass {
    pub reason: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Holds startup gate policy and the trusted expected manifest digest.
pub struct StartupAdmissionPolicy {
    pub mode: StartupAdmissionMode,
    pub required_level: TestGateLevel,
    pub gate_path: PathBuf,
    pub production_mode: bool,
    pub allow_production_bypass: bool,
    pub bypass: Option<AdmissionBypass>,
    /// Digest supplied by trusted caller configuration, independently of the gate artifact.
    pub expected_command_manifest_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Reports the evaluator's result without asserting caller startup behavior.
pub enum AdmissionOutcome {
    Disabled,
    Bypassed,
    Passed,
    Warning,
    Rejected,
}

impl AdmissionOutcome {
    /// Returns the stable serialized name for this outcome.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Bypassed => "bypassed",
            Self::Passed => "passed",
            Self::Warning => "warn",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Describes one startup-admission evaluation.
pub struct AdmissionEvaluation {
    pub outcome: AdmissionOutcome,
    pub required_level: TestGateLevel,
    pub gate_path: PathBuf,
    pub reason_code: Option<String>,
    pub detail: String,
    pub override_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Represents a versioned passing test-gate proof artifact.
pub struct GateArtifactV1 {
    pub schema_version: u32,
    pub component: String,
    pub gate_level: String,
    pub status: String,
    pub build_identity: String,
    pub source_fingerprint: String,
    pub command_manifest_digest: String,
    pub expires_at: String,
}

impl GateArtifactV1 {
    /// Creates a passing artifact bound to the supplied running build and digest.
    pub fn passing(
        runtime: &RuntimeProvenance,
        level: TestGateLevel,
        command_manifest_digest: impl Into<String>,
        expires_at: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            component: runtime.build.component.clone(),
            gate_level: level.as_str().to_string(),
            status: "pass".to_string(),
            build_identity: runtime.build.build_identity.clone(),
            source_fingerprint: runtime.build.source_fingerprint.clone(),
            command_manifest_digest: command_manifest_digest.into(),
            expires_at: expires_at.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Reports invalid local admission policy configuration.
pub enum AdmissionPolicyError {
    ProductionModeCannotDisableAdmission,
    BypassReasonRequired,
    BypassExpiryInvalid,
    ProductionBypassNotAllowed,
}

impl fmt::Display for AdmissionPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProductionModeCannotDisableAdmission => {
                write!(f, "startup admission cannot be disabled in production mode")
            }
            Self::BypassReasonRequired => write!(f, "startup admission bypass requires a reason"),
            Self::BypassExpiryInvalid => {
                write!(
                    f,
                    "startup admission bypass requires a valid RFC3339 expires_at"
                )
            }
            Self::ProductionBypassNotAllowed => {
                write!(
                    f,
                    "startup admission bypass is not allowed in production mode"
                )
            }
        }
    }
}

impl std::error::Error for AdmissionPolicyError {}

impl StartupAdmissionPolicy {
    /// Validates bypass and production policy constraints.
    ///
    /// # Errors
    /// Returns an error for empty bypass reasons, invalid expiries, or forbidden production settings.
    pub fn validate(&self) -> Result<(), AdmissionPolicyError> {
        if self.production_mode && matches!(self.mode, StartupAdmissionMode::Off) {
            return Err(AdmissionPolicyError::ProductionModeCannotDisableAdmission);
        }
        if let Some(bypass) = &self.bypass {
            if bypass.reason.trim().is_empty() {
                return Err(AdmissionPolicyError::BypassReasonRequired);
            }
            if OffsetDateTime::parse(&bypass.expires_at, &Rfc3339).is_err() {
                return Err(AdmissionPolicyError::BypassExpiryInvalid);
            }
            if self.production_mode && !self.allow_production_bypass {
                return Err(AdmissionPolicyError::ProductionBypassNotAllowed);
            }
        }
        Ok(())
    }
}

/// Evaluates proof evidence against policy and the independently supplied trusted digest.
///
/// # Errors
/// Returns an error when the policy itself is invalid. Evidence failures are returned as outcomes.
///
/// # Security
/// The artifact is not treated as the source of trust for the expected manifest digest.
/// Callers must restrict the gate path and file permissions to the deployment trust boundary.
pub fn evaluate_startup_admission(
    policy: &StartupAdmissionPolicy,
    runtime: &RuntimeProvenance,
) -> Result<AdmissionEvaluation, AdmissionPolicyError> {
    policy.validate()?;

    if matches!(policy.mode, StartupAdmissionMode::Off) {
        return Ok(AdmissionEvaluation {
            outcome: AdmissionOutcome::Disabled,
            required_level: policy.required_level,
            gate_path: policy.gate_path.clone(),
            reason_code: Some(CODE_DISABLED.to_string()),
            detail: "startup admission disabled by policy".to_string(),
            override_active: false,
        });
    }

    let now = OffsetDateTime::now_utc();
    let mut expired_bypass = false;
    if let Some(bypass) = &policy.bypass {
        let expires_at = OffsetDateTime::parse(&bypass.expires_at, &Rfc3339)
            .map_err(|_| AdmissionPolicyError::BypassExpiryInvalid)?;
        if now <= expires_at {
            return Ok(AdmissionEvaluation {
                outcome: AdmissionOutcome::Bypassed,
                required_level: policy.required_level,
                gate_path: policy.gate_path.clone(),
                reason_code: Some(CODE_OVERRIDE.to_string()),
                detail: format!(
                    "startup admission bypass active until {} (reason={})",
                    bypass.expires_at,
                    bounded_text(&bypass.reason, 180)
                ),
                override_active: true,
            });
        }
        expired_bypass = true;
    }

    let unavailable_fields = missing_required_provenance_fields(runtime);
    if !unavailable_fields.is_empty() {
        return Ok(warning_or_reject(
            policy,
            CODE_PROVENANCE_UNAVAILABLE,
            format!(
                "runtime provenance is incomplete; unavailable required fields: {}",
                unavailable_fields.join(", ")
            ),
        ));
    }

    let Some(expected_digest) = policy.expected_command_manifest_digest.as_deref() else {
        return Ok(warning_or_reject(
            policy,
            CODE_EXPECTED_MANIFEST_UNAVAILABLE,
            "trusted expected command-manifest digest is unavailable".to_string(),
        ));
    };
    if !valid_sha256_reference(expected_digest) {
        return Ok(warning_or_reject(
            policy,
            CODE_EXPECTED_MANIFEST_UNAVAILABLE,
            "trusted expected command-manifest digest is not valid sha256 syntax".to_string(),
        ));
    }

    // Open once so the freshness metadata and artifact contents come from the
    // same file, even if a caller replaces the path between operations.
    let mut gate_file = match fs::File::open(&policy.gate_path) {
        Ok(file) => file,
        Err(err) => {
            return Ok(warning_or_reject(
                policy,
                if expired_bypass {
                    CODE_OVERRIDE_EXPIRED
                } else {
                    CODE_MISSING
                },
                if expired_bypass {
                    format!("startup admission bypass expired and gate is unavailable: {err}")
                } else {
                    format!("required gate artifact missing or unreadable: {err}")
                },
            ));
        }
    };

    let gate_meta = match gate_file.metadata() {
        Ok(meta) => meta,
        Err(err) => {
            return Ok(warning_or_reject(
                policy,
                CODE_MISSING,
                format!("failed to inspect opened gate artifact: {err}"),
            ));
        }
    };

    let mut raw = String::new();
    match gate_file.read_to_string(&mut raw) {
        Ok(_) => {}
        Err(err) => {
            return Ok(warning_or_reject(
                policy,
                CODE_MISSING,
                format!("failed to read gate artifact: {err}"),
            ));
        }
    };
    let artifact = match serde_json::from_str::<GateArtifactV1>(&raw) {
        Ok(artifact) => artifact,
        Err(err) => {
            return Ok(warning_or_reject(
                policy,
                CODE_STATUS_INVALID,
                format!("invalid gate artifact JSON payload: {err}"),
            ));
        }
    };

    if artifact.schema_version != 1 {
        return Ok(warning_or_reject(
            policy,
            CODE_STATUS_INVALID,
            format!(
                "unsupported gate artifact schema_version {}; expected 1",
                artifact.schema_version
            ),
        ));
    }
    if artifact.component != runtime.build.component {
        return Ok(warning_or_reject(
            policy,
            CODE_COMPONENT_MISMATCH,
            format!(
                "gate component mismatch: expected {}, found {}",
                runtime.build.component, artifact.component
            ),
        ));
    }
    if artifact.gate_level != policy.required_level.as_str() {
        return Ok(warning_or_reject(
            policy,
            CODE_LEVEL_MISMATCH,
            format!(
                "gate level mismatch: expected {}, found {}",
                policy.required_level.as_str(),
                artifact.gate_level
            ),
        ));
    }
    if artifact.status != "pass" {
        return Ok(warning_or_reject(
            policy,
            CODE_STATUS_INVALID,
            format!("gate status is not pass: {}", artifact.status),
        ));
    }
    if artifact.build_identity != runtime.build.build_identity {
        return Ok(warning_or_reject(
            policy,
            CODE_BUILD_MISMATCH,
            format!(
                "gate build_identity mismatch: expected {}, found {}",
                runtime.build.build_identity, artifact.build_identity
            ),
        ));
    }
    if artifact.source_fingerprint != runtime.build.source_fingerprint {
        return Ok(warning_or_reject(
            policy,
            CODE_SOURCE_MISMATCH,
            format!(
                "gate source_fingerprint mismatch: expected {}, found {}",
                runtime.build.source_fingerprint, artifact.source_fingerprint
            ),
        ));
    }
    if !valid_sha256_reference(&artifact.command_manifest_digest) {
        return Ok(warning_or_reject(
            policy,
            CODE_MANIFEST_MISMATCH,
            "gate command_manifest_digest must be a non-empty sha256: reference".to_string(),
        ));
    }
    if artifact.command_manifest_digest != expected_digest {
        return Ok(warning_or_reject(
            policy,
            CODE_MANIFEST_MISMATCH,
            format!(
                "gate command_manifest_digest mismatch: expected {expected_digest}, found {}",
                artifact.command_manifest_digest
            ),
        ));
    }

    let expires_at = match OffsetDateTime::parse(&artifact.expires_at, &Rfc3339) {
        Ok(value) => value,
        Err(err) => {
            return Ok(warning_or_reject(
                policy,
                CODE_TIMESTAMP_INVALID,
                format!("gate expires_at is not valid RFC3339: {err}"),
            ));
        }
    };
    if now > expires_at {
        return Ok(warning_or_reject(
            policy,
            CODE_EXPIRED,
            format!("gate artifact expired at {}", artifact.expires_at),
        ));
    }

    let gate_modified_ms = gate_meta.modified().ok().and_then(system_time_to_unix_ms);
    let Some(binary_modified_ms) = runtime.binary.modified_unix_ms else {
        return Ok(warning_or_reject(
            policy,
            CODE_TIMESTAMP_INVALID,
            "runtime binary modification time is unavailable".to_string(),
        ));
    };
    let Some(gate_modified_ms) = gate_modified_ms else {
        return Ok(warning_or_reject(
            policy,
            CODE_TIMESTAMP_INVALID,
            "gate artifact modification time is unavailable".to_string(),
        ));
    };
    if gate_modified_ms < binary_modified_ms {
        return Ok(warning_or_reject(
            policy,
            CODE_EXPIRED,
            "required gate artifact is older than the running binary".to_string(),
        ));
    }

    Ok(AdmissionEvaluation {
        outcome: AdmissionOutcome::Passed,
        required_level: policy.required_level,
        gate_path: policy.gate_path.clone(),
        reason_code: None,
        detail: "startup admission checks passed".to_string(),
        override_active: false,
    })
}

/// Writes a gate artifact through a temporary sibling file.
///
/// # Errors
/// Returns a message describing directory creation, serialization, write, or rename failures.
///
/// # Security
/// Callers must restrict the destination path and permissions to their deployment trust boundary.
pub fn write_gate_artifact(path: &Path, artifact: &GateArtifactV1) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create gate artifact directory {}: {err}",
                parent.display()
            )
        })?;
    }
    let payload = serde_json::to_vec_pretty(artifact)
        .map_err(|err| format!("failed to serialize gate artifact: {err}"))?;
    let temp = path.with_extension("tmp");
    fs::write(&temp, payload)
        .map_err(|err| format!("failed to write gate artifact {}: {err}", temp.display()))?;
    fs::rename(&temp, path).map_err(|err| {
        format!(
            "failed to move gate artifact {} into {}: {err}",
            temp.display(),
            path.display()
        )
    })
}

fn warning_or_reject(
    policy: &StartupAdmissionPolicy,
    reason_code: &str,
    detail: String,
) -> AdmissionEvaluation {
    let outcome = match policy.mode {
        StartupAdmissionMode::Strict => AdmissionOutcome::Rejected,
        StartupAdmissionMode::Warn => AdmissionOutcome::Warning,
        StartupAdmissionMode::Off => AdmissionOutcome::Disabled,
    };
    AdmissionEvaluation {
        outcome,
        required_level: policy.required_level,
        gate_path: policy.gate_path.clone(),
        reason_code: Some(reason_code.to_string()),
        detail,
        override_active: false,
    }
}

fn valid_sha256_reference(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn missing_required_provenance_fields(runtime: &RuntimeProvenance) -> Vec<&'static str> {
    let mut missing = Vec::new();
    for (field, value) in [
        ("component", runtime.build.component.as_str()),
        ("server_version", runtime.build.server_version.as_str()),
        ("revision", runtime.build.source.revision.as_str()),
        ("reference", runtime.build.source.reference.as_str()),
        ("build_identity", runtime.build.build_identity.as_str()),
        (
            "source_fingerprint",
            runtime.build.source_fingerprint.as_str(),
        ),
        (
            "rustc_version",
            runtime.build.build_metadata.rustc_version.as_str(),
        ),
        ("executable_path", runtime.process.executable_path.as_str()),
    ] {
        if is_unknown(value) {
            missing.push(field);
        }
    }
    if runtime.build.source.dirty.is_none() {
        missing.push("dirty");
    }
    if runtime.process.pid == 0 {
        missing.push("pid");
    }
    if runtime.binary.file_size_bytes.is_none() {
        missing.push("binary_size_bytes");
    }
    if runtime.binary.modified_unix_ms.is_none() {
        missing.push("binary_modified_unix_ms");
    }
    missing
}

fn bounded_text(value: &str, max_chars: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        return compact;
    }
    let keep = max_chars.saturating_sub(3);
    let mut out: String = compact.chars().take(keep).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use time::Duration as TimeDuration;

    use super::*;
    use crate::provenance::{
        capture_runtime_provenance, BuildProvenance, BuildProvenanceInput, UNKNOWN_VALUE,
    };

    fn temp_path(directory: &tempfile::TempDir, prefix: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        directory
            .path()
            .join(format!("mcp-toolkit-{prefix}-{nonce}"))
    }

    fn runtime_for(executable: &Path) -> RuntimeProvenance {
        let build = BuildProvenance::from_input(BuildProvenanceInput {
            component: "example-mcp",
            server_version: "1.0.0",
            revision: Some("abc123"),
            reference: Some("main"),
            dirty: Some(false),
            profile: Some("release"),
            target: Some("x86_64-unknown-linux-gnu"),
            rustc_version: Some("rustc test"),
            source_date_epoch: None,
            build_identity_override: None,
        });
        capture_runtime_provenance(build, executable)
    }

    fn strict_policy(gate_path: PathBuf) -> StartupAdmissionPolicy {
        StartupAdmissionPolicy {
            mode: StartupAdmissionMode::Strict,
            required_level: TestGateLevel::Fast,
            gate_path,
            production_mode: false,
            allow_production_bypass: false,
            bypass: None,
            expected_command_manifest_digest: Some(format!("sha256:{}", "a".repeat(64))),
        }
    }

    #[test]
    fn strict_mode_rejects_missing_gate() {
        let fixture_dir = tempfile::tempdir().expect("create isolated fixture directory");
        let executable = temp_path(&fixture_dir, "exe");
        fs::write(&executable, "binary").expect("write executable fixture");
        let runtime = runtime_for(&executable);
        let gate_path = temp_path(&fixture_dir, "missing-gate");
        let evaluation =
            evaluate_startup_admission(&strict_policy(gate_path), &runtime).expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(evaluation.reason_code.as_deref(), Some(CODE_MISSING));
        let _ = fs::remove_file(executable);
    }

    #[test]
    fn every_required_provenance_field_blocks_strict_and_warns_in_warn_mode() {
        let fixture_dir = tempfile::tempdir().expect("create isolated fixture directory");
        let executable = temp_path(&fixture_dir, "exe");
        fs::write(&executable, "binary").expect("write executable fixture");
        let complete = runtime_for(&executable);
        let fields = [
            "component",
            "server_version",
            "revision",
            "reference",
            "dirty",
            "build_identity",
            "source_fingerprint",
            "rustc_version",
            "pid",
            "executable_path",
            "binary_size_bytes",
            "binary_modified_unix_ms",
        ];
        for field in fields {
            let mut runtime = complete.clone();
            match field {
                "component" => runtime.build.component = UNKNOWN_VALUE.to_string(),
                "server_version" => runtime.build.server_version = UNKNOWN_VALUE.to_string(),
                "revision" => runtime.build.source.revision = UNKNOWN_VALUE.to_string(),
                "reference" => runtime.build.source.reference = UNKNOWN_VALUE.to_string(),
                "dirty" => runtime.build.source.dirty = None,
                "build_identity" => runtime.build.build_identity = UNKNOWN_VALUE.to_string(),
                "source_fingerprint" => {
                    runtime.build.source_fingerprint = UNKNOWN_VALUE.to_string()
                }
                "rustc_version" => {
                    runtime.build.build_metadata.rustc_version = UNKNOWN_VALUE.to_string()
                }
                "pid" => runtime.process.pid = 0,
                "executable_path" => runtime.process.executable_path = UNKNOWN_VALUE.to_string(),
                "binary_size_bytes" => runtime.binary.file_size_bytes = None,
                "binary_modified_unix_ms" => runtime.binary.modified_unix_ms = None,
                _ => unreachable!("test field is listed above"),
            }
            for (mode, expected) in [
                (StartupAdmissionMode::Strict, AdmissionOutcome::Rejected),
                (StartupAdmissionMode::Warn, AdmissionOutcome::Warning),
            ] {
                let mut policy = strict_policy(temp_path(&fixture_dir, "gate"));
                policy.mode = mode;
                let evaluation =
                    evaluate_startup_admission(&policy, &runtime).expect("valid policy");
                assert_eq!(
                    evaluation.outcome, expected,
                    "field {field} in {mode:?} mode"
                );
                assert_eq!(
                    evaluation.reason_code.as_deref(),
                    Some(CODE_PROVENANCE_UNAVAILABLE)
                );
                assert!(
                    evaluation.detail.contains(field),
                    "field {field} should be identified"
                );
            }
        }
        let _ = fs::remove_file(executable);
    }

    #[test]
    fn strict_mode_accepts_gate_bound_to_running_build() {
        let fixture_dir = tempfile::tempdir().expect("create isolated fixture directory");
        let executable = temp_path(&fixture_dir, "exe");
        fs::write(&executable, "binary").expect("write executable fixture");
        let runtime = runtime_for(&executable);
        std::thread::sleep(Duration::from_millis(25));
        let gate_path = temp_path(&fixture_dir, "gate");
        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::hours(1))
            .format(&Rfc3339)
            .expect("format expiry");
        let artifact = GateArtifactV1::passing(
            &runtime,
            TestGateLevel::Fast,
            format!("sha256:{}", "a".repeat(64)),
            expires_at,
        );
        write_gate_artifact(&gate_path, &artifact).expect("write gate");

        let evaluation = evaluate_startup_admission(&strict_policy(gate_path.clone()), &runtime)
            .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Passed);
        let _ = fs::remove_file(executable);
        let _ = fs::remove_file(gate_path);
    }

    #[test]
    fn gate_bound_to_different_build_is_rejected() {
        let fixture_dir = tempfile::tempdir().expect("create isolated fixture directory");
        let executable = temp_path(&fixture_dir, "exe");
        fs::write(&executable, "binary").expect("write executable fixture");
        let runtime = runtime_for(&executable);
        std::thread::sleep(Duration::from_millis(25));
        let gate_path = temp_path(&fixture_dir, "gate");
        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::hours(1))
            .format(&Rfc3339)
            .expect("format expiry");
        let mut artifact = GateArtifactV1::passing(
            &runtime,
            TestGateLevel::Fast,
            format!("sha256:{}", "a".repeat(64)),
            expires_at,
        );
        artifact.build_identity = "other-mcp@1.0.0+deadbeef".to_string();
        write_gate_artifact(&gate_path, &artifact).expect("write gate");

        let evaluation = evaluate_startup_admission(&strict_policy(gate_path.clone()), &runtime)
            .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(evaluation.reason_code.as_deref(), Some(CODE_BUILD_MISMATCH));
        let _ = fs::remove_file(executable);
        let _ = fs::remove_file(gate_path);
    }

    #[test]
    fn expected_manifest_digest_is_required_and_compared_exactly() {
        let fixture_dir = tempfile::tempdir().expect("create isolated fixture directory");
        let executable = temp_path(&fixture_dir, "exe");
        fs::write(&executable, "binary").expect("write executable fixture");
        let runtime = runtime_for(&executable);
        let missing = temp_path(&fixture_dir, "missing-gate");
        let mut policy = strict_policy(missing);
        policy.expected_command_manifest_digest = None;
        let evaluation = evaluate_startup_admission(&policy, &runtime).expect("valid policy");
        assert_eq!(
            evaluation.reason_code.as_deref(),
            Some(CODE_EXPECTED_MANIFEST_UNAVAILABLE)
        );

        let gate_path = temp_path(&fixture_dir, "gate");
        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::hours(1))
            .format(&Rfc3339)
            .expect("format expiry");
        let artifact = GateArtifactV1::passing(
            &runtime,
            TestGateLevel::Fast,
            format!("sha256:{}", "b".repeat(64)),
            expires_at,
        );
        write_gate_artifact(&gate_path, &artifact).expect("write gate");
        let mut policy = strict_policy(gate_path.clone());
        policy.expected_command_manifest_digest = Some(format!("sha256:{}", "a".repeat(64)));
        let evaluation = evaluate_startup_admission(&policy, &runtime).expect("valid policy");
        assert_eq!(
            evaluation.reason_code.as_deref(),
            Some(CODE_MANIFEST_MISMATCH)
        );
        let _ = fs::remove_file(executable);
        let _ = fs::remove_file(gate_path);
    }

    #[test]
    fn malformed_gate_and_expected_digest_do_not_pass_strict_mode() {
        let fixture_dir = tempfile::tempdir().expect("create isolated fixture directory");
        let executable = temp_path(&fixture_dir, "exe");
        fs::write(&executable, "binary").expect("write executable fixture");
        let runtime = runtime_for(&executable);
        let gate_path = temp_path(&fixture_dir, "malformed-gate");
        fs::write(&gate_path, "not-json").expect("write malformed gate");
        let evaluation = evaluate_startup_admission(&strict_policy(gate_path.clone()), &runtime)
            .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(evaluation.reason_code.as_deref(), Some(CODE_STATUS_INVALID));
        let mut policy = strict_policy(gate_path.clone());
        policy.expected_command_manifest_digest = Some("sha256:not-a-digest".to_string());
        let evaluation = evaluate_startup_admission(&policy, &runtime).expect("valid policy");
        assert_eq!(
            evaluation.reason_code.as_deref(),
            Some(CODE_EXPECTED_MANIFEST_UNAVAILABLE)
        );
        let _ = fs::remove_file(executable);
        let _ = fs::remove_file(gate_path);
    }

    #[test]
    fn production_controls_and_expired_bypass_are_enforced() {
        let fixture_dir = tempfile::tempdir().expect("create isolated fixture directory");
        let mut policy = strict_policy(temp_path(&fixture_dir, "gate"));
        policy.production_mode = true;
        policy.mode = StartupAdmissionMode::Off;
        assert_eq!(
            policy.validate(),
            Err(AdmissionPolicyError::ProductionModeCannotDisableAdmission)
        );
        policy.mode = StartupAdmissionMode::Strict;
        policy.bypass = Some(AdmissionBypass {
            reason: "expired maintenance window".to_string(),
            expires_at: (OffsetDateTime::now_utc() - TimeDuration::minutes(1))
                .format(&Rfc3339)
                .expect("format expiry"),
        });
        assert_eq!(
            policy.validate(),
            Err(AdmissionPolicyError::ProductionBypassNotAllowed)
        );
        policy.allow_production_bypass = true;
        assert_eq!(policy.validate(), Ok(()));

        let executable = temp_path(&fixture_dir, "exe");
        fs::write(&executable, "binary").expect("write executable fixture");
        let runtime = runtime_for(&executable);
        let evaluation = evaluate_startup_admission(&policy, &runtime).expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(
            evaluation.reason_code.as_deref(),
            Some(CODE_OVERRIDE_EXPIRED)
        );
        let _ = fs::remove_file(executable);

        let mut invalid = strict_policy(temp_path(&fixture_dir, "gate"));
        invalid.bypass = Some(AdmissionBypass {
            reason: "  ".to_string(),
            expires_at: "not-a-timestamp".to_string(),
        });
        assert_eq!(
            invalid.validate(),
            Err(AdmissionPolicyError::BypassReasonRequired)
        );
        invalid.bypass = Some(AdmissionBypass {
            reason: "maintenance".to_string(),
            expires_at: "not-a-timestamp".to_string(),
        });
        assert_eq!(
            invalid.validate(),
            Err(AdmissionPolicyError::BypassExpiryInvalid)
        );
    }

    #[test]
    fn active_break_glass_bypass_requires_expiry_and_reason() {
        let fixture_dir = tempfile::tempdir().expect("create isolated fixture directory");
        let policy = StartupAdmissionPolicy {
            mode: StartupAdmissionMode::Strict,
            required_level: TestGateLevel::Standard,
            gate_path: temp_path(&fixture_dir, "gate"),
            production_mode: false,
            allow_production_bypass: false,
            bypass: Some(AdmissionBypass {
                reason: "emergency repair".to_string(),
                expires_at: (OffsetDateTime::now_utc() + TimeDuration::minutes(5))
                    .format(&Rfc3339)
                    .expect("format bypass expiry"),
            }),
            expected_command_manifest_digest: Some(format!("sha256:{}", "a".repeat(64))),
        };
        let executable = temp_path(&fixture_dir, "exe");
        fs::write(&executable, "binary").expect("write executable fixture");
        let runtime = runtime_for(&executable);

        let evaluation = evaluate_startup_admission(&policy, &runtime).expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Bypassed);
        assert!(evaluation.override_active);
        let _ = fs::remove_file(executable);
    }
}
