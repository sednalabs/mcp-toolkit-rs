use std::fmt;
use std::io::{self, Read};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::provenance::{RuntimeProvenance, TrustedLocalPath, UNKNOWN_VALUE};

pub const CODE_DISABLED: &str = "admission.disabled";
pub const CODE_OVERRIDE: &str = "admission.override.active";
pub const CODE_OVERRIDE_EXPIRED: &str = "admission.override.expired";
pub const CODE_MISSING: &str = "admission.gate.missing";
pub const CODE_NOT_REGULAR: &str = "admission.gate.not_regular";
pub const CODE_EXPIRED: &str = "admission.gate.expired";
pub const CODE_STATUS_INVALID: &str = "admission.gate.status_invalid";
pub const CODE_COMPONENT_MISMATCH: &str = "admission.gate.component_mismatch";
pub const CODE_LEVEL_MISMATCH: &str = "admission.gate.level_mismatch";
pub const CODE_BUILD_MISMATCH: &str = "admission.gate.build_mismatch";
pub const CODE_SOURCE_MISMATCH: &str = "admission.gate.source_mismatch";
pub const CODE_MANIFEST_MISMATCH: &str = "admission.gate.manifest_mismatch";
pub const CODE_TIMESTAMP_INVALID: &str = "admission.gate.timestamp_invalid";
pub const CODE_PROVENANCE_UNAVAILABLE: &str = "admission.runtime.provenance_unavailable";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StartupAdmissionMode {
    Off,
    Warn,
    Strict,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestGateLevel {
    Fast,
    Standard,
}

impl TestGateLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Standard => "standard",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionBypass {
    pub reason: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupAdmissionPolicy {
    pub mode: StartupAdmissionMode,
    pub required_level: TestGateLevel,
    /// Operator-selected local gate-artifact path. This path is read during
    /// startup admission and must not be populated from request data.
    pub gate_path: TrustedLocalPath,
    /// Exact command-manifest digest required by the startup gate.
    pub expected_command_manifest_digest: String,
    pub production_mode: bool,
    pub allow_production_bypass: bool,
    pub bypass: Option<AdmissionBypass>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionOutcome {
    Disabled,
    Bypassed,
    Passed,
    Warning,
    Rejected,
}

impl AdmissionOutcome {
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
pub struct AdmissionEvaluation {
    pub outcome: AdmissionOutcome,
    pub required_level: TestGateLevel,
    pub gate_path: PathBuf,
    pub reason_code: Option<String>,
    pub detail: String,
    pub override_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
pub enum AdmissionPolicyError {
    ProductionModeCannotDisableAdmission,
    BypassReasonRequired,
    BypassExpiryInvalid,
    ProductionBypassNotAllowed,
    CommandManifestDigestInvalid,
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
            Self::CommandManifestDigestInvalid => write!(
                f,
                "startup admission requires a canonical sha256 command-manifest digest"
            ),
        }
    }
}

impl std::error::Error for AdmissionPolicyError {}

impl StartupAdmissionPolicy {
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
            if self.production_mode {
                return Err(AdmissionPolicyError::ProductionBypassNotAllowed);
            }
        }
        if !valid_sha256_reference(&self.expected_command_manifest_digest) {
            return Err(AdmissionPolicyError::CommandManifestDigestInvalid);
        }
        Ok(())
    }
}

pub fn evaluate_startup_admission(
    policy: &StartupAdmissionPolicy,
    runtime: &RuntimeProvenance,
) -> Result<AdmissionEvaluation, AdmissionPolicyError> {
    policy.validate()?;

    if matches!(policy.mode, StartupAdmissionMode::Off) {
        return Ok(AdmissionEvaluation {
            outcome: AdmissionOutcome::Disabled,
            required_level: policy.required_level,
            gate_path: policy.gate_path.as_ref().to_path_buf(),
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
                gate_path: policy.gate_path.as_ref().to_path_buf(),
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

    if is_unknown(&runtime.build.component)
        || is_unknown(&runtime.build.server_version)
        || is_unknown(&runtime.build.source.revision)
        || is_unknown(&runtime.build.source.reference)
        || is_unknown(&runtime.build.build_identity)
        || is_unknown(&runtime.build.source_fingerprint)
        || is_unknown(&runtime.build.build_metadata.profile)
        || is_unknown(&runtime.build.build_metadata.target)
        || is_unknown(&runtime.build.build_metadata.rustc_version)
        || !valid_source_date_epoch(runtime.build.build_metadata.source_date_epoch.as_deref())
    {
        return Ok(warning_or_reject(
            policy,
            CODE_PROVENANCE_UNAVAILABLE,
            "runtime build provenance is incomplete".to_string(),
        ));
    }

    let mut gate_file = match policy.gate_path.open_confined_read() {
        Ok(file) => file,
        Err(err) => {
            let not_regular = err.kind() == io::ErrorKind::InvalidData;
            return Ok(warning_or_reject(
                policy,
                if not_regular {
                    CODE_NOT_REGULAR
                } else if expired_bypass {
                    CODE_OVERRIDE_EXPIRED
                } else {
                    CODE_MISSING
                },
                if not_regular {
                    format!("required gate artifact is not a regular file: {err}")
                } else if expired_bypass {
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
                format!("failed to inspect gate artifact: {err}"),
            ));
        }
    };

    let mut raw = String::new();
    if let Err(err) = gate_file.read_to_string(&mut raw) {
        return Ok(warning_or_reject(
            policy,
            CODE_MISSING,
            format!("failed to read gate artifact: {err}"),
        ));
    }
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
    if !valid_sha256_reference(&artifact.command_manifest_digest)
        || artifact.command_manifest_digest != policy.expected_command_manifest_digest
    {
        return Ok(warning_or_reject(
            policy,
            CODE_MANIFEST_MISMATCH,
            format!(
                "gate command_manifest_digest mismatch: expected {}, found {}",
                policy.expected_command_manifest_digest, artifact.command_manifest_digest
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
        gate_path: policy.gate_path.as_ref().to_path_buf(),
        reason_code: None,
        detail: "startup admission checks passed".to_string(),
        override_active: false,
    })
}

/// Writes a gate artifact to an operator-selected local path using an atomic
/// temporary-file replacement. The path must come from trusted build or
/// deployment configuration, never from request data.
pub fn write_gate_artifact(
    path: &TrustedLocalPath,
    artifact: &GateArtifactV1,
) -> Result<(), String> {
    let payload = serde_json::to_vec_pretty(artifact)
        .map_err(|err| format!("failed to serialize gate artifact: {err}"))?;
    path.write_confined_atomic(&payload).map_err(|err| {
        format!(
            "failed to write gate artifact {}: {err}",
            path.as_ref().display()
        )
    })
}

/// Marks an operator-selected local gate path for CodeQL's path-flow model.
/// The helper is crate-private so request-handling code cannot reuse it as a
/// generic path sanitizer.
#[cfg(test)]
pub(crate) fn operator_local_gate_path(path: &TrustedLocalPath) -> &Path {
    path.as_ref()
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
        gate_path: policy.gate_path.as_ref().to_path_buf(),
        reason_code: Some(reason_code.to_string()),
        detail,
        override_active: false,
    }
}

fn valid_sha256_reference(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_unknown(value: &str) -> bool {
    value.trim().is_empty() || value.eq_ignore_ascii_case(UNKNOWN_VALUE)
}

fn valid_source_date_epoch(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        let value = value.trim();
        !is_unknown(value) && value.parse::<u64>().is_ok()
    })
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

fn system_time_to_unix_ms(value: std::time::SystemTime) -> Option<u64> {
    let duration = value.duration_since(UNIX_EPOCH).ok()?;
    Some(duration.as_millis().min(u128::from(u64::MAX)) as u64)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use time::Duration as TimeDuration;

    use super::*;
    use crate::provenance::{capture_runtime_provenance, BuildProvenance, BuildProvenanceInput};

    fn temp_path() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from("/tmp").join(format!("mcp-toolkit-provenance-{nonce}"));
        fs::File::create(&path).expect("create temporary test path");
        path
    }

    #[cfg(unix)]
    fn temp_directory() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from("/tmp").join(format!("mcp-toolkit-provenance-tree-{nonce}"));
        fs::create_dir_all(&path).expect("create temporary test directory");
        path
    }

    const TEST_MANIFEST_DIGEST: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn trusted_path(path: PathBuf) -> TrustedLocalPath {
        TrustedLocalPath::from_root("/tmp", path).expect("bind trusted test path")
    }

    fn runtime_for(executable: &Path) -> RuntimeProvenance {
        let build = BuildProvenance::from_input(BuildProvenanceInput {
            component: "example-mcp",
            server_version: "1.0.0",
            revision: Some("abc123"),
            reference: Some("main"),
            dirty: false,
            profile: Some("release"),
            target: Some("x86_64-unknown-linux-gnu"),
            rustc_version: Some("rustc test"),
            source_date_epoch: Some("1700000000"),
            build_identity_override: None,
        });
        let executable = TrustedLocalPath::from_root(
            executable.parent().expect("executable parent"),
            executable,
        )
        .expect("bind executable path");
        capture_runtime_provenance(build, &executable)
    }

    fn strict_policy(gate_path: TrustedLocalPath) -> StartupAdmissionPolicy {
        StartupAdmissionPolicy {
            mode: StartupAdmissionMode::Strict,
            required_level: TestGateLevel::Fast,
            gate_path,
            expected_command_manifest_digest: TEST_MANIFEST_DIGEST.to_string(),
            production_mode: false,
            allow_production_bypass: false,
            bypass: None,
        }
    }

    #[test]
    fn strict_mode_rejects_missing_gate() {
        let executable = std::env::current_exe().expect("resolve test executable");
        let runtime = runtime_for(&executable);
        let gate_path = trusted_path(temp_path());
        let _ = fs::remove_file(operator_local_gate_path(&gate_path));
        let evaluation =
            evaluate_startup_admission(&strict_policy(gate_path), &runtime).expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(evaluation.reason_code.as_deref(), Some(CODE_MISSING));
    }

    #[test]
    fn strict_mode_accepts_gate_bound_to_running_build() {
        let executable = std::env::current_exe().expect("resolve test executable");
        let runtime = runtime_for(&executable);
        std::thread::sleep(Duration::from_millis(25));
        let gate_path = trusted_path(temp_path());
        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::hours(1))
            .format(&Rfc3339)
            .expect("format expiry");
        let artifact = GateArtifactV1::passing(
            &runtime,
            TestGateLevel::Fast,
            TEST_MANIFEST_DIGEST,
            expires_at,
        );
        write_gate_artifact(&gate_path, &artifact).expect("write gate");

        let evaluation = evaluate_startup_admission(&strict_policy(gate_path.clone()), &runtime)
            .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Passed);
        let _ = fs::remove_file(operator_local_gate_path(&gate_path));
    }

    #[test]
    fn gate_bound_to_different_build_is_rejected() {
        let executable = std::env::current_exe().expect("resolve test executable");
        let runtime = runtime_for(&executable);
        std::thread::sleep(Duration::from_millis(25));
        let gate_path = trusted_path(temp_path());
        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::hours(1))
            .format(&Rfc3339)
            .expect("format expiry");
        let mut artifact = GateArtifactV1::passing(
            &runtime,
            TestGateLevel::Fast,
            TEST_MANIFEST_DIGEST,
            expires_at,
        );
        artifact.build_identity = "other-mcp@1.0.0+deadbeef".to_string();
        write_gate_artifact(&gate_path, &artifact).expect("write gate");

        let evaluation = evaluate_startup_admission(&strict_policy(gate_path.clone()), &runtime)
            .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(evaluation.reason_code.as_deref(), Some(CODE_BUILD_MISMATCH));
        let _ = fs::remove_file(operator_local_gate_path(&gate_path));
    }

    #[test]
    fn strict_mode_rejects_mismatched_command_manifest() {
        let executable = std::env::current_exe().expect("resolve test executable");
        let runtime = runtime_for(&executable);
        std::thread::sleep(Duration::from_millis(25));
        let gate_path = trusted_path(temp_path());
        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::hours(1))
            .format(&Rfc3339)
            .expect("format expiry");
        let artifact = GateArtifactV1::passing(
            &runtime,
            TestGateLevel::Fast,
            "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            expires_at,
        );
        write_gate_artifact(&gate_path, &artifact).expect("write gate");

        let evaluation = evaluate_startup_admission(&strict_policy(gate_path.clone()), &runtime)
            .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(
            evaluation.reason_code.as_deref(),
            Some(CODE_MANIFEST_MISMATCH)
        );
        let _ = fs::remove_file(operator_local_gate_path(&gate_path));
    }

    #[test]
    fn strict_mode_rejects_unknown_component_provenance() {
        let executable = std::env::current_exe().expect("resolve test executable");
        let mut runtime = runtime_for(&executable);
        runtime.build.component = UNKNOWN_VALUE.to_string();
        let gate_path = trusted_path(temp_path());
        let evaluation =
            evaluate_startup_admission(&strict_policy(gate_path), &runtime).expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(
            evaluation.reason_code.as_deref(),
            Some(CODE_PROVENANCE_UNAVAILABLE)
        );
    }

    #[test]
    fn strict_mode_rejects_unknown_or_invalid_source_date_epoch() {
        let executable = std::env::current_exe().expect("resolve test executable");
        let mut runtime = runtime_for(&executable);
        let gate_path = trusted_path(temp_path());

        for value in [None, Some(UNKNOWN_VALUE), Some(" "), Some("not-a-number")] {
            runtime.build.build_metadata.source_date_epoch = value.map(str::to_owned);
            let evaluation =
                evaluate_startup_admission(&strict_policy(gate_path.clone()), &runtime)
                    .expect("valid policy");
            assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
            assert_eq!(
                evaluation.reason_code.as_deref(),
                Some(CODE_PROVENANCE_UNAVAILABLE)
            );
        }

        let _ = fs::remove_file(operator_local_gate_path(&gate_path));
    }

    #[cfg(unix)]
    #[test]
    fn write_gate_artifact_rejects_planted_temp_symlink() {
        use std::os::unix::fs::symlink;

        let executable = std::env::current_exe().expect("resolve test executable");
        let runtime = runtime_for(&executable);
        let gate_path = trusted_path(temp_path());
        let outside_path = temp_path();
        let temp_file_path = operator_local_gate_path(&gate_path).with_extension("tmp");
        fs::write(&outside_path, b"sentinel").expect("write outside sentinel");
        let _ = fs::remove_file(&temp_file_path);
        symlink(&outside_path, &temp_file_path).expect("plant temp symlink");

        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::hours(1))
            .format(&Rfc3339)
            .expect("format expiry");
        let artifact = GateArtifactV1::passing(
            &runtime,
            TestGateLevel::Fast,
            TEST_MANIFEST_DIGEST,
            expires_at,
        );

        assert!(write_gate_artifact(&gate_path, &artifact).is_err());
        assert_eq!(
            fs::read(&outside_path)
                .expect("read outside sentinel")
                .as_slice(),
            b"sentinel"
        );

        let _ = fs::remove_file(&temp_file_path);
        let _ = fs::remove_file(operator_local_gate_path(&gate_path));
        let _ = fs::remove_file(&outside_path);
    }

    #[cfg(unix)]
    #[test]
    fn strict_mode_rejects_gate_symlink_without_reading_outside() {
        use std::os::unix::fs::symlink;

        let executable = std::env::current_exe().expect("resolve test executable");
        let runtime = runtime_for(&executable);
        let gate_binding = trusted_path(temp_path());
        let outside_binding = trusted_path(temp_path());
        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::hours(1))
            .format(&Rfc3339)
            .expect("format expiry");
        let artifact = GateArtifactV1::passing(
            &runtime,
            TestGateLevel::Fast,
            TEST_MANIFEST_DIGEST,
            expires_at,
        );
        write_gate_artifact(&outside_binding, &artifact).expect("write outside gate");

        let gate_path = operator_local_gate_path(&gate_binding).to_path_buf();
        let outside_path = operator_local_gate_path(&outside_binding).to_path_buf();
        fs::remove_file(&gate_path).expect("remove gate placeholder");
        symlink(&outside_path, &gate_path).expect("plant gate symlink");

        let evaluation = evaluate_startup_admission(&strict_policy(gate_binding), &runtime)
            .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(evaluation.reason_code.as_deref(), Some(CODE_MISSING));

        let _ = fs::remove_file(&gate_path);
        let _ = fs::remove_file(&outside_path);
    }

    #[cfg(unix)]
    #[test]
    fn trusted_intermediate_directory_replacement_is_rejected() {
        use std::os::unix::fs::symlink;

        let executable = std::env::current_exe().expect("resolve test executable");
        let runtime = runtime_for(&executable);
        let root = temp_directory();
        let trusted_directory = root.join("trusted");
        fs::create_dir(&trusted_directory).expect("create trusted directory");
        let gate_path = trusted_directory.join("gate");
        fs::File::create(&gate_path).expect("create gate placeholder");
        let gate_binding =
            TrustedLocalPath::from_root(&root, &gate_path).expect("bind trusted gate path");

        let outside_directory = temp_directory();
        let outside_gate = outside_directory.join("gate");
        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::hours(1))
            .format(&Rfc3339)
            .expect("format expiry");
        let artifact = GateArtifactV1::passing(
            &runtime,
            TestGateLevel::Fast,
            TEST_MANIFEST_DIGEST,
            expires_at,
        );
        let outside_payload = serde_json::to_vec_pretty(&artifact).expect("serialize gate");
        fs::write(&outside_gate, &outside_payload).expect("write outside gate");

        fs::remove_file(&gate_path).expect("remove gate placeholder");
        fs::remove_dir(&trusted_directory).expect("remove trusted directory");
        symlink(&outside_directory, &trusted_directory).expect("replace directory with symlink");

        let evaluation = evaluate_startup_admission(&strict_policy(gate_binding.clone()), &runtime)
            .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(evaluation.reason_code.as_deref(), Some(CODE_MISSING));

        assert!(write_gate_artifact(&gate_binding, &artifact).is_err());
        assert_eq!(
            fs::read(&outside_gate)
                .expect("read outside gate")
                .as_slice(),
            outside_payload.as_slice()
        );
        assert!(!outside_gate.with_extension("tmp").exists());

        let _ = fs::remove_file(&trusted_directory);
        let _ = fs::remove_file(&outside_gate);
        let _ = fs::remove_dir(&outside_directory);
        let _ = fs::remove_dir(&root);
    }

    #[cfg(unix)]
    #[test]
    fn trusted_root_replacement_is_rejected() {
        use std::os::unix::fs::symlink;

        let executable = std::env::current_exe().expect("resolve test executable");
        let runtime = runtime_for(&executable);
        let root = temp_directory();
        let gate_path = root.join("gate");
        fs::File::create(&gate_path).expect("create gate placeholder");
        let gate_binding =
            TrustedLocalPath::from_root(&root, &gate_path).expect("bind trusted gate path");

        let outside_directory = temp_directory();
        let outside_gate = outside_directory.join("gate");
        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::hours(1))
            .format(&Rfc3339)
            .expect("format expiry");
        let artifact = GateArtifactV1::passing(
            &runtime,
            TestGateLevel::Fast,
            TEST_MANIFEST_DIGEST,
            expires_at,
        );
        let outside_payload = serde_json::to_vec_pretty(&artifact).expect("serialize gate");
        fs::write(&outside_gate, &outside_payload).expect("write outside gate");

        fs::remove_file(&gate_path).expect("remove gate placeholder");
        fs::remove_dir(&root).expect("remove trusted root");
        symlink(&outside_directory, &root).expect("replace root with symlink");

        let evaluation = evaluate_startup_admission(&strict_policy(gate_binding.clone()), &runtime)
            .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(evaluation.reason_code.as_deref(), Some(CODE_MISSING));

        assert!(write_gate_artifact(&gate_binding, &artifact).is_err());
        assert_eq!(
            fs::read(&outside_gate)
                .expect("read outside gate")
                .as_slice(),
            outside_payload.as_slice()
        );
        assert!(!outside_gate.with_extension("tmp").exists());

        let _ = fs::remove_file(&root);
        let _ = fs::remove_file(&outside_gate);
        let _ = fs::remove_dir(&outside_directory);
    }

    #[cfg(unix)]
    #[test]
    fn strict_mode_rejects_fifo_gate_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::sync::mpsc;

        let executable = std::env::current_exe().expect("resolve test executable");
        let runtime = runtime_for(&executable);
        let gate_path = temp_path();
        fs::remove_file(&gate_path).expect("remove gate placeholder");
        let fifo_name = CString::new(gate_path.as_os_str().as_bytes()).expect("FIFO path");
        // SAFETY: fifo_name is a valid NUL-terminated path and the mode is valid.
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let gate_binding = trusted_path(gate_path);

        let (sender, receiver) = mpsc::channel();
        let policy = strict_policy(gate_binding.clone());
        std::thread::spawn(move || {
            let evaluation = evaluate_startup_admission(&policy, &runtime).expect("valid policy");
            sender.send(evaluation).expect("send FIFO evaluation");
        });
        let evaluation = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("FIFO admission must not block");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(evaluation.reason_code.as_deref(), Some(CODE_NOT_REGULAR));

        let _ = fs::remove_file(operator_local_gate_path(&gate_binding));
    }

    #[test]
    fn active_break_glass_bypass_requires_expiry_and_reason() {
        let policy = StartupAdmissionPolicy {
            mode: StartupAdmissionMode::Strict,
            required_level: TestGateLevel::Standard,
            gate_path: trusted_path(temp_path()),
            expected_command_manifest_digest: TEST_MANIFEST_DIGEST.to_string(),
            production_mode: false,
            allow_production_bypass: false,
            bypass: Some(AdmissionBypass {
                reason: "emergency repair".to_string(),
                expires_at: (OffsetDateTime::now_utc() + TimeDuration::minutes(5))
                    .format(&Rfc3339)
                    .expect("format bypass expiry"),
            }),
        };
        let executable = std::env::current_exe().expect("resolve test executable");
        let runtime = runtime_for(&executable);

        let evaluation = evaluate_startup_admission(&policy, &runtime).expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Bypassed);
        assert!(evaluation.override_active);
    }

    #[test]
    fn production_mode_rejects_all_admission_bypasses() {
        let policy = StartupAdmissionPolicy {
            mode: StartupAdmissionMode::Strict,
            required_level: TestGateLevel::Standard,
            gate_path: trusted_path(temp_path()),
            expected_command_manifest_digest: TEST_MANIFEST_DIGEST.to_string(),
            production_mode: true,
            allow_production_bypass: true,
            bypass: Some(AdmissionBypass {
                reason: "emergency repair".to_string(),
                expires_at: (OffsetDateTime::now_utc() + TimeDuration::minutes(5))
                    .format(&Rfc3339)
                    .expect("format bypass expiry"),
            }),
        };

        assert_eq!(
            policy.validate(),
            Err(AdmissionPolicyError::ProductionBypassNotAllowed)
        );
    }
}
