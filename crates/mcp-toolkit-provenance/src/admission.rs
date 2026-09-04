use std::ffi::OsString;
use std::fmt::{self, Write as _};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{
    DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt,
    OpenOptionsSyncExt,
};
use cap_std::fs::{Dir, OpenOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::provenance::{RuntimeProvenance, UNKNOWN_VALUE};

pub const MAX_GATE_ARTIFACT_BYTES: usize = 64 * 1024;

pub const CODE_DISABLED: &str = "admission.disabled";
pub const CODE_OVERRIDE: &str = "admission.override.active";
pub const CODE_OVERRIDE_EXPIRED: &str = "admission.override.expired";
pub const CODE_MISSING: &str = "admission.gate.missing";
pub const CODE_NOT_REGULAR: &str = "admission.gate.not_regular";
pub const CODE_SYMLINK_REJECTED: &str = "admission.gate.symlink_rejected";
pub const CODE_TOO_LARGE: &str = "admission.gate.too_large";
pub const CODE_READ_FAILED: &str = "admission.gate.read_failed";
pub const CODE_DIGEST_MISMATCH: &str = "admission.gate.digest_mismatch";
pub const CODE_EXPIRED: &str = "admission.gate.expired";
pub const CODE_STATUS_INVALID: &str = "admission.gate.status_invalid";
pub const CODE_COMPONENT_MISMATCH: &str = "admission.gate.component_mismatch";
pub const CODE_LEVEL_MISMATCH: &str = "admission.gate.level_mismatch";
pub const CODE_BUILD_MISMATCH: &str = "admission.gate.build_mismatch";
pub const CODE_SOURCE_MISMATCH: &str = "admission.gate.source_mismatch";
pub const CODE_MANIFEST_MISMATCH: &str = "admission.gate.manifest_mismatch";
pub const CODE_TIMESTAMP_INVALID: &str = "admission.gate.timestamp_invalid";
pub const CODE_PROVENANCE_UNAVAILABLE: &str = "admission.runtime.provenance_unavailable";

/// The maximum number of bytes admitted from a gate artifact. One extra byte
/// is read so that an oversized artifact is rejected without an unbounded read.
pub const GATE_ARTIFACT_READ_LIMIT: usize = MAX_GATE_ARTIFACT_BYTES + 1;

/// A retained capability to the operator-selected directory containing a gate.
///
/// The ambient path is used only once, at this configuration boundary. All
/// subsequent opens are relative to the retained directory handle.
pub struct TrustedGateRoot {
    dir: Dir,
    display_path: PathBuf,
}

impl fmt::Debug for TrustedGateRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedGateRoot")
            .field("display_path", &self.display_path)
            .finish_non_exhaustive()
    }
}

/// A read-only gate-artifact source bound to a retained parent capability and
/// one final basename. It has no writer or arbitrary-path operation.
pub struct GateArtifactSource {
    parent: Dir,
    basename: OsString,
    display_path: PathBuf,
}

impl fmt::Debug for GateArtifactSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GateArtifactSource")
            .field("display_path", &self.display_path)
            .finish_non_exhaustive()
    }
}

/// Errors produced while establishing a retained gate capability.
#[derive(Debug, PartialEq, Eq)]
pub enum GateSourceError {
    RootNotAbsolute,
    RootTraversal,
    RootUnavailable(String),
    ArtifactPathEmpty,
    ArtifactPathAbsolute,
    ArtifactPathTraversal,
    ArtifactPathInvalid,
    IntermediateUnavailable { component: String, error: String },
}

impl fmt::Display for GateSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootNotAbsolute => write!(formatter, "trusted gate root must be absolute"),
            Self::RootTraversal => {
                write!(formatter, "trusted gate root must not contain traversal components")
            }
            Self::RootUnavailable(error) => {
                write!(formatter, "trusted gate root is unavailable: {error}")
            }
            Self::ArtifactPathEmpty => write!(formatter, "gate artifact path is empty"),
            Self::ArtifactPathAbsolute => {
                write!(formatter, "gate artifact path must be relative to its root")
            }
            Self::ArtifactPathTraversal => {
                write!(formatter, "gate artifact path must not contain traversal components")
            }
            Self::ArtifactPathInvalid => {
                write!(formatter, "gate artifact path contains an invalid component")
            }
            Self::IntermediateUnavailable { component, error } => write!(
                formatter,
                "gate artifact parent component {component:?} is unavailable: {error}"
            ),
        }
    }
}

impl std::error::Error for GateSourceError {}

impl TrustedGateRoot {
    /// Open and retain an operator-selected absolute directory capability.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GateSourceError> {
        let path = path.as_ref();
        validate_root_path(path)?;
        let dir = Dir::open_ambient_dir(path, cap_std::ambient_authority())
            .map_err(|error| GateSourceError::RootUnavailable(error.to_string()))?;
        Ok(Self {
            dir,
            display_path: path.to_path_buf(),
        })
    }

    /// Alias for [`TrustedGateRoot::open`] that emphasizes the binding point.
    pub fn bind_root(path: impl AsRef<Path>) -> Result<Self, GateSourceError> {
        Self::open(path)
    }

    /// Bind a relative gate path by retaining its final parent directory.
    pub fn bind(&self, path: impl AsRef<Path>) -> Result<GateArtifactSource, GateSourceError> {
        let path = path.as_ref();
        validate_artifact_path(path)?;

        let mut parent = self
            .dir
            .try_clone()
            .map_err(|error| GateSourceError::RootUnavailable(error.to_string()))?;
        let mut components = path.components().peekable();
        let basename = loop {
            let Some(component) = components.next() else {
                return Err(GateSourceError::ArtifactPathEmpty);
            };
            let Component::Normal(name) = component else {
                return Err(GateSourceError::ArtifactPathInvalid);
            };
            if components.peek().is_none() {
                break name.to_os_string();
            }
            parent = parent.open_dir_nofollow(Path::new(name)).map_err(|error| {
                GateSourceError::IntermediateUnavailable {
                    component: name.to_string_lossy().into_owned(),
                    error: error.to_string(),
                }
            })?;
        };

        Ok(GateArtifactSource {
            parent,
            basename,
            display_path: self.display_path.join(path),
        })
    }

    /// Alias for [`TrustedGateRoot::bind`] for callers that prefer source
    /// terminology at the configuration boundary.
    pub fn source(&self, path: impl AsRef<Path>) -> Result<GateArtifactSource, GateSourceError> {
        self.bind(path)
    }

    /// Return the configuration path for diagnostics only.
    pub fn path(&self) -> &Path {
        &self.display_path
    }
}

impl GateArtifactSource {
    /// Return the configuration path for diagnostics only.
    pub fn path(&self) -> &Path {
        &self.display_path
    }

    /// Duplicate the retained parent capability for an independently owned
    /// source value without exposing the underlying directory handle.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            parent: self.parent.try_clone()?,
            basename: self.basename.clone(),
            display_path: self.display_path.clone(),
        })
    }

    fn read_bounded(&self) -> Result<Vec<u8>, GateReadError> {
        let path = Path::new(self.basename.as_os_str());
        let link_metadata = self
            .parent
            .symlink_metadata(path)
            .map_err(GateReadError::from_open)?;
        if link_metadata.file_type().is_symlink() {
            return Err(GateReadError::SymlinkRejected(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gate artifact is a symbolic link or reparse point",
            )));
        }
        if !link_metadata.file_type().is_file() {
            return Err(GateReadError::NotRegular);
        }

        let mut options = OpenOptions::new();
        options
            .read(true)
            .follow(FollowSymlinks::No)
            .maybe_dir(false)
            .nonblock(true);

        let file = self
            .parent
            .open_with(path, &options)
            .map_err(GateReadError::from_open)?;
        let metadata = file.metadata().map_err(GateReadError::ReadFailed)?;
        if !metadata.file_type().is_file() {
            return Err(GateReadError::NotRegular);
        }

        let mut bytes = Vec::with_capacity(GATE_ARTIFACT_READ_LIMIT);
        file.take(GATE_ARTIFACT_READ_LIMIT as u64)
            .read_to_end(&mut bytes)
            .map_err(GateReadError::ReadFailed)?;
        if bytes.len() > MAX_GATE_ARTIFACT_BYTES {
            return Err(GateReadError::TooLarge {
                limit: MAX_GATE_ARTIFACT_BYTES,
            });
        }
        Ok(bytes)
    }
}

/// Structured reasons from the one-handle, bounded gate read.
#[derive(Debug)]
pub enum GateReadError {
    Missing(io::Error),
    SymlinkRejected(io::Error),
    NotRegular,
    TooLarge { limit: usize },
    ReadFailed(io::Error),
}

impl GateReadError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Missing(_) => CODE_MISSING,
            Self::SymlinkRejected(_) => CODE_SYMLINK_REJECTED,
            Self::NotRegular => CODE_NOT_REGULAR,
            Self::TooLarge { .. } => CODE_TOO_LARGE,
            Self::ReadFailed(_) => CODE_READ_FAILED,
        }
    }
}

impl fmt::Display for GateReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(error) => write!(formatter, "gate artifact is missing: {error}"),
            Self::SymlinkRejected(error) => {
                write!(formatter, "gate artifact symlink or reparse point rejected: {error}")
            }
            Self::NotRegular => write!(formatter, "gate artifact is not a regular file"),
            Self::TooLarge { limit } => {
                write!(formatter, "gate artifact exceeds the {limit}-byte limit")
            }
            Self::ReadFailed(error) => write!(formatter, "failed to read gate artifact: {error}"),
        }
    }
}

impl std::error::Error for GateReadError {}

impl GateReadError {
    fn from_open(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => Self::Missing(error),
            io::ErrorKind::InvalidInput => Self::SymlinkRejected(error),
            io::ErrorKind::IsADirectory => Self::NotRegular,
            _ => Self::ReadFailed(error),
        }
    }
}

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

#[derive(Debug)]
pub struct StartupAdmissionPolicy {
    pub mode: StartupAdmissionMode,
    pub required_level: TestGateLevel,
    /// Read-only source bound to a retained capability root.
    pub gate_source: GateArtifactSource,
    /// SHA-256 of the exact gate bytes expected on the immutable launch/config
    /// channel. The digest is checked before deserialization.
    pub expected_gate_artifact_digest: String,
    pub production_mode: bool,
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
    pub issued_at: String,
    pub expires_at: String,
}

impl GateArtifactV1 {
    /// Construct a passing artifact with an issuance timestamp from the
    /// current UTC clock. Publication remains outside this crate.
    pub fn passing(
        runtime: &RuntimeProvenance,
        level: TestGateLevel,
        command_manifest_digest: impl Into<String>,
        expires_at: impl Into<String>,
    ) -> Self {
        Self::passing_with_timestamps(
            runtime,
            level,
            command_manifest_digest,
            now_rfc3339(),
            expires_at,
        )
    }

    pub fn passing_with_timestamps(
        runtime: &RuntimeProvenance,
        level: TestGateLevel,
        command_manifest_digest: impl Into<String>,
        issued_at: impl Into<String>,
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
            issued_at: issued_at.into(),
            expires_at: expires_at.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionPolicyError {
    ProductionModeRequiresStrict,
    BypassReasonRequired,
    BypassExpiryInvalid,
    ProductionBypassNotAllowed,
    GateArtifactDigestInvalid,
}

impl fmt::Display for AdmissionPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProductionModeRequiresStrict => write!(
                formatter,
                "production startup admission requires strict mode"
            ),
            Self::BypassReasonRequired => {
                write!(formatter, "startup admission bypass requires a reason")
            }
            Self::BypassExpiryInvalid => write!(
                formatter,
                "startup admission bypass requires a valid RFC3339 expires_at"
            ),
            Self::ProductionBypassNotAllowed => write!(
                formatter,
                "startup admission bypass is not allowed in production mode"
            ),
            Self::GateArtifactDigestInvalid => write!(
                formatter,
                "startup admission requires a canonical sha256 gate-artifact digest"
            ),
        }
    }
}

impl std::error::Error for AdmissionPolicyError {}

impl StartupAdmissionPolicy {
    pub fn validate(&self) -> Result<(), AdmissionPolicyError> {
        if self.production_mode && !matches!(self.mode, StartupAdmissionMode::Strict) {
            return Err(AdmissionPolicyError::ProductionModeRequiresStrict);
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
        if !valid_sha256_reference(&self.expected_gate_artifact_digest) {
            return Err(AdmissionPolicyError::GateArtifactDigestInvalid);
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
            gate_path: policy.gate_source.path().to_path_buf(),
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
        if now < expires_at {
            return Ok(AdmissionEvaluation {
                outcome: AdmissionOutcome::Bypassed,
                required_level: policy.required_level,
                gate_path: policy.gate_source.path().to_path_buf(),
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

    let bytes = match policy.gate_source.read_bounded() {
        Ok(bytes) => bytes,
        Err(error) => {
            let reason_code = if expired_bypass {
                CODE_OVERRIDE_EXPIRED
            } else {
                error.code()
            };
            return Ok(warning_or_reject(
                policy,
                reason_code,
                if expired_bypass {
                    format!("startup admission bypass expired and gate is unavailable: {error}")
                } else {
                    error.to_string()
                },
            ));
        }
    };

    let actual_digest = sha256_reference(&bytes);
    if actual_digest != policy.expected_gate_artifact_digest {
        return Ok(warning_or_reject(
            policy,
            CODE_DIGEST_MISMATCH,
            format!(
                "gate artifact digest mismatch: expected {}, found {}",
                policy.expected_gate_artifact_digest, actual_digest
            ),
        ));
    }

    let artifact = match serde_json::from_slice::<GateArtifactV1>(&bytes) {
        Ok(artifact) => artifact,
        Err(error) => {
            return Ok(warning_or_reject(
                policy,
                CODE_STATUS_INVALID,
                format!("invalid gate artifact JSON payload: {error}"),
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
            format!(
                "gate command_manifest_digest is not canonical: {}",
                artifact.command_manifest_digest
            ),
        ));
    }

    let issued_at = match OffsetDateTime::parse(&artifact.issued_at, &Rfc3339) {
        Ok(value) => value,
        Err(error) => {
            return Ok(warning_or_reject(
                policy,
                CODE_TIMESTAMP_INVALID,
                format!("gate issued_at is not valid RFC3339: {error}"),
            ));
        }
    };
    let expires_at = match OffsetDateTime::parse(&artifact.expires_at, &Rfc3339) {
        Ok(value) => value,
        Err(error) => {
            return Ok(warning_or_reject(
                policy,
                CODE_TIMESTAMP_INVALID,
                format!("gate expires_at is not valid RFC3339: {error}"),
            ));
        }
    };
    if issued_at > now || expires_at <= issued_at {
        return Ok(warning_or_reject(
            policy,
            CODE_TIMESTAMP_INVALID,
            format!(
                "gate artifact timestamp window is invalid: issued_at={}, expires_at={}",
                artifact.issued_at, artifact.expires_at
            ),
        ));
    }
    if now >= expires_at {
        return Ok(warning_or_reject(
            policy,
            CODE_EXPIRED,
            format!("gate artifact expired at {}", artifact.expires_at),
        ));
    }

    Ok(AdmissionEvaluation {
        outcome: AdmissionOutcome::Passed,
        required_level: policy.required_level,
        gate_path: policy.gate_source.path().to_path_buf(),
        reason_code: None,
        detail: "startup admission checks passed".to_string(),
        override_active: false,
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
        gate_path: policy.gate_source.path().to_path_buf(),
        reason_code: Some(reason_code.to_string()),
        detail,
        override_active: false,
    }
}

fn validate_root_path(path: &Path) -> Result<(), GateSourceError> {
    if !path.is_absolute() {
        return Err(GateSourceError::RootNotAbsolute);
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(GateSourceError::RootTraversal);
    }
    Ok(())
}

fn validate_artifact_path(path: &Path) -> Result<(), GateSourceError> {
    if path.as_os_str().is_empty() {
        return Err(GateSourceError::ArtifactPathEmpty);
    }
    if path.is_absolute() {
        return Err(GateSourceError::ArtifactPathAbsolute);
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir => {
                return Err(GateSourceError::ArtifactPathTraversal)
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(GateSourceError::ArtifactPathAbsolute)
            }
        }
    }
    Ok(())
}

fn valid_sha256_reference(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn sha256_reference(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut reference = String::from("sha256:");
    for byte in digest {
        let _ = write!(&mut reference, "{byte:02x}");
    }
    reference
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

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use time::Duration as TimeDuration;

    use super::*;
    use crate::provenance::{capture_runtime_provenance, BuildProvenance, BuildProvenanceInput};

    const TEST_MANIFEST_DIGEST: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn temp_root() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("mcp-toolkit-provenance-tree-{nonce}"));
        fs::create_dir_all(&path).expect("create temporary test directory");
        path
    }

    fn runtime() -> RuntimeProvenance {
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
        capture_runtime_provenance(build)
    }

    fn artifact(runtime: &RuntimeProvenance) -> GateArtifactV1 {
        let issued_at = (OffsetDateTime::now_utc() - TimeDuration::minutes(1))
            .format(&Rfc3339)
            .expect("format issuance");
        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::hours(1))
            .format(&Rfc3339)
            .expect("format expiry");
        GateArtifactV1::passing_with_timestamps(
            runtime,
            TestGateLevel::Fast,
            TEST_MANIFEST_DIGEST,
            issued_at,
            expires_at,
        )
    }

    fn payload(runtime: &RuntimeProvenance) -> Vec<u8> {
        serde_json::to_vec(&artifact(runtime)).expect("serialize test artifact")
    }

    fn digest(bytes: &[u8]) -> String {
        sha256_reference(bytes)
    }

    fn strict_policy(
        source: GateArtifactSource,
        expected_digest: String,
    ) -> StartupAdmissionPolicy {
        StartupAdmissionPolicy {
            mode: StartupAdmissionMode::Strict,
            required_level: TestGateLevel::Fast,
            gate_source: source,
            expected_gate_artifact_digest: expected_digest,
            production_mode: false,
            bypass: None,
        }
    }

    #[test]
    fn strict_mode_accepts_digest_bound_gate() {
        let root = temp_root();
        let runtime = runtime();
        let bytes = payload(&runtime);
        fs::write(root.join("gate.json"), &bytes).expect("write test artifact");
        let source = TrustedGateRoot::open(&root)
            .expect("bind root")
            .bind("gate.json")
            .expect("bind source");

        let evaluation =
            evaluate_startup_admission(&strict_policy(source, digest(&bytes)), &runtime)
                .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Passed);
        assert_eq!(evaluation.reason_code, None);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn wrong_digest_is_rejected_before_json_parsing() {
        let root = temp_root();
        let runtime = runtime();
        let bytes = b"not-json";
        fs::write(root.join("gate.json"), bytes).expect("write test artifact");
        let source = TrustedGateRoot::open(&root)
            .expect("bind root")
            .bind("gate.json")
            .expect("bind source");
        let expected = digest(b"different bytes");

        let evaluation = evaluate_startup_admission(&strict_policy(source, expected), &runtime)
            .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(evaluation.reason_code.as_deref(), Some(CODE_DIGEST_MISMATCH));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn oversized_gate_is_rejected_at_bounded_read() {
        let root = temp_root();
        let runtime = runtime();
        let bytes = vec![b'x'; GATE_ARTIFACT_READ_LIMIT];
        fs::write(root.join("gate.json"), &bytes).expect("write test artifact");
        let source = TrustedGateRoot::open(&root)
            .expect("bind root")
            .bind("gate.json")
            .expect("bind source");
        let evaluation =
            evaluate_startup_admission(&strict_policy(source, digest(&bytes)), &runtime)
                .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(evaluation.reason_code.as_deref(), Some(CODE_TOO_LARGE));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn production_requires_strict_and_disallows_bypass() {
        let root = temp_root();
        let runtime = runtime();
        let bytes = payload(&runtime);
        fs::write(root.join("gate.json"), &bytes).expect("write test artifact");
        let source = TrustedGateRoot::open(&root)
            .expect("bind root")
            .bind("gate.json")
            .expect("bind source");
        let policy = StartupAdmissionPolicy {
            mode: StartupAdmissionMode::Warn,
            required_level: TestGateLevel::Fast,
            gate_source: source,
            expected_gate_artifact_digest: digest(&bytes),
            production_mode: true,
            bypass: None,
        };
        assert_eq!(
            policy.validate(),
            Err(AdmissionPolicyError::ProductionModeRequiresStrict)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn source_rejects_absolute_and_traversal_paths() {
        let root = temp_root();
        let trusted = TrustedGateRoot::open(&root).expect("bind root");
        assert!(matches!(
            trusted.bind(Path::new("../gate.json")),
            Err(GateSourceError::ArtifactPathTraversal)
        ));
        assert!(matches!(
            trusted.bind(root.join("gate.json")),
            Err(GateSourceError::ArtifactPathAbsolute)
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn retained_parent_survives_post_bind_replacement() {
        let root = temp_root();
        let old_root = root.join("old");
        fs::create_dir_all(&old_root).expect("create old root");
        let runtime = runtime();
        let bytes = payload(&runtime);
        fs::write(old_root.join("gate.json"), &bytes).expect("write test artifact");
        let trusted = TrustedGateRoot::open(&old_root).expect("bind root");
        let source = trusted.bind("gate.json").expect("bind source");

        let moved = root.join("moved");
        fs::rename(&old_root, &moved).expect("rename bound root");
        fs::create_dir_all(&old_root).expect("replace root path");
        fs::write(old_root.join("gate.json"), b"wrong bytes").expect("write replacement");

        let evaluation =
            evaluate_startup_admission(&strict_policy(source, digest(&bytes)), &runtime)
                .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Passed);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn expired_authenticated_artifact_is_rejected() {
        let root = temp_root();
        let runtime = runtime();
        let issued_at = (OffsetDateTime::now_utc() - TimeDuration::hours(2))
            .format(&Rfc3339)
            .expect("format issuance");
        let expires_at = (OffsetDateTime::now_utc() - TimeDuration::hours(1))
            .format(&Rfc3339)
            .expect("format expiry");
        let artifact = GateArtifactV1::passing_with_timestamps(
            &runtime,
            TestGateLevel::Fast,
            TEST_MANIFEST_DIGEST,
            issued_at,
            expires_at,
        );
        let bytes = serde_json::to_vec(&artifact).expect("serialize test artifact");
        fs::write(root.join("gate.json"), &bytes).expect("write test artifact");
        let source = TrustedGateRoot::open(&root)
            .expect("bind root")
            .bind("gate.json")
            .expect("bind source");
        let evaluation =
            evaluate_startup_admission(&strict_policy(source, digest(&bytes)), &runtime)
                .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Rejected);
        assert_eq!(evaluation.reason_code.as_deref(), Some(CODE_EXPIRED));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mtime_is_not_an_admission_input() {
        let root = temp_root();
        let mut runtime = runtime();
        runtime.binary.modified_unix_ms = None;
        let bytes = payload(&runtime);
        fs::write(root.join("gate.json"), &bytes).expect("write test artifact");
        let source = TrustedGateRoot::open(&root)
            .expect("bind root")
            .bind("gate.json")
            .expect("bind source");
        let evaluation =
            evaluate_startup_admission(&strict_policy(source, digest(&bytes)), &runtime)
                .expect("valid policy");
        assert_eq!(evaluation.outcome, AdmissionOutcome::Passed);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn artifact_constructor_still_supports_current_expiry_api() {
        let runtime = runtime();
        let expiry = (OffsetDateTime::now_utc() + TimeDuration::hours(1))
            .format(&Rfc3339)
            .expect("format expiry");
        let artifact = GateArtifactV1::passing(
            &runtime,
            TestGateLevel::Fast,
            TEST_MANIFEST_DIGEST,
            expiry,
        );
        assert_eq!(artifact.schema_version, 1);
        assert_eq!(artifact.status, "pass");
        assert!(!artifact.issued_at.is_empty());
    }
}
