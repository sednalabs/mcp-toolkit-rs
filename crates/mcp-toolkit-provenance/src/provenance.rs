//! Build and runtime provenance capture plus schema-v2 envelope construction.
//!
//! Values are provider-neutral metadata; they are not cryptographic attestations.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const ATTESTATION_SCHEMA_VERSION: u32 = 2;
pub const UNKNOWN_VALUE: &str = "unknown";

/// Supplies build-time values used to create provider-neutral provenance.
#[derive(Debug, Clone, Copy)]
pub struct BuildProvenanceInput<'a> {
    pub component: &'a str,
    pub server_version: &'a str,
    pub revision: Option<&'a str>,
    pub reference: Option<&'a str>,
    /// Set to `None` when the build system did not provide a trustworthy dirty state.
    pub dirty: Option<bool>,
    pub profile: Option<&'a str>,
    pub target: Option<&'a str>,
    pub rustc_version: Option<&'a str>,
    pub source_date_epoch: Option<&'a str>,
    pub build_identity_override: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Holds canonical build identity and source metadata.
pub struct BuildProvenance {
    pub component: String,
    pub server_version: String,
    pub build_identity: String,
    pub source_fingerprint: String,
    pub source: SourceProvenance,
    pub build_metadata: BuildMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Describes source control state without asserting cryptographic integrity.
pub struct SourceProvenance {
    pub vcs: String,
    pub revision: String,
    pub reference: String,
    pub dirty: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Describes compiler and optional build configuration metadata.
pub struct BuildMetadata {
    pub profile: String,
    pub target: String,
    pub rustc_version: String,
    pub source_date_epoch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Describes the current process identity.
pub struct ProcessProvenance {
    pub pid: u32,
    pub executable_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Describes reportable executable metadata, which may be advisory only.
pub struct BinaryProvenance {
    pub file_size_bytes: Option<u64>,
    pub modified_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Combines build, process, and binary report data without asserting loaded-image identity.
pub struct RuntimeProvenance {
    pub build: BuildProvenance,
    pub process: ProcessProvenance,
    pub binary: BinaryProvenance,
}

/// Holds reportable provenance plus private evidence captured from the loaded image.
///
/// Only [`capture_current_runtime_provenance`] can construct this value. It is not
/// serializable or cloneable, so decoded or caller-built report data cannot be
/// used as startup freshness evidence.
///
/// ```compile_fail
/// use mcp_toolkit_provenance::CapturedRuntimeProvenance;
/// let _forged = serde_json::from_str::<CapturedRuntimeProvenance>("{}").unwrap();
/// ```
///
/// ```compile_fail
/// use mcp_toolkit_provenance::{CapturedRuntimeProvenance, RuntimeProvenance};
/// let runtime: RuntimeProvenance = todo!();
/// let _forged = CapturedRuntimeProvenance { runtime, loaded_image: None };
/// ```
pub struct CapturedRuntimeProvenance {
    runtime: RuntimeProvenance,
    loaded_image: Option<LoadedImageEvidence>,
}

/// Supplies the stamp's timestamp without asserting that it could be measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StampTimestamp {
    /// The caller successfully measured the stamp file's modification time.
    Known(SystemTime),
    /// The stamp file's modification time could not be measured.
    Unknown,
}

/// Reports the relationship between a stamp and the captured loaded image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StampFreshness {
    /// The stamp is at least as recent as the loaded image.
    Fresh,
    /// The stamp is older than the loaded image.
    Stale,
    /// The stamp modification time is unavailable.
    UnknownStamp,
    /// The loaded image's modification time is unavailable.
    UnavailableLoadedImage,
}

/// Compares a caller-measured stamp time with evidence from the captured loaded image.
///
/// A timestamp at the same instant as the loaded image is fresh. This function
/// compares full-precision `SystemTime` values and does not consult report data.
///
/// # Errors
/// This function is infallible; measurement failures are returned as variants.
pub fn evaluate_stamp_freshness(
    captured: &CapturedRuntimeProvenance,
    stamp: StampTimestamp,
) -> StampFreshness {
    let StampTimestamp::Known(stamp_modified) = stamp else {
        return StampFreshness::UnknownStamp;
    };
    let Some(loaded_image) = captured.loaded_image.as_ref() else {
        return StampFreshness::UnavailableLoadedImage;
    };

    if stamp_modified >= loaded_image.modified {
        StampFreshness::Fresh
    } else {
        StampFreshness::Stale
    }
}

impl CapturedRuntimeProvenance {
    /// Returns the reportable provenance without exposing its loaded-image proof.
    pub fn runtime(&self) -> &RuntimeProvenance {
        &self.runtime
    }

    pub(crate) fn loaded_image_modified_unix_ms(&self) -> Option<u64> {
        self.loaded_image
            .as_ref()
            .and_then(|evidence| evidence.modified_unix_ms)
    }

    #[cfg(test)]
    pub(crate) fn runtime_mut_for_test(&mut self) -> &mut RuntimeProvenance {
        &mut self.runtime
    }

    #[cfg(test)]
    pub(crate) fn clear_loaded_image_for_test(&mut self) {
        self.loaded_image = None;
    }
}

struct LoadedImageEvidence {
    // Retaining this handle ties the measured metadata to the opened loaded image.
    _file: File,
    file_size_bytes: u64,
    modified: SystemTime,
    modified_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Reports whether an envelope contains all required provenance fields.
pub enum AttestationStatus {
    Ok,
    Degraded,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Names a field that could not be reported, with a stable code and explanation.
pub struct UnavailableField {
    pub field: String,
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Identifies the service build represented by an attestation.
pub struct AttestationIdentity {
    pub server_version: String,
    pub contract_version: Option<String>,
    pub build_identity: String,
    pub source_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Holds process and executable values included in an attestation.
pub struct AttestationRuntime {
    pub pid: Option<u32>,
    pub executable_path: Option<String>,
    pub binary_size_bytes: Option<u64>,
    pub binary_modified_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Groups identity, source, build, and runtime attestation facts.
pub struct AttestationPayload {
    pub identity: AttestationIdentity,
    pub source: SourceProvenance,
    pub build_metadata: BuildMetadata,
    pub runtime: AttestationRuntime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// Represents a deterministic schema-v2 provider-neutral provenance envelope.
pub struct AttestationEnvelope {
    pub status: AttestationStatus,
    pub schema_version: u32,
    pub component: String,
    pub timestamp: String,
    pub request_id: Option<String>,
    pub attestation: AttestationPayload,
    pub unavailable: Vec<UnavailableField>,
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default)]
/// Configures optional envelope context and extension data.
pub struct AttestationOptions {
    pub contract_version: Option<String>,
    pub request_id: Option<String>,
    pub extensions: BTreeMap<String, Value>,
}

impl AttestationOptions {
    /// Adds a contract version to the envelope.
    pub fn with_contract_version(mut self, value: impl Into<String>) -> Self {
        self.contract_version = Some(value.into());
        self
    }

    /// Adds a caller request identifier to the envelope.
    pub fn with_request_id(mut self, value: impl Into<String>) -> Self {
        self.request_id = Some(value.into());
        self
    }

    /// Adds a namespaced JSON extension to the envelope.
    pub fn with_extension(mut self, namespace: impl Into<String>, value: Value) -> Self {
        self.extensions.insert(namespace.into(), value);
        self
    }
}

impl BuildProvenance {
    /// Builds canonical identity fields from compile-time metadata.
    ///
    /// Unknown revision or dirty state produces unknown identity and fingerprint values.
    pub fn from_input(input: BuildProvenanceInput<'_>) -> Self {
        let component = normalized_or(input.component, UNKNOWN_VALUE);
        let server_version = normalized_or(input.server_version, UNKNOWN_VALUE);
        let revision =
            normalized_option(input.revision).unwrap_or_else(|| UNKNOWN_VALUE.to_string());
        let reference =
            normalized_option(input.reference).unwrap_or_else(|| UNKNOWN_VALUE.to_string());
        let source_date_epoch = normalized_option(input.source_date_epoch);
        let source_fingerprint = source_fingerprint(&revision, input.dirty);
        let build_identity = normalized_option(input.build_identity_override)
            .unwrap_or_else(|| build_identity(&component, &server_version, &revision, input.dirty));

        Self {
            component,
            server_version,
            build_identity,
            source_fingerprint,
            source: SourceProvenance {
                vcs: "git".to_string(),
                revision,
                reference,
                dirty: input.dirty,
            },
            build_metadata: BuildMetadata {
                profile: normalized_option(input.profile)
                    .unwrap_or_else(|| UNKNOWN_VALUE.to_string()),
                target: normalized_option(input.target)
                    .unwrap_or_else(|| UNKNOWN_VALUE.to_string()),
                rustc_version: normalized_option(input.rustc_version)
                    .unwrap_or_else(|| UNKNOWN_VALUE.to_string()),
                source_date_epoch,
            },
        }
    }
}

/// Captures advisory process and executable metadata for the supplied path.
///
/// # Errors
/// This function reports unavailable filesystem values in the result rather than failing.
///
/// # Security
/// The supplied path is caller-selected. Its metadata is descriptive only and
/// cannot be used as proof of the currently loaded executable.
pub fn capture_runtime_provenance(
    build: BuildProvenance,
    executable_path: &Path,
) -> RuntimeProvenance {
    let metadata = fs::metadata(executable_path).ok();
    let modified_unix_ms = metadata
        .as_ref()
        .and_then(|meta| meta.modified().ok())
        .and_then(system_time_to_unix_ms);

    RuntimeProvenance {
        build,
        process: ProcessProvenance {
            pid: std::process::id(),
            executable_path: executable_path.display().to_string(),
        },
        binary: BinaryProvenance {
            file_size_bytes: metadata.as_ref().map(|meta| meta.len()),
            modified_unix_ms,
        },
    }
}

/// Captures descriptive provenance and, when supported, private loaded-image evidence.
///
/// # Errors
/// Returns the operating system error when the current executable path cannot be read.
///
/// # Security
/// The executable path is descriptive. Strict startup freshness uses metadata
/// from a private handle opened through verified procfs on Linux; unsupported
/// or unavailable providers do not fall back to pathname metadata. The host
/// or supervisor must control the process mount namespace so an untrusted
/// caller cannot replace the procfs view used for capture.
pub fn capture_current_runtime_provenance(
    build: BuildProvenance,
) -> std::io::Result<CapturedRuntimeProvenance> {
    let executable_path = std::env::current_exe()?;
    let loaded_image = capture_loaded_image();
    let binary = loaded_image.as_ref().map_or(
        BinaryProvenance {
            file_size_bytes: None,
            modified_unix_ms: None,
        },
        |evidence| BinaryProvenance {
            file_size_bytes: Some(evidence.file_size_bytes),
            modified_unix_ms: evidence.modified_unix_ms,
        },
    );

    Ok(CapturedRuntimeProvenance {
        runtime: RuntimeProvenance {
            build,
            process: ProcessProvenance {
                pid: std::process::id(),
                executable_path: executable_path.display().to_string(),
            },
            binary,
        },
        loaded_image,
    })
}

#[cfg(target_os = "linux")]
fn capture_loaded_image() -> Option<LoadedImageEvidence> {
    use std::os::fd::{AsRawFd, FromRawFd};

    const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;
    const O_CLOEXEC: libc::c_int = libc::O_CLOEXEC;
    const O_RDONLY: libc::c_int = libc::O_RDONLY;

    // Opening /proc/self once anchors both the filesystem check and the
    // executable lookup to the same mount. The deployment must keep this mount
    // namespace under OS/supervisor control so an untrusted caller cannot
    // replace procfs or its view between process start and capture.
    let proc_self = File::open("/proc/self").ok()?;
    let mut fs_info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: proc_self owns a live directory fd and fs_info points to writable
    // storage of the libc-defined statfs layout for this Linux target.
    let fs_result = unsafe { libc::fstatfs(proc_self.as_raw_fd(), fs_info.as_mut_ptr()) };
    if fs_result != 0 {
        return None;
    }
    // SAFETY: successful fstatfs initialized the complete statfs value.
    let fs_info = unsafe { fs_info.assume_init() };
    if fs_info.f_type as libc::c_long != PROC_SUPER_MAGIC {
        return None;
    }

    let exe_name = c"exe";
    // SAFETY: proc_self remains open; exe_name is a NUL-terminated constant;
    // flags request a read-only close-on-exec descriptor. The fd is converted
    // to File exactly once below, including the ownership transfer.
    let exe_fd = unsafe {
        libc::openat(
            proc_self.as_raw_fd(),
            exe_name.as_ptr(),
            O_RDONLY | O_CLOEXEC,
        )
    };
    if exe_fd < 0 {
        return None;
    }
    // SAFETY: openat returned a new owned descriptor, transferred to File.
    let file = unsafe { File::from_raw_fd(exe_fd) };
    let metadata = file.metadata().ok()?;
    let modified = metadata.modified().ok()?;
    let modified_unix_ms = system_time_to_unix_ms(modified);

    Some(LoadedImageEvidence {
        _file: file,
        file_size_bytes: metadata.len(),
        modified,
        modified_unix_ms,
    })
}

#[cfg(not(target_os = "linux"))]
fn capture_loaded_image() -> Option<LoadedImageEvidence> {
    None
}

/// Creates a schema-v2 envelope and lists every unavailable required field.
pub fn build_attestation_envelope(
    provenance: &RuntimeProvenance,
    options: AttestationOptions,
) -> AttestationEnvelope {
    let mut unavailable = Vec::new();

    for (field, value) in [
        ("attestation.component", provenance.build.component.as_str()),
        (
            "attestation.identity.server_version",
            provenance.build.server_version.as_str(),
        ),
        (
            "attestation.identity.build_identity",
            provenance.build.build_identity.as_str(),
        ),
        (
            "attestation.identity.source_fingerprint",
            provenance.build.source_fingerprint.as_str(),
        ),
    ] {
        if is_unknown(value) {
            unavailable.push(unavailable_field(
                field,
                "provenance.unavailable.required",
                "required build identity is unavailable",
            ));
        }
    }
    if is_unknown(&provenance.build.source.revision) {
        unavailable.push(unavailable_field(
            "attestation.source.revision",
            "provenance.unavailable.git_revision",
            "git revision unavailable in build context",
        ));
    }
    if provenance.build.source.dirty.is_none() {
        unavailable.push(unavailable_field(
            "attestation.source.dirty",
            "provenance.unavailable.dirty_state",
            "source dirty state was not provided by the build context",
        ));
    }
    if is_unknown(&provenance.build.source.reference) {
        unavailable.push(unavailable_field(
            "attestation.source.reference",
            "provenance.unavailable.git_reference",
            "git reference unavailable in build context",
        ));
    }
    if is_unknown(&provenance.build.build_metadata.rustc_version) {
        unavailable.push(unavailable_field(
            "attestation.build_metadata.rustc_version",
            "provenance.unavailable.rustc_version",
            "rustc version unavailable in build context",
        ));
    }
    if provenance.process.pid == 0 {
        unavailable.push(unavailable_field(
            "attestation.runtime.pid",
            "provenance.unavailable.process_id",
            "process id unavailable at runtime",
        ));
    }
    if is_unknown(&provenance.process.executable_path) {
        unavailable.push(unavailable_field(
            "attestation.runtime.executable_path",
            "provenance.unavailable.executable_path",
            "executable path unavailable at runtime",
        ));
    }
    if provenance.binary.file_size_bytes.is_none() {
        unavailable.push(unavailable_field(
            "attestation.runtime.binary_size_bytes",
            "provenance.unavailable.binary_size",
            "binary size unavailable at runtime",
        ));
    }
    if provenance.binary.modified_unix_ms.is_none() {
        unavailable.push(unavailable_field(
            "attestation.runtime.binary_modified_unix_ms",
            "provenance.unavailable.binary_mtime",
            "binary modification time unavailable at runtime",
        ));
    }

    let status = if unavailable.is_empty() {
        AttestationStatus::Ok
    } else {
        AttestationStatus::Degraded
    };

    AttestationEnvelope {
        status,
        schema_version: ATTESTATION_SCHEMA_VERSION,
        component: provenance.build.component.clone(),
        timestamp: now_rfc3339(),
        request_id: options.request_id,
        attestation: AttestationPayload {
            identity: AttestationIdentity {
                server_version: provenance.build.server_version.clone(),
                contract_version: options.contract_version,
                build_identity: provenance.build.build_identity.clone(),
                source_fingerprint: provenance.build.source_fingerprint.clone(),
            },
            source: provenance.build.source.clone(),
            build_metadata: provenance.build.build_metadata.clone(),
            runtime: AttestationRuntime {
                pid: (provenance.process.pid != 0).then_some(provenance.process.pid),
                executable_path: (!is_unknown(&provenance.process.executable_path))
                    .then(|| provenance.process.executable_path.clone()),
                binary_size_bytes: provenance.binary.file_size_bytes,
                binary_modified_unix_ms: provenance.binary.modified_unix_ms,
            },
        },
        unavailable,
        extensions: options.extensions,
    }
}

/// Creates a source fingerprint only when revision and dirty state are known.
pub fn source_fingerprint(revision: &str, dirty: Option<bool>) -> String {
    let Some(dirty) = dirty else {
        return UNKNOWN_VALUE.to_string();
    };
    if is_unknown(revision) {
        return UNKNOWN_VALUE.to_string();
    }
    let cleanliness = if dirty { "dirty" } else { "clean" };
    format!("git:{revision}:{cleanliness}")
}

/// Creates a readable build identity only when revision and dirty state are known.
pub fn build_identity(
    component: &str,
    server_version: &str,
    revision: &str,
    dirty: Option<bool>,
) -> String {
    let Some(dirty) = dirty else {
        return UNKNOWN_VALUE.to_string();
    };
    if is_unknown(revision) || is_unknown(component) || is_unknown(server_version) {
        return UNKNOWN_VALUE.to_string();
    }
    let mut value = format!("{component}@{server_version}+{revision}");
    if dirty {
        value.push_str("-dirty");
    }
    value
}

fn normalized_or(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalized_option(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) fn is_unknown(value: &str) -> bool {
    value.trim().is_empty() || value.eq_ignore_ascii_case(UNKNOWN_VALUE)
}

fn unavailable_field(field: &str, code: &str, reason: &str) -> UnavailableField {
    UnavailableField {
        field: field.to_string(),
        code: code.to_string(),
        reason: reason.to_string(),
    }
}

pub(crate) fn system_time_to_unix_ms(value: std::time::SystemTime) -> Option<u64> {
    let duration = value.duration_since(UNIX_EPOCH).ok()?;
    Some(duration.as_millis().min(u128::from(u64::MAX)) as u64)
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn input(dirty: Option<bool>) -> BuildProvenanceInput<'static> {
        BuildProvenanceInput {
            component: "example-mcp",
            server_version: "1.2.3",
            revision: Some("abc123"),
            reference: Some("main"),
            dirty,
            profile: Some("release"),
            target: Some("x86_64-unknown-linux-gnu"),
            rustc_version: Some("rustc test"),
            source_date_epoch: None,
            build_identity_override: None,
        }
    }

    fn captured_with_loaded_modified(modified: Option<SystemTime>) -> CapturedRuntimeProvenance {
        let loaded_image = modified.map(|modified| {
            let executable_path = std::env::current_exe().expect("current executable path");
            let file = File::open(executable_path).expect("open current executable");
            let file_size_bytes = file
                .metadata()
                .expect("metadata for current executable")
                .len();
            LoadedImageEvidence {
                _file: file,
                file_size_bytes,
                modified_unix_ms: system_time_to_unix_ms(modified),
                modified,
            }
        });
        let binary = loaded_image.as_ref().map_or(
            BinaryProvenance {
                file_size_bytes: None,
                modified_unix_ms: None,
            },
            |evidence| BinaryProvenance {
                file_size_bytes: Some(evidence.file_size_bytes),
                modified_unix_ms: evidence.modified_unix_ms,
            },
        );
        CapturedRuntimeProvenance {
            runtime: RuntimeProvenance {
                build: BuildProvenance::from_input(input(Some(false))),
                process: ProcessProvenance {
                    pid: std::process::id(),
                    executable_path: "test-only synthetic timestamp".to_string(),
                },
                binary,
            },
            loaded_image,
        }
    }

    #[test]
    fn canonical_identity_marks_dirty_builds() {
        let clean = BuildProvenance::from_input(input(Some(false)));
        assert_eq!(clean.build_identity, "example-mcp@1.2.3+abc123");
        assert_eq!(clean.source_fingerprint, "git:abc123:clean");

        let dirty = BuildProvenance::from_input(input(Some(true)));
        assert_eq!(dirty.build_identity, "example-mcp@1.2.3+abc123-dirty");
        assert_eq!(dirty.source_fingerprint, "git:abc123:dirty");
    }

    #[test]
    fn stamp_freshness_compares_full_precision_loaded_time() {
        let loaded = UNIX_EPOCH + Duration::from_millis(10) + Duration::from_nanos(800_000);
        let captured = captured_with_loaded_modified(Some(loaded));

        assert_eq!(
            evaluate_stamp_freshness(&captured, StampTimestamp::Known(loaded)),
            StampFreshness::Fresh
        );
        assert_eq!(
            evaluate_stamp_freshness(
                &captured,
                StampTimestamp::Known(loaded - Duration::from_nanos(1))
            ),
            StampFreshness::Stale
        );
        assert_eq!(
            evaluate_stamp_freshness(
                &captured,
                StampTimestamp::Known(loaded + Duration::from_nanos(1))
            ),
            StampFreshness::Fresh
        );
        assert_eq!(
            captured.runtime.binary.modified_unix_ms,
            Some(10),
            "the adjacent times intentionally share the same report millisecond"
        );
    }

    #[test]
    fn stamp_freshness_reports_unknown_and_unavailable_evidence() {
        let captured = captured_with_loaded_modified(Some(UNIX_EPOCH));
        assert_eq!(
            evaluate_stamp_freshness(&captured, StampTimestamp::Unknown),
            StampFreshness::UnknownStamp
        );

        let unavailable = captured_with_loaded_modified(None);
        assert_eq!(
            evaluate_stamp_freshness(
                &unavailable,
                StampTimestamp::Known(UNIX_EPOCH + Duration::from_secs(1))
            ),
            StampFreshness::UnavailableLoadedImage
        );
    }

    #[test]
    fn loaded_image_evidence_survives_unreportable_pre_epoch_time() {
        let pre_epoch = UNIX_EPOCH
            .checked_sub(Duration::from_nanos(1))
            .expect("one nanosecond before Unix epoch");
        let captured = captured_with_loaded_modified(Some(pre_epoch));
        let evidence = captured.loaded_image.as_ref().expect("loaded evidence");

        assert_eq!(evidence.modified, pre_epoch);
        assert_eq!(evidence.modified_unix_ms, None);
        assert_eq!(captured.runtime.binary.modified_unix_ms, None);
        assert_eq!(
            evaluate_stamp_freshness(&captured, StampTimestamp::Known(pre_epoch)),
            StampFreshness::Fresh
        );
    }

    #[test]
    fn unknown_revision_degrades_attestation_explicitly() {
        let mut input = input(Some(false));
        input.revision = None;
        let build = BuildProvenance::from_input(input);
        let runtime = RuntimeProvenance {
            build,
            process: ProcessProvenance {
                pid: 1,
                executable_path: "/tmp/example".to_string(),
            },
            binary: BinaryProvenance {
                file_size_bytes: Some(10),
                modified_unix_ms: Some(20),
            },
        };

        let envelope = build_attestation_envelope(&runtime, AttestationOptions::default());
        assert_eq!(envelope.status, AttestationStatus::Degraded);
        assert!(envelope
            .unavailable
            .iter()
            .any(|item| item.code == "provenance.unavailable.git_revision"));
    }

    #[test]
    fn unknown_dirty_state_and_missing_required_fields_degrade() {
        let mut input = input(None);
        input.component = " ";
        input.server_version = "";
        input.revision = None;
        input.reference = None;
        input.rustc_version = None;
        let build = BuildProvenance::from_input(input);
        assert_eq!(build.source_fingerprint, UNKNOWN_VALUE);
        assert_eq!(build.source.dirty, None);
        let runtime = RuntimeProvenance {
            build,
            process: ProcessProvenance {
                pid: 0,
                executable_path: UNKNOWN_VALUE.to_string(),
            },
            binary: BinaryProvenance {
                file_size_bytes: None,
                modified_unix_ms: None,
            },
        };
        let envelope = build_attestation_envelope(&runtime, AttestationOptions::default());
        assert_eq!(envelope.status, AttestationStatus::Degraded);
        for field in [
            "attestation.component",
            "attestation.identity.server_version",
            "attestation.source.dirty",
            "attestation.runtime.pid",
            "attestation.runtime.executable_path",
        ] {
            assert!(envelope
                .unavailable
                .iter()
                .any(|unavailable| unavailable.field == field));
        }
        let serialized = serde_json::to_string(&envelope).expect("serialize envelope");
        let decoded: AttestationEnvelope =
            serde_json::from_str(&serialized).expect("deserialize envelope");
        assert_eq!(decoded, envelope);
        assert!(envelope.attestation.runtime.pid.is_none());
        assert!(envelope.attestation.runtime.executable_path.is_none());
        let json: Value = serde_json::from_str(&serialized).expect("parse envelope JSON");
        assert!(json["attestation"]["runtime"]["pid"].is_null());
        assert!(json["attestation"]["runtime"]["executable_path"].is_null());

        let mut empty_path_runtime = runtime.clone();
        empty_path_runtime.process.pid = 1;
        empty_path_runtime.process.executable_path.clear();
        let empty_path_envelope =
            build_attestation_envelope(&empty_path_runtime, AttestationOptions::default());
        assert!(empty_path_envelope
            .attestation
            .runtime
            .executable_path
            .is_none());
    }

    #[test]
    fn optional_build_metadata_does_not_degrade_complete_required_fields() {
        let mut input = input(Some(false));
        input.profile = None;
        input.target = None;
        input.source_date_epoch = None;
        let build = BuildProvenance::from_input(input);
        let runtime = RuntimeProvenance {
            build,
            process: ProcessProvenance {
                pid: 1,
                executable_path: "/tmp/example".into(),
            },
            binary: BinaryProvenance {
                file_size_bytes: Some(1),
                modified_unix_ms: Some(1),
            },
        };
        let envelope = build_attestation_envelope(&runtime, AttestationOptions::default());
        assert_eq!(envelope.status, AttestationStatus::Ok);
        assert!(envelope.unavailable.is_empty());
    }

    #[test]
    fn current_capture_uses_private_loaded_image_metadata_when_supported() {
        let captured =
            capture_current_runtime_provenance(BuildProvenance::from_input(input(Some(false))))
                .expect("capture current executable");

        #[cfg(target_os = "linux")]
        {
            let evidence = captured
                .loaded_image
                .as_ref()
                .expect("verified procfs should provide loaded-image evidence");
            assert_eq!(
                captured.runtime.binary.file_size_bytes,
                Some(evidence.file_size_bytes)
            );
            assert_eq!(
                captured.runtime.binary.modified_unix_ms,
                evidence.modified_unix_ms
            );
        }

        #[cfg(not(target_os = "linux"))]
        {
            assert!(captured.loaded_image.is_none());
            assert_eq!(captured.runtime.binary.file_size_bytes, None);
            assert_eq!(captured.runtime.binary.modified_unix_ms, None);
        }

        let envelope =
            build_attestation_envelope(captured.runtime(), AttestationOptions::default());
        let json = serde_json::to_value(envelope).expect("serialize schema-v2 envelope");
        assert!(json.get("attestation").is_some());
        assert!(json["attestation"]["runtime"]
            .get("executable_path")
            .is_some());
        assert!(json["attestation"]["runtime"]
            .get("binary_modified_unix_ms")
            .is_some());
        assert!(json.get("loaded_image").is_none());
    }
}
