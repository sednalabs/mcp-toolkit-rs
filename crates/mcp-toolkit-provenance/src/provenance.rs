//! Build and runtime provenance capture plus schema-v2 envelope construction.
//!
//! Values are provider-neutral metadata; they are not cryptographic attestations.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

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
/// Describes available metadata for the running executable.
pub struct BinaryProvenance {
    pub file_size_bytes: Option<u64>,
    pub modified_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Combines build, process, and binary metadata.
pub struct RuntimeProvenance {
    pub build: BuildProvenance,
    pub process: ProcessProvenance,
    pub binary: BinaryProvenance,
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

/// Captures process and executable metadata for the supplied binary path.
///
/// # Errors
/// This function reports unavailable filesystem values in the result rather than failing.
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

/// Captures metadata for the currently running executable.
///
/// # Errors
/// Returns the operating system error when the current executable path cannot be read.
pub fn capture_current_runtime_provenance(
    build: BuildProvenance,
) -> std::io::Result<RuntimeProvenance> {
    let executable_path = std::env::current_exe()?;
    Ok(capture_runtime_provenance(build, &executable_path))
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
                pid: Some(provenance.process.pid),
                executable_path: Some(provenance.process.executable_path.clone()),
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

fn is_unknown(value: &str) -> bool {
    value.trim().is_empty() || value.eq_ignore_ascii_case(UNKNOWN_VALUE)
}

fn unavailable_field(field: &str, code: &str, reason: &str) -> UnavailableField {
    UnavailableField {
        field: field.to_string(),
        code: code.to_string(),
        reason: reason.to_string(),
    }
}

fn system_time_to_unix_ms(value: std::time::SystemTime) -> Option<u64> {
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
}
