//! # MCP Toolkit Provenance
//!
//! Reusable build provenance, runtime attestation, and startup proof-admission
//! primitives for Rust MCP services.
//!
//! This crate deliberately contains no provider-specific vocabulary and no MCP
//! transport implementation. It standardizes operational identity and startup
//! evidence that otherwise tends to be reimplemented independently by each
//! service.

pub mod admission;
pub mod provenance;

pub use admission::{
    evaluate_startup_admission, write_gate_artifact, AdmissionBypass, AdmissionEvaluation,
    AdmissionOutcome, AdmissionPolicyError, GateArtifactV1, StartupAdmissionMode,
    StartupAdmissionPolicy, TestGateLevel,
};
pub use provenance::{
    build_attestation_envelope, build_identity, capture_current_runtime_provenance,
    capture_runtime_provenance, source_fingerprint, AttestationEnvelope, AttestationIdentity,
    AttestationOptions, AttestationPayload, AttestationRuntime, AttestationStatus, BinaryProvenance,
    BuildMetadata, BuildProvenance, BuildProvenanceInput, ProcessProvenance, RuntimeProvenance,
    SourceProvenance, UnavailableField, ATTESTATION_SCHEMA_VERSION, UNKNOWN_VALUE,
};

/// Build canonical provenance from a consumer crate's compile-time environment.
///
/// The macro expands in the consuming crate, so `CARGO_PKG_NAME` and
/// `CARGO_PKG_VERSION` identify the service rather than this toolkit crate.
/// Build pipelines may inject the optional `MCP_BUILD_*` variables to bind the
/// binary to exact source/build metadata.
#[macro_export]
macro_rules! build_provenance_from_env {
    () => {{
        $crate::BuildProvenance::from_input($crate::BuildProvenanceInput {
            component: option_env!("MCP_BUILD_COMPONENT").unwrap_or(env!("CARGO_PKG_NAME")),
            server_version: option_env!("MCP_BUILD_SERVER_VERSION")
                .unwrap_or(env!("CARGO_PKG_VERSION")),
            revision: option_env!("MCP_BUILD_GIT_SHA"),
            reference: option_env!("MCP_BUILD_GIT_REF"),
            dirty: matches!(
                option_env!("MCP_BUILD_GIT_DIRTY")
                    .map(str::trim)
                    .map(str::to_ascii_lowercase)
                    .as_deref(),
                Some("1" | "true" | "yes" | "on")
            ),
            profile: option_env!("MCP_BUILD_PROFILE"),
            target: option_env!("MCP_BUILD_TARGET"),
            rustc_version: option_env!("MCP_BUILD_RUSTC_VERSION"),
            source_date_epoch: option_env!("MCP_BUILD_SOURCE_DATE_EPOCH"),
            build_identity_override: option_env!("MCP_BUILD_IDENTITY_OVERRIDE"),
        })
    }};
}
