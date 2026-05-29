//! # Policy Kernel FFI Raw Stubs
//!
//! Low-level C-style structures and external function declarations for the SPARK
//! policy kernel.
//!
//! ## Ownership
//! This module owns the C-compatible memory layout definitions (structs) and
//! FFI symbol signatures required for dynamic interoperation with the SPARK kernel.
//!
//! ## Non-ownership
//! This module does not manage the logic defining how kernel decisions are
//! computed or proof-checked; it strictly defines the interface.
//!
//! ## Policy & Guarantees
//! * **ABI Strictness**: Enforces memory alignment and data layout to maintain
//!   binary compatibility with the upstream SPARK policy kernel.
//! * **Foreign Boundary Safety**: Uses `repr(C)` and explicit pointers to bridge
//!   Rust memory safety with FFI memory models.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Ensuring that ABI structures match the exact header definitions provided
//!   by the SPARK implementation.
//! * Validating the `PkAbiVersion` of the loaded kernel before invoking functions.
//! * Managing the lifecycle of pointers passed across the FFI boundary.
//!
//! ## References
//! * `mcp-policy-kernel` header definitions.

use std::os::raw::{c_char, c_int, c_uint};

/// A non-owning view into a UTF-8 string, suitable for FFI passing.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PkStrView {
    pub ptr: *const c_char,
    pub len: usize,
}

/// A non-owning view into a list of strings.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PkStrList {
    pub items: *const PkStrView,
    pub len: usize,
}

/// An optional string view.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PkOptStr {
    pub present: u8,
    pub value: PkStrView,
}

/// Stable error codes returned by the kernel.
pub type PkDecisionCode = c_int;
pub const PK_DECISION_NONE: PkDecisionCode = 0;
pub const PK_DECISION_MISSING_TOKEN: PkDecisionCode = 1;
pub const PK_DECISION_MISSING_SCOPES: PkDecisionCode = 2;
pub const PK_DECISION_MISSING_ROLES: PkDecisionCode = 3;
pub const PK_DECISION_ISSUER_MISMATCH: PkDecisionCode = 4;
pub const PK_DECISION_AUDIENCE_MISMATCH: PkDecisionCode = 5;
pub const PK_DECISION_AZP_NOT_ALLOWED: PkDecisionCode = 6;
pub const PK_DECISION_INVALID_PATH: PkDecisionCode = 7;
pub const PK_DECISION_MISSING_REALM: PkDecisionCode = 8;
pub const PK_DECISION_SYSTEM_TOKEN_FORBIDDEN: PkDecisionCode = 9;
pub const PK_DECISION_ALLOWLIST_DENIED: PkDecisionCode = 10;
pub const PK_DECISION_CAPABILITY_MISSING: PkDecisionCode = 11;
pub const PK_DECISION_CAPABILITY_MISMATCH: PkDecisionCode = 12;
pub const PK_DECISION_QUORUM_MISSING: PkDecisionCode = 13;
pub const PK_DECISION_QUORUM_STALE: PkDecisionCode = 14;
pub const PK_DECISION_EMPTY_SQL: PkDecisionCode = 15;
pub const PK_DECISION_UNTERMINATED_TOKEN: PkDecisionCode = 16;
pub const PK_DECISION_MULTIPLE_STATEMENTS: PkDecisionCode = 17;
pub const PK_DECISION_NOT_READ_ONLY_PREFIX: PkDecisionCode = 18;
pub const PK_DECISION_FORBIDDEN_KEYWORD: PkDecisionCode = 19;
pub const PK_DECISION_FORBIDDEN_FUNCTION: PkDecisionCode = 20;
pub const PK_DECISION_EXPLAIN_NOT_READ_ONLY: PkDecisionCode = 21;
pub const PK_DECISION_CLASSIFIER_UNAVAILABLE: PkDecisionCode = 22;
pub const PK_DECISION_SPARK_RUNTIME_UNAVAILABLE: PkDecisionCode = 23;
pub const PK_DECISION_INVALID_INPUT: PkDecisionCode = 24;

/// Result of a kernel decision.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PkDecision {
    pub allow: u8,
    pub code: PkDecisionCode,
}

pub type PkAudKind = c_int;
pub const PK_AUD_NONE: PkAudKind = 0;
pub const PK_AUD_STRING: PkAudKind = 1;
pub const PK_AUD_LIST: PkAudKind = 2;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PkAudClaim {
    pub kind: PkAudKind,
    pub string: PkStrView,
    pub list: PkStrList,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PkClaimsCfg {
    pub expected_issuer: PkOptStr,
    pub expected_audience: PkOptStr,
    pub allowed_azp: PkStrList,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PkTokenClaims {
    pub iss: PkOptStr,
    pub aud: PkAudClaim,
    pub azp: PkOptStr,
    pub client_id: PkOptStr,
}

pub type PkAccess = c_int;
pub const PK_ACCESS_READ: PkAccess = 0;
pub const PK_ACCESS_WRITE: PkAccess = 1;

pub type PkRisk = c_int;
pub const PK_RISK_LOW: PkRisk = 0;
pub const PK_RISK_HIGH: PkRisk = 1;

pub type PkQuorum = c_int;
pub const PK_QUORUM_OK: PkQuorum = 0;
pub const PK_QUORUM_MISSING: PkQuorum = 1;
pub const PK_QUORUM_STALE: PkQuorum = 2;
pub const PK_QUORUM_DISABLED: PkQuorum = 3;

// ABI guardrails: Ada side fixes discriminants to C int-sized values.
const _: [(); 4] = [(); std::mem::size_of::<PkDecisionCode>()];
const _: [(); 4] = [(); std::mem::size_of::<PkAudKind>()];
const _: [(); 4] = [(); std::mem::size_of::<PkAccess>()];
const _: [(); 4] = [(); std::mem::size_of::<PkRisk>()];
const _: [(); 4] = [(); std::mem::size_of::<PkQuorum>()];
const _: [(); 1] = [(); std::mem::size_of::<u8>()];

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PkAuthCtx {
    pub scopes: PkStrList,
    pub roles: PkStrList,
    pub azp: PkOptStr,
    pub is_system: u8,
    pub project_id: u64,
    pub cap_sql_key: PkOptStr,
    pub cap_params_hash: PkOptStr,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PkDasCfg {
    pub write_implies_read: u8,
    pub system_allow_endpoints: PkStrList,
    pub system_allow_sql_keys: PkStrList,
    pub devtools_roles: PkStrList,
    pub delegation_mode: u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PkDasQuery {
    pub endpoint: PkStrView,
    pub sql_key: PkStrView,
    pub params_hash: PkStrView,
    pub access: PkAccess,
    pub risk: PkRisk,
    pub quorum: PkQuorum,
}

#[repr(C)]
pub struct PkAbiVersion {
    pub major: c_uint,
    pub minor: c_uint,
}

extern "C" {
    /// Return the ABI version of the linked policy kernel.
    pub fn pk_policy_kernel_abi_version() -> PkAbiVersion;
    /// Validates a bearer header.
    pub fn pk_validate_bearer_header(raw_bearer: PkStrView) -> PkDecision;
    /// Enforces OIDC claim invariants.
    pub fn pk_enforce_claims(cfg: PkClaimsCfg, claims: PkTokenClaims) -> PkDecision;
    /// Executes restricted SQL classification policy.
    pub fn pk_sql_restricted_policy_decision(
        policy_contract_version: PkStrView,
        sql: PkStrView,
    ) -> PkDecision;
    /// Executes gateway authorization decision.
    pub fn pk_gateway_decision(
        method: PkStrView,
        path: PkStrView,
        token_scopes: PkStrList,
        cfg: PkClaimsCfg,
        claims: PkTokenClaims,
    ) -> PkDecision;
    /// Executes a DAS database access decision.
    pub fn pk_das_query_decision(
        auth: PkAuthCtx,
        cfg: PkDasCfg,
        query: PkDasQuery,
        allowlist: PkStrList,
    ) -> PkDecision;
    /// Executes a DAS observability access decision.
    pub fn pk_das_observability_decision(
        auth: PkAuthCtx,
        cfg: PkDasCfg,
        endpoint: PkStrView,
    ) -> PkDecision;
}

include!(concat!(env!("OUT_DIR"), "/pk_abi.rs"));
