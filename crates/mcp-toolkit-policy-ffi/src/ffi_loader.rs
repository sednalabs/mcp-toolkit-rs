//! # Policy Kernel FFI Loader
//!
//! Managed loader for the dynamic SPARK policy kernel.
//!
//! ## Ownership
//! This module owns the dynamic library loading, symbol resolution, and FFI marshaling
//! layer, mediating between Rust and the external policy kernel.
//!
//! ## Non-ownership
//! This module does not define the policy itself; it is an infrastructure component
//! for invoking the independently-compiled policy kernel.
//!
//! ## Policy & Guarantees
//! * **ABI Verification**: Validates the ABI major version before resolving symbols,
//!   reducing the risk of memory corruption from mismatched kernel versions.
//! * **Resource Management**: Ensures safe cleanup of loaded kernel symbols.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Configuring the kernel library path and runtime mode via environment variables.
//! * Validating the environment security context in which the kernel binary is loaded.
//!
//! ## References
//! * `crates/mcp-toolkit-policy-ffi/src/ffi.rs`

use std::env;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::OnceLock;

use libloading::{Library, Symbol};
use mcp_toolkit_policy_core::{
    ClaimsCfg, Decision, DecisionCode, SqlRestrictedPolicyInput, MALFORMED_CLAIMS_REASON,
    SQL_POLICY_REASON,
};
use mcp_toolkit_policy_kernel_adapters::{
    DasAuthInput, DasCfgInput, DasDecisionInput, DasObservabilityInput, DasQueryInput,
    GatewayDecisionInput, QuorumState, SqlAccess, SqlRisk,
};
use serde_json::Value;

use crate::ffi::{
    PkAbiVersion, PkAccess, PkAudClaim, PkAuthCtx, PkClaimsCfg, PkDasCfg, PkDasQuery, PkDecision,
    PkDecisionCode, PkOptStr, PkQuorum, PkRisk, PkStrList, PkStrView, PkTokenClaims, PK_ABI_MAJOR,
    PK_ACCESS_READ, PK_ACCESS_WRITE, PK_AUD_LIST, PK_AUD_NONE, PK_DECISION_ALLOWLIST_DENIED,
    PK_DECISION_AUDIENCE_MISMATCH, PK_DECISION_AZP_NOT_ALLOWED, PK_DECISION_CAPABILITY_MISMATCH,
    PK_DECISION_CAPABILITY_MISSING, PK_DECISION_CLASSIFIER_UNAVAILABLE, PK_DECISION_EMPTY_SQL,
    PK_DECISION_EXPLAIN_NOT_READ_ONLY, PK_DECISION_FORBIDDEN_FUNCTION,
    PK_DECISION_FORBIDDEN_KEYWORD, PK_DECISION_INVALID_INPUT, PK_DECISION_INVALID_PATH,
    PK_DECISION_ISSUER_MISMATCH, PK_DECISION_MISSING_REALM, PK_DECISION_MISSING_ROLES,
    PK_DECISION_MISSING_SCOPES, PK_DECISION_MISSING_TOKEN, PK_DECISION_MULTIPLE_STATEMENTS,
    PK_DECISION_NONE, PK_DECISION_NOT_READ_ONLY_PREFIX, PK_DECISION_QUORUM_MISSING,
    PK_DECISION_QUORUM_STALE, PK_DECISION_SPARK_RUNTIME_UNAVAILABLE,
    PK_DECISION_SYSTEM_TOKEN_FORBIDDEN, PK_DECISION_UNTERMINATED_TOKEN, PK_QUORUM_DISABLED,
    PK_QUORUM_MISSING, PK_QUORUM_OK, PK_QUORUM_STALE, PK_RISK_HIGH, PK_RISK_LOW,
};
const MODE_ENV: &str = "PK_POLICY_KERNEL_MODE";
const LIB_PATH_ENV: &str = "PK_POLICY_KERNEL_LIBRARY";
const KERNEL_ROOT_ENV: &str = "PK_POLICY_KERNEL_ROOT";
const MODE_SPARK_PREFER: &str = "spark-prefer";
const MODE_SPARK_REQUIRED: &str = "spark-required";

/// Runtime operation mode for the FFI policy kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparkRuntimeMode {
    Rust,
    SparkPrefer,
    SparkRequired,
}

/// Detects the configured policy runtime mode from the process environment.
pub fn runtime_mode() -> SparkRuntimeMode {
    let value = env::var(MODE_ENV).unwrap_or_default();
    match value.trim().to_ascii_lowercase().as_str() {
        MODE_SPARK_PREFER => SparkRuntimeMode::SparkPrefer,
        MODE_SPARK_REQUIRED => SparkRuntimeMode::SparkRequired,
        _ => SparkRuntimeMode::Rust,
    }
}
// ... internal state omitted for clarity ...

fn default_library_path() -> PathBuf {
    configured_kernel_root()
        .join("spark")
        .join("libpk_policy_kernel.so")
}

fn configured_kernel_root() -> PathBuf {
    env::var_os(KERNEL_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("..")
                .join("..")
                .join("mcp-policy-kernel")
        })
}

fn configured_library_path() -> PathBuf {
    env::var_os(LIB_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(default_library_path)
}

struct SparkKernel {
    _library: Library,
    validate_bearer_header: unsafe extern "C" fn(PkStrView) -> PkDecision,
    enforce_claims: unsafe extern "C" fn(PkClaimsCfg, PkTokenClaims) -> PkDecision,
    sql_restricted_policy_decision:
        Option<unsafe extern "C" fn(PkStrView, PkStrView) -> PkDecision>,
    gateway_decision: unsafe extern "C" fn(
        PkStrView,
        PkStrView,
        PkStrList,
        PkClaimsCfg,
        PkTokenClaims,
    ) -> PkDecision,
    das_query_decision:
        unsafe extern "C" fn(PkAuthCtx, PkDasCfg, PkDasQuery, PkStrList) -> PkDecision,
    das_observability_decision: unsafe extern "C" fn(PkAuthCtx, PkDasCfg, PkStrView) -> PkDecision,
}

impl SparkKernel {
    fn load() -> Result<Self, String> {
        let path = configured_library_path();
        let library = unsafe { Library::new(&path) }
            .map_err(|err| format!("failed to load {}: {}", path.display(), err))?;

        let (
            validate_bearer_header,
            enforce_claims,
            sql_restricted_policy_decision,
            gateway_decision,
            das_query_decision,
            das_observability_decision,
        ) = unsafe {
            let abi_version: Symbol<'_, unsafe extern "C" fn() -> PkAbiVersion> = library
                .get(b"pk_policy_kernel_abi_version")
                .map_err(|err| format!("missing symbol pk_policy_kernel_abi_version: {err}"))?;

            let abi = abi_version();
            if abi.major != PK_ABI_MAJOR {
                return Err(format!(
                    "abi major mismatch: library={} expected={}",
                    abi.major, PK_ABI_MAJOR
                ));
            }

            let validate_bearer_header: Symbol<'_, unsafe extern "C" fn(PkStrView) -> PkDecision> =
                library
                    .get(b"pk_validate_bearer_header")
                    .map_err(|err| format!("missing symbol pk_validate_bearer_header: {err}"))?;

            let enforce_claims: Symbol<
                '_,
                unsafe extern "C" fn(PkClaimsCfg, PkTokenClaims) -> PkDecision,
            > = library
                .get(b"pk_enforce_claims")
                .map_err(|err| format!("missing symbol pk_enforce_claims: {err}"))?;

            let sql_restricted_policy_decision: Option<
                unsafe extern "C" fn(PkStrView, PkStrView) -> PkDecision,
            > = match library.get::<unsafe extern "C" fn(PkStrView, PkStrView) -> PkDecision>(
                b"pk_sql_restricted_policy_decision",
            ) {
                Ok(symbol) => Some(*symbol),
                Err(_) => None,
            };

            let gateway_decision: Symbol<
                '_,
                unsafe extern "C" fn(
                    PkStrView,
                    PkStrView,
                    PkStrList,
                    PkClaimsCfg,
                    PkTokenClaims,
                ) -> PkDecision,
            > = library
                .get(b"pk_gateway_decision")
                .map_err(|err| format!("missing symbol pk_gateway_decision: {err}"))?;

            let das_query_decision: Symbol<
                '_,
                unsafe extern "C" fn(PkAuthCtx, PkDasCfg, PkDasQuery, PkStrList) -> PkDecision,
            > = library
                .get(b"pk_das_query_decision")
                .map_err(|err| format!("missing symbol pk_das_query_decision: {err}"))?;

            let das_observability_decision: Symbol<
                '_,
                unsafe extern "C" fn(PkAuthCtx, PkDasCfg, PkStrView) -> PkDecision,
            > = library
                .get(b"pk_das_observability_decision")
                .map_err(|err| format!("missing symbol pk_das_observability_decision: {err}"))?;

            (
                *validate_bearer_header,
                *enforce_claims,
                sql_restricted_policy_decision,
                *gateway_decision,
                *das_query_decision,
                *das_observability_decision,
            )
        };

        Ok(Self {
            _library: library,
            validate_bearer_header,
            enforce_claims,
            sql_restricted_policy_decision,
            gateway_decision,
            das_query_decision,
            das_observability_decision,
        })
    }
}

static SPARK_KERNEL: OnceLock<Result<SparkKernel, String>> = OnceLock::new();

fn kernel() -> Result<&'static SparkKernel, String> {
    match SPARK_KERNEL.get_or_init(SparkKernel::load) {
        Ok(value) => Ok(value),
        Err(err) => Err(err.clone()),
    }
}

fn null_str_view() -> PkStrView {
    PkStrView {
        ptr: std::ptr::null(),
        len: 0,
    }
}

#[inline]
fn bool_to_flag(value: bool) -> u8 {
    if value {
        1
    } else {
        0
    }
}

#[derive(Debug)]
struct OwnedStrView {
    bytes: Vec<u8>,
}

impl OwnedStrView {
    fn new(value: &str) -> Self {
        Self {
            bytes: value.as_bytes().to_vec(),
        }
    }

    fn as_ffi(&self) -> PkStrView {
        PkStrView {
            ptr: self.bytes.as_ptr() as *const c_char,
            len: self.bytes.len(),
        }
    }
}

#[derive(Debug)]
struct OwnedOptStr {
    _storage: Option<OwnedStrView>,
    value: PkOptStr,
}

impl OwnedOptStr {
    fn from_option(value: Option<&str>) -> Self {
        let storage = value.map(OwnedStrView::new);
        let view = storage
            .as_ref()
            .map(OwnedStrView::as_ffi)
            .unwrap_or_else(null_str_view);
        Self {
            _storage: storage,
            value: PkOptStr {
                present: bool_to_flag(value.is_some()),
                value: view,
            },
        }
    }
}

#[derive(Debug)]
struct OwnedStrList {
    _storage: Vec<OwnedStrView>,
    views: Vec<PkStrView>,
}

impl OwnedStrList {
    fn from_iter<'a, I>(values: I) -> Self
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut storage = Vec::new();
        let mut views = Vec::new();

        for value in values {
            let owned = OwnedStrView::new(value);
            views.push(owned.as_ffi());
            storage.push(owned);
        }

        Self {
            _storage: storage,
            views,
        }
    }

    fn from_strings(values: &[String]) -> Self {
        Self::from_iter(values.iter().map(String::as_str))
    }

    fn as_ffi(&self) -> PkStrList {
        PkStrList {
            items: if self.views.is_empty() {
                std::ptr::null()
            } else {
                self.views.as_ptr()
            },
            len: self.views.len(),
        }
    }
}

fn normalized_claim_string(claims: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    claims
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn normalized_audiences(claims: &serde_json::Map<String, Value>) -> Vec<String> {
    match claims.get("aud") {
        Some(Value::String(value)) => value
            .split_whitespace()
            .filter(|segment| !segment.is_empty())
            .map(str::to_string)
            .collect(),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

struct OwnedClaimsCfg {
    expected_issuer: OwnedOptStr,
    expected_audience: OwnedOptStr,
    allowed_azp: OwnedStrList,
}

impl OwnedClaimsCfg {
    fn new(cfg: &ClaimsCfg) -> Self {
        Self {
            expected_issuer: OwnedOptStr::from_option(cfg.expected_issuer.as_deref()),
            expected_audience: OwnedOptStr::from_option(cfg.expected_audience.as_deref()),
            allowed_azp: OwnedStrList::from_strings(&cfg.allowed_azp),
        }
    }

    fn as_ffi(&self) -> PkClaimsCfg {
        PkClaimsCfg {
            expected_issuer: self.expected_issuer.value,
            expected_audience: self.expected_audience.value,
            allowed_azp: self.allowed_azp.as_ffi(),
        }
    }
}

struct OwnedTokenClaims {
    iss: OwnedOptStr,
    azp: OwnedOptStr,
    client_id: OwnedOptStr,
    aud_list: OwnedStrList,
}

impl OwnedTokenClaims {
    fn new(claims: &serde_json::Map<String, Value>) -> Self {
        let audiences = normalized_audiences(claims);
        Self {
            iss: OwnedOptStr::from_option(normalized_claim_string(claims, "iss").as_deref()),
            azp: OwnedOptStr::from_option(normalized_claim_string(claims, "azp").as_deref()),
            client_id: OwnedOptStr::from_option(
                normalized_claim_string(claims, "client_id").as_deref(),
            ),
            aud_list: OwnedStrList::from_iter(audiences.iter().map(String::as_str)),
        }
    }

    fn as_ffi(&self) -> PkTokenClaims {
        let aud_kind = if self.aud_list.views.is_empty() {
            PK_AUD_NONE
        } else {
            PK_AUD_LIST
        };

        PkTokenClaims {
            iss: self.iss.value,
            aud: PkAudClaim {
                kind: aud_kind,
                string: null_str_view(),
                list: self.aud_list.as_ffi(),
            },
            azp: self.azp.value,
            client_id: self.client_id.value,
        }
    }
}

fn claims_have_valid_types(claims: &serde_json::Map<String, Value>) -> bool {
    for key in ["iss", "azp", "client_id"] {
        if let Some(value) = claims.get(key) {
            if !value.is_string() {
                return false;
            }
        }
    }

    match claims.get("aud") {
        None => true,
        Some(Value::String(_)) => true,
        Some(Value::Array(values)) => values.iter().all(|value| value.is_string()),
        _ => false,
    }
}

struct OwnedAuthCtx {
    scopes: OwnedStrList,
    roles: OwnedStrList,
    azp: OwnedOptStr,
    cap_sql_key: OwnedOptStr,
    cap_params_hash: OwnedOptStr,
    is_system: bool,
    project_id: u64,
}

impl OwnedAuthCtx {
    fn new(input: &DasAuthInput) -> Self {
        Self {
            scopes: OwnedStrList::from_strings(&input.scopes),
            roles: OwnedStrList::from_strings(&input.roles),
            azp: OwnedOptStr::from_option(input.azp.as_deref()),
            cap_sql_key: OwnedOptStr::from_option(
                input.claims.get("sql_key").and_then(Value::as_str),
            ),
            cap_params_hash: OwnedOptStr::from_option(
                input.claims.get("params_hash").and_then(Value::as_str),
            ),
            is_system: input.is_system,
            project_id: input.project_id.max(0) as u64,
        }
    }

    fn as_ffi(&self) -> PkAuthCtx {
        PkAuthCtx {
            scopes: self.scopes.as_ffi(),
            roles: self.roles.as_ffi(),
            azp: self.azp.value,
            is_system: bool_to_flag(self.is_system),
            project_id: self.project_id,
            cap_sql_key: self.cap_sql_key.value,
            cap_params_hash: self.cap_params_hash.value,
        }
    }
}

struct OwnedDasCfg {
    system_allow_endpoints: OwnedStrList,
    system_allow_sql_keys: OwnedStrList,
    devtools_roles: OwnedStrList,
    write_implies_read: bool,
    delegation_mode: bool,
}

impl OwnedDasCfg {
    fn new(input: &DasCfgInput) -> Self {
        Self {
            system_allow_endpoints: OwnedStrList::from_strings(&input.system_allow_endpoints),
            system_allow_sql_keys: OwnedStrList::from_strings(&input.system_allow_sql_keys),
            devtools_roles: OwnedStrList::from_strings(&input.devtools_roles),
            write_implies_read: input.write_implies_read,
            delegation_mode: input.delegation_mode,
        }
    }

    fn as_ffi(&self) -> PkDasCfg {
        PkDasCfg {
            write_implies_read: bool_to_flag(self.write_implies_read),
            system_allow_endpoints: self.system_allow_endpoints.as_ffi(),
            system_allow_sql_keys: self.system_allow_sql_keys.as_ffi(),
            devtools_roles: self.devtools_roles.as_ffi(),
            delegation_mode: bool_to_flag(self.delegation_mode),
        }
    }
}

struct OwnedDasQuery {
    endpoint: OwnedStrView,
    sql_key: OwnedStrView,
    params_hash: OwnedStrView,
    access: PkAccess,
    risk: PkRisk,
    quorum: PkQuorum,
}

impl OwnedDasQuery {
    fn new(input: &DasQueryInput) -> Self {
        let access = match input.access {
            SqlAccess::Read => PK_ACCESS_READ,
            SqlAccess::Write => PK_ACCESS_WRITE,
        };
        let risk = match input.risk {
            SqlRisk::Low => PK_RISK_LOW,
            SqlRisk::High => PK_RISK_HIGH,
        };
        let quorum = match input.quorum_state {
            QuorumState::Ok => PK_QUORUM_OK,
            QuorumState::Missing => PK_QUORUM_MISSING,
            QuorumState::Stale => PK_QUORUM_STALE,
            QuorumState::Disabled => PK_QUORUM_DISABLED,
        };

        Self {
            endpoint: OwnedStrView::new(&input.endpoint),
            sql_key: OwnedStrView::new(&input.sql_key),
            params_hash: OwnedStrView::new(&input.params_hash),
            access,
            risk,
            quorum,
        }
    }

    fn as_ffi(&self) -> PkDasQuery {
        PkDasQuery {
            endpoint: self.endpoint.as_ffi(),
            sql_key: self.sql_key.as_ffi(),
            params_hash: self.params_hash.as_ffi(),
            access: self.access,
            risk: self.risk,
            quorum: self.quorum,
        }
    }
}

fn decision_code_from_ffi(code: PkDecisionCode) -> Result<Option<DecisionCode>, String> {
    match code {
        PK_DECISION_NONE => Ok(None),
        PK_DECISION_MISSING_TOKEN => Ok(Some(DecisionCode::MissingToken)),
        PK_DECISION_MISSING_SCOPES => Ok(Some(DecisionCode::MissingScopes)),
        PK_DECISION_MISSING_ROLES => Ok(Some(DecisionCode::MissingRoles)),
        PK_DECISION_ISSUER_MISMATCH => Ok(Some(DecisionCode::IssuerMismatch)),
        PK_DECISION_AUDIENCE_MISMATCH => Ok(Some(DecisionCode::AudienceMismatch)),
        PK_DECISION_AZP_NOT_ALLOWED => Ok(Some(DecisionCode::AzpNotAllowed)),
        PK_DECISION_INVALID_PATH => Ok(Some(DecisionCode::InvalidPath)),
        PK_DECISION_MISSING_REALM => Ok(Some(DecisionCode::MissingRealm)),
        PK_DECISION_SYSTEM_TOKEN_FORBIDDEN => Ok(Some(DecisionCode::SystemTokenForbidden)),
        PK_DECISION_ALLOWLIST_DENIED => Ok(Some(DecisionCode::AllowlistDenied)),
        PK_DECISION_CAPABILITY_MISSING => Ok(Some(DecisionCode::CapabilityMissing)),
        PK_DECISION_CAPABILITY_MISMATCH => Ok(Some(DecisionCode::CapabilityMismatch)),
        PK_DECISION_QUORUM_MISSING => Ok(Some(DecisionCode::QuorumMissing)),
        PK_DECISION_QUORUM_STALE => Ok(Some(DecisionCode::QuorumStale)),
        PK_DECISION_EMPTY_SQL => Ok(Some(DecisionCode::EmptySql)),
        PK_DECISION_UNTERMINATED_TOKEN => Ok(Some(DecisionCode::UnterminatedToken)),
        PK_DECISION_MULTIPLE_STATEMENTS => Ok(Some(DecisionCode::MultipleStatements)),
        PK_DECISION_NOT_READ_ONLY_PREFIX => Ok(Some(DecisionCode::NotReadOnlyPrefix)),
        PK_DECISION_FORBIDDEN_KEYWORD => Ok(Some(DecisionCode::ForbiddenKeyword)),
        PK_DECISION_FORBIDDEN_FUNCTION => Ok(Some(DecisionCode::ForbiddenFunction)),
        PK_DECISION_EXPLAIN_NOT_READ_ONLY => Ok(Some(DecisionCode::ExplainNotReadOnly)),
        PK_DECISION_CLASSIFIER_UNAVAILABLE => Ok(Some(DecisionCode::ClassifierUnavailable)),
        PK_DECISION_SPARK_RUNTIME_UNAVAILABLE => Ok(Some(DecisionCode::SparkRuntimeUnavailable)),
        PK_DECISION_INVALID_INPUT => Ok(Some(DecisionCode::InvalidInput)),
        _ => Err(format!("unknown decision code from SPARK runtime: {code}")),
    }
}

fn decode_decision(value: PkDecision) -> Result<Decision, String> {
    let allow = match value.allow {
        0 => false,
        1 => true,
        raw => return Err(format!("invalid allow flag from SPARK runtime: {raw}")),
    };

    let mapped = decision_code_from_ffi(value.code)?;
    if allow {
        if mapped.is_some() {
            return Err(format!(
                "invalid allow decision code from SPARK runtime: {}",
                value.code
            ));
        }

        return Ok(Decision::allow());
    }

    let code = mapped.ok_or_else(|| {
        format!(
            "invalid deny decision code from SPARK runtime: {}",
            value.code
        )
    })?;
    Ok(Decision::deny(code, None))
}

fn with_canonical_bearer_reason(decision: Decision) -> Decision {
    if !decision.allow
        && decision.reason.is_none()
        && decision.code.as_deref() == Some(DecisionCode::MissingToken.as_str())
    {
        return Decision {
            reason: Some("invalid_bearer".to_string()),
            ..decision
        };
    }
    decision
}

fn with_canonical_sql_reason(decision: Decision) -> Decision {
    if decision.allow || decision.reason.is_some() {
        return decision;
    }
    if decision.code.as_deref() == Some(DecisionCode::InvalidInput.as_str()) {
        return Decision {
            reason: Some("boundary_limits".to_string()),
            ..decision
        };
    }
    Decision {
        reason: Some(SQL_POLICY_REASON.to_string()),
        ..decision
    }
}

pub fn validate_bearer_header(raw: &str) -> Result<Decision, String> {
    let kernel = kernel()?;

    let raw_bearer = OwnedStrView::new(raw);
    let raw = unsafe { (kernel.validate_bearer_header)(raw_bearer.as_ffi()) };
    decode_decision(raw).map(with_canonical_bearer_reason)
}

pub fn enforce_claims(
    cfg: &ClaimsCfg,
    claims: &serde_json::Map<String, Value>,
) -> Result<Decision, String> {
    let kernel = kernel()?;

    if !claims_have_valid_types(claims) {
        return Ok(Decision::deny(
            DecisionCode::InvalidInput,
            Some(MALFORMED_CLAIMS_REASON),
        ));
    }

    let cfg = OwnedClaimsCfg::new(cfg);
    let claims = OwnedTokenClaims::new(claims);
    let raw = unsafe { (kernel.enforce_claims)(cfg.as_ffi(), claims.as_ffi()) };
    decode_decision(raw)
}

pub fn sql_restricted_policy_decision(
    input: &SqlRestrictedPolicyInput,
) -> Result<Decision, String> {
    let kernel = kernel()?;
    let Some(sql_fn) = kernel.sql_restricted_policy_decision else {
        return Err("missing symbol pk_sql_restricted_policy_decision".to_string());
    };

    let policy_contract_version = OwnedStrView::new(&input.policy_contract_version);
    let sql = OwnedStrView::new(&input.sql);
    let raw = unsafe { sql_fn(policy_contract_version.as_ffi(), sql.as_ffi()) };
    decode_decision(raw).map(with_canonical_sql_reason)
}

pub fn gateway_decision(input: &GatewayDecisionInput) -> Result<Decision, String> {
    let kernel = kernel()?;

    if !claims_have_valid_types(&input.claims) {
        return Ok(Decision::deny(
            DecisionCode::InvalidInput,
            Some(MALFORMED_CLAIMS_REASON),
        ));
    }

    let method = OwnedStrView::new(&input.method);
    let path = OwnedStrView::new(&input.path);
    let token_scopes = OwnedStrList::from_strings(&input.token_scopes);
    let cfg = OwnedClaimsCfg::new(&input.cfg);
    let claims = OwnedTokenClaims::new(&input.claims);

    let raw = unsafe {
        (kernel.gateway_decision)(
            method.as_ffi(),
            path.as_ffi(),
            token_scopes.as_ffi(),
            cfg.as_ffi(),
            claims.as_ffi(),
        )
    };
    decode_decision(raw)
}

pub fn das_query_decision(input: &DasDecisionInput) -> Result<Decision, String> {
    let kernel = kernel()?;

    let auth = OwnedAuthCtx::new(&input.auth);
    let cfg = OwnedDasCfg::new(&input.cfg);
    let query = OwnedDasQuery::new(&input.query);
    let allowlist = OwnedStrList::from_strings(&input.allowlist);

    let raw = unsafe {
        (kernel.das_query_decision)(
            auth.as_ffi(),
            cfg.as_ffi(),
            query.as_ffi(),
            allowlist.as_ffi(),
        )
    };
    decode_decision(raw)
}

pub fn das_observability_decision(input: &DasObservabilityInput) -> Result<Decision, String> {
    let kernel = kernel()?;

    let auth = OwnedAuthCtx::new(&input.auth);
    let cfg = OwnedDasCfg::new(&input.cfg);
    let endpoint = OwnedStrView::new(&input.endpoint);

    let raw = unsafe {
        (kernel.das_observability_decision)(auth.as_ffi(), cfg.as_ffi(), endpoint.as_ffi())
    };
    decode_decision(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{
        PK_DECISION_ALLOWLIST_DENIED, PK_DECISION_AUDIENCE_MISMATCH, PK_DECISION_AZP_NOT_ALLOWED,
        PK_DECISION_CAPABILITY_MISMATCH, PK_DECISION_CAPABILITY_MISSING,
        PK_DECISION_CLASSIFIER_UNAVAILABLE, PK_DECISION_EMPTY_SQL,
        PK_DECISION_EXPLAIN_NOT_READ_ONLY, PK_DECISION_FORBIDDEN_FUNCTION,
        PK_DECISION_FORBIDDEN_KEYWORD, PK_DECISION_INVALID_INPUT, PK_DECISION_INVALID_PATH,
        PK_DECISION_ISSUER_MISMATCH, PK_DECISION_MISSING_REALM, PK_DECISION_MISSING_ROLES,
        PK_DECISION_MISSING_SCOPES, PK_DECISION_MISSING_TOKEN, PK_DECISION_MULTIPLE_STATEMENTS,
        PK_DECISION_NONE, PK_DECISION_NOT_READ_ONLY_PREFIX, PK_DECISION_QUORUM_MISSING,
        PK_DECISION_QUORUM_STALE, PK_DECISION_SPARK_RUNTIME_UNAVAILABLE,
        PK_DECISION_SYSTEM_TOKEN_FORBIDDEN, PK_DECISION_UNTERMINATED_TOKEN,
    };
    use serde_json::json;

    #[test]
    fn decode_decision_allows_only_none_code_for_allow() {
        let value = PkDecision {
            allow: 1,
            code: PK_DECISION_MISSING_SCOPES,
        };
        let err = decode_decision(value).expect_err("allow=true with deny code must fail");
        assert!(err.contains("invalid allow decision code"));
    }

    #[test]
    fn decode_decision_rejects_none_code_for_deny() {
        let value = PkDecision {
            allow: 0,
            code: PK_DECISION_NONE,
        };
        let err = decode_decision(value).expect_err("deny with NONE code must fail");
        assert!(err.contains("invalid deny decision code"));
    }

    #[test]
    fn decode_decision_rejects_invalid_allow_flag() {
        let value = PkDecision {
            allow: 2,
            code: PK_DECISION_NONE,
        };
        let err = decode_decision(value).expect_err("invalid allow flag must fail");
        assert!(err.contains("invalid allow flag"));
    }

    #[test]
    fn decode_decision_rejects_unknown_foreign_code() {
        let value = PkDecision { allow: 0, code: 99 };
        let err = decode_decision(value).expect_err("unknown code must fail");
        assert!(err.contains("unknown decision code"));
    }

    #[test]
    fn decode_decision_accepts_known_deny_code() {
        let value = PkDecision {
            allow: 0,
            code: PK_DECISION_QUORUM_STALE,
        };
        let decision = decode_decision(value).expect("known deny code should decode");
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("QUORUM_STALE"));
    }

    #[test]
    fn decode_decision_accepts_allow_none() {
        let value = PkDecision {
            allow: 1,
            code: PK_DECISION_NONE,
        };
        let decision = decode_decision(value).expect("allow with NONE code should decode");
        assert!(decision.allow);
        assert!(decision.code.is_none());
        assert!(decision.reason.is_none());
    }

    #[test]
    fn decode_decision_denies_without_reason() {
        let value = PkDecision {
            allow: 0,
            code: PK_DECISION_INVALID_INPUT,
        };
        let decision = decode_decision(value).expect("deny should decode");
        assert!(!decision.allow);
        assert_eq!(decision.reason, None);
    }

    #[test]
    fn canonical_bearer_reason_is_restored_for_missing_token() {
        let decision =
            with_canonical_bearer_reason(Decision::deny(DecisionCode::MissingToken, None));
        assert_eq!(decision.reason.as_deref(), Some("invalid_bearer"));
    }

    #[test]
    fn canonical_sql_reason_is_restored_for_denies() {
        let decision =
            with_canonical_sql_reason(Decision::deny(DecisionCode::ForbiddenKeyword, None));
        assert_eq!(decision.reason.as_deref(), Some(SQL_POLICY_REASON));
    }

    #[test]
    fn canonical_sql_reason_preserves_boundary_limits_for_invalid_input() {
        let decision = with_canonical_sql_reason(Decision::deny(DecisionCode::InvalidInput, None));
        assert_eq!(decision.reason.as_deref(), Some("boundary_limits"));
    }

    #[test]
    fn decision_code_mapping_covers_known_constants() {
        let known = [
            PK_DECISION_MISSING_TOKEN,
            PK_DECISION_MISSING_SCOPES,
            PK_DECISION_MISSING_ROLES,
            PK_DECISION_ISSUER_MISMATCH,
            PK_DECISION_AUDIENCE_MISMATCH,
            PK_DECISION_AZP_NOT_ALLOWED,
            PK_DECISION_INVALID_PATH,
            PK_DECISION_MISSING_REALM,
            PK_DECISION_SYSTEM_TOKEN_FORBIDDEN,
            PK_DECISION_ALLOWLIST_DENIED,
            PK_DECISION_CAPABILITY_MISSING,
            PK_DECISION_CAPABILITY_MISMATCH,
            PK_DECISION_QUORUM_MISSING,
            PK_DECISION_QUORUM_STALE,
            PK_DECISION_EMPTY_SQL,
            PK_DECISION_UNTERMINATED_TOKEN,
            PK_DECISION_MULTIPLE_STATEMENTS,
            PK_DECISION_NOT_READ_ONLY_PREFIX,
            PK_DECISION_FORBIDDEN_KEYWORD,
            PK_DECISION_FORBIDDEN_FUNCTION,
            PK_DECISION_EXPLAIN_NOT_READ_ONLY,
            PK_DECISION_CLASSIFIER_UNAVAILABLE,
            PK_DECISION_SPARK_RUNTIME_UNAVAILABLE,
            PK_DECISION_INVALID_INPUT,
        ];

        for raw in known {
            assert!(decision_code_from_ffi(raw).unwrap().is_some());
        }
        assert!(decision_code_from_ffi(PK_DECISION_NONE).unwrap().is_none());
    }

    #[test]
    fn normalized_claim_string_treats_non_string_input_as_absent() {
        let claims = json!({ "iss": 123 })
            .as_object()
            .expect("claims object")
            .clone();
        assert_eq!(normalized_claim_string(&claims, "iss"), None);
    }

    #[test]
    fn normalized_audiences_drops_non_string_array_entries() {
        let claims = json!({ "aud": ["mcp", 3] })
            .as_object()
            .expect("claims object")
            .clone();
        let audiences = normalized_audiences(&claims);
        assert_eq!(audiences, vec!["mcp".to_string()]);
    }

    #[test]
    fn owned_token_claims_treats_non_string_claim_shapes_as_absent() {
        let claims = json!({ "azp": false })
            .as_object()
            .expect("claims object")
            .clone();
        let claims = OwnedTokenClaims::new(&claims);
        let ffi = claims.as_ffi();
        assert_eq!(ffi.azp.present, 0);
    }

    #[test]
    fn claims_have_valid_types_rejects_non_string_iss() {
        let claims = json!({ "iss": 123 })
            .as_object()
            .expect("claims object")
            .clone();
        assert!(!claims_have_valid_types(&claims));
    }

    #[test]
    fn claims_have_valid_types_rejects_mixed_aud_array() {
        let claims = json!({ "aud": ["mcp", 5] })
            .as_object()
            .expect("claims object")
            .clone();
        assert!(!claims_have_valid_types(&claims));
    }

    #[test]
    fn claims_have_valid_types_accepts_string_aud() {
        let claims = json!({ "aud": "mcp" })
            .as_object()
            .expect("claims object")
            .clone();
        assert!(claims_have_valid_types(&claims));
    }
}
