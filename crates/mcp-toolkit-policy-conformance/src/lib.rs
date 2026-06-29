//! # MCP Toolkit Policy Conformance
//!
//! Vector/schema validation and conformance execution helpers for toolkit policy
//! surfaces.
//!
//! ## Rationale
//! Keep `mcp-policy-kernel` as the canonical source of policy contracts while
//! providing reusable conformance primitives to toolkit and service crates.
//!
//! ## Security Boundaries
//! * This crate performs pure in-memory validation and decision matching.
//! * SQL conformance evaluation uses `mcp-toolkit-policy-core` and remains
//!   fail-closed for malformed or unsupported input.
//! * Gateway and DAS execution is adapter-driven to keep domain logic outside
//!   generic toolkit crates.

use std::path::Path;

use mcp_toolkit_policy_core::{
    sql_restricted_policy_decision, Decision,
    SqlRestrictedPolicyInput as CoreSqlRestrictedPolicyInput,
    SQL_POLICY_CONTRACT_VERSION as CORE_SQL_POLICY_CONTRACT_VERSION,
    SQL_POLICY_REASON as CORE_SQL_POLICY_REASON,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const OP_VALIDATE_BEARER_HEADER: &str = "validate_bearer_header";
pub const OP_ENFORCE_CLAIMS: &str = "enforce_claims";
pub const OP_REQUIRED_SCOPES: &str = "required_scopes";
pub const OP_GATEWAY_DECISION: &str = "gateway_decision";
pub const OP_DAS_QUERY_DECISION: &str = "das_query_decision";
pub const OP_DAS_OBSERVABILITY_DECISION: &str = "das_observability_decision";
pub const OP_SQL_RESTRICTED_POLICY_DECISION: &str = "sql_restricted_policy_decision";

pub const SQL_POLICY_CONTRACT_VERSION: &str = CORE_SQL_POLICY_CONTRACT_VERSION;
pub const SQL_POLICY_DENY_REASON: &str = CORE_SQL_POLICY_REASON;

/// Stable decision shape used by conformance matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceDecision {
    pub allow: bool,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub required_scopes: Option<Vec<String>>,
}

impl ConformanceDecision {
    pub fn allow() -> Self {
        Self {
            allow: true,
            code: None,
            reason: None,
            required_scopes: None,
        }
    }

    pub fn deny(code: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            code: Some(code.into()),
            reason: Some(reason.into()),
            required_scopes: None,
        }
    }

    pub fn with_required_scopes(mut self, required_scopes: Vec<String>) -> Self {
        self.required_scopes = Some(required_scopes);
        self
    }
}

/// Expected outcome for a vector case.
#[derive(Debug, Clone, Deserialize)]
pub struct DecisionExpect {
    pub allow: bool,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub required_scopes: Option<Vec<String>>,
}

/// A single policy conformance vector case.
#[derive(Debug, Clone, Deserialize)]
pub struct VectorCase {
    pub op: String,
    pub case: String,
    pub input: Value,
    pub expect: DecisionExpect,
}

/// Input contract for `validate_bearer_header` vectors.
#[derive(Debug, Clone, Deserialize)]
pub struct BearerInput {
    pub raw_bearer: String,
}

/// OIDC claims policy configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ClaimsCfg {
    #[serde(default)]
    pub expected_issuer: Option<String>,
    #[serde(default)]
    pub expected_audience: Option<String>,
    #[serde(default)]
    pub allowed_azp: Vec<String>,
}

/// Input contract for `enforce_claims` vectors.
#[derive(Debug, Clone, Deserialize)]
pub struct ClaimsInput {
    pub cfg: ClaimsCfg,
    pub claims: serde_json::Map<String, Value>,
}

/// Input contract for `required_scopes` vectors.
#[derive(Debug, Clone, Deserialize)]
pub struct RequiredScopesInput {
    pub method: String,
    pub path: String,
}

/// Input contract for `gateway_decision` vectors.
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayDecisionInput {
    pub method: String,
    pub path: String,
    pub token_scopes: Vec<String>,
    pub claims: serde_json::Map<String, Value>,
    pub cfg: ClaimsCfg,
}

/// Auth context payload used by DAS vectors.
#[derive(Debug, Clone, Deserialize)]
pub struct DasAuthInput {
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub azp: Option<String>,
    pub is_system: bool,
    pub claims: serde_json::Map<String, Value>,
    pub project_id: i64,
}

/// DAS policy config payload.
#[derive(Debug, Clone, Deserialize)]
pub struct DasCfgInput {
    pub write_implies_read: bool,
    pub system_allow_endpoints: Vec<String>,
    pub system_allow_sql_keys: Vec<String>,
    pub devtools_roles: Vec<String>,
    pub delegation_mode: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SqlAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SqlRisk {
    Low,
    High,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuorumState {
    Ok,
    Missing,
    Stale,
    Disabled,
}

/// DAS query metadata payload.
#[derive(Debug, Clone, Deserialize)]
pub struct DasQueryInput {
    pub endpoint: String,
    pub sql_key: String,
    pub params_hash: String,
    pub access: SqlAccess,
    pub risk: SqlRisk,
    pub quorum_state: QuorumState,
}

/// Input contract for `das_query_decision` vectors.
#[derive(Debug, Clone, Deserialize)]
pub struct DasDecisionInput {
    pub auth: DasAuthInput,
    pub cfg: DasCfgInput,
    pub query: DasQueryInput,
    pub allowlist: Vec<String>,
}

/// Input contract for `das_observability_decision` vectors.
#[derive(Debug, Clone, Deserialize)]
pub struct DasObservabilityInput {
    pub auth: DasAuthInput,
    pub cfg: DasCfgInput,
    pub endpoint: String,
}

/// Input contract for `sql_restricted_policy_decision` vectors.
#[derive(Debug, Clone, Deserialize)]
pub struct SqlRestrictedPolicyInput {
    pub policy_contract_version: String,
    pub sql: String,
}

/// Adapter surface for non-SQL conformance operations.
///
/// Domain-specific policy implementations can satisfy this trait while this
/// crate stays generic and contract-focused.
pub trait PolicyOperationAdapter {
    fn validate_bearer_header(&self, _input: &BearerInput) -> Result<ConformanceDecision, String> {
        Err("validate_bearer_header unsupported by adapter".to_string())
    }

    fn enforce_claims(&self, _input: &ClaimsInput) -> Result<ConformanceDecision, String> {
        Err("enforce_claims unsupported by adapter".to_string())
    }

    fn required_scopes(&self, _input: &RequiredScopesInput) -> Result<Vec<String>, String> {
        Err("required_scopes unsupported by adapter".to_string())
    }

    fn gateway_decision(
        &self,
        _input: &GatewayDecisionInput,
    ) -> Result<ConformanceDecision, String> {
        Err("gateway_decision unsupported by adapter".to_string())
    }

    fn das_query_decision(&self, _input: &DasDecisionInput) -> Result<ConformanceDecision, String> {
        Err("das_query_decision unsupported by adapter".to_string())
    }

    fn das_observability_decision(
        &self,
        _input: &DasObservabilityInput,
    ) -> Result<ConformanceDecision, String> {
        Err("das_observability_decision unsupported by adapter".to_string())
    }
}

/// Load vector cases from raw JSON text.
pub fn parse_vectors(raw_json: &str) -> Result<Vec<VectorCase>, String> {
    serde_json::from_str(raw_json).map_err(|err| format!("vector parse failed: {err}"))
}

/// Load vector cases from a file path.
pub fn load_vectors(path: &Path) -> Result<(Vec<VectorCase>, String), String> {
    let raw = std::fs::read_to_string(path).map_err(|err| format!("vector read failed: {err}"))?;
    let cases = parse_vectors(&raw)?;
    Ok((cases, raw))
}

/// Parse SQL-policy input shape for one vector case.
pub fn parse_sql_policy_input(case: &VectorCase) -> Result<SqlRestrictedPolicyInput, String> {
    serde_json::from_value(case.input.clone())
        .map_err(|err| format!("{}: invalid input: {err}", case.case))
}

/// Validate vector shape against operation-level type contracts.
pub fn validate_vectors(cases: &[VectorCase]) -> Result<(), String> {
    for case in cases {
        match case.op.as_str() {
            OP_VALIDATE_BEARER_HEADER => {
                let _: BearerInput = serde_json::from_value(case.input.clone())
                    .map_err(|err| format!("{}: invalid input: {err}", case.case))?;
            }
            OP_ENFORCE_CLAIMS => {
                let _: ClaimsInput = serde_json::from_value(case.input.clone())
                    .map_err(|err| format!("{}: invalid input: {err}", case.case))?;
            }
            OP_REQUIRED_SCOPES => {
                let _: RequiredScopesInput = serde_json::from_value(case.input.clone())
                    .map_err(|err| format!("{}: invalid input: {err}", case.case))?;
                if case.expect.required_scopes.is_none() {
                    return Err(format!("{}: required_scopes expect missing", case.case));
                }
                if !case.expect.allow {
                    return Err(format!("{}: required_scopes must allow", case.case));
                }
            }
            OP_GATEWAY_DECISION => {
                let _: GatewayDecisionInput = serde_json::from_value(case.input.clone())
                    .map_err(|err| format!("{}: invalid input: {err}", case.case))?;
            }
            OP_DAS_QUERY_DECISION => {
                let _: DasDecisionInput = serde_json::from_value(case.input.clone())
                    .map_err(|err| format!("{}: invalid input: {err}", case.case))?;
            }
            OP_DAS_OBSERVABILITY_DECISION => {
                let _: DasObservabilityInput = serde_json::from_value(case.input.clone())
                    .map_err(|err| format!("{}: invalid input: {err}", case.case))?;
            }
            OP_SQL_RESTRICTED_POLICY_DECISION => {
                let _ = parse_sql_policy_input(case)?;
            }
            _ => return Err(format!("{}: unknown op {}", case.case, case.op)),
        }

        if case.expect.code.is_none() && !case.expect.allow {
            return Err(format!("{}: deny requires code", case.case));
        }

        if case.expect.required_scopes.is_some()
            && !matches!(case.op.as_str(), OP_REQUIRED_SCOPES | OP_GATEWAY_DECISION)
        {
            return Err(format!("{}: required_scopes not allowed for op", case.case));
        }
    }

    Ok(())
}

/// Validate vectors against schema and operation-level type contracts.
pub fn validate_vectors_with_schema(
    cases: &[VectorCase],
    raw_json: &str,
    schema_path: &Path,
) -> Result<(), String> {
    let schema_raw =
        std::fs::read_to_string(schema_path).map_err(|err| format!("schema read failed: {err}"))?;
    let schema_json: Value =
        serde_json::from_str(&schema_raw).map_err(|err| format!("schema parse failed: {err}"))?;
    let instance_json: Value =
        serde_json::from_str(raw_json).map_err(|err| format!("vector parse failed: {err}"))?;

    let compiled = jsonschema::JSONSchema::compile(&schema_json)
        .map_err(|err| format!("schema compile failed: {err}"))?;

    if let Err(errors) = compiled.validate(&instance_json) {
        let mut messages = Vec::new();
        for error in errors {
            messages.push(error.to_string());
        }
        return Err(format!("schema validation failed: {}", messages.join("; ")));
    }

    validate_vectors(cases)
}

fn evaluate_sql_case(case: &VectorCase) -> Result<ConformanceDecision, String> {
    let input = parse_sql_policy_input(case)?;
    let decision = sql_restricted_policy_decision(&CoreSqlRestrictedPolicyInput {
        policy_contract_version: input.policy_contract_version,
        sql: input.sql,
    });
    Ok(conformance_from_policy_decision(decision))
}

fn conformance_from_policy_decision(decision: Decision) -> ConformanceDecision {
    ConformanceDecision {
        allow: decision.allow,
        code: decision.code,
        reason: decision.reason,
        required_scopes: decision.required_scopes,
    }
}

fn evaluate_case(
    case: &VectorCase,
    adapter: Option<&dyn PolicyOperationAdapter>,
) -> Result<ConformanceDecision, String> {
    match case.op.as_str() {
        OP_VALIDATE_BEARER_HEADER => {
            let input: BearerInput = serde_json::from_value(case.input.clone())
                .map_err(|err| format!("{}: invalid input: {err}", case.case))?;
            adapter_for_op(adapter, OP_VALIDATE_BEARER_HEADER)?
                .validate_bearer_header(&input)
                .map_err(|err| format!("{}: {err}", case.case))
        }
        OP_ENFORCE_CLAIMS => {
            let input: ClaimsInput = serde_json::from_value(case.input.clone())
                .map_err(|err| format!("{}: invalid input: {err}", case.case))?;
            adapter_for_op(adapter, OP_ENFORCE_CLAIMS)?
                .enforce_claims(&input)
                .map_err(|err| format!("{}: {err}", case.case))
        }
        OP_REQUIRED_SCOPES => {
            let input: RequiredScopesInput = serde_json::from_value(case.input.clone())
                .map_err(|err| format!("{}: invalid input: {err}", case.case))?;
            let scopes = adapter_for_op(adapter, OP_REQUIRED_SCOPES)?
                .required_scopes(&input)
                .map_err(|err| format!("{}: {err}", case.case))?;
            Ok(ConformanceDecision::allow().with_required_scopes(scopes))
        }
        OP_GATEWAY_DECISION => {
            let input: GatewayDecisionInput = serde_json::from_value(case.input.clone())
                .map_err(|err| format!("{}: invalid input: {err}", case.case))?;
            adapter_for_op(adapter, OP_GATEWAY_DECISION)?
                .gateway_decision(&input)
                .map_err(|err| format!("{}: {err}", case.case))
        }
        OP_DAS_QUERY_DECISION => {
            let input: DasDecisionInput = serde_json::from_value(case.input.clone())
                .map_err(|err| format!("{}: invalid input: {err}", case.case))?;
            adapter_for_op(adapter, OP_DAS_QUERY_DECISION)?
                .das_query_decision(&input)
                .map_err(|err| format!("{}: {err}", case.case))
        }
        OP_DAS_OBSERVABILITY_DECISION => {
            let input: DasObservabilityInput = serde_json::from_value(case.input.clone())
                .map_err(|err| format!("{}: invalid input: {err}", case.case))?;
            adapter_for_op(adapter, OP_DAS_OBSERVABILITY_DECISION)?
                .das_observability_decision(&input)
                .map_err(|err| format!("{}: {err}", case.case))
        }
        OP_SQL_RESTRICTED_POLICY_DECISION => evaluate_sql_case(case),
        _ => Err(format!("{}: unknown op {}", case.case, case.op)),
    }
}

fn adapter_for_op<'a>(
    adapter: Option<&'a dyn PolicyOperationAdapter>,
    op: &str,
) -> Result<&'a dyn PolicyOperationAdapter, String> {
    match adapter {
        Some(adapter) => Ok(adapter),
        None => Err(format!("{}: no adapter supplied for non-SQL operation", op)),
    }
}

/// Execute vectors and enforce exact decision parity.
///
/// SQL decisions are evaluated with `mcp-toolkit-policy-core`.
/// Gateway and DAS operations require a caller-supplied adapter.
pub fn run_vectors(
    cases: &[VectorCase],
    adapter: Option<&dyn PolicyOperationAdapter>,
) -> Result<(), String> {
    for case in cases {
        let actual = evaluate_case(case, adapter)?;

        if actual.allow != case.expect.allow {
            return Err(format!("{}: allow mismatch", case.case));
        }
        if actual.code != case.expect.code {
            return Err(format!("{}: code mismatch", case.case));
        }
        if actual.reason != case.expect.reason {
            return Err(format!("{}: reason mismatch", case.case));
        }

        if let Some(expected_scopes) = case.expect.required_scopes.as_ref() {
            let actual_scopes = actual.required_scopes.as_ref().ok_or_else(|| {
                format!("{}: expected required_scopes but none returned", case.case)
            })?;
            if actual_scopes != expected_scopes {
                return Err(format!("{}: required_scopes mismatch", case.case));
            }
        } else if actual.required_scopes.is_some() {
            return Err(format!(
                "{}: unexpected required_scopes returned",
                case.case
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubAdapter;

    impl PolicyOperationAdapter for StubAdapter {
        fn validate_bearer_header(
            &self,
            _input: &BearerInput,
        ) -> Result<ConformanceDecision, String> {
            Ok(ConformanceDecision::deny("MISSING_TOKEN", "invalid_bearer"))
        }

        fn required_scopes(&self, input: &RequiredScopesInput) -> Result<Vec<String>, String> {
            if input.method == "GET" {
                Ok(vec!["scope:read".to_string()])
            } else {
                Ok(vec!["scope:write".to_string()])
            }
        }

        fn gateway_decision(
            &self,
            _input: &GatewayDecisionInput,
        ) -> Result<ConformanceDecision, String> {
            Ok(ConformanceDecision::allow().with_required_scopes(vec!["scope:read".to_string()]))
        }

        fn das_query_decision(
            &self,
            _input: &DasDecisionInput,
        ) -> Result<ConformanceDecision, String> {
            Ok(ConformanceDecision::deny(
                "ALLOWLIST_DENIED",
                "allowlist_denied",
            ))
        }

        fn das_observability_decision(
            &self,
            _input: &DasObservabilityInput,
        ) -> Result<ConformanceDecision, String> {
            Ok(ConformanceDecision::allow())
        }

        fn enforce_claims(&self, _input: &ClaimsInput) -> Result<ConformanceDecision, String> {
            Ok(ConformanceDecision::allow())
        }
    }

    fn sql_case(sql: &str, allow: bool, code: Option<&str>) -> VectorCase {
        VectorCase {
            op: OP_SQL_RESTRICTED_POLICY_DECISION.to_string(),
            case: "sql_case".to_string(),
            input: serde_json::json!({
                "policy_contract_version": SQL_POLICY_CONTRACT_VERSION,
                "sql": sql,
            }),
            expect: DecisionExpect {
                allow,
                code: code.map(ToOwned::to_owned),
                reason: if allow {
                    None
                } else {
                    Some(SQL_POLICY_DENY_REASON.to_string())
                },
                required_scopes: None,
            },
        }
    }

    #[test]
    fn validate_vectors_rejects_deny_without_code() {
        let cases = vec![VectorCase {
            op: OP_SQL_RESTRICTED_POLICY_DECISION.to_string(),
            case: "missing_code".to_string(),
            input: serde_json::json!({
                "policy_contract_version": SQL_POLICY_CONTRACT_VERSION,
                "sql": "INSERT INTO t VALUES (1)",
            }),
            expect: DecisionExpect {
                allow: false,
                code: None,
                reason: Some(SQL_POLICY_DENY_REASON.to_string()),
                required_scopes: None,
            },
        }];

        let err = validate_vectors(&cases).expect_err("deny without code should fail");
        assert!(err.contains("deny requires code"));
    }

    #[test]
    fn run_vectors_executes_sql_allow_and_deny() {
        let cases = vec![
            sql_case("SELECT 1", true, None),
            sql_case(
                "INSERT INTO t VALUES (1)",
                false,
                Some("NOT_READ_ONLY_PREFIX"),
            ),
        ];

        validate_vectors(&cases).expect("vector validation should pass");
        run_vectors(&cases, None).expect("sql-only vectors should run without adapter");
    }

    #[test]
    fn run_vectors_sql_contract_mismatch_maps_to_classifier_unavailable() {
        let cases = vec![VectorCase {
            op: OP_SQL_RESTRICTED_POLICY_DECISION.to_string(),
            case: "contract_mismatch".to_string(),
            input: serde_json::json!({
                "policy_contract_version": "sql-restricted/v999",
                "sql": "SELECT 1",
            }),
            expect: DecisionExpect {
                allow: false,
                code: Some("CLASSIFIER_UNAVAILABLE".to_string()),
                reason: Some(SQL_POLICY_DENY_REASON.to_string()),
                required_scopes: None,
            },
        }];

        validate_vectors(&cases).expect("vector validation should pass");
        run_vectors(&cases, None).expect("contract mismatch should map to deny decision");
    }

    #[test]
    fn run_vectors_sql_boundary_overflow_maps_to_invalid_input() {
        let oversized = "x".repeat(mcp_toolkit_policy_core::BOUNDARY_MAX_STRING_LENGTH + 1);
        let cases = vec![VectorCase {
            op: OP_SQL_RESTRICTED_POLICY_DECISION.to_string(),
            case: "boundary_overflow".to_string(),
            input: serde_json::json!({
                "policy_contract_version": oversized,
                "sql": "SELECT 1",
            }),
            expect: DecisionExpect {
                allow: false,
                code: Some("INVALID_INPUT".to_string()),
                reason: Some("boundary_limits".to_string()),
                required_scopes: None,
            },
        }];

        validate_vectors(&cases).expect("vector validation should pass");
        run_vectors(&cases, None).expect("boundary overflow should map to deny decision");
    }

    #[test]
    fn run_vectors_requires_adapter_for_gateway_ops() {
        let cases = vec![VectorCase {
            op: OP_GATEWAY_DECISION.to_string(),
            case: "gateway_requires_adapter".to_string(),
            input: serde_json::json!({
                "method": "GET",
                "path": "/admin/realms/demo/users",
                "token_scopes": ["scope:read"],
                "claims": {},
                "cfg": {"allowed_azp": []}
            }),
            expect: DecisionExpect {
                allow: true,
                code: None,
                reason: None,
                required_scopes: Some(vec!["scope:read".to_string()]),
            },
        }];

        validate_vectors(&cases).expect("vector validation should pass");
        let err = run_vectors(&cases, None).expect_err("gateway should require adapter");
        assert!(err.contains("no adapter supplied"));
    }

    #[test]
    fn run_vectors_with_adapter_supports_gateway_and_das() {
        let cases = vec![
            VectorCase {
                op: OP_REQUIRED_SCOPES.to_string(),
                case: "required_scopes".to_string(),
                input: serde_json::json!({
                    "method": "GET",
                    "path": "/x"
                }),
                expect: DecisionExpect {
                    allow: true,
                    code: None,
                    reason: None,
                    required_scopes: Some(vec!["scope:read".to_string()]),
                },
            },
            VectorCase {
                op: OP_DAS_QUERY_DECISION.to_string(),
                case: "das_query".to_string(),
                input: serde_json::json!({
                    "auth": {
                        "scopes": ["ops:read"],
                        "roles": [],
                        "azp": null,
                        "is_system": false,
                        "claims": {},
                        "project_id": 1
                    },
                    "cfg": {
                        "write_implies_read": true,
                        "system_allow_endpoints": [],
                        "system_allow_sql_keys": [],
                        "devtools_roles": [],
                        "delegation_mode": false
                    },
                    "query": {
                        "endpoint": "query",
                        "sql_key": "unknown",
                        "params_hash": "h",
                        "access": "read",
                        "risk": "low",
                        "quorum_state": "disabled"
                    },
                    "allowlist": ["known"]
                }),
                expect: DecisionExpect {
                    allow: false,
                    code: Some("ALLOWLIST_DENIED".to_string()),
                    reason: Some("allowlist_denied".to_string()),
                    required_scopes: None,
                },
            },
        ];

        validate_vectors(&cases).expect("vector validation should pass");
        run_vectors(&cases, Some(&StubAdapter)).expect("adapter-backed vectors should pass");
    }

    #[test]
    fn run_vectors_rejects_unexpected_required_scopes() {
        let cases = vec![VectorCase {
            op: OP_GATEWAY_DECISION.to_string(),
            case: "unexpected_required_scopes".to_string(),
            input: serde_json::json!({
                "method": "GET",
                "path": "/admin/realms/demo/users",
                "token_scopes": ["scope:read"],
                "claims": {},
                "cfg": {"allowed_azp": []}
            }),
            expect: DecisionExpect {
                allow: true,
                code: None,
                reason: None,
                required_scopes: None,
            },
        }];

        validate_vectors(&cases).expect("vector validation should pass");
        let err = run_vectors(&cases, Some(&StubAdapter))
            .expect_err("unexpected required_scopes should fail parity");
        assert!(err.contains("unexpected required_scopes"));
    }

    #[test]
    fn validate_vectors_with_schema_checks_raw_payload() {
        let schema_path = std::env::temp_dir().join(format!(
            "policy-conformance-schema-{}.json",
            std::process::id()
        ));
        std::fs::write(
            &schema_path,
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"array","items":{"type":"object","required":["op","case","input","expect"]}}"#,
        )
        .expect("schema write should succeed");

        let raw = r#"[{"op":"sql_restricted_policy_decision","case":"x","input":{"policy_contract_version":"sql-restricted/v1","sql":"SELECT 1"},"expect":{"allow":true}}]"#;
        let cases = parse_vectors(raw).expect("vector parse should succeed");
        validate_vectors_with_schema(&cases, raw, &schema_path)
            .expect("schema+type validation should pass");

        let _ = std::fs::remove_file(schema_path);
    }
}
