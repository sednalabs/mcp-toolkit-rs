//! # Policy Authority
//!
//! Interfaces for stateful evaluation of MCP authorization policies.
//!
//! ## Ownership
//! This module owns the `PolicyAuthority` trait and its default implementations,
//! providing a structured interface for runtime policy evaluation.
//!
//! ## Non-ownership
//! This module does not define the underlying policy logic; it provides the
//! infrastructure for evaluating request-specific policy decisions.
//!
//! ## Policy & Guarantees
//! * **Decision Provenance**: Attaches metadata (source, runtime mode) to policy
//!   decisions to improve auditability and debugging.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Implementing the `PolicyAuthority` trait for domain-specific policy models.
//! * Ensuring that authority implementations are thread-safe and deterministic.
//!
//! ## References
//! * [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization.md)

use std::sync::Arc;

use mcp_toolkit_policy_core::{
    Decision, DecisionCode, SqlRestrictedPolicyInput, SQL_POLICY_CONTRACT_VERSION,
};
use mcp_toolkit_policy_kernel_adapters::{
    DasDecisionInput, DasObservabilityInput, GatewayDecisionInput,
};
use serde::{Deserialize, Serialize};

const SQL_AUTHORITY_SOURCE: &str = "mcp_toolkit_policy_runtime.sql_restricted";
const GATEWAY_AUTHORITY_SOURCE: &str = "mcp_toolkit_policy_runtime.gateway";
const DAS_QUERY_AUTHORITY_SOURCE: &str = "mcp_toolkit_policy_runtime.das_query";
const DAS_OBSERVABILITY_AUTHORITY_SOURCE: &str = "mcp_toolkit_policy_runtime.das_observability";
const SPARK_RUNTIME_UNAVAILABLE_REASON: &str = "spark_runtime_unavailable";

/// Runtime mode provenance for policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuntimeMode {
    Rust,
    SparkPrefer,
    SparkRequired,
}

impl PolicyRuntimeMode {
    /// Reads the configured policy-kernel runtime mode from the environment.
    pub fn configured() -> Self {
        match mcp_toolkit_policy_ffi::runtime_mode() {
            mcp_toolkit_policy_ffi::SparkRuntimeMode::Rust => Self::Rust,
            mcp_toolkit_policy_ffi::SparkRuntimeMode::SparkPrefer => Self::SparkPrefer,
            mcp_toolkit_policy_ffi::SparkRuntimeMode::SparkRequired => Self::SparkRequired,
        }
    }
}

/// Decision envelope emitted by policy authorities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyAuthorityDecision {
    pub allow: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub decision_source: String,
    pub runtime_mode: PolicyRuntimeMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_contract_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_scopes: Option<Vec<String>>,
}

impl PolicyAuthorityDecision {
    /// Constructs a decision from core toolkit decision primitives.
    pub fn from_policy_decision(
        decision: Decision,
        decision_source: impl Into<String>,
        runtime_mode: PolicyRuntimeMode,
        policy_contract_version: Option<&str>,
    ) -> Self {
        Self {
            allow: decision.allow,
            code: decision.code.clone(),
            reason: decision.reason.clone(),
            decision_source: decision_source.into(),
            runtime_mode,
            policy_contract_version: policy_contract_version.map(ToOwned::to_owned),
            required_scopes: decision.required_scopes.clone(),
        }
    }
}

/// Interface for request-to-decision policy evaluation.
pub trait PolicyAuthority<Request>: Send + Sync {
    /// Evaluates a request policy.
    fn evaluate(&self, request: &Request) -> PolicyAuthorityDecision;
}

/// Shared authority object used for service integration.
pub type SharedPolicyAuthority<Request> = Arc<dyn PolicyAuthority<Request>>;

/// Closure-backed policy authority.
#[derive(Clone)]
pub struct ClosurePolicyAuthority<Request> {
    decision_source: String,
    runtime_mode: PolicyRuntimeMode,
    policy_contract_version: Option<String>,
    evaluator: Arc<dyn Fn(&Request) -> Decision + Send + Sync>,
}

impl<Request> ClosurePolicyAuthority<Request> {
    /// Constructs a closure-backed authority with explicit metadata.
    pub fn new(
        decision_source: impl Into<String>,
        runtime_mode: PolicyRuntimeMode,
        policy_contract_version: Option<&str>,
        evaluator: impl Fn(&Request) -> Decision + Send + Sync + 'static,
    ) -> Self {
        Self {
            decision_source: decision_source.into(),
            runtime_mode,
            policy_contract_version: policy_contract_version.map(ToOwned::to_owned),
            evaluator: Arc::new(evaluator),
        }
    }
}

impl<Request> PolicyAuthority<Request> for ClosurePolicyAuthority<Request> {
    fn evaluate(&self, request: &Request) -> PolicyAuthorityDecision {
        let decision = (self.evaluator)(request);
        PolicyAuthorityDecision::from_policy_decision(
            decision,
            self.decision_source.clone(),
            self.runtime_mode,
            self.policy_contract_version.as_deref(),
        )
    }
}

#[derive(Clone)]
struct KernelPolicyAuthority<Request> {
    decision_source: &'static str,
    runtime_mode: PolicyRuntimeMode,
    policy_contract_version: Option<&'static str>,
    rust_evaluator: fn(&Request) -> Decision,
    spark_evaluator: fn(&Request) -> Result<Decision, String>,
}

impl<Request> KernelPolicyAuthority<Request> {
    fn new(
        decision_source: &'static str,
        runtime_mode: PolicyRuntimeMode,
        policy_contract_version: Option<&'static str>,
        rust_evaluator: fn(&Request) -> Decision,
        spark_evaluator: fn(&Request) -> Result<Decision, String>,
    ) -> Self {
        Self {
            decision_source,
            runtime_mode,
            policy_contract_version,
            rust_evaluator,
            spark_evaluator,
        }
    }

    fn evaluate_rust(&self, request: &Request) -> PolicyAuthorityDecision {
        let decision = (self.rust_evaluator)(request);
        PolicyAuthorityDecision::from_policy_decision(
            decision,
            format!("{}.rust", self.decision_source),
            self.runtime_mode,
            self.policy_contract_version,
        )
    }

    fn evaluate_spark(&self, request: &Request) -> Result<PolicyAuthorityDecision, String> {
        let decision = (self.spark_evaluator)(request)?;
        Ok(PolicyAuthorityDecision::from_policy_decision(
            decision,
            format!("{}.spark", self.decision_source),
            self.runtime_mode,
            self.policy_contract_version,
        ))
    }

    fn evaluate_spark_required_failure(&self) -> PolicyAuthorityDecision {
        let decision = Decision::deny(
            DecisionCode::SparkRuntimeUnavailable,
            Some(SPARK_RUNTIME_UNAVAILABLE_REASON),
        );
        PolicyAuthorityDecision::from_policy_decision(
            decision,
            format!("{}.spark_unavailable", self.decision_source),
            self.runtime_mode,
            self.policy_contract_version,
        )
    }
}

impl<Request> PolicyAuthority<Request> for KernelPolicyAuthority<Request> {
    fn evaluate(&self, request: &Request) -> PolicyAuthorityDecision {
        match self.runtime_mode {
            PolicyRuntimeMode::Rust => self.evaluate_rust(request),
            PolicyRuntimeMode::SparkPrefer => self
                .evaluate_spark(request)
                .unwrap_or_else(|_| self.evaluate_rust(request)),
            PolicyRuntimeMode::SparkRequired => self
                .evaluate_spark(request)
                .unwrap_or_else(|_| self.evaluate_spark_required_failure()),
        }
    }
}

/// Constructs a SQL restricted policy authority.
///
/// # Security
///
/// `SparkRequired` fails closed when the configured SPARK runtime cannot be
/// loaded. `SparkPrefer` falls back to the Rust policy-kernel adapter and
/// records the configured runtime mode plus the decision source in the emitted
/// envelope.
pub fn sql_restricted_policy_authority(
    runtime_mode: PolicyRuntimeMode,
) -> SharedPolicyAuthority<SqlRestrictedPolicyInput> {
    Arc::new(KernelPolicyAuthority::new(
        SQL_AUTHORITY_SOURCE,
        runtime_mode,
        Some(SQL_POLICY_CONTRACT_VERSION),
        mcp_toolkit_policy_core::sql_restricted_policy_decision,
        mcp_toolkit_policy_ffi::sql_restricted_policy_decision,
    ))
}

/// Constructs a SQL restricted policy authority from process configuration.
///
/// # Security
///
/// The runtime mode is read from the process environment. Use this constructor
/// only after the surrounding server has established its trusted environment
/// and launch configuration.
pub fn configured_sql_restricted_policy_authority(
) -> SharedPolicyAuthority<SqlRestrictedPolicyInput> {
    sql_restricted_policy_authority(PolicyRuntimeMode::configured())
}

/// Constructs a gateway policy authority.
///
/// # Security
///
/// `SparkRequired` fails closed when the configured SPARK runtime cannot be
/// loaded. `SparkPrefer` falls back to the Rust policy-kernel adapter and
/// records the configured runtime mode plus the decision source in the emitted
/// envelope.
pub fn gateway_policy_authority(
    runtime_mode: PolicyRuntimeMode,
) -> SharedPolicyAuthority<GatewayDecisionInput> {
    Arc::new(KernelPolicyAuthority::new(
        GATEWAY_AUTHORITY_SOURCE,
        runtime_mode,
        None,
        mcp_toolkit_policy_kernel_adapters::gateway_decision,
        mcp_toolkit_policy_ffi::gateway_decision,
    ))
}

/// Constructs a gateway policy authority from process configuration.
///
/// # Security
///
/// The runtime mode is read from the process environment. Use this constructor
/// only after the surrounding server has established its trusted environment
/// and launch configuration.
pub fn configured_gateway_policy_authority() -> SharedPolicyAuthority<GatewayDecisionInput> {
    gateway_policy_authority(PolicyRuntimeMode::configured())
}

/// Constructs a DAS query policy authority.
///
/// # Security
///
/// `SparkRequired` fails closed when the configured SPARK runtime cannot be
/// loaded. `SparkPrefer` falls back to the Rust policy-kernel adapter and
/// records the configured runtime mode plus the decision source in the emitted
/// envelope.
pub fn das_query_policy_authority(
    runtime_mode: PolicyRuntimeMode,
) -> SharedPolicyAuthority<DasDecisionInput> {
    Arc::new(KernelPolicyAuthority::new(
        DAS_QUERY_AUTHORITY_SOURCE,
        runtime_mode,
        None,
        mcp_toolkit_policy_kernel_adapters::das_query_decision,
        mcp_toolkit_policy_ffi::das_query_decision,
    ))
}

/// Constructs a DAS query policy authority from process configuration.
///
/// # Security
///
/// The runtime mode is read from the process environment. Use this constructor
/// only after the surrounding server has established its trusted environment
/// and launch configuration.
pub fn configured_das_query_policy_authority() -> SharedPolicyAuthority<DasDecisionInput> {
    das_query_policy_authority(PolicyRuntimeMode::configured())
}

/// Constructs a DAS observability policy authority.
///
/// # Security
///
/// `SparkRequired` fails closed when the configured SPARK runtime cannot be
/// loaded. `SparkPrefer` falls back to the Rust policy-kernel adapter and
/// records the configured runtime mode plus the decision source in the emitted
/// envelope.
pub fn das_observability_policy_authority(
    runtime_mode: PolicyRuntimeMode,
) -> SharedPolicyAuthority<DasObservabilityInput> {
    Arc::new(KernelPolicyAuthority::new(
        DAS_OBSERVABILITY_AUTHORITY_SOURCE,
        runtime_mode,
        None,
        mcp_toolkit_policy_kernel_adapters::das_observability_decision,
        mcp_toolkit_policy_ffi::das_observability_decision,
    ))
}

/// Constructs a DAS observability policy authority from process configuration.
///
/// # Security
///
/// The runtime mode is read from the process environment. Use this constructor
/// only after the surrounding server has established its trusted environment
/// and launch configuration.
pub fn configured_das_observability_policy_authority(
) -> SharedPolicyAuthority<DasObservabilityInput> {
    das_observability_policy_authority(PolicyRuntimeMode::configured())
}

/// Security profile template for hello-server integrations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelloServerProfile {
    Minimal,
    Secure,
    Regulated,
}

/// Request model for hello-server policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HelloPolicyRequest {
    pub route: String,
    pub authenticated: bool,
    pub required_scope: Option<String>,
    pub granted_scopes: Vec<String>,
}

/// Constructs a profile-based authority for hello-server integrations.
pub fn hello_server_policy_authority(
    profile: HelloServerProfile,
) -> SharedPolicyAuthority<HelloPolicyRequest> {
    Arc::new(ClosurePolicyAuthority::new(
        "mcp_toolkit_policy_runtime.hello_server",
        PolicyRuntimeMode::Rust,
        None,
        move |request: &HelloPolicyRequest| evaluate_hello_request(profile, request),
    ))
}

fn evaluate_hello_request(profile: HelloServerProfile, request: &HelloPolicyRequest) -> Decision {
    match profile {
        HelloServerProfile::Minimal => Decision::allow(),
        HelloServerProfile::Secure => evaluate_secure_hello_request(request),
        HelloServerProfile::Regulated => evaluate_regulated_hello_request(request),
    }
}

fn evaluate_secure_hello_request(request: &HelloPolicyRequest) -> Decision {
    if !request.authenticated {
        return Decision::deny(DecisionCode::MissingToken, Some("missing_token"));
    }
    if let Some(required_scope) = request.required_scope.as_deref() {
        let has_scope = request
            .granted_scopes
            .iter()
            .any(|scope| scope == required_scope);
        if !has_scope {
            return Decision::deny(DecisionCode::MissingScopes, Some("required_scope_missing"));
        }
    }
    Decision::allow()
}

fn evaluate_regulated_hello_request(request: &HelloPolicyRequest) -> Decision {
    if request.route != "/mcp" && !request.route.starts_with("/mcp/") {
        return Decision::deny(DecisionCode::InvalidPath, Some("regulated_route_required"));
    }
    if request.required_scope.is_none() {
        return Decision::deny(DecisionCode::MissingScopes, Some("required_scope_unset"));
    }
    evaluate_secure_hello_request(request)
}

#[cfg(test)]
mod tests {
    use super::{
        das_observability_policy_authority, das_query_policy_authority, gateway_policy_authority,
        hello_server_policy_authority, sql_restricted_policy_authority, ClosurePolicyAuthority,
        HelloPolicyRequest, HelloServerProfile, KernelPolicyAuthority, PolicyAuthority,
        PolicyRuntimeMode,
    };
    use mcp_toolkit_policy_core::{
        Decision, DecisionCode, SqlRestrictedPolicyInput, SQL_POLICY_CONTRACT_VERSION,
    };
    use mcp_toolkit_policy_kernel_adapters::{
        DasAuthInput, DasCfgInput, DasDecisionInput, DasObservabilityInput, DasQueryInput,
        GatewayDecisionInput, QuorumState, SqlAccess, SqlRisk,
    };
    use serde_json::{json, Value};

    #[test]
    fn closure_authority_attaches_provenance() {
        let authority = ClosurePolicyAuthority::new(
            "unit.policy",
            PolicyRuntimeMode::SparkPrefer,
            Some("sql-restricted/v1"),
            |_request: &String| {
                Decision::deny(DecisionCode::ForbiddenKeyword, Some("forbidden_keyword"))
            },
        );
        let request = "select 1".to_string();
        let decision = authority.evaluate(&request);
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("FORBIDDEN_KEYWORD"));
        assert_eq!(decision.reason.as_deref(), Some("forbidden_keyword"));
        assert_eq!(decision.decision_source, "unit.policy");
        assert_eq!(decision.runtime_mode, PolicyRuntimeMode::SparkPrefer);
        assert_eq!(
            decision.policy_contract_version.as_deref(),
            Some("sql-restricted/v1")
        );
        assert!(decision.required_scopes.is_none());
    }

    #[test]
    fn minimal_profile_allows_without_checks() {
        let authority = hello_server_policy_authority(HelloServerProfile::Minimal);
        let request = HelloPolicyRequest {
            route: "/anything".to_string(),
            authenticated: false,
            required_scope: None,
            granted_scopes: Vec::new(),
        };
        let decision = authority.evaluate(&request);
        assert!(decision.allow);
        assert_eq!(decision.code, None);
    }

    #[test]
    fn secure_profile_requires_authentication() {
        let authority = hello_server_policy_authority(HelloServerProfile::Secure);
        let request = HelloPolicyRequest {
            route: "/mcp/health".to_string(),
            authenticated: false,
            required_scope: Some("tools:read".to_string()),
            granted_scopes: vec!["tools:read".to_string()],
        };
        let decision = authority.evaluate(&request);
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("MISSING_TOKEN"));
    }

    #[test]
    fn regulated_profile_requires_route_prefix_and_scope_binding() {
        let authority = hello_server_policy_authority(HelloServerProfile::Regulated);
        let request = HelloPolicyRequest {
            route: "/health".to_string(),
            authenticated: true,
            required_scope: Some("tools:read".to_string()),
            granted_scopes: vec!["tools:read".to_string()],
        };
        let decision = authority.evaluate(&request);
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("INVALID_PATH"));
    }

    #[test]
    fn closure_authority_preserves_required_scopes() {
        let authority = ClosurePolicyAuthority::new(
            "scope.authority",
            PolicyRuntimeMode::Rust,
            None,
            |_request: &String| {
                Decision::allow().with_required_scopes(vec!["tools:read".to_string()])
            },
        );
        let request = "any".to_string();
        let decision = authority.evaluate(&request);
        assert!(decision.allow);
        assert_eq!(
            decision.required_scopes,
            Some(vec!["tools:read".to_string()])
        );
    }

    #[test]
    fn regulated_profile_allows_exact_mcp_route() {
        let authority = hello_server_policy_authority(HelloServerProfile::Regulated);
        let request = HelloPolicyRequest {
            route: "/mcp".to_string(),
            authenticated: true,
            required_scope: Some("tools:read".to_string()),
            granted_scopes: vec!["tools:read".to_string()],
        };
        let decision = authority.evaluate(&request);
        assert!(decision.allow);
    }

    #[test]
    fn sql_authority_attaches_contract_and_rust_provenance() {
        let authority = sql_restricted_policy_authority(PolicyRuntimeMode::Rust);
        let decision = authority.evaluate(&SqlRestrictedPolicyInput {
            policy_contract_version: SQL_POLICY_CONTRACT_VERSION.to_string(),
            sql: "select 1".to_string(),
        });
        assert!(decision.allow);
        assert_eq!(decision.runtime_mode, PolicyRuntimeMode::Rust);
        assert_eq!(
            decision.policy_contract_version.as_deref(),
            Some(SQL_POLICY_CONTRACT_VERSION)
        );
        assert_eq!(
            decision.decision_source,
            "mcp_toolkit_policy_runtime.sql_restricted.rust"
        );
    }

    #[test]
    fn spark_prefer_falls_back_to_rust_when_runtime_is_unavailable() {
        let authority = KernelPolicyAuthority::new(
            "unit.kernel",
            PolicyRuntimeMode::SparkPrefer,
            Some("unit/v1"),
            rust_denies_for_test,
            spark_unavailable_for_test,
        );
        let decision = authority.evaluate(&"request".to_string());
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("FORBIDDEN_KEYWORD"));
        assert_eq!(decision.reason.as_deref(), Some("restricted_sql"));
        assert_eq!(decision.runtime_mode, PolicyRuntimeMode::SparkPrefer);
        assert_eq!(decision.policy_contract_version.as_deref(), Some("unit/v1"));
        assert_eq!(decision.decision_source, "unit.kernel.rust");
    }

    #[test]
    fn spark_required_fails_closed_when_runtime_is_unavailable() {
        let authority = KernelPolicyAuthority::new(
            "unit.kernel",
            PolicyRuntimeMode::SparkRequired,
            Some("unit/v1"),
            rust_denies_for_test,
            spark_unavailable_for_test,
        );
        let decision = authority.evaluate(&"request".to_string());
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("SPARK_RUNTIME_UNAVAILABLE"));
        assert_eq!(
            decision.reason.as_deref(),
            Some("spark_runtime_unavailable")
        );
        assert_eq!(decision.runtime_mode, PolicyRuntimeMode::SparkRequired);
        assert_eq!(decision.policy_contract_version.as_deref(), Some("unit/v1"));
        assert_eq!(decision.decision_source, "unit.kernel.spark_unavailable");
    }

    #[test]
    fn gateway_authority_preserves_required_scopes() {
        let authority = gateway_policy_authority(PolicyRuntimeMode::Rust);
        let decision = authority.evaluate(&gateway_input_for("/admin/realms/demo/users"));
        assert!(decision.allow);
        assert_eq!(
            decision.required_scopes,
            Some(vec!["keycloak-admin:users:read".to_string()])
        );
        assert_eq!(
            decision.decision_source,
            "mcp_toolkit_policy_runtime.gateway.rust"
        );
    }

    #[test]
    fn das_query_authority_enforces_quorum() {
        let authority = das_query_policy_authority(PolicyRuntimeMode::Rust);
        let decision = authority.evaluate(&das_query_input());
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("QUORUM_STALE"));
        assert_eq!(
            decision.decision_source,
            "mcp_toolkit_policy_runtime.das_query.rust"
        );
    }

    #[test]
    fn das_observability_authority_allows_devtools_role() {
        let authority = das_observability_policy_authority(PolicyRuntimeMode::Rust);
        let decision = authority.evaluate(&DasObservabilityInput {
            auth: das_auth_input(vec![], vec!["devtools".to_string()]),
            cfg: das_cfg_input(),
            endpoint: "metrics".to_string(),
        });
        assert!(decision.allow);
        assert_eq!(
            decision.decision_source,
            "mcp_toolkit_policy_runtime.das_observability.rust"
        );
    }

    fn gateway_input_for(path: &str) -> GatewayDecisionInput {
        GatewayDecisionInput {
            method: "GET".to_string(),
            path: path.to_string(),
            token_scopes: vec![
                "keycloak-admin:realm:read".to_string(),
                "keycloak-admin:users:read".to_string(),
            ],
            claims: sample_claims(),
            cfg: mcp_toolkit_policy_core::ClaimsCfg {
                expected_issuer: Some("https://issuer.example".to_string()),
                expected_audience: Some("mcp".to_string()),
                allowed_azp: vec!["client-a".to_string()],
            },
        }
    }

    fn sample_claims() -> serde_json::Map<String, Value> {
        json!({
            "iss": "https://issuer.example",
            "aud": ["mcp"],
            "azp": "client-a"
        })
        .as_object()
        .expect("claims object")
        .clone()
    }

    fn das_auth_input(scopes: Vec<String>, roles: Vec<String>) -> DasAuthInput {
        DasAuthInput {
            scopes,
            roles,
            azp: None,
            is_system: false,
            claims: json!({}).as_object().expect("claims object").clone(),
            project_id: 1,
        }
    }

    fn das_cfg_input() -> DasCfgInput {
        DasCfgInput {
            write_implies_read: true,
            system_allow_endpoints: Vec::new(),
            system_allow_sql_keys: Vec::new(),
            devtools_roles: vec!["devtools".to_string()],
            delegation_mode: false,
        }
    }

    fn das_query_input() -> DasDecisionInput {
        DasDecisionInput {
            auth: das_auth_input(vec!["ops:write".to_string()], Vec::new()),
            cfg: das_cfg_input(),
            query: DasQueryInput {
                endpoint: "query".to_string(),
                sql_key: "foo".to_string(),
                params_hash: "abc".to_string(),
                access: SqlAccess::Write,
                risk: SqlRisk::High,
                quorum_state: QuorumState::Stale,
            },
            allowlist: vec!["foo".to_string()],
        }
    }

    fn rust_denies_for_test(_: &String) -> Decision {
        Decision::deny(DecisionCode::ForbiddenKeyword, Some("restricted_sql"))
    }

    fn spark_unavailable_for_test(_: &String) -> Result<Decision, String> {
        Err("unavailable".to_string())
    }
}
