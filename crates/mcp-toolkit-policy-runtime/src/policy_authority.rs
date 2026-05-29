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

use mcp_toolkit_policy_core::{Decision, DecisionCode};
use serde::{Deserialize, Serialize};

/// Runtime mode provenance for policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuntimeMode {
    Rust,
    SparkPrefer,
    SparkRequired,
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
        hello_server_policy_authority, ClosurePolicyAuthority, HelloPolicyRequest,
        HelloServerProfile, PolicyAuthority, PolicyRuntimeMode,
    };
    use mcp_toolkit_policy_core::{Decision, DecisionCode};

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
}
