//! # Route and Scope Policy Authority
//!
//! Provider-neutral fail-closed authorization for HTTP boundaries that need a
//! fixed route set, method set, and OAuth scope set before a request reaches an
//! MCP service.
//!
//! This module intentionally carries no bearer-token parsing and no service
//! vocabulary. Authentication middleware supplies the normalized request facts;
//! the authority turns those facts into a provenance-bearing Toolkit policy
//! decision.

use std::collections::HashSet;
use std::sync::Arc;

use mcp_toolkit_policy_core::{Decision, DecisionCode};
use serde::{Deserialize, Serialize};

use crate::policy_authority::{ClosurePolicyAuthority, PolicyRuntimeMode, SharedPolicyAuthority};

/// Default decision-source namespace for generic route/scope policy.
pub const ROUTE_SCOPE_POLICY_DECISION_SOURCE: &str = "mcp_toolkit_policy_runtime.route_scope";

/// Contract version for the generic route/scope authority.
pub const ROUTE_SCOPE_POLICY_CONTRACT_VERSION: &str = "mcp-toolkit/route-scope/v1";

/// Immutable configuration for a route/scope policy boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteScopePolicyConfig {
    /// Allowed request paths. Empty means deny every path.
    pub allowed_paths: Vec<String>,
    /// Allowed HTTP methods as uppercase ASCII labels. Empty means deny every method.
    pub allowed_methods: Vec<String>,
    /// Scopes that must all be present on the authenticated principal.
    pub required_scopes: Vec<String>,
    /// Stable decision source emitted in policy provenance.
    pub decision_source: String,
    /// Stable policy contract version emitted in policy provenance.
    pub policy_contract_version: String,
}

impl RouteScopePolicyConfig {
    /// Creates a normalized fail-closed route/scope policy.
    pub fn new<P, M, S>(paths: P, methods: M, required_scopes: S) -> Self
    where
        P: IntoIterator,
        P::Item: AsRef<str>,
        M: IntoIterator,
        M::Item: AsRef<str>,
        S: IntoIterator,
        S::Item: AsRef<str>,
    {
        Self {
            allowed_paths: normalize_values(paths, false),
            allowed_methods: normalize_values(methods, true),
            required_scopes: normalize_values(required_scopes, false),
            decision_source: ROUTE_SCOPE_POLICY_DECISION_SOURCE.to_string(),
            policy_contract_version: ROUTE_SCOPE_POLICY_CONTRACT_VERSION.to_string(),
        }
    }

    /// Overrides the stable decision source.
    pub fn with_decision_source(mut self, source: impl Into<String>) -> Self {
        let source = source.into();
        let trimmed = source.trim();
        if !trimmed.is_empty() {
            self.decision_source = trimmed.to_string();
        }
        self
    }

    /// Overrides the policy contract version.
    pub fn with_contract_version(mut self, version: impl Into<String>) -> Self {
        let version = version.into();
        let trimmed = version.trim();
        if !trimmed.is_empty() {
            self.policy_contract_version = trimmed.to_string();
        }
        self
    }
}

/// Normalized request facts evaluated by [`route_scope_policy_authority`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteScopePolicyRequest {
    pub method: String,
    pub path: String,
    pub authenticated: bool,
    pub granted_scopes: Vec<String>,
}

impl RouteScopePolicyRequest {
    /// Builds request facts without carrying tokens or claims into policy state.
    pub fn new<S>(
        method: impl Into<String>,
        path: impl Into<String>,
        authenticated: bool,
        granted_scopes: S,
    ) -> Self
    where
        S: IntoIterator,
        S::Item: AsRef<str>,
    {
        Self {
            method: method.into().trim().to_ascii_uppercase(),
            path: normalize_path(&path.into()),
            authenticated,
            granted_scopes: normalize_values(granted_scopes, false),
        }
    }
}

/// Builds a provenance-bearing policy authority for one fixed HTTP boundary.
///
/// Evaluation is fail-closed in this order: authentication, path, method, then
/// required scopes. All required scopes must be present.
pub fn route_scope_policy_authority(
    config: RouteScopePolicyConfig,
) -> SharedPolicyAuthority<RouteScopePolicyRequest> {
    let source = config.decision_source.clone();
    let contract = config.policy_contract_version.clone();
    let config = Arc::new(config);
    Arc::new(ClosurePolicyAuthority::new(
        source,
        PolicyRuntimeMode::Rust,
        Some(contract.as_str()),
        move |request: &RouteScopePolicyRequest| evaluate_route_scope(&config, request),
    ))
}

/// Evaluates one request without constructing an authority object.
pub fn evaluate_route_scope(
    config: &RouteScopePolicyConfig,
    request: &RouteScopePolicyRequest,
) -> Decision {
    if !request.authenticated {
        return Decision::deny(DecisionCode::MissingToken, Some("missing_auth_context"));
    }

    if !config
        .allowed_paths
        .iter()
        .any(|path| path == &request.path)
    {
        return Decision::deny(DecisionCode::InvalidPath, Some("route_not_allowed"));
    }

    if !config
        .allowed_methods
        .iter()
        .any(|method| method == &request.method)
    {
        return Decision::deny(DecisionCode::InvalidInput, Some("method_not_allowed"));
    }

    let granted: HashSet<&str> = request.granted_scopes.iter().map(String::as_str).collect();
    let missing = config
        .required_scopes
        .iter()
        .filter(|scope| !granted.contains(scope.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Decision::deny(DecisionCode::MissingScopes, Some("required_scope_missing"))
            .with_required_scopes(config.required_scopes.clone());
    }

    Decision::allow().with_required_scopes(config.required_scopes.clone())
}

fn normalize_values<I>(values: I, uppercase: bool) -> Vec<String>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut out = Vec::new();
    for value in values {
        let value = value.as_ref().trim();
        if value.is_empty() {
            continue;
        }
        let value = if uppercase {
            value.to_ascii_uppercase()
        } else {
            value.to_string()
        };
        if !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

fn normalize_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() || path == "/" {
        "/".to_string()
    } else {
        format!("/{}", path.trim_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RouteScopePolicyConfig {
        RouteScopePolicyConfig::new(["/mcp"], ["POST"], ["example:run", "example:read"])
    }

    #[test]
    fn allows_authenticated_request_with_all_required_scopes() {
        let authority = route_scope_policy_authority(config());
        let request = RouteScopePolicyRequest::new(
            "post",
            "mcp/",
            true,
            ["example:read", "example:run", "other"],
        );
        let decision = authority.evaluate(&request);

        assert!(decision.allow);
        assert_eq!(decision.decision_source, ROUTE_SCOPE_POLICY_DECISION_SOURCE);
        assert_eq!(
            decision.policy_contract_version.as_deref(),
            Some(ROUTE_SCOPE_POLICY_CONTRACT_VERSION)
        );
        assert_eq!(
            decision.required_scopes,
            Some(vec!["example:run".to_string(), "example:read".to_string()])
        );
    }

    #[test]
    fn missing_auth_fails_before_route_or_scope_checks() {
        let decision = evaluate_route_scope(
            &config(),
            &RouteScopePolicyRequest::new("GET", "/wrong", false, Vec::<String>::new()),
        );
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("MISSING_TOKEN"));
        assert_eq!(decision.reason.as_deref(), Some("missing_auth_context"));
    }

    #[test]
    fn rejects_unexpected_route_and_method() {
        let route = evaluate_route_scope(
            &config(),
            &RouteScopePolicyRequest::new("POST", "/other", true, ["example:run", "example:read"]),
        );
        assert_eq!(route.code.as_deref(), Some("INVALID_PATH"));

        let method = evaluate_route_scope(
            &config(),
            &RouteScopePolicyRequest::new("DELETE", "/mcp", true, ["example:run", "example:read"]),
        );
        assert_eq!(method.code.as_deref(), Some("INVALID_INPUT"));
    }

    #[test]
    fn missing_any_required_scope_denies_with_complete_requirement() {
        let decision = evaluate_route_scope(
            &config(),
            &RouteScopePolicyRequest::new("POST", "/mcp", true, ["example:run"]),
        );
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("MISSING_SCOPES"));
        assert_eq!(
            decision.required_scopes,
            Some(vec!["example:run".to_string(), "example:read".to_string()])
        );
    }

    #[test]
    fn empty_allowed_sets_fail_closed() {
        let empty = RouteScopePolicyConfig::new(
            Vec::<String>::new(),
            Vec::<String>::new(),
            Vec::<String>::new(),
        );
        let decision = evaluate_route_scope(
            &empty,
            &RouteScopePolicyRequest::new("POST", "/mcp", true, Vec::<String>::new()),
        );
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("INVALID_PATH"));
    }
}
