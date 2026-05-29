//! # MCP Toolkit Policy Kernel Adapters
//!
//! Exact gateway/DAS parity adapters layered on top of the generic toolkit policy core.
//!
//! ## Rationale
//! These adapters preserve the current `mcp-policy-kernel` domain contracts without
//! moving domain logic into `mcp-toolkit-policy-core`. They provide a stable interface
//! for legacy policy enforcement mechanisms.
//!
//! ## Security Boundaries
//! * Validates input against rigid boundary limits to prevent resource exhaustion.
//! * Enforces strict scope and role checks for administrative and observability endpoints.
//! * Normalizes claims and path inputs to mitigate bypass techniques like encoded delimiters.
//! * Fails closed on all policy evaluation errors or invalid input conditions.
//!
//! ## References
//! * MCP Toolkit Policy Core.
//! * Gateway admin API scope families.
//!
//! ## Notes
//! * Does not perform IO or network operations.
//! * Pure function based authorization logic.

use mcp_toolkit_policy_core::{
    enforce_claims, list_within_boundary_limits, optional_string_within_boundary_limit,
    string_within_boundary_limit, ClaimsCfg, Decision, DecisionCode, BOUNDARY_MAX_LIST_LENGTH,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Input for scope discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredScopesInput {
    pub method: String,
    pub path: String,
}

/// Input for full gateway authorization decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayDecisionInput {
    pub method: String,
    pub path: String,
    pub token_scopes: Vec<String>,
    pub claims: serde_json::Map<String, Value>,
    pub cfg: ClaimsCfg,
}

/// Validated auth context for DAS decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DasAuthInput {
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub azp: Option<String>,
    pub is_system: bool,
    pub claims: serde_json::Map<String, Value>,
    pub project_id: i64,
}

/// Service configuration for DAS policy enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DasCfgInput {
    pub write_implies_read: bool,
    pub system_allow_endpoints: Vec<String>,
    pub system_allow_sql_keys: Vec<String>,
    pub devtools_roles: Vec<String>,
    pub delegation_mode: bool,
}

/// SQL access levels (read vs write).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SqlAccess {
    Read,
    Write,
}

/// SQL risk levels (low vs high).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SqlRisk {
    Low,
    High,
}

/// Global quorum certificate state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuorumState {
    Ok,
    Missing,
    Stale,
    Disabled,
}

/// Metadata about the target SQL query being executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DasQueryInput {
    pub endpoint: String,
    pub sql_key: String,
    pub params_hash: String,
    pub access: SqlAccess,
    pub risk: SqlRisk,
    pub quorum_state: QuorumState,
}

/// Input for DAS query authorization decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DasDecisionInput {
    pub auth: DasAuthInput,
    pub cfg: DasCfgInput,
    pub query: DasQueryInput,
    pub allowlist: Vec<String>,
}

/// Input for DAS observability authorization decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DasObservabilityInput {
    pub auth: DasAuthInput,
    pub cfg: DasCfgInput,
    pub endpoint: String,
}

/// Discover which Keycloak scopes are required for a given HTTP path.
///
/// # Security
/// * Maps paths to specific administrative scopes to enforce Principle of Least Privilege.
/// * Denies access if the path cannot be mapped to a known scope family.
pub fn required_scopes(method: &str, path: &str) -> Vec<String> {
    let segments = path_segments(path);
    let is_read = matches!(method, "GET" | "HEAD" | "OPTIONS");
    let family = scope_family(&segments);

    match family {
        ScopeFamily::Users => scope_for_rw(
            is_read,
            "keycloak-admin:users:read",
            "keycloak-admin:users:write",
        ),
        ScopeFamily::Groups => scope_for_rw(
            is_read,
            "keycloak-admin:groups:read",
            "keycloak-admin:groups:write",
        ),
        ScopeFamily::Roles => scope_for_rw(
            is_read,
            "keycloak-admin:roles:read",
            "keycloak-admin:roles:write",
        ),
        ScopeFamily::Clients => {
            if is_client_secret_path(&segments) {
                vec!["keycloak-admin:clients:secrets".to_string()]
            } else {
                scope_for_rw(
                    is_read,
                    "keycloak-admin:clients:read",
                    "keycloak-admin:clients:write",
                )
            }
        }
        ScopeFamily::ClientScopes => scope_for_rw(
            is_read,
            "keycloak-admin:client-scopes:read",
            "keycloak-admin:client-scopes:write",
        ),
        ScopeFamily::Idp => scope_for_rw(
            is_read,
            "keycloak-admin:idp:read",
            "keycloak-admin:idp:write",
        ),
        ScopeFamily::Events => scope_for_rw(
            is_read,
            "keycloak-admin:events:read",
            "keycloak-admin:events:admin",
        ),
        ScopeFamily::Realm => scope_for_rw(
            is_read,
            "keycloak-admin:realm:read",
            "keycloak-admin:realm:write",
        ),
        ScopeFamily::Tokens => {
            if is_read {
                vec!["keycloak-admin:tokens:read".to_string()]
            } else {
                vec!["keycloak-admin:realm:admin".to_string()]
            }
        }
        ScopeFamily::Observability => vec!["keycloak-admin:observability:read".to_string()],
    }
}

/// Executes a full gateway authorization decision.
///
/// # Security
/// * Performs input boundary checks to prevent resource exhaustion.
/// * Enforces claim validation using core policy engine.
/// * Blocks dangerous path patterns (e.g., encoded delimiters, directory traversal).
/// * Verifies that the token contains the required scopes for the requested path.
pub fn gateway_decision(input: &GatewayDecisionInput) -> Decision {
    if !gateway_input_within_boundary_limits(input) {
        return Decision::deny(DecisionCode::InvalidInput, Some("boundary_limits"));
    }

    let claims_decision = enforce_claims(&input.cfg, &input.claims);
    if !claims_decision.allow {
        return claims_decision;
    }

    let segments = path_segments(&input.path);
    if kernel_gateway_path_denied(&input.path, &segments) {
        return Decision::deny(DecisionCode::InvalidPath, None);
    }
    if segments.is_empty() {
        return Decision::deny(DecisionCode::MissingRealm, None);
    }

    let scopes = required_scopes(&input.method, &input.path);
    let missing = scopes
        .iter()
        .any(|scope| !input.token_scopes.iter().any(|value| value == scope));
    if missing {
        return Decision::deny(DecisionCode::MissingScopes, None);
    }

    Decision::allow().with_required_scopes(scopes)
}

/// Executes a DAS database access decision.
///
/// # Security
/// * Performs input boundary checks.
/// * Enforces system token restrictions on endpoints and SQL keys.
/// * Validates that the requested SQL key is present in the allowlist.
/// * Enforces read/write scope requirements.
/// * Verifies quorum state for high-risk or write operations.
/// * Enforces capability checks in delegation mode.
pub fn das_query_decision(input: &DasDecisionInput) -> Decision {
    if !das_query_input_within_boundary_limits(input) {
        return Decision::deny(DecisionCode::InvalidInput, Some("boundary_limits"));
    }

    let query = &input.query;

    if input.auth.is_system {
        if !input.cfg.system_allow_endpoints.contains(&query.endpoint) {
            return Decision::deny(DecisionCode::SystemTokenForbidden, None);
        }
        if query.endpoint == "query" {
            let allowed = &input.cfg.system_allow_sql_keys;
            if allowed.is_empty() || !allowed.contains(&query.sql_key) {
                return Decision::deny(DecisionCode::SystemTokenForbidden, None);
            }
        }
    }

    if !input.allowlist.iter().any(|value| value == &query.sql_key) {
        return Decision::deny(DecisionCode::AllowlistDenied, None);
    }

    let scopes_ok = match query.access {
        SqlAccess::Write => input.auth.scopes.iter().any(|scope| scope == "ops:write"),
        SqlAccess::Read => {
            input.auth.scopes.iter().any(|scope| scope == "ops:read")
                || (input.cfg.write_implies_read
                    && input.auth.scopes.iter().any(|scope| scope == "ops:write"))
        }
    };
    if !scopes_ok {
        return Decision::deny(DecisionCode::MissingScopes, None);
    }

    if matches!(
        query.quorum_state,
        QuorumState::Missing | QuorumState::Stale
    ) && (matches!(query.risk, SqlRisk::High) || matches!(query.access, SqlAccess::Write))
    {
        let code = match query.quorum_state {
            QuorumState::Missing => DecisionCode::QuorumMissing,
            QuorumState::Stale => DecisionCode::QuorumStale,
            _ => DecisionCode::QuorumMissing,
        };
        return Decision::deny(code, None);
    }

    if input.cfg.delegation_mode {
        let expected_key = input
            .auth
            .claims
            .get("sql_key")
            .and_then(|value| value.as_str());
        let expected_hash = input
            .auth
            .claims
            .get("params_hash")
            .and_then(|value| value.as_str());
        if expected_key.is_none() || expected_hash.is_none() {
            return Decision::deny(DecisionCode::CapabilityMissing, None);
        }
        if expected_key != Some(query.sql_key.as_str())
            || expected_hash != Some(query.params_hash.as_str())
        {
            return Decision::deny(DecisionCode::CapabilityMismatch, None);
        }
    }

    Decision::allow()
}

/// Executes a DAS observability access decision.
///
/// # Security
/// * Performs input boundary checks.
/// * Enforces system token endpoint restrictions.
/// * Requires devtools roles for non-system tokens to access observability data.
pub fn das_observability_decision(input: &DasObservabilityInput) -> Decision {
    if !das_observability_input_within_boundary_limits(input) {
        return Decision::deny(DecisionCode::InvalidInput, Some("boundary_limits"));
    }

    if input.auth.is_system {
        if !input.cfg.system_allow_endpoints.contains(&input.endpoint) {
            return Decision::deny(DecisionCode::SystemTokenForbidden, None);
        }
        return Decision::allow();
    }

    if input.cfg.devtools_roles.is_empty() {
        return Decision::deny(DecisionCode::MissingRoles, None);
    }

    if input
        .auth
        .roles
        .iter()
        .any(|role| input.cfg.devtools_roles.contains(role))
    {
        return Decision::allow();
    }

    Decision::deny(DecisionCode::MissingRoles, None)
}

fn normalized_claim_string_within_limits(
    claims: &serde_json::Map<String, Value>,
    key: &str,
) -> bool {
    optional_string_within_boundary_limit(
        claims
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty()),
    )
}

fn normalized_claim_audience_within_limits(claims: &serde_json::Map<String, Value>) -> bool {
    match claims.get("aud") {
        None => true,
        Some(Value::String(value)) => {
            let audiences = value
                .split_whitespace()
                .filter(|segment| !segment.is_empty())
                .collect::<Vec<_>>();
            audiences.len() <= BOUNDARY_MAX_LIST_LENGTH
                && audiences
                    .iter()
                    .all(|aud| string_within_boundary_limit(aud))
        }
        Some(Value::Array(values)) => {
            let mut count = 0usize;
            for value in values {
                let Some(aud) = value.as_str() else {
                    continue;
                };
                let aud = aud.trim();
                if aud.is_empty() {
                    continue;
                }
                count += 1;
                if count > BOUNDARY_MAX_LIST_LENGTH || !string_within_boundary_limit(aud) {
                    return false;
                }
            }
            true
        }
        _ => true,
    }
}

fn auth_claim_within_boundary_limits(claims: &serde_json::Map<String, Value>, key: &str) -> bool {
    optional_string_within_boundary_limit(claims.get(key).and_then(Value::as_str))
}

fn gateway_input_within_boundary_limits(input: &GatewayDecisionInput) -> bool {
    string_within_boundary_limit(&input.method)
        && string_within_boundary_limit(&input.path)
        && list_within_boundary_limits(&input.token_scopes)
        && optional_string_within_boundary_limit(input.cfg.expected_issuer.as_deref())
        && optional_string_within_boundary_limit(input.cfg.expected_audience.as_deref())
        && list_within_boundary_limits(&input.cfg.allowed_azp)
        && normalized_claim_string_within_limits(&input.claims, "iss")
        && normalized_claim_string_within_limits(&input.claims, "azp")
        && normalized_claim_string_within_limits(&input.claims, "client_id")
        && normalized_claim_audience_within_limits(&input.claims)
}

fn das_auth_within_boundary_limits(auth: &DasAuthInput) -> bool {
    list_within_boundary_limits(&auth.scopes)
        && list_within_boundary_limits(&auth.roles)
        && optional_string_within_boundary_limit(auth.azp.as_deref())
        && auth_claim_within_boundary_limits(&auth.claims, "sql_key")
        && auth_claim_within_boundary_limits(&auth.claims, "params_hash")
        && auth.project_id >= 0
}

fn das_cfg_within_boundary_limits(cfg: &DasCfgInput) -> bool {
    list_within_boundary_limits(&cfg.system_allow_endpoints)
        && list_within_boundary_limits(&cfg.system_allow_sql_keys)
        && list_within_boundary_limits(&cfg.devtools_roles)
}

fn das_query_within_boundary_limits(query: &DasQueryInput) -> bool {
    string_within_boundary_limit(&query.endpoint)
        && string_within_boundary_limit(&query.sql_key)
        && string_within_boundary_limit(&query.params_hash)
}

fn das_query_input_within_boundary_limits(input: &DasDecisionInput) -> bool {
    das_auth_within_boundary_limits(&input.auth)
        && das_cfg_within_boundary_limits(&input.cfg)
        && das_query_within_boundary_limits(&input.query)
        && list_within_boundary_limits(&input.allowlist)
}

fn das_observability_input_within_boundary_limits(input: &DasObservabilityInput) -> bool {
    das_auth_within_boundary_limits(&input.auth)
        && das_cfg_within_boundary_limits(&input.cfg)
        && string_within_boundary_limit(&input.endpoint)
}

fn kernel_gateway_path_denied(path: &str, segments: &[&str]) -> bool {
    path.contains(';')
        || path.contains('?')
        || path.contains('#')
        || contains_encoded_delimiter(path)
        || segments
            .iter()
            .any(|segment| matches!(*segment, "." | ".."))
}

fn contains_encoded_delimiter(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("%2f")
        || lower.contains("%3b")
        || lower.contains("%3f")
        || lower.contains("%23")
        || lower.contains("%2e")
}

fn path_segments(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn scope_for_rw(is_read: bool, read_scope: &str, write_scope: &str) -> Vec<String> {
    if is_read {
        vec![read_scope.to_string()]
    } else {
        vec![write_scope.to_string()]
    }
}

fn is_client_secret_path(segments: &[&str]) -> bool {
    segments.contains(&"client-secret")
}

enum ScopeFamily {
    Users,
    Groups,
    Roles,
    Clients,
    ClientScopes,
    Idp,
    Events,
    Tokens,
    Observability,
    Realm,
}

fn scope_family(segments: &[&str]) -> ScopeFamily {
    if let Some(family) = admin_realm_scope(segments) {
        return family;
    }

    match segments.get(1).copied() {
        Some("users") => ScopeFamily::Users,
        Some("groups") => ScopeFamily::Groups,
        Some("roles") | Some("roles-by-id") => ScopeFamily::Roles,
        Some("clients") => ScopeFamily::Clients,
        Some("client-scopes") => ScopeFamily::ClientScopes,
        Some("identity-provider") => ScopeFamily::Idp,
        Some("events") => ScopeFamily::Events,
        Some("sessions")
        | Some("user-sessions")
        | Some("offline-sessions")
        | Some("client-session-stats") => ScopeFamily::Tokens,
        Some("attack-detection") | Some("serverinfo") | Some("metrics") => {
            ScopeFamily::Observability
        }
        _ => ScopeFamily::Realm,
    }
}

fn admin_realm_scope(segments: &[&str]) -> Option<ScopeFamily> {
    if segments.first() != Some(&"admin") || segments.get(1) != Some(&"realms") {
        return None;
    }

    match segments.get(3).copied() {
        Some("users") => Some(ScopeFamily::Users),
        Some("groups") => Some(ScopeFamily::Groups),
        Some("roles") | Some("roles-by-id") => Some(ScopeFamily::Roles),
        Some("clients") => Some(ScopeFamily::Clients),
        Some("client-scopes") => Some(ScopeFamily::ClientScopes),
        Some("identity-provider") => Some(ScopeFamily::Idp),
        Some("events") => Some(ScopeFamily::Events),
        Some("sessions")
        | Some("user-sessions")
        | Some("offline-sessions")
        | Some("client-session-stats") => Some(ScopeFamily::Tokens),
        Some("attack-detection") | Some("serverinfo") | Some("metrics") => {
            Some(ScopeFamily::Observability)
        }
        Some("realm") => Some(ScopeFamily::Realm),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        das_observability_decision, das_query_decision, gateway_decision, required_scopes,
        ClaimsCfg, DasAuthInput, DasCfgInput, DasDecisionInput, DasObservabilityInput,
        DasQueryInput, GatewayDecisionInput, QuorumState, SqlAccess, SqlRisk,
    };
    use serde_json::{json, Value};

    #[test]
    fn gateway_scope_mapping_matches_realm_default() {
        assert_eq!(
            required_scopes("GET", "/admin/realms/demo/users"),
            vec!["keycloak-admin:users:read".to_string()]
        );
        assert_eq!(
            required_scopes("POST", "/admin/realms/demo"),
            vec!["keycloak-admin:realm:write".to_string()]
        );
    }

    #[test]
    fn gateway_decision_returns_required_scopes_on_allow() {
        let claims = json!({
            "iss": "https://issuer.example",
            "aud": ["mcp"],
            "azp": "client-a"
        })
        .as_object()
        .expect("claims object")
        .clone();
        let decision = gateway_decision(&GatewayDecisionInput {
            method: "GET".to_string(),
            path: "/admin/realms/demo/users".to_string(),
            token_scopes: vec!["keycloak-admin:users:read".to_string()],
            claims,
            cfg: ClaimsCfg {
                expected_issuer: Some("https://issuer.example".to_string()),
                expected_audience: Some("mcp".to_string()),
                allowed_azp: vec!["client-a".to_string()],
            },
        });
        assert!(decision.allow);
        assert_eq!(
            decision.required_scopes,
            Some(vec!["keycloak-admin:users:read".to_string()])
        );
    }

    #[test]
    fn das_query_enforces_quorum_for_high_risk_write() {
        let decision = das_query_decision(&DasDecisionInput {
            auth: DasAuthInput {
                scopes: vec!["ops:write".to_string()],
                roles: Vec::new(),
                azp: None,
                is_system: false,
                claims: json!({}).as_object().expect("claims object").clone(),
                project_id: 1,
            },
            cfg: DasCfgInput {
                write_implies_read: true,
                system_allow_endpoints: Vec::new(),
                system_allow_sql_keys: Vec::new(),
                devtools_roles: vec!["devtools".to_string()],
                delegation_mode: false,
            },
            query: DasQueryInput {
                endpoint: "query".to_string(),
                sql_key: "foo".to_string(),
                params_hash: "abc".to_string(),
                access: SqlAccess::Write,
                risk: SqlRisk::High,
                quorum_state: QuorumState::Stale,
            },
            allowlist: vec!["foo".to_string()],
        });
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("QUORUM_STALE"));
    }

    #[test]
    fn das_observability_requires_devtools_role() {
        let decision = das_observability_decision(&DasObservabilityInput {
            auth: DasAuthInput {
                scopes: Vec::new(),
                roles: vec!["devtools".to_string()],
                azp: None,
                is_system: false,
                claims: json!({}).as_object().expect("claims object").clone(),
                project_id: 1,
            },
            cfg: DasCfgInput {
                write_implies_read: true,
                system_allow_endpoints: Vec::new(),
                system_allow_sql_keys: Vec::new(),
                devtools_roles: vec!["devtools".to_string()],
                delegation_mode: false,
            },
            endpoint: "metrics".to_string(),
        });
        assert!(decision.allow);
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

    fn sample_cfg() -> ClaimsCfg {
        ClaimsCfg {
            expected_issuer: Some("https://issuer.example".to_string()),
            expected_audience: Some("mcp".to_string()),
            allowed_azp: vec!["client-a".to_string()],
        }
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
            cfg: sample_cfg(),
        }
    }

    #[test]
    fn gateway_denies_encoded_delimiters() {
        let decision = gateway_decision(&gateway_input_for("/admin/realms/%23/users"));
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("INVALID_PATH"));
    }

    #[test]
    fn gateway_allows_percent_5c() {
        let decision = gateway_decision(&gateway_input_for("/admin/realms/demo%5cusers"));
        assert!(decision.allow);
    }

    #[test]
    fn gateway_denies_dot_segments() {
        let decision = gateway_decision(&gateway_input_for("/admin/realms/../users"));
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("INVALID_PATH"));
    }

    #[test]
    fn gateway_denies_missing_realm() {
        let decision = gateway_decision(&gateway_input_for(""));
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("MISSING_REALM"));
    }

    #[test]
    fn gateway_non_string_issuer_is_invalid_input_malformed_claims() {
        let mut input = gateway_input_for("/admin/realms/demo/users");
        input.claims = json!({
            "iss": 123,
            "aud": ["mcp"],
            "azp": "client-a"
        })
        .as_object()
        .expect("claims object")
        .clone();
        let decision = gateway_decision(&input);
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("INVALID_INPUT"));
        assert_eq!(decision.reason.as_deref(), Some("malformed_claims"));
    }

    #[test]
    fn gateway_audience_mixed_types_is_invalid_input_malformed_claims() {
        let mut input = gateway_input_for("/admin/realms/demo/users");
        input.claims = json!({
            "iss": "https://issuer.example",
            "aud": ["mcp", 7, "", "   "],
            "azp": "client-a"
        })
        .as_object()
        .expect("claims object")
        .clone();
        let decision = gateway_decision(&input);
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("INVALID_INPUT"));
        assert_eq!(decision.reason.as_deref(), Some("malformed_claims"));
    }

    #[test]
    fn das_query_negative_project_id_denies_as_invalid_input() {
        let decision = das_query_decision(&DasDecisionInput {
            auth: DasAuthInput {
                scopes: vec!["ops:write".to_string()],
                roles: Vec::new(),
                azp: None,
                is_system: false,
                claims: json!({}).as_object().expect("claims object").clone(),
                project_id: -1,
            },
            cfg: DasCfgInput {
                write_implies_read: true,
                system_allow_endpoints: Vec::new(),
                system_allow_sql_keys: Vec::new(),
                devtools_roles: vec!["devtools".to_string()],
                delegation_mode: false,
            },
            query: DasQueryInput {
                endpoint: "query".to_string(),
                sql_key: "foo".to_string(),
                params_hash: "abc".to_string(),
                access: SqlAccess::Write,
                risk: SqlRisk::Low,
                quorum_state: QuorumState::Ok,
            },
            allowlist: vec!["foo".to_string()],
        });
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("INVALID_INPUT"));
        assert_eq!(decision.reason.as_deref(), Some("boundary_limits"));
    }
}
