//! # Embedded Policy API
//!
//! High-level, non-domain-specific embedding helpers for MCP servers.
//!
//! ## Rationale
//! The kernel's low-level API is intentionally explicit for conformance and proof
//! parity. This module adds a thin ergonomic layer for service integration without
//! changing core decision semantics.
//!
//! ## Formal Alignment
//! These helpers delegate claims and deny-code behavior to the canonical decision
//! primitives in this crate (`enforce_claims`, `DecisionCode`).
//!
//! ## References
//! * `spec/README.md`
//! * `docs/industrial_workflow_case_study.md`

use serde_json::{Map, Value};

use crate::{
    enforce_claims, has_path_segment, list_within_boundary_limits, string_within_boundary_limit,
    validate_http_path, ClaimsCfg, Decision, DecisionCode,
};

const DEFAULT_READ_SCOPE: &str = "mcp:read";
const DEFAULT_WRITE_SCOPE: &str = "mcp:write";

/// Builder for `ClaimsCfg` with fluent ergonomics.
#[derive(Debug, Clone, Default)]
pub struct ClaimsCfgBuilder {
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
    allowed_azp: Vec<String>,
}

impl ClaimsCfgBuilder {
    pub fn expected_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.expected_issuer = Some(issuer.into());
        self
    }

    pub fn expected_audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audience = Some(audience.into());
        self
    }

    pub fn allow_azp(mut self, azp: impl Into<String>) -> Self {
        self.allowed_azp.push(azp.into());
        self
    }

    pub fn build(self) -> ClaimsCfg {
        ClaimsCfg {
            expected_issuer: self.expected_issuer,
            expected_audience: self.expected_audience,
            allowed_azp: self.allowed_azp,
        }
    }
}

impl ClaimsCfg {
    /// Start a fluent `ClaimsCfg` builder.
    pub fn builder() -> ClaimsCfgBuilder {
        ClaimsCfgBuilder::default()
    }
}

/// Route-specific scope binding used by `RoutePolicy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRoute {
    pub prefix: String,
    pub read_scope: String,
    pub write_scope: String,
}

impl ScopeRoute {
    pub fn new(
        prefix: impl Into<String>,
        read_scope: impl Into<String>,
        write_scope: impl Into<String>,
    ) -> Self {
        Self {
            prefix: normalize_prefix(&prefix.into()),
            read_scope: read_scope.into(),
            write_scope: write_scope.into(),
        }
    }
}

/// Non-domain route-to-scope policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePolicy {
    default_read_scope: String,
    default_write_scope: String,
    routes: Vec<ScopeRoute>,
}

impl Default for RoutePolicy {
    fn default() -> Self {
        Self {
            default_read_scope: DEFAULT_READ_SCOPE.to_string(),
            default_write_scope: DEFAULT_WRITE_SCOPE.to_string(),
            routes: Vec::new(),
        }
    }
}

impl RoutePolicy {
    pub fn with_default_scopes(
        mut self,
        read_scope: impl Into<String>,
        write_scope: impl Into<String>,
    ) -> Self {
        self.default_read_scope = read_scope.into();
        self.default_write_scope = write_scope.into();
        self
    }

    pub fn with_route(
        mut self,
        prefix: impl Into<String>,
        read_scope: impl Into<String>,
        write_scope: impl Into<String>,
    ) -> Self {
        self.routes
            .push(ScopeRoute::new(prefix, read_scope, write_scope));
        self.routes
            .sort_by_key(|route| std::cmp::Reverse(route.prefix.len()));
        self
    }

    /// Resolve required scopes for a request method/path.
    pub fn required_scopes(&self, method: &str, path: &str) -> Vec<String> {
        let is_read = is_read_method(method);
        let scope = self
            .route_for_path(path)
            .map(|route| {
                if is_read {
                    route.read_scope.as_str()
                } else {
                    route.write_scope.as_str()
                }
            })
            .unwrap_or_else(|| {
                if is_read {
                    self.default_read_scope.as_str()
                } else {
                    self.default_write_scope.as_str()
                }
            });
        vec![scope.to_string()]
    }

    fn route_for_path(&self, path: &str) -> Option<&ScopeRoute> {
        let normalized = normalize_path(path);
        self.routes.iter().find(|route| {
            if route.prefix == "/" {
                return true;
            }
            normalized == route.prefix
                || normalized
                    .strip_prefix(route.prefix.as_str())
                    .map(|tail| tail.starts_with('/'))
                    .unwrap_or(false)
        })
    }
}

/// A lightweight request envelope for service integration.
#[derive(Debug, Clone, PartialEq)]
pub struct GenericPolicyRequest {
    pub method: String,
    pub path: String,
    pub token_scopes: Vec<String>,
    pub claims: Map<String, Value>,
}

/// Error returned when claims ingestion shape is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimsShapeError {
    NonObjectClaims,
}

impl std::fmt::Display for ClaimsShapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonObjectClaims => write!(f, "claims payload must be a JSON object"),
        }
    }
}

impl std::error::Error for ClaimsShapeError {}

impl GenericPolicyRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            token_scopes: Vec::new(),
            claims: Map::new(),
        }
    }

    pub fn with_token_scopes(mut self, token_scopes: Vec<String>) -> Self {
        self.token_scopes = token_scopes;
        self
    }

    pub fn with_claims(mut self, claims: Map<String, Value>) -> Self {
        self.claims = claims;
        self
    }

    pub fn with_claims_value(mut self, claims: &Value) -> Result<Self, ClaimsShapeError> {
        let object = claims
            .as_object()
            .ok_or(ClaimsShapeError::NonObjectClaims)?
            .clone();
        self.claims = object;
        Ok(self)
    }
}

/// High-level engine for embedding the policy kernel into HTTP/MCP services.
#[derive(Debug, Clone)]
pub struct EmbeddedPolicyKernel {
    claims_cfg: ClaimsCfg,
    route_policy: RoutePolicy,
}

impl Default for EmbeddedPolicyKernel {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl EmbeddedPolicyKernel {
    pub fn builder() -> EmbeddedPolicyKernelBuilder {
        EmbeddedPolicyKernelBuilder::default()
    }

    pub fn claims_cfg(&self) -> &ClaimsCfg {
        &self.claims_cfg
    }

    pub fn route_policy(&self) -> &RoutePolicy {
        &self.route_policy
    }

    /// Evaluate a generic request using non-domain scope policy + core claims checks.
    pub fn authorize(&self, request: &GenericPolicyRequest) -> Decision {
        if !request_within_boundary_limits(request) {
            return Decision::deny(DecisionCode::InvalidInput, Some("boundary_limits"));
        }
        let claims_decision = enforce_claims(&self.claims_cfg, &request.claims);
        if !claims_decision.allow {
            return claims_decision;
        }

        let path_decision = validate_http_path(&request.path);
        if !path_decision.allow {
            return path_decision;
        }
        if !has_path_segment(&request.path) {
            return Decision::deny(DecisionCode::MissingRealm, None);
        }
        if matches!(classify_method(&request.method), MethodPolicy::Deny) {
            return Decision::deny(DecisionCode::MissingScopes, Some("unsupported_method"));
        }

        let required_scopes = self
            .route_policy
            .required_scopes(&request.method, &request.path);
        if !list_within_boundary_limits(&required_scopes) {
            return Decision::deny(DecisionCode::InvalidInput, Some("boundary_limits"));
        }
        let missing_scope = required_scopes
            .iter()
            .any(|scope| !request.token_scopes.iter().any(|actual| actual == scope));
        if missing_scope {
            return Decision::deny(DecisionCode::MissingScopes, None);
        }

        Decision::allow().with_required_scopes(required_scopes)
    }

    /// Convenience helper for toolkits storing claims as `serde_json::Value`.
    pub fn authorize_value_claims(
        &self,
        method: &str,
        path: &str,
        token_scopes: &[String],
        claims: &Value,
    ) -> Result<Decision, ClaimsShapeError> {
        let request = GenericPolicyRequest::new(method, path)
            .with_token_scopes(token_scopes.to_vec())
            .with_claims_value(claims)?;
        Ok(self.authorize(&request))
    }
}

/// Builder for `EmbeddedPolicyKernel`.
#[derive(Debug, Clone)]
pub struct EmbeddedPolicyKernelBuilder {
    claims_cfg: ClaimsCfgBuilder,
    route_policy: RoutePolicy,
}

impl Default for EmbeddedPolicyKernelBuilder {
    fn default() -> Self {
        Self {
            claims_cfg: ClaimsCfg::builder(),
            route_policy: RoutePolicy::default(),
        }
    }
}

impl EmbeddedPolicyKernelBuilder {
    pub fn expected_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.claims_cfg = self.claims_cfg.expected_issuer(issuer);
        self
    }

    pub fn expected_audience(mut self, audience: impl Into<String>) -> Self {
        self.claims_cfg = self.claims_cfg.expected_audience(audience);
        self
    }

    pub fn allow_azp(mut self, azp: impl Into<String>) -> Self {
        self.claims_cfg = self.claims_cfg.allow_azp(azp);
        self
    }

    pub fn default_scopes(
        mut self,
        read_scope: impl Into<String>,
        write_scope: impl Into<String>,
    ) -> Self {
        self.route_policy = self
            .route_policy
            .with_default_scopes(read_scope, write_scope);
        self
    }

    pub fn route(
        mut self,
        prefix: impl Into<String>,
        read_scope: impl Into<String>,
        write_scope: impl Into<String>,
    ) -> Self {
        self.route_policy = self
            .route_policy
            .with_route(prefix, read_scope, write_scope);
        self
    }

    pub fn build(self) -> EmbeddedPolicyKernel {
        EmbeddedPolicyKernel {
            claims_cfg: self.claims_cfg.build(),
            route_policy: self.route_policy,
        }
    }
}

fn normalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim();
    let core = trimmed.trim_matches('/');
    if core.is_empty() {
        return "/".to_string();
    }
    format!("/{core}")
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodPolicy {
    Read,
    Write,
    Deny,
}

fn classify_method(method: &str) -> MethodPolicy {
    let normalized = method.trim().to_ascii_uppercase();
    match normalized.as_str() {
        "GET" | "HEAD" | "OPTIONS" => MethodPolicy::Read,
        "TRACE" | "CONNECT" => MethodPolicy::Deny,
        _ => MethodPolicy::Write,
    }
}

fn is_read_method(method: &str) -> bool {
    matches!(classify_method(method), MethodPolicy::Read)
}

fn request_within_boundary_limits(request: &GenericPolicyRequest) -> bool {
    string_within_boundary_limit(request.method.trim())
        && string_within_boundary_limit(&request.path)
        && list_within_boundary_limits(&request.token_scopes)
}

#[cfg(test)]
mod tests {
    use super::{
        ClaimsCfgBuilder, EmbeddedPolicyKernel, GenericPolicyRequest, RoutePolicy, ScopeRoute,
    };
    use crate::DecisionCode;
    use serde_json::json;

    #[test]
    fn claims_cfg_builder_sets_expected_fields() {
        let cfg = ClaimsCfgBuilder::default()
            .expected_issuer("https://issuer.example")
            .expected_audience("mcp-api")
            .allow_azp("tool-a")
            .build();
        assert_eq!(
            cfg.expected_issuer.as_deref(),
            Some("https://issuer.example")
        );
        assert_eq!(cfg.expected_audience.as_deref(), Some("mcp-api"));
        assert_eq!(cfg.allowed_azp, vec!["tool-a".to_string()]);
    }

    #[test]
    fn route_policy_prefers_longest_prefix() {
        let policy = RoutePolicy::default()
            .with_route("/mcp", "mcp:read", "mcp:write")
            .with_route("/mcp/admin", "mcp:admin:read", "mcp:admin:write");
        assert_eq!(
            policy.required_scopes("GET", "/mcp/admin/tools"),
            vec!["mcp:admin:read".to_string()]
        );
        assert_eq!(
            policy.required_scopes("POST", "/mcp/admin/tools"),
            vec!["mcp:admin:write".to_string()]
        );
    }

    #[test]
    fn route_policy_deep_prefix_precedence_with_root_fallback() {
        let policy = RoutePolicy::default()
            .with_route("/", "public:read", "public:write")
            .with_route("/api", "api:read", "api:write")
            .with_route("/api/v1/admin", "admin:read", "admin:write");

        assert_eq!(
            policy.required_scopes("GET", "/api/v1/admin/users"),
            vec!["admin:read".to_string()]
        );
        assert_eq!(
            policy.required_scopes("POST", "/api/v1/admin/users"),
            vec!["admin:write".to_string()]
        );
        assert_eq!(
            policy.required_scopes("GET", "/api/v1/tools"),
            vec!["api:read".to_string()]
        );
        assert_eq!(
            policy.required_scopes("POST", "/api/v1/tools"),
            vec!["api:write".to_string()]
        );
        assert_eq!(
            policy.required_scopes("GET", "/status"),
            vec!["public:read".to_string()]
        );
        assert_eq!(
            policy.required_scopes("POST", "/status"),
            vec!["public:write".to_string()]
        );
    }

    #[test]
    fn scope_route_normalizes_prefix() {
        let route = ScopeRoute::new("///mcp/admin//", "read", "write");
        assert_eq!(route.prefix, "/mcp/admin");
    }

    #[test]
    fn embedded_kernel_denies_missing_scope() {
        let kernel = EmbeddedPolicyKernel::default();
        let request = GenericPolicyRequest::new("POST", "/tools/call")
            .with_token_scopes(vec!["mcp:read".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(!decision.allow);
        assert_eq!(
            decision.code.as_deref(),
            Some(DecisionCode::MissingScopes.as_str())
        );
    }

    #[test]
    fn embedded_kernel_allows_default_read_scope() {
        let kernel = EmbeddedPolicyKernel::default();
        let request = GenericPolicyRequest::new("GET", "/tools/list")
            .with_token_scopes(vec!["mcp:read".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(decision.allow);
        assert_eq!(decision.required_scopes, Some(vec!["mcp:read".to_string()]));
    }

    #[test]
    fn embedded_kernel_enforces_claims_cfg() {
        let kernel = EmbeddedPolicyKernel::builder()
            .expected_issuer("https://issuer.example")
            .build();

        let claims = json!({ "iss": "https://other.example" });
        let decision = kernel
            .authorize_value_claims("GET", "/tools/list", &["mcp:read".to_string()], &claims)
            .expect("object claims should parse");
        assert!(!decision.allow);
        assert_eq!(
            decision.code.as_deref(),
            Some(DecisionCode::IssuerMismatch.as_str())
        );
    }

    #[test]
    fn with_claims_value_rejects_non_object_claims() {
        let request = GenericPolicyRequest::new("GET", "/tools/list")
            .with_claims_value(&json!(["scope:a", "scope:b"]));
        assert!(request.is_err());
    }

    #[test]
    fn authorize_value_claims_rejects_non_object_claims() {
        let kernel = EmbeddedPolicyKernel::default();
        let result = kernel.authorize_value_claims(
            "GET",
            "/tools/list",
            &["mcp:read".to_string()],
            &json!(null),
        );
        assert!(result.is_err());
    }

    #[test]
    fn embedded_kernel_denies_path_confusion() {
        let kernel = EmbeddedPolicyKernel::default();
        let request = GenericPolicyRequest::new("GET", "/tools/%2e%2e/secrets")
            .with_token_scopes(vec!["mcp:read".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(!decision.allow);
        assert_eq!(
            decision.code.as_deref(),
            Some(DecisionCode::InvalidPath.as_str())
        );
    }

    #[test]
    fn embedded_kernel_allows_double_slash_path() {
        let kernel = EmbeddedPolicyKernel::default();
        let request = GenericPolicyRequest::new("GET", "//tools/list")
            .with_token_scopes(vec!["mcp:read".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(decision.allow);
        assert_eq!(decision.required_scopes, Some(vec!["mcp:read".to_string()]));
    }

    #[test]
    fn embedded_kernel_denies_boundary_exceeding_method() {
        let kernel = EmbeddedPolicyKernel::default();
        let request = GenericPolicyRequest::new(
            "A".repeat(crate::BOUNDARY_MAX_STRING_LENGTH + 1),
            "/tools/list",
        )
        .with_token_scopes(vec!["mcp:read".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(!decision.allow);
        assert_eq!(
            decision.code.as_deref(),
            Some(DecisionCode::InvalidInput.as_str())
        );
        assert_eq!(decision.reason.as_deref(), Some("boundary_limits"));
    }

    #[test]
    fn embedded_kernel_denies_boundary_exceeding_required_scope() {
        let oversized_scope = "s".repeat(crate::BOUNDARY_MAX_STRING_LENGTH + 1);
        let kernel = EmbeddedPolicyKernel::builder()
            .default_scopes(oversized_scope, "mcp:write")
            .build();
        let request = GenericPolicyRequest::new("GET", "/tools/list")
            .with_token_scopes(vec!["mcp:read".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(!decision.allow);
        assert_eq!(
            decision.code.as_deref(),
            Some(DecisionCode::InvalidInput.as_str())
        );
        assert_eq!(decision.reason.as_deref(), Some("boundary_limits"));
    }

    #[test]
    fn embedded_kernel_denies_root_path_missing_realm() {
        let kernel = EmbeddedPolicyKernel::default();
        let request =
            GenericPolicyRequest::new("GET", "/").with_token_scopes(vec!["mcp:read".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(!decision.allow);
        assert_eq!(
            decision.code.as_deref(),
            Some(DecisionCode::MissingRealm.as_str())
        );
    }

    #[test]
    fn embedded_kernel_denies_empty_path_missing_realm() {
        let kernel = EmbeddedPolicyKernel::default();
        let request =
            GenericPolicyRequest::new("GET", "").with_token_scopes(vec!["mcp:read".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(!decision.allow);
        assert_eq!(
            decision.code.as_deref(),
            Some(DecisionCode::MissingRealm.as_str())
        );
    }

    #[test]
    fn embedded_kernel_denies_trace_method_even_with_write_scope() {
        let kernel = EmbeddedPolicyKernel::default();
        let request = GenericPolicyRequest::new("TRACE", "/tools/list")
            .with_token_scopes(vec!["mcp:write".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(!decision.allow);
        assert_eq!(
            decision.code.as_deref(),
            Some(DecisionCode::MissingScopes.as_str())
        );
        assert_eq!(decision.reason.as_deref(), Some("unsupported_method"));
    }

    #[test]
    fn embedded_kernel_denies_connect_method_even_with_write_scope() {
        let kernel = EmbeddedPolicyKernel::default();
        let request = GenericPolicyRequest::new("CONNECT", "/tools/list")
            .with_token_scopes(vec!["mcp:write".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(!decision.allow);
        assert_eq!(
            decision.code.as_deref(),
            Some(DecisionCode::MissingScopes.as_str())
        );
        assert_eq!(decision.reason.as_deref(), Some("unsupported_method"));
    }

    #[test]
    fn embedded_kernel_treats_unknown_method_as_write() {
        let kernel = EmbeddedPolicyKernel::default();
        let request = GenericPolicyRequest::new("BREW", "/tools/list")
            .with_token_scopes(vec!["mcp:read".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(!decision.allow);
        assert_eq!(
            decision.code.as_deref(),
            Some(DecisionCode::MissingScopes.as_str())
        );
        assert_eq!(decision.reason, None);
    }

    #[test]
    fn embedded_kernel_denies_double_encoded_dot_segments() {
        let kernel = EmbeddedPolicyKernel::default();
        let request = GenericPolicyRequest::new("GET", "/tools/%252e%252e/secrets")
            .with_token_scopes(vec!["mcp:read".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(!decision.allow);
        assert_eq!(
            decision.code.as_deref(),
            Some(DecisionCode::InvalidPath.as_str())
        );
    }

    #[test]
    fn embedded_kernel_denies_double_encoded_slash() {
        let kernel = EmbeddedPolicyKernel::default();
        let request = GenericPolicyRequest::new("GET", "/tools%252fadmin/list")
            .with_token_scopes(vec!["mcp:read".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(!decision.allow);
        assert_eq!(
            decision.code.as_deref(),
            Some(DecisionCode::InvalidPath.as_str())
        );
    }

    #[test]
    fn embedded_kernel_denies_malformed_percent_encoding() {
        let kernel = EmbeddedPolicyKernel::default();
        let request = GenericPolicyRequest::new("GET", "/tools/%2")
            .with_token_scopes(vec!["mcp:read".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(!decision.allow);
        assert_eq!(
            decision.code.as_deref(),
            Some(DecisionCode::InvalidPath.as_str())
        );
    }

    #[test]
    fn embedded_kernel_allows_double_encoded_non_confusing_sequence() {
        let kernel = EmbeddedPolicyKernel::default();
        let request = GenericPolicyRequest::new("GET", "/tools/%2520summary")
            .with_token_scopes(vec!["mcp:read".to_string()]);
        let decision = kernel.authorize(&request);
        assert!(decision.allow);
    }
}
