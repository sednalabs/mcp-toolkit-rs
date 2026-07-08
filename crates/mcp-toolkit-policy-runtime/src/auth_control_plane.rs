//! # Auth Control-Plane Policy
//!
//! Canonical request projection and authority helpers for authenticated MCP
//! control-plane requests.
//!
//! ## Ownership
//! This module owns reusable auth/control-plane request envelopes, HTTP request
//! mappers, and a generic policy authority that can be installed after the
//! toolkit auth surface.
//!
//! ## Non-ownership
//! This module does not parse raw bearer tokens, perform OAuth token exchange,
//! or encode server-specific business rules. It consumes sanitized
//! `AuthContext` data and delegates route/scope/claims checks to the embedded
//! policy kernel.
//!
//! ## Policy & Guarantees
//! * **Fail Closed**: Missing authenticated context, malformed envelopes, and
//!   inconsistent session/project bindings deny before dispatch.
//! * **Canonical Provenance**: Decisions are emitted with
//!   `auth-control-plane/v1`, runtime mode, and decision source metadata.
//! * **Projection Boundary**: Raw tokens are intentionally absent from the
//!   mapped control-plane request.
//!
//! ## Caller Responsibility
//! Callers are responsible for installing the mapper after authentication,
//! configuring route scopes for their service, and handling any domain-specific
//! policy decisions outside the generic toolkit authority.

use std::sync::Arc;

use mcp_toolkit_policy_core::{
    Decision, DecisionCode, EmbeddedPolicyKernel, EmbeddedPolicyKernelBuilder, GenericPolicyRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    PolicyAuthority, PolicyAuthorityDecision, PolicyHttpRequestContext, PolicyRequestMapper,
    PolicyRuntimeMode, SharedPolicyAuthority,
};

/// Canonical auth/control-plane contract version consumed by toolkit runtime helpers.
pub const AUTH_CONTROL_PLANE_POLICY_CONTRACT_VERSION: &str = "auth-control-plane/v1";

const AUTH_CONTROL_PLANE_AUTHORITY_SOURCE: &str = "mcp_toolkit_policy_runtime.auth_control_plane";
const DEFAULT_RESOURCE_KIND: &str = "mcp";
const DEFAULT_PROJECT_ID_CLAIM: &str = "project_id";
const DEFAULT_SESSION_ID_CLAIM: &str = "sid";
const DEFAULT_TOOL_CLAIM: &str = "tool";
const DEFAULT_RESOURCE_ID_CLAIM: &str = "resource_id";

/// Canonical token mode after authentication and edge verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthControlPlaneTokenMode {
    None,
    Bearer,
    SenderConstrained,
    Opaque,
    System,
}

/// Policy for health/readiness/status exposure when the policy layer wraps those routes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthControlPlaneHealthStatusExposure {
    /// Health and status routes require normal authenticated policy checks.
    #[default]
    Protected,
    /// Read-only health and status routes may pass without authenticated context.
    PublicReadOnly,
}

/// Canonical auth/control-plane subject or actor after edge authentication.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthControlPlanePrincipal {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act_as: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

/// OAuth client identity after edge validation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthControlPlaneClient {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
}

/// Canonical target resource for an auth/control-plane request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthControlPlaneResource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// Session binding facts supplied by the authenticated service edge.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthControlPlaneSession {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Normalized request action. Transport paths and raw URLs stay edge-owned.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthControlPlaneRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

/// Token-exchange posture after the STS or gateway normalizes the proposal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthControlPlaneExchange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester_client: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_claim_project_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_token_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_chain_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_parameter_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_requested: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_token_remaining_ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_fallback_allowed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub das_must_revalidate: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_actor_client: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange_id: Option<String>,
}

/// Normalized opaque-token introspection response after edge verification.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthControlPlaneIntrospection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audiences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_constrained: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf_thumbprint_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

/// Canonical token posture for broad auth/control-plane decisions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthControlPlaneToken {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<AuthControlPlaneTokenMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange: Option<AuthControlPlaneExchange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection: Option<AuthControlPlaneIntrospection>,
}

/// Proof-of-possession and replay facts produced by edge verification.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthControlPlaneProof {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_constrained: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf_thumbprint_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_ok: Option<bool>,
}

/// One normalized delegation or act-as hop.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthControlPlaneDelegation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange_id: Option<String>,
}

/// Edge-classified action risk.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthControlPlaneRisk {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_action: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_action: Option<bool>,
}

/// Observation/read classification for non-mutating surfaces.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthControlPlaneObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_class: Option<String>,
}

/// Canonical auth/control-plane request envelope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthControlPlaneInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<AuthControlPlanePrincipal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<AuthControlPlanePrincipal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audiences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<AuthControlPlaneClient>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<AuthControlPlaneResource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<AuthControlPlaneSession>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<AuthControlPlaneRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<AuthControlPlaneToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<AuthControlPlaneProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Vec<AuthControlPlaneDelegation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<AuthControlPlaneRisk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation: Option<AuthControlPlaneObservation>,
}

/// Policy authority for generic auth/control-plane requests.
#[derive(Debug, Clone)]
pub struct AuthControlPlanePolicyAuthority {
    decision_source: String,
    runtime_mode: PolicyRuntimeMode,
    policy_contract_version: String,
    kernel: EmbeddedPolicyKernel,
    health_status_exposure: AuthControlPlaneHealthStatusExposure,
}

impl AuthControlPlanePolicyAuthority {
    /// Builds a default auth/control-plane policy authority.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// The default authority requires authenticated context for all routes and
    /// delegates method/path scope decisions to `EmbeddedPolicyKernel`.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(kernel: EmbeddedPolicyKernel) -> Self {
        Self {
            decision_source: AUTH_CONTROL_PLANE_AUTHORITY_SOURCE.to_string(),
            runtime_mode: PolicyRuntimeMode::Rust,
            policy_contract_version: AUTH_CONTROL_PLANE_POLICY_CONTRACT_VERSION.to_string(),
            kernel,
            health_status_exposure: AuthControlPlaneHealthStatusExposure::Protected,
        }
    }

    /// Starts an auth/control-plane authority builder.
    pub fn builder() -> AuthControlPlanePolicyAuthorityBuilder {
        AuthControlPlanePolicyAuthorityBuilder::default()
    }

    /// Wraps this authority in a shared trait object for Tower integration.
    pub fn shared(self) -> SharedPolicyAuthority<AuthControlPlaneInput> {
        Arc::new(self)
    }

    fn evaluate_policy(&self, input: &AuthControlPlaneInput) -> Decision {
        if input.schema_version.as_deref() != Some(AUTH_CONTROL_PLANE_POLICY_CONTRACT_VERSION) {
            return Decision::deny(DecisionCode::InvalidInput, Some("contract_version"));
        }

        if self.health_status_exposure == AuthControlPlaneHealthStatusExposure::PublicReadOnly
            && is_health_status_read(input)
        {
            return Decision::allow();
        }

        let token_mode = match token_mode(input) {
            Some(AuthControlPlaneTokenMode::None) | None => {
                return Decision::deny(DecisionCode::MissingToken, Some("token_missing"));
            }
            Some(mode) => mode,
        };

        let subject_id = match principal_id(input.subject.as_ref()) {
            Some(value) => value,
            None => return Decision::deny(DecisionCode::MissingToken, Some("subject_missing")),
        };
        let actor_id = match principal_id(input.actor.as_ref()) {
            Some(value) => value,
            None => return Decision::deny(DecisionCode::MissingToken, Some("actor_missing")),
        };

        if token_mode == AuthControlPlaneTokenMode::System
            && request_action(input) != Some("system.run")
        {
            return Decision::deny(
                DecisionCode::SystemTokenForbidden,
                Some("system_token_forbidden"),
            );
        }

        if let Some(decision) = validate_session_binding(input, subject_id, actor_id) {
            return decision;
        }
        if let Some(decision) = validate_token_exchange(input) {
            return decision;
        }
        if let Some(decision) = validate_sender_constraint(input, token_mode) {
            return decision;
        }

        let request = match to_generic_request(input) {
            Ok(value) => value,
            Err(decision) => return decision,
        };
        self.kernel.authorize(&request)
    }
}

impl PolicyAuthority<AuthControlPlaneInput> for AuthControlPlanePolicyAuthority {
    fn evaluate(&self, request: &AuthControlPlaneInput) -> PolicyAuthorityDecision {
        PolicyAuthorityDecision::from_policy_decision(
            self.evaluate_policy(request),
            self.decision_source.clone(),
            self.runtime_mode,
            Some(&self.policy_contract_version),
        )
    }
}

impl Default for AuthControlPlanePolicyAuthority {
    fn default() -> Self {
        Self::new(EmbeddedPolicyKernel::default())
    }
}

/// Builder for [`AuthControlPlanePolicyAuthority`].
#[derive(Debug, Clone)]
pub struct AuthControlPlanePolicyAuthorityBuilder {
    decision_source: String,
    runtime_mode: PolicyRuntimeMode,
    policy_contract_version: String,
    kernel: EmbeddedPolicyKernelBuilder,
    health_status_exposure: AuthControlPlaneHealthStatusExposure,
}

impl AuthControlPlanePolicyAuthorityBuilder {
    /// Overrides decision-source provenance.
    pub fn decision_source(mut self, source: impl Into<String>) -> Self {
        self.decision_source = source.into();
        self
    }

    /// Overrides runtime-mode provenance.
    pub fn runtime_mode(mut self, mode: PolicyRuntimeMode) -> Self {
        self.runtime_mode = mode;
        self
    }

    /// Overrides policy contract-version provenance.
    pub fn policy_contract_version(mut self, version: impl Into<String>) -> Self {
        self.policy_contract_version = version.into();
        self
    }

    /// Requires a claims issuer value when evaluating mapped requests.
    pub fn expected_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.kernel = self.kernel.expected_issuer(issuer);
        self
    }

    /// Requires a claims audience value when evaluating mapped requests.
    pub fn expected_audience(mut self, audience: impl Into<String>) -> Self {
        self.kernel = self.kernel.expected_audience(audience);
        self
    }

    /// Allows an authorized-party/client value when evaluating mapped requests.
    pub fn allow_azp(mut self, azp: impl Into<String>) -> Self {
        self.kernel = self.kernel.allow_azp(azp);
        self
    }

    /// Configures default read/write scopes.
    pub fn default_scopes(
        mut self,
        read_scope: impl Into<String>,
        write_scope: impl Into<String>,
    ) -> Self {
        self.kernel = self.kernel.default_scopes(read_scope, write_scope);
        self
    }

    /// Adds a route-prefix scope binding.
    pub fn route(
        mut self,
        prefix: impl Into<String>,
        read_scope: impl Into<String>,
        write_scope: impl Into<String>,
    ) -> Self {
        self.kernel = self.kernel.route(prefix, read_scope, write_scope);
        self
    }

    /// Configures health/status route exposure.
    pub fn health_status_exposure(
        mut self,
        exposure: AuthControlPlaneHealthStatusExposure,
    ) -> Self {
        self.health_status_exposure = exposure;
        self
    }

    /// Builds the authority.
    pub fn build(self) -> AuthControlPlanePolicyAuthority {
        AuthControlPlanePolicyAuthority {
            decision_source: self.decision_source,
            runtime_mode: self.runtime_mode,
            policy_contract_version: self.policy_contract_version,
            kernel: self.kernel.build(),
            health_status_exposure: self.health_status_exposure,
        }
    }
}

impl Default for AuthControlPlanePolicyAuthorityBuilder {
    fn default() -> Self {
        Self {
            decision_source: AUTH_CONTROL_PLANE_AUTHORITY_SOURCE.to_string(),
            runtime_mode: PolicyRuntimeMode::Rust,
            policy_contract_version: AUTH_CONTROL_PLANE_POLICY_CONTRACT_VERSION.to_string(),
            kernel: EmbeddedPolicyKernel::builder(),
            health_status_exposure: AuthControlPlaneHealthStatusExposure::Protected,
        }
    }
}

/// Constructs the default shared auth/control-plane policy authority.
pub fn auth_control_plane_policy_authority() -> SharedPolicyAuthority<AuthControlPlaneInput> {
    AuthControlPlanePolicyAuthority::default().shared()
}

/// Maps sanitized toolkit HTTP auth context into an auth/control-plane request envelope.
#[derive(Debug, Clone)]
pub struct AuthControlPlaneHttpMapper {
    token_mode: AuthControlPlaneTokenMode,
    resource_kind: String,
    project_id_claim: String,
    session_id_claim: String,
    tool_claim: String,
    resource_id_claim: String,
}

impl AuthControlPlaneHttpMapper {
    /// Creates a mapper with default bearer-token posture and standard claim names.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the token mode projected by this mapper when auth context exists.
    pub fn token_mode(mut self, mode: AuthControlPlaneTokenMode) -> Self {
        self.token_mode = mode;
        self
    }

    /// Sets the resource kind projected into control-plane requests.
    pub fn resource_kind(mut self, kind: impl Into<String>) -> Self {
        self.resource_kind = kind.into();
        self
    }

    /// Sets the claim name used for project binding.
    pub fn project_id_claim(mut self, claim: impl Into<String>) -> Self {
        self.project_id_claim = claim.into();
        self
    }

    /// Sets the claim name used for session binding.
    pub fn session_id_claim(mut self, claim: impl Into<String>) -> Self {
        self.session_id_claim = claim.into();
        self
    }

    /// Sets the claim name used for tool attribution.
    pub fn tool_claim(mut self, claim: impl Into<String>) -> Self {
        self.tool_claim = claim.into();
        self
    }

    /// Sets the claim name used for resource identity.
    pub fn resource_id_claim(mut self, claim: impl Into<String>) -> Self {
        self.resource_id_claim = claim.into();
        self
    }
}

impl Default for AuthControlPlaneHttpMapper {
    fn default() -> Self {
        Self {
            token_mode: AuthControlPlaneTokenMode::Bearer,
            resource_kind: DEFAULT_RESOURCE_KIND.to_string(),
            project_id_claim: DEFAULT_PROJECT_ID_CLAIM.to_string(),
            session_id_claim: DEFAULT_SESSION_ID_CLAIM.to_string(),
            tool_claim: DEFAULT_TOOL_CLAIM.to_string(),
            resource_id_claim: DEFAULT_RESOURCE_ID_CLAIM.to_string(),
        }
    }
}

impl PolicyRequestMapper<AuthControlPlaneInput> for AuthControlPlaneHttpMapper {
    fn map_request(&self, context: &PolicyHttpRequestContext) -> AuthControlPlaneInput {
        let claims = context.auth.as_ref().map(|auth| auth.claims.clone());
        let project_id = claims
            .as_ref()
            .and_then(|value| claim_string(value, &self.project_id_claim));
        let session_id = claims
            .as_ref()
            .and_then(|value| claim_string(value, &self.session_id_claim))
            .or_else(|| {
                claims
                    .as_ref()
                    .and_then(|value| claim_string(value, "session_id"))
            });
        let subject_id = context
            .auth
            .as_ref()
            .and_then(|auth| auth.subject.clone())
            .or_else(|| claims.as_ref().and_then(|value| claim_string(value, "sub")))
            .or_else(|| context.auth.as_ref().map(|auth| auth.actor.clone()));
        let actor_id = context.auth.as_ref().map(|auth| auth.actor.clone());
        let action = infer_action(&context.method, &context.path);
        let tool = claims
            .as_ref()
            .and_then(|value| claim_string(value, &self.tool_claim))
            .or_else(|| infer_tool_from_path(&context.path));
        let resource_id = claims
            .as_ref()
            .and_then(|value| claim_string(value, &self.resource_id_claim))
            .or_else(|| {
                context
                    .surface
                    .as_ref()
                    .map(|surface| surface.resource_url.clone())
            });

        AuthControlPlaneInput {
            schema_version: Some(AUTH_CONTROL_PLANE_POLICY_CONTRACT_VERSION.to_string()),
            subject: context.auth.as_ref().map(|auth| AuthControlPlanePrincipal {
                kind: Some("user".to_string()),
                id: subject_id.clone(),
                tenant: claims
                    .as_ref()
                    .and_then(|value| claim_string(value, "tenant_id")),
                act_as: None,
                roles: non_empty_vec(auth.roles.clone()),
            }),
            actor: context.auth.as_ref().map(|auth| AuthControlPlanePrincipal {
                kind: Some("actor".to_string()),
                id: actor_id.clone(),
                tenant: claims
                    .as_ref()
                    .and_then(|value| claim_string(value, "tenant_id")),
                act_as: None,
                roles: non_empty_vec(auth.roles.clone()),
            }),
            issuer: context
                .surface
                .as_ref()
                .map(|surface| surface.issuer.clone())
                .or_else(|| claims.as_ref().and_then(|value| claim_string(value, "iss"))),
            audiences: claims.as_ref().and_then(claim_audiences),
            client: context.auth.as_ref().map(|auth| AuthControlPlaneClient {
                client_id: auth.azp.clone().or_else(|| {
                    claims
                        .as_ref()
                        .and_then(|value| claim_string(value, "client_id"))
                }),
                azp: auth.azp.clone(),
            }),
            scopes: context.auth.as_ref().map(|auth| auth.scopes.clone()),
            resource: Some(AuthControlPlaneResource {
                kind: Some(self.resource_kind.clone()),
                project_id: project_id.clone(),
                tenant_id: claims
                    .as_ref()
                    .and_then(|value| claim_string(value, "tenant_id")),
                id: resource_id,
            }),
            session: Some(AuthControlPlaneSession {
                session_id,
                project_id: project_id.clone(),
                bound_subject: claims
                    .as_ref()
                    .and_then(|value| claim_string(value, "bound_subject")),
                bound_actor: claims
                    .as_ref()
                    .and_then(|value| claim_string(value, "bound_actor")),
                state: claims
                    .as_ref()
                    .and_then(|value| claim_string(value, "session_state")),
            }),
            request: Some(AuthControlPlaneRequest {
                method: Some(context.method.clone()),
                path: Some(context.path.clone()),
                tool,
                action: Some(action.clone()),
            }),
            token: Some(AuthControlPlaneToken {
                mode: context.auth.as_ref().map(|_| self.token_mode),
                exchange: claims.as_ref().and_then(claim_exchange),
                introspection: claims.as_ref().and_then(claim_introspection),
            }),
            proof: claims.as_ref().map(claim_proof),
            delegation: claims.as_ref().and_then(claim_delegations),
            risk: Some(classify_risk(&context.method, &context.path, &action)),
            observation: observation_for_action(&action),
        }
    }
}

fn token_mode(input: &AuthControlPlaneInput) -> Option<AuthControlPlaneTokenMode> {
    input.token.as_ref().and_then(|token| token.mode)
}

fn principal_id(principal: Option<&AuthControlPlanePrincipal>) -> Option<&str> {
    principal
        .and_then(|value| value.id.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn request_action(input: &AuthControlPlaneInput) -> Option<&str> {
    input
        .request
        .as_ref()
        .and_then(|request| request.action.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn request_method_path(input: &AuthControlPlaneInput) -> Result<(&str, &str), Decision> {
    let request = input
        .request
        .as_ref()
        .ok_or_else(|| Decision::deny(DecisionCode::InvalidInput, Some("request_missing")))?;
    let method = request
        .method
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Decision::deny(DecisionCode::InvalidInput, Some("method_missing")))?;
    let path = request
        .path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Decision::deny(DecisionCode::InvalidInput, Some("path_missing")))?;
    Ok((method, path))
}

fn to_generic_request(input: &AuthControlPlaneInput) -> Result<GenericPolicyRequest, Decision> {
    let (method, path) = request_method_path(input)?;
    let scopes = input
        .scopes
        .clone()
        .ok_or_else(|| Decision::deny(DecisionCode::MissingScopes, Some("scopes_missing")))?;
    let claims = claims_from_control_plane_input(input);
    Ok(GenericPolicyRequest::new(method, path)
        .with_token_scopes(scopes)
        .with_claims(claims))
}

fn claims_from_control_plane_input(input: &AuthControlPlaneInput) -> Map<String, Value> {
    let mut claims = Map::new();
    if let Some(issuer) = input.issuer.as_ref() {
        claims.insert("iss".to_string(), Value::String(issuer.clone()));
    }
    if let Some(audiences) = input.audiences.as_ref() {
        claims.insert("aud".to_string(), audience_value(audiences));
    }
    if let Some(client) = input.client.as_ref() {
        if let Some(client_id) = client.client_id.as_ref() {
            claims.insert("client_id".to_string(), Value::String(client_id.clone()));
        }
        if let Some(azp) = client.azp.as_ref() {
            claims.insert("azp".to_string(), Value::String(azp.clone()));
        }
    }
    if let Some(subject) = input
        .subject
        .as_ref()
        .and_then(|principal| principal.id.as_ref())
    {
        claims.insert("sub".to_string(), Value::String(subject.clone()));
    }
    claims
}

fn audience_value(audiences: &[String]) -> Value {
    if audiences.len() == 1 {
        return Value::String(audiences[0].clone());
    }
    Value::Array(audiences.iter().cloned().map(Value::String).collect())
}

fn validate_session_binding(
    input: &AuthControlPlaneInput,
    subject_id: &str,
    actor_id: &str,
) -> Option<Decision> {
    let resource_project = input
        .resource
        .as_ref()
        .and_then(|resource| resource.project_id.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let session = input.session.as_ref()?;
    if let (Some(resource_project), Some(session_project)) =
        (resource_project, session.project_id.as_deref())
    {
        if session_project.trim() != resource_project {
            return Some(Decision::deny(
                DecisionCode::CapabilityMismatch,
                Some("project_binding_mismatch"),
            ));
        }
    }
    if let Some(bound_subject) = session
        .bound_subject
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if bound_subject != subject_id {
            return Some(Decision::deny(
                DecisionCode::CapabilityMismatch,
                Some("session_subject_mismatch"),
            ));
        }
    }
    if let Some(bound_actor) = session
        .bound_actor
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if bound_actor != actor_id {
            return Some(Decision::deny(
                DecisionCode::CapabilityMismatch,
                Some("session_actor_mismatch"),
            ));
        }
    }
    None
}

fn validate_token_exchange(input: &AuthControlPlaneInput) -> Option<Decision> {
    let exchange = input
        .token
        .as_ref()
        .and_then(|token| token.exchange.as_ref());
    if request_action(input) != Some("token.exchange") {
        if exchange.is_some() {
            return Some(Decision::deny(
                DecisionCode::CapabilityMismatch,
                Some("exchange_not_allowed"),
            ));
        }
        return None;
    }

    let Some(exchange) = exchange else {
        return Some(Decision::deny(
            DecisionCode::CapabilityMissing,
            Some("audit_binding_missing"),
        ));
    };

    if exchange
        .audit_subject
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
        || exchange
            .audit_actor_client
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        || exchange
            .exchange_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        || exchange.das_must_revalidate != Some(true)
    {
        return Some(Decision::deny(
            DecisionCode::CapabilityMissing,
            Some("audit_binding_missing"),
        ));
    }
    None
}

fn validate_sender_constraint(
    input: &AuthControlPlaneInput,
    token_mode: AuthControlPlaneTokenMode,
) -> Option<Decision> {
    if token_mode != AuthControlPlaneTokenMode::SenderConstrained {
        return None;
    }
    let Some(proof) = input.proof.as_ref() else {
        return Some(Decision::deny(
            DecisionCode::InvalidInput,
            Some("sender_constraint"),
        ));
    };
    if proof.sender_constrained == Some(true)
        && (proof.dpop_valid == Some(true) || proof.cnf_thumbprint_match == Some(true))
        && proof.replay_ok != Some(false)
    {
        return None;
    }
    Some(Decision::deny(
        DecisionCode::InvalidInput,
        Some("sender_constraint"),
    ))
}

fn is_health_status_read(input: &AuthControlPlaneInput) -> bool {
    let Ok((method, path)) = request_method_path(input) else {
        return false;
    };
    is_read_method(method) && is_health_or_status_path(path)
}

fn is_read_method(method: &str) -> bool {
    matches!(
        method.trim().to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    )
}

fn is_health_or_status_path(path: &str) -> bool {
    matches!(
        normalize_path(path).as_str(),
        "/health" | "/healthz" | "/ready" | "/readiness" | "/live" | "/liveness" | "/status"
    )
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }
    let mut normalized = String::with_capacity(trimmed.len().max(1));
    if !trimmed.starts_with('/') {
        normalized.push('/');
    }
    let mut previous_was_slash = false;
    for ch in trimmed.chars() {
        if ch == '/' {
            if !previous_was_slash {
                normalized.push('/');
            }
            previous_was_slash = true;
        } else {
            normalized.push(ch);
            previous_was_slash = false;
        }
    }
    if normalized.len() > 1 {
        normalized.trim_end_matches('/').to_string()
    } else {
        normalized
    }
}

fn infer_action(method: &str, path: &str) -> String {
    let normalized = normalize_path(path).to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "/health" | "/healthz" | "/ready" | "/readiness" | "/live" | "/liveness"
    ) {
        return "health.read".to_string();
    }
    if normalized == "/status" {
        return "status.read".to_string();
    }
    if normalized.ends_with("/token/exchange") || normalized.ends_with("/token-exchange") {
        return "token.exchange".to_string();
    }
    if normalized.ends_with("/tools/list")
        || (is_read_method(method) && normalized.ends_with("/tools"))
    {
        return "tool.list".to_string();
    }
    if normalized.ends_with("/tools/call") {
        return "tool.call".to_string();
    }
    if normalized.ends_with("/resources/read") {
        return "resource.read".to_string();
    }
    if normalized.ends_with("/prompts/get") {
        return "prompt.get".to_string();
    }
    if is_read_method(method) {
        "http.read".to_string()
    } else {
        "http.write".to_string()
    }
}

fn infer_tool_from_path(path: &str) -> Option<String> {
    let normalized = normalize_path(path);
    let marker = "/tools/";
    let start = normalized.find(marker)? + marker.len();
    let tail = &normalized[start..];
    let value = tail.split('/').next().map(str::trim)?;
    if matches!(value, "" | "list" | "call") {
        return None;
    }
    Some(value.to_string())
}

fn classify_risk(method: &str, path: &str, action: &str) -> AuthControlPlaneRisk {
    let normalized = normalize_path(path).to_ascii_lowercase();
    let write_action =
        !is_read_method(method) || action == "tool.call" || action == "token.exchange";
    let admin_action = normalized.contains("/admin/")
        || normalized.ends_with("/admin")
        || action == "token.exchange";
    let level = if admin_action {
        "admin"
    } else if write_action {
        "write"
    } else {
        "read"
    };
    AuthControlPlaneRisk {
        level: Some(level.to_string()),
        admin_action: Some(admin_action),
        write_action: Some(write_action),
    }
}

fn observation_for_action(action: &str) -> Option<AuthControlPlaneObservation> {
    match action {
        "health.read" => Some(AuthControlPlaneObservation {
            intent: Some("health".to_string()),
            data_class: Some("service_status".to_string()),
        }),
        "status.read" => Some(AuthControlPlaneObservation {
            intent: Some("status".to_string()),
            data_class: Some("service_status".to_string()),
        }),
        _ => None,
    }
}

fn non_empty_vec(values: Vec<String>) -> Option<Vec<String>> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

fn claim_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn claim_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn claim_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn claim_string_vec(value: &Value, key: &str) -> Option<Vec<String>> {
    let raw = value.get(key)?;
    match raw {
        Value::String(inner) => split_scope_string(inner),
        Value::Array(values) => {
            let strings: Vec<String> = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect();
            if strings.is_empty() {
                None
            } else {
                Some(strings)
            }
        }
        _ => None,
    }
}

fn split_scope_string(value: &str) -> Option<Vec<String>> {
    let scopes: Vec<String> = value
        .split_whitespace()
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    if scopes.is_empty() {
        None
    } else {
        Some(scopes)
    }
}

fn claim_audiences(value: &Value) -> Option<Vec<String>> {
    claim_string_vec(value, "aud")
}

fn claim_exchange(value: &Value) -> Option<AuthControlPlaneExchange> {
    let exchange = value
        .get("token_exchange")
        .or_else(|| value.get("exchange"))?;
    Some(AuthControlPlaneExchange {
        mode: claim_string(exchange, "mode"),
        requester_client: claim_string(exchange, "requester_client"),
        subject_present: claim_bool(exchange, "subject_present"),
        source_audience: claim_string(exchange, "source_audience"),
        requested_audience: claim_string(exchange, "requested_audience"),
        requested_scopes: claim_string_vec(exchange, "requested_scopes"),
        endpoint: claim_string(exchange, "endpoint"),
        sql_key: claim_string(exchange, "sql_key"),
        selected_project_id: claim_string(exchange, "selected_project_id"),
        subject_claim_project_ids: claim_string_vec(exchange, "subject_claim_project_ids"),
        subject_token_kind: claim_string(exchange, "subject_token_kind"),
        requested_token_type: claim_string(exchange, "requested_token_type"),
        proof_profile: claim_string(exchange, "proof_profile"),
        actor_chain_present: claim_bool(exchange, "actor_chain_present"),
        resource_parameter_present: claim_bool(exchange, "resource_parameter_present"),
        refresh_token_requested: claim_bool(exchange, "refresh_token_requested"),
        requested_ttl_seconds: claim_u64(exchange, "requested_ttl_seconds"),
        subject_token_remaining_ttl_seconds: claim_u64(
            exchange,
            "subject_token_remaining_ttl_seconds",
        ),
        max_ttl_seconds: claim_u64(exchange, "max_ttl_seconds"),
        system_fallback_allowed: claim_bool(exchange, "system_fallback_allowed"),
        das_must_revalidate: claim_bool(exchange, "das_must_revalidate"),
        audit_subject: claim_string(exchange, "audit_subject"),
        audit_actor_client: claim_string(exchange, "audit_actor_client"),
        exchange_id: claim_string(exchange, "exchange_id"),
    })
}

fn claim_introspection(value: &Value) -> Option<AuthControlPlaneIntrospection> {
    let introspection = value.get("introspection")?;
    Some(AuthControlPlaneIntrospection {
        active: claim_bool(introspection, "active"),
        cache_state: claim_string(introspection, "cache_state"),
        subject: claim_string(introspection, "subject"),
        actor: claim_string(introspection, "actor"),
        issuer: claim_string(introspection, "issuer"),
        audiences: claim_string_vec(introspection, "audiences"),
        scopes: claim_string_vec(introspection, "scopes"),
        client_id: claim_string(introspection, "client_id"),
        project_id: claim_string(introspection, "project_id"),
        sender_constrained: claim_bool(introspection, "sender_constrained"),
        cnf_thumbprint_match: claim_bool(introspection, "cnf_thumbprint_match"),
        ttl_seconds: claim_u64(introspection, "ttl_seconds"),
    })
}

fn claim_proof(value: &Value) -> AuthControlPlaneProof {
    let proof = value.get("proof").unwrap_or(value);
    AuthControlPlaneProof {
        sender_constrained: claim_bool(proof, "sender_constrained"),
        dpop_valid: claim_bool(proof, "dpop_valid"),
        cnf_thumbprint_match: claim_bool(proof, "cnf_thumbprint_match"),
        replay_ok: claim_bool(proof, "replay_ok"),
    }
}

fn claim_delegations(value: &Value) -> Option<Vec<AuthControlPlaneDelegation>> {
    let raw = value.get("delegation")?;
    let entries = raw.as_array()?;
    let delegations: Vec<AuthControlPlaneDelegation> = entries
        .iter()
        .filter_map(|entry| {
            if !entry.is_object() {
                return None;
            }
            Some(AuthControlPlaneDelegation {
                subject: claim_string(entry, "subject"),
                actor: claim_string(entry, "actor"),
                audience: claim_string(entry, "audience"),
                scopes: claim_string_vec(entry, "scopes"),
                resource: claim_string(entry, "resource"),
                expires_at: claim_string(entry, "expires_at"),
                exchange_id: claim_string(entry, "exchange_id"),
            })
        })
        .collect();
    if delegations.is_empty() {
        None
    } else {
        Some(delegations)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        auth_control_plane_policy_authority, AuthControlPlaneHealthStatusExposure,
        AuthControlPlaneHttpMapper, AuthControlPlaneInput, AuthControlPlanePolicyAuthority,
        AuthControlPlanePrincipal, AuthControlPlaneRequest, AuthControlPlaneSession,
        AuthControlPlaneToken, AuthControlPlaneTokenMode,
        AUTH_CONTROL_PLANE_POLICY_CONTRACT_VERSION,
    };
    use crate::{
        PolicyAuthority, PolicyHttpAuthContext, PolicyHttpRequestContext, PolicyHttpSurfaceContext,
        PolicyRequestMapper, PolicyRuntimeMode,
    };
    use serde_json::json;

    #[test]
    fn http_mapper_projects_sanitized_auth_without_raw_token() {
        let mapper = AuthControlPlaneHttpMapper::default();
        let mapped = mapper.map_request(&http_context(
            "POST",
            "/mcp/tools/call",
            json!({
                "iss": "https://issuer.example",
                "aud": ["mcp://ops"],
                "sub": "subject-1",
                "project_id": "project-7",
                "sid": "session-1",
                "tool": "db.query"
            }),
        ));

        assert_eq!(
            mapped.schema_version.as_deref(),
            Some(AUTH_CONTROL_PLANE_POLICY_CONTRACT_VERSION)
        );
        assert_eq!(
            mapped
                .request
                .as_ref()
                .and_then(|request| request.action.as_deref()),
            Some("tool.call")
        );
        assert_eq!(
            mapped
                .request
                .as_ref()
                .and_then(|request| request.tool.as_deref()),
            Some("db.query")
        );
        assert_eq!(
            mapped
                .resource
                .as_ref()
                .and_then(|resource| resource.project_id.as_deref()),
            Some("project-7")
        );
        assert_eq!(
            mapped
                .session
                .as_ref()
                .and_then(|session| session.session_id.as_deref()),
            Some("session-1")
        );
        assert_eq!(
            mapped.token.as_ref().and_then(|token| token.mode),
            Some(AuthControlPlaneTokenMode::Bearer)
        );
        assert_eq!(
            serde_json::to_value(&mapped)
                .expect("mapped request should serialize")
                .get("raw_token"),
            None
        );
    }

    #[test]
    fn default_authority_allows_scoped_request_with_provenance() {
        let authority = AuthControlPlanePolicyAuthority::builder()
            .expected_issuer("https://issuer.example")
            .expected_audience("mcp://ops")
            .allow_azp("desktop-client")
            .build();
        let request = AuthControlPlaneHttpMapper::default().map_request(&http_context(
            "GET",
            "/tools/list",
            json!({
                "iss": "https://issuer.example",
                "aud": "mcp://ops",
                "sub": "subject-1"
            }),
        ));

        let decision = authority.evaluate(&request);

        assert!(decision.allow);
        assert_eq!(
            decision.policy_contract_version.as_deref(),
            Some(AUTH_CONTROL_PLANE_POLICY_CONTRACT_VERSION)
        );
        assert_eq!(decision.runtime_mode, PolicyRuntimeMode::Rust);
        assert_eq!(decision.required_scopes, Some(vec!["mcp:read".to_string()]));
    }

    #[test]
    fn default_authority_denies_missing_auth_context_fail_closed() {
        let authority = auth_control_plane_policy_authority();
        let request = AuthControlPlaneInput {
            schema_version: Some(AUTH_CONTROL_PLANE_POLICY_CONTRACT_VERSION.to_string()),
            request: Some(AuthControlPlaneRequest {
                method: Some("GET".to_string()),
                path: Some("/tools/list".to_string()),
                tool: None,
                action: Some("tool.list".to_string()),
            }),
            token: Some(AuthControlPlaneToken {
                mode: Some(AuthControlPlaneTokenMode::None),
                exchange: None,
                introspection: None,
            }),
            ..AuthControlPlaneInput::default()
        };

        let decision = authority.evaluate(&request);

        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("MISSING_TOKEN"));
        assert_eq!(decision.reason.as_deref(), Some("token_missing"));
    }

    #[test]
    fn authority_denies_session_subject_mismatch_before_dispatch() {
        let authority = AuthControlPlanePolicyAuthority::default();
        let request = AuthControlPlaneInput {
            schema_version: Some(AUTH_CONTROL_PLANE_POLICY_CONTRACT_VERSION.to_string()),
            subject: Some(AuthControlPlanePrincipal {
                id: Some("subject-a".to_string()),
                ..AuthControlPlanePrincipal::default()
            }),
            actor: Some(AuthControlPlanePrincipal {
                id: Some("actor-a".to_string()),
                ..AuthControlPlanePrincipal::default()
            }),
            scopes: Some(vec!["mcp:read".to_string()]),
            session: Some(AuthControlPlaneSession {
                bound_subject: Some("subject-b".to_string()),
                ..AuthControlPlaneSession::default()
            }),
            request: Some(AuthControlPlaneRequest {
                method: Some("GET".to_string()),
                path: Some("/tools/list".to_string()),
                action: Some("tool.list".to_string()),
                tool: None,
            }),
            token: Some(AuthControlPlaneToken {
                mode: Some(AuthControlPlaneTokenMode::Bearer),
                exchange: None,
                introspection: None,
            }),
            ..AuthControlPlaneInput::default()
        };

        let decision = authority.evaluate(&request);

        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("CAPABILITY_MISMATCH"));
        assert_eq!(decision.reason.as_deref(), Some("session_subject_mismatch"));
    }

    #[test]
    fn authority_denies_exchange_without_audit_binding() {
        let authority = AuthControlPlanePolicyAuthority::default();
        let request = AuthControlPlaneHttpMapper::default().map_request(&http_context(
            "POST",
            "/mcp/token/exchange",
            json!({
                "iss": "https://issuer.example",
                "aud": "mcp://ops",
                "sub": "subject-1",
                "token_exchange": {
                    "requester_client": "ops-mcp",
                    "requested_audience": "mcp://ops-das"
                }
            }),
        ));

        let decision = authority.evaluate(&request);

        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("CAPABILITY_MISSING"));
        assert_eq!(decision.reason.as_deref(), Some("audit_binding_missing"));
    }

    #[test]
    fn authority_denies_exchange_without_exchange_metadata() {
        let authority = AuthControlPlanePolicyAuthority::default();
        let request = AuthControlPlaneHttpMapper::default().map_request(&http_context(
            "POST",
            "/mcp/token/exchange",
            json!({
                "iss": "https://issuer.example",
                "aud": "mcp://ops",
                "sub": "subject-1"
            }),
        ));

        let decision = authority.evaluate(&request);

        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("CAPABILITY_MISSING"));
        assert_eq!(decision.reason.as_deref(), Some("audit_binding_missing"));
    }

    #[test]
    fn public_health_status_exposure_allows_read_without_auth() {
        let authority = AuthControlPlanePolicyAuthority::builder()
            .health_status_exposure(AuthControlPlaneHealthStatusExposure::PublicReadOnly)
            .build();
        let request = AuthControlPlaneInput {
            schema_version: Some(AUTH_CONTROL_PLANE_POLICY_CONTRACT_VERSION.to_string()),
            request: Some(AuthControlPlaneRequest {
                method: Some("GET".to_string()),
                path: Some("/health".to_string()),
                tool: None,
                action: Some("health.read".to_string()),
            }),
            token: Some(AuthControlPlaneToken {
                mode: Some(AuthControlPlaneTokenMode::None),
                exchange: None,
                introspection: None,
            }),
            ..AuthControlPlaneInput::default()
        };

        let decision = authority.evaluate(&request);

        assert!(decision.allow);
    }

    fn http_context(
        method: &str,
        path: &str,
        claims: serde_json::Value,
    ) -> PolicyHttpRequestContext {
        PolicyHttpRequestContext {
            method: method.to_string(),
            path: path.to_string(),
            auth: Some(PolicyHttpAuthContext {
                actor: "alice".to_string(),
                scopes: vec!["mcp:read".to_string(), "mcp:write".to_string()],
                roles: vec!["operator".to_string()],
                azp: Some("desktop-client".to_string()),
                subject: claims
                    .get("sub")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned),
                claims,
            }),
            surface: Some(PolicyHttpSurfaceContext {
                resource_path: "/mcp".to_string(),
                resource_url: "https://example.invalid/mcp".to_string(),
                issuer: "https://issuer.example".to_string(),
            }),
        }
    }
}
