//! # HTTP Policy Gate
//!
//! Request lifecycle integration between the auth surface and policy authorities.
//!
//! ## Ownership
//! This module owns the generic HTTP/Tower gate that evaluates a
//! `PolicyAuthority` after authentication and before request dispatch.
//!
//! ## Non-ownership
//! This module does not authenticate tokens, define domain-specific policy
//! inputs, or own server route logic. Callers provide the mapper that turns an
//! authenticated HTTP request context into the authority request type.
//!
//! ## Policy & Guarantees
//! * **Fail Closed**: Deny decisions are converted to HTTP responses before the
//!   inner service is called.
//! * **Provenance Propagation**: The full `PolicyAuthorityDecision` is attached
//!   to request extensions on allow and response extensions on deny.
//! * **Request Binding**: Consumes a current, single-use auth-surface witness
//!   before policy evaluation. Stale, rebound, or incorrectly ordered requests
//!   fail closed.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying a mapper that preserves each server's route/tool semantics.
//! * Logging only sanitized decision metadata.

use std::{
    future::Future,
    marker::PhantomData,
    sync::Arc,
    task::{Context, Poll},
};

use axum::body::Body;
use futures_util::future::BoxFuture;
use http::{header::CONTENT_TYPE, request::Parts, HeaderValue, Request, Response, StatusCode};
use mcp_toolkit_auth::{
    consume_verified_auth_surface_request, consume_verified_auth_surface_request_from_request,
    surface::AuthSurfaceContext, AuthContext, Authenticator, VerifiedAuthSurfaceRequest,
};
use mcp_toolkit_policy_core::{Decision, DecisionCode};
use serde::Serialize;
use tower::{Layer, Service};

use crate::{PolicyAuthorityDecision, PolicyRuntimeMode, SharedPolicyAuthority};

const APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");
const INVALID_AUTH_SURFACE_REASON: &str = "auth_surface_request_unverified";
const INVALID_AUTH_SURFACE_DECISION_SOURCE: &str = "http_policy.auth_surface";

/// Sanitized authentication context exposed to policy mappers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyHttpAuthContext {
    pub actor: String,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub azp: Option<String>,
    pub subject: Option<String>,
    pub claims: serde_json::Value,
}

impl From<&AuthContext> for PolicyHttpAuthContext {
    fn from(context: &AuthContext) -> Self {
        Self {
            actor: context.actor.clone(),
            scopes: context.scopes.clone(),
            roles: context.roles.clone(),
            azp: context.azp.clone(),
            subject: context.subject.clone(),
            claims: context.claims.clone(),
        }
    }
}

/// Auth-surface route metadata exposed to policy mappers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyHttpSurfaceContext {
    pub resource_path: String,
    pub resource_url: String,
    pub issuer: String,
}

impl From<&AuthSurfaceContext> for PolicyHttpSurfaceContext {
    fn from(context: &AuthSurfaceContext) -> Self {
        Self {
            resource_path: context.resource_path.clone(),
            resource_url: context.resource_url.clone(),
            issuer: context.issuer.clone(),
        }
    }
}

/// HTTP request metadata available when mapping into a policy authority request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyHttpRequestContext {
    pub method: String,
    pub path: String,
    pub auth: Option<PolicyHttpAuthContext>,
    pub surface: Option<PolicyHttpSurfaceContext>,
}

impl PolicyHttpRequestContext {
    /// Consumes a policy request context from HTTP request parts.
    ///
    /// # Errors
    /// * Returns `None` when the request did not pass through the auth surface,
    ///   when its witness no longer matches, or when another policy gate already
    ///   consumed it.
    ///
    /// # Security
    /// * Accepts auth metadata only from the current auth-surface lifecycle.
    ///   Missing, stale, rebound, replayed, or independently issued witnesses
    ///   fail closed as `None`.
    /// * Omits raw bearer tokens from the policy context.
    ///
    /// # Panics
    /// * None.
    pub fn from_parts(parts: &Parts, authenticator: &Authenticator) -> Option<Self> {
        let verified = consume_verified_auth_surface_request(parts, authenticator)?;
        Some(Self::from_verified_request(parts, &verified))
    }

    fn from_verified_request(parts: &Parts, verified: &VerifiedAuthSurfaceRequest) -> Self {
        Self {
            method: parts.method.as_str().to_string(),
            path: parts.uri.path().to_string(),
            auth: verified.auth().map(Into::into),
            surface: verified.surface().map(Into::into),
        }
    }

    /// Consumes a policy request context from an HTTP request.
    ///
    /// # Errors
    /// * Returns `None` when the request did not pass through the auth surface,
    ///   when its witness no longer matches, or when another policy gate already
    ///   consumed it.
    ///
    /// # Security
    /// * Accepts auth metadata only from the current auth-surface lifecycle.
    ///   Missing, stale, rebound, replayed, or independently issued witnesses
    ///   fail closed as `None`.
    /// * Omits raw bearer tokens from the policy context.
    ///
    /// # Panics
    /// * None.
    pub fn from_request<B>(request: &Request<B>, authenticator: &Authenticator) -> Option<Self> {
        Self::consume_from_request(request, authenticator).map(|(context, _)| context)
    }

    fn consume_from_request<B>(
        request: &Request<B>,
        authenticator: &Authenticator,
    ) -> Option<(Self, Option<AuthContext>)> {
        let verified = consume_verified_auth_surface_request_from_request(request, authenticator)?;
        let auth = verified.auth().cloned();
        Some((
            Self {
                method: request.method().as_str().to_string(),
                path: request.uri().path().to_string(),
                auth: verified.auth().map(Into::into),
                surface: verified.surface().map(Into::into),
            },
            auth,
        ))
    }
}

/// Maps an authenticated HTTP context into a domain-specific authority request.
pub trait PolicyRequestMapper<Request>: Clone + Send + Sync + 'static {
    fn map_request(&self, context: &PolicyHttpRequestContext) -> Request;
}

impl<Request, F> PolicyRequestMapper<Request> for F
where
    F: Fn(&PolicyHttpRequestContext) -> Request + Clone + Send + Sync + 'static,
{
    fn map_request(&self, context: &PolicyHttpRequestContext) -> Request {
        self(context)
    }
}

/// Builds the HTTP response returned for a denied policy decision.
pub trait PolicyHttpDenyHandler: Clone + Send + Sync + 'static {
    fn deny_response(&self, decision: &PolicyAuthorityDecision) -> Response<Body>;
}

/// Default JSON deny handler for policy-gated HTTP services.
#[derive(Debug, Clone, Default)]
pub struct JsonPolicyDenyHandler;

#[derive(Debug, Serialize)]
struct JsonPolicyDenyBody<'a> {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    decision_source: &'a str,
    runtime_mode: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_contract_version: Option<&'a str>,
}

impl PolicyHttpDenyHandler for JsonPolicyDenyHandler {
    fn deny_response(&self, decision: &PolicyAuthorityDecision) -> Response<Body> {
        let body = JsonPolicyDenyBody {
            error: "policy_denied",
            code: decision.code.as_deref(),
            reason: decision.reason.as_deref(),
            decision_source: &decision.decision_source,
            runtime_mode: match decision.runtime_mode {
                crate::PolicyRuntimeMode::Rust => "rust",
                crate::PolicyRuntimeMode::SparkPrefer => "spark_prefer",
                crate::PolicyRuntimeMode::SparkRequired => "spark_required",
            },
            policy_contract_version: decision.policy_contract_version.as_deref(),
        };
        let body =
            serde_json::to_vec(&body).unwrap_or_else(|_| b"{\"error\":\"policy_denied\"}".to_vec());
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = StatusCode::FORBIDDEN;
        response
            .headers_mut()
            .insert(CONTENT_TYPE, APPLICATION_JSON);
        response
    }
}

/// Tower layer that evaluates a policy authority before dispatch.
#[derive(Clone)]
pub struct PolicyAuthorityLayer<AuthorityRequest, Mapper, DenyHandler = JsonPolicyDenyHandler> {
    authority: SharedPolicyAuthority<AuthorityRequest>,
    mapper: Mapper,
    deny_handler: DenyHandler,
    authenticator: Arc<Authenticator>,
}

impl<AuthorityRequest, Mapper>
    PolicyAuthorityLayer<AuthorityRequest, Mapper, JsonPolicyDenyHandler>
{
    /// Creates a policy authority layer with the default JSON deny handler.
    ///
    /// # Errors
    /// * This function does not return errors directly.
    ///
    /// # Security
    /// * `authenticator` must be the same shared instance configured on the
    ///   preceding auth surface. Missing or incorrectly bound context reaches
    ///   the mapper as unauthenticated input.
    ///
    /// # Panics
    /// * None.
    pub fn new(
        authority: SharedPolicyAuthority<AuthorityRequest>,
        mapper: Mapper,
        authenticator: Arc<Authenticator>,
    ) -> Self {
        Self::with_deny_handler(authority, mapper, authenticator, JsonPolicyDenyHandler)
    }
}

impl<AuthorityRequest, Mapper, DenyHandler>
    PolicyAuthorityLayer<AuthorityRequest, Mapper, DenyHandler>
{
    /// Creates a policy authority layer with an explicit deny handler.
    ///
    /// # Errors
    /// * This function does not return errors directly.
    ///
    /// # Security
    /// * `authenticator` must be the same shared instance configured on the
    ///   preceding auth surface. Missing or incorrectly bound context reaches
    ///   the mapper as unauthenticated input.
    /// * Deny handlers must not expose raw tokens, claims, or server-internal
    ///   route details in public responses.
    ///
    /// # Panics
    /// * None.
    pub fn with_deny_handler(
        authority: SharedPolicyAuthority<AuthorityRequest>,
        mapper: Mapper,
        authenticator: Arc<Authenticator>,
        deny_handler: DenyHandler,
    ) -> Self {
        Self {
            authority,
            mapper,
            deny_handler,
            authenticator,
        }
    }
}

impl<S, AuthorityRequest, Mapper, DenyHandler> Layer<S>
    for PolicyAuthorityLayer<AuthorityRequest, Mapper, DenyHandler>
where
    Mapper: Clone,
    DenyHandler: Clone,
{
    type Service = PolicyAuthorityService<S, AuthorityRequest, Mapper, DenyHandler>;

    fn layer(&self, inner: S) -> Self::Service {
        PolicyAuthorityService {
            inner,
            authority: self.authority.clone(),
            mapper: self.mapper.clone(),
            deny_handler: self.deny_handler.clone(),
            authenticator: self.authenticator.clone(),
            request_type: PhantomData,
        }
    }
}

/// Service wrapper created by [`PolicyAuthorityLayer`].
pub struct PolicyAuthorityService<S, AuthorityRequest, Mapper, DenyHandler> {
    inner: S,
    authority: SharedPolicyAuthority<AuthorityRequest>,
    mapper: Mapper,
    deny_handler: DenyHandler,
    authenticator: Arc<Authenticator>,
    request_type: PhantomData<fn(AuthorityRequest)>,
}

impl<S, AuthorityRequest, Mapper, DenyHandler> Clone
    for PolicyAuthorityService<S, AuthorityRequest, Mapper, DenyHandler>
where
    S: Clone,
    Mapper: Clone,
    DenyHandler: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            authority: self.authority.clone(),
            mapper: self.mapper.clone(),
            deny_handler: self.deny_handler.clone(),
            authenticator: self.authenticator.clone(),
            request_type: PhantomData,
        }
    }
}

impl<S, AuthorityRequest, Mapper, DenyHandler> Service<Request<Body>>
    for PolicyAuthorityService<S, AuthorityRequest, Mapper, DenyHandler>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    AuthorityRequest: Send + 'static,
    Mapper: PolicyRequestMapper<AuthorityRequest>,
    DenyHandler: PolicyHttpDenyHandler,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response<Body>, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let Some((context, current_auth)) =
            PolicyHttpRequestContext::consume_from_request(&request, &self.authenticator)
        else {
            let decision = invalid_auth_surface_decision();
            let mut response = self.deny_handler.deny_response(&decision);
            response.extensions_mut().insert(decision);
            return Box::pin(async move { Ok(response) });
        };
        let authority_request = self.mapper.map_request(&context);
        let decision = self.authority.evaluate(&authority_request);

        if decision.allow {
            match current_auth {
                Some(auth) => {
                    request.extensions_mut().insert(auth);
                }
                None => {
                    let _ = request.extensions_mut().remove::<AuthContext>();
                }
            }
            request.extensions_mut().insert(decision);
            let future = self.inner.call(request);
            return boxed(future);
        }

        let mut response = self.deny_handler.deny_response(&decision);
        response.extensions_mut().insert(decision);
        Box::pin(async move { Ok(response) })
    }
}

fn invalid_auth_surface_decision() -> PolicyAuthorityDecision {
    PolicyAuthorityDecision::from_policy_decision(
        Decision::deny(
            DecisionCode::InvalidInput,
            Some(INVALID_AUTH_SURFACE_REASON),
        ),
        INVALID_AUTH_SURFACE_DECISION_SOURCE,
        PolicyRuntimeMode::Rust,
        None,
    )
}

fn boxed<F, E>(future: F) -> BoxFuture<'static, Result<Response<Body>, E>>
where
    F: Future<Output = Result<Response<Body>, E>> + Send + 'static,
{
    Box::pin(future)
}

/// Retrieves a reference to a policy authority decision from request extensions.
pub fn policy_authority_decision_ref_from_parts(parts: &Parts) -> Option<&PolicyAuthorityDecision> {
    parts.extensions.get::<PolicyAuthorityDecision>()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        convert::Infallible,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use axum::body::Body;
    use http::{header::AUTHORIZATION, Extensions, HeaderMap, Request, Response, StatusCode};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use mcp_toolkit_auth::{
        surface::{
            AuthSurfaceConfig, AuthSurfaceContext, AuthSurfaceLayer, IssuerEntry, RootAliasPolicy,
        },
        AuthConfig, AuthMode, Authenticator, VerifiedAuthContext,
    };
    use mcp_toolkit_policy_core::{Decision, DecisionCode};
    use tower::{service_fn, Layer, ServiceExt};

    use super::{PolicyAuthorityLayer, PolicyHttpRequestContext};
    use crate::{
        AuthControlPlaneHealthStatusExposure, AuthControlPlaneHttpMapper,
        AuthControlPlanePolicyAuthority, ClosurePolicyAuthority, PolicyRuntimeMode,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MappedRequest {
        method: String,
        path: String,
        actor: Option<String>,
        resource_path: Option<String>,
    }

    #[tokio::test]
    async fn allow_attaches_policy_decision_to_request_before_dispatch() {
        let authenticator = test_authenticator();
        let authority = Arc::new(ClosurePolicyAuthority::new(
            "unit.policy",
            PolicyRuntimeMode::Rust,
            None,
            |request: &MappedRequest| {
                if request.actor.as_deref() == Some("alice") {
                    Decision::allow()
                } else {
                    Decision::deny(DecisionCode::MissingToken, Some("missing_auth"))
                }
            },
        ));
        let saw_decision = Arc::new(AtomicBool::new(false));
        let saw_decision_for_service = saw_decision.clone();
        let inner = service_fn(move |request: Request<Body>| {
            saw_decision_for_service.store(
                request
                    .extensions()
                    .get::<crate::PolicyAuthorityDecision>()
                    .is_some(),
                Ordering::SeqCst,
            );
            async move { Ok::<_, Infallible>(Response::new(Body::from("ok"))) }
        });
        let policy =
            PolicyAuthorityLayer::new(authority, mapper, authenticator.clone()).layer(inner);
        let service = test_auth_surface(authenticator).layer(policy);
        let token = delegation_token("alice", "allow-decision");

        let response = service
            .oneshot(request_with_bearer("/mcp", &token))
            .await
            .expect("policy allow should dispatch");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(saw_decision.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn deny_blocks_dispatch_and_attaches_policy_decision_to_response() {
        let authenticator = test_authenticator();
        let authority = Arc::new(ClosurePolicyAuthority::new(
            "unit.policy",
            PolicyRuntimeMode::Rust,
            Some("unit/v1"),
            |request: &MappedRequest| {
                if request.path == "/mcp/blocked" {
                    Decision::deny(DecisionCode::MissingScopes, Some("required_scope_missing"))
                } else {
                    Decision::allow()
                }
            },
        ));
        let called_inner = Arc::new(AtomicBool::new(false));
        let called_inner_for_service = called_inner.clone();
        let inner = service_fn(move |_request: Request<Body>| {
            called_inner_for_service.store(true, Ordering::SeqCst);
            async move { Ok::<_, Infallible>(Response::new(Body::from("ok"))) }
        });
        let policy =
            PolicyAuthorityLayer::new(authority, mapper, authenticator.clone()).layer(inner);
        let service = test_auth_surface(authenticator).layer(policy);
        let token = delegation_token("alice", "deny-decision");

        let response = service
            .oneshot(request_with_bearer("/mcp/blocked", &token))
            .await
            .expect("policy deny should produce response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!called_inner.load(Ordering::SeqCst));
        let decision = response
            .extensions()
            .get::<crate::PolicyAuthorityDecision>()
            .expect("deny response should carry decision provenance");
        assert_eq!(decision.code.as_deref(), Some("MISSING_SCOPES"));
        assert_eq!(decision.policy_contract_version.as_deref(), Some("unit/v1"));
        assert_eq!(decision.decision_source, "unit.policy");
    }

    #[tokio::test]
    async fn auth_surface_witness_reaches_policy_gated_protected_route() {
        let authenticator = test_authenticator();
        let authority = Arc::new(ClosurePolicyAuthority::new(
            "unit.policy",
            PolicyRuntimeMode::Rust,
            None,
            |request: &MappedRequest| {
                if request.actor.as_deref() == Some("alice") {
                    Decision::allow()
                } else {
                    Decision::deny(DecisionCode::MissingToken, Some("missing_auth"))
                }
            },
        ));
        let saw_expected_witness = Arc::new(AtomicBool::new(false));
        let saw_expected_witness_for_service = saw_expected_witness.clone();
        let authenticator_for_service = authenticator.clone();
        let inner = service_fn(move |request: Request<Body>| {
            let expected_witness = request
                .extensions()
                .get::<VerifiedAuthContext>()
                .is_some_and(|context| context.is_issued_by(&authenticator_for_service));
            let has_policy_decision = request
                .extensions()
                .get::<crate::PolicyAuthorityDecision>()
                .is_some();
            saw_expected_witness_for_service
                .store(expected_witness && has_policy_decision, Ordering::SeqCst);
            async move { Ok::<_, Infallible>(Response::new(Body::from("ok"))) }
        });
        let policy =
            PolicyAuthorityLayer::new(authority, mapper, authenticator.clone()).layer(inner);
        let service = test_auth_surface(authenticator).layer(policy);
        let token = delegation_token("alice", "surface-policy-ingress");

        let response = service
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("protected request should build"),
            )
            .await
            .expect("authenticated policy request should dispatch");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(saw_expected_witness.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn intended_order_replaces_stale_privileged_witness_with_current_identity() {
        let authenticator = test_authenticator();
        let stale_extensions = capture_completed_auth_surface_extensions(
            authenticator.clone(),
            "/mcp",
            &delegation_token("alice", "stale-privileged-intended"),
        )
        .await;
        let authority = Arc::new(ClosurePolicyAuthority::new(
            "unit.policy",
            PolicyRuntimeMode::Rust,
            None,
            |request: &MappedRequest| {
                if request.actor.as_deref() == Some("alice") {
                    Decision::allow()
                } else {
                    Decision::deny(
                        DecisionCode::MissingScopes,
                        Some("current_identity_not_allowed"),
                    )
                }
            },
        ));
        let called_inner = Arc::new(AtomicBool::new(false));
        let called_inner_for_service = called_inner.clone();
        let inner = service_fn(move |_request: Request<Body>| {
            called_inner_for_service.store(true, Ordering::SeqCst);
            async move { Ok::<_, Infallible>(Response::new(Body::from("unexpected"))) }
        });
        let policy =
            PolicyAuthorityLayer::new(authority, mapper, authenticator.clone()).layer(inner);
        let service = test_auth_surface(authenticator).layer(policy);
        let lower_token = delegation_token("bob", "current-lower-intended");
        let mut request = request_with_bearer("/mcp", &lower_token);
        *request.extensions_mut() = stale_extensions;

        let response = service
            .oneshot(request)
            .await
            .expect("current lower-privilege identity should be evaluated");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let decision = response
            .extensions()
            .get::<crate::PolicyAuthorityDecision>()
            .expect("policy denial should carry provenance");
        assert_eq!(decision.code.as_deref(), Some("MISSING_SCOPES"));
        assert_eq!(
            decision.reason.as_deref(),
            Some("current_identity_not_allowed")
        );
        assert_eq!(decision.decision_source, "unit.policy");
        assert!(!called_inner.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn policy_gate_rejects_current_request_token_rebinding_after_authentication() {
        let authenticator = test_authenticator();
        let authority = Arc::new(ClosurePolicyAuthority::new(
            "unit.policy",
            PolicyRuntimeMode::Rust,
            None,
            |_request: &MappedRequest| Decision::allow(),
        ));
        let called_inner = Arc::new(AtomicBool::new(false));
        let called_inner_for_service = called_inner.clone();
        let application = service_fn(move |_request: Request<Body>| {
            called_inner_for_service.store(true, Ordering::SeqCst);
            async move { Ok::<_, Infallible>(Response::new(Body::from("unexpected"))) }
        });
        let policy =
            PolicyAuthorityLayer::new(authority, mapper, authenticator.clone()).layer(application);
        let lower_header: http::HeaderValue = format!(
            "Bearer {}",
            delegation_token("bob", "lower-token-after-auth")
        )
        .parse()
        .expect("lower-privilege authorization header should build");
        let tamper = service_fn(move |mut request: Request<Body>| {
            request
                .headers_mut()
                .insert(AUTHORIZATION, lower_header.clone());
            let policy = policy.clone();
            async move { policy.oneshot(request).await }
        });
        let service = test_auth_surface(authenticator).layer(tamper);
        let privileged_token = delegation_token("alice", "privileged-before-token-rebind");

        let response = service
            .oneshot(request_with_bearer("/mcp", &privileged_token))
            .await
            .expect("token-rebound request should return a closed denial");

        assert_invalid_auth_surface_denial(&response);
        assert!(!called_inner.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn policy_gate_rejects_current_request_route_rebinding_after_authentication() {
        let authenticator = test_authenticator();
        let authority = Arc::new(ClosurePolicyAuthority::new(
            "unit.policy",
            PolicyRuntimeMode::Rust,
            None,
            |_request: &MappedRequest| Decision::allow(),
        ));
        let called_inner = Arc::new(AtomicBool::new(false));
        let called_inner_for_service = called_inner.clone();
        let application = service_fn(move |_request: Request<Body>| {
            called_inner_for_service.store(true, Ordering::SeqCst);
            async move { Ok::<_, Infallible>(Response::new(Body::from("unexpected"))) }
        });
        let policy =
            PolicyAuthorityLayer::new(authority, mapper, authenticator.clone()).layer(application);
        let tamper = service_fn(move |mut request: Request<Body>| {
            *request.uri_mut() = "/mcp/admin"
                .parse()
                .expect("rebound protected route should parse");
            let policy = policy.clone();
            async move { policy.oneshot(request).await }
        });
        let service = test_auth_surface(authenticator).layer(tamper);
        let token = delegation_token("alice", "privileged-before-route-rebind");

        let response = service
            .oneshot(request_with_bearer("/mcp", &token))
            .await
            .expect("route-rebound request should return a closed denial");

        assert_invalid_auth_surface_denial(&response);
        assert!(!called_inner.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn reversed_order_fails_closed_for_stale_witness_and_current_identity() {
        let authenticator = test_authenticator();
        let stale_extensions = capture_completed_auth_surface_extensions(
            authenticator.clone(),
            "/mcp",
            &delegation_token("alice", "stale-privileged-reversed"),
        )
        .await;
        let authority = Arc::new(ClosurePolicyAuthority::new(
            "unit.policy",
            PolicyRuntimeMode::Rust,
            None,
            |request: &MappedRequest| {
                if request.actor.as_deref() == Some("alice") {
                    Decision::allow()
                } else {
                    Decision::deny(DecisionCode::MissingToken, Some("missing_auth"))
                }
            },
        ));
        let called_inner = Arc::new(AtomicBool::new(false));
        let called_inner_for_service = called_inner.clone();
        let application = service_fn(move |_request: Request<Body>| {
            called_inner_for_service.store(true, Ordering::SeqCst);
            async move { Ok::<_, Infallible>(Response::new(Body::from("unexpected"))) }
        });
        let auth_inner = test_auth_surface(authenticator.clone()).layer(application);
        let service = PolicyAuthorityLayer::new(authority, mapper, authenticator).layer(auth_inner);
        let lower_token = delegation_token("bob", "current-lower-reversed");
        let mut request = request_with_bearer("/mcp", &lower_token);
        *request.extensions_mut() = stale_extensions;

        let response = service
            .oneshot(request)
            .await
            .expect("unsafe layer order should return a closed denial");

        assert_invalid_auth_surface_denial(&response);
        assert!(!called_inner.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn completed_request_witness_cannot_be_replayed_on_same_route_and_token() {
        let authenticator = test_authenticator();
        let token = delegation_token("alice", "completed-request-replay");
        let stale_extensions =
            capture_completed_auth_surface_extensions(authenticator.clone(), "/mcp", &token).await;
        let authority = Arc::new(ClosurePolicyAuthority::new(
            "unit.policy",
            PolicyRuntimeMode::Rust,
            None,
            |_request: &MappedRequest| Decision::allow(),
        ));
        let called_inner = Arc::new(AtomicBool::new(false));
        let called_inner_for_service = called_inner.clone();
        let service = PolicyAuthorityLayer::new(authority, mapper, authenticator).layer(
            service_fn(move |_request: Request<Body>| {
                called_inner_for_service.store(true, Ordering::SeqCst);
                async move { Ok::<_, Infallible>(Response::new(Body::from("unexpected"))) }
            }),
        );
        let mut request = request_with_bearer("/mcp", &token);
        *request.extensions_mut() = stale_extensions;

        let response = service
            .oneshot(request)
            .await
            .expect("completed request witness should be rejected");

        assert_invalid_auth_surface_denial(&response);
        assert!(!called_inner.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn policy_gate_denies_stripped_and_foreign_authentication_contexts() {
        let authenticator = test_authenticator();
        let foreign_authenticator = test_authenticator();
        let foreign_token = delegation_token("alice", "foreign-context");
        let foreign_context = foreign_authenticator
            .authenticate_token(&HeaderMap::new(), &foreign_token)
            .await
            .expect("independent authenticator should issue its own witness");
        let authority = Arc::new(ClosurePolicyAuthority::new(
            "unit.policy",
            PolicyRuntimeMode::Rust,
            None,
            |_request: &MappedRequest| Decision::allow(),
        ));
        let service = PolicyAuthorityLayer::new(authority, mapper, authenticator).layer(
            service_fn(|_request: Request<Body>| async {
                Ok::<_, Infallible>(Response::new(Body::from("unexpected")))
            }),
        );
        let mut request = request_with_bearer("/mcp", &foreign_token);
        request
            .extensions_mut()
            .insert(foreign_context.context().clone());
        request.extensions_mut().insert(foreign_context);
        insert_surface_context(&mut request);

        let response = service
            .oneshot(request)
            .await
            .expect("unbound foreign witness should produce a denial");

        assert_invalid_auth_surface_denial(&response);
    }

    #[tokio::test]
    async fn policy_gate_preserves_explicit_public_read_only_routes_without_authentication() {
        let authenticator = test_authenticator();
        let stale_extensions = capture_completed_auth_surface_extensions(
            authenticator.clone(),
            "/mcp",
            &delegation_token("alice", "stale-public-route"),
        )
        .await;
        let authority = AuthControlPlanePolicyAuthority::builder()
            .health_status_exposure(AuthControlPlaneHealthStatusExposure::PublicReadOnly)
            .build()
            .shared();
        let policy = PolicyAuthorityLayer::new(
            authority,
            AuthControlPlaneHttpMapper::default(),
            authenticator.clone(),
        )
        .layer(service_fn(|request: Request<Body>| async move {
            assert!(
                request.extensions().get::<VerifiedAuthContext>().is_none(),
                "public route must not retain an authenticated witness"
            );
            assert!(
                request
                    .extensions()
                    .get::<mcp_toolkit_auth::AuthContext>()
                    .is_none(),
                "public route must not retain a bare auth context"
            );
            Ok::<_, Infallible>(Response::new(Body::from("ok")))
        }));
        let service = test_auth_surface_with_public_health(authenticator).layer(policy);
        let mut request = Request::builder()
            .method("GET")
            .uri("/health")
            .body(Body::empty())
            .expect("public read-only request should build");
        *request.extensions_mut() = stale_extensions;

        let response = service
            .oneshot(request)
            .await
            .expect("explicit public read-only policy should dispatch");

        assert_eq!(response.status(), StatusCode::OK);
    }

    fn mapper(context: &PolicyHttpRequestContext) -> MappedRequest {
        MappedRequest {
            method: context.method.clone(),
            path: context.path.clone(),
            actor: context.auth.as_ref().map(|auth| auth.actor.clone()),
            resource_path: context
                .surface
                .as_ref()
                .map(|surface| surface.resource_path.clone()),
        }
    }

    fn test_authenticator() -> Arc<Authenticator> {
        Arc::new(
            Authenticator::new(AuthConfig {
                mode: AuthMode::Delegation,
                delegation_secret: Some("policy-test-secret".to_string()),
                delegation_issuer: "https://issuer.example".to_string(),
                delegation_audience: "mcp://service.example".to_string(),
                ..AuthConfig::default()
            })
            .expect("test authenticator should build"),
        )
    }

    fn test_auth_surface(authenticator: Arc<Authenticator>) -> AuthSurfaceLayer {
        test_auth_surface_with_public_paths(authenticator, HashSet::new())
    }

    fn test_auth_surface_with_public_health(authenticator: Arc<Authenticator>) -> AuthSurfaceLayer {
        test_auth_surface_with_public_paths(authenticator, HashSet::from(["/health".to_string()]))
    }

    fn test_auth_surface_with_public_paths(
        authenticator: Arc<Authenticator>,
        public_paths: HashSet<String>,
    ) -> AuthSurfaceLayer {
        AuthSurfaceLayer::from_config(AuthSurfaceConfig {
            public_base_url: "https://service.example".to_string(),
            entries: vec![IssuerEntry {
                resource_path: "/mcp".to_string(),
                issuer: "https://issuer.example".to_string(),
                authorization_endpoint: "https://issuer.example/authorize".to_string(),
                token_endpoint: "https://issuer.example/token".to_string(),
                registration_endpoint: None,
                jwks_uri: None,
                introspection_endpoint: None,
                device_authorization_endpoint: None,
                grant_types_supported: None,
                client_id_metadata_document_supported: None,
                token_endpoint_auth_methods_supported: None,
                code_challenge_methods_supported: None,
                realm: "policy-test".to_string(),
                scopes_supported: vec!["tools:read".to_string()],
                allowed_client_ids: HashSet::new(),
                authenticator,
                resource_url_override: Some("https://service.example/mcp".to_string()),
            }],
            root_alias_policy: RootAliasPolicy::Disabled,
            public_paths,
            public_prefixes: Vec::new(),
            allow_insecure_http: false,
        })
        .expect("test auth surface should build")
    }

    fn delegation_token(actor: &str, jti: &str) -> String {
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time should follow epoch")
            .as_secs()
            + 300;
        encode(
            &Header::default(),
            &serde_json::json!({
                "exp": expiration,
                "sub": actor,
                "aud": "mcp://service.example",
                "iss": "https://issuer.example",
                "jti": jti,
                "scope": "tools:read",
            }),
            &EncodingKey::from_secret(b"policy-test-secret"),
        )
        .expect("test token should encode")
    }

    async fn capture_completed_auth_surface_extensions(
        authenticator: Arc<Authenticator>,
        path: &str,
        token: &str,
    ) -> Extensions {
        let captured = Arc::new(Mutex::new(None));
        let captured_for_service = captured.clone();
        let service =
            test_auth_surface(authenticator).layer(service_fn(move |request: Request<Body>| {
                let extensions = request.extensions().clone();
                let mut slot = captured_for_service
                    .lock()
                    .expect("captured request mutex should not be poisoned");
                *slot = Some(extensions);
                drop(slot);
                async move { Ok::<_, Infallible>(Response::new(Body::from("captured"))) }
            }));

        let response = service
            .oneshot(request_with_bearer(path, token))
            .await
            .expect("auth surface should process capture request");
        assert_eq!(response.status(), StatusCode::OK);

        let extensions = captured
            .lock()
            .expect("captured request mutex should not be poisoned")
            .take()
            .expect("auth surface should expose request extensions to its inner service");
        extensions
    }

    fn request_with_bearer(path: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("test request should build")
    }

    fn insert_surface_context(request: &mut Request<Body>) {
        request.extensions_mut().insert(AuthSurfaceContext {
            resource_path: "/mcp".to_string(),
            resource_url: "https://service.example/mcp".to_string(),
            issuer: "https://issuer.example".to_string(),
        });
    }

    fn assert_invalid_auth_surface_denial(response: &Response<Body>) {
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let decision = response
            .extensions()
            .get::<crate::PolicyAuthorityDecision>()
            .expect("denial should carry decision provenance");
        assert_eq!(decision.code.as_deref(), Some("INVALID_INPUT"));
        assert_eq!(
            decision.reason.as_deref(),
            Some("auth_surface_request_unverified")
        );
        assert_eq!(decision.decision_source, "http_policy.auth_surface");
    }
}
