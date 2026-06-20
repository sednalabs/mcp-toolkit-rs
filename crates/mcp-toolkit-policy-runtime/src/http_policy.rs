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
//! * **Auth Separation**: Reads `AuthContext` and `AuthSurfaceContext` inserted
//!   by `mcp-toolkit-auth`; it does not validate credentials itself.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Installing this layer after `AuthSurfaceLayer` for protected routes.
//! * Supplying a mapper that preserves each server's route/tool semantics.
//! * Logging only sanitized decision metadata.

use std::{
    future::Future,
    marker::PhantomData,
    task::{Context, Poll},
};

use axum::body::Body;
use futures_util::future::BoxFuture;
use http::{header::CONTENT_TYPE, request::Parts, HeaderValue, Request, Response, StatusCode};
use mcp_toolkit_auth::{surface::AuthSurfaceContext, AuthContext};
use serde::Serialize;
use tower::{Layer, Service};

use crate::{PolicyAuthorityDecision, SharedPolicyAuthority};

const APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");

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
    /// Builds a policy request context from HTTP request parts.
    ///
    /// # Errors
    /// * This function does not return errors directly.
    ///
    /// # Security
    /// * Copies sanitized auth metadata and intentionally omits raw bearer
    ///   tokens from the policy mapping context.
    ///
    /// # Panics
    /// * None.
    pub fn from_parts(parts: &Parts) -> Self {
        Self {
            method: parts.method.as_str().to_string(),
            path: parts.uri.path().to_string(),
            auth: parts.extensions.get::<AuthContext>().map(Into::into),
            surface: parts.extensions.get::<AuthSurfaceContext>().map(Into::into),
        }
    }

    /// Builds a policy request context from an HTTP request.
    ///
    /// # Errors
    /// * This function does not return errors directly.
    ///
    /// # Security
    /// * Copies sanitized auth metadata and intentionally omits raw bearer
    ///   tokens from the policy mapping context.
    ///
    /// # Panics
    /// * None.
    pub fn from_request<B>(request: &Request<B>) -> Self {
        Self {
            method: request.method().as_str().to_string(),
            path: request.uri().path().to_string(),
            auth: request.extensions().get::<AuthContext>().map(Into::into),
            surface: request
                .extensions()
                .get::<AuthSurfaceContext>()
                .map(Into::into),
        }
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
    /// * The layer must run after authentication for protected routes so the
    ///   mapper receives a trusted `AuthContext`.
    ///
    /// # Panics
    /// * None.
    pub fn new(authority: SharedPolicyAuthority<AuthorityRequest>, mapper: Mapper) -> Self {
        Self::with_deny_handler(authority, mapper, JsonPolicyDenyHandler)
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
    /// * Deny handlers must not expose raw tokens, claims, or server-internal
    ///   route details in public responses.
    ///
    /// # Panics
    /// * None.
    pub fn with_deny_handler(
        authority: SharedPolicyAuthority<AuthorityRequest>,
        mapper: Mapper,
        deny_handler: DenyHandler,
    ) -> Self {
        Self {
            authority,
            mapper,
            deny_handler,
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
        let context = PolicyHttpRequestContext::from_request(&request);
        let authority_request = self.mapper.map_request(&context);
        let decision = self.authority.evaluate(&authority_request);

        if decision.allow {
            request.extensions_mut().insert(decision);
            let mut inner = self.inner.clone();
            let future = inner.call(request);
            return boxed(future);
        }

        let mut response = self.deny_handler.deny_response(&decision);
        response.extensions_mut().insert(decision);
        Box::pin(async move { Ok(response) })
    }
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
        convert::Infallible,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    use axum::body::Body;
    use http::{Request, Response, StatusCode};
    use mcp_toolkit_auth::{surface::AuthSurfaceContext, AuthContext};
    use mcp_toolkit_policy_core::{Decision, DecisionCode};
    use tower::{service_fn, Layer, ServiceExt};

    use super::{PolicyAuthorityLayer, PolicyHttpRequestContext};
    use crate::{ClosurePolicyAuthority, PolicyRuntimeMode};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MappedRequest {
        method: String,
        path: String,
        actor: Option<String>,
        resource_path: Option<String>,
    }

    #[tokio::test]
    async fn allow_attaches_policy_decision_to_request_before_dispatch() {
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
        let layer = PolicyAuthorityLayer::new(authority, mapper);
        let service = layer.layer(service_fn(move |request: Request<Body>| {
            saw_decision_for_service.store(
                request
                    .extensions()
                    .get::<crate::PolicyAuthorityDecision>()
                    .is_some(),
                Ordering::SeqCst,
            );
            async move { Ok::<_, Infallible>(Response::new(Body::from("ok"))) }
        }));

        let response = service
            .oneshot(request_with_auth("/mcp", "alice"))
            .await
            .expect("policy allow should dispatch");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(saw_decision.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn deny_blocks_dispatch_and_attaches_policy_decision_to_response() {
        let authority = Arc::new(ClosurePolicyAuthority::new(
            "unit.policy",
            PolicyRuntimeMode::Rust,
            Some("unit/v1"),
            |request: &MappedRequest| {
                if request.path == "/blocked" {
                    Decision::deny(DecisionCode::MissingScopes, Some("required_scope_missing"))
                } else {
                    Decision::allow()
                }
            },
        ));
        let called_inner = Arc::new(AtomicBool::new(false));
        let called_inner_for_service = called_inner.clone();
        let layer = PolicyAuthorityLayer::new(authority, mapper);
        let service = layer.layer(service_fn(move |_request: Request<Body>| {
            called_inner_for_service.store(true, Ordering::SeqCst);
            async move { Ok::<_, Infallible>(Response::new(Body::from("ok"))) }
        }));

        let response = service
            .oneshot(request_with_auth("/blocked", "alice"))
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

    fn request_with_auth(path: &str, actor: &str) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .body(Body::empty())
            .expect("test request should build");
        request.extensions_mut().insert(AuthContext {
            actor: actor.to_string(),
            scopes: vec!["tools:read".to_string()],
            roles: Vec::new(),
            claims: serde_json::json!({"sub": actor}),
            azp: Some("client-a".to_string()),
            subject: Some(actor.to_string()),
            token_ref: "token-ref".to_string(),
            raw_token: "raw-token".to_string(),
        });
        request.extensions_mut().insert(AuthSurfaceContext {
            resource_path: "/mcp".to_string(),
            resource_url: "https://example.invalid/mcp".to_string(),
            issuer: "https://issuer.example".to_string(),
        });
        request
    }
}
