//! # Streamable HTTP Server Composition
//!
//! Runtime and route-bundle helpers for local Streamable HTTP MCP servers.
//!
//! ## Rationale
//! HTTP MCP services commonly repeat bind safety checks, bounded session
//! construction, optional stateless fallback, host guarding, health routes, and
//! `/mcp` request routing. This module packages those seams while preserving
//! service-owned state and policy decisions.
//!
//! ## Security Boundaries
//! * Non-loopback bind validation is explicit and requires auth unless callers
//!   intentionally choose a different deployment policy outside this helper.
//! * Host guarding uses `mcp-toolkit-http` allowlist validation.
//! * Domain authorization and tool policy stay in service crates.
//!
//! ## References
//! * **DESIGN**: `docs/server-composition-layer.md`
//! * **HTTP**: `crates/mcp-toolkit-http/src/streamable.rs`

use std::{collections::HashSet, fmt, net::SocketAddr, sync::Arc};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get},
    Json, Router,
};
use http::{header::CONTENT_TYPE, Method, StatusCode};
use mcp_toolkit_http::{
    host::validate_host_header,
    oauth::protected_resource_well_known_paths,
    session::{BoundedSessionManager, RecordingSessionManager, SessionStats},
    streamable::{build_local_streamable_http_service, LocalStreamableHttpServiceConfig},
};
use rmcp::{
    transport::streamable_http_server::{
        SessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
    RoleServer, Service,
};
use serde_json::json;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "auth")]
use crate::auth::AuthSurfaceLayer;

const MCP_SESSION_ID_HEADER: &str = "Mcp-Session-Id";

/// Bind safety policy for hosted HTTP MCP servers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HttpBindSafety {
    /// Allow binding to a non-loopback address.
    pub allow_non_loopback: bool,
    /// True when the exposed HTTP surface has bearer auth enabled.
    pub auth_enabled: bool,
}

impl HttpBindSafety {
    /// Builds a bind-safety policy.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Non-loopback binds are rejected unless `allow_non_loopback` is true, and
    /// non-loopback binds without auth are always rejected by this policy.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(allow_non_loopback: bool, auth_enabled: bool) -> Self {
        Self {
            allow_non_loopback,
            auth_enabled,
        }
    }

    /// Validates a bind address against this safety policy.
    ///
    /// # Errors
    /// Returns `HttpBindSafetyError` when a non-loopback bind is disallowed or
    /// when auth is disabled for a non-loopback bind.
    ///
    /// # Security
    /// This is a fail-closed guard for accidental public exposure.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn validate(self, addr: SocketAddr) -> Result<(), HttpBindSafetyError> {
        if addr.ip().is_loopback() {
            return Ok(());
        }
        if !self.allow_non_loopback {
            return Err(HttpBindSafetyError::NonLoopbackDenied { addr });
        }
        if !self.auth_enabled {
            return Err(HttpBindSafetyError::AuthRequiredForNonLoopback { addr });
        }
        Ok(())
    }
}

/// Bind safety validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpBindSafetyError {
    /// The address is not loopback and the policy does not allow it.
    NonLoopbackDenied { addr: SocketAddr },
    /// The address is not loopback and auth is disabled.
    AuthRequiredForNonLoopback { addr: SocketAddr },
}

impl fmt::Display for HttpBindSafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLoopbackDenied { addr } => {
                write!(f, "non-loopback bind denied for {addr}")
            }
            Self::AuthRequiredForNonLoopback { addr } => {
                write!(f, "auth is required for non-loopback bind {addr}")
            }
        }
    }
}

impl std::error::Error for HttpBindSafetyError {}

/// Builder for a local Streamable HTTP MCP runtime.
#[derive(Debug, Clone, Default)]
pub struct LocalMcpHttpRuntimeBuilder {
    config: LocalStreamableHttpServiceConfig,
    stateless_fallback: bool,
    stateless_server_config: Option<StreamableHttpServerConfig>,
}

impl LocalMcpHttpRuntimeBuilder {
    /// Builds a runtime builder with loopback-friendly defaults.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Defaults come from `mcp-toolkit-http` and remain bounded and
    /// loopback-oriented.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the full low-level Streamable HTTP service configuration.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Callers must preserve safe allowed-host and cancellation-token posture
    /// when replacing the full configuration.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn config(mut self, config: LocalStreamableHttpServiceConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets the maximum number of bounded stateful sessions.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Keep this bound small enough for the deployment's memory budget.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn max_sessions(mut self, max_sessions: usize) -> Self {
        self.config.max_sessions = max_sessions;
        self
    }

    /// Enables or disables resumable sessions.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Resume mode keeps disconnected session state until expiry. Pair it with
    /// appropriate idle timeouts for public services.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn allow_resume(mut self, allow_resume: bool) -> Self {
        self.config.allow_resume = allow_resume;
        self
    }

    /// Replaces the low-level local session configuration.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Session channel capacity and keepalive settings influence memory use and
    /// retention behavior.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn session_config(
        mut self,
        session_config: rmcp::transport::streamable_http_server::session::local::SessionConfig,
    ) -> Self {
        self.config.session_config = session_config;
        self
    }

    /// Replaces the low-level Streamable HTTP server configuration.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Ensure allowed hosts and cancellation behavior match the deployment.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn server_config(mut self, server_config: StreamableHttpServerConfig) -> Self {
        self.config.server_config = server_config;
        self
    }

    /// Sets allowed Host header values on the stateful service.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Host allowlists mitigate DNS rebinding attacks. Do not clear them for
    /// public deployments.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn allowed_hosts(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.config.server_config = self.config.server_config.with_allowed_hosts(hosts);
        self
    }

    /// Sets the cancellation token used by the HTTP runtime.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Use a service-owned token so shutdown tears down session sweepers and
    /// Streamable HTTP workers together.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn cancellation_token(mut self, token: CancellationToken) -> Self {
        self.config.server_config = self.config.server_config.with_cancellation_token(token);
        self
    }

    /// Enables or disables stateless fallback for POST requests that cannot use a session.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Stateless fallback is useful for clients that cannot retain session IDs.
    /// Keep auth and host guards outside or above the route bundle.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn stateless_fallback(mut self, enabled: bool) -> Self {
        self.stateless_fallback = enabled;
        self
    }

    /// Replaces the stateless fallback server configuration.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// The supplied configuration should keep `stateful_mode` disabled unless
    /// the caller intentionally wants two stateful services.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn stateless_server_config(mut self, config: StreamableHttpServerConfig) -> Self {
        self.stateless_server_config = Some(config);
        self
    }

    /// Builds the local Streamable HTTP runtime.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// The service factory must not capture secrets that could be exposed in
    /// debug output. The runtime preserves bounded session behavior from
    /// `mcp-toolkit-http`.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn build<S, F>(self, service_factory: F) -> LocalMcpHttpRuntime<S>
    where
        S: Service<RoleServer> + Send + 'static,
        F: Fn() -> Result<S, std::io::Error> + Clone + Send + Sync + 'static,
    {
        let stateful_config = self.config;
        let allowed_hosts = stateful_config.server_config.allowed_hosts.clone();
        let fallback_config = self.stateless_server_config.unwrap_or_else(|| {
            StreamableHttpServerConfig::default()
                .with_allowed_hosts(allowed_hosts.clone())
                .with_stateful_mode(false)
                .with_sse_retry(None)
                .with_cancellation_token(
                    stateful_config
                        .server_config
                        .cancellation_token
                        .child_token(),
                )
        });
        let stateful_factory = service_factory.clone();
        let stateful = build_local_streamable_http_service(stateful_factory, stateful_config);
        let stateless_service = if self.stateless_fallback {
            let recording_session_manager = Arc::new(RecordingSessionManager::new(
                stateful.session_manager.clone(),
                None,
            ));
            Some(StreamableHttpService::new(
                service_factory,
                recording_session_manager,
                fallback_config,
            ))
        } else {
            None
        };

        LocalMcpHttpRuntime {
            session_manager: stateful.session_manager,
            stateful_service: stateful.service,
            stateless_service,
            allowed_hosts: allowed_hosts.into_iter().collect(),
        }
    }
}

/// Runtime components for a local Streamable HTTP MCP server.
pub struct LocalMcpHttpRuntime<S> {
    /// Bounded session manager shared by the stateful and optional fallback services.
    pub session_manager: Arc<BoundedSessionManager>,
    /// Stateful Streamable HTTP MCP service.
    pub stateful_service: StreamableHttpService<S, RecordingSessionManager>,
    /// Optional stateless fallback service.
    pub stateless_service: Option<StreamableHttpService<S, RecordingSessionManager>>,
    /// Allowed Host header values copied from the stateful server config.
    pub allowed_hosts: HashSet<String>,
}

impl<S> LocalMcpHttpRuntime<S>
where
    S: Service<RoleServer> + Send + 'static,
{
    /// Converts runtime pieces into route state.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// The `auth_enabled` flag controls unauthenticated GET hints only. It does
    /// not install auth middleware; use `AuthSurfaceLayer` for bearer enforcement.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn into_state(self, auth_enabled: bool) -> LocalMcpHttpState<S> {
        LocalMcpHttpState {
            session_manager: self.session_manager,
            stateful_service: self.stateful_service,
            stateless_service: self.stateless_service,
            allowed_hosts: self.allowed_hosts,
            auth_enabled,
        }
    }
}

/// Shared route state for the local MCP HTTP route bundle.
pub struct LocalMcpHttpState<S> {
    /// Bounded session manager used to validate session-bound requests.
    pub session_manager: Arc<BoundedSessionManager>,
    /// Stateful MCP service.
    pub stateful_service: StreamableHttpService<S, RecordingSessionManager>,
    /// Optional stateless fallback service.
    pub stateless_service: Option<StreamableHttpService<S, RecordingSessionManager>>,
    /// Allowed Host header values for the route-bundle host guard.
    pub allowed_hosts: HashSet<String>,
    /// True when bearer authentication is active above the route bundle.
    pub auth_enabled: bool,
}

impl<S> Clone for LocalMcpHttpState<S> {
    fn clone(&self) -> Self {
        Self {
            session_manager: self.session_manager.clone(),
            stateful_service: self.stateful_service.clone(),
            stateless_service: self.stateless_service.clone(),
            allowed_hosts: self.allowed_hosts.clone(),
            auth_enabled: self.auth_enabled,
        }
    }
}

/// Builder for a local MCP HTTP route bundle.
pub struct LocalMcpHttpRouterBuilder<S> {
    state: LocalMcpHttpState<S>,
    include_health: bool,
    include_host_guard: bool,
    include_oauth_not_configured: bool,
    mcp_path: String,
    resource_path: String,
    #[cfg(feature = "auth")]
    auth_layer: Option<AuthSurfaceLayer>,
}

impl<S> LocalMcpHttpRouterBuilder<S>
where
    S: Service<RoleServer> + Send + 'static,
{
    /// Builds a route-bundle builder from route state.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// The default bundle includes host guarding and a generic health route.
    /// Auth middleware must be supplied separately when serving non-loopback.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(state: LocalMcpHttpState<S>) -> Self {
        Self {
            state,
            include_health: true,
            include_host_guard: true,
            include_oauth_not_configured: false,
            mcp_path: "/mcp".to_string(),
            resource_path: "/mcp".to_string(),
            #[cfg(feature = "auth")]
            auth_layer: None,
        }
    }

    /// Enables or disables the built-in health route.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// The built-in health payload includes only transport/session posture and
    /// no service-specific secrets.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn include_health(mut self, include: bool) -> Self {
        self.include_health = include;
        self
    }

    /// Enables or disables the route-bundle host guard.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Disabling the host guard is not recommended for public deployments.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn include_host_guard(mut self, include: bool) -> Self {
        self.include_host_guard = include;
        self
    }

    /// Enables unauthenticated OAuth protected-resource placeholder routes.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Placeholder routes reveal only that OAuth metadata is not configured for
    /// the local route bundle. Authenticated deployments should prefer a real
    /// `AuthSurfaceLayer`.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn include_oauth_not_configured(mut self, include: bool) -> Self {
        self.include_oauth_not_configured = include;
        self
    }

    /// Sets the MCP route path.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// The path should be the same protected resource path used by auth
    /// metadata when auth is enabled.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn mcp_path(mut self, path: impl Into<String>) -> Self {
        self.mcp_path = normalize_route_path(&path.into());
        self.resource_path = self.mcp_path.clone();
        self
    }

    /// Sets the protected resource path used for placeholder discovery routes.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Keep this aligned with the MCP resource path exposed to clients.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn resource_path(mut self, path: impl Into<String>) -> Self {
        self.resource_path = normalize_route_path(&path.into());
        self
    }

    /// Installs an auth layer around the route bundle.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// The supplied layer must be built from issuer metadata that matches the
    /// public resource URL for this route bundle.
    ///
    /// # Panics
    /// This function does not panic.
    #[cfg(feature = "auth")]
    pub fn auth_layer(mut self, layer: AuthSurfaceLayer) -> Self {
        self.auth_layer = Some(layer);
        self
    }

    /// Builds the route bundle.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Host guarding is enabled by default. Auth is installed only when
    /// `auth_layer` is supplied.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn build(self) -> Router {
        let state = self.state;
        let mut router = Router::new().route(&self.mcp_path, any(handle_mcp::<S>));
        let slash_path = format!("{}/", self.mcp_path.trim_end_matches('/'));
        if slash_path != self.mcp_path {
            router = router.route(&slash_path, any(handle_mcp::<S>));
        }
        if self.include_health {
            router = router.route("/health", get(health::<S>));
        }
        if self.include_oauth_not_configured {
            for path in protected_resource_well_known_paths(&self.resource_path) {
                router = router.route(&path, get(oauth_protected_resource_not_configured));
            }
        }
        if self.include_host_guard {
            router = router.layer(middleware::from_fn_with_state(
                state.clone(),
                host_guard::<S>,
            ));
        }
        #[cfg(feature = "auth")]
        {
            if let Some(layer) = self.auth_layer {
                router = router.layer(layer);
            }
        }
        router.with_state(state)
    }
}

/// Handles a Streamable HTTP MCP request with stateful sessions and optional stateless fallback.
///
/// # Errors
/// This function does not return errors; protocol failures are encoded as HTTP
/// responses.
///
/// # Security
/// Apply host and auth middleware before this handler for exposed deployments.
///
/// # Panics
/// This function does not panic.
pub async fn handle_mcp<S>(State(state): State<LocalMcpHttpState<S>>, req: Request) -> Response
where
    S: Service<RoleServer> + Send + 'static,
{
    let method = req.method().clone();
    let session_id = session_id_from_headers(req.headers());

    match method {
        Method::POST => handle_post(state, req, session_id).await,
        Method::GET | Method::DELETE => handle_stateful_read(state, req, session_id, method).await,
        _ => session_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not allowed.",
            "Use POST /mcp to initialize, then reuse the session id for later requests.",
        ),
    }
}

async fn handle_post<S>(
    state: LocalMcpHttpState<S>,
    req: Request,
    session_id: Option<String>,
) -> Response
where
    S: Service<RoleServer> + Send + 'static,
{
    if let Some(session_id) = session_id {
        if session_exists(&state.session_manager, &session_id).await {
            return forward_service(state.stateful_service, req).await;
        }
        if let Some(stateless) = state.stateless_service {
            return forward_service(stateless, req).await;
        }
        return session_error(
            StatusCode::NOT_FOUND,
            "Invalid or expired session ID.",
            "Re-initialize with POST /mcp to obtain a new session id.",
        );
    }

    let (parts, body) = req.into_parts();
    let bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return session_error(
                StatusCode::BAD_REQUEST,
                "Failed to read request body.",
                "Retry the request.",
            );
        }
    };
    let req = Request::from_parts(parts, Body::from(bytes.clone()));
    if is_initialize_payload(&bytes) {
        return forward_service(state.stateful_service, req).await;
    }
    if let Some(stateless) = state.stateless_service {
        return forward_service(stateless, req).await;
    }
    session_error(
        StatusCode::BAD_REQUEST,
        "Missing session ID.",
        "Initialize with POST /mcp to obtain a session id.",
    )
}

async fn handle_stateful_read<S>(
    state: LocalMcpHttpState<S>,
    req: Request,
    session_id: Option<String>,
    method: Method,
) -> Response
where
    S: Service<RoleServer> + Send + 'static,
{
    let Some(session_id) = session_id else {
        if matches!(method, Method::GET) && !state.auth_enabled {
            return endpoint_ready_hint();
        }
        return session_error(
            StatusCode::BAD_REQUEST,
            "Missing session ID.",
            "Initialize with POST /mcp to obtain a session id.",
        );
    };
    if !session_exists(&state.session_manager, &session_id).await {
        return session_error(
            StatusCode::NOT_FOUND,
            "Invalid or expired session ID.",
            "Re-initialize with POST /mcp to obtain a new session id.",
        );
    }
    forward_service(state.stateful_service, req).await
}

async fn forward_service<S>(
    service: StreamableHttpService<S, RecordingSessionManager>,
    req: Request,
) -> Response
where
    S: Service<RoleServer> + Send + 'static,
{
    service.handle(req).await.map(Body::new)
}

async fn health<S>(State(state): State<LocalMcpHttpState<S>>) -> Json<serde_json::Value>
where
    S: Service<RoleServer> + Send + 'static,
{
    let stats = state.session_manager.stats().await;
    Json(json!({
        "status": "ok",
        "transport": "streamable_http",
        "auth_enabled": state.auth_enabled,
        "stateless_fallback": state.stateless_service.is_some(),
        "session": session_stats_json(stats),
    }))
}

async fn host_guard<S>(
    State(state): State<LocalMcpHttpState<S>>,
    req: Request,
    next: Next,
) -> Response
where
    S: Service<RoleServer> + Send + 'static,
{
    if let Err(err) = validate_host_header(req.headers(), &state.allowed_hosts) {
        return plain_response(err.status_code(), err.message());
    }

    next.run(req).await
}

async fn oauth_protected_resource_not_configured() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "status": "not_configured",
            "error": "OAuth protected resource metadata is not configured for this local route bundle."
        })),
    )
}

fn session_stats_json(stats: SessionStats) -> serde_json::Value {
    json!({
        "active_sessions": stats.active_sessions,
        "max_sessions": stats.max_sessions,
        "resume_enabled": stats.resume_enabled,
        "lifecycle_mode": format!("{:?}", stats.lifecycle_mode).to_lowercase(),
        "lifecycle_connected_streams": stats.lifecycle_connected_streams,
        "lifecycle_disconnected_sessions": stats.lifecycle_disconnected_sessions,
        "lifecycle_expired_sessions_total": stats.lifecycle_expired_sessions_total,
    })
}

fn session_id_from_headers(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(MCP_SESSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn is_initialize_payload(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    match payload {
        serde_json::Value::Object(map) => map
            .get("method")
            .and_then(|value| value.as_str())
            .map(|method| method == "initialize")
            .unwrap_or(false),
        _ => false,
    }
}

async fn session_exists(session_manager: &BoundedSessionManager, session_id: &str) -> bool {
    (session_manager.has_session(&session_id.into()).await).unwrap_or_default()
}

fn session_error(status: StatusCode, message: &str, hint: &str) -> Response {
    json_response(
        status,
        json!({
            "status": "error",
            "error": message,
            "hint": hint,
        }),
    )
}

fn endpoint_ready_hint() -> Response {
    json_response(
        StatusCode::OK,
        json!({
            "status": "ok",
            "message": "MCP endpoint reachable.",
            "hint": "Initialize with POST /mcp to obtain a session id.",
        }),
    )
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response {
    let body = Body::from(value.to_string());
    match Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(body)
    {
        Ok(response) => response,
        Err(_) => Response::new(Body::from("{\"status\":\"error\"}")),
    }
}

fn plain_response(status: StatusCode, message: &'static str) -> Response {
    match Response::builder().status(status).body(Body::from(message)) {
        Ok(response) => response,
        Err(_) => Response::new(Body::from(message)),
    }
}

fn normalize_route_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_string()
    } else {
        format!("/{}", trimmed.trim_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_route_path, HttpBindSafety, HttpBindSafetyError};

    #[test]
    fn bind_safety_allows_loopback_without_auth() {
        let addr = "127.0.0.1:9411".parse().expect("socket addr");
        let result = HttpBindSafety::new(false, false).validate(addr);
        assert!(result.is_ok());
    }

    #[test]
    fn bind_safety_rejects_non_loopback_without_override() {
        let addr = "0.0.0.0:9411".parse().expect("socket addr");
        let result = HttpBindSafety::new(false, true).validate(addr);
        assert_eq!(result, Err(HttpBindSafetyError::NonLoopbackDenied { addr }));
    }

    #[test]
    fn bind_safety_rejects_non_loopback_without_auth() {
        let addr = "0.0.0.0:9411".parse().expect("socket addr");
        let result = HttpBindSafety::new(true, false).validate(addr);
        assert_eq!(
            result,
            Err(HttpBindSafetyError::AuthRequiredForNonLoopback { addr })
        );
    }

    #[test]
    fn normalize_route_path_adds_leading_slash() {
        assert_eq!(normalize_route_path("mcp/"), "/mcp");
        assert_eq!(normalize_route_path("/mcp"), "/mcp");
        assert_eq!(normalize_route_path(""), "/");
    }
}
