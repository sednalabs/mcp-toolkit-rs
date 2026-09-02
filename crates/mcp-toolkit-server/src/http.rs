//! # Streamable HTTP Server Composition
//!
//! Thin hosted-HTTP composition around RMCP 3.x.
//!
//! RMCP owns MCP protocol-version routing. In particular, one
//! `StreamableHttpService` can serve both legacy session-era requests and MCP
//! 2026-07-28 stateless requests. Toolkit adds deployment policy around that
//! service: bind safety, host/origin guarding, health routes, optional auth
//! composition, and an explicit compatibility fallback for older clients that
//! issue sessionless pre-2026 requests.
//!
//! ## Security Boundaries
//! * Non-loopback bind validation is explicit and requires auth.
//! * Host and Origin guarding use `mcp-toolkit-http` allowlist validation.
//! * Current MCP requests are not forced through legacy session lookup.
//! * Legacy requests carrying a session id are fail-closed when that session is
//!   malformed, unknown, or expired.
//! * Domain authorization and tool policy stay in service crates.

use std::{error::Error, fmt, net::SocketAddr, sync::Arc};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get},
    Json, Router,
};
use http::{
    header::{CONTENT_LENGTH, CONTENT_TYPE},
    Method, StatusCode,
};
use http_body_util::LengthLimitError;
use mcp_toolkit_http::{
    host::{
        validate_origin_header, validate_origin_header_against_allowed_origins,
        validate_request_authority,
    },
    oauth::protected_resource_well_known_paths,
    session::{BoundedSessionManager, RecordingSessionManager, SessionStats},
    streamable::{
        build_local_streamable_http_service, resolve_mcp_session_route, LiveMcpSessionId,
        LocalStreamableHttpServiceConfig, McpSessionRoute,
    },
};
use rmcp::{
    model::ProtocolVersion,
    transport::{
        common::http_header::{HEADER_MCP_PROTOCOL_VERSION, HEADER_SESSION_ID},
        streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService},
    },
    ServerHandler,
};
use serde_json::json;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "auth")]
use crate::auth::AuthSurfaceLayer;

/// Default maximum buffered MCP POST body size.
pub const DEFAULT_REQUEST_BODY_LIMIT: usize = 64 * 1024;
const CURRENT_PROTOCOL_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";

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
    pub fn new(allow_non_loopback: bool, auth_enabled: bool) -> Self {
        Self {
            allow_non_loopback,
            auth_enabled,
        }
    }

    /// Validates a bind address against this safety policy.
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
#[derive(Debug, Clone)]
pub struct LocalMcpHttpRuntimeBuilder {
    config: LocalStreamableHttpServiceConfig,
    legacy_stateless_fallback: bool,
    legacy_stateless_server_config: Option<StreamableHttpServerConfig>,
    max_request_body_bytes: usize,
}

impl Default for LocalMcpHttpRuntimeBuilder {
    fn default() -> Self {
        Self {
            config: LocalStreamableHttpServiceConfig::default(),
            legacy_stateless_fallback: false,
            legacy_stateless_server_config: None,
            max_request_body_bytes: DEFAULT_REQUEST_BODY_LIMIT,
        }
    }
}

impl LocalMcpHttpRuntimeBuilder {
    /// Builds a runtime builder with loopback-friendly defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the full low-level Streamable HTTP service configuration.
    pub fn config(mut self, config: LocalStreamableHttpServiceConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets the maximum number of bounded legacy sessions.
    pub fn max_sessions(mut self, max_sessions: usize) -> Self {
        self.config.max_sessions = max_sessions;
        self
    }

    /// Enables or disables resumability for legacy session-era requests.
    ///
    /// MCP 2026-07-28 requests are stateless and do not use this setting.
    pub fn allow_resume(mut self, allow_resume: bool) -> Self {
        self.config.allow_resume = allow_resume;
        self
    }

    /// Replaces the low-level local legacy-session configuration.
    pub fn session_config(
        mut self,
        session_config: rmcp::transport::streamable_http_server::session::local::SessionConfig,
    ) -> Self {
        self.config.session_config = session_config;
        self
    }

    /// Replaces the low-level RMCP Streamable HTTP server configuration.
    pub fn server_config(mut self, server_config: StreamableHttpServerConfig) -> Self {
        self.config.server_config = server_config;
        self
    }

    /// Sets allowed Host header values.
    pub fn allowed_hosts(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.config.server_config = self.config.server_config.with_allowed_hosts(hosts);
        self
    }

    /// Sets allowed browser Origin values.
    pub fn allowed_origins(mut self, origins: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.config.server_config = self.config.server_config.with_allowed_origins(origins);
        self
    }

    /// Sets the cancellation token used by the HTTP runtime.
    pub fn cancellation_token(mut self, token: CancellationToken) -> Self {
        self.config.server_config = self.config.server_config.with_cancellation_token(token);
        self
    }

    /// Enables a compatibility fallback for pre-2026 clients that issue
    /// sessionless non-initialize POST requests.
    ///
    /// This option is not needed for MCP 2026-07-28. Current requests are
    /// handled statelessly by the primary RMCP service automatically.
    pub fn stateless_fallback(mut self, enabled: bool) -> Self {
        self.legacy_stateless_fallback = enabled;
        self
    }

    /// Sets the maximum buffered body size for every MCP POST request.
    pub fn max_request_body_bytes(mut self, max_request_body_bytes: usize) -> Self {
        self.max_request_body_bytes = max_request_body_bytes;
        self
    }

    /// Replaces the configuration used by the legacy sessionless compatibility
    /// fallback. Toolkit forces `legacy_session_mode=false` for this service.
    pub fn stateless_server_config(mut self, config: StreamableHttpServerConfig) -> Self {
        self.legacy_stateless_server_config = Some(config);
        self
    }

    /// Builds the local Streamable HTTP runtime.
    pub fn build<S, F>(self, service_factory: F) -> LocalMcpHttpRuntime<S>
    where
        S: ServerHandler + Send + 'static,
        F: Fn() -> Result<S, std::io::Error> + Clone + Send + Sync + 'static,
    {
        let primary_config = self.config;
        let allowed_hosts = primary_config.server_config.allowed_hosts.clone();
        let allowed_origins = primary_config.server_config.allowed_origins.clone();
        let cancellation_token = primary_config
            .server_config
            .cancellation_token
            .child_token();

        let primary_factory = service_factory.clone();
        let primary = build_local_streamable_http_service(primary_factory, primary_config);

        let stateless_service = if self.legacy_stateless_fallback {
            let fallback_config = self
                .legacy_stateless_server_config
                .unwrap_or_else(|| {
                    StreamableHttpServerConfig::default()
                        .with_allowed_hosts(allowed_hosts.clone())
                        .with_allowed_origins(allowed_origins.clone())
                        .with_sse_retry(None)
                        .with_cancellation_token(cancellation_token)
                })
                .with_legacy_session_mode(false)
                .with_stateless_protocol_metadata_required(false);
            let recording_session_manager = Arc::new(RecordingSessionManager::new(
                primary.session_manager.clone(),
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
            session_manager: primary.session_manager,
            stateful_service: primary.service,
            stateless_service,
            allowed_hosts,
            allowed_origins,
            max_request_body_bytes: self.max_request_body_bytes,
        }
    }
}

/// Runtime components for a local Streamable HTTP MCP server.
///
/// `stateful_service` is retained as the public field name for compatibility,
/// but under RMCP 3 it is the primary dual-era service: current protocol
/// requests are stateless while legacy requests may use sessions.
pub struct LocalMcpHttpRuntime<S> {
    /// Bounded manager used only for legacy session-era requests.
    pub session_manager: Arc<BoundedSessionManager>,
    /// Primary RMCP Streamable HTTP service.
    pub stateful_service: StreamableHttpService<S, RecordingSessionManager>,
    /// Optional legacy sessionless compatibility service.
    pub stateless_service: Option<StreamableHttpService<S, RecordingSessionManager>>,
    /// Allowed Host values copied from the primary server config.
    pub allowed_hosts: Vec<String>,
    /// Allowed browser Origin values copied from the primary server config.
    pub allowed_origins: Vec<String>,
    /// Maximum buffered body size for every MCP POST request.
    pub max_request_body_bytes: usize,
}

impl<S> LocalMcpHttpRuntime<S>
where
    S: ServerHandler + Send + 'static,
{
    /// Converts runtime pieces into route state.
    pub fn into_state(self, auth_enabled: bool) -> LocalMcpHttpState<S> {
        LocalMcpHttpState {
            session_manager: self.session_manager,
            stateful_service: self.stateful_service,
            stateless_service: self.stateless_service,
            allowed_hosts: self.allowed_hosts,
            allowed_origins: self.allowed_origins,
            auth_enabled,
            max_request_body_bytes: self.max_request_body_bytes,
        }
    }
}

/// Shared route state for the local MCP HTTP route bundle.
pub struct LocalMcpHttpState<S> {
    /// Bounded manager used to validate legacy session-bound requests.
    pub session_manager: Arc<BoundedSessionManager>,
    /// Primary RMCP MCP service.
    pub stateful_service: StreamableHttpService<S, RecordingSessionManager>,
    /// Optional legacy sessionless compatibility service.
    pub stateless_service: Option<StreamableHttpService<S, RecordingSessionManager>>,
    /// Allowed Host values for the route-bundle guard.
    pub allowed_hosts: Vec<String>,
    /// Allowed full browser Origin values for the route-bundle guard.
    pub allowed_origins: Vec<String>,
    /// True when bearer authentication is active above the route bundle.
    pub auth_enabled: bool,
    /// Maximum buffered body size for every MCP POST request.
    pub max_request_body_bytes: usize,
}

impl<S> Clone for LocalMcpHttpState<S> {
    fn clone(&self) -> Self {
        Self {
            session_manager: self.session_manager.clone(),
            stateful_service: self.stateful_service.clone(),
            stateless_service: self.stateless_service.clone(),
            allowed_hosts: self.allowed_hosts.clone(),
            allowed_origins: self.allowed_origins.clone(),
            auth_enabled: self.auth_enabled,
            max_request_body_bytes: self.max_request_body_bytes,
        }
    }
}

/// Opinionated builder for a local Streamable HTTP MCP router.
pub struct LocalMcpHttpServerBuilder {
    runtime: LocalMcpHttpRuntimeBuilder,
    auth_enabled: bool,
    include_health: bool,
    include_host_guard: bool,
    include_oauth_not_configured: bool,
    mcp_path: String,
    resource_path: Option<String>,
    #[cfg(feature = "auth")]
    auth_layer: Option<AuthSurfaceLayer>,
}

impl fmt::Debug for LocalMcpHttpServerBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("LocalMcpHttpServerBuilder");
        builder
            .field("runtime", &self.runtime)
            .field("auth_enabled", &self.auth_enabled)
            .field("include_health", &self.include_health)
            .field(
                "include_oauth_not_configured",
                &self.include_oauth_not_configured,
            )
            .field("mcp_path", &self.mcp_path)
            .field("resource_path", &self.resource_path);
        #[cfg(feature = "auth")]
        builder.field("auth_layer", &self.auth_layer.is_some());
        builder.finish()
    }
}

impl Default for LocalMcpHttpServerBuilder {
    fn default() -> Self {
        Self {
            runtime: LocalMcpHttpRuntimeBuilder::new(),
            auth_enabled: false,
            include_health: true,
            include_host_guard: true,
            include_oauth_not_configured: false,
            mcp_path: "/mcp".to_string(),
            resource_path: None,
            #[cfg(feature = "auth")]
            auth_layer: None,
        }
    }
}

impl LocalMcpHttpServerBuilder {
    /// Builds a hosted HTTP builder with safe local defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the underlying Streamable HTTP runtime builder.
    pub fn runtime(mut self, runtime: LocalMcpHttpRuntimeBuilder) -> Self {
        self.runtime = runtime;
        self
    }

    /// Sets allowed Host values.
    pub fn allowed_hosts(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.runtime = self.runtime.allowed_hosts(hosts);
        self
    }

    /// Sets allowed browser Origin values.
    pub fn allowed_origins(mut self, origins: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.runtime = self.runtime.allowed_origins(origins);
        self
    }

    /// Sets the maximum number of bounded legacy sessions.
    pub fn max_sessions(mut self, max_sessions: usize) -> Self {
        self.runtime = self.runtime.max_sessions(max_sessions);
        self
    }

    /// Enables or disables resumability for legacy session-era requests.
    pub fn allow_resume(mut self, allow_resume: bool) -> Self {
        self.runtime = self.runtime.allow_resume(allow_resume);
        self
    }

    /// Sets the cancellation token used by the HTTP runtime.
    pub fn cancellation_token(mut self, token: CancellationToken) -> Self {
        self.runtime = self.runtime.cancellation_token(token);
        self
    }

    /// Enables or disables the pre-2026 sessionless compatibility fallback.
    pub fn stateless_fallback(mut self, enabled: bool) -> Self {
        self.runtime = self.runtime.stateless_fallback(enabled);
        self
    }

    /// Sets the maximum buffered body size for every MCP POST request.
    pub fn max_request_body_bytes(mut self, max_request_body_bytes: usize) -> Self {
        self.runtime = self.runtime.max_request_body_bytes(max_request_body_bytes);
        self
    }

    /// Replaces the low-level Streamable HTTP service configuration.
    pub fn runtime_config(mut self, config: LocalStreamableHttpServiceConfig) -> Self {
        self.runtime = self.runtime.config(config);
        self
    }

    /// Replaces the low-level local legacy-session configuration.
    pub fn session_config(
        mut self,
        session_config: rmcp::transport::streamable_http_server::session::local::SessionConfig,
    ) -> Self {
        self.runtime = self.runtime.session_config(session_config);
        self
    }

    /// Replaces the primary RMCP Streamable HTTP server configuration.
    pub fn server_config(mut self, server_config: StreamableHttpServerConfig) -> Self {
        self.runtime = self.runtime.server_config(server_config);
        self
    }

    /// Replaces the pre-2026 sessionless compatibility configuration.
    pub fn stateless_server_config(mut self, config: StreamableHttpServerConfig) -> Self {
        self.runtime = self.runtime.stateless_server_config(config);
        self
    }

    /// Enables or disables the built-in health route.
    pub fn include_health(mut self, include: bool) -> Self {
        self.include_health = include;
        self
    }

    /// Enables or disables the route-bundle host/origin guard.
    pub fn include_host_guard(mut self, include: bool) -> Self {
        self.include_host_guard = include;
        self
    }

    /// Enables unauthenticated OAuth protected-resource placeholder routes.
    pub fn include_oauth_not_configured(mut self, include: bool) -> Self {
        self.include_oauth_not_configured = include;
        self
    }

    /// Sets the MCP route path.
    pub fn mcp_path(mut self, path: impl Into<String>) -> Self {
        self.mcp_path = normalize_route_path(&path.into());
        self
    }

    /// Sets the protected resource path used for discovery routes.
    pub fn resource_path(mut self, path: impl Into<String>) -> Self {
        self.resource_path = Some(normalize_route_path(&path.into()));
        self
    }

    /// Marks the route bundle as protected by auth middleware supplied elsewhere.
    pub fn auth_enabled(mut self, enabled: bool) -> Self {
        self.auth_enabled = enabled;
        self
    }

    /// Installs an auth layer around the route bundle.
    #[cfg(feature = "auth")]
    pub fn auth_layer(mut self, layer: AuthSurfaceLayer) -> Self {
        self.auth_enabled = true;
        self.auth_layer = Some(layer);
        self
    }

    /// Builds the HTTP router from a service factory.
    pub fn build<S, F>(self, service_factory: F) -> Router
    where
        S: ServerHandler + Send + 'static,
        F: Fn() -> Result<S, std::io::Error> + Clone + Send + Sync + 'static,
    {
        let runtime = self.runtime.build(service_factory);
        let mut router = LocalMcpHttpRouterBuilder::new(runtime.into_state(self.auth_enabled))
            .include_health(self.include_health)
            .include_host_guard(self.include_host_guard)
            .include_oauth_not_configured(self.include_oauth_not_configured)
            .mcp_path(self.mcp_path);

        if let Some(resource_path) = self.resource_path {
            router = router.resource_path(resource_path);
        }

        #[cfg(feature = "auth")]
        {
            if let Some(layer) = self.auth_layer {
                router = router.auth_layer(layer);
            }
        }

        router.build()
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
    S: ServerHandler + Send + 'static,
{
    /// Builds a route-bundle builder from route state.
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
    pub fn include_health(mut self, include: bool) -> Self {
        self.include_health = include;
        self
    }

    /// Enables or disables the route-bundle host/origin guard.
    pub fn include_host_guard(mut self, include: bool) -> Self {
        self.include_host_guard = include;
        self
    }

    /// Enables unauthenticated OAuth protected-resource placeholder routes.
    pub fn include_oauth_not_configured(mut self, include: bool) -> Self {
        self.include_oauth_not_configured = include;
        self
    }

    /// Sets the MCP route path.
    pub fn mcp_path(mut self, path: impl Into<String>) -> Self {
        self.mcp_path = normalize_route_path(&path.into());
        self.resource_path = self.mcp_path.clone();
        self
    }

    /// Sets the protected resource path used for placeholder discovery routes.
    pub fn resource_path(mut self, path: impl Into<String>) -> Self {
        self.resource_path = normalize_route_path(&path.into());
        self
    }

    /// Installs an auth layer around the route bundle.
    #[cfg(feature = "auth")]
    pub fn auth_layer(mut self, layer: AuthSurfaceLayer) -> Self {
        self.auth_layer = Some(layer);
        self
    }

    /// Builds the route bundle.
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
        #[cfg(feature = "auth")]
        {
            if let Some(layer) = self.auth_layer {
                router = router.layer(layer);
            }
        }
        if self.include_host_guard {
            router = router.layer(middleware::from_fn_with_state(
                state.clone(),
                host_guard::<S>,
            ));
        }
        router.with_state(state)
    }
}

/// Handles a dual-era Streamable HTTP MCP request.
///
/// Current MCP requests are delegated directly to RMCP and remain stateless.
/// Legacy session-era requests keep the Toolkit's fail-closed live-session
/// preflight and optional sessionless compatibility fallback.
pub async fn handle_mcp<S>(State(state): State<LocalMcpHttpState<S>>, req: Request) -> Response
where
    S: ServerHandler + Send + 'static,
{
    match req.method().clone() {
        Method::POST => handle_post(state, req).await,
        Method::GET => handle_get(state, req).await,
        Method::DELETE => handle_delete(state, req).await,
        method => {
            log_route_rejection(
                &method,
                req.headers().contains_key(HEADER_SESSION_ID),
                "method_not_allowed",
                StatusCode::METHOD_NOT_ALLOWED,
            );
            plain_response(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed.")
        }
    }
}

async fn handle_post<S>(state: LocalMcpHttpState<S>, req: Request) -> Response
where
    S: ServerHandler + Send + 'static,
{
    if content_length_exceeds(req.headers(), state.max_request_body_bytes) {
        log_route_rejection(
            req.method(),
            req.headers().contains_key(HEADER_SESSION_ID),
            "request_body_too_large",
            StatusCode::PAYLOAD_TOO_LARGE,
        );
        return sessionless_body_too_large_response();
    }

    // A declared current protocol request is stateless by specification. Do
    // not force it through legacy session lookup even if a stale legacy header
    // is also present; RMCP validates the actual request metadata and headers.
    if declares_current_protocol(req.headers()) {
        return forward_service(state.stateful_service, req, "current_stateless").await;
    }

    let has_session_header = req.headers().contains_key(HEADER_SESSION_ID);
    if has_session_header {
        let route = resolve_mcp_session_route(req.headers(), state.session_manager.as_ref()).await;
        return match route {
            McpSessionRoute::Live(session_id) => {
                forward_live_service(state.stateful_service, req, session_id).await
            }
            McpSessionRoute::Headerless => {
                // `header_present` above and exact resolver semantics make this
                // branch unreachable, but keep the match total and fail closed.
                session_error(
                    StatusCode::BAD_REQUEST,
                    "Missing session ID.",
                    "Use a valid legacy session id or a current protocol request.",
                )
            }
            McpSessionRoute::InvalidOrExpired => session_error(
                StatusCode::NOT_FOUND,
                "Invalid or expired session ID.",
                "Re-initialize a legacy session or use MCP 2026-07-28 stateless requests.",
            ),
        };
    }

    // Headerless requests without an explicit protocol header may be either a
    // legacy initialize/sessionless compatibility call or a current request
    // whose version is carried only in `_meta`. Probe only this ambiguous path.
    if content_length_exceeds(req.headers(), state.max_request_body_bytes) {
        return sessionless_body_too_large_response();
    }
    let (parts, body) = req.into_parts();
    let bytes = match to_bytes(body, state.max_request_body_bytes).await {
        Ok(bytes) => bytes,
        Err(err) if is_body_limit_error(&err) => return sessionless_body_too_large_response(),
        Err(_) => {
            return session_error(
                StatusCode::BAD_REQUEST,
                "Failed to read request body.",
                "Retry the request.",
            );
        }
    };
    let is_initialize = is_initialize_payload(&bytes);
    let is_current = payload_declares_current_protocol(&bytes);
    let req = Request::from_parts(parts, Body::from(bytes));

    if is_initialize || is_current {
        return forward_service(
            state.stateful_service,
            req,
            if is_current {
                "current_stateless_body_meta"
            } else {
                "legacy_initialize"
            },
        )
        .await;
    }

    if let Some(stateless) = state.stateless_service {
        return forward_service(stateless, req, "legacy_stateless_fallback").await;
    }

    // Let RMCP own the actual protocol error shape for ambiguous headerless
    // requests rather than reimplementing JSON-RPC transport semantics here.
    forward_service(state.stateful_service, req, "rmcp_protocol_dispatch").await
}

async fn handle_get<S>(state: LocalMcpHttpState<S>, req: Request) -> Response
where
    S: ServerHandler + Send + 'static,
{
    // MCP 2026-07-28 GET is stateless and may be used by RMCP for retained-event
    // replay. Do not apply legacy session preflight to current requests, even if
    // they also carry a stale legacy session header.
    if declares_current_protocol(req.headers()) {
        return forward_service(state.stateful_service, req, "current_stateless_get").await;
    }

    if !req.headers().contains_key(HEADER_SESSION_ID) {
        if !state.auth_enabled {
            return endpoint_ready_hint();
        }
        return session_error(
            StatusCode::BAD_REQUEST,
            "Missing legacy session ID.",
            "MCP 2026-07-28 uses stateless routing; legacy GET streams require a live session.",
        );
    }

    match resolve_mcp_session_route(req.headers(), state.session_manager.as_ref()).await {
        McpSessionRoute::Live(session_id) => {
            forward_live_service(state.stateful_service, req, session_id).await
        }
        McpSessionRoute::Headerless => session_error(
            StatusCode::BAD_REQUEST,
            "Missing legacy session ID.",
            "Legacy GET streams require a live session.",
        ),
        McpSessionRoute::InvalidOrExpired => session_error(
            StatusCode::NOT_FOUND,
            "Invalid or expired session ID.",
            "Re-initialize the legacy session.",
        ),
    }
}

async fn handle_delete<S>(state: LocalMcpHttpState<S>, req: Request) -> Response
where
    S: ServerHandler + Send + 'static,
{
    // Current MCP has no session to terminate. Delegate the request to RMCP so
    // it owns the method-not-allowed response and protocol-version validation.
    if declares_current_protocol(req.headers()) {
        return forward_service(state.stateful_service, req, "current_stateless_delete").await;
    }

    match resolve_mcp_session_route(req.headers(), state.session_manager.as_ref()).await {
        McpSessionRoute::Live(session_id) => {
            forward_live_service(state.stateful_service, req, session_id).await
        }
        McpSessionRoute::Headerless => session_error(
            StatusCode::BAD_REQUEST,
            "Missing legacy session ID.",
            "Legacy DELETE requires a live session.",
        ),
        McpSessionRoute::InvalidOrExpired => session_error(
            StatusCode::NOT_FOUND,
            "Invalid or expired session ID.",
            "Re-initialize the legacy session.",
        ),
    }
}

async fn forward_live_service<S>(
    service: StreamableHttpService<S, RecordingSessionManager>,
    mut req: Request,
    session_id: LiveMcpSessionId,
) -> Response
where
    S: ServerHandler + Send + 'static,
{
    req.extensions_mut().insert(session_id);
    forward_service(service, req, "legacy_stateful_session").await
}

async fn forward_service<S>(
    service: StreamableHttpService<S, RecordingSessionManager>,
    req: Request,
    phase: &'static str,
) -> Response
where
    S: ServerHandler + Send + 'static,
{
    let method = req.method().clone();
    let has_session_header = req.headers().contains_key(HEADER_SESSION_ID);
    let response = service.handle(req).await.map(Body::new);
    tracing::debug!(
        method = %method,
        has_session_header,
        phase,
        status = response.status().as_u16(),
        "streamable HTTP route-bundle request forwarded"
    );
    response
}

async fn health<S>(State(state): State<LocalMcpHttpState<S>>) -> Json<serde_json::Value>
where
    S: ServerHandler + Send + 'static,
{
    let stats = state.session_manager.stats().await;
    let session = session_stats_json(stats);
    let stateless_fallback = state.stateless_service.is_some();
    Json(json!({
        "status": "ok",
        "transport": "streamable_http",
        "protocol_posture": "rmcp3_dual_era",
        "current_protocol_stateless": true,
        "auth_enabled": state.auth_enabled,
        "legacy_stateless_fallback": stateless_fallback,
        "stateless_fallback": stateless_fallback,
        "max_request_body_bytes": state.max_request_body_bytes,
        "legacy_session": session.clone(),
        "session": session,
    }))
}

async fn host_guard<S>(
    State(state): State<LocalMcpHttpState<S>>,
    req: Request,
    next: Next,
) -> Response
where
    S: ServerHandler + Send + 'static,
{
    if let Err(err) =
        validate_request_authority(Some(req.uri()), req.headers(), &state.allowed_hosts)
    {
        tracing::warn!(
            method = %req.method(),
            has_session_header = req.headers().contains_key(HEADER_SESSION_ID),
            rejection_class = "host_rejected",
            status = err.status_code().as_u16(),
            "streamable HTTP route-bundle request rejected"
        );
        return plain_response(err.status_code(), err.message());
    }
    let origin_result = if state.allowed_origins.is_empty() {
        validate_origin_header(req.headers(), &state.allowed_hosts)
    } else {
        validate_origin_header_against_allowed_origins(req.headers(), &state.allowed_origins)
    };
    if let Err(err) = origin_result {
        tracing::warn!(
            method = %req.method(),
            has_session_header = req.headers().contains_key(HEADER_SESSION_ID),
            rejection_class = "origin_rejected",
            status = err.status_code().as_u16(),
            "streamable HTTP route-bundle request rejected"
        );
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

fn declares_current_protocol(headers: &http::HeaderMap) -> bool {
    headers
        .get(HEADER_MCP_PROTOCOL_VERSION)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_protocol_version)
        .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28)
}

fn payload_declares_current_protocol(body: &[u8]) -> bool {
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    payload
        .get("params")
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get(CURRENT_PROTOCOL_META_KEY))
        .and_then(|value| value.as_str())
        .and_then(parse_protocol_version)
        .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28)
}

fn parse_protocol_version(value: &str) -> Option<ProtocolVersion> {
    serde_json::from_value(serde_json::Value::String(value.to_owned())).ok()
}

fn log_route_rejection(
    method: &Method,
    has_session_header: bool,
    rejection_class: &'static str,
    status: StatusCode,
) {
    tracing::warn!(
        method = %method,
        has_session_header,
        rejection_class,
        status = status.as_u16(),
        "streamable HTTP route-bundle request rejected"
    );
}

fn content_length_exceeds(headers: &http::HeaderMap, limit: usize) -> bool {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .map(|length| length > limit)
        .unwrap_or(false)
}

fn is_body_limit_error(err: &axum::Error) -> bool {
    err.source()
        .is_some_and(|source| source.is::<LengthLimitError>())
}

fn is_initialize_payload(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    payload
        .get("method")
        .and_then(|value| value.as_str())
        .is_some_and(|method| method == "initialize")
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

fn sessionless_body_too_large_response() -> Response {
    session_error(
        StatusCode::PAYLOAD_TOO_LARGE,
        "Request body too large for legacy sessionless protocol probing.",
        "Use MCP 2026-07-28 with MCP-Protocol-Version or initialize a legacy session.",
    )
}

fn endpoint_ready_hint() -> Response {
    json_response(
        StatusCode::OK,
        json!({
            "status": "ok",
            "message": "MCP endpoint reachable.",
            "hint": "Use MCP 2026-07-28 stateless POST requests. Legacy clients may initialize a session when compatibility is enabled.",
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
