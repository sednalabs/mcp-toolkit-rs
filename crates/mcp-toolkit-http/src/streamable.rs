//! # Streamable HTTP Service Builders
//!
//! Helpers for constructing loopback-friendly Streamable HTTP MCP services.
//!
//! ## Ownership
//! This module owns the builder infrastructure for constructing `StreamableHttpService`
//! instances with bounded session management and standardized loopback configurations.
//!
//! ## Non-ownership
//! This module does not manage transport-level security (TLS) or the underlying
//! MCP service lifecycle beyond session sweep cleanup.
//!
//! ## Policy & Guarantees
//! * **Bounded Concurrency**: Limits session capacity to reduce the risk of memory exhaustion.
//! * **Loopback-First**: Employs conservative loopback defaults for host allowlisting.
//! * **Stateful Request Routing**: Provides handlers to route MCP requests to the
//!   correct session context.
//! * **Live Session Context**: Marks forwarded stateful requests only after the
//!   authoritative session store confirms exact live membership.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Configuring appropriate session capacities (`max_sessions`, `channel_capacity`).
//! * Ensuring that host allowlists match their deployment environment requirements.
//! * Binding [`LiveMcpSessionId`] to an authenticated actor before treating the
//!   session as application authorization.
//!
//! ## References
//! * [MCP Streamable HTTP Transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

use std::{error::Error, sync::Arc};

use axum::body::{to_bytes, Body};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::LengthLimitError;
use rmcp::{
    transport::{
        common::http_header::HEADER_SESSION_ID,
        streamable_http_server::{
            session::{
                local::{LocalSessionManager, SessionConfig},
                SessionManager,
            },
            StreamableHttpServerConfig, StreamableHttpService,
        },
    },
    RoleServer,
};
use serde_json::json;
use tokio::time::{Duration, MissedTickBehavior};

use crate::session::{BoundedSessionManager, RecordingSessionManager, SessionLifecycleConfig};

const SESSIONLESS_INITIALIZE_BODY_LIMIT: usize = 64 * 1024;

/// Identifies a session confirmed present in the authoritative session store.
///
/// The Streamable HTTP router inserts this type into the forwarded request's
/// extensions after one successful live-session lookup. Downstream middleware
/// can consume it from the `http::request::Parts` carried by `rmcp`.
///
/// # Security
/// This marker proves only live session-store membership at routing time. It
/// does not authenticate an actor, bind the session to an actor, or authorize
/// any operation. Services that require those guarantees must derive their own
/// stronger marker after applying service-specific authentication policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LiveMcpSessionId(String);

impl LiveMcpSessionId {
    /// Returns the exact canonical session identifier accepted by the store.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Classifies the authority carried by an MCP session header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpSessionRoute {
    /// The request omitted the session header and may use an explicitly enabled
    /// stateless route.
    Headerless,
    /// The request named a session that is currently live using its exact,
    /// canonical identifier.
    Live(LiveMcpSessionId),
    /// The request supplied a malformed, unknown, expired, or unverifiable
    /// session identifier.
    InvalidOrExpired,
}

impl McpSessionRoute {
    /// Reports whether the request supplied any MCP session header value.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Security
    /// Invalid and duplicate header values count as present so callers cannot
    /// silently downgrade them to headerless stateless authority.
    pub fn header_present(&self) -> bool {
        !matches!(self, Self::Headerless)
    }
}

/// Resolves an MCP session header against the authoritative live-session store.
///
/// # Errors
/// Session-store errors are converted to [`McpSessionRoute::InvalidOrExpired`]
/// so routing fails closed.
///
/// # Security
/// Only an entirely absent `Mcp-Session-Id` is classified as headerless.
/// Malformed, blank, whitespace-padded, duplicate, unknown, expired, and
/// lookup-failed values must never acquire stateless fallback authority.
/// Accepted identifiers are not normalized because the original header is
/// forwarded to the underlying Streamable HTTP service.
pub async fn resolve_mcp_session_route<M>(
    headers: &HeaderMap,
    session_manager: &M,
) -> McpSessionRoute
where
    M: SessionManager + Send + Sync,
{
    let mut values = headers.get_all(HEADER_SESSION_ID).iter();
    let Some(value) = values.next() else {
        return McpSessionRoute::Headerless;
    };
    if values.next().is_some() {
        return McpSessionRoute::InvalidOrExpired;
    }
    let Ok(value) = value.to_str() else {
        return McpSessionRoute::InvalidOrExpired;
    };
    if value.is_empty() || value.trim() != value {
        return McpSessionRoute::InvalidOrExpired;
    }
    let session_id = value.to_string();
    let lookup_session_id = session_id.as_str().into();
    match session_manager.has_session(&lookup_session_id).await {
        Ok(true) => McpSessionRoute::Live(LiveMcpSessionId(session_id)),
        Ok(false) | Err(_) => McpSessionRoute::InvalidOrExpired,
    }
}

/// Bounded local Streamable HTTP service configuration.
#[derive(Debug, Clone)]
pub struct LocalStreamableHttpServiceConfig {
    pub max_sessions: usize,
    pub allow_resume: bool,
    pub session_config: SessionConfig,
    pub server_config: StreamableHttpServerConfig,
}

impl Default for LocalStreamableHttpServiceConfig {
    fn default() -> Self {
        Self {
            max_sessions: 32,
            allow_resume: false,
            session_config: SessionConfig::default(),
            server_config: StreamableHttpServerConfig::default(),
        }
    }
}

/// Shared runtime components for a local Streamable HTTP MCP service.
pub struct LocalStreamableHttpServiceRuntime<S> {
    pub session_manager: Arc<BoundedSessionManager>,
    pub service: StreamableHttpService<S, RecordingSessionManager>,
}

/// Builds a bounded local Streamable HTTP service runtime.
pub fn build_local_streamable_http_service<S>(
    service_factory: impl Fn() -> Result<S, std::io::Error> + Send + Sync + 'static,
    config: LocalStreamableHttpServiceConfig,
) -> LocalStreamableHttpServiceRuntime<S>
where
    S: rmcp::Service<RoleServer> + Send + 'static,
{
    let disconnected_idle_timeout = config
        .session_config
        .keep_alive
        .or(Some(SessionConfig::DEFAULT_KEEP_ALIVE));
    let enable_background_session_sweeper =
        config.allow_resume && disconnected_idle_timeout.is_some();
    let lifecycle_config = if config.allow_resume {
        SessionLifecycleConfig::connected(disconnected_idle_timeout)
    } else {
        SessionLifecycleConfig::default()
    };

    let mut session_config = config.session_config;
    if config.allow_resume {
        session_config.keep_alive = None;
    }

    let session_manager = Arc::new(BoundedSessionManager::new_with_lifecycle(
        LocalSessionManager::default(),
        config.max_sessions,
        config.allow_resume,
        session_config,
        lifecycle_config,
    ));
    let recording_session_manager =
        Arc::new(RecordingSessionManager::new(session_manager.clone(), None));
    let sweep_token = config.server_config.cancellation_token.child_token();
    let service = StreamableHttpService::new(
        service_factory,
        recording_session_manager,
        config.server_config,
    );
    if enable_background_session_sweeper {
        let sweep_sessions = session_manager.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = sweep_token.cancelled() => break,
                    _ = ticker.tick() => {
                        sweep_sessions.sweep_expired_sessions().await;
                    }
                }
            }
        });
    }
    LocalStreamableHttpServiceRuntime {
        session_manager,
        service,
    }
}

/// Routes stateful `/mcp` requests, handling session validation and error responses.
///
/// # Security
/// * Assumes caller-provided host/auth guards are already applied.
/// * Bounds sessionless POST body probing before buffering.
pub async fn handle_stateful_mcp_request<S, M>(
    service: StreamableHttpService<S, M>,
    session_manager: Arc<BoundedSessionManager>,
    req: Request<Body>,
) -> Response<Body>
where
    S: rmcp::Service<RoleServer> + Send + 'static,
    M: SessionManager + Send + Sync + 'static,
{
    let method = req.method().clone();
    let session_route = resolve_mcp_session_route(req.headers(), session_manager.as_ref()).await;
    let has_session_header = session_route.header_present();
    tracing::debug!(
        method = %method,
        has_session_header,
        "streamable HTTP request received"
    );

    match method {
        Method::POST => {
            match session_route {
                McpSessionRoute::Live(session_id) => {
                    return forward_live_service(service, req, session_id).await;
                }
                McpSessionRoute::InvalidOrExpired => {
                    log_session_rejection(
                        &method,
                        true,
                        "invalid_or_expired_session",
                        StatusCode::NOT_FOUND,
                    );
                    return session_error(
                        StatusCode::NOT_FOUND,
                        "Invalid or expired session ID.",
                        "Re-initialize with POST /mcp to obtain a new session id.",
                    );
                }
                McpSessionRoute::Headerless => {}
            }

            let (parts, body) = req.into_parts();
            let bytes = match to_bytes(body, SESSIONLESS_INITIALIZE_BODY_LIMIT).await {
                Ok(bytes) => bytes,
                Err(err) if is_body_limit_error(&err) => {
                    log_session_rejection(
                        &method,
                        false,
                        "sessionless_body_too_large",
                        StatusCode::PAYLOAD_TOO_LARGE,
                    );
                    return session_error(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Request body too large.",
                        "Send a smaller initialize request.",
                    );
                }
                Err(_) => {
                    log_session_rejection(
                        &method,
                        false,
                        "sessionless_body_read_failed",
                        StatusCode::BAD_REQUEST,
                    );
                    return session_error(
                        StatusCode::BAD_REQUEST,
                        "Failed to read request body.",
                        "Retry the request.",
                    );
                }
            };
            if is_initialize_payload(&bytes) {
                let req = Request::from_parts(parts, Body::from(bytes));
                return forward_service(service, req, "initialize").await;
            }
            log_session_rejection(
                &method,
                false,
                "missing_session_id",
                StatusCode::BAD_REQUEST,
            );
            session_error(
                StatusCode::BAD_REQUEST,
                "Missing session ID.",
                "Initialize with POST /mcp to obtain a session id.",
            )
        }
        Method::GET | Method::DELETE => match session_route {
            McpSessionRoute::Headerless => {
                log_session_rejection(
                    &method,
                    false,
                    "missing_session_id",
                    StatusCode::BAD_REQUEST,
                );
                session_error(
                    StatusCode::BAD_REQUEST,
                    "Missing session ID.",
                    "Initialize with POST /mcp to obtain a session id.",
                )
            }
            McpSessionRoute::InvalidOrExpired => {
                log_session_rejection(
                    &method,
                    true,
                    "invalid_or_expired_session",
                    StatusCode::NOT_FOUND,
                );
                session_error(
                    StatusCode::NOT_FOUND,
                    "Invalid or expired session ID.",
                    "Re-initialize with POST /mcp to obtain a new session id.",
                )
            }
            McpSessionRoute::Live(session_id) => {
                forward_live_service(service, req, session_id).await
            }
        },
        _ => {
            log_session_rejection(
                &method,
                has_session_header,
                "method_not_allowed",
                StatusCode::METHOD_NOT_ALLOWED,
            );
            session_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "Method not allowed.",
                "Use POST /mcp to initialize, then reuse the session id for later requests.",
            )
        }
    }
}

async fn forward_live_service<S, M>(
    service: StreamableHttpService<S, M>,
    mut req: Request<Body>,
    session_id: LiveMcpSessionId,
) -> Response<Body>
where
    S: rmcp::Service<RoleServer> + Send + 'static,
    M: SessionManager + Send + Sync + 'static,
{
    attach_live_session_context(&mut req, session_id);
    forward_service(service, req, "stateful_session").await
}

fn attach_live_session_context<B>(req: &mut Request<B>, session_id: LiveMcpSessionId) {
    req.extensions_mut().insert(session_id);
}

async fn forward_service<S, M>(
    service: StreamableHttpService<S, M>,
    req: Request<Body>,
    phase: &'static str,
) -> Response<Body>
where
    S: rmcp::Service<RoleServer> + Send + 'static,
    M: SessionManager + Send + Sync + 'static,
{
    let method = req.method().clone();
    let has_session_header = req.headers().contains_key(HEADER_SESSION_ID);
    let response = service.handle(req).await.map(Body::new);
    tracing::debug!(
        method = %method,
        has_session_header,
        phase,
        status = response.status().as_u16(),
        "streamable HTTP request forwarded"
    );
    response
}

fn is_body_limit_error(err: &axum::Error) -> bool {
    err.source()
        .is_some_and(|source| source.is::<LengthLimitError>())
}

fn log_session_rejection(
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
        "streamable HTTP request rejected"
    );
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

fn session_error(status: StatusCode, message: &str, hint: &str) -> Response<Body> {
    let body = json!({
        "status": "error",
        "error": message,
        "hint": hint,
    });
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from("{\"status\":\"error\"}")))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        attach_live_session_context, build_local_streamable_http_service,
        handle_stateful_mcp_request, resolve_mcp_session_route, LiveMcpSessionId,
        LocalStreamableHttpServiceConfig, McpSessionRoute, SessionConfig,
        SESSIONLESS_INITIALIZE_BODY_LIMIT,
    };
    use axum::body::Body;
    use bytes::Bytes;
    use http::{
        header::{ACCEPT, CONTENT_TYPE, HOST},
        HeaderMap, HeaderValue, Request, StatusCode,
    };
    use http_body_util::{BodyExt, Full};
    use rmcp::{
        handler::server::{router::tool::ToolRouter, wrapper::Parameters},
        model::{ServerCapabilities, ServerInfo},
        schemars, tool, tool_router,
        transport::{
            common::http_header::HEADER_SESSION_ID,
            streamable_http_server::session::never::NeverSessionManager,
        },
        ServerHandler,
    };

    #[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
    struct SumRequest {
        pub a: i32,
        pub b: i32,
    }

    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    struct Calculator {
        tool_router: ToolRouter<Self>,
    }

    impl Calculator {
        fn new() -> Self {
            Self {
                tool_router: Self::tool_router(),
            }
        }
    }

    #[tool_router]
    impl Calculator {
        #[tool(description = "Calculate the sum of two numbers")]
        fn sum(&self, Parameters(SumRequest { a, b }): Parameters<SumRequest>) -> String {
            (a + b).to_string()
        }
    }

    impl ServerHandler for Calculator {
        fn get_info(&self) -> ServerInfo {
            ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
                .with_instructions("A simple calculator")
        }
    }

    const ACCEPT_STREAMABLE: &str = "application/json, text/event-stream";

    fn init_body() -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": rmcp::model::ProtocolVersion::LATEST,
                "capabilities": {},
                "clientInfo": {
                    "name": "test",
                    "version": "1.0"
                }
            }
        })
        .to_string()
    }

    #[tokio::test]
    async fn build_local_streamable_http_service_preserves_bounds_and_hosts() {
        let config = LocalStreamableHttpServiceConfig {
            max_sessions: 9,
            server_config:
                rmcp::transport::streamable_http_server::StreamableHttpServerConfig::default()
                    .with_allowed_hosts(["localhost", "127.0.0.1"]),
            ..Default::default()
        };
        let runtime = build_local_streamable_http_service(|| Ok(Calculator::new()), config);

        let stats = runtime.session_manager.stats().await;
        assert_eq!(stats.max_sessions, 9);
        assert_eq!(
            runtime.service.config.allowed_hosts,
            vec!["localhost".to_string(), "127.0.0.1".to_string()]
        );
    }

    #[tokio::test]
    async fn build_local_streamable_http_service_uses_connected_lifecycle_when_resume_enabled() {
        let config = LocalStreamableHttpServiceConfig {
            allow_resume: true,
            ..Default::default()
        };
        let runtime = build_local_streamable_http_service(|| Ok(Calculator::new()), config);

        let stats = runtime.session_manager.stats().await;
        assert!(stats.resume_enabled);
        assert_eq!(
            stats.lifecycle_mode,
            crate::session::SessionLifecycleMode::ConnectedUnboundedDisconnectedIdle
        );
    }

    #[tokio::test]
    async fn connected_local_streamable_service_expires_disconnected_session_after_idle_timeout() {
        let mut session_config = SessionConfig::default();
        session_config.keep_alive = Some(Duration::from_secs(1));

        let config = LocalStreamableHttpServiceConfig {
            allow_resume: true,
            session_config,
            ..Default::default()
        };
        let runtime = build_local_streamable_http_service(|| Ok(Calculator::new()), config);
        let request = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/mcp")
            .header(HOST, "127.0.0.1")
            .header(ACCEPT, ACCEPT_STREAMABLE)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(init_body()))
            .expect("request");

        let response = runtime.service.handle(request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let session_id = response
            .headers()
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .expect("session id");

        tokio::time::sleep(Duration::from_millis(1100)).await;
        runtime.session_manager.sweep_expired_sessions().await;

        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_SESSION_ID,
            HeaderValue::from_str(&session_id).expect("session header"),
        );
        assert_eq!(
            resolve_mcp_session_route(&headers, runtime.session_manager.as_ref()).await,
            McpSessionRoute::InvalidOrExpired,
            "expected disconnected session to expire"
        );

        let stats = runtime.session_manager.stats().await;
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.lifecycle_disconnected_sessions, 0);
        assert_eq!(stats.lifecycle_expired_sessions_total, 1);
    }

    #[tokio::test]
    async fn built_service_handles_initialize_request() {
        let runtime =
            build_local_streamable_http_service(|| Ok(Calculator::new()), Default::default());
        let request: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/mcp")
            .header(HOST, "127.0.0.1")
            .header(ACCEPT, ACCEPT_STREAMABLE)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::from(Bytes::from(init_body())))
            .expect("request");

        let response = runtime.service.handle(request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().contains_key("mcp-session-id"),
            "expected initialize response to create a session"
        );

        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body_text = String::from_utf8(body.to_vec()).expect("utf8 body");
        assert!(
            body_text.contains("protocolVersion") && body_text.contains("serverInfo"),
            "expected initialize result in response body, got: {body_text}"
        );
    }

    #[tokio::test]
    async fn session_route_is_headerless_only_when_the_header_is_absent() {
        let runtime =
            build_local_streamable_http_service(|| Ok(Calculator::new()), Default::default());

        assert_eq!(
            resolve_mcp_session_route(&HeaderMap::new(), runtime.session_manager.as_ref()).await,
            McpSessionRoute::Headerless
        );

        let mut headers = HeaderMap::new();
        headers.insert(HEADER_SESSION_ID, HeaderValue::from_static(""));
        assert_eq!(
            resolve_mcp_session_route(&headers, runtime.session_manager.as_ref()).await,
            McpSessionRoute::InvalidOrExpired
        );

        let mut headers = HeaderMap::new();
        headers.insert(HEADER_SESSION_ID, HeaderValue::from_static(" \t "));
        assert_eq!(
            resolve_mcp_session_route(&headers, runtime.session_manager.as_ref()).await,
            McpSessionRoute::InvalidOrExpired
        );

        let mut headers = HeaderMap::new();
        headers.append(HEADER_SESSION_ID, HeaderValue::from_static("first"));
        headers.append(HEADER_SESSION_ID, HeaderValue::from_static("second"));
        assert_eq!(
            resolve_mcp_session_route(&headers, runtime.session_manager.as_ref()).await,
            McpSessionRoute::InvalidOrExpired
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_SESSION_ID,
            HeaderValue::from_bytes(&[0xff]).expect("opaque header value"),
        );
        assert_eq!(
            resolve_mcp_session_route(&headers, runtime.session_manager.as_ref()).await,
            McpSessionRoute::InvalidOrExpired
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_SESSION_ID,
            HeaderValue::from_static("unknown-session"),
        );
        assert_eq!(
            resolve_mcp_session_route(&headers, runtime.session_manager.as_ref()).await,
            McpSessionRoute::InvalidOrExpired
        );

        let request = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/mcp")
            .header(HOST, "127.0.0.1")
            .header(ACCEPT, ACCEPT_STREAMABLE)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(init_body()))
            .expect("request");
        let response = runtime.service.handle(request).await;
        let session_id = response
            .headers()
            .get(HEADER_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .expect("live session id")
            .to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_SESSION_ID,
            HeaderValue::from_str(&session_id).expect("session header"),
        );
        assert_eq!(
            resolve_mcp_session_route(&headers, runtime.session_manager.as_ref()).await,
            McpSessionRoute::Live(LiveMcpSessionId(session_id.clone()))
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_SESSION_ID,
            HeaderValue::from_str(&format!(" {session_id} ")).expect("padded session header"),
        );
        assert_eq!(
            resolve_mcp_session_route(&headers, runtime.session_manager.as_ref()).await,
            McpSessionRoute::InvalidOrExpired
        );
    }

    #[tokio::test]
    async fn session_route_fails_closed_when_live_session_lookup_fails() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_SESSION_ID,
            HeaderValue::from_static("candidate-session"),
        );

        assert_eq!(
            resolve_mcp_session_route(&headers, &NeverSessionManager::default()).await,
            McpSessionRoute::InvalidOrExpired
        );
    }

    #[tokio::test]
    async fn handle_stateful_mcp_request_rejects_missing_session_get() {
        let runtime =
            build_local_streamable_http_service(|| Ok(Calculator::new()), Default::default());
        let request = Request::builder()
            .method("GET")
            .uri("http://127.0.0.1/mcp")
            .header(HOST, "127.0.0.1")
            .body(Body::empty())
            .expect("request");

        let response =
            handle_stateful_mcp_request(runtime.service.clone(), runtime.session_manager, request)
                .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body_text = String::from_utf8(body.to_vec()).expect("utf8 body");
        assert!(body_text.contains("Missing session ID."));
        assert!(body_text.contains("POST /mcp"));
    }

    #[tokio::test]
    async fn handle_stateful_mcp_request_rejects_non_initialize_post_without_session() {
        let runtime =
            build_local_streamable_http_service(|| Ok(Calculator::new()), Default::default());
        let request = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/mcp")
            .header(HOST, "127.0.0.1")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
            ))
            .expect("request");

        let response =
            handle_stateful_mcp_request(runtime.service.clone(), runtime.session_manager, request)
                .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body_text = String::from_utf8(body.to_vec()).expect("utf8 body");
        assert!(body_text.contains("Missing session ID."));
    }

    #[tokio::test]
    async fn handle_stateful_mcp_request_rejects_every_present_unusable_session() {
        let runtime =
            build_local_streamable_http_service(|| Ok(Calculator::new()), Default::default());
        let initialize = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/mcp")
            .header(HOST, "127.0.0.1")
            .header(ACCEPT, ACCEPT_STREAMABLE)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(init_body()))
            .expect("initialize request");
        let initialize_response = runtime.service.handle(initialize).await;
        let live_session_id = initialize_response
            .headers()
            .get(HEADER_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .expect("live session id")
            .to_string();

        let unusable_session_headers = vec![
            vec![HeaderValue::from_static("unknown-session")],
            vec![HeaderValue::from_static("")],
            vec![HeaderValue::from_static(" \t ")],
            vec![HeaderValue::from_bytes(&[0xff]).expect("opaque header value")],
            vec![
                HeaderValue::from_static("first-session"),
                HeaderValue::from_static("second-session"),
            ],
            vec![HeaderValue::from_str(&format!(" {live_session_id} "))
                .expect("padded live session header")],
        ];

        for values in unusable_session_headers {
            let mut request = Request::builder()
                .method("POST")
                .uri("http://127.0.0.1/mcp")
                .header(HOST, "127.0.0.1")
                .header(ACCEPT, ACCEPT_STREAMABLE)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(init_body()))
                .expect("session-bearing initialize request");
            for value in values {
                request.headers_mut().append(HEADER_SESSION_ID, value);
            }

            let response = handle_stateful_mcp_request(
                runtime.service.clone(),
                runtime.session_manager.clone(),
                request,
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let body = response
                .into_body()
                .collect()
                .await
                .expect("session rejection body")
                .to_bytes();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).expect("session rejection JSON"),
                serde_json::json!({
                    "status": "error",
                    "error": "Invalid or expired session ID.",
                    "hint": "Re-initialize with POST /mcp to obtain a new session id.",
                })
            );
        }
    }

    #[tokio::test]
    async fn handle_stateful_mcp_request_rejects_oversized_sessionless_post() {
        let runtime =
            build_local_streamable_http_service(|| Ok(Calculator::new()), Default::default());
        let oversized_body = "{".repeat(SESSIONLESS_INITIALIZE_BODY_LIMIT + 1);
        let request = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/mcp")
            .header(HOST, "127.0.0.1")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(oversized_body))
            .expect("request");

        let response =
            handle_stateful_mcp_request(runtime.service.clone(), runtime.session_manager, request)
                .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body_text = String::from_utf8(body.to_vec()).expect("utf8 body");
        assert!(body_text.contains("Request body too large."));
    }

    #[tokio::test]
    async fn handle_stateful_mcp_request_forwards_initialize_post() {
        let runtime =
            build_local_streamable_http_service(|| Ok(Calculator::new()), Default::default());
        let request = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/mcp")
            .header(HOST, "127.0.0.1")
            .header(ACCEPT, ACCEPT_STREAMABLE)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(init_body()))
            .expect("request");

        let response =
            handle_stateful_mcp_request(runtime.service.clone(), runtime.session_manager, request)
                .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("mcp-session-id"));
    }

    #[tokio::test]
    async fn live_session_context_carries_exact_store_verified_identifier() {
        let runtime =
            build_local_streamable_http_service(|| Ok(Calculator::new()), Default::default());
        let initialize = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/mcp")
            .header(HOST, "127.0.0.1")
            .header(ACCEPT, ACCEPT_STREAMABLE)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(init_body()))
            .expect("initialize request");
        let initialize_response = runtime.service.handle(initialize).await;
        let session_id = initialize_response
            .headers()
            .get(HEADER_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .expect("live session id")
            .to_string();

        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_SESSION_ID,
            HeaderValue::from_str(session_id.as_str()).expect("session header"),
        );
        let McpSessionRoute::Live(live_session_id) =
            resolve_mcp_session_route(&headers, runtime.session_manager.as_ref()).await
        else {
            panic!("expected exact live-session route");
        };

        let mut request = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/mcp")
            .body(Body::empty())
            .expect("request");
        attach_live_session_context(&mut request, live_session_id);

        assert_eq!(
            request
                .extensions()
                .get::<LiveMcpSessionId>()
                .map(LiveMcpSessionId::as_str),
            Some(session_id.as_str()),
            "the exact store-verified session id must be attached to forwarded request extensions"
        );
    }
}
