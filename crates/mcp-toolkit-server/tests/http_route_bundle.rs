#![cfg(feature = "http")]

use axum::{
    body::Body,
    http::{request::Parts, HeaderValue, Request},
};
use http_body_util::BodyExt;
use mcp_toolkit_http::streamable::LiveMcpSessionId;
use mcp_toolkit_server::{
    http::{LocalMcpHttpRouterBuilder, LocalMcpHttpRuntimeBuilder, LocalMcpHttpServerBuilder},
    rmcp::{
        handler::server::{router::tool::ToolRouter, tool::Extension, wrapper::Parameters},
        model::{ServerCapabilities, ServerInfo},
        schemars, tool, tool_router, ServerHandler,
    },
};
use tokio::sync::mpsc::{self, UnboundedSender};
use tower::ServiceExt;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct EchoRequest {
    value: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TestMcp {
    tool_router: ToolRouter<Self>,
    routed_session_observer: Option<UnboundedSender<Option<String>>>,
}

impl TestMcp {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
            routed_session_observer: None,
        }
    }

    fn with_routed_session_observer(
        routed_session_observer: UnboundedSender<Option<String>>,
    ) -> Self {
        Self {
            tool_router: Self::tool_router(),
            routed_session_observer: Some(routed_session_observer),
        }
    }
}

#[tool_router]
impl TestMcp {
    #[tool(description = "Echo a value")]
    fn echo(&self, Parameters(EchoRequest { value }): Parameters<EchoRequest>) -> String {
        value
    }

    #[tool(description = "Report the routed live-session marker")]
    fn routed_session(&self, Extension(parts): Extension<Parts>) -> String {
        let routed_session = parts
            .extensions
            .get::<LiveMcpSessionId>()
            .map(LiveMcpSessionId::as_str)
            .map(str::to_string);
        if let Some(observer) = &self.routed_session_observer {
            let _ = observer.send(routed_session.clone());
        }
        routed_session.unwrap_or_else(|| "absent".to_string())
    }
}

impl ServerHandler for TestMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("test server")
    }
}

const ACCEPT_STREAMABLE: &str = "application/json, text/event-stream";

fn init_body() -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": mcp_toolkit_server::rmcp::model::ProtocolVersion::LATEST,
            "capabilities": {},
            "clientInfo": {
                "name": "test",
                "version": "1.0"
            }
        }
    })
    .to_string()
}

fn routed_session_body(id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "routed_session",
            "arguments": {}
        }
    })
    .to_string()
}

#[tokio::test]
async fn server_builder_composes_runtime_and_router_defaults() {
    let router = LocalMcpHttpServerBuilder::new()
        .allowed_hosts(["127.0.0.1"])
        .mcp_path("/api/mcp")
        .build(|| Ok(TestMcp::new()));

    let health = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .expect("health request"),
        )
        .await
        .expect("health response");
    assert_eq!(health.status(), 200);

    let ready = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/mcp")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .expect("ready request"),
        )
        .await
        .expect("ready response");
    assert_eq!(ready.status(), 200);
}

#[tokio::test]
async fn route_bundle_serves_health_and_initialize() {
    let runtime = LocalMcpHttpRuntimeBuilder::new()
        .allowed_hosts(["127.0.0.1"])
        .build(|| Ok(TestMcp::new()));
    let router = LocalMcpHttpRouterBuilder::new(runtime.into_state(false))
        .include_oauth_not_configured(true)
        .build();

    let health = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .expect("health request"),
        )
        .await
        .expect("health response");
    assert_eq!(health.status(), 200);

    let init = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header("accept", ACCEPT_STREAMABLE)
                .header("content-type", "application/json")
                .body(Body::from(init_body()))
                .expect("initialize request"),
        )
        .await
        .expect("initialize response");
    assert_eq!(init.status(), 200);
    assert!(init.headers().contains_key("mcp-session-id"));

    let ready = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .expect("ready request"),
        )
        .await
        .expect("ready response");
    assert_eq!(ready.status(), 200);
    let body = ready
        .into_body()
        .collect()
        .await
        .expect("ready body")
        .to_bytes();
    let text = String::from_utf8(body.to_vec()).expect("utf8 ready body");
    assert!(text.contains("MCP endpoint reachable"));
}

#[tokio::test]
async fn route_bundle_rejects_oversized_sessionless_post() {
    let runtime = LocalMcpHttpRuntimeBuilder::new()
        .allowed_hosts(["127.0.0.1"])
        .build(|| Ok(TestMcp::new()));
    let router = LocalMcpHttpRouterBuilder::new(runtime.into_state(false)).build();
    let body = vec![b' '; 65 * 1024];

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header("accept", ACCEPT_STREAMABLE)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("oversized sessionless request"),
        )
        .await
        .expect("oversized sessionless response");

    assert_eq!(response.status(), 413);
}

#[tokio::test]
async fn route_bundle_rejects_present_unusable_sessions_before_stateless_fallback() {
    let (routed_session_sender, mut routed_session_receiver) = mpsc::unbounded_channel();
    let runtime = LocalMcpHttpRuntimeBuilder::new()
        .allowed_hosts(["127.0.0.1"])
        .stateless_fallback(true)
        .build(move || {
            Ok(TestMcp::with_routed_session_observer(
                routed_session_sender.clone(),
            ))
        });
    let router = LocalMcpHttpRouterBuilder::new(runtime.into_state(false)).build();

    let initialize_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header("accept", ACCEPT_STREAMABLE)
                .header("content-type", "application/json")
                .body(Body::from(init_body()))
                .expect("initialize request"),
        )
        .await
        .expect("initialize response");
    let live_session_id = initialize_response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .expect("live session id")
        .to_string();

    let live_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header("accept", ACCEPT_STREAMABLE)
                .header("content-type", "application/json")
                .header("mcp-session-id", &live_session_id)
                .body(Body::from(routed_session_body(2)))
                .expect("live session request"),
        )
        .await
        .expect("live session response");
    assert_eq!(live_response.status(), 200);
    assert_eq!(
        routed_session_receiver.recv().await,
        Some(Some(live_session_id.clone())),
        "the route bundle must forward the exact store-verified session marker"
    );

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
            .uri("/mcp")
            .header("host", "127.0.0.1")
            .header("accept", ACCEPT_STREAMABLE)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}"#,
            ))
            .expect("session-bearing request");
        for value in values {
            request.headers_mut().append("mcp-session-id", value);
        }

        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("session rejection response");
        assert_eq!(response.status(), 404);
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

    let headerless_response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header("accept", ACCEPT_STREAMABLE)
                .header("content-type", "application/json")
                .body(Body::from(routed_session_body(4)))
                .expect("headerless request"),
        )
        .await
        .expect("headerless stateless response");
    assert_eq!(headerless_response.status(), 200);
    assert_eq!(
        routed_session_receiver.recv().await,
        Some(None),
        "headerless stateless routing must not mint live-session authority"
    );
}

#[tokio::test]
async fn route_bundle_rejects_unknown_host() {
    let runtime = LocalMcpHttpRuntimeBuilder::new()
        .allowed_hosts(["127.0.0.1"])
        .build(|| Ok(TestMcp::new()));
    let router = LocalMcpHttpRouterBuilder::new(runtime.into_state(false)).build();

    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("host", "example.com")
                .body(Body::empty())
                .expect("health request"),
        )
        .await
        .expect("health response");

    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn route_bundle_rejects_unknown_origin() {
    let runtime = LocalMcpHttpRuntimeBuilder::new()
        .allowed_hosts(["127.0.0.1"])
        .build(|| Ok(TestMcp::new()));
    let router = LocalMcpHttpRouterBuilder::new(runtime.into_state(false)).build();

    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("host", "127.0.0.1")
                .header("origin", "https://example.com")
                .body(Body::empty())
                .expect("health request"),
        )
        .await
        .expect("health response");

    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn route_bundle_preserves_port_qualified_host_allowlist() {
    let runtime = LocalMcpHttpRuntimeBuilder::new()
        .allowed_hosts(["example.com:8080"])
        .build(|| Ok(TestMcp::new()));
    let router = LocalMcpHttpRouterBuilder::new(runtime.into_state(false)).build();

    let allowed = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("host", "example.com:8080")
                .body(Body::empty())
                .expect("allowed health request"),
        )
        .await
        .expect("allowed health response");
    assert_eq!(allowed.status(), 200);

    let wrong_port = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("host", "example.com:8081")
                .body(Body::empty())
                .expect("wrong port health request"),
        )
        .await
        .expect("wrong port health response");
    assert_eq!(wrong_port.status(), 403);

    let missing_port = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("host", "example.com")
                .body(Body::empty())
                .expect("missing port health request"),
        )
        .await
        .expect("missing port health response");
    assert_eq!(missing_port.status(), 403);
}

#[tokio::test]
async fn route_bundle_accepts_uri_authority_when_host_header_is_absent() {
    let runtime = LocalMcpHttpRuntimeBuilder::new()
        .allowed_hosts(["example.com:8080"])
        .build(|| Ok(TestMcp::new()));
    let router = LocalMcpHttpRouterBuilder::new(runtime.into_state(false)).build();

    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("http://example.com:8080/health")
                .body(Body::empty())
                .expect("absolute-uri health request"),
        )
        .await
        .expect("absolute-uri health response");

    assert_eq!(response.status(), 200);
}
