#![cfg(feature = "http")]

use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use mcp_toolkit_server::{
    http::{LocalMcpHttpRouterBuilder, LocalMcpHttpRuntimeBuilder, LocalMcpHttpServerBuilder},
    rmcp::{
        handler::server::{router::tool::ToolRouter, wrapper::Parameters},
        model::{ServerCapabilities, ServerInfo},
        schemars, tool, tool_router, ServerHandler,
    },
};
use tower::ServiceExt;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct EchoRequest {
    value: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TestMcp {
    tool_router: ToolRouter<Self>,
}

impl TestMcp {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl TestMcp {
    #[tool(description = "Echo a value")]
    fn echo(&self, Parameters(EchoRequest { value }): Parameters<EchoRequest>) -> String {
        value
    }
}

impl ServerHandler for TestMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("test server")
    }
}

const INIT_BODY: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;
const ACCEPT_STREAMABLE: &str = "application/json, text/event-stream";

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
                .body(Body::from(INIT_BODY))
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
