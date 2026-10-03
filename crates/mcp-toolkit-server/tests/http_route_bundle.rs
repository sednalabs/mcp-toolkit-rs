#![cfg(feature = "http")]

use axum::{
    body::Body,
    http::{HeaderValue, Request},
};
use http_body_util::BodyExt;
use mcp_toolkit_http::native_event_store::{NativeEventStore, NativeEventStoreConfig};
use mcp_toolkit_server::{
    http::{LocalMcpHttpRouterBuilder, LocalMcpHttpRuntimeBuilder, LocalMcpHttpServerBuilder},
    rmcp::{
        handler::server::{router::tool::ToolRouter, wrapper::Parameters},
        model::{ServerCapabilities, ServerConfig},
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
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("test server")
    }
}

#[derive(Clone)]
struct ProgressMcp;

impl ServerHandler for ProgressMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn call_tool(
        &self,
        _request: mcp_toolkit_server::rmcp::model::CallToolRequestParams,
        context: mcp_toolkit_server::rmcp::service::RequestContext<
            mcp_toolkit_server::rmcp::RoleServer,
        >,
    ) -> Result<
        mcp_toolkit_server::rmcp::model::CallToolResponse,
        mcp_toolkit_server::rmcp::ErrorData,
    > {
        use mcp_toolkit_server::rmcp::model::{
            CallToolResult, ContentBlock, ProgressNotificationParam,
        };

        let progress_token = context.meta.get_progress_token().expect("progress token");
        context
            .peer
            .notify_progress(
                ProgressNotificationParam::new(progress_token, 50.0)
                    .with_total(100.0)
                    .with_message("working"),
            )
            .await
            .expect("progress notification");
        Ok(CallToolResult::success(vec![ContentBlock::text("done")]).into())
    }
}

const ACCEPT_STREAMABLE: &str = "application/json, text/event-stream";

fn init_body() -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": mcp_toolkit_server::rmcp::model::ProtocolVersion::LATEST_WITH_INITIALIZE,
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
async fn current_protocol_post_replays_later_event_without_initialize_or_session_id() {
    let store = std::sync::Arc::new(
        NativeEventStore::new(NativeEventStoreConfig::default()).expect("native event store"),
    );
    let runtime = LocalMcpHttpRuntimeBuilder::new()
        .allowed_hosts(["127.0.0.1"])
        .allowed_origins(["https://allowed.example"])
        .with_event_store(store)
        .build(|| Ok(ProgressMcp));
    let router = LocalMcpHttpRouterBuilder::new(runtime.into_state(false)).build();
    let original = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header("accept", ACCEPT_STREAMABLE)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "progress")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"progress","arguments":{},"_meta":{"progressToken":"progress-1","io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1.0"},"io.modelcontextprotocol/clientCapabilities":{}}}}"#,
                ))
                .expect("current protocol request"),
        )
        .await
        .expect("POST response");
    assert_eq!(original.status(), 200);
    assert!(!original.headers().contains_key("mcp-session-id"));
    let body = original
        .into_body()
        .collect()
        .await
        .expect("POST body")
        .to_bytes();
    let body = String::from_utf8(body.to_vec())
        .expect("SSE body is UTF-8")
        .replace("\r\n", "\n");
    let anchor = body
        .split("\n\n")
        .find(|event| event.contains("notifications/progress"))
        .and_then(|event| event.lines().find_map(|line| line.strip_prefix("id: ")))
        .expect("progress event has a native replay ID")
        .to_owned();
    assert!(
        body.contains(r#""id":2"#),
        "POST includes final response: {body}"
    );
    let response_id = body
        .split("\n\n")
        .find(|event| event.contains(r#""id":2"#))
        .and_then(|event| event.lines().find_map(|line| line.strip_prefix("id: ")))
        .expect("response event has a native replay ID")
        .to_owned();

    let replay = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header("accept", "text/event-stream")
                .header("mcp-protocol-version", "2026-07-28")
                .header("last-event-id", &anchor)
                .body(Body::empty())
                .expect("replay request"),
        )
        .await
        .expect("replay response");
    assert_eq!(replay.status(), 200);
    assert!(!replay.headers().contains_key("mcp-session-id"));
    let body = replay
        .into_body()
        .collect()
        .await
        .expect("replay body")
        .to_bytes();
    let body = String::from_utf8(body.to_vec())
        .expect("replay SSE body is UTF-8")
        .replace("\r\n", "\n");
    assert!(
        body.contains(r#""id":2"#),
        "GET replays later response: {body}"
    );
    assert!(body.contains(&format!("id: {response_id}")));
    assert!(!body.contains(&format!("id: {anchor}")));

    let unknown = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header("accept", "text/event-stream")
                .header("mcp-protocol-version", "2026-07-28")
                .header("last-event-id", "unknown-anchor")
                .body(Body::empty())
                .expect("unknown anchor request"),
        )
        .await
        .expect("unknown anchor response");
    assert_eq!(unknown.status(), 200);
    let unknown_body = unknown
        .into_body()
        .collect()
        .await
        .expect("unknown anchor body")
        .to_bytes();
    assert!(!String::from_utf8_lossy(&unknown_body).contains(r#""id":2"#));

    let denied = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header("origin", "https://denied.example")
                .header("accept", "text/event-stream")
                .header("mcp-protocol-version", "2026-07-28")
                .header("last-event-id", &anchor)
                .body(Body::empty())
                .expect("denied replay request"),
        )
        .await
        .expect("denied replay response");
    assert_eq!(denied.status(), 403);
    let denied_body = denied
        .into_body()
        .collect()
        .await
        .expect("denial body")
        .to_bytes();
    assert!(!String::from_utf8_lossy(&denied_body).contains(r#""id":2"#));
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
async fn route_bundle_rejects_oversized_stateful_post() {
    let router = LocalMcpHttpServerBuilder::new()
        .allowed_hosts(["127.0.0.1"])
        .max_request_body_bytes(1024)
        .build(|| Ok(TestMcp::new()));

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
    assert_eq!(initialize_response.status(), 200);
    let session_id = initialize_response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .expect("live session id")
        .to_string();

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header("accept", ACCEPT_STREAMABLE)
                .header("content-type", "application/json")
                .header("mcp-session-id", session_id)
                .body(Body::from(vec![b' '; 1025]))
                .expect("oversized stateful request"),
        )
        .await
        .expect("oversized stateful response");

    assert_eq!(response.status(), 413);
}

#[tokio::test]
async fn route_bundle_rejects_present_unusable_sessions_before_stateless_fallback() {
    let runtime = LocalMcpHttpRuntimeBuilder::new()
        .allowed_hosts(["127.0.0.1"])
        .stateless_fallback(true)
        .build(|| Ok(TestMcp::new()));
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
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
                ))
                .expect("live session request"),
        )
        .await
        .expect("live session response");
    assert_eq!(live_response.status(), 200);

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
                "hint": "Re-initialize a legacy session or use MCP 2026-07-28 stateless requests.",
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
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}"#,
                ))
                .expect("headerless request"),
        )
        .await
        .expect("headerless stateless response");
    assert_eq!(headerless_response.status(), 200);
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
