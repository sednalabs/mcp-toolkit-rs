#![cfg(feature = "http")]

use axum::{body::Body, extract::State};
use http::{
    header::{ACCEPT, CONTENT_TYPE, HOST},
    Request, StatusCode,
};
use http_body_util::BodyExt;
use mcp_toolkit_server::http::{handle_mcp, LocalMcpHttpRuntimeBuilder};
use rmcp::{
    model::{ServerCapabilities, ServerInfo},
    transport::common::http_header::{HEADER_MCP_PROTOCOL_VERSION, HEADER_SESSION_ID},
    ServerHandler,
};
use serde_json::{json, Value};

const CURRENT_PROTOCOL: &str = "2026-07-28";
const PROTOCOL_VERSION_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_INFO_META_KEY: &str = "io.modelcontextprotocol/clientInfo";
const CLIENT_CAPABILITIES_META_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
const ACCEPT_STREAMABLE: &str = "application/json, text/event-stream";

#[derive(Debug, Clone)]
struct EmptyToolServer;

impl ServerHandler for EmptyToolServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("HTTP current-protocol contract test server")
    }
}

fn current_tools_list_body() -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
            "_meta": {
                PROTOCOL_VERSION_META_KEY: CURRENT_PROTOCOL,
                CLIENT_INFO_META_KEY: {
                    "name": "mcp-toolkit-http-contract",
                    "version": "0.0.0"
                },
                CLIENT_CAPABILITIES_META_KEY: {}
            }
        }
    })
    .to_string()
}

fn current_request() -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("http://127.0.0.1/mcp")
        .header(HOST, "127.0.0.1")
        .header(ACCEPT, ACCEPT_STREAMABLE)
        .header(CONTENT_TYPE, "application/json")
        .header(HEADER_MCP_PROTOCOL_VERSION, CURRENT_PROTOCOL)
        .body(Body::from(current_tools_list_body()))
        .expect("current MCP request")
}

async fn assert_current_tools_list_response(response: axum::response::Response) {
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !response.headers().contains_key(HEADER_SESSION_ID),
        "MCP 2026-07-28 requests must not create legacy session state"
    );

    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    let payload: Value = serde_json::from_slice(&body).expect("JSON-RPC response JSON");
    assert_eq!(payload["jsonrpc"], json!("2.0"));
    assert_eq!(payload["id"], json!(1));
    assert!(payload.get("error").is_none(), "unexpected error: {payload}");
    assert!(
        payload["result"]["tools"].is_array(),
        "expected tools/list result: {payload}"
    );
}

#[tokio::test]
async fn current_protocol_post_is_stateless_without_initialize() {
    let runtime = LocalMcpHttpRuntimeBuilder::new()
        .allowed_hosts(["127.0.0.1", "localhost"])
        .build(|| Ok(EmptyToolServer));
    let state = runtime.into_state(false);

    let response = handle_mcp(State(state), current_request()).await;
    assert_current_tools_list_response(response).await;
}

#[tokio::test]
async fn current_protocol_post_bypasses_legacy_session_preflight() {
    let runtime = LocalMcpHttpRuntimeBuilder::new()
        .allowed_hosts(["127.0.0.1", "localhost"])
        .build(|| Ok(EmptyToolServer));
    let state = runtime.into_state(false);
    let mut request = current_request();
    request
        .headers_mut()
        .insert(HEADER_SESSION_ID, "stale-legacy-session".parse().unwrap());

    let response = handle_mcp(State(state), request).await;
    assert_current_tools_list_response(response).await;
}
