//! # Optional MCP Apps tool-list security metadata projection
//!
//! RMCP 3.x models can carry a tool's `_meta.securitySchemes`, but some
//! ChatGPT Apps hosts additionally require the same schemes on the descriptor's
//! top-level `securitySchemes` field. This opt-in Axum middleware performs
//! the final projection on bounded JSON responses from a hosted MCP route.
//!
//! It never authenticates a caller, adds scopes, touches tool-call arguments or
//! buffers SSE subscription streams. The caller must supply the correct
//! per-tool metadata and preserve the normal OAuth enforcement layers.

use axum::{
    body::{to_bytes, Body},
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{
    header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG},
    Method, StatusCode,
};
use mcp_toolkit_core::mcp_apps::normalize_mcp_apps_security_schemes_in_tools_list_payload;
use serde_json::Value;

/// Maximum body buffered by the optional Apps JSON projection (256 KiB).
pub const APPS_TOOL_LIST_JSON_LIMIT_BYTES: usize = 256 * 1024;

/// Project the tool security schemes into a JSON-RPC `tools/list` response.
///
/// Install only on the MCP route, after the server's OAuth protection, e.g.
/// `router.layer(axum::middleware::from_fn(mirror_apps_tool_security_schemes))`.
///
/// The response must be a successful, uncompressed JSON response. SSE streams,
/// other methods, errors and non-JSON responses pass through untouched.
/// Content-Length and ETag are dropped only when JSON bytes are rewritten.
/// Unbounded bodies are rejected with 502 rather than buffered indefinitely.
///
/// # Security
///
/// This is presentation metadata only. The caller must continue to enforce
/// issuer, audience, scope and domain authorisation before tool execution.
/// The scheme source is the tool's `_meta.securitySchemes` or its existing
/// descriptor field, never data supplied by an IRC message or untrusted caller.
///
/// # Errors
///
/// This middleware responds 502 if an eligible JSON body cannot be read within
/// the configured 256 KiB maximum. It does not modify OAuth failure responses.
pub async fn mirror_apps_tool_security_schemes(request: Request, next: Next) -> Response {
    if request.method() != Method::POST {
        return next.run(request).await;
    }
    // Standard modern MCP hosts send Mcp-Method. Headerless clients are still
    // supported: the response shape then determines whether projection applies.
    if let Some(method) = request.headers().get("mcp-method") {
        if method.to_str().ok() != Some("tools/list") {
            return next.run(request).await;
        }
    }

    let response = next.run(request).await;
    if response.status() != StatusCode::OK
        || response.headers().contains_key(CONTENT_ENCODING)
        || !response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|content_type| content_type.starts_with("application/json"))
    {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let bytes = match to_bytes(body, APPS_TOOL_LIST_JSON_LIMIT_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "MCP Apps tool list response exceeds the byte limit.")
                .into_response();
        }
    };
    let replacement = project_tool_list_payload(&bytes);
    if let Some(body) = replacement {
        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.remove(ETAG);
        return Response::from_parts(parts, Body::from(body));
    }
    Response::from_parts(parts, Body::from(bytes))
}

fn project_tool_list_payload(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(bytes).ok()?;
    (normalize_mcp_apps_security_schemes_in_tools_list_payload(&mut value) != 0)
        .then(|| serde_json::to_vec(&value).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::{mirror_apps_tool_security_schemes, project_tool_list_payload};
    use axum::{
        body::{to_bytes, Body},
        http::{header, Request, StatusCode},
        middleware,
        response::{IntoResponse, Response},
        routing::post,
        Json, Router,
    };
    use serde_json::{json, Value};
    use tower::ServiceExt;

    fn tool_payload() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "result": {
                "tools": [
                    {
                        "name": "items.read",
                        "inputSchema": {"type": "object"},
                        "_meta": {
                            "securitySchemes": [{"type": "oauth2", "scopes": ["items:read"]}],
                            "ui": {"visibility": ["model"]}
                        }
                    }
                ],
                "nextCursor": "next-page"
            }
        })
    }

    async fn read_response(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[test]
    fn projects_only_missing_descriptor_scheme_and_keeps_existing_metadata() {
        let input = tool_payload();
        let updated = project_tool_list_payload(input.to_string().as_bytes()).unwrap();
        let value: Value = serde_json::from_slice(&updated).unwrap();
        assert_eq!(
            value["result"]["tools"][0]["securitySchemes"],
            input["result"]["tools"][0]["_meta"]["securitySchemes"]
        );
        assert_eq!(
            value["result"]["tools"][0]["_meta"]["ui"]["visibility"],
            json!(["model"])
        );
        assert_eq!(value["result"]["nextCursor"], "next-page");
        assert!(project_tool_list_payload(&updated).is_none());
    }

    #[test]
    fn does_not_rewrite_non_tool_responses() {
        let input = json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"hello"}]}});
        assert!(project_tool_list_payload(input.to_string().as_bytes()).is_none());
        assert!(project_tool_list_payload(b"not-json").is_none());
    }

    #[tokio::test]
    async fn actual_http_json_has_descriptor_scheme_and_valid_body_length() {
        let app = Router::new()
            .route("/mcp", post(|| async { Json(tool_payload()) }))
            .layer(middleware::from_fn(mirror_apps_tool_security_schemes));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("mcp-method", "tools/list")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!response.headers().contains_key(header::CONTENT_LENGTH));
        let (status, result) = read_response(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            result["result"]["tools"][0]["securitySchemes"],
            result["result"]["tools"][0]["_meta"]["securitySchemes"]
        );
    }

    #[tokio::test]
    async fn does_not_buffer_or_rewrite_sse_or_unrelated_mcp_methods() {
        let app = Router::new()
            .route(
                "/mcp",
                post(|| async {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .body(Body::from("event: message\ndata: test\n\n"))
                        .unwrap()
                }),
            )
            .layer(middleware::from_fn(mirror_apps_tool_security_schemes));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("mcp-method", "tools/list")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/event-stream"
        );
        let body = to_bytes(response.into_body(), 100).await.unwrap();
        assert_eq!(body.as_ref(), b"event: message\ndata: test\n\n");

        let app = Router::new()
            .route("/mcp", post(|| async { Json(tool_payload()) }))
            .layer(middleware::from_fn(mirror_apps_tool_security_schemes));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("mcp-method", "tools/call")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (_, result) = read_response(response).await;
        assert!(result["result"]["tools"][0].get("securitySchemes").is_none());
    }

    #[tokio::test]
    async fn does_not_mutate_denied_oauth_responses() {
        let app = Router::new()
            .route(
                "/mcp",
                post(|| async {
                    (
                        StatusCode::UNAUTHORIZED,
                        [(header::WWW_AUTHENTICATE, "Bearer realm=\"irc\"")],
                        Json(tool_payload()),
                    )
                        .into_response()
                }),
            )
            .layer(middleware::from_fn(mirror_apps_tool_security_schemes));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer realm=\"irc\""
        );
        let (status, result) = read_response(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(result["result"]["tools"][0].get("securitySchemes").is_none());
    }
}
