use axum::body::{to_bytes, Body};
use hosted_http_auth_server::{build_router, HostedHttpConfig};
use http::{header, Request, StatusCode};
use mcp_toolkit_testing::auth_surface_contract::AuthSurfaceContract;
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn health_is_public_and_host_guarded() {
    let router = build_router(HostedHttpConfig::local_dev()).expect("router");

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
    assert_eq!(health.status(), StatusCode::OK);

    let bad_host = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("host", "example.com")
                .body(Body::empty())
                .expect("bad-host health request"),
        )
        .await
        .expect("bad-host health response");
    assert_eq!(bad_host.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn auth_surface_serves_prm_and_challenges_missing_token() {
    let config = HostedHttpConfig::local_dev();
    let contract = AuthSurfaceContract::new(
        "http://127.0.0.1:9411/mcp",
        &["http://issuer.example"],
        &["example.read"],
        "example",
    );
    let router = build_router(config).expect("router");

    let discovery = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/oauth-protected-resource/mcp")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .expect("discovery request"),
        )
        .await
        .expect("discovery response");
    let (parts, body) = discovery.into_parts();
    assert_eq!(parts.status, StatusCode::OK);
    let bytes = to_bytes(body, usize::MAX).await.expect("discovery body");
    let payload: Value = serde_json::from_slice(&bytes).expect("discovery json");
    contract.assert_resource_metadata(&payload);

    let challenge = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                ))
                .expect("initialize request"),
        )
        .await
        .expect("challenge response");
    let (parts, _body) = challenge.into_parts();
    assert_eq!(parts.status, StatusCode::UNAUTHORIZED);
    let header = parts
        .headers
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .expect("bearer challenge");
    contract.assert_missing_token_challenge(header);
}
