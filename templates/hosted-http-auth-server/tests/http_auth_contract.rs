use axum::body::{to_bytes, Body};
use hosted_http_auth_server::{build_router, HostedHttpConfig};
use http::{Request, StatusCode};
use mcp_toolkit_testing::auth_surface_contract::{
    assert_forbidden_without_bearer_challenge, AuthSurfaceContract,
    AuthorizationServerMetadataContract,
};
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn health_is_public_and_host_origin_guarded() {
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

    let allowed_origin = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("host", "127.0.0.1")
                .header("origin", "http://127.0.0.1:9411")
                .body(Body::empty())
                .expect("allowed-origin health request"),
        )
        .await
        .expect("allowed-origin health response");
    assert_eq!(allowed_origin.status(), StatusCode::OK);

    let bad_host = router
        .clone()
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

    let bad_origin = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("host", "127.0.0.1")
                .header("origin", "https://example.com")
                .body(Body::empty())
                .expect("bad-origin health request"),
        )
        .await
        .expect("bad-origin health response");
    assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);
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

    let authorization_metadata = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/oauth-authorization-server/mcp")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .expect("authorization metadata request"),
        )
        .await
        .expect("authorization metadata response");
    let (parts, body) = authorization_metadata.into_parts();
    assert_eq!(parts.status, StatusCode::OK);
    let bytes = to_bytes(body, usize::MAX)
        .await
        .expect("authorization metadata body");
    let payload: Value = serde_json::from_slice(&bytes).expect("authorization metadata json");
    AuthorizationServerMetadataContract::new(
        "http://issuer.example",
        "http://issuer.example/oauth/authorize",
        "http://issuer.example/oauth/token",
    )
    .with_device_authorization_endpoint("http://issuer.example/oauth/device")
    .with_grant_types_supported(&[
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:device_code",
    ])
    .assert_metadata(&payload);

    let post_challenge = router
        .clone()
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
        .expect("post challenge response");
    let (parts, _body) = post_challenge.into_parts();
    contract.assert_missing_token_response(parts.status, &parts.headers);

    let get_challenge = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .expect("get challenge request"),
        )
        .await
        .expect("get challenge response");
    let (parts, _body) = get_challenge.into_parts();
    contract.assert_missing_token_response(parts.status, &parts.headers);
}

#[tokio::test]
async fn mcp_route_rejects_bad_hosts_before_auth_challenge() {
    let router = build_router(HostedHttpConfig::local_dev()).expect("router");

    let post_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "example.com")
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                ))
                .expect("bad-host post request"),
        )
        .await
        .expect("bad-host post response");
    assert_forbidden_without_bearer_challenge(post_response.status(), post_response.headers());

    let get_response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header("host", "example.com")
                .body(Body::empty())
                .expect("bad-host get request"),
        )
        .await
        .expect("bad-host get response");
    assert_forbidden_without_bearer_challenge(get_response.status(), get_response.headers());
}
