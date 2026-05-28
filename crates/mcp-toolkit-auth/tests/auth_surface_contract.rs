use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use http::{header::CONTENT_TYPE, Request, Response, StatusCode};
use mcp_toolkit_auth::surface::{
    AuthSurfaceConfig, AuthSurfaceLayer, AuthorizationServerMetadataSource, IssuerEntry,
};
use mcp_toolkit_auth::{AuthConfig, AuthMode, Authenticator, AuthorizationServerMetadata};
use mcp_toolkit_http::oauth::{GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_DEVICE_CODE};
use mcp_toolkit_testing::auth_surface_contract::AuthSurfaceContract;
use serde_json::{json, Value};
use tower::{service_fn, Layer, Service};

fn test_authenticator() -> Arc<Authenticator> {
    let config = AuthConfig {
        mode: AuthMode::Delegation,
        delegation_secret: Some("secret".to_string()),
        delegation_issuer: "https://issuer.example".to_string(),
        delegation_audience: "https://example.test/mcp".to_string(),
        ..AuthConfig::default()
    };
    Arc::new(Authenticator::new(config).expect("authenticator"))
}

#[tokio::test]
async fn auth_surface_contract_serves_discovery_and_challenges_missing_token() {
    let contract = AuthSurfaceContract::new(
        "https://example.test/mcp",
        &["https://issuer.example"],
        &["tool:read", "tool:write"],
        "toolkit-test",
    );

    let entry = IssuerEntry::from_metadata_source(
        "/mcp",
        AuthorizationServerMetadataSource::Explicit(AuthorizationServerMetadata {
            issuer: "https://issuer.example".to_string(),
            authorization_endpoint: "https://issuer.example/oauth/authorize".to_string(),
            token_endpoint: "https://issuer.example/oauth/token".to_string(),
            registration_endpoint: None,
            jwks_uri: None,
            introspection_endpoint: None,
            device_authorization_endpoint: Some("https://issuer.example/oauth/device".to_string()),
            grant_types_supported: Some(vec![
                GRANT_TYPE_AUTHORIZATION_CODE.to_string(),
                GRANT_TYPE_DEVICE_CODE.to_string(),
            ]),
        }),
        "toolkit-test",
        vec!["tool:read".to_string(), "tool:write".to_string()],
        HashSet::new(),
        test_authenticator(),
        Some("https://example.test/mcp".to_string()),
    )
    .expect("issuer entry");

    let service_counter = Arc::new(AtomicUsize::new(0));
    let service_counter_clone = service_counter.clone();
    let inner = service_fn(move |_req: Request<Body>| {
        let service_counter = service_counter_clone.clone();
        async move {
            service_counter.fetch_add(1, Ordering::SeqCst);
            Ok::<_, Infallible>(Response::new(Body::from("ok")))
        }
    });

    let layer = AuthSurfaceLayer::from_config(AuthSurfaceConfig::single_issuer(
        "https://example.test",
        entry,
    ))
    .expect("auth surface layer");

    let mut service = layer.layer(inner);

    let discovery_response = service
        .call(
            Request::builder()
                .uri("/.well-known/oauth-protected-resource/mcp")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("discovery response");
    let (parts, body) = discovery_response.into_parts();
    assert_eq!(parts.status, StatusCode::OK);
    assert_eq!(
        parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let payload_bytes = to_bytes(body, usize::MAX).await.expect("discovery body");
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("discovery json");
    contract.assert_resource_metadata(&payload);

    let authorization_response = service
        .call(
            Request::builder()
                .uri("/.well-known/oauth-authorization-server/mcp")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("authorization metadata response");
    let (parts, body) = authorization_response.into_parts();
    assert_eq!(parts.status, StatusCode::OK);
    assert_eq!(
        parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let payload_bytes = to_bytes(body, usize::MAX)
        .await
        .expect("authorization metadata body");
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("authorization json");
    assert_eq!(
        payload,
        json!({
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/oauth/authorize",
            "token_endpoint": "https://issuer.example/oauth/token",
            "device_authorization_endpoint": "https://issuer.example/oauth/device",
            "grant_types_supported": [
                GRANT_TYPE_AUTHORIZATION_CODE,
                GRANT_TYPE_DEVICE_CODE,
            ],
        })
    );

    let challenge_response = service
        .call(
            Request::builder()
                .uri("/mcp")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("challenge response");
    let (parts, body) = challenge_response.into_parts();
    assert_eq!(parts.status, StatusCode::UNAUTHORIZED);
    let challenge = parts
        .headers
        .get(http::header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .expect("challenge header");
    contract.assert_missing_token_challenge(challenge);

    let challenge_body = to_bytes(body, usize::MAX).await.expect("challenge body");
    assert_eq!(challenge_body.as_ref(), b"missing token");
    assert_eq!(service_counter.load(Ordering::SeqCst), 0);
}
