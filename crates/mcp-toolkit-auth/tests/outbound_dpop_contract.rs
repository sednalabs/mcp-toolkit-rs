use std::collections::VecDeque;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::jwk::ThumbprintHash;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use mcp_toolkit_auth::outbound_dpop::{
    canonical_dpop_target, DpopAuthorization, DpopSigner, DpopTokenExchangeClient,
    DpopTokenExchangeConfig, OutboundDpopError, Rfc8693TokenExchangeRequest,
    TokenExchangeAuditMetadata, RFC8693_ACCESS_TOKEN_TYPE, RFC8693_GRANT_TYPE,
};
use mcp_toolkit_auth::upstream_oauth::SecretString;
use reqwest::Url;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

#[derive(Clone)]
struct ScriptedResponse {
    status: StatusCode,
    headers: Vec<(&'static str, &'static str)>,
    body: String,
}

impl ScriptedResponse {
    fn json(status: StatusCode, headers: Vec<(&'static str, &'static str)>, body: Value) -> Self {
        Self {
            status,
            headers,
            body: body.to_string(),
        }
    }
}

#[derive(Clone)]
struct RecordedRequest {
    headers: HeaderMap,
    body: String,
}

struct ScriptState {
    responses: Mutex<VecDeque<ScriptedResponse>>,
    requests: Mutex<Vec<RecordedRequest>>,
}

async fn scripted_token_endpoint(
    State(state): State<Arc<ScriptState>>,
    headers: HeaderMap,
    body: String,
) -> Response<Body> {
    state
        .requests
        .lock()
        .await
        .push(RecordedRequest { headers, body });
    let scripted = state
        .responses
        .lock()
        .await
        .pop_front()
        .unwrap_or_else(|| ScriptedResponse {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            headers: Vec::new(),
            body: "missing scripted response".to_string(),
        });
    let mut response = (scripted.status, scripted.body).into_response();
    for (name, value) in scripted.headers {
        response.headers_mut().insert(
            http::header::HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    response
}

async fn start_scripted_server(
    responses: Vec<ScriptedResponse>,
) -> (
    Url,
    Arc<ScriptState>,
    tokio::task::JoinHandle<Result<(), std::io::Error>>,
) {
    let state = Arc::new(ScriptState {
        responses: Mutex::new(responses.into()),
        requests: Mutex::new(Vec::new()),
    });
    let app = Router::new()
        .route("/token", post(scripted_token_endpoint))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind scripted token endpoint");
    let address = listener.local_addr().expect("scripted endpoint address");
    let handle = tokio::spawn(async move { axum::serve(listener, app).await });
    let endpoint = Url::parse(&format!("http://{address}/token")) // DevSkim: ignore DS137138 loopback test fixture
        .expect("token endpoint URL");
    (endpoint, state, handle)
}

fn audit() -> TokenExchangeAuditMetadata {
    TokenExchangeAuditMetadata::new("exchange-1", "subject-1", "client-1").expect("audit metadata")
}

fn exchange_request() -> Rfc8693TokenExchangeRequest {
    Rfc8693TokenExchangeRequest::new(SecretString::new("subject-token-secret"), audit())
        .expect("exchange request")
        .with_audience("https://resource.example")
        .expect("audience")
        .with_scopes(vec!["read".to_string(), "write".to_string()])
        .expect("scopes")
}

fn exchange_client(endpoint: Url) -> DpopTokenExchangeClient {
    let config = DpopTokenExchangeConfig::new_allow_insecure_loopback(
        endpoint,
        "client-id",
        Some(SecretString::new("client-secret")),
    )
    .expect("token exchange config");
    DpopTokenExchangeClient::new(config, DpopSigner::generate().expect("DPoP signer"))
        .expect("token exchange client")
}

fn decode_proof(compact: &str) -> (jsonwebtoken::Header, Value) {
    let header = decode_header(compact).expect("proof header");
    let jwk = header.jwk.as_ref().expect("proof JWK");
    let key = DecodingKey::from_jwk(jwk).expect("proof decoding key");
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    let decoded: TokenData<Value> = decode(compact, &key, &validation).expect("verified proof");
    (header, decoded.claims)
}

fn proof_from_authorization(authorization: &DpopAuthorization, target: &Url) -> Value {
    let request = authorization
        .apply(reqwest::Client::new().get(target.clone()))
        .build()
        .expect("resource request");
    let compact = request
        .headers()
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .expect("DPoP request header");
    decode_proof(compact).1
}

#[test]
fn signer_produces_verified_jwk_bound_ath_and_canonical_target() {
    let signer = DpopSigner::generate().expect("DPoP signer");
    let target = Url::parse(
        "https://user:password@resource.example:443/v1/items?access_token=query-secret#fragment",
    )
    .expect("resource URL");
    let token = SecretString::new("access-token-secret");
    let proof = signer
        .resource_proof(Method::PATCH, &target, &token, Some("resource-nonce"))
        .expect("resource proof");
    let (header, claims) = decode_proof(proof.expose_secret());

    let jwk = header.jwk.expect("public proof JWK");
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.typ.as_deref(), Some("dpop+jwt"));
    assert_eq!(&jwk, signer.public_jwk().as_jwk());
    assert_eq!(
        jwk.thumbprint(ThumbprintHash::SHA256),
        signer.public_jwk().thumbprint()
    );
    assert_eq!(claims["htu"], "https://resource.example/v1/items");
    assert_eq!(claims["htm"], "PATCH");
    assert_eq!(claims["nonce"], "resource-nonce");
    assert!(claims["iat"].as_u64().is_some());
    assert!(claims["jti"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(
        claims["ath"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(b"access-token-secret"))
    );
    assert_eq!(
        canonical_dpop_target(&target).expect("canonical target"),
        "https://resource.example/v1/items"
    );
}

#[test]
fn canonical_target_rejects_non_loopback_cleartext() {
    let target = Url::parse("http://resource.example/items") // DevSkim: ignore DS137138 rejected negative test fixture
        .expect("resource URL");
    assert_eq!(
        canonical_dpop_target(&target),
        Err(OutboundDpopError::InsecureEndpoint)
    );
}

#[test]
fn exchange_request_requires_complete_audit_metadata_and_redacts_subject() {
    assert_eq!(
        TokenExchangeAuditMetadata::new("", "subject", "client"),
        Err(OutboundDpopError::InvalidField("exchange_id"))
    );
    assert_eq!(
        TokenExchangeAuditMetadata::new("exchange", "", "client"),
        Err(OutboundDpopError::InvalidField("audit_subject"))
    );
    assert_eq!(
        TokenExchangeAuditMetadata::new("exchange", "subject", ""),
        Err(OutboundDpopError::InvalidField("audit_actor_client"))
    );

    let request = exchange_request();
    let rendered = format!("{request:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("subject-token-secret"));
    assert!(!rendered.contains("subject-1"));
}

#[tokio::test]
async fn token_exchange_retries_one_nonce_and_keeps_resource_nonces_isolated() {
    let responses = vec![
        ScriptedResponse::json(
            StatusCode::BAD_REQUEST,
            vec![("dpop-nonce", "token-endpoint-nonce")],
            json!({"error": "use_dpop_nonce"}),
        ),
        ScriptedResponse::json(
            StatusCode::OK,
            Vec::new(),
            json!({
                "access_token": "issued-access-secret",
                "issued_token_type": RFC8693_ACCESS_TOKEN_TYPE,
                "token_type": "DPoP",
                "expires_in": 60,
                "scope": "read write"
            }),
        ),
    ];
    let (endpoint, state, server) = start_scripted_server(responses).await;
    let client = exchange_client(endpoint.clone());
    let token = client
        .exchange(&exchange_request())
        .await
        .expect("DPoP token exchange");

    assert_eq!(token.access_token().expose_secret(), "issued-access-secret");
    assert_eq!(token.issued_token_type(), Some(RFC8693_ACCESS_TOKEN_TYPE));
    assert_eq!(token.expires_in(), Some(60));
    assert_eq!(token.scope(), Some("read write"));
    assert_eq!(token.proof_thumbprint(), client.public_jwk().thumbprint());

    let requests = state.requests.lock().await.clone();
    assert_eq!(requests.len(), 2);
    assert!(requests[0]
        .body
        .contains(&format!("grant_type={}", urlencoding(RFC8693_GRANT_TYPE))));
    assert!(requests[0]
        .body
        .contains("subject_token=subject-token-secret"));
    assert!(!requests[0].body.contains("exchange-1"));
    assert!(!requests[0].body.contains("subject-1"));
    let first_proof = requests[0]
        .headers
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .expect("first proof");
    let second_proof = requests[1]
        .headers
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .expect("second proof");
    let first_claims = decode_proof(first_proof).1;
    let second_claims = decode_proof(second_proof).1;
    assert_eq!(first_claims.get("nonce"), None);
    assert_eq!(second_claims["nonce"], "token-endpoint-nonce");
    assert_eq!(second_claims["htu"], endpoint.as_str());
    assert_eq!(second_claims["htm"], "POST");
    assert_eq!(second_claims.get("ath"), None);

    let first_target =
        Url::parse("https://resource.example/v1/items?ignored=yes").expect("first target");
    let second_target = Url::parse("https://resource.example/v1/other").expect("second target");
    let mut get_request = client
        .resource_request(&token, Method::GET, first_target.clone())
        .expect("GET resource request");
    let first_resource_claims = proof_from_authorization(
        &get_request.authorization().expect("first authorization"),
        &first_target,
    );
    assert_eq!(first_resource_claims.get("nonce"), None);

    let mut challenge_headers = HeaderMap::new();
    challenge_headers.insert("dpop-nonce", HeaderValue::from_static("get-items-nonce"));
    assert!(get_request
        .accept_nonce_challenge(StatusCode::UNAUTHORIZED, &challenge_headers)
        .expect("eligible resource nonce challenge"));
    let retried_claims = proof_from_authorization(
        &get_request.authorization().expect("retry authorization"),
        &first_target,
    );
    assert_eq!(retried_claims["nonce"], "get-items-nonce");
    assert_eq!(
        retried_claims["ath"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(b"issued-access-secret"))
    );
    assert_eq!(
        get_request.accept_nonce_challenge(StatusCode::UNAUTHORIZED, &challenge_headers),
        Err(OutboundDpopError::NonceRetryLimitReached)
    );

    let post_request = client
        .resource_request(&token, Method::POST, first_target.clone())
        .expect("POST resource request");
    assert_eq!(
        proof_from_authorization(
            &post_request.authorization().expect("POST authorization"),
            &first_target
        )
        .get("nonce"),
        None
    );
    let other_request = client
        .resource_request(&token, Method::GET, second_target.clone())
        .expect("other resource request");
    assert_eq!(
        proof_from_authorization(
            &other_request.authorization().expect("other authorization"),
            &second_target
        )
        .get("nonce"),
        None
    );

    server.abort();
}

#[tokio::test]
async fn repeated_token_endpoint_nonce_challenge_fails_after_one_retry() {
    let challenge = || {
        ScriptedResponse::json(
            StatusCode::BAD_REQUEST,
            vec![("dpop-nonce", "retry-nonce")],
            json!({"error": "use_dpop_nonce"}),
        )
    };
    let (endpoint, state, server) = start_scripted_server(vec![challenge(), challenge()]).await;
    let error = exchange_client(endpoint)
        .exchange(&exchange_request())
        .await
        .expect_err("second challenge must fail");
    assert_eq!(error, OutboundDpopError::NonceRetryLimitReached);
    assert_eq!(state.requests.lock().await.len(), 2);
    server.abort();
}

#[tokio::test]
async fn token_exchange_fails_closed_on_unbound_broadened_or_refresh_results() {
    let cases = [
        (
            json!({"access_token": "issued", "token_type": "Bearer"}),
            OutboundDpopError::UnexpectedTokenType,
        ),
        (
            json!({"access_token": "issued", "token_type": "DPoP", "issued_token_type": "urn:example:other"}),
            OutboundDpopError::UnexpectedIssuedTokenType,
        ),
        (
            json!({"access_token": "issued", "token_type": "DPoP", "scope": "read admin"}),
            OutboundDpopError::BroadenedScopes,
        ),
        (
            json!({"access_token": "issued", "token_type": "DPoP", "refresh_token": "refresh-secret"}),
            OutboundDpopError::UnexpectedRefreshToken,
        ),
    ];

    for (body, expected) in cases {
        let (endpoint, _state, server) = start_scripted_server(vec![ScriptedResponse::json(
            StatusCode::OK,
            Vec::new(),
            body,
        )])
        .await;
        let actual = exchange_client(endpoint)
            .exchange(&exchange_request())
            .await
            .expect_err("unsafe response must fail closed");
        assert_eq!(actual, expected);
        server.abort();
    }
}

#[tokio::test]
async fn token_exchange_errors_and_debug_output_do_not_expose_secrets() {
    let leaked_body = json!({
        "error": "client_secret=client-secret",
        "error_description": "subject-token-secret issued-access-secret retry-nonce"
    });
    let (endpoint, _state, server) = start_scripted_server(vec![ScriptedResponse::json(
        StatusCode::UNAUTHORIZED,
        Vec::new(),
        leaked_body,
    )])
    .await;
    let signer = DpopSigner::generate().expect("DPoP signer");
    let proof = signer
        .token_endpoint_proof(&endpoint, Some("retry-nonce"))
        .expect("token endpoint proof");
    let config = DpopTokenExchangeConfig::new_allow_insecure_loopback(
        endpoint,
        "client-id",
        Some(SecretString::new("client-secret")),
    )
    .expect("token config");
    let client = DpopTokenExchangeClient::new(config.clone(), signer.clone()).expect("client");
    let request = exchange_request();
    let error = client
        .exchange(&request)
        .await
        .expect_err("endpoint rejection");
    match &error {
        OutboundDpopError::TokenEndpointRejected { status, code } => {
            assert_eq!(*status, StatusCode::UNAUTHORIZED);
            assert_eq!(code.as_str(), "token_endpoint_error");
        }
        other => panic!("unexpected endpoint error: {other:?}"),
    }

    let rendered =
        format!("{config:?} {signer:?} {proof:?} {client:?} {request:?} {error:?} {error}");
    for secret in [
        "client-secret",
        "subject-token-secret",
        "issued-access-secret",
        "retry-nonce",
        proof.expose_secret(),
    ] {
        assert!(!rendered.contains(secret), "diagnostics leaked a secret");
    }
    assert!(rendered.contains("token_endpoint_error"));
    server.abort();
}

#[tokio::test]
async fn token_response_size_is_bounded() {
    let (endpoint, _state, server) = start_scripted_server(vec![ScriptedResponse {
        status: StatusCode::OK,
        headers: Vec::new(),
        body: "x".repeat(64 * 1024 + 1),
    }])
    .await;
    let error = exchange_client(endpoint)
        .exchange(&exchange_request())
        .await
        .expect_err("oversized response");
    assert_eq!(
        error,
        OutboundDpopError::ResponseTooLarge {
            max_bytes: 64 * 1024
        }
    );
    server.abort();
}

fn urlencoding(value: &str) -> String {
    value.replace(':', "%3A").replace('/', "%2F")
}
