use std::collections::VecDeque;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

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
    canonical_dpop_target, BearerSubjectToken, DpopAccessToken, DpopAuthorization,
    DpopBoundAccessToken, DpopEndpointPolicy, DpopNonceState, DpopProviderValidationMetadata,
    DpopSigner, DpopTokenExchangeClient, DpopTokenExchangeConfig, OutboundDpopError,
    Rfc8693TokenExchangeRequest,
    TokenExchangeAuditMetadata, RFC8693_ACCESS_TOKEN_TYPE, RFC8693_GRANT_TYPE,
};
use mcp_toolkit_auth::upstream_oauth::{OAuthClientAuthMethod, SecretString};
use reqwest::Url;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify};

#[derive(Clone)]
struct ScriptedResponse {
    status: StatusCode,
    headers: Vec<(&'static str, &'static str)>,
    body: String,
    delay: Option<Duration>,
    location: Option<String>,
}

impl ScriptedResponse {
    fn json(
        status: StatusCode,
        mut headers: Vec<(&'static str, &'static str)>,
        body: Value,
    ) -> Self {
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        {
            headers.push(("content-type", "application/json"));
        }
        Self {
            status,
            headers,
            body: body.to_string(),
            delay: None,
            location: None,
        }
    }

    fn delayed_json(status: StatusCode, body: Value, delay: Duration) -> Self {
        Self {
            status,
            headers: vec![("content-type", "application/json")],
            body: body.to_string(),
            delay: Some(delay),
            location: None,
        }
    }

    fn redirect(location: String) -> Self {
        Self {
            status: StatusCode::FOUND,
            headers: Vec::new(),
            body: String::new(),
            delay: None,
            location: Some(location),
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
    request_seen: Notify,
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
            delay: None,
            location: None,
        });
    state.request_seen.notify_one();
    if let Some(delay) = scripted.delay {
        tokio::time::sleep(delay).await;
    }
    let mut response = (scripted.status, scripted.body).into_response();
    response.headers_mut().remove(http::header::CONTENT_TYPE);
    for (name, value) in scripted.headers {
        response.headers_mut().append(
            http::header::HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if let Some(location) = scripted.location {
        response.headers_mut().insert(
            http::header::LOCATION,
            HeaderValue::from_str(&location).expect("scripted redirect location"),
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
        request_seen: Notify::new(),
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
    Rfc8693TokenExchangeRequest::new(
        BearerSubjectToken::new(SecretString::new("subject-token-secret"))
            .expect("bearer subject token"),
        audit(),
    )
        .expect("exchange request")
        .with_audience("https://resource.example")
        .expect("audience")
        .with_scopes(vec!["read".to_string(), "write".to_string()])
        .expect("scopes")
}

fn exchange_client(endpoint: Url) -> DpopTokenExchangeClient {
    let policy = DpopEndpointPolicy::exact_loopback_http(endpoint.clone())
        .expect("loopback endpoint policy");
    let config = DpopTokenExchangeConfig::new(
        endpoint,
        policy,
        "client-id",
        Some(SecretString::new("client-secret")),
    )
    .expect("token exchange config");
    DpopTokenExchangeClient::new(config, DpopSigner::generate().expect("DPoP signer"))
        .expect("token exchange client")
}

fn exchange_client_with_nonce_state(
    endpoint: Url,
    signer: DpopSigner,
    nonces: DpopNonceState,
) -> DpopTokenExchangeClient {
    let policy = DpopEndpointPolicy::exact_loopback_http(endpoint.clone())
        .expect("loopback endpoint policy");
    let config = DpopTokenExchangeConfig::new(
        endpoint,
        policy,
        "client-id",
        Some(SecretString::new("client-secret")),
    )
    .expect("token exchange config");
    DpopTokenExchangeClient::with_nonce_state(config, signer, nonces)
        .expect("token exchange client")
}

fn provider_bound_token(
    client: &DpopTokenExchangeClient,
    token: &DpopAccessToken,
) -> DpopBoundAccessToken {
    let metadata = DpopProviderValidationMetadata::from_provider(
        "issuer.example",
        token.access_token_hash(),
        client.public_jwk().thumbprint(),
        "https://resource.example",
        SystemTime::now() + Duration::from_secs(60),
    )
    .expect("provider validation metadata");
    client
        .validate_provider_binding(token, metadata)
        .expect("provider-bound token")
}

fn successful_token_response(access_token: &str) -> Value {
    json!({
        "access_token": access_token,
        "issued_token_type": RFC8693_ACCESS_TOKEN_TYPE,
        "token_type": "DPoP",
        "expires_in": 60,
        "scope": "read write"
    })
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
fn canonical_target_and_default_config_require_https() {
    for target in [
        "http://resource.example/items", // DevSkim: ignore DS137138 rejected negative test fixture
        "http://127.0.0.1/items",        // DevSkim: ignore DS137138 rejected negative test fixture
        "http://localhost/items",        // DevSkim: ignore DS137138 rejected negative test fixture
    ] {
        assert_eq!(
            canonical_dpop_target(&Url::parse(target).expect("resource URL")),
            Err(OutboundDpopError::InsecureEndpoint)
        );
    }
    assert_eq!(
        canonical_dpop_target(&Url::parse("ftp://resource.example/items").expect("FTP URL")),
        Err(OutboundDpopError::InvalidUrl)
    );

    for endpoint in [
        "https://user:password@issuer.example/token",
        "https://issuer.example/token?credential=value",
        "https://issuer.example/token#fragment",
    ] {
        assert!(matches!(
            DpopTokenExchangeConfig::new(
                Url::parse(endpoint).expect("token endpoint URL"),
                DpopEndpointPolicy::exact_https(
                    Url::parse("https://issuer.example/token").expect("trusted endpoint"),
                )
                .expect("endpoint policy"),
                "client-id",
                None,
            ),
            Err(OutboundDpopError::InvalidUrl)
        ));
    }

    assert!(matches!(
        DpopTokenExchangeConfig::new(
            Url::parse("http://localhost/token") // DevSkim: ignore DS137138 rejected negative test fixture
                .expect("localhost token endpoint"),
            DpopEndpointPolicy::exact_loopback_http(
                Url::parse("http://127.0.0.1/token") // DevSkim: ignore DS137138 loopback test fixture
                    .expect("numeric loopback endpoint policy"),
            )
            .expect("loopback policy construction"),
            "client-id",
            None,
        ),
        Err(OutboundDpopError::InsecureEndpoint)
    ));
    DpopTokenExchangeConfig::new(
        Url::parse("http://127.0.0.1/token") // DevSkim: ignore DS137138 loopback test fixture
            .expect("numeric loopback token endpoint"),
        DpopEndpointPolicy::exact_loopback_http(
            Url::parse("http://127.0.0.1/token") // DevSkim: ignore DS137138 loopback test fixture
                .expect("numeric loopback policy endpoint"),
        )
        .expect("numeric loopback policy"),
        "client-id",
        None,
    )
    .expect("numeric loopback is the explicit local-development exception");
}

#[test]
fn credential_endpoint_requires_matching_explicit_trust_policy() {
    let endpoint = Url::parse("https://issuer-a.example/token").expect("token endpoint");
    let different_policy = DpopEndpointPolicy::exact_https(
        Url::parse("https://issuer-b.example/token").expect("different trusted endpoint"),
    )
    .expect("trusted endpoint policy");
    assert!(matches!(
        DpopTokenExchangeConfig::new(endpoint, different_policy, "client-id", None),
        Err(OutboundDpopError::UntrustedEndpoint)
    ));
}

#[test]
fn exchange_request_requires_complete_audit_metadata_and_redacts_subject() {
    assert_eq!(
        BearerSubjectToken::new(SecretString::new("")),
        Err(OutboundDpopError::InvalidField("subject_token"))
    );
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

    for invalid in [
        "relative/resource",
        "https://resource.example/items#fragment",
        "https://user@resource.example/items",
        "https://user:password@resource.example/items",
        "://missing-scheme",
    ] {
        assert!(matches!(
            exchange_request().with_resource(invalid),
            Err(OutboundDpopError::InvalidField("resource"))
        ));
    }
    exchange_request()
        .with_resource("urn:example:resource")
        .expect("absolute fragment-free resource URI");

    let request = exchange_request()
        .with_resource("https://resource.example/items?access_token=resource-query-secret")
        .expect("query-bearing resource URI");
    let rendered = format!("{request:?}");
    assert!(rendered.contains("?<redacted>"));
    assert!(!rendered.contains("resource-query-secret"));
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
    let request = exchange_request()
        .with_resource("https://resource.example/items?access_token=resource-query-secret")
        .expect("query-bearing resource indicator");
    let token = client
        .exchange(&request)
        .await
        .expect("DPoP token exchange");

    assert_eq!(token.access_token().expose_secret(), "issued-access-secret");
    assert_eq!(token.issued_token_type(), RFC8693_ACCESS_TOKEN_TYPE);
    assert_eq!(token.expires_in(), Some(60));
    assert_eq!(token.scope(), Some("read write"));
    let bound_token = provider_bound_token(&client, &token);
    assert_eq!(bound_token.proof_thumbprint(), client.public_jwk().thumbprint());
    assert_eq!(bound_token.audience(), "https://resource.example");
    assert_eq!(bound_token.provider(), "issuer.example");
    let mismatched_hash = DpopProviderValidationMetadata::from_provider(
        "issuer.example",
        "not-the-issued-token",
        client.public_jwk().thumbprint(),
        "https://resource.example",
        SystemTime::now() + Duration::from_secs(60),
    )
    .expect("mismatched provider metadata shape");
    assert!(matches!(
        client.validate_provider_binding(&token, mismatched_hash),
        Err(OutboundDpopError::ProviderBindingMismatch)
    ));
    assert!(matches!(
        DpopProviderValidationMetadata::from_provider(
            "issuer.example",
            token.access_token_hash(),
            client.public_jwk().thumbprint(),
            "https://resource.example",
            SystemTime::now() - Duration::from_secs(1),
        ),
        Err(OutboundDpopError::ProviderBindingExpired)
    ));

    let requests = state.requests.lock().await.clone();
    assert_eq!(requests.len(), 2);
    assert!(requests[0]
        .body
        .contains(&format!("grant_type={}", urlencoding(RFC8693_GRANT_TYPE))));
    assert!(requests[0]
        .body
        .contains("subject_token=subject-token-secret"));
    assert!(requests[0].body.contains(&format!(
        "subject_token_type={}",
        urlencoding(RFC8693_ACCESS_TOKEN_TYPE)
    )));
    assert!(requests[0].body.contains(&format!(
        "requested_token_type={}",
        urlencoding(RFC8693_ACCESS_TOKEN_TYPE)
    )));
    assert!(requests[0].body.contains(
        "resource=https%3A%2F%2Fresource.example%2Fitems%3Faccess_token%3Dresource-query-secret"
    ));
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
    let first_policy = DpopEndpointPolicy::exact_https(
        Url::parse("https://resource.example/v1/items").expect("first trusted target"),
    )
    .expect("first resource policy");
    let second_policy = DpopEndpointPolicy::exact_https(
        Url::parse("https://resource.example/v1/other").expect("second trusted target"),
    )
    .expect("second resource policy");
    let mut get_request = client
        .resource_request(
            &bound_token,
            Method::GET,
            first_target.clone(),
            &first_policy,
        )
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
        .resource_request(
            &bound_token,
            Method::POST,
            first_target.clone(),
            &first_policy,
        )
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
        .resource_request(&bound_token, Method::GET, second_target.clone(), &second_policy)
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
async fn resource_http_policy_matches_the_client_loopback_exception() {
    let (endpoint, _state, server) = start_scripted_server(vec![ScriptedResponse::json(
        StatusCode::OK,
        Vec::new(),
        successful_token_response("loopback-policy-token"),
    )])
    .await;
    let signer = DpopSigner::generate().expect("DPoP signer");
    let loopback_config = DpopTokenExchangeConfig::new(
        endpoint.clone(),
        DpopEndpointPolicy::exact_loopback_http(endpoint)
            .expect("loopback endpoint policy"),
        "client-id",
        Some(SecretString::new("client-secret")),
    )
    .expect("loopback token config");
    let loopback_client =
        DpopTokenExchangeClient::new(loopback_config, signer.clone()).expect("loopback client");
    let token = loopback_client
        .exchange(&exchange_request())
        .await
        .expect("loopback token exchange");
    let bound_token = provider_bound_token(&loopback_client, &token);
    let resource = Url::parse("http://127.0.0.1/resource") // DevSkim: ignore DS137138 loopback test fixture
        .expect("loopback resource URL");
    let resource_policy = DpopEndpointPolicy::exact_loopback_http(resource.clone())
        .expect("loopback resource policy");
    loopback_client
        .resource_request(&bound_token, Method::GET, resource.clone(), &resource_policy)
        .expect("explicit loopback policy applies to resource authorization");

    let strict_config = DpopTokenExchangeConfig::new(
        Url::parse("https://issuer.example/token").expect("strict token endpoint"),
        DpopEndpointPolicy::exact_https(
            Url::parse("https://issuer.example/token").expect("strict token policy endpoint"),
        )
        .expect("strict endpoint policy"),
        "client-id",
        Some(SecretString::new("client-secret")),
    )
    .expect("strict token config");
    let strict_client = DpopTokenExchangeClient::new(strict_config, signer).expect("strict client");
    let error = strict_client
        .resource_request(&bound_token, Method::GET, resource, &resource_policy)
        .expect_err("strict client must reject cleartext resource authorization");
    assert_eq!(error, OutboundDpopError::InsecureEndpoint);
    server.abort();
}

#[tokio::test]
async fn resource_authorization_requires_matching_explicit_trust_policy() {
    let (endpoint, _state, server) = start_scripted_server(vec![ScriptedResponse::json(
        StatusCode::OK,
        Vec::new(),
        successful_token_response("resource-policy-token"),
    )])
    .await;
    let client = exchange_client(endpoint);
    let token = client
        .exchange(&exchange_request())
        .await
        .expect("token exchange");
    let bound_token = provider_bound_token(&client, &token);
    let target = Url::parse("https://resource.example/v1/items").expect("resource target");
    let different_policy = DpopEndpointPolicy::exact_https(
        Url::parse("https://other.example/v1/items").expect("different trusted target"),
    )
    .expect("different resource policy");
    assert!(matches!(
        client.resource_request(&bound_token, Method::GET, target, &different_policy),
        Err(OutboundDpopError::UntrustedEndpoint)
    ));
    server.abort();
}

#[tokio::test]
async fn token_endpoint_nonces_are_isolated_by_endpoint_under_concurrency() {
    let responses = |nonce: &'static str, access_token: &'static str| {
        vec![
            ScriptedResponse::json(
                StatusCode::BAD_REQUEST,
                vec![("dpop-nonce", nonce)],
                json!({"error": "use_dpop_nonce"}),
            ),
            ScriptedResponse::json(
                StatusCode::OK,
                Vec::new(),
                successful_token_response(access_token),
            ),
            ScriptedResponse::json(
                StatusCode::OK,
                Vec::new(),
                successful_token_response(access_token),
            ),
        ]
    };
    let (endpoint_a, state_a, server_a) =
        start_scripted_server(responses("endpoint-a-nonce", "token-a")).await;
    let (endpoint_b, state_b, server_b) =
        start_scripted_server(responses("endpoint-b-nonce", "token-b")).await;
    let signer = DpopSigner::generate().expect("shared DPoP signer");
    let nonces = DpopNonceState::default();
    let client_a = exchange_client_with_nonce_state(endpoint_a, signer.clone(), nonces.clone());
    let client_b = exchange_client_with_nonce_state(endpoint_b, signer, nonces);

    let request_a = exchange_request();
    let request_b = exchange_request();
    let (seed_a, seed_b) =
        tokio::join!(client_a.exchange(&request_a), client_b.exchange(&request_b));
    seed_a.expect("endpoint A nonce exchange");
    seed_b.expect("endpoint B nonce exchange");

    let request_a = exchange_request();
    let request_b = exchange_request();
    let (reuse_a, reuse_b) =
        tokio::join!(client_a.exchange(&request_a), client_b.exchange(&request_b));
    reuse_a.expect("endpoint A nonce reuse");
    reuse_b.expect("endpoint B nonce reuse");

    for (state, expected_nonce) in [
        (&state_a, "endpoint-a-nonce"),
        (&state_b, "endpoint-b-nonce"),
    ] {
        let requests = state.requests.lock().await.clone();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            decode_proof(
                requests[1]
                    .headers
                    .get("dpop")
                    .and_then(|value| value.to_str().ok())
                    .expect("nonce retry proof")
            )
            .1["nonce"],
            expected_nonce
        );
        assert_eq!(
            decode_proof(
                requests[2]
                    .headers
                    .get("dpop")
                    .and_then(|value| value.to_str().ok())
                    .expect("stored nonce proof")
            )
            .1["nonce"],
            expected_nonce
        );
    }

    server_a.abort();
    server_b.abort();
}

#[tokio::test]
async fn basic_client_auth_uses_one_sensitive_header_and_no_body_credentials() {
    let (endpoint, state, server) = start_scripted_server(vec![ScriptedResponse::json(
        StatusCode::OK,
        Vec::new(),
        successful_token_response("basic-token"),
    )])
    .await;
    let config = DpopTokenExchangeConfig::new(
        endpoint.clone(),
        DpopEndpointPolicy::exact_loopback_http(endpoint)
            .expect("loopback endpoint policy"),
        "client-id",
        Some(SecretString::new("client-secret")),
    )
    .expect("token exchange config")
    .with_client_auth_method(OAuthClientAuthMethod::Basic);
    let client = DpopTokenExchangeClient::new(config, DpopSigner::generate().expect("DPoP signer"))
        .expect("token exchange client");
    client
        .exchange(&exchange_request())
        .await
        .expect("Basic-auth exchange");

    let requests = state.requests.lock().await.clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0]
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=")
    );
    assert!(!requests[0].body.contains("client_id="));
    assert!(!requests[0].body.contains("client_secret="));
    assert!(requests[0].headers.contains_key("dpop"));
    server.abort();
}

#[tokio::test]
async fn malformed_or_duplicate_dpop_nonce_headers_fail_closed() {
    for headers in [
        vec![("dpop-nonce", "invalid,nonce")],
        vec![("dpop-nonce", "first"), ("dpop-nonce", "second")],
    ] {
        let (endpoint, state, server) = start_scripted_server(vec![ScriptedResponse::json(
            StatusCode::BAD_REQUEST,
            headers,
            json!({"error": "use_dpop_nonce"}),
        )])
        .await;
        let error = exchange_client(endpoint)
            .exchange(&exchange_request())
            .await
            .expect_err("invalid nonce response must fail");
        assert_eq!(error, OutboundDpopError::InvalidNonceHeader);
        assert_eq!(state.requests.lock().await.len(), 1);
        server.abort();
    }
}

#[tokio::test]
async fn token_endpoint_redirect_is_not_followed() {
    let (destination, destination_state, destination_server) =
        start_scripted_server(vec![ScriptedResponse::json(
            StatusCode::OK,
            Vec::new(),
            successful_token_response("redirected-token"),
        )])
        .await;
    let (endpoint, source_state, source_server) =
        start_scripted_server(vec![ScriptedResponse::redirect(destination.to_string())]).await;

    let error = exchange_client(endpoint)
        .exchange(&exchange_request())
        .await
        .expect_err("token endpoint redirect must fail closed");
    assert!(matches!(
        error,
        OutboundDpopError::TokenEndpointRejected {
            status: StatusCode::FOUND,
            ..
        }
    ));
    assert_eq!(source_state.requests.lock().await.len(), 1);
    assert_eq!(destination_state.requests.lock().await.len(), 0);
    source_server.abort();
    destination_server.abort();
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
            json!({"access_token": "issued", "token_type": "DPoP"}),
            OutboundDpopError::UnexpectedIssuedTokenType,
        ),
        (
            json!({"access_token": "issued", "issued_token_type": RFC8693_ACCESS_TOKEN_TYPE, "token_type": "DPoP", "scope": "read admin"}),
            OutboundDpopError::BroadenedScopes,
        ),
        (
            json!({"access_token": "issued", "issued_token_type": RFC8693_ACCESS_TOKEN_TYPE, "token_type": "DPoP", "refresh_token": "refresh-secret"}),
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
async fn token_exchange_enforces_literal_space_scope_grammar_and_omission_semantics() {
    for malformed_scope in [
        "",
        "read\twrite",
        "read\nwrite",
        "read\rwrite",
        " read",
        "read ",
        "read  write",
        "read\u{a0}write",
        "read\"write",
    ] {
        let mut body = successful_token_response("issued");
        body["scope"] = Value::String(malformed_scope.to_string());
        let (endpoint, _state, server) = start_scripted_server(vec![ScriptedResponse::json(
            StatusCode::OK,
            Vec::new(),
            body,
        )])
        .await;
        let error = exchange_client(endpoint)
            .exchange(&exchange_request())
            .await
            .expect_err("malformed response scope must fail closed");
        assert_eq!(error, OutboundDpopError::MalformedTokenResponse);
        server.abort();
    }

    let (endpoint, _state, server) = start_scripted_server(vec![ScriptedResponse::json(
        StatusCode::OK,
        Vec::new(),
        successful_token_response("valid-scope-token"),
    )])
    .await;
    let token = exchange_client(endpoint)
        .exchange(&exchange_request())
        .await
        .expect("literal-SP-delimited multi-token scope");
    assert_eq!(token.scope(), Some("read write"));
    server.abort();

    let mut omitted_scope = successful_token_response("omitted-scope-token");
    omitted_scope
        .as_object_mut()
        .expect("token response object")
        .remove("scope");
    let (endpoint, _state, server) = start_scripted_server(vec![ScriptedResponse::json(
        StatusCode::OK,
        Vec::new(),
        omitted_scope,
    )])
    .await;
    let token = exchange_client(endpoint)
        .exchange(&exchange_request())
        .await
        .expect("omitted response scope inherits the requested scope");
    assert_eq!(token.scope(), Some("read write"));
    server.abort();
}

#[tokio::test]
async fn token_exchange_requires_exact_ok_status_and_json_media_type() {
    let success = successful_token_response("issued");
    let (endpoint, _state, server) = start_scripted_server(vec![ScriptedResponse::json(
        StatusCode::CREATED,
        Vec::new(),
        success.clone(),
    )])
    .await;
    let error = exchange_client(endpoint)
        .exchange(&exchange_request())
        .await
        .expect_err("non-200 2xx response must fail closed");
    match error {
        OutboundDpopError::TokenEndpointRejected { status, code } => {
            assert_eq!(status, StatusCode::CREATED);
            assert_eq!(code.as_str(), "token_endpoint_error");
        }
        other => panic!("unexpected non-200 response error: {other:?}"),
    }
    server.abort();

    let cases = vec![
        (
            ScriptedResponse {
                status: StatusCode::OK,
                headers: Vec::new(),
                body: success.to_string(),
                delay: None,
                location: None,
            },
            OutboundDpopError::UnexpectedResponseContentType,
        ),
        (
            ScriptedResponse::json(
                StatusCode::OK,
                vec![("content-type", "text/plain")],
                success.clone(),
            ),
            OutboundDpopError::UnexpectedResponseContentType,
        ),
        (
            ScriptedResponse::json(
                StatusCode::OK,
                vec![
                    ("content-type", "application/json"),
                    ("content-type", "application/json"),
                ],
                success.clone(),
            ),
            OutboundDpopError::UnexpectedResponseContentType,
        ),
    ];

    for (response, expected) in cases {
        let (endpoint, _state, server) = start_scripted_server(vec![response]).await;
        let actual = exchange_client(endpoint)
            .exchange(&exchange_request())
            .await
            .expect_err("invalid HTTP success contract must fail closed");
        assert_eq!(actual, expected);
        server.abort();
    }

    let (endpoint, _state, server) = start_scripted_server(vec![ScriptedResponse::json(
        StatusCode::OK,
        vec![("content-type", "Application/JSON; charset=utf-8")],
        success,
    )])
    .await;
    exchange_client(endpoint)
        .exchange(&exchange_request())
        .await
        .expect("case-insensitive JSON media type with parameters");
    server.abort();
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
        .token_endpoint_proof(
            &Url::parse("https://issuer.example/token").expect("HTTPS proof endpoint"),
            Some("retry-nonce"),
        )
        .expect("token endpoint proof");
    let config = DpopTokenExchangeConfig::new(
        endpoint.clone(),
        DpopEndpointPolicy::exact_loopback_http(endpoint)
            .expect("loopback endpoint policy"),
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

    let (endpoint, _state, server) = start_scripted_server(vec![ScriptedResponse::json(
        StatusCode::BAD_REQUEST,
        Vec::new(),
        json!({"error": "invalid_scope"}),
    )])
    .await;
    let error = exchange_client(endpoint)
        .exchange(&exchange_request())
        .await
        .expect_err("standard OAuth error");
    match error {
        OutboundDpopError::TokenEndpointRejected { code, .. } => {
            assert_eq!(code.as_str(), "invalid_scope");
            assert_eq!(
                format!("{code:?} {code}"),
                "SafeOAuthErrorCode(\"invalid_scope\") invalid_scope"
            );
        }
        other => panic!("unexpected endpoint error: {other:?}"),
    }
    server.abort();
}

#[tokio::test]
async fn cancelled_exchange_does_not_poison_later_requests() {
    let (endpoint, state, server) = start_scripted_server(vec![
        ScriptedResponse::delayed_json(
            StatusCode::OK,
            successful_token_response("cancelled-token"),
            Duration::from_secs(30),
        ),
        ScriptedResponse::json(
            StatusCode::OK,
            Vec::new(),
            successful_token_response("replacement-token"),
        ),
    ])
    .await;
    let client = exchange_client(endpoint);
    let task_client = client.clone();
    let task = tokio::spawn(async move { task_client.exchange(&exchange_request()).await });
    state.request_seen.notified().await;
    task.abort();
    let cancellation = task.await.expect_err("exchange task must be cancelled");
    assert!(cancellation.is_cancelled());

    let token = client
        .exchange(&exchange_request())
        .await
        .expect("replacement exchange after cancellation");
    assert_eq!(token.access_token().expose_secret(), "replacement-token");
    assert_eq!(state.requests.lock().await.len(), 2);
    server.abort();
}

const PROXY_CHILD_MARKER: &str = "MCP_TOOLKIT_OUTBOUND_DPOP_PROXY_CHILD";
const PROXY_CHILD_ENDPOINT: &str = "MCP_TOOLKIT_OUTBOUND_DPOP_DIRECT_ENDPOINT";

#[tokio::test]
async fn ambient_proxy_child() {
    if std::env::var_os(PROXY_CHILD_MARKER).is_none() {
        return;
    }
    let endpoint =
        Url::parse(&std::env::var(PROXY_CHILD_ENDPOINT).expect("direct endpoint for proxy child"))
            .expect("direct endpoint URL");
    let token = exchange_client(endpoint)
        .exchange(&exchange_request())
        .await
        .expect("ambient proxy must be ignored");
    assert_eq!(token.access_token().expose_secret(), "direct-token");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ambient_proxy_is_ignored_for_credential_bearing_exchange() {
    let (direct_endpoint, direct_state, direct_server) =
        start_scripted_server(vec![ScriptedResponse::json(
            StatusCode::OK,
            Vec::new(),
            successful_token_response("direct-token"),
        )])
        .await;
    let (proxy_endpoint, proxy_state, proxy_server) =
        start_scripted_server(vec![ScriptedResponse::json(
            StatusCode::BAD_GATEWAY,
            Vec::new(),
            json!({"error": "server_error"}),
        )])
        .await;
    let mut proxy_origin = proxy_endpoint;
    proxy_origin.set_path("");
    proxy_origin.set_query(None);
    proxy_origin.set_fragment(None);

    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("ambient_proxy_child")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(PROXY_CHILD_MARKER, "1")
        .env(PROXY_CHILD_ENDPOINT, direct_endpoint.as_str())
        .env("HTTP_PROXY", proxy_origin.as_str())
        .env("HTTPS_PROXY", proxy_origin.as_str())
        .env("ALL_PROXY", proxy_origin.as_str())
        .env("http_proxy", proxy_origin.as_str())
        .env("https_proxy", proxy_origin.as_str())
        .env("all_proxy", proxy_origin.as_str())
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .expect("run isolated ambient-proxy child");
    assert!(
        output.status.success(),
        "proxy child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(direct_state.requests.lock().await.len(), 1);
    assert_eq!(proxy_state.requests.lock().await.len(), 0);
    direct_server.abort();
    proxy_server.abort();
}

#[tokio::test]
async fn token_response_size_is_bounded() {
    let (endpoint, _state, server) = start_scripted_server(vec![ScriptedResponse {
        status: StatusCode::OK,
        headers: vec![("content-type", "application/json")],
        body: "x".repeat(64 * 1024 + 1),
        delay: None,
        location: None,
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
