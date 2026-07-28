pub(crate) use crate::auth_context_from_parts;
pub(crate) use crate::auth_context_ref_from_parts;
pub(crate) use crate::verified_auth_context_from_parts;
pub(crate) use crate::verified_auth_context_ref_from_parts;
pub(crate) use crate::claims::{extract_scopes, merge_claims};
pub(crate) use crate::{
    parse_strict_dpop_authorization, parse_strict_dpop_proof, AuthConfig, AuthContext, AuthError,
    AuthMode, AuthSecurityProfile, Authenticator, ClientAuthMethod, DpopParseError,
    InMemoryJtiReplayStore, SenderConstrainedAuthError,
};

mod tests {
    use super::{
        auth_context_from_parts, auth_context_ref_from_parts, merge_claims,
        parse_strict_dpop_authorization, parse_strict_dpop_proof, AuthConfig, AuthContext,
        AuthError, AuthMode, AuthSecurityProfile, Authenticator, ClientAuthMethod, DpopParseError,
        InMemoryJtiReplayStore, SenderConstrainedAuthError, verified_auth_context_from_parts,
        verified_auth_context_ref_from_parts,
    };
    use axum::extract::State;
    use axum::http::{header::AUTHORIZATION, HeaderMap, HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    use dpop_verifier::{DpopError, DpopVerifier, NonceMode, ReplayContext, ReplayStore};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::sync::{oneshot, Mutex};

    const TEST_ES256_SIGNING_KEY_B64: &str = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1dURmZDR2xqWTZhdzNIcnQKa0htUFJpYXp1a3hQTGI2aWxwUkFld2pXOG5paFJBTkNBQVREc2tDaFQrQWx0a205WDdNSTY5VDNJVW1yUVUwTAo5NTBJeEV6dncveDVCTUVJTlJNclhMQkpocXpPOUJtK2Q2SmJxQTIxWVFtZDFLdDRSekxKUjFXKwotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==";

    /// Executes auth_context_extracts_from_parts.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// use http::Request;
    ///
    /// use mcp_toolkit_auth::{auth_context_from_parts, AuthContext};
    ///
    /// use serde_json::json;
    ///
    ///
    ///
    /// let (mut parts, _) = Request::new(()).into_parts();
    ///
    /// parts.extensions.insert(AuthContext {
    ///
    ///     actor: "tester".to_string(),
    ///
    ///     scopes: Vec::new(),
    ///
    ///     roles: Vec::new(),
    ///
    ///     claims: json!({}),
    ///
    ///     azp: None,
    ///
    ///     subject: None,
    ///
    ///     token_ref: "ref".to_string(),
    ///
    ///     raw_token: "token".to_string(),
    ///
    /// });
    ///
    /// let _ = auth_context_from_parts(&parts);
    /// ```
    #[test]
    fn auth_context_extracts_from_parts() {
        let (mut parts, _) = axum::http::Request::new(()).into_parts();
        let context = AuthContext {
            actor: "tester".to_string(),
            scopes: vec!["codebase:read".to_string()],
            roles: vec![],
            claims: json!({"sub": "tester"}),
            azp: Some("client".to_string()),
            subject: Some("tester".to_string()),
            token_ref: "ref".to_string(),
            raw_token: "token".to_string(),
        };
        parts.extensions.insert(context.clone());

        let owned = auth_context_from_parts(&parts).expect("auth context");
        let borrowed = auth_context_ref_from_parts(&parts).expect("auth context ref");

        assert_eq!(owned.actor, "tester");
        assert_eq!(borrowed.actor, "tester");
    }

    /// Executes delegation_config.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// use mcp_toolkit_auth::{AuthConfig, AuthMode};
    ///
    ///
    ///
    /// let _ = AuthConfig {
    ///
    ///     mode: AuthMode::Delegation,
    ///
    ///     ..AuthConfig::default()
    ///
    /// };
    /// ```
    fn delegation_config() -> AuthConfig {
        AuthConfig {
            mode: AuthMode::Delegation,
            delegation_secret: Some("test-secret".to_string()),
            delegation_issuer: "issuer".to_string(),
            delegation_audience: "audience".to_string(),
            jti_ttl_s: 300.0,
            jti_cache_size: 100,
            jti_enforce_bearer: true,
            ..Default::default()
        }
    }

    /// Executes delegation_config_no_jti.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// use mcp_toolkit_auth::{AuthConfig, AuthMode};
    ///
    ///
    ///
    /// let _ = AuthConfig {
    ///
    ///     mode: AuthMode::Delegation,
    ///
    ///     ..AuthConfig::default()
    ///
    /// };
    /// ```
    fn delegation_config_no_jti() -> AuthConfig {
        AuthConfig {
            mode: AuthMode::Delegation,
            delegation_secret: Some("test-secret".to_string()),
            delegation_issuer: "issuer".to_string(),
            delegation_audience: "audience".to_string(),
            jti_ttl_s: 0.0,
            jti_cache_size: 0,
            strict_oauth: true,
            ..Default::default()
        }
    }

    /// Executes token_without_jti.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// use mcp_toolkit_auth::{AuthConfig, AuthMode};
    ///
    ///
    ///
    /// let _ = AuthConfig {
    ///
    ///     mode: AuthMode::Delegation,
    ///
    ///     ..AuthConfig::default()
    ///
    /// };
    /// ```
    fn token_without_jti() -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let claims = json!({
            "exp": exp,
            "sub": "user-123",
            "aud": "audience",
            "iss": "issuer"
        });
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("token")
    }

    fn token_with_jti(jti: &str) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let claims = json!({
            "exp": exp,
            "sub": "user-123",
            "aud": "audience",
            "iss": "issuer",
            "jti": jti
        });
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("token")
    }

    fn token_with_jti_and_cnf(jti: &str, cnf: Value) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let claims = json!({
            "exp": exp,
            "sub": "user-123",
            "aud": "audience",
            "iss": "issuer",
            "jti": jti,
            "cnf": cnf,
        });
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("token")
    }

    fn token_with_cnf(cnf: Value) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let claims = json!({
            "exp": exp,
            "sub": "user-123",
            "aud": "audience",
            "iss": "issuer",
            "cnf": cnf,
        });
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("token")
    }

    #[derive(Default)]
    struct TestDpopReplayStore(HashSet<[u8; 32]>);

    #[async_trait::async_trait]
    impl ReplayStore for TestDpopReplayStore {
        async fn insert_once(
            &mut self,
            jti_hash: [u8; 32],
            _context: ReplayContext<'_>,
        ) -> Result<bool, DpopError> {
            Ok(self.0.insert(jti_hash))
        }
    }

    struct FailingDpopReplayStore;

    #[async_trait::async_trait]
    impl ReplayStore for FailingDpopReplayStore {
        async fn insert_once(
            &mut self,
            _jti_hash: [u8; 32],
            _context: ReplayContext<'_>,
        ) -> Result<bool, DpopError> {
            Err(DpopError::Store(Box::new(std::io::Error::other(
                "fixture replay-store failure",
            ))))
        }
    }

    struct SignedDpopProof {
        compact_jws: String,
        jkt: String,
    }

    fn signed_dpop_proof(access_token: &str, htu: &str, htm: &str, jti: &str) -> SignedDpopProof {
        signed_dpop_proof_with_claims(
            access_token,
            htu,
            htm,
            jti,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("current time")
                .as_secs() as i64,
            None,
        )
    }

    fn signed_dpop_proof_with_claims(
        access_token: &str,
        htu: &str,
        htm: &str,
        jti: &str,
        iat: i64,
        nonce: Option<&str>,
    ) -> SignedDpopProof {
        let signing_key = SigningKey::from_slice(&[42_u8; 32]).expect("fixed P-256 scalar");
        let point = signing_key.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed x coordinate"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed y coordinate"));
        let jkt = dpop_verifier::thumbprint_ec_p256(&x, &y).expect("JKT");
        let header = json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {"kty": "EC", "crv": "P-256", "x": x, "y": y},
        });
        let mut claims = json!({
            "jti": jti,
            "iat": iat,
            "htm": htm,
            "htu": htu,
            "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes())),
        });
        if let Some(nonce) = nonce {
            claims
                .as_object_mut()
                .expect("claims object")
                .insert("nonce".to_string(), json!(nonce));
        }
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let compact_jws = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );

        SignedDpopProof { compact_jws, jkt }
    }

    fn dpop_headers(scheme: &str, access_token: &str, proof: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("{scheme} {access_token}")).expect("authorization"),
        );
        headers.insert("dpop", HeaderValue::from_str(proof).expect("dpop proof"));
        headers
    }

    async fn authenticate_sender_constrained<S: ReplayStore + Send + ?Sized>(
        auth: &Authenticator,
        access_token: &str,
        proof: &str,
        expected_htu: &str,
        expected_htm: &str,
        verifier: &DpopVerifier,
        replay_store: &mut S,
    ) -> Result<AuthContext, SenderConstrainedAuthError> {
        let headers = dpop_headers("DPoP", access_token, proof);
        let access_token =
            parse_strict_dpop_authorization(&headers).expect("strict DPoP authorization");
        let proof = parse_strict_dpop_proof(&headers).expect("strict DPoP proof");
        let result = auth
            .authenticate_sender_constrained_dpop(
                access_token,
                proof,
                expected_htu,
                expected_htm,
                verifier,
                replay_store,
            )
            .await;
        result
    }

    #[derive(Clone)]
    struct IntrospectionState {
        payload: Value,
        require_basic: bool,
        header_capture: Arc<Mutex<Option<String>>>,
    }

    /// Executes spawn_introspection_server.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// use mcp_toolkit_auth::AuthConfig;
    ///
    ///
    ///
    /// let _ = AuthConfig::default();
    /// ```
    async fn spawn_introspection_server(
        state: IntrospectionState,
    ) -> (String, oneshot::Sender<()>) {
        /// Executes introspection_handler.
        ///
        /// # Errors
        /// * Does not return errors.
        ///
        /// # Security
        /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
        ///
        /// # Panics
        /// * None.
        ///
        /// ```rust,no_run
        /// use mcp_toolkit_auth::AuthConfig;
        ///
        ///
        ///
        /// let _ = AuthConfig::default();
        /// ```
        async fn introspection_handler(
            State(state): State<IntrospectionState>,
            headers: HeaderMap,
        ) -> impl IntoResponse {
            let auth_header = headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());

            *state.header_capture.lock().await = auth_header.clone();

            if state.require_basic {
                let is_basic = auth_header
                    .as_deref()
                    .map(|value| value.starts_with("Basic "))
                    .unwrap_or(false);
                if !is_basic {
                    return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
                }
            }

            axum::Json(state.payload.clone()).into_response()
        }

        let app = Router::new()
            .route("/introspect", post(introspection_handler))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let addr = listener.local_addr().expect("addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        (
            format!("http://{addr}/introspect"), // DevSkim: ignore DS137138 loopback test fixture
            shutdown_tx,
        )
    }

    async fn spawn_jwks_server() -> (String, oneshot::Sender<()>) {
        async fn jwks_handler() -> Json<Value> {
            Json(json!({
                "keys": [{
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ",
                    "y": "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4",
                    "kid": "test-ec-key",
                    "alg": "ES256",
                    "use": "sig",
                }]
            }))
        }

        let app = Router::new().route("/jwks", get(jwks_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let addr = listener.local_addr().expect("addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        (
            format!("http://{addr}/jwks"), // DevSkim: ignore DS137138 loopback test fixture
            shutdown_tx,
        )
    }

    fn jwks_signed_confirmation_token() -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("test-ec-key".to_string());
        let signing_key_pem = BASE64_STANDARD
            .decode(TEST_ES256_SIGNING_KEY_B64)
            .expect("test signing key");
        encode(
            &header,
            &json!({
                "exp": exp,
                "sub": "user-123",
                "aud": "audience",
                "iss": "issuer",
                "cnf": {"jkt": "signed-thumbprint"},
            }),
            &EncodingKey::from_ec_pem(&signing_key_pem).expect("test signing key"),
        )
        .expect("token")
    }

    /// Executes extract_scopes_from_scope_string.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// use serde_json::json;
    ///
    ///
    ///
    /// let _ = json!({"scope": "read"});
    /// ```
    #[test]
    fn extract_scopes_from_scope_string() {
        let claims = json!({"scope": "read write"});
        let scopes = super::extract_scopes(&claims);
        assert_eq!(scopes, vec!["read", "write"]);
    }

    /// Executes extract_scopes_from_scp_array.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// use serde_json::json;
    ///
    ///
    ///
    /// let _ = json!({"scp": ["read"]});
    /// ```
    #[test]
    fn extract_scopes_from_scp_array() {
        let claims = json!({"scp": ["alpha", "beta"]});
        let scopes = super::extract_scopes(&claims);
        assert_eq!(scopes, vec!["alpha", "beta"]);
    }

    /// Executes extract_scopes_from_scopes_array.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// use serde_json::json;
    ///
    ///
    ///
    /// let _ = json!({"scopes": ["read"]});
    /// ```
    #[test]
    fn extract_scopes_from_scopes_array() {
        let claims = json!({"scopes": ["ops.read", "ops.write"]});
        let scopes = super::extract_scopes(&claims);
        assert_eq!(scopes, vec!["ops.read", "ops.write"]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_signed_dpop_proof_admits_matching_sender_constrained_token() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let provisional_token = token_with_cnf(json!({"jkt": "provisional"}));
        let proof = signed_dpop_proof(
            &provisional_token,
            "https://ops.example.test/mcp",
            "POST",
            "valid-proof",
        );
        let token = token_with_cnf(json!({"jkt": proof.jkt}));
        let proof = signed_dpop_proof(
            &token,
            "https://ops.example.test/mcp",
            "POST",
            "valid-proof",
        );
        let mut replay_store = TestDpopReplayStore::default();

        let bearer_headers = dpop_headers("Bearer", &token, &proof.compact_jws);
        assert_eq!(
            parse_strict_dpop_authorization(&bearer_headers),
            Err(DpopParseError::UnsupportedScheme),
            "ordinary Bearer ingress cannot construct a DpopToken"
        );

        authenticate_sender_constrained(
            &auth,
            &token,
            &proof.compact_jws,
            "https://ops.example.test/mcp",
            "POST",
            &DpopVerifier::new(),
            &mut replay_store,
        )
        .await
        .expect("real verified DPoP proof should admit a matching sender-constrained token");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_bearer_auth_requires_jti_when_configured() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let token = token_without_jti();
        let result = auth.authenticate_token(&HeaderMap::new(), &token).await;
        assert!(
            result.is_err(),
            "expected missing jti to fail for bearer-only auth"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bearer_only_context_accepts_unconstrained_bearer_jwt() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let token = token_with_jti("ordinary-bearer-jwt");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
        );

        let context = auth
            .authenticate_headers(&headers)
            .await
            .expect("ordinary bearer JWT should be accepted");

        assert_eq!(context.subject.as_deref(), Some("user-123"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verified_context_is_issued_only_after_bearer_authentication() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let token = token_with_jti("verified-context-witness");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
        );

        let context = auth
            .authenticate_verified_headers(&headers)
            .await
            .expect("ordinary bearer JWT should yield an authenticator-issued context");

        assert_eq!(context.context().subject.as_deref(), Some("user-123"));
        assert!(!format!("{context:?}").contains(&token));

        let (mut parts, _) = axum::http::Request::new(()).into_parts();
        parts.extensions.insert(context.clone());
        assert_eq!(
            verified_auth_context_from_parts(&parts)
                .as_ref()
                .and_then(|value| value.context().subject.as_deref()),
            Some("user-123")
        );
        assert_eq!(
            verified_auth_context_ref_from_parts(&parts)
                .and_then(|value| value.context().subject.as_deref()),
            Some("user-123")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bearer_only_context_rejects_sender_constrained_bearer_jwt() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let token = token_with_jti_and_cnf(
            "sender-constrained-bearer-jwt",
            json!({"jkt": "key-thumbprint"}),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
        );

        let error = auth
            .authenticate_headers(&headers)
            .await
            .expect_err("sender-constrained token must not enter a bearer-only context");

        assert_eq!(error.decision_code(), "SENDER_CONSTRAINED_BEARER_TOKEN");
        assert_eq!(error.bearer_error(), Some("invalid_token"));
        assert_eq!(error.public_message(), "Invalid bearer token.");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bearer_only_context_handles_empty_and_malformed_cnf_fail_closed() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let empty_cnf = token_with_jti_and_cnf("empty-cnf", json!({}));
        let malformed_cnf = token_with_jti_and_cnf("malformed-cnf", json!("not-an-object"));

        for (label, token) in [
            ("empty-object", empty_cnf),
            ("null", token_with_jti_and_cnf("null-cnf", Value::Null)),
        ] {
            let error = auth
                .authenticate_token(&HeaderMap::new(), &token)
                .await
                .expect_err("present cnf must not enter a bearer-only context");
            assert_eq!(
                error.decision_code(),
                "SENDER_CONSTRAINED_BEARER_TOKEN",
                "{label}"
            );
        }

        let error = auth
            .authenticate_token(&HeaderMap::new(), &malformed_cnf)
            .await
            .expect_err("malformed cnf must not enter a bearer-only context");
        assert_eq!(error.decision_code(), "SENDER_CONSTRAINED_BEARER_TOKEN");
    }

    #[test]
    fn optional_jwks_introspection_merge_retains_primary_confirmation_claim() {
        let signed_claims = json!({
            "iss": "issuer",
            "aud": "audience",
            "sub": "user-123",
            "cnf": {"jkt": "signed-thumbprint"},
        });

        for introspection_cnf in [Value::Null, json!({})] {
            let merged = merge_claims(
                &signed_claims,
                &json!({"active": true, "cnf": introspection_cnf}),
            );
            assert_eq!(merged.get("cnf"), signed_claims.get("cnf"));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn optional_jwks_introspection_path_rejects_erased_confirmation_claim() {
        for introspection_cnf in [Value::Null, json!({})] {
            let state = IntrospectionState {
                payload: json!({"active": true, "cnf": introspection_cnf}),
                require_basic: true,
                header_capture: Arc::new(Mutex::new(None)),
            };
            let (introspection_url, introspection_shutdown) =
                spawn_introspection_server(state).await;
            let (jwks_url, jwks_shutdown) = spawn_jwks_server().await;
            let auth = Authenticator::new(AuthConfig {
                mode: AuthMode::Jwks,
                jwks_url: Some(jwks_url),
                issuer: Some("issuer".to_string()),
                audience: Some("audience".to_string()),
                introspection_url: Some(introspection_url),
                introspection_client_id: Some("client".to_string()),
                introspection_client_secret: Some("secret".to_string()),
                introspection_auth_method: ClientAuthMethod::ClientSecretBasic,
                strict_oauth: true,
                jti_ttl_s: 0.0,
                jti_cache_size: 0,
                ..Default::default()
            })
            .expect("auth");
            let token = jwks_signed_confirmation_token();
            let mut headers = HeaderMap::new();
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
            );

            let error = auth
                .authenticate_headers(&headers)
                .await
                .expect_err("introspection must not erase a signed confirmation claim");
            let _ = introspection_shutdown.send(());
            let _ = jwks_shutdown.send(());

            assert_eq!(error.decision_code(), "SENDER_CONSTRAINED_BEARER_TOKEN");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sender_constrained_dpop_rejects_wrong_access_token_and_http_binding() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let token = token_with_cnf(json!({"jkt": "proof-thumbprint"}));
        let proof = signed_dpop_proof(
            &token,
            "https://ops.example.test/mcp",
            "POST",
            "binding-failures",
        );

        let wrong_token = token_with_cnf(json!({"jkt": proof.jkt}));
        let mut ath_store = TestDpopReplayStore::default();
        let error = authenticate_sender_constrained(
            &auth,
            &wrong_token,
            &proof.compact_jws,
            "https://ops.example.test/mcp",
            "POST",
            &DpopVerifier::new(),
            &mut ath_store,
        )
        .await
        .expect_err("proof must be bound to the exact access token");
        assert!(matches!(
            error,
            SenderConstrainedAuthError::Dpop(DpopError::AthMismatch)
        ));

        let mut htu_store = TestDpopReplayStore::default();
        let error = authenticate_sender_constrained(
            &auth,
            &token,
            &proof.compact_jws,
            "https://ops.example.test/other",
            "POST",
            &DpopVerifier::new(),
            &mut htu_store,
        )
        .await
        .expect_err("proof must be bound to the exact HTTP target");
        assert!(matches!(
            error,
            SenderConstrainedAuthError::Dpop(DpopError::HtuMismatch)
        ));

        let mut htm_store = TestDpopReplayStore::default();
        let error = authenticate_sender_constrained(
            &auth,
            &token,
            &proof.compact_jws,
            "https://ops.example.test/mcp",
            "GET",
            &DpopVerifier::new(),
            &mut htm_store,
        )
        .await
        .expect_err("proof must be bound to the exact HTTP method");
        assert!(matches!(
            error,
            SenderConstrainedAuthError::Dpop(DpopError::HtmMismatch)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sender_constrained_dpop_preserves_invalid_signature_failure() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let provisional_token = token_with_cnf(json!({"jkt": "provisional"}));
        let provisional_proof = signed_dpop_proof(
            &provisional_token,
            "https://ops.example.test/mcp",
            "POST",
            "invalid-signature-provisional",
        );
        let token = token_with_cnf(json!({"jkt": provisional_proof.jkt}));
        let mut proof = signed_dpop_proof(
            &token,
            "https://ops.example.test/mcp",
            "POST",
            "invalid-signature",
        )
        .compact_jws
        .into_bytes();
        let last = proof.last_mut().expect("signature byte");
        *last = if *last == b'A' { b'B' } else { b'A' };
        let proof = String::from_utf8(proof).expect("compact proof remains text");
        let mut replay_store = TestDpopReplayStore::default();

        let error = authenticate_sender_constrained(
            &auth,
            &token,
            &proof,
            "https://ops.example.test/mcp",
            "POST",
            &DpopVerifier::new(),
            &mut replay_store,
        )
        .await
        .expect_err("invalid proof signature must fail");

        assert!(matches!(
            error,
            SenderConstrainedAuthError::Dpop(DpopError::InvalidSignature)
        ));
        assert!(replay_store.0.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sender_constrained_dpop_preserves_stale_and_future_proof_failures() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let provisional_token = token_with_cnf(json!({"jkt": "provisional"}));
        let provisional_proof = signed_dpop_proof(
            &provisional_token,
            "https://ops.example.test/mcp",
            "POST",
            "time-provisional",
        );
        let token = token_with_cnf(json!({"jkt": provisional_proof.jkt}));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time")
            .as_secs() as i64;

        for (label, iat, expected) in [
            ("stale", now - 3_600, DpopError::Stale),
            ("future", now + 3_600, DpopError::FutureSkew),
        ] {
            let proof = signed_dpop_proof_with_claims(
                &token,
                "https://ops.example.test/mcp",
                "POST",
                &format!("{label}-proof"),
                iat,
                None,
            );
            let mut replay_store = TestDpopReplayStore::default();
            let error = authenticate_sender_constrained(
                &auth,
                &token,
                &proof.compact_jws,
                "https://ops.example.test/mcp",
                "POST",
                &DpopVerifier::new()
                    .with_max_age_seconds(60)
                    .with_future_skew_seconds(5),
                &mut replay_store,
            )
            .await
            .expect_err("out-of-window proof must fail");
            assert_eq!(
                std::mem::discriminant(
                    error
                        .dpop_error()
                        .expect("freshness failure remains a DPoP error")
                ),
                std::mem::discriminant(&expected),
                "{label}"
            );
            assert!(replay_store.0.is_empty(), "{label}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sender_constrained_dpop_preserves_required_and_incorrect_nonce_failures() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let provisional_token = token_with_cnf(json!({"jkt": "provisional"}));
        let provisional_proof = signed_dpop_proof(
            &provisional_token,
            "https://ops.example.test/mcp",
            "POST",
            "nonce-provisional",
        );
        let token = token_with_cnf(json!({"jkt": provisional_proof.jkt}));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time")
            .as_secs() as i64;
        let verifier = DpopVerifier::new().with_nonce_mode(NonceMode::RequireEqual {
            expected_nonce: "server-expected".to_string(),
        });

        let missing = signed_dpop_proof_with_claims(
            &token,
            "https://ops.example.test/mcp",
            "POST",
            "nonce-missing",
            now,
            None,
        );
        let mut missing_store = TestDpopReplayStore::default();
        let missing_error = authenticate_sender_constrained(
            &auth,
            &token,
            &missing.compact_jws,
            "https://ops.example.test/mcp",
            "POST",
            &verifier,
            &mut missing_store,
        )
        .await
        .expect_err("required nonce must fail when absent");
        assert!(matches!(
            missing_error,
            SenderConstrainedAuthError::Dpop(DpopError::MissingNonce)
        ));
        assert!(missing_store.0.is_empty());

        let incorrect = signed_dpop_proof_with_claims(
            &token,
            "https://ops.example.test/mcp",
            "POST",
            "nonce-incorrect",
            now,
            Some("client-wrong"),
        );
        let mut incorrect_store = TestDpopReplayStore::default();
        let incorrect_error = authenticate_sender_constrained(
            &auth,
            &token,
            &incorrect.compact_jws,
            "https://ops.example.test/mcp",
            "POST",
            &verifier,
            &mut incorrect_store,
        )
        .await
        .expect_err("incorrect nonce must request the expected nonce");
        match incorrect_error {
            SenderConstrainedAuthError::Dpop(DpopError::UseDpopNonce { nonce }) => {
                assert_eq!(nonce, "server-expected");
            }
            other => panic!("expected nonce challenge, got {other:?}"),
        }
        assert!(incorrect_store.0.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sender_constrained_dpop_preserves_replay_store_failures() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let provisional_token = token_with_cnf(json!({"jkt": "provisional"}));
        let provisional_proof = signed_dpop_proof(
            &provisional_token,
            "https://ops.example.test/mcp",
            "POST",
            "store-failure-provisional",
        );
        let token = token_with_cnf(json!({"jkt": provisional_proof.jkt}));
        let proof = signed_dpop_proof(
            &token,
            "https://ops.example.test/mcp",
            "POST",
            "store-failure",
        );
        let mut replay_store = FailingDpopReplayStore;

        let error = authenticate_sender_constrained(
            &auth,
            &token,
            &proof.compact_jws,
            "https://ops.example.test/mcp",
            "POST",
            &DpopVerifier::new(),
            &mut replay_store,
        )
        .await
        .expect_err("replay-store failure must remain typed");

        assert!(matches!(
            error,
            SenderConstrainedAuthError::Dpop(DpopError::Store(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sender_constrained_dpop_requires_matching_nonempty_cnf_jkt_and_rejects_replay() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let provisional_token = token_with_cnf(json!({"jkt": "provisional"}));
        let proof = signed_dpop_proof(
            &provisional_token,
            "https://ops.example.test/mcp",
            "POST",
            "cnf-mismatch",
        );

        for (label, token) in [
            ("missing", token_with_jti("missing-cnf")),
            (
                "malformed",
                token_with_jti_and_cnf("malformed-cnf", json!({"jkt": []})),
            ),
            (
                "mismatch",
                token_with_jti_and_cnf("mismatch-cnf", json!({"jkt": "other-jkt"})),
            ),
        ] {
            let proof = signed_dpop_proof(
                &token,
                "https://ops.example.test/mcp",
                "POST",
                &format!("{label}-cnf"),
            );
            let mut replay_store = TestDpopReplayStore::default();
            let error = authenticate_sender_constrained(
                &auth,
                &token,
                &proof.compact_jws,
                "https://ops.example.test/mcp",
                "POST",
                &DpopVerifier::new(),
                &mut replay_store,
            )
            .await
            .expect_err("missing or mismatched cnf must fail closed");
            let auth_error = error
                .auth_error()
                .expect("confirmation denial must remain an authentication failure");
            assert_eq!(
                auth_error.decision_code(),
                "DPOP_CONFIRMATION_CLAIM_MISMATCH",
                "{label}"
            );
            assert_eq!(
                auth_error.public_message(),
                "Invalid bearer token.",
                "{label}"
            );
            assert!(
                replay_store.0.is_empty(),
                "{label} confirmation denial must not consume replay capacity"
            );
        }

        let token = token_with_cnf(json!({"jkt": proof.jkt}));
        let proof = signed_dpop_proof(
            &token,
            "https://ops.example.test/mcp",
            "POST",
            "replayed-proof",
        );
        let mut replay_store = TestDpopReplayStore::default();
        authenticate_sender_constrained(
            &auth,
            &token,
            &proof.compact_jws,
            "https://ops.example.test/mcp",
            "POST",
            &DpopVerifier::new(),
            &mut replay_store,
        )
        .await
        .expect("first proof use succeeds");
        let error = authenticate_sender_constrained(
            &auth,
            &token,
            &proof.compact_jws,
            "https://ops.example.test/mcp",
            "POST",
            &DpopVerifier::new(),
            &mut replay_store,
        )
        .await
        .expect_err("second proof use must be rejected as replay");
        assert!(matches!(
            error,
            SenderConstrainedAuthError::Dpop(DpopError::Replay)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hostile_confirmation_mismatches_do_not_consume_replay_capacity() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let mut replay_store = TestDpopReplayStore::default();

        for index in 0..64 {
            let jti = format!("hostile-confirmation-mismatch-{index}");
            let token = token_with_jti_and_cnf(&jti, json!({"jkt": "wrong-jkt"}));
            let proof = signed_dpop_proof(&token, "https://ops.example.test/mcp", "POST", &jti);
            let error = authenticate_sender_constrained(
                &auth,
                &token,
                &proof.compact_jws,
                "https://ops.example.test/mcp",
                "POST",
                &DpopVerifier::new(),
                &mut replay_store,
            )
            .await
            .expect_err("a mismatched confirmation key must fail");
            assert_eq!(
                error
                    .auth_error()
                    .expect("confirmation denial must remain an authentication failure")
                    .decision_code(),
                "DPOP_CONFIRMATION_CLAIM_MISMATCH"
            );
        }

        assert!(
            replay_store.0.is_empty(),
            "attacker-key proofs must not consume or evict replay entries"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn default_and_strong_profiles_allow_reusable_bearer_tokens() {
        let mut configs = vec![("default", AuthConfig::default())];
        configs.extend([
            (
                "L2Strong",
                AuthConfig::with_profile(AuthSecurityProfile::L2Strong),
            ),
            (
                "L3Boundary",
                AuthConfig::with_profile(AuthSecurityProfile::L3Boundary),
            ),
        ]);

        for (name, mut config) in configs {
            config.mode = AuthMode::Delegation;
            config.delegation_secret = Some("test-secret".to_string());
            config.delegation_issuer = "issuer".to_string();
            config.delegation_audience = "audience".to_string();

            let auth = Authenticator::new(config).expect("auth");
            let token = token_with_jti(&format!("{name}-streamable"));

            auth.authenticate_token(&HeaderMap::new(), &token)
                .await
                .expect("first use should pass");
            auth.authenticate_token(&HeaderMap::new(), &token)
                .await
                .expect("second use should also pass");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_bearer_jti_replay_guard_rejects_replayed_jti() {
        let auth = Authenticator::new(AuthConfig {
            mode: AuthMode::Delegation,
            delegation_secret: Some("test-secret".to_string()),
            delegation_issuer: "issuer".to_string(),
            delegation_audience: "audience".to_string(),
            jti_enforce_bearer: true,
            ..Default::default()
        })
        .expect("auth");
        let token = token_with_jti("replay-default-1");

        auth.authenticate_token(&HeaderMap::new(), &token)
            .await
            .expect("first use should pass");
        let replay = auth
            .authenticate_token(&HeaderMap::new(), &token)
            .await
            .expect_err("second use should be rejected");

        assert!(matches!(replay, AuthError::ReplayDetected));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shared_jti_replay_store_rejects_replay_across_authenticators() {
        let config = AuthConfig {
            mode: AuthMode::Delegation,
            delegation_secret: Some("test-secret".to_string()),
            delegation_issuer: "issuer".to_string(),
            delegation_audience: "audience".to_string(),
            jti_enforce_bearer: true,
            jti_cache_size: 0,
            ..Default::default()
        };
        let store = InMemoryJtiReplayStore::shared(Duration::from_secs(300), 128);
        let first_auth =
            Authenticator::new_with_jti_replay_store(config.clone(), store.clone()).expect("auth");
        let second_auth = Authenticator::new_with_jti_replay_store(config, store).expect("auth");
        let token = token_with_jti("shared-replay-1");

        first_auth
            .authenticate_token(&HeaderMap::new(), &token)
            .await
            .expect("first authenticator should accept first use");
        let replay = second_auth
            .authenticate_token(&HeaderMap::new(), &token)
            .await
            .expect_err("second authenticator should reject shared replay");

        assert!(matches!(replay, AuthError::ReplayDetected));
    }

    #[test]
    fn custom_jti_replay_store_requires_positive_ttl() {
        let store = InMemoryJtiReplayStore::shared(Duration::from_secs(300), 128);
        let err = Authenticator::new_with_jti_replay_store(
            AuthConfig {
                mode: AuthMode::Delegation,
                delegation_secret: Some("test-secret".to_string()),
                delegation_issuer: "issuer".to_string(),
                delegation_audience: "audience".to_string(),
                jti_enforce_bearer: true,
                jti_ttl_s: 0.0,
                jti_cache_size: 0,
                ..Default::default()
            },
            store,
        )
        .expect_err("disabled replay ttl should reject custom store");

        assert!(matches!(err, AuthError::ConfigError(_)));
    }

    /// Executes strict_bearer_rejects_extra_space.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// use http::header::AUTHORIZATION;
    ///
    /// use http::{HeaderMap, HeaderValue};
    ///
    ///
    ///
    /// let mut headers = HeaderMap::new();
    ///
    /// headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
    ///
    /// let _ = headers;
    /// ```
    #[tokio::test(flavor = "current_thread")]
    async fn strict_bearer_rejects_extra_space() {
        let auth = Authenticator::new(delegation_config_no_jti()).expect("auth");
        let token = token_without_jti();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer  {token}")).expect("header"),
        );
        let result = auth.authenticate_headers(&headers).await;
        assert!(
            matches!(result, Err(AuthError::MissingToken)),
            "expected strict bearer parsing to reject extra spaces"
        );
    }

    /// Executes introspection_uses_client_auth_header.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// use mcp_toolkit_auth::AuthConfig;
    ///
    ///
    ///
    /// let _ = AuthConfig::default();
    /// ```
    #[tokio::test(flavor = "current_thread")]
    async fn introspection_uses_client_auth_header() {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let payload = json!({
            "active": true,
            "iss": "issuer",
            "aud": "audience",
            "sub": "user-123",
            "exp": exp,
            "scope": "read"
        });
        let header_capture = Arc::new(Mutex::new(None));
        let state = IntrospectionState {
            payload,
            require_basic: true,
            header_capture: header_capture.clone(),
        };
        let (url, shutdown_tx) = spawn_introspection_server(state).await;

        let auth = Authenticator::new(AuthConfig {
            mode: AuthMode::Introspection,
            introspection_url: Some(url),
            introspection_client_id: Some("client".to_string()),
            introspection_client_secret: Some("secret".to_string()),
            introspection_auth_method: ClientAuthMethod::ClientSecretBasic,
            issuer: Some("issuer".to_string()),
            audience: Some("audience".to_string()),
            jti_ttl_s: 0.0,
            jti_cache_size: 0,
            strict_oauth: true,
            ..Default::default()
        })
        .expect("auth");

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer inbound-token"),
        );
        let result = auth.authenticate_headers(&headers).await;
        let _ = shutdown_tx.send(());

        assert!(result.is_ok(), "expected introspection to succeed");
        let captured = header_capture.lock().await.clone().unwrap_or_default();
        assert!(
            captured.starts_with("Basic "),
            "expected client auth to use basic header"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn introspection_mode_trusts_only_introspection_claims() {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let token = [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsInN1YiI6InVzZXItMTIzIiwic2NvcGUiOiJ1bnRydXN0ZWQtc2NvcGUiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsia2MtYWRtaW4tYWNjZXNzIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsicmVhbG0tbWFuYWdlbWVudCI6eyJyb2xlcyI6WyJ2aWV3LXVzZXJzIl19fX0",
            "invalid-signature-not-checked",
        ]
        .join(".");
        let payload = json!({
            "active": true,
            "iss": "issuer",
            "aud": "audience",
            "sub": "user-123",
            "exp": exp,
            "scope": "read"
        });
        let header_capture = Arc::new(Mutex::new(None));
        let state = IntrospectionState {
            payload,
            require_basic: true,
            header_capture,
        };
        let (url, shutdown_tx) = spawn_introspection_server(state).await;

        let auth = Authenticator::new(AuthConfig {
            mode: AuthMode::Introspection,
            introspection_url: Some(url),
            introspection_client_id: Some("client".to_string()),
            introspection_client_secret: Some("secret".to_string()),
            introspection_auth_method: ClientAuthMethod::ClientSecretBasic,
            issuer: Some("issuer".to_string()),
            audience: Some("audience".to_string()),
            jti_ttl_s: 0.0,
            jti_cache_size: 0,
            strict_oauth: true,
            ..Default::default()
        })
        .expect("auth");

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
        );
        let result = auth.authenticate_headers(&headers).await;
        let _ = shutdown_tx.send(());

        let context = result.expect("expected introspection to succeed");
        assert_eq!(context.scopes, vec!["read"]);
        assert_eq!(context.roles, Vec::<String>::new());
        assert_eq!(context.claims.get("active"), Some(&json!(true)));
        assert_eq!(context.claims.get("realm_access"), None);
        assert_eq!(context.claims.get("resource_access"), None);
    }

    /// Executes introspection_rejects_mismatched_issuer.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Panics
    /// * None.
    ///
    /// ```rust,no_run
    /// use mcp_toolkit_auth::AuthConfig;
    ///
    ///
    ///
    /// let _ = AuthConfig::default();
    /// ```
    #[tokio::test(flavor = "current_thread")]
    async fn introspection_rejects_mismatched_issuer() {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let payload = json!({
            "active": true,
            "iss": "other-issuer",
            "aud": "audience",
            "sub": "user-123",
            "exp": exp
        });
        let header_capture = Arc::new(Mutex::new(None));
        let state = IntrospectionState {
            payload,
            require_basic: true,
            header_capture,
        };
        let (url, shutdown_tx) = spawn_introspection_server(state).await;

        let auth = Authenticator::new(AuthConfig {
            mode: AuthMode::Introspection,
            introspection_url: Some(url),
            introspection_client_id: Some("client".to_string()),
            introspection_client_secret: Some("secret".to_string()),
            introspection_auth_method: ClientAuthMethod::ClientSecretBasic,
            issuer: Some("issuer".to_string()),
            audience: Some("audience".to_string()),
            jti_ttl_s: 0.0,
            jti_cache_size: 0,
            strict_oauth: true,
            ..Default::default()
        })
        .expect("auth");

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer inbound-token"),
        );
        let result = auth.authenticate_headers(&headers).await;
        let _ = shutdown_tx.send(());

        assert!(
            matches!(result, Err(AuthError::InvalidToken)),
            "expected issuer mismatch to fail"
        );
    }
}
