pub(crate) use crate::auth_context_from_parts;
pub(crate) use crate::auth_context_ref_from_parts;
pub(crate) use crate::claims::extract_scopes;
pub(crate) use crate::{
    AuthConfig, AuthContext, AuthError, AuthMode, AuthRequestContext, AuthSecurityProfile,
    Authenticator, ClientAuthMethod, InMemoryJtiReplayStore,
};

mod tests {
    use super::{
        auth_context_from_parts, auth_context_ref_from_parts, AuthConfig, AuthContext, AuthError,
        AuthMode, AuthRequestContext, AuthSecurityProfile, Authenticator, ClientAuthMethod,
        InMemoryJtiReplayStore,
    };
    use axum::extract::State;
    use axum::http::{header::AUTHORIZATION, HeaderMap, HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::Router;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::{json, Value};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::sync::{oneshot, Mutex};

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

    #[test]
    fn supplemental_jwt_claims_accepts_trimmed_jwt() {
        let claims = json!({
            "sub": "user-123",
            "realm_access": {
                "roles": ["kc-admin-access"]
            }
        });
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("token");
        let trimmed = format!("  {token}  ");

        let decoded = super::supplemental_jwt_claims(&trimmed).expect("supplemental claims");

        assert_eq!(decoded.get("sub"), Some(&json!("user-123")));
        assert_eq!(
            decoded
                .pointer("/realm_access/roles/0")
                .and_then(Value::as_str),
            Some("kc-admin-access")
        );
    }

    #[test]
    fn supplemental_jwt_claims_rejects_non_object_payload() {
        let token = encode(
            &Header::default(),
            &json!(["not", "an", "object"]),
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("token");

        assert!(super::supplemental_jwt_claims(&token).is_none());
    }

    /// Executes jti_not_required_for_token_bound_context.
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
    #[tokio::test(flavor = "current_thread")]
    async fn jti_not_required_for_token_bound_context() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let token = token_without_jti();
        let ctx = AuthRequestContext::token_bound();
        let result = auth
            .authenticate_token_with_context(&HeaderMap::new(), &token, ctx)
            .await;
        assert!(
            result.is_ok(),
            "expected jti to be optional for token-bound auth"
        );
    }

    /// Executes jti_required_for_bearer_only_context.
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
    #[tokio::test(flavor = "current_thread")]
    async fn jti_required_for_bearer_only_context() {
        let auth = Authenticator::new(delegation_config()).expect("auth");
        let token = token_without_jti();
        let ctx = AuthRequestContext::bearer_only();
        let result = auth
            .authenticate_token_with_context(&HeaderMap::new(), &token, ctx)
            .await;
        assert!(
            result.is_err(),
            "expected missing jti to fail for bearer-only auth"
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

            auth.authenticate_token_with_context(
                &HeaderMap::new(),
                &token,
                AuthRequestContext::bearer_only(),
            )
            .await
            .expect("first use should pass");
            auth.authenticate_token_with_context(
                &HeaderMap::new(),
                &token,
                AuthRequestContext::bearer_only(),
            )
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

        auth.authenticate_token_with_context(
            &HeaderMap::new(),
            &token,
            AuthRequestContext::bearer_only(),
        )
        .await
        .expect("first use should pass");
        let replay = auth
            .authenticate_token_with_context(
                &HeaderMap::new(),
                &token,
                AuthRequestContext::bearer_only(),
            )
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
            .authenticate_token_with_context(
                &HeaderMap::new(),
                &token,
                AuthRequestContext::bearer_only(),
            )
            .await
            .expect("first authenticator should accept first use");
        let replay = second_auth
            .authenticate_token_with_context(
                &HeaderMap::new(),
                &token,
                AuthRequestContext::bearer_only(),
            )
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
