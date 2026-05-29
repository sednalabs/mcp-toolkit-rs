pub(crate) use crate::auth_context_from_parts;
pub(crate) use crate::auth_context_ref_from_parts;
pub(crate) use crate::claims::extract_scopes;
pub(crate) use crate::{
    AuthConfig, AuthContext, AuthError, AuthMode, AuthRequestContext, Authenticator,
    ClientAuthMethod,
};

mod tests {
    use super::{
        auth_context_from_parts, auth_context_ref_from_parts, AuthConfig, AuthContext, AuthError,
        AuthMode, AuthRequestContext, Authenticator, ClientAuthMethod,
    };
    use axum::extract::State;
    use axum::http::{header::AUTHORIZATION, HeaderMap, HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::Router;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::{json, Value};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
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

        (format!("http://{addr}/introspect"), shutdown_tx)
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
