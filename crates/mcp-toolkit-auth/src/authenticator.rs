use std::sync::{Arc, RwLock};
use std::time::Duration;

use dpop_verifier::{DpopError, DpopVerifier, ReplayContext, ReplayStore};
use http::HeaderMap;
use reqwest::Client;
use serde_json::{json, Value};

use crate::bearer::parse_strict_bearer_authorization;
use crate::claims::{
    extract_roles, extract_scopes, has_confirmation_claim, merge_claims, validate_issuer_audience,
};
use crate::providers::{IntrospectionCache, JwksCache};
use crate::replay::{InMemoryJtiReplayStore, SharedJtiReplayStore};
use crate::util::{auth_debug_event, hash_identifier, token_ref};
use crate::{
    AuthConfig, AuthContext, AuthError, AuthMode, DpopProof, DpopToken, SenderConstrainedAuthError,
    VerifiedAuthContext,
};

#[derive(Debug, Clone, Copy)]
enum TokenBinding {
    BearerOnly,
    SenderConstrained,
}

struct ConfirmationBoundReplayStore<'a, S: ?Sized> {
    inner: &'a mut S,
    expected_jkt: &'a str,
    confirmation_mismatch: bool,
}

#[async_trait::async_trait]
impl<S: ReplayStore + Send + ?Sized> ReplayStore for ConfirmationBoundReplayStore<'_, S> {
    async fn insert_once(
        &mut self,
        jti_hash: [u8; 32],
        context: ReplayContext<'_>,
    ) -> Result<bool, DpopError> {
        if context.jkt != Some(self.expected_jkt) {
            self.confirmation_mismatch = true;
            return Ok(false);
        }
        self.inner.insert_once(jti_hash, context).await
    }
}

#[derive(Debug, Clone)]
pub struct Authenticator {
    pub(crate) config: Arc<AuthConfig>,
    pub(crate) jti_replay_store: Option<SharedJtiReplayStore>,
    pub(crate) introspection_cache: Option<Arc<RwLock<IntrospectionCache>>>,
    pub(crate) jwks_cache: Option<Arc<JwksCache>>,
    pub(crate) client: Client,
    pub(crate) provenance_marker: Arc<u8>,
}

impl Authenticator {
    pub fn new(config: AuthConfig) -> Result<Self, AuthError> {
        Self::new_with_optional_jti_replay_store(config, None)
    }

    /// Builds an authenticator with a caller-owned JTI replay store.
    ///
    /// The supplied store is used for Bearer JTI checks when
    /// `AuthConfig::jti_enforce_bearer` is enabled. `AuthConfig::jti_ttl_s`
    /// must remain positive; the
    /// `jti_cache_size` setting only controls the default in-memory store. Use
    /// this for service-owned shared backends such as a DAS SQLite/Redis replay
    /// table.
    ///
    /// # Errors
    /// Returns [`AuthError`] when the auth configuration is invalid.
    ///
    /// # Security
    /// The replay store must perform atomic check-and-record operations. A
    /// shared store only closes cross-worker replay gaps when every worker uses
    /// the same backend and TTL semantics.
    pub fn new_with_jti_replay_store(
        config: AuthConfig,
        jti_replay_store: SharedJtiReplayStore,
    ) -> Result<Self, AuthError> {
        Self::new_with_optional_jti_replay_store(config, Some(jti_replay_store))
    }

    fn new_with_optional_jti_replay_store(
        config: AuthConfig,
        jti_replay_store: Option<SharedJtiReplayStore>,
    ) -> Result<Self, AuthError> {
        if matches!(config.mode, AuthMode::Jwks) {
            if config.jwks_url.is_none() || config.issuer.is_none() || config.audience.is_none() {
                return Err(AuthError::ConfigError(
                    "JWKS auth requires jwks_url, issuer, and audience.".to_string(),
                ));
            }
            if config.introspection_url.is_some()
                && (config.introspection_client_id.is_none()
                    || config.introspection_client_secret.is_none())
            {
                return Err(AuthError::ConfigError(
                    "Introspection requires client_id and client_secret.".to_string(),
                ));
            }
        } else if matches!(config.mode, AuthMode::Introspection) {
            if config.introspection_url.is_none() {
                return Err(AuthError::ConfigError(
                    "Introspection mode requires introspection_url.".to_string(),
                ));
            }
        } else if config.introspection_url.is_some() {
            return Err(AuthError::ConfigError(
                "Introspection requires jwks or introspection auth mode.".to_string(),
            ));
        }

        let custom_jti_replay_store = jti_replay_store.is_some();
        if custom_jti_replay_store && config.jti_ttl_s <= 0.0 {
            return Err(AuthError::ConfigError(
                "Custom JTI replay store requires positive jti_ttl_s.".to_string(),
            ));
        }
        if config.jti_enforce_bearer
            && !custom_jti_replay_store
            && (config.jti_ttl_s <= 0.0 || config.jti_cache_size <= 0)
        {
            return Err(AuthError::ConfigError(
                "Bearer JTI replay enforcement requires positive jti_ttl_s and jti_cache_size."
                    .to_string(),
            ));
        }

        let jti_replay_store = match (jti_replay_store, config.jti_ttl_s > 0.0) {
            (Some(store), true) => Some(store),
            (None, true) if config.jti_cache_size > 0 => Some(InMemoryJtiReplayStore::shared(
                Duration::from_secs_f64(config.jti_ttl_s),
                config.jti_cache_size as usize,
            )),
            _ => None,
        };

        let introspection_cache = if config.introspection_cache_ttl_s > 0.0 {
            Some(Arc::new(RwLock::new(IntrospectionCache::new(
                Duration::from_secs_f64(config.introspection_cache_ttl_s),
                10000,
            ))))
        } else {
            None
        };

        let jwks_cache = if matches!(config.mode, AuthMode::Jwks) {
            let url = config.jwks_url.clone().unwrap_or_default();
            Some(Arc::new(JwksCache::new(url, Duration::from_secs(300))))
        } else {
            None
        };

        auth_debug_event(
            "auth.config",
            json!({
                "mode": format!("{:?}", config.mode),
                "strict_oauth": config.strict_oauth,
                "issuer": config.issuer,
                "audience": config.audience,
                "jwks_url": config.jwks_url,
                "introspection_url": config.introspection_url,
                "introspection_cache_ttl_s": config.introspection_cache_ttl_s,
                "introspection_force": config.introspection_force,
                "required_scopes": config.required_scopes,
                "actor_claim": config.actor_claim,
                "jti_ttl_s": config.jti_ttl_s,
                "jti_cache_size": config.jti_cache_size,
                "jti_enforce_bearer": config.jti_enforce_bearer,
            }),
        );

        Ok(Self {
            config: Arc::new(config),
            jti_replay_store,
            introspection_cache,
            jwks_cache,
            client: Client::new(),
            provenance_marker: Arc::new(0),
        })
    }

    pub async fn authenticate_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthContext, AuthError> {
        let token =
            bearer_token(headers, self.config.strict_oauth).ok_or(AuthError::MissingToken)?;
        self.authenticate_token_with_binding(&token, TokenBinding::BearerOnly)
            .await
    }

    /// Authenticates request headers and returns an authenticator-issued context.
    ///
    /// # Errors
    /// Returns [`AuthError`] when the bearer credential is missing or fails
    /// the configured authentication and replay checks.
    ///
    /// # Security
    /// The returned [`VerifiedAuthContext`] has no public constructor and is
    /// the appropriate input for downstream operations that need proof this
    /// exact context came from `Authenticator`, rather than merely trusting
    /// context-shaped data.
    pub async fn authenticate_verified_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<VerifiedAuthContext, AuthError> {
        self.authenticate_headers(headers)
            .await
            .map(|context| {
                VerifiedAuthContext::from_authenticator(context, self.provenance_marker.clone())
            })
    }

    pub async fn authenticate_token(
        &self,
        _headers: &HeaderMap,
        token: &str,
    ) -> Result<AuthContext, AuthError> {
        self.authenticate_token_with_binding(token, TokenBinding::BearerOnly)
            .await
    }

    /// Authenticates a sender-constrained token with an exact DPoP proof.
    ///
    /// # Errors
    /// Returns [`SenderConstrainedAuthError`] when DPoP proof verification, the
    /// `cnf.jkt` match, or normal token policy validation fails.
    ///
    /// # Security
    /// This is the only sender-constrained entrypoint. It verifies the compact
    /// access token first, then verifies the DPoP proof and binds it to the
    /// exact token, method, URI, and token `cnf.jkt` in the same call.
    ///
    /// `access_token` must be extracted from an RFC 9449
    /// `Authorization: DPoP <token>` header, for example with
    /// [`crate::parse_strict_dpop_authorization`]. It must not come from an
    /// ordinary `Bearer` authorization header.
    ///
    /// `expected_htu` and `expected_htm` must come from the canonical inbound
    /// request after trusted proxy handling. Configure nonce and freshness
    /// policy on `verifier`; `replay_store` must provide shared atomic
    /// insert-once semantics across the service's workers. The toolkit guards
    /// the replay store with the token's expected confirmation thumbprint, so a
    /// proof signed by a different key is rejected without consuming replay
    /// capacity.
    pub async fn authenticate_sender_constrained_dpop<S: ReplayStore + Send + ?Sized>(
        &self,
        access_token: DpopToken<'_>,
        proof: DpopProof<'_>,
        expected_htu: &str,
        expected_htm: &str,
        verifier: &DpopVerifier,
        replay_store: &mut S,
    ) -> Result<AuthContext, SenderConstrainedAuthError> {
        let access_token = access_token.as_str();
        let context = self
            .authenticate_token_with_binding(access_token, TokenBinding::SenderConstrained)
            .await
            .map_err(SenderConstrainedAuthError::Authentication)?;
        let expected_jkt = confirmation_jkt(&context.claims).ok_or_else(|| {
            SenderConstrainedAuthError::Authentication(confirmation_claim_mismatch(access_token))
        })?;
        let mut guarded_store = ConfirmationBoundReplayStore {
            inner: replay_store,
            expected_jkt,
            confirmation_mismatch: false,
        };
        let verification = verifier
            .verify(
                &mut guarded_store,
                proof.as_str(),
                expected_htu,
                expected_htm,
                Some(access_token),
            )
            .await;
        if guarded_store.confirmation_mismatch {
            return Err(SenderConstrainedAuthError::Authentication(
                confirmation_claim_mismatch(access_token),
            ));
        }
        verification.map_err(SenderConstrainedAuthError::Dpop)?;

        auth_debug_event(
            "auth.dpop_success",
            json!({
                "actor_hash": hash_identifier(&context.actor),
                "token_ref": context.token_ref,
            }),
        );
        Ok(context)
    }

    async fn authenticate_token_with_binding(
        &self,
        token: &str,
        binding: TokenBinding,
    ) -> Result<AuthContext, AuthError> {
        let mut claims = match self.config.mode {
            AuthMode::Delegation => self.decode_delegation(token)?,
            AuthMode::Jwks => {
                if self.config.introspection_force && self.config.introspection_url.is_some() {
                    let introspected = self.introspect_token(token).await?;
                    validate_issuer_audience(&introspected, &self.config)?;
                    introspected
                } else {
                    self.decode_with_jwks(token).await?
                }
            }
            AuthMode::Introspection => self.introspect_token(token).await?,
        };

        let subject_hint = claims
            .get("sub")
            .and_then(|value| value.as_str())
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(hash_identifier);
        let scope_hint = claims
            .get("scope")
            .cloned()
            .or_else(|| claims.get("scp").cloned());

        if matches!(self.config.mode, AuthMode::Jwks)
            && self.config.introspection_url.is_some()
            && !self.config.introspection_force
        {
            let introspected = self.introspect_token(token).await?;
            claims = merge_claims(&claims, &introspected);
        }

        validate_confirmation_claim(&claims, binding, token)?;

        let azp = claims
            .get("azp")
            .or_else(|| claims.get("client_id"))
            .and_then(|value| value.as_str())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        auth_debug_event(
            "auth.claims",
            json!({
                "mode": format!("{:?}", self.config.mode),
                "token_binding": match binding {
                    TokenBinding::BearerOnly => "bearer_only",
                    TokenBinding::SenderConstrained => "sender_constrained_preflight",
                },
                "issuer": self.config.issuer,
                "audience": self.config.audience,
                "claims_iss": claims.get("iss").cloned(),
                "claims_aud": claims.get("aud").cloned(),
                "claims_azp": azp,
                "claims_scope": scope_hint,
                "subject_hash": subject_hint,
                "token_ref": token_ref(token),
            }),
        );

        let actor_claim = self.config.actor_claim.trim();
        let actor_value = claims.get(actor_claim);
        let actor = actor_value
            .and_then(|value| value.as_str())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                auth_debug_event(
                    "auth.missing_actor",
                    json!({
                        "actor_claim": actor_claim,
                        "token_ref": token_ref(token),
                    }),
                );
                AuthError::Generic {
                    message: format!("Token missing actor claim ({actor_claim})"),
                    status_code: 401,
                    code: Some("AUTH_MISSING_ACTOR"),
                    reason: Some("missing_actor"),
                }
            })?;

        let mut scopes = extract_scopes(&claims);
        let roles = extract_roles(&claims);

        if !self.config.required_scopes.is_empty() {
            let missing: Vec<String> = self
                .config
                .required_scopes
                .iter()
                .filter(|scope| !scopes.contains(scope))
                .cloned()
                .collect();
            if !missing.is_empty() {
                auth_debug_event(
                    "auth.missing_scopes",
                    json!({
                        "missing_scopes": missing,
                        "token_scopes": scopes,
                        "token_ref": token_ref(token),
                    }),
                );
                return Err(AuthError::MissingScopes);
            }
        }

        if matches!(binding, TokenBinding::BearerOnly) && self.config.jti_enforce_bearer {
            let jti_replay_store = self.jti_replay_store.as_ref().ok_or_else(|| {
                AuthError::ConfigError(
                    "Bearer JTI replay enforcement requires an enabled replay store.".to_string(),
                )
            })?;
            let jti = claims
                .get("jti")
                .and_then(|value| value.as_str())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .ok_or(AuthError::InvalidToken)?;

            let replay_seen = jti_replay_store.seen(&jti).map_err(|error| {
                AuthError::new(format!("JTI replay store failed: {error}"))
                    .with_status(500)
                    .with_code("AUTH_REPLAY_STORE_ERROR")
                    .with_reason("replay_store_error")
            })?;

            if replay_seen {
                auth_debug_event(
                    "auth.replay_detected",
                    json!({
                        "jti_hash": hash_identifier(&jti),
                        "token_ref": token_ref(token),
                    }),
                );
                return Err(AuthError::ReplayDetected);
            }
        }

        scopes.sort();
        scopes.dedup();

        let subject = claims
            .get("sub")
            .and_then(|value| value.as_str())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        auth_debug_event(
            match binding {
                TokenBinding::BearerOnly => "auth.success",
                TokenBinding::SenderConstrained => "auth.token_preflight_success",
            },
            json!({
                "actor_hash": hash_identifier(&actor),
                "azp": azp,
                "scopes_count": scopes.len(),
                "roles_count": roles.len(),
                "subject_hash": subject.as_ref().map(|value| hash_identifier(value)),
                "token_ref": token_ref(token),
            }),
        );
        Ok(AuthContext {
            actor,
            scopes,
            roles,
            claims,
            azp,
            subject,
            token_ref: token_ref(token),
            raw_token: token.to_string(),
        })
    }
}

fn validate_confirmation_claim(
    claims: &Value,
    binding: TokenBinding,
    token: &str,
) -> Result<(), AuthError> {
    match binding {
        TokenBinding::BearerOnly if has_confirmation_claim(claims) => {
            auth_debug_event(
                "auth.sender_constrained_bearer_rejected",
                json!({
                    "token_ref": token_ref(token),
                }),
            );
            Err(AuthError::new("Invalid bearer token.")
                .with_code("SENDER_CONSTRAINED_BEARER_TOKEN")
                .with_reason("sender_constrained"))
        }
        TokenBinding::BearerOnly => Ok(()),
        TokenBinding::SenderConstrained if confirmation_jkt(claims).is_some() => Ok(()),
        TokenBinding::SenderConstrained => Err(confirmation_claim_mismatch(token)),
    }
}

fn confirmation_jkt(claims: &Value) -> Option<&str> {
    claims
        .get("cnf")
        .and_then(Value::as_object)
        .and_then(|cnf| cnf.get("jkt"))
        .and_then(Value::as_str)
        .filter(|jkt| !jkt.is_empty())
}

fn confirmation_claim_mismatch(token: &str) -> AuthError {
    auth_debug_event(
        "auth.dpop_confirmation_rejected",
        json!({
            "token_ref": token_ref(token),
        }),
    );
    AuthError::new("Invalid bearer token.")
        .with_code("DPOP_CONFIRMATION_CLAIM_MISMATCH")
        .with_reason("dpop_confirmation_mismatch")
}

fn bearer_token(headers: &HeaderMap, strict: bool) -> Option<String> {
    if strict {
        return parse_strict_bearer_authorization(headers)
            .ok()
            .map(|token| token.as_str().to_owned());
    }

    let mut values = headers.get_all(http::header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let raw = value.to_str().ok()?;
    let raw: String = raw.chars().filter(|c| !c.is_control()).collect();
    let raw = raw.trim();
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}
