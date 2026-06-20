use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use http::HeaderMap;
use reqwest::Client;
use serde_json::json;

use crate::bearer::parse_strict_bearer_authorization;
use crate::claims::{extract_roles, extract_scopes, merge_claims, validate_issuer_audience};
use crate::providers::{IntrospectionCache, JwksCache};
use crate::replay::JtiCache;
use crate::util::{auth_debug_event, hash_identifier, token_ref};
use crate::{AuthConfig, AuthContext, AuthError, AuthMode, AuthRequestContext};

#[derive(Debug, Clone)]
pub struct Authenticator {
    pub(crate) config: Arc<AuthConfig>,
    pub(crate) jti_cache: Option<Arc<Mutex<JtiCache>>>,
    pub(crate) introspection_cache: Option<Arc<RwLock<IntrospectionCache>>>,
    pub(crate) jwks_cache: Option<Arc<JwksCache>>,
    pub(crate) client: Client,
}

impl Authenticator {
    pub fn new(config: AuthConfig) -> Result<Self, AuthError> {
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

        let enforce_replay = config.jti_ttl_s > 0.0 && config.jti_cache_size > 0;
        let jti_cache = if enforce_replay {
            Some(Arc::new(Mutex::new(JtiCache::new(
                Duration::from_secs_f64(config.jti_ttl_s),
                config.jti_cache_size as usize,
            ))))
        } else {
            None
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
            jti_cache,
            introspection_cache,
            jwks_cache,
            client: Client::new(),
        })
    }

    pub async fn authenticate_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthContext, AuthError> {
        let token =
            bearer_token(headers, self.config.strict_oauth).ok_or(AuthError::MissingToken)?;
        self.authenticate_token_with_context(headers, &token, AuthRequestContext::bearer_only())
            .await
    }

    pub async fn authenticate_token(
        &self,
        headers: &HeaderMap,
        token: &str,
    ) -> Result<AuthContext, AuthError> {
        self.authenticate_token_with_context(headers, token, AuthRequestContext::bearer_only())
            .await
    }

    pub async fn authenticate_headers_with_context(
        &self,
        headers: &HeaderMap,
        context: AuthRequestContext,
    ) -> Result<AuthContext, AuthError> {
        let token =
            bearer_token(headers, self.config.strict_oauth).ok_or(AuthError::MissingToken)?;
        self.authenticate_token_with_context(headers, &token, context)
            .await
    }

    pub async fn authenticate_token_with_context(
        &self,
        _headers: &HeaderMap,
        token: &str,
        context: AuthRequestContext,
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
                "bearer_only": context.bearer_only,
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

        if let Some(cache_lock) = &self.jti_cache {
            let enforce_jti = context.bearer_only && self.config.jti_enforce_bearer;
            if !enforce_jti {
                scopes.sort();
                scopes.dedup();

                let subject = claims
                    .get("sub")
                    .and_then(|value| value.as_str())
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty());

                auth_debug_event(
                    "auth.success",
                    json!({
                        "actor_hash": hash_identifier(&actor),
                        "azp": azp,
                        "scopes_count": scopes.len(),
                        "roles_count": roles.len(),
                        "subject_hash": subject.as_ref().map(|value| hash_identifier(value)),
                        "token_ref": token_ref(token),
                    }),
                );
                return Ok(AuthContext {
                    actor,
                    scopes,
                    roles,
                    claims,
                    azp,
                    subject,
                    token_ref: token_ref(token),
                    raw_token: token.to_string(),
                });
            }

            let jti = claims
                .get("jti")
                .and_then(|value| value.as_str())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .ok_or(AuthError::InvalidToken)?;

            let mut cache = cache_lock.lock().map_err(|_| AuthError::Generic {
                message: "JTI cache lock poisoned".to_string(),
                status_code: 500,
                code: None,
                reason: None,
            })?;

            if cache.seen(&jti) {
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
            "auth.success",
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
