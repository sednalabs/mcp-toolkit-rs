//! OAuth 2.0 Token Introspection
//!
//! Provides support for OAuth 2.0 Token Introspection (RFC 7662), enabling
//! runtime verification of access tokens against an authorization server.
//!
//! ## Rationale
//! Allows resource servers to verify token state (active/inactive) and obtain
//! metadata (scopes, subject) directly from the authorization server.
//!
//! ## Security Boundaries
//! * **Size Limiting**: Enforces strict payload limits on introspection responses to prevent DoS.
//! * **Credential Handling**: Uses `basic_auth` or `client_secret_post` to securely authenticate with the introspection endpoint.
//! * **Caching**: Caches introspection results using token hashes to balance latency with token revocation responsiveness.
//!
//! ## References
//! * [RFC 7662] OAuth 2.0 Token Introspection.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::claims::validate_issuer_audience;
use crate::providers::read_body_limited;
use crate::util::token_ref;
use crate::{AuthError, AuthMode, Authenticator, ClientAuthMethod};

const INTROSPECTION_MAX_BYTES: usize = 1024 * 1024;

/// In-memory cache for token introspection results.
#[derive(Debug)]
pub(crate) struct IntrospectionCache {
    ttl: Duration,
    capacity: usize,
    entries: HashMap<String, (Value, Option<Instant>)>,
}

impl IntrospectionCache {
    /// Creates a new `IntrospectionCache` with the specified TTL and capacity.
    pub(crate) fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            entries: HashMap::new(),
        }
    }

    /// Fetches a cached introspection result for the given token hash.
    ///
    /// # Returns
    /// Returns the cached `Value` if present and valid; otherwise `None`.
    pub(crate) fn get(&self, hashed_token: &str) -> Option<Value> {
        if self.ttl.is_zero() {
            return None;
        }
        let now = Instant::now();
        if let Some((payload, expires_at)) = self.entries.get(hashed_token) {
            if let Some(expiry) = expires_at {
                if now > *expiry {
                    return None;
                }
            }
            return Some(payload.clone());
        }
        None
    }

    /// Stores an introspection result in the cache.
    pub(crate) fn set(&mut self, hashed_token: &str, payload: Value, exp: Option<i64>) {
        if self.ttl.is_zero() {
            return;
        }

        let now_inst = Instant::now();
        self.entries
            .retain(|_, (_, expiry)| expiry.map(|e| e > now_inst).unwrap_or(true));

        if self.entries.len() >= self.capacity {
            if let Some(key) = self.entries.keys().next().cloned() {
                self.entries.remove(&key);
            }
        }

        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let expires_at = exp
            .and_then(|seconds| {
                let remaining = seconds.saturating_sub(now_epoch);
                if remaining <= 0 {
                    None
                } else {
                    let expiry = now_inst + Duration::from_secs(remaining as u64);
                    let ttl_expiry = now_inst + self.ttl;
                    if expiry < ttl_expiry {
                        Some(expiry)
                    } else {
                        Some(ttl_expiry)
                    }
                }
            })
            .or_else(|| Some(now_inst + self.ttl));

        self.entries
            .insert(hashed_token.to_string(), (payload, expires_at));
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct IntrospectionResponse {
    active: bool,
    scope: Option<String>,
    sub: Option<String>,
    exp: Option<i64>,
    client_id: Option<String>,
    azp: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

impl Authenticator {
    /// Performs token introspection against the configured authorization server.
    ///
    /// # Errors
    /// * Returns `AuthError::Generic` if the request fails, the response is too large,
    ///   non-JSON, or the token is reported inactive.
    ///
    /// # Security
    /// * **Credential Safety**: Uses secure authentication methods (`basic_auth` or
    ///   `client_secret_post`) to talk to the authorization server.
    /// * **DoS Protection**: Enforces size limits on introspection responses.
    /// * **Cache Security**: Stores results indexed by a token hash to prevent leaking
    ///   sensitive token data in memory.
    pub(crate) async fn introspect_token(&self, token: &str) -> Result<Value, AuthError> {
        let url = match &self.config.introspection_url {
            Some(url) => url,
            None => return Ok(Value::Null),
        };

        let hashed_token = token_ref(token);

        if let Some(cache_lock) = &self.introspection_cache {
            let cache = cache_lock.read().map_err(|_| AuthError::Generic {
                message: "Introspection cache lock poisoned".to_string(),
                status_code: 500,
                code: None,
                reason: None,
            })?;
            if let Some(cached) = cache.get(&hashed_token) {
                return Ok(cached);
            }
        }

        let mut form_params = vec![("token", token)];

        let client_id = self.config.introspection_client_id.as_deref();
        let client_secret = self.config.introspection_client_secret.as_deref();

        if matches!(
            self.config.introspection_auth_method,
            ClientAuthMethod::ClientSecretPost
        ) {
            if let Some(id) = client_id {
                form_params.push(("client_id", id));
            }
            if let Some(secret) = client_secret {
                form_params.push(("client_secret", secret));
            }
        }

        let mut request = self
            .client
            .post(url)
            .timeout(Duration::from_secs(5))
            .form(&form_params);

        if matches!(
            self.config.introspection_auth_method,
            ClientAuthMethod::ClientSecretBasic
        ) {
            if let (Some(id), Some(secret)) = (client_id, client_secret) {
                request = request.basic_auth(id, Some(secret));
            }
        }

        let response = request.send().await.map_err(|_| AuthError::Generic {
            message: "Token introspection failed".to_string(),
            status_code: 401,
            code: None,
            reason: Some("introspection_failed"),
        })?;

        if !response.status().is_success() {
            return Err(AuthError::Generic {
                message: "Token introspection failed".to_string(),
                status_code: 401,
                code: None,
                reason: Some("introspection_failed"),
            });
        }

        let is_json = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("application/json"))
            .unwrap_or(false);

        if !is_json {
            return Err(AuthError::Generic {
                message: "Introspection response was not JSON".to_string(),
                status_code: 502,
                code: None,
                reason: None,
            });
        }

        if response.content_length().unwrap_or(0) > INTROSPECTION_MAX_BYTES as u64 {
            return Err(AuthError::Generic {
                message: "Introspection response too large".to_string(),
                status_code: 502,
                code: None,
                reason: None,
            });
        }

        let body = read_body_limited(response, INTROSPECTION_MAX_BYTES, "Introspection").await?;
        let payload: IntrospectionResponse =
            serde_json::from_slice(&body).map_err(|_| AuthError::Generic {
                message: "Invalid introspection response".to_string(),
                status_code: 401,
                code: None,
                reason: Some("introspection_invalid_response"),
            })?;

        if !payload.active {
            return Err(AuthError::Generic {
                message: "Token inactive".to_string(),
                status_code: 401,
                code: None,
                reason: Some("introspection_inactive"),
            });
        }

        let claims = serde_json::to_value(&payload).map_err(|_| AuthError::InvalidToken)?;
        if matches!(self.config.mode, AuthMode::Introspection) {
            validate_issuer_audience(&claims, &self.config)?;
        }

        if let Some(cache_lock) = &self.introspection_cache {
            if let Ok(mut cache) = cache_lock.write() {
                cache.set(&hashed_token, claims.clone(), payload.exp);
            }
        }

        Ok(claims)
    }
}
