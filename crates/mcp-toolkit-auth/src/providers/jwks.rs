//! JWKS Key Management and Caching
//!
//! Handles fetching, caching, and rotation of JSON Web Key Sets (JWKS) for OIDC
//! token validation.
//!
//! ## Rationale
//! Centralizes key management to reduce external network traffic while maintaining
//! security through periodic key rotation and cache invalidation.
//!
//! ## Security Boundaries
//! * **Size Limiting**: Enforces strict payload size limits on JWKS fetches.
//! * **Algorithm Restriction**: Restricts allowed signing algorithms to secure primitives.
//! * **Jitter**: Introduces jitter to cache expiration to prevent synchronized re-fetches.
//! * **Fail-Closed**: Re-fetches keys on unknown `kid` after a short miss cooldown.
//!
//! ## References
//! * [RFC 7517] JSON Web Key (JWK).
//! * [OpenID Connect Discovery 1.0] JWKS endpoint specification.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{JwkSet, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde_json::Value;

use crate::claims::{auth_error_from_jwt, required_claims};
use crate::providers::read_body_limited;
use crate::{AuthError, Authenticator};

const JWKS_MAX_BYTES: usize = 1024 * 1024;
const JWKS_KID_MISS_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);

/// Cache for JWKS provider keys, facilitating efficient validation.
#[derive(Debug)]
pub(crate) struct JwksCache {
    pub(crate) url: String,
    ttl: Duration,
    state: RwLock<JwksState>,
    // Use tokio::sync::Mutex because we hold this guard across an .await point.
    refresh_lock: tokio::sync::Mutex<()>,
    client: Client,
}

#[derive(Debug, Clone)]
struct JwksState {
    fetched_at: Option<Instant>,
    set: Option<JwkSet>,
    next_refresh_at: Option<Instant>,
}

impl JwksCache {
    /// Initializes a new `JwksCache`.
    pub(crate) fn new(url: String, ttl: Duration) -> Self {
        Self {
            url,
            ttl,
            state: RwLock::new(JwksState {
                fetched_at: None,
                set: None,
                next_refresh_at: None,
            }),
            refresh_lock: tokio::sync::Mutex::new(()),
            client: Client::new(),
        }
    }

    /// Retrieves the JWKS, using cached keys if valid.
    ///
    /// # Errors
    /// * Returns `AuthError::Generic` if fetching or parsing keys fails.
    pub(crate) async fn get(&self) -> Result<JwkSet, AuthError> {
        let now = Instant::now();
        {
            let state = self.state.read().map_err(|_| AuthError::Generic {
                message: "JWKS lock poisoned".to_string(),
                status_code: 500,
                code: None,
                reason: None,
            })?;

            if let Some(set) = &state.set {
                if let Some(refresh_at) = state.next_refresh_at {
                    if now < refresh_at {
                        return Ok(set.clone());
                    }
                }
            }
        }

        let _guard = self.refresh_lock.lock().await;

        {
            let state = self.state.read().map_err(|_| AuthError::Generic {
                message: "JWKS lock poisoned".to_string(),
                status_code: 500,
                code: None,
                reason: None,
            })?;

            if let Some(set) = &state.set {
                if let Some(refresh_at) = state.next_refresh_at {
                    if now < refresh_at {
                        return Ok(set.clone());
                    }
                }
            }
        }

        let result = self.fetch_and_store().await;
        result
    }

    async fn refresh_on_kid_miss(&self) -> Result<JwkSet, AuthError> {
        if let Some(set) = self.cached_set_within_kid_miss_cooldown(Instant::now())? {
            return Ok(set);
        }

        let _guard = self.refresh_lock.lock().await;
        if let Some(set) = self.cached_set_within_kid_miss_cooldown(Instant::now())? {
            return Ok(set);
        }
        let result = self.fetch_and_store().await;
        result
    }

    fn cached_set_within_kid_miss_cooldown(
        &self,
        now: Instant,
    ) -> Result<Option<JwkSet>, AuthError> {
        let cooldown = self.ttl.min(JWKS_KID_MISS_REFRESH_COOLDOWN);
        if cooldown.is_zero() {
            return Ok(None);
        }
        let state = self.state.read().map_err(|_| AuthError::Generic {
            message: "JWKS lock poisoned".to_string(),
            status_code: 500,
            code: None,
            reason: None,
        })?;
        match (&state.set, state.fetched_at) {
            (Some(set), Some(fetched_at)) => {
                let age = now.checked_duration_since(fetched_at).unwrap_or_default();
                if age < cooldown {
                    Ok(Some(set.clone()))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    async fn fetch_and_store(&self) -> Result<JwkSet, AuthError> {
        let now = Instant::now();
        let set = self.fetch_jwks().await?;

        let jitter_range = self.ttl.as_secs_f64() * 0.1;
        let jitter = (rand::random::<f64>() - 0.5) * jitter_range;
        let jittered_ttl = Duration::from_secs_f64(self.ttl.as_secs_f64() + jitter);

        {
            let mut state = self.state.write().map_err(|_| AuthError::Generic {
                message: "JWKS lock poisoned".to_string(),
                status_code: 500,
                code: None,
                reason: None,
            })?;
            state.set = Some(set.clone());
            state.fetched_at = Some(now);
            state.next_refresh_at = Some(now + jittered_ttl);
        }

        Ok(set)
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, AuthError> {
        let response = self
            .client
            .get(&self.url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| AuthError::Generic {
                message: format!("Failed to fetch JWKS: {e}"),
                status_code: 500,
                code: None,
                reason: None,
            })?;

        if !response.status().is_success() {
            return Err(AuthError::Generic {
                message: format!("JWKS fetch failed with status {}", response.status()),
                status_code: 500,
                code: None,
                reason: None,
            });
        }

        let is_json = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(is_json_content_type)
            .unwrap_or(false);

        if !is_json {
            return Err(AuthError::Generic {
                message: "JWKS response was not JSON".to_string(),
                status_code: 502,
                code: None,
                reason: None,
            });
        }

        if response.content_length().unwrap_or(0) > JWKS_MAX_BYTES as u64 {
            return Err(AuthError::Generic {
                message: "JWKS response too large".to_string(),
                status_code: 502,
                code: None,
                reason: None,
            });
        }

        let body = read_body_limited(response, JWKS_MAX_BYTES, "JWKS").await?;
        let set: JwkSet = serde_json::from_slice(&body).map_err(|e| AuthError::Generic {
            message: format!("Failed to parse JWKS: {e}"),
            status_code: 500,
            code: None,
            reason: None,
        })?;

        Ok(set)
    }
}

fn is_json_content_type(value: &str) -> bool {
    let media_type = value
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if media_type == "application/json" {
        return true;
    }
    let Some((_, subtype)) = media_type.rsplit_once('/') else {
        return false;
    };
    subtype.ends_with("+json")
}

impl Authenticator {
    /// Validates a JWT bearer token against current JWKS.
    ///
    /// # Errors
    /// * Returns `AuthError` if the token is invalid, uses an unsupported algorithm,
    ///   fails signature verification, or if the `kid` is missing or unknown.
    ///
    /// # Security
    /// * **Algorithm Enforcement**: Restricts signing algorithms to secure variants.
    /// * **Kid Re-fetch**: Refreshes JWKS for unknown `kid` values after a short cooldown,
    ///   preserving key-rotation resilience without unbounded provider traffic.
    pub(crate) async fn decode_with_jwks(&self, token: &str) -> Result<Value, AuthError> {
        let jwks_cache = self
            .jwks_cache
            .as_ref()
            .ok_or_else(|| AuthError::ConfigError("JWKS client not configured.".to_string()))?;

        let mut jwks = jwks_cache.get().await?;

        let header = decode_header(token).map_err(auth_error_from_jwt)?;
        let kid = header
            .kid
            .ok_or_else(|| AuthError::new("Invalid bearer token.").with_reason("missing_kid"))?;

        if !jwks
            .keys
            .iter()
            .any(|key| key.common.key_id.as_deref() == Some(kid.as_str()))
        {
            jwks = jwks_cache.refresh_on_kid_miss().await?;
        }

        let jwk = jwks
            .keys
            .iter()
            .find(|key| key.common.key_id.as_deref() == Some(kid.as_str()))
            .ok_or_else(|| AuthError::new("Invalid bearer token.").with_reason("kid_not_found"))?;

        if let Some(key_use) = &jwk.common.public_key_use {
            if !matches!(key_use, PublicKeyUse::Signature) {
                return Err(AuthError::new("Invalid bearer token.").with_reason("invalid_key_use"));
            }
        }

        let decoding_key = DecodingKey::from_jwk(jwk)
            .map_err(|_| AuthError::new("Invalid bearer token.").with_reason("invalid_key"))?;
        let allowed_alg = match header.alg {
            Algorithm::RS256 | Algorithm::RS512 | Algorithm::ES256 | Algorithm::ES384 => header.alg,
            _ => {
                return Err(
                    AuthError::new("Invalid bearer token.").with_reason("invalid_algorithm")
                );
            }
        };
        let mut validation = Validation::new(allowed_alg);
        validation.algorithms = vec![allowed_alg];
        if let Some(issuer) = &self.config.issuer {
            validation.set_issuer(std::slice::from_ref(issuer));
        }
        if let Some(audience) = &self.config.audience {
            validation.set_audience(std::slice::from_ref(audience));
        }
        validation.required_spec_claims = required_claims();
        validation.leeway = self.config.clock_skew_s as u64;
        validation.validate_nbf = true;

        decode::<Value>(token, &decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(auth_error_from_jwt)
    }
}

#[cfg(test)]
mod tests {
    use super::{is_json_content_type, JwksCache, JwksState, JWKS_KID_MISS_REFRESH_COOLDOWN};
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, Jwk, JwkSet, RSAKeyParameters, RSAKeyType,
    };
    use std::time::{Duration, Instant};

    fn test_jwks(kid: &str) -> JwkSet {
        JwkSet {
            keys: vec![Jwk {
                common: CommonParameters {
                    key_id: Some(kid.to_string()),
                    ..Default::default()
                },
                algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                    key_type: RSAKeyType::RSA,
                    n: "sXch0gYf".to_string(),
                    e: "AQAB".to_string(),
                }),
            }],
        }
    }

    #[test]
    fn jwks_content_type_accepts_standard_json_suffixes() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("application/json; charset=utf-8"));
        assert!(is_json_content_type("application/jwk-set+json"));
        assert!(is_json_content_type(
            "APPLICATION/JWK-SET+JSON; charset=utf-8"
        ));
        assert!(!is_json_content_type("text/plain"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_kid_refresh_reuses_fresh_cached_set() {
        let cache = JwksCache::new(
            "http://127.0.0.1:1/jwks".to_string(),
            Duration::from_secs(300),
        );
        let set = test_jwks("cached");
        {
            let mut state = cache.state.write().expect("jwks state lock");
            *state = JwksState {
                fetched_at: Some(Instant::now()),
                set: Some(set.clone()),
                next_refresh_at: Some(Instant::now() + Duration::from_secs(300)),
            };
        }

        let refreshed = cache
            .refresh_on_kid_miss()
            .await
            .expect("fresh unknown-kid miss should use cache");
        assert_eq!(refreshed, set);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_kid_refresh_attempts_network_after_cooldown() {
        let cache = JwksCache::new(
            "http://127.0.0.1:1/jwks".to_string(),
            Duration::from_secs(300),
        );
        {
            let mut state = cache.state.write().expect("jwks state lock");
            *state = JwksState {
                fetched_at: Some(
                    Instant::now() - JWKS_KID_MISS_REFRESH_COOLDOWN - Duration::from_secs(1),
                ),
                set: Some(test_jwks("stale")),
                next_refresh_at: Some(Instant::now() + Duration::from_secs(300)),
            };
        }

        let err = cache
            .refresh_on_kid_miss()
            .await
            .expect_err("stale unknown-kid miss should attempt refresh");
        assert!(err.to_string().contains("Failed to fetch JWKS"));
    }
}
