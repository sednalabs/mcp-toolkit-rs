//! Bounded native OAuth authorization-code and opaque access-token custody.
//!
//! This is a local state machine for trusted authorization endpoints, not an
//! HTTP router or an identity provider. Applications must verify upstream
//! identity and actual user consent before completing a pending authorization.
use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::Url;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{upstream_oauth::SecretString, AuthError};

/// Trusted access-token validation used by the common resource authenticator.
pub trait LocalTokenVerifier: Send + Sync + fmt::Debug {
    /// Resolve a currently valid opaque access token to verified claims.
    ///
    /// # Errors
    /// Rejects unknown, expired, revoked or non-access credentials.
    fn claims_for_access_token(&self, token: &str) -> Result<Value, AuthError>;
}

#[derive(Clone)]
pub struct NativePublicClient {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub scopes: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct NativeOAuthLimits {
    pub max_pending: usize,
    pub max_grants: usize,
    pub pending_ttl: Duration,
    pub code_ttl: Duration,
    pub access_ttl: Duration,
    pub grant_ttl: Duration,
}

pub struct NativeOAuthConfig {
    pub issuer: String,
    pub resource: String,
    pub clients: Vec<NativePublicClient>,
    pub limits: NativeOAuthLimits,
}

/// Exact downstream authorization parameters. Only S256 PKCE is supported.
/// The HTTP layer must reject duplicate request fields and other grant types.
pub struct NativeAuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub resource: String,
    pub state: String,
    pub scopes: BTreeSet<String>,
    pub s256_challenge: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NativeOAuthError {
    #[error("invalid OAuth configuration")]
    InvalidConfiguration,
    #[error("invalid OAuth authorization request")]
    InvalidRequest,
    #[error("invalid or expired OAuth grant")]
    InvalidGrant,
    #[error("OAuth state capacity unavailable")]
    Capacity,
    #[error("OAuth state unavailable")]
    Unavailable,
}

/// The returned credentials are local MCP tokens, never upstream credentials.
/// The HTTP endpoint must expose them only in the intended token response and
/// send Cache-Control: no-store. Do not log these values.
#[derive(Debug)]
pub struct NativeTokenResponse {
    pub access_token: SecretString,
    pub refresh_token: SecretString,
    pub expires_in: u64,
    pub scope: String,
}

/// A trusted provider grant recovered from a current local access token.
/// No Debug or Serialize implementation: provider credentials never belong
/// in MCP-facing output or diagnostics.
pub struct NativeVerifiedGrant<C> {
    pub subject: String,
    pub client_id: String,
    pub resource: String,
    pub scopes: BTreeSet<String>,
    pub credentials: Arc<C>,
}

struct Pending {
    request: NativeAuthorizationRequest,
    expires: Instant,
}
struct Code<C> {
    request: NativeAuthorizationRequest,
    subject: String,
    credentials: Arc<C>,
    expires: Instant,
}
struct Grant<C> {
    subject: String,
    client_id: String,
    scopes: BTreeSet<String>,
    credentials: Arc<C>,
    access_digest: String,
    refresh_digest: String,
    access_expires: Instant,
    access_exp_unix: u64,
    expires: Instant,
}

struct State<C> {
    pending: HashMap<String, Pending>,
    codes: HashMap<String, Code<C>>,
    grants: HashMap<String, Grant<C>>,
}
impl<C> Default for State<C> {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
            codes: HashMap::new(),
            grants: HashMap::new(),
        }
    }
}

/// Process-local authorization state. Capacity is fail-closed; live grants
/// are never evicted to admit a new login. Restart invalidates every local
/// code and token. Distributed deployments need a separate atomic, encrypted
/// state backend or explicit affinity and revocation semantics.
pub struct NativeOAuthStore<C> {
    config: NativeOAuthConfig,
    state: Mutex<State<C>>,
}

impl<C> fmt::Debug for NativeOAuthStore<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeOAuthStore(<redacted>)")
    }
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

fn valid_url(value: &str, allow_loopback: bool) -> bool {
    if !valid_text(value, 2048) {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    if url.scheme() == "https" {
        return true;
    }
    allow_loopback
        && url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
}

fn valid_redirect(value: &str) -> bool {
    valid_url(value, true)
        && Url::parse(value).is_ok_and(|url| {
            !url.query_pairs().any(|(key, _)| {
                matches!(
                    key.as_ref(),
                    "code" | "state" | "error" | "error_description"
                )
            })
        })
}

fn digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

fn fresh_secret() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

fn valid_secret(token: &str) -> bool {
    token.len() == 43
        && URL_SAFE_NO_PAD
            .decode(token)
            .is_ok_and(|value| value.len() == 32)
}

fn valid_pkce(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn unix_seconds() -> Result<u64, NativeOAuthError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| NativeOAuthError::Unavailable)
}

impl<C> State<C> {
    fn prune(&mut self, now: Instant) {
        self.pending.retain(|_, item| now < item.expires);
        self.codes.retain(|_, item| now < item.expires);
        self.grants.retain(|_, item| now < item.expires);
    }
}

impl<C> NativeOAuthStore<C> {
    /// Validate immutable public-client registrations and bounded custody limits.
    ///
    /// # Errors
    /// Rejects unsafe URLs, duplicate clients, invalid scopes or limits.
    pub fn new(config: NativeOAuthConfig) -> Result<Self, NativeOAuthError> {
        let limits = config.limits;
        let now = Instant::now();
        let ttl_valid = [
            limits.pending_ttl,
            limits.code_ttl,
            limits.access_ttl,
            limits.grant_ttl,
        ]
        .iter()
        .all(|ttl| !ttl.is_zero() && now.checked_add(*ttl).is_some());
        if !valid_url(&config.issuer, false)
            || !valid_url(&config.resource, false)
            || limits.max_pending == 0
            || limits.max_pending > 4096
            || limits.max_grants == 0
            || limits.max_grants > 4096
            || !ttl_valid
            || limits.access_ttl > limits.grant_ttl
            || config.clients.is_empty()
            || config.clients.len() > 256
        {
            return Err(NativeOAuthError::InvalidConfiguration);
        }
        let mut clients = BTreeSet::new();
        for client in &config.clients {
            if !valid_text(&client.client_id, 256)
                || !clients.insert(&client.client_id)
                || client.redirect_uris.is_empty()
                || client.redirect_uris.len() > 16
                || client.redirect_uris.iter().any(|uri| !valid_redirect(uri))
                || client.scopes.is_empty()
                || client.scopes.len() > 32
                || client.scopes.iter().any(|scope| !valid_scope(scope))
            {
                return Err(NativeOAuthError::InvalidConfiguration);
            }
        }
        Ok(Self {
            config,
            state: Mutex::new(State::default()),
        })
    }

    /// Begin a bounded, exact-client S256 authorization transaction.
    ///
    /// # Errors
    /// Rejects invalid resource, registration, redirect, state or scope.
    /// # Security
    /// Return the opaque transaction ID only to trusted upstream login wiring.
    /// It is not an authenticated identity or an OAuth access token.
    pub fn begin(
        &self,
        request: NativeAuthorizationRequest,
    ) -> Result<SecretString, NativeOAuthError> {
        let client = self
            .config
            .clients
            .iter()
            .find(|client| client.client_id == request.client_id)
            .ok_or(NativeOAuthError::InvalidRequest)?;
        if request.resource != self.config.resource
            || !client.redirect_uris.contains(&request.redirect_uri)
            || !valid_text(&request.state, 2048)
            || !valid_secret(&request.s256_challenge)
            || request.scopes.is_empty()
            || !request.scopes.is_subset(&client.scopes)
        {
            return Err(NativeOAuthError::InvalidRequest);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeOAuthError::Unavailable)?;
        let now = Instant::now();
        state.prune(now);
        if state.pending.len() + state.codes.len() >= self.config.limits.max_pending {
            return Err(NativeOAuthError::Capacity);
        }
        let id = fresh_secret();
        let key = digest(&id);
        if state.pending.contains_key(&key) {
            return Err(NativeOAuthError::Capacity);
        }
        state.pending.insert(
            key,
            Pending {
                request,
                expires: now + self.config.limits.pending_ttl,
            },
        );
        Ok(SecretString::new(id))
    }

    /// Complete a pending transaction after upstream identity and user consent
    /// were independently verified. Returns an exact registered client redirect
    /// with the single-use local authorization code and original state.
    ///
    /// # Errors
    /// Rejects expired transactions, missing consent or invalid subject.
    /// # Security
    /// Invoke only from trusted provider callback wiring; never accept the
    /// subject, scopes or credentials from untrusted authorization parameters.
    pub fn complete(
        &self,
        transaction: &str,
        verified_subject: String,
        approved_scopes: &BTreeSet<String>,
        credentials: Arc<C>,
    ) -> Result<SecretString, NativeOAuthError> {
        if !valid_secret(transaction) || !valid_text(&verified_subject, 512) {
            return Err(NativeOAuthError::InvalidGrant);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeOAuthError::Unavailable)?;
        let now = Instant::now();
        state.prune(now);
        let pending = state
            .pending
            .remove(&digest(transaction))
            .ok_or(NativeOAuthError::InvalidGrant)?;
        if !pending.request.scopes.is_subset(approved_scopes) {
            return Err(NativeOAuthError::InvalidGrant);
        }
        let code = fresh_secret();
        let key = digest(&code);
        if state.codes.contains_key(&key) {
            return Err(NativeOAuthError::Capacity);
        }
        let mut redirect = Url::parse(&pending.request.redirect_uri)
            .map_err(|_| NativeOAuthError::InvalidGrant)?;
        redirect
            .query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", &pending.request.state);
        state.codes.insert(
            key,
            Code {
                request: pending.request,
                subject: verified_subject,
                credentials,
                expires: now + self.config.limits.code_ttl,
            },
        );
        Ok(SecretString::new(redirect.to_string()))
    }

    /// Atomically exchange a one-use local authorization code using its exact
    /// registered client, redirect, resource and S256 verifier.
    ///
    /// # Errors
    /// Rejects replay, invalid bindings, expired codes or exhausted capacity.
    pub fn exchange_code(
        &self,
        client_id: &str,
        redirect_uri: &str,
        resource: &str,
        code: &str,
        verifier: &str,
    ) -> Result<NativeTokenResponse, NativeOAuthError> {
        if !valid_secret(code) {
            return Err(NativeOAuthError::InvalidGrant);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeOAuthError::Unavailable)?;
        let now = Instant::now();
        state.prune(now);
        let key = digest(code);
        // Consume any recognized code on its first exchange attempt, including
        // malformed PKCE, wrong client or resource, and capacity failures.
        let code = state
            .codes
            .remove(&key)
            .ok_or(NativeOAuthError::InvalidGrant)?;
        if !valid_pkce(verifier)
            || resource != self.config.resource
            || code.request.client_id != client_id
            || code.request.redirect_uri != redirect_uri
            || code.request.resource != resource
            || code.request.s256_challenge != digest(verifier)
        {
            return Err(NativeOAuthError::InvalidGrant);
        }
        if state.grants.len() >= self.config.limits.max_grants {
            return Err(NativeOAuthError::Capacity);
        }
        let access = fresh_secret();
        let refresh = fresh_secret();
        let id = fresh_secret();
        if state.grants.contains_key(&id) {
            return Err(NativeOAuthError::Capacity);
        }
        let expires_in = self.config.limits.access_ttl.as_secs();
        let access_exp_unix = unix_seconds()?
            .checked_add(expires_in)
            .ok_or(NativeOAuthError::Unavailable)?;
        let scope = code
            .request
            .scopes
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        state.grants.insert(
            id,
            Grant {
                subject: code.subject,
                client_id: code.request.client_id,
                scopes: code.request.scopes,
                credentials: code.credentials,
                access_digest: digest(&access),
                refresh_digest: digest(&refresh),
                access_expires: now + self.config.limits.access_ttl,
                access_exp_unix,
                expires: now + self.config.limits.grant_ttl,
            },
        );
        Ok(NativeTokenResponse {
            access_token: SecretString::new(access),
            refresh_token: SecretString::new(refresh),
            expires_in,
            scope,
        })
    }

    /// Rotate the current local refresh token and its access token. A grant's
    /// absolute lifetime never extends. Requested scopes may only narrow.
    ///
    /// # Errors
    /// Rejects wrong client/resource, expired, replayed or widened grants.
    pub fn refresh(
        &self,
        client_id: &str,
        resource: &str,
        refresh_token: &str,
        scopes: Option<&BTreeSet<String>>,
    ) -> Result<NativeTokenResponse, NativeOAuthError> {
        if !valid_secret(refresh_token) || resource != self.config.resource {
            return Err(NativeOAuthError::InvalidGrant);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeOAuthError::Unavailable)?;
        let now = Instant::now();
        state.prune(now);
        let key = digest(refresh_token);
        let grant = state
            .grants
            .values_mut()
            .find(|g| g.refresh_digest == key && g.client_id == client_id)
            .ok_or(NativeOAuthError::InvalidGrant)?;
        if let Some(scopes) = scopes {
            if scopes.is_empty() || !scopes.is_subset(&grant.scopes) {
                return Err(NativeOAuthError::InvalidGrant);
            }
        }
        let remaining = grant.expires.saturating_duration_since(now);
        let access_ttl = remaining.min(self.config.limits.access_ttl);
        let expires_in = access_ttl.as_secs();
        if expires_in == 0 {
            return Err(NativeOAuthError::InvalidGrant);
        }
        let exp = unix_seconds()?
            .checked_add(expires_in)
            .ok_or(NativeOAuthError::Unavailable)?;
        if let Some(scopes) = scopes {
            grant.scopes = scopes.clone();
        }
        let access = fresh_secret();
        let refresh = fresh_secret();
        grant.access_digest = digest(&access);
        grant.refresh_digest = digest(&refresh);
        grant.access_expires = now + access_ttl;
        grant.access_exp_unix = exp;
        let scope = grant.scopes.iter().cloned().collect::<Vec<_>>().join(" ");
        Ok(NativeTokenResponse {
            access_token: SecretString::new(access),
            refresh_token: SecretString::new(refresh),
            expires_in,
            scope,
        })
    }

    /// Revoke the full local grant for an exact client and access or refresh
    /// token. The HTTP revocation endpoint should return a uniform response.
    ///
    /// # Errors
    /// Returns unavailable when state cannot be locked.
    /// # Security
    /// Local revocation is immediate but does not revoke upstream credentials.
    /// The application must implement provider revocation separately.
    pub fn revoke(&self, client_id: &str, token: &str) -> Result<(), NativeOAuthError> {
        if !valid_secret(token) {
            return Ok(());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeOAuthError::Unavailable)?;
        state.prune(Instant::now());
        let key = digest(token);
        state.grants.retain(|_, grant| {
            !(grant.client_id == client_id
                && (grant.access_digest == key || grant.refresh_digest == key))
        });
        Ok(())
    }

    /// Resolve currently authorized provider credential custody. Invoke only
    /// with a token from the current verified resource-server request.
    ///
    /// # Errors
    /// Rejects unknown, expired and revoked access tokens; refresh tokens are
    /// never accepted here.
    pub fn verified_grant(&self, token: &str) -> Result<NativeVerifiedGrant<C>, NativeOAuthError> {
        self.with_access(token, |grant| NativeVerifiedGrant {
            subject: grant.subject.clone(),
            client_id: grant.client_id.clone(),
            resource: self.config.resource.clone(),
            scopes: grant.scopes.clone(),
            credentials: grant.credentials.clone(),
        })
    }

    fn with_access<T>(
        &self,
        token: &str,
        f: impl FnOnce(&Grant<C>) -> T,
    ) -> Result<T, NativeOAuthError> {
        if !valid_secret(token) {
            return Err(NativeOAuthError::InvalidGrant);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeOAuthError::Unavailable)?;
        let now = Instant::now();
        state.prune(now);
        let key = digest(token);
        let grant = state
            .grants
            .values()
            .find(|g| g.access_digest == key && now < g.access_expires)
            .ok_or(NativeOAuthError::InvalidGrant)?;
        Ok(f(grant))
    }
}

impl<C: Send + Sync + 'static> LocalTokenVerifier for NativeOAuthStore<C> {
    fn claims_for_access_token(&self, token: &str) -> Result<Value, AuthError> {
        self.with_access(token,|grant| json!({
            "iss":self.config.issuer,"aud":self.config.resource,"sub":grant.subject,
            "client_id":grant.client_id,"scope":grant.scopes.iter().cloned().collect::<Vec<_>>().join(" "),
            "exp":grant.access_exp_unix,
        })).map_err(|_|AuthError::InvalidToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const RESOURCE: &str = "https://mcp.example/mcp";
    const ISSUER: &str = "https://mcp.example";
    const CALLBACK: &str = "http://127.0.0.1:5555/callback";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    fn scopes() -> BTreeSet<String> {
        ["ga4:read".to_string(), "ga4:report".to_string()].into()
    }
    fn fixture() -> NativeOAuthStore<String> {
        NativeOAuthStore::new(NativeOAuthConfig {
            issuer: ISSUER.into(),
            resource: RESOURCE.into(),
            clients: vec![NativePublicClient {
                client_id: "fixture".into(),
                redirect_uris: vec![CALLBACK.into()],
                scopes: scopes(),
            }],
            limits: NativeOAuthLimits {
                max_pending: 2,
                max_grants: 2,
                pending_ttl: Duration::from_secs(60),
                code_ttl: Duration::from_secs(30),
                access_ttl: Duration::from_secs(60),
                grant_ttl: Duration::from_secs(120),
            },
        })
        .unwrap()
    }
    fn request() -> NativeAuthorizationRequest {
        NativeAuthorizationRequest {
            client_id: "fixture".into(),
            redirect_uri: CALLBACK.into(),
            resource: RESOURCE.into(),
            state: "client-state".into(),
            scopes: scopes(),
            s256_challenge: digest(VERIFIER),
        }
    }
    fn code(store: &NativeOAuthStore<String>) -> String {
        let pending = store.begin(request()).unwrap();
        let redirect = store
            .complete(
                pending.expose_secret(),
                "verified-subject".into(),
                &scopes(),
                Arc::new("upstream-private".into()),
            )
            .unwrap();
        assert!(store
            .complete(
                pending.expose_secret(),
                "other".into(),
                &scopes(),
                Arc::new("other".into())
            )
            .is_err());
        let url = Url::parse(redirect.expose_secret()).unwrap();
        assert!(url
            .query_pairs()
            .any(|(k, v)| k == "state" && v == "client-state"));
        url.query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned()
    }
    #[test]
    fn exact_redirect_resource_pkce_and_single_use() {
        let store = fixture();
        let mut bad = request();
        bad.redirect_uri = "https://evil.example/callback".into();
        assert!(store.begin(bad).is_err());
        let mut bad = request();
        bad.resource = "https://other.example/mcp".into();
        assert!(store.begin(bad).is_err());
        for (client, redirect, resource, verifier) in [
            ("other", CALLBACK, RESOURCE, VERIFIER),
            (
                "fixture",
                "https://evil.example/callback",
                RESOURCE,
                VERIFIER,
            ),
            ("fixture", CALLBACK, "https://other.example/mcp", VERIFIER),
            ("fixture", CALLBACK, RESOURCE, "short"),
            ("fixture", CALLBACK, RESOURCE, &"x".repeat(43)),
        ] {
            let rejected = code(&store);
            assert!(store
                .exchange_code(client, redirect, resource, &rejected, verifier)
                .is_err());
            assert!(store
                .exchange_code("fixture", CALLBACK, RESOURCE, &rejected, VERIFIER)
                .is_err());
        }
        let code = code(&store);
        let tokens = store
            .exchange_code("fixture", CALLBACK, RESOURCE, &code, VERIFIER)
            .unwrap();
        assert!(store
            .exchange_code("fixture", CALLBACK, RESOURCE, &code, VERIFIER)
            .is_err());
        assert!(store
            .verified_grant(tokens.refresh_token.expose_secret())
            .is_err());
        assert_eq!(
            *store
                .verified_grant(tokens.access_token.expose_secret())
                .unwrap()
                .credentials,
            "upstream-private"
        );
        assert!(!format!("{tokens:?}").contains(tokens.access_token.expose_secret()));
    }
    #[test]
    fn refresh_rotation_and_revocation_are_immediate() {
        let store = fixture();
        let code = code(&store);
        let old = store
            .exchange_code("fixture", CALLBACK, RESOURCE, &code, VERIFIER)
            .unwrap();
        let narrow = BTreeSet::from(["ga4:read".to_string()]);
        let new = store
            .refresh(
                "fixture",
                RESOURCE,
                old.refresh_token.expose_secret(),
                Some(&narrow),
            )
            .unwrap();
        assert!(store
            .refresh("fixture", RESOURCE, old.refresh_token.expose_secret(), None)
            .is_err());
        assert!(store
            .verified_grant(old.access_token.expose_secret())
            .is_err());
        assert!(store
            .refresh(
                "fixture",
                RESOURCE,
                new.refresh_token.expose_secret(),
                Some(&scopes())
            )
            .is_err());
        store
            .revoke("other", new.access_token.expose_secret())
            .unwrap();
        assert!(store
            .verified_grant(new.access_token.expose_secret())
            .is_ok());
        store
            .revoke("fixture", new.refresh_token.expose_secret())
            .unwrap();
        assert!(store
            .verified_grant(new.access_token.expose_secret())
            .is_err());
        assert!(store
            .refresh("fixture", RESOURCE, new.refresh_token.expose_secret(), None)
            .is_err());
    }
    #[tokio::test]
    async fn common_authenticator_checks_local_access_claims_without_fallback() {
        let store = Arc::new(fixture());
        let code = code(&store);
        let tokens = store
            .exchange_code("fixture", CALLBACK, RESOURCE, &code, VERIFIER)
            .unwrap();
        let mut config = crate::AuthConfig::with_profile(crate::AuthSecurityProfile::L2Strong);
        config.mode = crate::AuthMode::Introspection;
        config.introspection_cache_ttl_s = 0.0;
        config.issuer = Some(ISSUER.into());
        config.audience = Some(RESOURCE.into());
        config.actor_claim = "sub".into();
        config.required_scopes = vec!["ga4:read".into()];
        let auth =
            crate::Authenticator::new_with_local_token_verifier(config, store.clone()).unwrap();
        let context = auth
            .authenticate_token(&http::HeaderMap::new(), tokens.access_token.expose_secret())
            .await
            .unwrap();
        assert_eq!(
            context.context().subject.as_deref(),
            Some("verified-subject")
        );
        store
            .revoke("fixture", tokens.access_token.expose_secret())
            .unwrap();
        assert!(auth
            .authenticate_token(&http::HeaderMap::new(), tokens.access_token.expose_secret())
            .await
            .is_err());
    }
}
