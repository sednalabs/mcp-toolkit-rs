//! # Hosted upstream OAuth transactions
//!
//! Bounded, process-local custody for prepared PKCE authorizations. The store
//! keeps initiating identity and provider-route binding alongside each single-use
//! authorization. It does not authenticate requests, issue MCP access tokens,
//! or provide a distributed credential store.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::{oauth_callback_correlation_key, PendingOAuthAuthorization, SecretString};

const MAX_SCOPE_BYTES: usize = 4096;
const MAX_STATE_BYTES: usize = 4096;

/// Exact, application-owned identity and configured provider-flow namespace.
///
/// # Security
/// Construct from verified initiating identity and trusted deployment
/// configuration, never model arguments or unverified callback parameters.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingOAuthScope {
    principal: String,
    flow: String,
}

impl PendingOAuthScope {
    /// Construct an exact scope without normalizing identity-bearing strings.
    ///
    /// # Errors
    /// Rejects blank, excessive, or control-containing components.
    /// # Security
    /// Representation validation is not identity verification.
    pub fn new(
        principal: impl Into<String>,
        flow: impl Into<String>,
    ) -> Result<Self, PendingOAuthStoreError> {
        let scope = Self {
            principal: principal.into(),
            flow: flow.into(),
        };
        if !valid_component(&scope.principal) || !valid_component(&scope.flow) {
            return Err(PendingOAuthStoreError::InvalidScope);
        }
        Ok(scope)
    }

    /// Borrow the trusted initiating principal for credential custody.
    /// # Security
    /// Do not expose this identity to a callback client or log it.
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// Borrow the configured flow identifier.
    pub fn flow(&self) -> &str {
        &self.flow
    }
}

impl fmt::Debug for PendingOAuthScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingOAuthScope(<redacted>)")
    }
}

fn valid_component(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_SCOPE_BYTES
        && !value.chars().any(char::is_control)
}

/// Operator-selected, fixed transaction-store limits.
#[derive(Clone, Copy, Debug)]
pub struct PendingOAuthLimits {
    pub max_pending: usize,
    pub max_pending_per_principal: usize,
    pub max_lifetime: Duration,
    pub max_authorization_url_bytes: usize,
}

/// Caller-safe error categories; no callback state, URL, principal or token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PendingOAuthStoreError {
    #[error("invalid pending OAuth store limits")]
    InvalidConfiguration,
    #[error("invalid pending OAuth scope")]
    InvalidScope,
    #[error("authorization is invalid or no longer available")]
    InvalidTransaction,
    #[error("authorization URL exceeds the configured size limit")]
    AuthorizationTooLarge,
    #[error("pending OAuth transaction capacity reached")]
    CapacityReached,
    #[error("pending OAuth transaction correlation collision")]
    Collision,
    #[error("pending OAuth store unavailable")]
    Unavailable,
}

/// One claimed transaction and its original initiating identity.
///
/// # Security
/// Only trusted callback handlers should receive this value. Persist exchanged
/// credentials under its original scope, not the callback's cookies, query
/// parameters or a model-supplied identity.
pub struct BoundPendingOAuthAuthorization {
    scope: PendingOAuthScope,
    authorization: PendingOAuthAuthorization,
}

impl BoundPendingOAuthAuthorization {
    /// Consume the claimed transaction and recover its exact original scope.
    pub fn into_parts(self) -> (PendingOAuthScope, PendingOAuthAuthorization) {
        (self.scope, self.authorization)
    }
}

impl fmt::Debug for BoundPendingOAuthAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoundPendingOAuthAuthorization(<redacted>)")
    }
}

struct Entry {
    bound: BoundPendingOAuthAuthorization,
    expires_at: Instant,
}

impl Entry {
    fn live_at(&self, now: Instant) -> bool {
        now < self.expires_at && !self.bound.authorization.is_expired()
    }
}

/// Store prepared provider authorizations for one service instance.
///
/// # Security
/// The store never authenticates an initiating caller. Bind insertions to
/// verified identity, and derive callback flow and URI from trusted route
/// configuration. Callback state is secret; do not log it. A callback must
/// exchange the claimed transaction only once, store tokens for the bound
/// scope, and return a generic result page. Restart invalidates all entries.
/// A multi-instance deployment requires sticky routing or a separate secure
/// distributed transaction protocol.
///
/// ```no_run
/// use std::time::Duration;
/// use mcp_toolkit_auth::upstream_oauth::{
///     prepare_authorization, OAuthAuthorizationOptions, OAuthClientConfig,
///     pending_store::{PendingOAuthLimits, PendingOAuthScope, PendingOAuthStore},
/// };
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let store = PendingOAuthStore::new(PendingOAuthLimits {
///     max_pending: 64,
///     max_pending_per_principal: 2,
///     max_lifetime: Duration::from_secs(300),
///     max_authorization_url_bytes: 16_384,
/// })?;
/// let client = OAuthClientConfig::new("client", None,
///     "https://provider.example/authorize", "https://provider.example/token")?;
/// let prepared = prepare_authorization(client, vec!["resource.read".into()],
///     OAuthAuthorizationOptions::new("https://mcp.example/oauth/callback"))?;
/// // In production these values are derived from verified identity and configuration.
/// let scope = PendingOAuthScope::new("verified-issuer/subject", "provider-flow")?;
/// let browser_url = store.insert(scope, prepared)?;
/// // Deliver browser_url.expose_secret() only to the intended user.
/// # let _ = browser_url;
/// # Ok(())
/// # }
/// ```
pub struct PendingOAuthStore {
    limits: PendingOAuthLimits,
    entries: Mutex<HashMap<String, Entry>>,
}

impl PendingOAuthStore {
    /// Create a store with positive, finite transaction limits.
    ///
    /// # Errors
    /// Rejects zero limits, per-principal capacity above global capacity, and
    /// a lifetime not representable by the monotonic clock.
    pub fn new(limits: PendingOAuthLimits) -> Result<Self, PendingOAuthStoreError> {
        if limits.max_pending == 0
            || limits.max_pending_per_principal == 0
            || limits.max_pending_per_principal > limits.max_pending
            || limits.max_authorization_url_bytes == 0
            || limits.max_lifetime.is_zero()
            || Instant::now().checked_add(limits.max_lifetime).is_none()
        {
            return Err(PendingOAuthStoreError::InvalidConfiguration);
        }
        Ok(Self {
            limits,
            entries: Mutex::new(HashMap::new()),
        })
    }

    /// Register a prepared authorization and return its secret browser URL.
    ///
    /// # Errors
    /// Rejects expired transactions, excess URL size, collisions, exhausted
    /// capacity, and unavailable state. Live transactions are never evicted.
    /// # Security
    /// The supplied scope must come from verified initiating identity.
    /// Return the URL only to that caller; never log it.
    pub fn insert(
        &self,
        scope: PendingOAuthScope,
        authorization: PendingOAuthAuthorization,
    ) -> Result<SecretString, PendingOAuthStoreError> {
        self.insert_at(scope, authorization, Instant::now())
    }

    fn insert_at(
        &self,
        scope: PendingOAuthScope,
        authorization: PendingOAuthAuthorization,
        now: Instant,
    ) -> Result<SecretString, PendingOAuthStoreError> {
        let deadline = now
            .checked_add(self.limits.max_lifetime)
            .ok_or(PendingOAuthStoreError::InvalidConfiguration)?;
        let expires_at = deadline.min(authorization.expires_at);
        if expires_at <= now || authorization.is_expired() {
            return Err(PendingOAuthStoreError::InvalidTransaction);
        }
        if authorization.authorization_url().len() > self.limits.max_authorization_url_bytes {
            return Err(PendingOAuthStoreError::AuthorizationTooLarge);
        }
        let correlation = authorization.correlation_key();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| PendingOAuthStoreError::Unavailable)?;
        let now = now.max(Instant::now());
        if expires_at <= now {
            return Err(PendingOAuthStoreError::InvalidTransaction);
        }
        entries.retain(|_, entry| entry.live_at(now));
        if entries.contains_key(&correlation) {
            return Err(PendingOAuthStoreError::Collision);
        }
        if entries.len() >= self.limits.max_pending
            || entries
                .values()
                .filter(|entry| entry.bound.scope.principal == scope.principal)
                .count()
                >= self.limits.max_pending_per_principal
        {
            return Err(PendingOAuthStoreError::CapacityReached);
        }
        let url = SecretString::new(authorization.authorization_url());
        entries.insert(
            correlation,
            Entry {
                bound: BoundPendingOAuthAuthorization {
                    scope,
                    authorization,
                },
                expires_at,
            },
        );
        Ok(url)
    }

    /// Atomically consume a transaction for a browser callback.
    ///
    /// # Errors
    /// Unknown, expired, malformed and wrong-route states produce the same
    /// invalid-transaction result. A wrong-route request does not consume a
    /// valid transaction. A poisoned store returns unavailable.
    /// # Security
    /// Derive expected flow and redirect URI from the actual server route's
    /// trusted configuration, never the callback body. The original scope
    /// remains attached to the transaction; it is not inferred from the
    /// callback. Do not return credentials from a browser callback.
    pub fn consume_callback(
        &self,
        state: &str,
        expected_flow: &str,
        expected_redirect_uri: &str,
    ) -> Result<BoundPendingOAuthAuthorization, PendingOAuthStoreError> {
        self.consume_at(state, Instant::now(), |bound| {
            bound.scope.flow == expected_flow
                && bound.authorization.redirect_uri() == expected_redirect_uri
        })
    }

    /// Atomically consume a transaction for an already-authenticated caller.
    ///
    /// # Errors
    /// Unknown, expired and wrong-scope states are indistinguishable.
    /// # Security
    /// Derive expected scope and redirect URI from verified request context
    /// and trusted configuration; never from a tool argument. The caller
    /// must still pass the original callback state to authorization finish.
    pub fn consume_for_scope(
        &self,
        state: &str,
        expected_scope: &PendingOAuthScope,
        expected_redirect_uri: &str,
    ) -> Result<BoundPendingOAuthAuthorization, PendingOAuthStoreError> {
        self.consume_at(state, Instant::now(), |bound| {
            &bound.scope == expected_scope
                && bound.authorization.redirect_uri() == expected_redirect_uri
        })
    }

    fn consume_at(
        &self,
        state: &str,
        now: Instant,
        matches: impl FnOnce(&BoundPendingOAuthAuthorization) -> bool,
    ) -> Result<BoundPendingOAuthAuthorization, PendingOAuthStoreError> {
        if state.is_empty() || state.len() > MAX_STATE_BYTES || state.chars().any(char::is_control)
        {
            return Err(PendingOAuthStoreError::InvalidTransaction);
        }
        let correlation = oauth_callback_correlation_key(state);
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| PendingOAuthStoreError::Unavailable)?;
        let now = now.max(Instant::now());
        entries.retain(|_, entry| entry.live_at(now));
        if !entries
            .get(&correlation)
            .is_some_and(|entry| matches(&entry.bound))
        {
            return Err(PendingOAuthStoreError::InvalidTransaction);
        }
        entries
            .remove(&correlation)
            .map(|entry| entry.bound)
            .ok_or(PendingOAuthStoreError::InvalidTransaction)
    }

    /// Remove pending transactions for one exact verified scope.
    ///
    /// # Errors
    /// Returns unavailable if the store lock is poisoned.
    /// # Security
    /// Derive the scope from verified state. This cancels only pending local
    /// transactions; it does not revoke already-exchanged upstream credentials.
    pub fn cancel_scope(&self, scope: &PendingOAuthScope) -> Result<usize, PendingOAuthStoreError> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| PendingOAuthStoreError::Unavailable)?;
        entries.retain(|_, entry| entry.live_at(now));
        let before = entries.len();
        entries.retain(|_, entry| &entry.bound.scope != scope);
        Ok(before - entries.len())
    }

    /// Remove expired transactions and reclaim their capacity.
    ///
    /// # Errors
    /// Returns unavailable if the store lock is poisoned.
    pub fn prune_expired(&self) -> Result<usize, PendingOAuthStoreError> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| PendingOAuthStoreError::Unavailable)?;
        let before = entries.len();
        entries.retain(|_, entry| entry.live_at(now));
        Ok(before - entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream_oauth::{
        prepare_authorization, OAuthAuthorizationOptions, OAuthClientConfig,
    };

    const CALLBACK: &str = "https://mcp.example/oauth/callback";

    fn store() -> PendingOAuthStore {
        PendingOAuthStore::new(PendingOAuthLimits {
            max_pending: 3,
            max_pending_per_principal: 1,
            max_lifetime: Duration::from_secs(60),
            max_authorization_url_bytes: 8192,
        })
        .expect("store")
    }

    fn scope(principal: &str, flow: &str) -> PendingOAuthScope {
        PendingOAuthScope::new(principal, flow).expect("scope")
    }

    fn prepare() -> PendingOAuthAuthorization {
        let client = OAuthClientConfig::new(
            "fixture-client",
            None,
            "https://provider.example/authorize",
            "https://provider.example/token",
        )
        .expect("client");
        prepare_authorization(
            client,
            vec!["resource.read".to_string()],
            OAuthAuthorizationOptions::new(CALLBACK).with_timeout(Duration::from_secs(120)),
        )
        .expect("prepare")
    }

    fn state(url: &SecretString) -> String {
        reqwest::Url::parse(url.expose_secret())
            .expect("authorization URL")
            .query_pairs()
            .find(|(key, _)| key == "state")
            .expect("state")
            .1
            .into_owned()
    }

    #[test]
    fn consumes_once_and_preserves_original_identity() {
        let store = store();
        let a = scope("issuer/a", "flow-a");
        let url = store.insert(a.clone(), prepare()).expect("insert");
        let state = state(&url);
        assert!(store.consume_callback(&state, "flow-b", CALLBACK).is_err());
        assert!(store
            .consume_callback(&state, "flow-a", "https://mcp.example/other")
            .is_err());
        assert!(store
            .consume_for_scope(&state, &scope("issuer/b", "flow-a"), CALLBACK)
            .is_err());
        let bound = store
            .consume_callback(&state, "flow-a", CALLBACK)
            .expect("valid callback");
        let (original, prepared) = bound.into_parts();
        assert_eq!(original, a);
        assert_eq!(original.principal(), "issuer/a");
        assert_eq!(
            prepared.correlation_key(),
            oauth_callback_correlation_key(&state)
        );
        assert!(store.consume_callback(&state, "flow-a", CALLBACK).is_err());
        assert!(!format!("{url:?}").contains(&state));
        assert!(!format!("{original:?}").contains("issuer/a"));
    }

    #[test]
    fn enforces_capacity_across_flows_without_evicting_live_entries() {
        let store = store();
        let a = scope("a", "one");
        let a_url = store.insert(a.clone(), prepare()).expect("first");
        assert!(matches!(
            store.insert(scope("a", "two"), prepare()),
            Err(PendingOAuthStoreError::CapacityReached)
        ));
        store.insert(scope("b", "one"), prepare()).expect("second");
        store.insert(scope("c", "one"), prepare()).expect("third");
        assert!(matches!(
            store.insert(scope("d", "one"), prepare()),
            Err(PendingOAuthStoreError::CapacityReached)
        ));
        assert!(store
            .consume_for_scope(&state(&a_url), &a, CALLBACK)
            .is_ok());
        assert!(store.insert(scope("a", "two"), prepare()).is_ok());
    }

    #[test]
    fn expiry_is_bounded_by_store_and_cancel_is_exact() {
        let store = store();
        let a = scope("a", "one");
        let now = Instant::now();
        let url = store.insert_at(a.clone(), prepare(), now).expect("insert");
        assert!(store
            .consume_at(&state(&url), now + Duration::from_secs(60), |_| true)
            .is_err());
        let url = store.insert(a.clone(), prepare()).expect("reinsert");
        assert_eq!(store.cancel_scope(&scope("a", "two")).expect("cancel"), 0);
        assert_eq!(store.cancel_scope(&a).expect("cancel"), 1);
        assert!(store.consume_for_scope(&state(&url), &a, CALLBACK).is_err());
        assert!(store
            .consume_callback(&"x".repeat(4097), "one", CALLBACK)
            .is_err());
        assert!(PendingOAuthScope::new(" ", "flow").is_err());
    }

    #[test]
    fn concurrent_callbacks_have_exactly_one_winner() {
        let store = std::sync::Arc::new(store());
        let url = store.insert(scope("a", "one"), prepare()).expect("insert");
        let state = state(&url);
        let workers = (0..8)
            .map(|_| {
                let store = store.clone();
                let state = state.clone();
                std::thread::spawn(move || store.consume_callback(&state, "one", CALLBACK).is_ok())
            })
            .collect::<Vec<_>>();
        let count = workers
            .into_iter()
            .map(|worker| usize::from(worker.join().expect("worker")))
            .sum::<usize>();
        assert_eq!(count, 1);
    }
}
