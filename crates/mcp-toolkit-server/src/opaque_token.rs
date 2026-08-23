//! # Bound opaque token storage
//!
//! In-memory, process-local state for bounded continuation and reservation
//! tokens used by MCP servers.
//!
//! ## Security Boundaries
//! * Tokens are unguessable UUIDv4 values and reveal no stored state.
//! * Exact optional session and principal bindings prevent cross-context use.
//! * TTL and capacity limits bound retention and memory growth.
//! * Consumption is one-shot; restoration preserves the original expiry.
//!
//! ```
//! use std::time::Duration;
//! use mcp_toolkit_server::opaque_token::{OpaqueTokenStore, TokenBinding};
//!
//! let store = OpaqueTokenStore::new(Duration::from_secs(60), 32)?;
//! let binding = TokenBinding::new(Some("session-1"), Some("principal-1"));
//! let token = store.create("continuation", binding.clone())?;
//! let consumed = store.consume(&token, &binding)?;
//! assert_eq!(consumed.payload(), &"continuation");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

/// Identifies the request context allowed to use an opaque token.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TokenBinding {
    session_id: Option<String>,
    principal: Option<String>,
}

impl TokenBinding {
    /// Creates a binding from optional session and principal identifiers.
    ///
    /// Blank identifiers are normalized to absent bindings.
    #[must_use]
    pub fn new(session_id: Option<&str>, principal: Option<&str>) -> Self {
        Self {
            session_id: normalize_binding(session_id),
            principal: normalize_binding(principal),
        }
    }

    /// Returns the normalized session identifier.
    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Returns the normalized principal identifier.
    #[must_use]
    pub fn principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }
}

/// Describes an opaque-token store failure without disclosing stored state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpaqueTokenError {
    InvalidConfiguration,
    InvalidOrExpired,
    BindingMismatch,
    Unavailable,
}

impl fmt::Display for OpaqueTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidConfiguration => "token store limits must be positive",
            Self::InvalidOrExpired => "opaque token is invalid or expired",
            Self::BindingMismatch => "opaque token does not match the active context",
            Self::Unavailable => "opaque token store is unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OpaqueTokenError {}

/// Reports bounded store occupancy without exposing tokens or payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpaqueTokenStats {
    pub entries: usize,
    pub max_entries: usize,
    pub ttl: Duration,
}

/// Holds a consumed token reservation that can be restored after a safe retry.
///
/// Keeping the fields private prevents callers from changing bindings, token
/// identity, or expiry between consumption and restoration.
pub struct ConsumedOpaqueToken<T> {
    token: String,
    record: TokenRecord<T>,
}

impl<T> ConsumedOpaqueToken<T> {
    /// Returns the reserved payload.
    #[must_use]
    pub fn payload(&self) -> &T {
        &self.record.payload
    }

    /// Consumes the reservation and returns its payload without restoring it.
    #[must_use]
    pub fn into_payload(self) -> T {
        self.record.payload
    }
}

/// Stores bounded, opaque, context-bound tokens in process memory.
pub struct OpaqueTokenStore<T> {
    ttl: Duration,
    max_entries: usize,
    inner: Mutex<StoreState<T>>,
}

struct TokenRecord<T> {
    payload: T,
    binding: TokenBinding,
    expires_at: Instant,
}

struct StoreState<T> {
    entries: HashMap<String, TokenRecord<T>>,
    order: VecDeque<String>,
}

impl<T> Default for StoreState<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl<T> OpaqueTokenStore<T> {
    /// Creates a store with fixed retention and capacity bounds.
    ///
    /// # Errors
    /// Returns [`OpaqueTokenError::InvalidConfiguration`] when either bound is
    /// zero.
    pub fn new(ttl: Duration, max_entries: usize) -> Result<Self, OpaqueTokenError> {
        if ttl.is_zero() || max_entries == 0 {
            return Err(OpaqueTokenError::InvalidConfiguration);
        }
        Ok(Self {
            ttl,
            max_entries,
            inner: Mutex::new(StoreState::default()),
        })
    }

    /// Stores a payload and returns a new opaque token.
    ///
    /// # Errors
    /// Returns [`OpaqueTokenError::Unavailable`] if synchronized state is
    /// poisoned.
    ///
    /// # Security
    /// The returned token carries no payload or binding data. Callers must avoid
    /// logging it because possession still grants use within the bound context.
    pub fn create(&self, payload: T, binding: TokenBinding) -> Result<String, OpaqueTokenError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| OpaqueTokenError::Unavailable)?;
        sweep_expired(&mut state);
        let token = next_token(&state);
        state.entries.insert(
            token.clone(),
            TokenRecord {
                payload,
                binding,
                expires_at: Instant::now() + self.ttl,
            },
        );
        state.order.push_back(token.clone());
        trim_to_capacity(&mut state, self.max_entries);
        Ok(token)
    }

    /// Returns bounded store occupancy.
    ///
    /// # Errors
    /// Returns [`OpaqueTokenError::Unavailable`] if synchronized state is
    /// poisoned.
    pub fn stats(&self) -> Result<OpaqueTokenStats, OpaqueTokenError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| OpaqueTokenError::Unavailable)?;
        sweep_expired(&mut state);
        Ok(OpaqueTokenStats {
            entries: state.entries.len(),
            max_entries: self.max_entries,
            ttl: self.ttl,
        })
    }

    /// Removes and reserves a token for one-shot use.
    ///
    /// # Errors
    /// Returns a closed error for missing, expired, mismatched, or unavailable
    /// state. A binding mismatch does not consume the token.
    ///
    /// # Security
    /// Exact binding equality is checked before the record is removed.
    pub fn consume(
        &self,
        token: &str,
        binding: &TokenBinding,
    ) -> Result<ConsumedOpaqueToken<T>, OpaqueTokenError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| OpaqueTokenError::Unavailable)?;
        sweep_expired(&mut state);
        let record = state
            .entries
            .get(token)
            .ok_or(OpaqueTokenError::InvalidOrExpired)?;
        if record.binding != *binding {
            return Err(OpaqueTokenError::BindingMismatch);
        }
        let record = state
            .entries
            .remove(token)
            .ok_or(OpaqueTokenError::Unavailable)?;
        remove_from_order(&mut state.order, token);
        Ok(ConsumedOpaqueToken {
            token: token.to_owned(),
            record,
        })
    }

    /// Restores a consumed reservation if its original lifetime remains valid.
    ///
    /// Returns `false` if the token expired or another record already occupies
    /// the same token identity.
    ///
    /// # Errors
    /// Returns [`OpaqueTokenError::Unavailable`] if synchronized state is
    /// poisoned.
    ///
    /// # Security
    /// Restoration preserves the original token, binding, and expiry; retries
    /// cannot extend token lifetime or change authority.
    pub fn restore(&self, consumed: ConsumedOpaqueToken<T>) -> Result<bool, OpaqueTokenError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| OpaqueTokenError::Unavailable)?;
        sweep_expired(&mut state);
        if consumed.record.expires_at <= Instant::now()
            || state.entries.contains_key(&consumed.token)
        {
            return Ok(false);
        }
        let token = consumed.token;
        state.entries.insert(token.clone(), consumed.record);
        state.order.push_back(token);
        trim_to_capacity(&mut state, self.max_entries);
        Ok(true)
    }
}

impl<T: Clone> OpaqueTokenStore<T> {
    /// Resolves a token without consuming it.
    ///
    /// # Errors
    /// Returns a closed error for missing, expired, mismatched, or unavailable
    /// state. Successful resolution refreshes only eviction order, not expiry.
    ///
    /// # Security
    /// Exact binding equality is checked before the payload is cloned.
    pub fn resolve(&self, token: &str, binding: &TokenBinding) -> Result<T, OpaqueTokenError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| OpaqueTokenError::Unavailable)?;
        sweep_expired(&mut state);
        let payload = {
            let record = state
                .entries
                .get(token)
                .ok_or(OpaqueTokenError::InvalidOrExpired)?;
            if record.binding != *binding {
                return Err(OpaqueTokenError::BindingMismatch);
            }
            record.payload.clone()
        };
        touch_order(&mut state.order, token);
        Ok(payload)
    }
}

fn normalize_binding(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn next_token<T>(state: &StoreState<T>) -> String {
    loop {
        let token = Uuid::new_v4().to_string();
        if !state.entries.contains_key(&token) {
            return token;
        }
    }
}

fn sweep_expired<T>(state: &mut StoreState<T>) {
    let now = Instant::now();
    state.entries.retain(|_, record| record.expires_at > now);
    state
        .order
        .retain(|token| state.entries.contains_key(token));
}

fn trim_to_capacity<T>(state: &mut StoreState<T>, max_entries: usize) {
    while state.entries.len() > max_entries {
        let Some(oldest) = state.order.pop_front() else {
            break;
        };
        state.entries.remove(&oldest);
    }
}

fn touch_order(order: &mut VecDeque<String>, token: &str) {
    remove_from_order(order, token);
    order.push_back(token.to_owned());
}

fn remove_from_order(order: &mut VecDeque<String>, token: &str) {
    if let Some(position) = order.iter().position(|item| item == token) {
        order.remove(position);
    }
}

#[cfg(test)]
mod tests {
    use super::{OpaqueTokenError, OpaqueTokenStore, TokenBinding};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn token_is_bound_and_consumed_once() {
        let store = OpaqueTokenStore::new(Duration::from_secs(60), 8)
            .unwrap_or_else(|error| panic!("store should be valid: {error}"));
        let owner = TokenBinding::new(Some("session-a"), Some("principal-a"));
        let token = store
            .create("payload", owner.clone())
            .unwrap_or_else(|error| panic!("create should succeed: {error}"));

        assert!(matches!(
            store.consume(
                &token,
                &TokenBinding::new(Some("session-b"), Some("principal-a"))
            ),
            Err(OpaqueTokenError::BindingMismatch)
        ));
        let consumed = store
            .consume(&token, &owner)
            .unwrap_or_else(|error| panic!("owner should consume: {error}"));
        assert_eq!(consumed.payload(), &"payload");
        assert!(matches!(
            store.consume(&token, &owner),
            Err(OpaqueTokenError::InvalidOrExpired)
        ));
    }

    #[test]
    fn restoration_preserves_binding_and_original_expiry() {
        let store = OpaqueTokenStore::new(Duration::from_millis(25), 8)
            .unwrap_or_else(|error| panic!("store should be valid: {error}"));
        let owner = TokenBinding::new(Some("session-a"), Some("principal-a"));
        let token = store
            .create(7, owner.clone())
            .unwrap_or_else(|error| panic!("create should succeed: {error}"));
        let consumed = store
            .consume(&token, &owner)
            .unwrap_or_else(|error| panic!("consume should succeed: {error}"));

        assert!(store.restore(consumed).unwrap_or(false));
        assert_eq!(
            store.resolve(
                &token,
                &TokenBinding::new(Some("session-a"), Some("principal-b"))
            ),
            Err(OpaqueTokenError::BindingMismatch)
        );
        thread::sleep(Duration::from_millis(35));
        assert_eq!(
            store.resolve(&token, &owner),
            Err(OpaqueTokenError::InvalidOrExpired)
        );
    }

    #[test]
    fn capacity_evicts_least_recently_used_token() {
        let store = OpaqueTokenStore::new(Duration::from_secs(60), 2)
            .unwrap_or_else(|error| panic!("store should be valid: {error}"));
        let binding = TokenBinding::default();
        let first = store
            .create(1, binding.clone())
            .unwrap_or_else(|error| panic!("first create should succeed: {error}"));
        let second = store
            .create(2, binding.clone())
            .unwrap_or_else(|error| panic!("second create should succeed: {error}"));
        assert_eq!(store.resolve(&first, &binding), Ok(1));
        let third = store
            .create(3, binding.clone())
            .unwrap_or_else(|error| panic!("third create should succeed: {error}"));

        assert_eq!(
            store.resolve(&second, &binding),
            Err(OpaqueTokenError::InvalidOrExpired)
        );
        assert_eq!(store.resolve(&first, &binding), Ok(1));
        assert_eq!(store.resolve(&third, &binding), Ok(3));
    }

    #[test]
    fn rejects_zero_limits() {
        assert_eq!(
            OpaqueTokenStore::<()>::new(Duration::ZERO, 1).err(),
            Some(OpaqueTokenError::InvalidConfiguration)
        );
        assert_eq!(
            OpaqueTokenStore::<()>::new(Duration::from_secs(1), 0).err(),
            Some(OpaqueTokenError::InvalidConfiguration)
        );
    }
}
