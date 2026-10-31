//! # Scoped, bounded continuation state
//!
//! Stores short-lived continuation payloads without coupling them to a transport
//! session. A cursor is bound to an authenticated principal, a resource/purpose,
//! and an application generation. It is not an authorisation credential.
//!
//! ## Security boundaries
//! The application generates unpredictable tokens, constructs scopes from trusted
//! request state, and rechecks current access on every use. This module enforces
//! exact scope equality, finite lifetime, entry and serialized-payload bounds.
//! It performs no network I/O, token authentication, or durable storage. Restart
//! invalidates all cursors. Expiry does not slide when a cursor is read.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

/// Exact application-owned continuation scope. No field is optional.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CursorScope {
    principal: String,
    resource: String,
    generation: String,
}

impl CursorScope {
    /// Construct a scope without normalising identity-bearing strings.
    ///
    /// # Errors
    /// Rejects blank fields and fields exceeding 1,024 UTF-8 bytes.
    ///
    /// # Security
    /// Derive the principal from authenticated state, never model arguments.
    pub fn new(
        principal: impl Into<String>,
        resource: impl Into<String>,
        generation: impl Into<String>,
    ) -> Result<Self, CursorError> {
        let scope = Self {
            principal: principal.into(),
            resource: resource.into(),
            generation: generation.into(),
        };
        for field in [&scope.principal, &scope.resource, &scope.generation] {
            if field.trim().is_empty() || field.len() > 1024 {
                return Err(CursorError::InvalidScope);
            }
        }
        Ok(scope)
    }
}

/// Fixed resource limits for an in-memory cursor store.
#[derive(Clone, Copy, Debug)]
pub struct CursorLimits {
    pub ttl: Duration,
    pub max_entries: usize,
    pub max_payload_bytes: usize,
}

/// Caller-safe failure categories. Unknown, expired and foreign cursors are indistinguishable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CursorError {
    InvalidConfiguration,
    InvalidScope,
    InvalidToken,
    InvalidCursor,
    TokenCollision,
    CapacityReached,
    PayloadTooLarge,
    Unavailable,
}

impl fmt::Display for CursorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid cursor-store limits",
            Self::InvalidScope => "invalid cursor scope",
            Self::InvalidToken => "invalid cursor token",
            Self::InvalidCursor => "cursor is invalid or no longer available",
            Self::TokenCollision => "cursor token already exists",
            Self::CapacityReached => "cursor capacity reached",
            Self::PayloadTooLarge => "cursor payload exceeds configured limit",
            Self::Unavailable => "cursor store unavailable",
        })
    }
}

impl std::error::Error for CursorError {}

#[derive(Clone)]
struct Entry {
    scope: CursorScope,
    payload: Value,
    expires_at: Instant,
}

/// A process-local store for small continuation payloads.
///
/// ```
/// use std::time::Duration;
/// use mcp_toolkit_core::scoped_cursor::{CursorLimits, CursorScope, ScopedCursorStore};
/// let store = ScopedCursorStore::new(CursorLimits {
///     ttl: Duration::from_secs(60), max_entries: 100, max_payload_bytes: 1024,
/// })?;
/// let scope = CursorScope::new("verified-user", "messages:channel-a", "backend-epoch-1")?;
/// // In production, generate a fresh cryptographically unpredictable token.
/// let token = "example-token-not-for-production-0001";
/// store.insert(token, scope.clone(), serde_json::json!({"after": 42}))?;
/// assert_eq!(store.resolve(token, &scope)?, serde_json::json!({"after": 42}));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct ScopedCursorStore {
    limits: CursorLimits,
    entries: Mutex<HashMap<String, Entry>>,
}

impl ScopedCursorStore {
    /// Create a store with explicit positive limits.
    ///
    /// # Errors
    /// Rejects zero limits or a lifetime not representable by the monotonic clock.
    pub fn new(limits: CursorLimits) -> Result<Self, CursorError> {
        if limits.ttl.is_zero()
            || limits.max_entries == 0
            || limits.max_payload_bytes == 0
            || Instant::now().checked_add(limits.ttl).is_none()
        {
            return Err(CursorError::InvalidConfiguration);
        }
        Ok(Self {
            limits,
            entries: Mutex::new(HashMap::new()),
        })
    }

    /// Insert a payload under an application-generated opaque token.
    ///
    /// # Errors
    /// Rejects invalid or duplicate tokens, oversize payloads, capacity exhaustion,
    /// an unrepresentable expiry, or a poisoned store. Existing live entries are
    /// never silently evicted to make space.
    ///
    /// # Security
    /// Generate at least 128 unpredictable bits; the syntax check does not prove
    /// entropy. Tokens must not be supplied by a model. No authentication is
    /// performed here, and a token alone never bypasses the scope check.
    pub fn insert(&self, token: &str, scope: CursorScope, payload: Value) -> Result<(), CursorError> {
        self.insert_at(token, scope, payload, Instant::now())
    }

    fn insert_at(
        &self,
        token: &str,
        scope: CursorScope,
        payload: Value,
        now: Instant,
    ) -> Result<(), CursorError> {
        if !(32..=256).contains(&token.len())
            || !token.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(CursorError::InvalidToken);
        }
        let mut counter = LimitedCounter {
            used: 0,
            limit: self.limits.max_payload_bytes,
        };
        serde_json::to_writer(&mut counter, &payload).map_err(|_| CursorError::PayloadTooLarge)?;
        let expires_at = now.checked_add(self.limits.ttl).ok_or(CursorError::InvalidConfiguration)?;
        let mut entries = self.entries.lock().map_err(|_| CursorError::Unavailable)?;
        entries.retain(|_, entry| entry.expires_at > now);
        if entries.contains_key(token) {
            return Err(CursorError::TokenCollision);
        }
        if entries.len() >= self.limits.max_entries {
            return Err(CursorError::CapacityReached);
        }
        entries.insert(token.to_owned(), Entry { scope, payload, expires_at });
        Ok(())
    }

    /// Read a payload after an exact scope check, without advancing consumer state.
    ///
    /// # Errors
    /// Returns `InvalidCursor` for unknown, expired or foreign cursors, and
    /// `Unavailable` if the store's lock is poisoned.
    ///
    /// # Security
    /// The caller must still authorise access to the resource at time of use.
    pub fn resolve(&self, token: &str, scope: &CursorScope) -> Result<Value, CursorError> {
        self.lookup_at(token, scope, false, Instant::now())
    }

    /// Atomically read and remove a payload after an exact scope check.
    ///
    /// # Errors
    /// Returns the same errors as `resolve`.
    ///
    /// # Security
    /// A foreign caller cannot consume a valid caller's cursor. Consumption is
    /// not proof that any downstream side effect happened.
    pub fn consume(&self, token: &str, scope: &CursorScope) -> Result<Value, CursorError> {
        self.lookup_at(token, scope, true, Instant::now())
    }

    fn lookup_at(
        &self,
        token: &str,
        scope: &CursorScope,
        consume: bool,
        now: Instant,
    ) -> Result<Value, CursorError> {
        if token.len() > 256 {
            return Err(CursorError::InvalidCursor);
        }
        let mut entries = self.entries.lock().map_err(|_| CursorError::Unavailable)?;
        entries.retain(|_, entry| entry.expires_at > now);
        let entry = entries.get(token)
            .filter(|entry| entry.scope == *scope)
            .ok_or(CursorError::InvalidCursor)?;
        let payload = entry.payload.clone();
        if consume {
            entries.remove(token);
        }
        Ok(payload)
    }
}

struct LimitedCounter {
    used: usize,
    limit: usize,
}

impl Write for LimitedCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.used = self.used.checked_add(bytes.len())
            .filter(|used| *used <= self.limit)
            .ok_or_else(|| io::Error::other("serialized payload limit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const A: &str = "00000000-0000-4000-8000-000000000001";
    const B: &str = "00000000-0000-4000-8000-000000000002";

    fn scope() -> CursorScope {
        CursorScope::new("actor", "resource", "epoch").unwrap()
    }

    fn store(n: usize, bytes: usize) -> ScopedCursorStore {
        ScopedCursorStore::new(CursorLimits {
            ttl: Duration::from_secs(60),
            max_entries: n,
            max_payload_bytes: bytes,
        }).unwrap()
    }

    #[test]
    fn read_does_not_consume_and_consume_is_one_shot() {
        let s = store(2, 100);
        s.insert(A, scope(), json!({"x": 1})).unwrap();
        assert_eq!(s.resolve(A, &scope()).unwrap(), json!({"x": 1}));
        assert_eq!(s.consume(A, &scope()).unwrap(), json!({"x": 1}));
        assert_eq!(s.resolve(A, &scope()), Err(CursorError::InvalidCursor));
    }

    #[test]
    fn each_scope_dimension_is_enforced_without_consuming() {
        let s = store(2, 100);
        s.insert(A, scope(), json!(1)).unwrap();
        for foreign in [
            CursorScope::new("other", "resource", "epoch"),
            CursorScope::new("actor", "other", "epoch"),
            CursorScope::new("actor", "resource", "other"),
        ] {
            assert_eq!(s.consume(A, &foreign.unwrap()), Err(CursorError::InvalidCursor));
        }
        assert_eq!(s.resolve(A, &scope()).unwrap(), json!(1));
    }

    #[test]
    fn expires_at_boundary_and_reads_do_not_extend_lifetime() {
        let s = store(2, 100);
        let now = Instant::now();
        s.insert_at(A, scope(), json!(1), now).unwrap();
        assert_eq!(s.lookup_at(A, &scope(), false, now + Duration::from_secs(59)).unwrap(), json!(1));
        assert_eq!(s.lookup_at(A, &scope(), false, now + Duration::from_secs(60)), Err(CursorError::InvalidCursor));
    }

    #[test]
    fn capacity_never_evicts_live_cursors() {
        let s = store(1, 100);
        s.insert(A, scope(), json!(1)).unwrap();
        assert_eq!(s.insert(B, scope(), json!(2)), Err(CursorError::CapacityReached));
        assert_eq!(s.resolve(A, &scope()).unwrap(), json!(1));
    }

    #[test]
    fn expired_capacity_is_reclaimed() {
        let s = store(1, 100);
        let now = Instant::now();
        s.insert_at(A, scope(), json!(1), now).unwrap();
        s.insert_at(B, scope(), json!(2), now + Duration::from_secs(61)).unwrap();
        assert_eq!(s.lookup_at(A, &scope(), false, now + Duration::from_secs(61)), Err(CursorError::InvalidCursor));
    }

    #[test]
    fn collision_preserves_original_payload() {
        let s = store(2, 100);
        s.insert(A, scope(), json!(1)).unwrap();
        assert_eq!(s.insert(A, scope(), json!(2)), Err(CursorError::TokenCollision));
        assert_eq!(s.resolve(A, &scope()).unwrap(), json!(1));
    }

    #[test]
    fn payload_bound_counts_utf8_serialization_bytes() {
        let s = store(2, 5);
        s.insert(A, scope(), json!("a")).unwrap();
        assert_eq!(s.insert(B, scope(), json!("éé")), Err(CursorError::PayloadTooLarge));
    }

    #[test]
    fn tokens_and_scopes_are_bounded() {
        let s = store(2, 100);
        assert_eq!(s.insert("short", scope(), json!(1)), Err(CursorError::InvalidToken));
        assert_eq!(CursorScope::new("", "a", "b"), Err(CursorError::InvalidScope));
        assert_eq!(CursorScope::new("a".repeat(1025), "a", "b"), Err(CursorError::InvalidScope));
    }

    #[test]
    fn zero_limits_are_rejected() {
        for limits in [
            CursorLimits { ttl: Duration::ZERO, max_entries: 1, max_payload_bytes: 1 },
            CursorLimits { ttl: Duration::from_secs(1), max_entries: 0, max_payload_bytes: 1 },
            CursorLimits { ttl: Duration::from_secs(1), max_entries: 1, max_payload_bytes: 0 },
        ] {
            assert!(matches!(ScopedCursorStore::new(limits), Err(CursorError::InvalidConfiguration)));
        }
    }

    #[test]
    fn concurrent_consumption_succeeds_once() {
        let s = std::sync::Arc::new(store(2, 100));
        s.insert(A, scope(), json!(1)).unwrap();
        let joins: Vec<_> = (0..8).map(|_| {
            let s = s.clone();
            std::thread::spawn(move || s.consume(A, &scope()).is_ok())
        }).collect();
        assert_eq!(joins.into_iter().map(|j| usize::from(j.join().unwrap())).sum::<usize>(), 1);
    }

    #[test]
    fn restart_does_not_revalidate_old_token() {
        let s = store(2, 100);
        s.insert(A, scope(), json!(1)).unwrap();
        assert_eq!(store(2, 100).resolve(A, &scope()), Err(CursorError::InvalidCursor));
    }
}
