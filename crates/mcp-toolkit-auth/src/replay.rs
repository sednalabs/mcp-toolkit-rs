//! # Replay Protection
//!
//! Replay storage for detecting JWT/OIDC replay attacks via JTI (JWT ID) claims.
//!
//! ## Ownership
//! This module owns the JTI replay-store trait, the default in-memory storage,
//! cache eviction, and duplicate-check logic.
//!
//! ## Non-ownership
//! This module does not manage persistence or distributed cache synchronization.
//! Services that need multi-process replay protection should implement
//! [`JtiReplayStore`] with their own shared backend.
//!
//! ## Policy & Guarantees
//! * **Replay Mitigation**: Detects duplicate JTI claims within the configured TTL,
//!   aiding in mitigating token replay attempts.
//! * **Capacity Bounding**: Enforces a maximum cache size to prevent memory-exhaustion risks.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Configuring TTL and capacity limits that match their threat model.
//! * Ensuring that tokens submitted for validation actually include unique `jti` claims.
//!
//! ## References
//! * [RFC 7519] JSON Web Token (JWT) Claim definitions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use thiserror::Error;

/// Shared JTI replay store used by authenticators that need a common backend.
pub type SharedJtiReplayStore = Arc<dyn JtiReplayStore>;

/// Stores seen bearer JTIs and reports duplicates as replay attempts.
pub trait JtiReplayStore: std::fmt::Debug + Send + Sync {
    /// Records a JTI if it has not been seen.
    ///
    /// Returns `true` when the JTI was already present and unexpired.
    ///
    /// # Errors
    /// Returns an error when the underlying replay backend cannot complete the
    /// check-and-record operation.
    ///
    /// # Security
    /// Implementations must make the check-and-record operation atomic for the
    /// backend they protect. Split check-then-insert behavior can admit replay
    /// races under concurrency.
    fn seen(&self, jti: &str) -> Result<bool, JtiReplayStoreError>;
}

/// Error returned by a JTI replay store backend.
#[derive(Debug, Error)]
pub enum JtiReplayStoreError {
    #[error("{0}")]
    Backend(String),
}

impl JtiReplayStoreError {
    /// Builds a backend error without exposing sensitive token material.
    pub fn backend(message: impl Into<String>) -> Self {
        Self::Backend(message.into())
    }
}

/// In-memory cache for tracking JTIs (JWT IDs) to mitigate token replay.
#[derive(Debug)]
pub struct JtiCache {
    ttl: Duration,
    capacity: usize,
    entries: HashMap<String, Instant>,
    calls_since_prune: u32,
}

impl JtiCache {
    /// Creates a new cache with the specified TTL and maximum entry capacity.
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            entries: HashMap::new(),
            calls_since_prune: 0,
        }
    }

    /// Checks if a JTI has already been processed. Records it if unseen.
    ///
    /// # Security
    /// * Returns `true` if a replay is detected (JTI seen and not yet expired).
    pub fn seen(&mut self, jti: &str) -> bool {
        let now = Instant::now();

        self.calls_since_prune += 1;
        if self.calls_since_prune >= 100 {
            self.entries.retain(|_, expiry| *expiry > now);
            self.calls_since_prune = 0;
        }

        if let Some(expiry) = self.entries.get(jti).copied() {
            if expiry > now {
                return true;
            }
            self.entries.remove(jti);
        }

        if self.entries.len() >= self.capacity {
            if let Some(key) = self.entries.keys().next().cloned() {
                self.entries.remove(&key);
            }
        }

        self.entries.insert(jti.to_string(), now + self.ttl);
        false
    }
}

/// Thread-safe in-memory replay store for single-process deployments.
#[derive(Debug)]
pub struct InMemoryJtiReplayStore {
    inner: Mutex<JtiCache>,
}

impl InMemoryJtiReplayStore {
    /// Creates a thread-safe in-memory replay store.
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(JtiCache::new(ttl, capacity)),
        }
    }

    /// Creates a shared in-memory replay store suitable for multiple
    /// authenticators in one process.
    pub fn shared(ttl: Duration, capacity: usize) -> SharedJtiReplayStore {
        Arc::new(Self::new(ttl, capacity))
    }
}

impl JtiReplayStore for InMemoryJtiReplayStore {
    fn seen(&self, jti: &str) -> Result<bool, JtiReplayStoreError> {
        let mut cache = self.inner.lock().map_err(|_| {
            JtiReplayStoreError::backend("in-memory JTI replay store lock poisoned")
        })?;
        Ok(cache.seen(jti))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_entries_do_not_report_replay_before_prune_cycle() {
        let mut cache = JtiCache::new(Duration::from_secs(60), 8);
        cache.entries.insert(
            "expired".to_string(),
            Instant::now() - Duration::from_secs(1),
        );
        cache.calls_since_prune = 1;

        assert!(!cache.seen("expired"));
        assert!(cache.entries["expired"] > Instant::now());
        assert_eq!(cache.calls_since_prune, 2);
    }

    #[test]
    fn unexpired_entries_still_report_replay() {
        let mut cache = JtiCache::new(Duration::from_secs(60), 8);
        cache.entries.insert(
            "active".to_string(),
            Instant::now() + Duration::from_secs(60),
        );

        assert!(cache.seen("active"));
    }

    #[test]
    fn shared_store_reports_replay_across_handles() {
        let store = InMemoryJtiReplayStore::shared(Duration::from_secs(60), 8);
        let second_handle = store.clone();

        assert!(!store.seen("shared").expect("first insert"));
        assert!(second_handle.seen("shared").expect("replay"));
    }
}
