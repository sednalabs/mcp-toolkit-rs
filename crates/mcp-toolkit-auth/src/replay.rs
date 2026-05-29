//! # Replay Protection
//!
//! In-memory cache for detecting JWT/OIDC replay attacks via JTI (JWT ID) claims.
//!
//! ## Ownership
//! This module owns the in-memory JTI storage, cache eviction, and duplicate-check logic.
//!
//! ## Non-ownership
//! This module does not manage persistence or distributed cache synchronization.
//! It is strictly in-memory and limited to the scope of a single process.
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
use std::time::{Duration, Instant};

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
}
