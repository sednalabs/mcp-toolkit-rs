//! # Capability Guard
//!
//! Stateful caching for capability validation checks.
//!
//! ## Ownership
//! This module owns the in-memory cache storage, eviction logic, and refresh-flight
//! state management for capability checks.
//!
//! ## Non-ownership
//! This module does not manage the logic defining what a capability *is* or how
//! it is validated; it strictly manages the cache state for those results.
//!
//! ## Policy & Guarantees
//! * **Bounded Cache**: Limits the number of cached capability results to mitigate
//!   memory exhaustion risks.
//! * **Refresh Single-flighting**: Tracks in-flight refreshes to prevent redundant
//!   validation checks during high-concurrency periods.
//! * **Expiration**: Prunes cached entries based on TTL to ensure policy freshness.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying meaningful capability keys.
//! * Providing accurate TTL/capacity constraints.
//! * Performing the actual capability validation logic.
//!
//! ## References
//! * `mcp-toolkit-policy-core` (Logic definitions).

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

const INFLIGHT_REFRESH_TTL: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct GuardState<K> {
    verified: HashMap<K, Instant>,
    in_flight: HashMap<K, Instant>,
}

/// Thread-safe, bounded cache for capability validation results.
#[derive(Debug)]
pub struct CapabilityGuard<K> {
    ttl: Duration,
    max_entries: usize,
    state: Mutex<GuardState<K>>,
}

/// Status of a capability refresh operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityRefreshState {
    FreshSuccess,
    StartRefresh,
    RefreshInFlight,
}

impl<K> CapabilityGuard<K>
where
    K: Eq + Hash,
{
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries: max_entries.max(1),
            state: Mutex::new(GuardState {
                verified: HashMap::new(),
                in_flight: HashMap::new(),
            }),
        }
    }

    /// Checks if a capability check is currently cached and fresh.
    pub fn has_fresh_success(&self, capability: &K) -> Result<bool, CapabilityGuardError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CapabilityGuardError::unavailable())?;
        prune_expired(&mut state.verified, self.ttl);
        prune_expired(&mut state.in_flight, INFLIGHT_REFRESH_TTL);
        Ok(state.verified.contains_key(capability))
    }

    /// Transitions a capability to a "refresh in progress" state, if not already fresh.
    pub fn begin_refresh(
        &self,
        capability: K,
    ) -> Result<CapabilityRefreshState, CapabilityGuardError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CapabilityGuardError::unavailable())?;
        prune_expired(&mut state.verified, self.ttl);
        prune_expired(&mut state.in_flight, INFLIGHT_REFRESH_TTL);

        if state.verified.contains_key(&capability) {
            return Ok(CapabilityRefreshState::FreshSuccess);
        }
        if state.in_flight.contains_key(&capability) {
            return Ok(CapabilityRefreshState::RefreshInFlight);
        }

        state.in_flight.insert(capability, Instant::now());
        Ok(CapabilityRefreshState::StartRefresh)
    }

    /// Finalizes a refresh attempt, updating the cache if successful.
    pub fn complete_refresh(
        &self,
        capability: K,
        verified_success: bool,
    ) -> Result<(), CapabilityGuardError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CapabilityGuardError::unavailable())?;
        prune_expired(&mut state.verified, self.ttl);
        prune_expired(&mut state.in_flight, INFLIGHT_REFRESH_TTL);
        state.in_flight.remove(&capability);
        if verified_success {
            record_verified(&mut state.verified, capability, self.max_entries);
        }
        Ok(())
    }

    /// Removes a cached verification.
    pub fn invalidate(&self, capability: &K) -> Result<(), CapabilityGuardError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CapabilityGuardError::unavailable())?;
        state.verified.remove(capability);
        Ok(())
    }

    /// Records a successful verification.
    pub fn record_success(&self, capability: K) -> Result<(), CapabilityGuardError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CapabilityGuardError::unavailable())?;
        prune_expired(&mut state.verified, self.ttl);
        record_verified(&mut state.verified, capability, self.max_entries);
        Ok(())
    }
}
// ... internal functions retained ...

fn record_verified<K>(verified: &mut HashMap<K, Instant>, capability: K, max_entries: usize)
where
    K: Eq + Hash,
{
    if !verified.contains_key(&capability) && verified.len() >= max_entries {
        return;
    }
    verified.insert(capability, Instant::now());
}

fn prune_expired<K>(map: &mut HashMap<K, Instant>, ttl: Duration)
where
    K: Eq + Hash,
{
    if ttl.is_zero() {
        map.clear();
        return;
    }
    let now = Instant::now();
    map.retain(|_, recorded_at| now.duration_since(*recorded_at) <= ttl);
}

/// Stable failure contract for capability guard operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGuardError {
    pub code: String,
    pub reason: String,
    pub message: String,
}

impl CapabilityGuardError {
    fn unavailable() -> Self {
        Self {
            code: "CAPABILITY_GUARD_UNAVAILABLE".to_string(),
            reason: "guard_unavailable".to_string(),
            message: "capability guard is unavailable".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CapabilityGuard, CapabilityRefreshState};
    use std::thread::sleep;
    use std::time::Duration;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    enum TestCapability {
        Hypopg,
        PgStatStatements,
    }

    #[test]
    fn guard_starts_empty() {
        let guard = CapabilityGuard::new(Duration::from_secs(60), 16);
        assert_eq!(
            guard.has_fresh_success(&TestCapability::PgStatStatements),
            Ok(false)
        );
    }

    #[test]
    fn guard_records_success() {
        let guard = CapabilityGuard::new(Duration::from_secs(60), 16);
        assert!(guard.record_success(TestCapability::Hypopg).is_ok());
        assert_eq!(guard.has_fresh_success(&TestCapability::Hypopg), Ok(true));
    }

    #[test]
    fn guard_expires_entries_by_ttl() {
        let guard = CapabilityGuard::new(Duration::from_millis(1), 16);
        assert!(guard.record_success(TestCapability::Hypopg).is_ok());
        sleep(Duration::from_millis(2));
        assert_eq!(guard.has_fresh_success(&TestCapability::Hypopg), Ok(false));
    }

    #[test]
    fn guard_capacity_pressure_skips_new_entries() {
        let guard = CapabilityGuard::new(Duration::from_secs(60), 1);
        assert!(guard.record_success(TestCapability::Hypopg).is_ok());
        assert!(guard
            .record_success(TestCapability::PgStatStatements)
            .is_ok());
        assert_eq!(guard.has_fresh_success(&TestCapability::Hypopg), Ok(true));
        assert_eq!(
            guard.has_fresh_success(&TestCapability::PgStatStatements),
            Ok(false)
        );
    }

    #[test]
    fn guard_invalidation_clears_cached_success() {
        let guard = CapabilityGuard::new(Duration::from_secs(60), 16);
        assert!(guard.record_success(TestCapability::Hypopg).is_ok());
        assert_eq!(guard.has_fresh_success(&TestCapability::Hypopg), Ok(true));
        assert!(guard.invalidate(&TestCapability::Hypopg).is_ok());
        assert_eq!(guard.has_fresh_success(&TestCapability::Hypopg), Ok(false));
    }

    #[test]
    fn guard_singleflight_refresh_states() {
        let guard = CapabilityGuard::new(Duration::from_secs(60), 16);
        assert_eq!(
            guard.begin_refresh(TestCapability::Hypopg),
            Ok(CapabilityRefreshState::StartRefresh)
        );
        assert_eq!(
            guard.begin_refresh(TestCapability::Hypopg),
            Ok(CapabilityRefreshState::RefreshInFlight)
        );
        assert!(guard.complete_refresh(TestCapability::Hypopg, true).is_ok());
        assert_eq!(
            guard.begin_refresh(TestCapability::Hypopg),
            Ok(CapabilityRefreshState::FreshSuccess)
        );
    }
}
