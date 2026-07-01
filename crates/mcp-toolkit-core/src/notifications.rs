//! # Tool List Change Helpers
//!
//! Tracks tool list fingerprints to detect controlled tool-list changes so
//! server code can decide when to emit `notifications/tools/list_changed`.
//!
//! ## Ownership
//! This module owns the fingerprinting logic and the in-memory state tracker for
//! identifying when an MCP server's tool registry has changed for a given session.
//!
//! ## Non-ownership
//! This module does not perform I/O or transport operations. It purely provides
//! memory-based state tracking for notification triggers.
//!
//! ## When to use
//! Use this when your `tools/list` surface is stable for a negotiated session
//! but may change after an explicit capability refresh, profile switch, or
//! deferred-loading phase. It is a fit for session-aware MCP servers that need
//! to detect "same tools" versus "tool list changed" without storing a full
//! copy of the registry.
//!
//! ## Policy & Guarantees
//! * **Change Detection**: Generates stable fingerprints based on tool set, allowing
//!   detection of tool list modifications.
//! * **Fingerprint Consistency**: Fingerprint calculation is order-insensitive and
//!   handles duplicate/empty inputs consistently.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Invoking the observer periodically to check for state transitions.
//! * Translating `ToolListUpdate` states into actual transport-level notifications.
//!
//! ## References
//! * [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)

use std::collections::HashMap;
use std::sync::Mutex;

/// MCP method name for tool list change notifications.
pub const TOOLS_LIST_CHANGED_METHOD: &str = "notifications/tools/list_changed";

/// Classification of tool list state changes between observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolListUpdate {
    /// First observation for the session.
    NewSession { fingerprint: u64 },
    /// No change detected since the last observation.
    Unchanged { fingerprint: u64 },
    /// Tool list changed since the last observation.
    Changed { previous: u64, current: u64 },
}

impl ToolListUpdate {
    /// Returns true if the tool list changed compared to the previous observation.
    pub fn changed(self) -> bool {
        matches!(self, ToolListUpdate::Changed { .. })
    }

    /// Returns the current fingerprint for this observation.
    pub fn fingerprint(self) -> u64 {
        match self {
            ToolListUpdate::NewSession { fingerprint } => fingerprint,
            ToolListUpdate::Unchanged { fingerprint } => fingerprint,
            ToolListUpdate::Changed { current, .. } => current,
        }
    }
}

/// Tracks per-session tool list fingerprints.
#[derive(Debug, Default)]
pub struct ToolListTracker {
    fingerprints: Mutex<HashMap<String, u64>>,
}

impl ToolListTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe a session's current tool names and classify the change.
    ///
    /// Returns `NewSession` the first time a session is seen, `Unchanged` when
    /// the fingerprint matches the previous observation, and `Changed` when the
    /// exported tool list differs.
    pub fn observe<I, S>(&self, session_id: &str, tools: I) -> ToolListUpdate
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let fingerprint = fingerprint_tools(tools);
        let mut guard = match self.fingerprints.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match guard.insert(session_id.to_string(), fingerprint) {
            None => ToolListUpdate::NewSession { fingerprint },
            Some(previous) if previous == fingerprint => ToolListUpdate::Unchanged { fingerprint },
            Some(previous) => ToolListUpdate::Changed {
                previous,
                current: fingerprint,
            },
        }
    }

    /// Forget a session's stored fingerprint when the session ends or resets.
    pub fn forget(&self, session_id: &str) -> bool {
        let mut guard = match self.fingerprints.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.remove(session_id).is_some()
    }
}

/// Computes a stable, order-insensitive fingerprint for a tool list.
pub fn fingerprint_tools<I, S>(tools: I) -> u64
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut names: Vec<String> = tools
        .into_iter()
        .filter_map(|name| {
            let trimmed = name.as_ref().trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect();
    names.sort();
    names.dedup();

    let mut hash = FNV_OFFSET_BASIS;
    for name in names {
        for byte in name.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

#[cfg(test)]
mod tests {
    use super::{fingerprint_tools, ToolListTracker, ToolListUpdate};

    #[test]
    fn fingerprint_is_order_insensitive() {
        let a = fingerprint_tools(["users.list", "clients.list"]);
        let b = fingerprint_tools(["clients.list", "users.list"]);
        assert_eq!(a, b);
    }

    #[test]
    fn observe_tracks_changes() {
        let tracker = ToolListTracker::new();
        let update = tracker.observe("sess-1", ["alpha", "beta"]);
        assert!(matches!(update, ToolListUpdate::NewSession { .. }));

        let update = tracker.observe("sess-1", ["alpha", "beta"]);
        assert!(matches!(update, ToolListUpdate::Unchanged { .. }));

        let update = tracker.observe("sess-1", ["alpha", "gamma"]);
        assert!(matches!(update, ToolListUpdate::Changed { .. }));
        assert!(update.changed());
    }
}
