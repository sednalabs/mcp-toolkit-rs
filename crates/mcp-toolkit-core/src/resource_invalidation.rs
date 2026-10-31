//! # Bounded resource invalidations
//!
//! A finite, insertion-ordered set of dirty resource keys for MCP notification
//! producers. Repeated updates to an unread resource coalesce, but an update
//! after that marker is taken becomes a new notification.
//!
//! ## Boundaries
//!
//! This is not a transcript, message queue, delivery receipt or subscription
//! manager. Callers must derive the accepted inventory from current access
//! policy, check permission again when delivering or reading the resource, and
//! handle transport disconnects and consumer cancellations themselves. An
//! invalidation never establishes message delivery or wakes a model.

use std::collections::{BTreeSet, VecDeque};

/// Errors constructing a bounded resource inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationError {
    /// Inventory is empty, duplicated, too large, or contains an invalid key.
    InvalidInventory,
}

/// FIFO set of dirty resources over a fixed, pre-authorised inventory.
///
/// The queue holds at most one marker for each accepted resource. A noisy
/// resource cannot indefinitely starve a second resource that is already dirty.
///
/// ```
/// use mcp_toolkit_core::resource_invalidation::InvalidationSet;
/// let mut dirty = InvalidationSet::new(
///     vec!["resource://a".into(), "resource://b".into()], 2, 128
/// )?;
/// assert!(dirty.mark("resource://a"));
/// assert!(!dirty.mark("resource://a"));
/// assert!(!dirty.mark("resource://foreign"));
/// assert_eq!(dirty.pop().as_deref(), Some("resource://a"));
/// assert!(dirty.mark("resource://a"));
/// # Ok::<(), mcp_toolkit_core::resource_invalidation::InvalidationError>(())
/// ```
#[derive(Debug)]
pub struct InvalidationSet {
    accepted: BTreeSet<String>,
    pending: BTreeSet<String>,
    queue: VecDeque<String>,
}

impl InvalidationSet {
    /// Construct a finite accepted key inventory.
    ///
    /// # Errors
    ///
    /// Rejects zero limits, blank or whitespace-padded keys, duplicate keys,
    /// oversize UTF-8 keys, empty inventories and inventories over `max_keys`.
    ///
    /// # Security
    ///
    /// The caller must authorise keys before construction; this object checks
    /// only exact membership in that supplied inventory.
    pub fn new(
        keys: Vec<String>,
        max_keys: usize,
        max_key_bytes: usize,
    ) -> Result<Self, InvalidationError> {
        if keys.is_empty()
            || max_keys == 0
            || max_key_bytes == 0
            || keys.len() > max_keys
            || keys
                .iter()
                .any(|key| key.is_empty() || key.trim() != key || key.len() > max_key_bytes)
        {
            return Err(InvalidationError::InvalidInventory);
        }
        let accepted: BTreeSet<_> = keys.iter().cloned().collect();
        if accepted.len() != keys.len() {
            return Err(InvalidationError::InvalidInventory);
        }
        Ok(Self {
            accepted,
            pending: BTreeSet::new(),
            queue: VecDeque::new(),
        })
    }

    /// Mark one authorised resource dirty. Returns true only for a new marker.
    ///
    /// Foreign keys and already-pending keys are ignored. This is not an
    /// authorisation decision for a later delivery.
    pub fn mark(&mut self, key: &str) -> bool {
        if !self.accepted.contains(key) || !self.pending.insert(key.to_owned()) {
            return false;
        }
        self.queue.push_back(key.to_owned());
        true
    }

    /// Mark the entire authorised inventory dirty, without duplicating markers.
    ///
    /// Useful for initial reads or after a backend continuity boundary. The
    /// returned ordering is stable, and existing pending markers keep their place.
    pub fn mark_all(&mut self) {
        let keys: Vec<_> = self.accepted.iter().cloned().collect();
        for key in keys {
            self.mark(&key);
        }
    }

    /// Take the oldest dirty marker, leaving that key available to mark again.
    ///
    /// Removing a marker is *not* an acknowledgement of message delivery.
    pub fn pop(&mut self) -> Option<String> {
        let key = self.queue.pop_front()?;
        self.pending.remove(&key);
        Some(key)
    }

    /// Number of pending markers; never exceeds the accepted inventory size.
    pub fn pending_len(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{InvalidationError, InvalidationSet};

    fn queue() -> InvalidationSet {
        InvalidationSet::new(vec!["a".into(), "b".into()], 2, 64).unwrap()
    }

    #[test]
    fn coalesces_duplicates_and_denies_unknown_keys() {
        let mut q = queue();
        assert!(q.mark("b"));
        assert!(!q.mark("b"));
        assert!(!q.mark("not-a-resource"));
        assert!(q.mark("a"));
        assert_eq!(q.pending_len(), 2);
        assert_eq!(q.pop().as_deref(), Some("b"));
        assert_eq!(q.pop().as_deref(), Some("a"));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn update_after_pop_is_a_new_notification() {
        let mut q = queue();
        assert!(q.mark("a"));
        assert_eq!(q.pop().as_deref(), Some("a"));
        assert!(q.mark("a"));
        assert_eq!(q.pop().as_deref(), Some("a"));
    }

    #[test]
    fn noisy_resource_does_not_starve_others() {
        let mut q = queue();
        q.mark_all();
        assert_eq!(q.pop().as_deref(), Some("a"));
        for _ in 0..100 {
            q.mark("a");
        }
        assert_eq!(q.pop().as_deref(), Some("b"));
        assert_eq!(q.pop().as_deref(), Some("a"));
    }

    #[test]
    fn mark_all_preserves_existing_order_without_growth() {
        let mut q = queue();
        assert!(q.mark("b"));
        for _ in 0..1_000 {
            q.mark_all();
        }
        assert_eq!(q.pending_len(), 2);
        assert_eq!(q.pop().as_deref(), Some("b"));
        assert_eq!(q.pop().as_deref(), Some("a"));
        assert_eq!(q.pending_len(), 0);
    }

    #[test]
    fn rejects_invalid_inventory() {
        assert_eq!(
            InvalidationSet::new(vec!["a".into(), "a".into()], 2, 10).unwrap_err(),
            InvalidationError::InvalidInventory
        );
        assert!(InvalidationSet::new(vec![], 1, 10).is_err());
        assert!(InvalidationSet::new(vec![" a".into()], 1, 10).is_err());
        assert!(InvalidationSet::new(vec!["a ".into()], 1, 10).is_err());
        assert!(InvalidationSet::new(vec!["é".into()], 1, 1).is_err());
        assert!(InvalidationSet::new(vec!["a".into(), "b".into()], 1, 10).is_err());
        assert!(InvalidationSet::new(vec!["a".into()], 0, 10).is_err());
        assert!(InvalidationSet::new(vec!["a".into()], 1, 0).is_err());
    }

    #[test]
    fn never_confuses_resource_markers_with_message_count() {
        let mut q = InvalidationSet::new(vec!["inbox".into()], 1, 10).unwrap();
        for _ in 0..10_000 {
            q.mark("inbox");
        }
        assert_eq!(q.pending_len(), 1);
        assert_eq!(q.pop().as_deref(), Some("inbox"));
        assert!(q.mark("inbox"));
    }
}
