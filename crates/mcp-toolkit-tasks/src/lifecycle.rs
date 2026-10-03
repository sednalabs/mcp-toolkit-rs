//! Opt-in low-cardinality observation of authorized task snapshots.
//!
//! Only states submitted by the caller are recorded. Intermediate transitions
//! between observations can be skipped; this adapter is not a durable audit.

use crate::AuthorizedTaskSnapshot;
use mcp_toolkit_observability::{record_task_state, TaskState};

/// Result of submitting an authorized snapshot to an observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveResult {
    Recorded,
    Duplicate,
    DifferentTask,
}

/// Tracks one caller-selected task's last observed revision.
#[derive(Default)]
pub struct LifecycleObserver {
    task_id: Option<String>,
    revision: Option<u64>,
}

impl LifecycleObserver {
    /// Creates an observer with no task selected.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the state in an authority-returned snapshot when it is new.
    /// A different task is rejected and emits no metric.
    pub fn observe(&mut self, snapshot: &AuthorizedTaskSnapshot) -> ObserveResult {
        let id = &snapshot.task.task.task_id;
        if self.task_id.as_deref().is_some_and(|current| current != id) {
            return ObserveResult::DifferentTask;
        }
        let state = match snapshot.task.status() {
            rmcp::model::TaskStatus::Working => TaskState::Working,
            rmcp::model::TaskStatus::InputRequired => TaskState::InputRequired,
            rmcp::model::TaskStatus::Completed => TaskState::Completed,
            rmcp::model::TaskStatus::Failed => TaskState::Failed,
            rmcp::model::TaskStatus::Cancelled => TaskState::Cancelled,
            _ => return ObserveResult::Duplicate,
        };
        if self
            .revision
            .is_some_and(|revision| snapshot.revision <= revision)
        {
            return ObserveResult::Duplicate;
        }
        record_task_state(state);
        self.task_id = Some(id.clone());
        self.revision = Some(snapshot.revision);
        ObserveResult::Recorded
    }
}

#[cfg(test)]
mod tests;
