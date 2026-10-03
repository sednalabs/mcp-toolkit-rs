//! Opt-in low-cardinality observation of authorized task snapshots.
//!
//! Only states submitted by the caller are recorded. Intermediate transitions
//! between observations can be skipped; this adapter is not a durable audit.
//! Each newer authority observation revision emits one state sample, even when
//! its closed state is unchanged. This counts observed revisions, not changes.

use crate::{TaskAuthority, TaskAuthorityError, TaskPrincipal};
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

    /// Fetches and records the current principal-authorized task state.
    /// A different task is rejected without emitting a metric.
    pub fn observe(
        &mut self,
        authority: &TaskAuthority,
        principal: &TaskPrincipal,
        task_id: &str,
    ) -> Result<ObserveResult, TaskAuthorityError> {
        let snapshot = authority.get_task_for_principal(principal, task_id)?;
        let id = &snapshot.task.task.task_id;
        if self.task_id.as_deref().is_some_and(|current| current != id) {
            return Ok(ObserveResult::DifferentTask);
        }
        let state = match snapshot.task.status() {
            rmcp::model::TaskStatus::Working => TaskState::Working,
            rmcp::model::TaskStatus::InputRequired => TaskState::InputRequired,
            rmcp::model::TaskStatus::Completed => TaskState::Completed,
            rmcp::model::TaskStatus::Failed => TaskState::Failed,
            rmcp::model::TaskStatus::Cancelled => TaskState::Cancelled,
            _ => return Ok(ObserveResult::Duplicate),
        };
        if self
            .revision
            .is_some_and(|revision| snapshot.revision <= revision)
        {
            return Ok(ObserveResult::Duplicate);
        }
        record_task_state(state);
        self.task_id = Some(id.clone());
        self.revision = Some(snapshot.revision);
        Ok(ObserveResult::Recorded)
    }
}

#[cfg(test)]
mod tests;
