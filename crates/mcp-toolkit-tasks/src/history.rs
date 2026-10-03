//! Bounded, principal-partitioned operation summaries.
//!
//! This module stores typed task summaries only. It does not retain task
//! payloads, logs, commands, environments, results, or errors.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::{TaskAuthority, TaskAuthorityError, TaskPrincipal};

/// Closed operation state suitable for bounded history and telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationState {
    Working,
    InputRequired,
    Completed,
    Failed,
    Cancelled,
}

impl OperationState {
    fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Bounded operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    /// An RMCP task managed by `TaskAuthority`.
    Task,
}

/// A summary of one authorized task. Fields contain no free-form task data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationSummary {
    /// Opaque RMCP task identifier.
    pub operation_id: String,
    /// Closed operation kind.
    pub kind: OperationKind,
    /// Closed operation state.
    pub state: OperationState,
    /// RMCP creation timestamp.
    pub created_at: String,
    /// Timestamp of the last authoritative update.
    pub last_updated_at: String,
    /// Authority observation revision.
    pub revision: u64,
}

/// Count and terminal-age limits for retained summaries.
#[derive(Debug, Clone, Copy)]
pub struct HistoryLimits {
    /// Maximum number of retained entries across all principals.
    pub max_entries: usize,
    /// Maximum age of a retained terminal entry.
    pub max_terminal_age: Duration,
}

/// History errors are deliberately low detail to avoid exposing identifiers.
#[derive(Debug)]
pub enum HistoryError {
    Authority(TaskAuthorityError),
    CapacityFull,
    StateUnavailable,
    InvalidSummary,
}

impl From<TaskAuthorityError> for HistoryError {
    fn from(value: TaskAuthorityError) -> Self {
        Self::Authority(value)
    }
}

#[derive(Debug, Clone)]
struct Stored {
    summary: OperationSummary,
    terminal_at: Option<SystemTime>,
}

/// In-memory bounded history. This is not restart persistence. Build Helper's
/// provider-owned SQLite adapter is a separate consumer integration outcome.
pub struct OperationHistory {
    limits: HistoryLimits,
    partitions: Mutex<HashMap<String, Vec<Stored>>>,
}

impl OperationHistory {
    /// Creates an empty history with explicit global count and terminal-age limits.
    pub fn new(limits: HistoryLimits) -> Self {
        Self {
            limits,
            partitions: Mutex::new(HashMap::new()),
        }
    }

    /// Authorizes, summarizes, and stores the current task in one operation.
    /// The principal partition is derived only after TaskAuthority succeeds.
    pub fn record(
        &self,
        authority: &TaskAuthority,
        principal: &TaskPrincipal,
        task_id: &str,
    ) -> Result<OperationSummary, HistoryError> {
        let snapshot = authority.get_task_for_principal(principal, task_id)?;
        let task = snapshot.task;
        let state = match task.status() {
            rmcp::model::TaskStatus::Working => OperationState::Working,
            rmcp::model::TaskStatus::InputRequired => OperationState::InputRequired,
            rmcp::model::TaskStatus::Completed => OperationState::Completed,
            rmcp::model::TaskStatus::Failed => OperationState::Failed,
            rmcp::model::TaskStatus::Cancelled => OperationState::Cancelled,
            _ => return Err(HistoryError::StateUnavailable),
        };
        let summary = OperationSummary {
            operation_id: task.task.task_id,
            kind: OperationKind::Task,
            state,
            created_at: task.task.created_at,
            last_updated_at: task.task.last_updated_at,
            revision: snapshot.revision,
        };
        if summary.operation_id.is_empty()
            || summary.operation_id.chars().count() > 256
            || summary.created_at.is_empty()
            || summary.created_at.len() > 64
            || summary.last_updated_at.is_empty()
            || summary.last_updated_at.len() > 64
        {
            return Err(HistoryError::InvalidSummary);
        }
        let proof = PrincipalBoundWrite {
            partition: principal.as_str().to_owned(),
            summary: summary.clone(),
        };
        self.insert(proof)?;
        Ok(summary)
    }

    /// Returns one summary only from the authenticated principal's partition.
    pub fn get(
        &self,
        principal: &TaskPrincipal,
        operation_id: &str,
    ) -> Result<Option<OperationSummary>, HistoryError> {
        let mut partitions = self
            .partitions
            .lock()
            .map_err(|_| HistoryError::StateUnavailable)?;
        prune_expired(
            &mut partitions,
            SystemTime::now(),
            self.limits.max_terminal_age,
        );
        Ok(partitions
            .get(principal.as_str())
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| item.summary.operation_id == operation_id)
            })
            .map(|item| item.summary.clone()))
    }

    /// Lists summaries from only the authenticated principal's partition.
    pub fn list(
        &self,
        principal: &TaskPrincipal,
        limit: usize,
    ) -> Result<Vec<OperationSummary>, HistoryError> {
        let mut partitions = self
            .partitions
            .lock()
            .map_err(|_| HistoryError::StateUnavailable)?;
        prune_expired(
            &mut partitions,
            SystemTime::now(),
            self.limits.max_terminal_age,
        );
        Ok(partitions
            .get(principal.as_str())
            .map(|items| {
                items
                    .iter()
                    .rev()
                    .take(limit)
                    .map(|item| item.summary.clone())
                    .collect()
            })
            .unwrap_or_default())
    }

    fn insert(&self, proof: PrincipalBoundWrite) -> Result<(), HistoryError> {
        let mut partitions = self
            .partitions
            .lock()
            .map_err(|_| HistoryError::StateUnavailable)?;
        let now = SystemTime::now();
        prune_expired(&mut partitions, now, self.limits.max_terminal_age);

        let existing = partitions.get(&proof.partition).and_then(|items| {
            items
                .iter()
                .position(|item| item.summary.operation_id == proof.summary.operation_id)
        });
        if let Some(index) = existing {
            let Some(items) = partitions.get_mut(&proof.partition) else {
                return Err(HistoryError::StateUnavailable);
            };
            let mut item = items.remove(index);
            item.terminal_at = proof.summary.state.terminal().then_some(now);
            item.summary = proof.summary;
            items.push(item);
            return Ok(());
        }

        let total = partitions.values().map(Vec::len).sum::<usize>();
        if total >= self.limits.max_entries {
            let oldest = partitions
                .iter()
                .flat_map(|(partition, items)| {
                    items.iter().enumerate().filter_map(move |(index, item)| {
                        item.terminal_at.map(|at| (at, partition.clone(), index))
                    })
                })
                .min_by_key(|(at, _, _)| *at);
            if let Some((_, partition, index)) = oldest {
                let Some(items) = partitions.get_mut(&partition) else {
                    return Err(HistoryError::StateUnavailable);
                };
                items.remove(index);
                if partitions.get(&partition).is_some_and(Vec::is_empty) {
                    partitions.remove(&partition);
                }
            } else {
                return Err(HistoryError::CapacityFull);
            }
        }
        partitions.entry(proof.partition).or_default().push(Stored {
            terminal_at: proof.summary.state.terminal().then_some(now),
            summary: proof.summary,
        });
        Ok(())
    }
}

fn prune_expired(
    partitions: &mut HashMap<String, Vec<Stored>>,
    now: SystemTime,
    max_terminal_age: Duration,
) {
    for items in partitions.values_mut() {
        items.retain(|item| {
            item.terminal_at
                .is_none_or(|at| now.duration_since(at).unwrap_or_default() < max_terminal_age)
        });
    }
    partitions.retain(|_, items| !items.is_empty());
}

// Constructed only after the authority read in `record`; neither public API
// accepts a snapshot plus an independently supplied partition.
struct PrincipalBoundWrite {
    partition: String,
    summary: OperationSummary,
}

#[cfg(test)]
mod tests;
