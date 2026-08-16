//! # MCP Toolkit Tasks
//!
//! Production-oriented task authority built around RMCP's native
//! `io.modelcontextprotocol/tasks` implementation.
//!
//! RMCP remains responsible for the MCP task state machine, TTL semantics,
//! `input_required`, terminal result/error projection, and cooperative
//! cancellation. This crate adds reusable server substrate that the protocol
//! SDK intentionally does not own:
//!
//! * task-to-principal binding;
//! * fail-closed cross-principal access;
//! * monotonic revision tracking;
//! * race-safe wait-for-change and wait-for-terminal observation;
//! * revision-aware wrappers around RMCP's task context.
//!
//! The crate deliberately does not add another MCP Tasks wire protocol and does
//! not expose `tasks/list`.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::model::{DetailedTask, InputRequest, Task};
use rmcp::task_manager::{TaskContext, TaskExit, TaskFuture, TaskManager, TaskOptions};
use tokio::sync::Notify;

/// Stable principal identifier used to bind an MCP task to its caller.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaskPrincipal(String);

impl TaskPrincipal {
    /// Creates a normalized principal identifier.
    ///
    /// # Errors
    /// Returns [`TaskAuthorityError::InvalidPrincipal`] when the identifier is
    /// empty or exceeds the bounded metadata limit.
    pub fn new(value: impl Into<String>) -> Result<Self, TaskAuthorityError> {
        let value = value.into();
        let normalized = value.trim();
        if normalized.is_empty() || normalized.chars().count() > 256 {
            return Err(TaskAuthorityError::InvalidPrincipal);
        }
        Ok(Self(normalized.to_string()))
    }

    /// Returns the normalized principal identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Errors exposed by the principal-bound task authority.
#[derive(Debug)]
pub enum TaskAuthorityError {
    /// Principal input was empty or exceeded the metadata bound.
    InvalidPrincipal,
    /// The task is absent or is not owned by the supplied principal.
    ///
    /// Ownership mismatch intentionally shares the same error as absence to
    /// avoid turning task identifiers into a cross-principal enumeration
    /// oracle.
    TaskNotFound,
    /// RMCP rejected an otherwise authorized task operation.
    Rmcp(rmcp::ErrorData),
    /// Internal task-authority state became unavailable.
    StateUnavailable,
}

impl fmt::Display for TaskAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrincipal => write!(f, "invalid task principal"),
            Self::TaskNotFound => write!(f, "task not found"),
            Self::Rmcp(error) => write!(f, "RMCP task operation failed: {error}"),
            Self::StateUnavailable => write!(f, "task authority state unavailable"),
        }
    }
}

impl std::error::Error for TaskAuthorityError {}

/// Condition used by [`TaskAuthority::wait`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskWaitCondition {
    /// Return after any revision strictly newer than `after_revision`.
    RevisionChange,
    /// Ignore intermediate revisions and return only once the task is terminal.
    Terminal,
}

/// Principal-authorized task snapshot with a monotonic local revision.
#[derive(Debug, Clone)]
pub struct AuthorizedTaskSnapshot {
    pub task: DetailedTask,
    pub revision: u64,
}

#[derive(Debug)]
struct RevisionSignal {
    revision: AtomicU64,
    notify: Notify,
}

impl RevisionSignal {
    fn new() -> Self {
        Self {
            revision: AtomicU64::new(1),
            notify: Notify::new(),
        }
    }

    fn current(&self) -> u64 {
        self.revision.load(Ordering::SeqCst)
    }

    fn bump(&self) -> u64 {
        let revision = self.revision.fetch_add(1, Ordering::SeqCst) + 1;
        self.notify.notify_waiters();
        revision
    }
}

#[derive(Debug)]
struct TaskBinding {
    principal: TaskPrincipal,
    signal: Arc<RevisionSignal>,
}

/// RMCP [`TaskContext`] wrapper that keeps the local observation revision in
/// sync with task-visible state changes.
#[derive(Clone)]
pub struct ManagedTaskContext {
    inner: TaskContext,
    signal: Arc<RevisionSignal>,
}

impl ManagedTaskContext {
    /// Returns the RMCP task id.
    pub fn task_id(&self) -> &str {
        self.inner.task_id()
    }

    /// Surface a mid-flight client input request and wait for its response.
    ///
    /// The revision is bumped when the task becomes `input_required` and again
    /// when the input wait resolves.
    pub async fn request_input(
        &self,
        key: impl Into<String>,
        request: InputRequest,
    ) -> Result<serde_json::Value, TaskExit> {
        self.signal.bump();
        let result = self.inner.request_input(key, request).await;
        self.signal.bump();
        result
    }

    /// Update the task status message and publish a new revision.
    pub fn set_status_message(&self, message: impl Into<String>) {
        self.inner.set_status_message(message);
        self.signal.bump();
    }

    /// Returns true when RMCP has received a cooperative cancellation request.
    pub fn is_cancel_requested(&self) -> bool {
        self.inner.is_cancel_requested()
    }

    /// Resolves once RMCP receives a cooperative cancellation request.
    pub async fn cancelled(&self) {
        self.inner.cancelled().await;
    }
}

/// Principal-bound authority around RMCP's native [`TaskManager`].
///
/// All task protocol semantics remain delegated to RMCP. The authority binds a
/// task id before the caller is allowed to return it to a client, and every
/// subsequent get/update/cancel/wait path verifies that binding first.
#[derive(Clone, Default)]
pub struct TaskAuthority {
    manager: TaskManager,
    bindings: Arc<Mutex<HashMap<String, Arc<TaskBinding>>>>,
}

impl TaskAuthority {
    /// Creates an empty task authority.
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawns an RMCP task bound to `principal`.
    ///
    /// The task binding and revision signal are installed before this method
    /// returns, so callers may safely return the task handle immediately.
    pub fn spawn_for_principal<F>(
        &self,
        principal: TaskPrincipal,
        options: TaskOptions,
        make_future: F,
    ) -> Result<Task, TaskAuthorityError>
    where
        F: FnOnce(ManagedTaskContext) -> TaskFuture,
    {
        let signal = Arc::new(RevisionSignal::new());
        let operation_signal = signal.clone();
        let task = self.manager.spawn(options, move |context| {
            let managed = ManagedTaskContext {
                inner: context,
                signal: operation_signal.clone(),
            };
            let future = make_future(managed);
            Box::pin(async move {
                let result = future.await;
                operation_signal.bump();
                result
            })
        });

        let binding = Arc::new(TaskBinding { principal, signal });
        self.bindings
            .lock()
            .map_err(|_| TaskAuthorityError::StateUnavailable)?
            .insert(task.task_id.clone(), binding);
        Ok(task)
    }

    /// Returns the current authorized task snapshot.
    pub fn get_task_for_principal(
        &self,
        principal: &TaskPrincipal,
        task_id: &str,
    ) -> Result<AuthorizedTaskSnapshot, TaskAuthorityError> {
        let binding = self.binding_for(principal, task_id)?;
        match self.manager.get_task(task_id) {
            Ok(task) => Ok(AuthorizedTaskSnapshot {
                task,
                revision: binding.signal.current(),
            }),
            Err(_) => {
                self.remove_binding(task_id);
                Err(TaskAuthorityError::TaskNotFound)
            }
        }
    }

    /// Delivers RMCP `tasks/update` input responses after principal validation.
    pub fn update_task_for_principal(
        &self,
        principal: &TaskPrincipal,
        task_id: &str,
        input_responses: impl IntoIterator<Item = (String, serde_json::Value)>,
    ) -> Result<(), TaskAuthorityError> {
        let binding = self.binding_for(principal, task_id)?;
        self.manager
            .update_task(task_id, input_responses)
            .map_err(TaskAuthorityError::Rmcp)?;
        binding.signal.bump();
        Ok(())
    }

    /// Records cooperative RMCP `tasks/cancel` intent after principal validation.
    pub fn cancel_task_for_principal(
        &self,
        principal: &TaskPrincipal,
        task_id: &str,
    ) -> Result<(), TaskAuthorityError> {
        let binding = self.binding_for(principal, task_id)?;
        self.manager
            .cancel_task(task_id)
            .map_err(TaskAuthorityError::Rmcp)?;
        binding.signal.bump();
        Ok(())
    }

    /// Waits for a newer revision or a terminal task state without polling the
    /// RMCP manager in a tight loop.
    ///
    /// Returns `Ok(None)` when the timeout expires.
    pub async fn wait(
        &self,
        principal: &TaskPrincipal,
        task_id: &str,
        after_revision: Option<u64>,
        timeout: Duration,
        condition: TaskWaitCondition,
    ) -> Result<Option<AuthorizedTaskSnapshot>, TaskAuthorityError> {
        let binding = self.binding_for(principal, task_id)?;
        let baseline = after_revision.unwrap_or_else(|| binding.signal.current());

        let wait = async {
            loop {
                let notified = binding.signal.notify.notified();
                let snapshot = self.get_task_for_principal(principal, task_id)?;
                let ready = match condition {
                    TaskWaitCondition::RevisionChange => snapshot.revision > baseline,
                    TaskWaitCondition::Terminal => snapshot.task.status().is_terminal(),
                };
                if ready {
                    return Ok(snapshot);
                }

                // Double-check after creating the waiter so an update cannot
                // land between the state check and the await.
                let revision_after_check = binding.signal.current();
                if revision_after_check > snapshot.revision {
                    continue;
                }
                notified.await;
            }
        };

        match tokio::time::timeout(timeout, wait).await {
            Ok(result) => result.map(Some),
            Err(_) => Ok(None),
        }
    }

    /// Returns the number of currently non-terminal RMCP tasks.
    pub fn running_task_count(&self) -> usize {
        self.manager.running_task_count()
    }

    /// Aborts all running RMCP tasks and clears principal bindings.
    pub fn shutdown(&self) {
        self.manager.shutdown();
        if let Ok(mut bindings) = self.bindings.lock() {
            bindings.clear();
        }
    }

    fn binding_for(
        &self,
        principal: &TaskPrincipal,
        task_id: &str,
    ) -> Result<Arc<TaskBinding>, TaskAuthorityError> {
        let bindings = self
            .bindings
            .lock()
            .map_err(|_| TaskAuthorityError::StateUnavailable)?;
        let binding = bindings
            .get(task_id)
            .cloned()
            .ok_or(TaskAuthorityError::TaskNotFound)?;
        if &binding.principal != principal {
            return Err(TaskAuthorityError::TaskNotFound);
        }
        Ok(binding)
    }

    fn remove_binding(&self, task_id: &str) {
        if let Ok(mut bindings) = self.bindings.lock() {
            bindings.remove(task_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{CallToolResult, ContentBlock, TaskStatus};
    use tokio::sync::oneshot;

    fn principal(value: &str) -> TaskPrincipal {
        TaskPrincipal::new(value).expect("valid principal")
    }

    fn ok_result(text: &str) -> CallToolResult {
        CallToolResult::success(vec![ContentBlock::text(text.to_string())])
    }

    #[tokio::test]
    async fn cross_principal_task_access_is_concealed() {
        let authority = TaskAuthority::new();
        let owner = principal("owner-a");
        let other = principal("owner-b");
        let task = authority
            .spawn_for_principal(owner.clone(), TaskOptions::default(), |_ctx| {
                Box::pin(async { Ok(ok_result("done")) })
            })
            .expect("spawn task");

        assert!(matches!(
            authority.get_task_for_principal(&other, &task.task_id),
            Err(TaskAuthorityError::TaskNotFound)
        ));
        assert!(matches!(
            authority.cancel_task_for_principal(&other, &task.task_id),
            Err(TaskAuthorityError::TaskNotFound)
        ));
        assert!(authority
            .get_task_for_principal(&owner, &task.task_id)
            .is_ok());
    }

    #[tokio::test]
    async fn status_message_change_wakes_revision_waiter() {
        let authority = Arc::new(TaskAuthority::new());
        let owner = principal("owner-a");
        let (context_tx, context_rx) = oneshot::channel::<ManagedTaskContext>();
        let task = authority
            .spawn_for_principal(owner.clone(), TaskOptions::default(), move |ctx| {
                Box::pin(async move {
                    let _ = context_tx.send(ctx.clone());
                    ctx.cancelled().await;
                    Err(TaskExit::Cancelled)
                })
            })
            .expect("spawn task");
        let context = context_rx.await.expect("task context");
        let initial = authority
            .get_task_for_principal(&owner, &task.task_id)
            .expect("initial snapshot");

        let waiter_authority = authority.clone();
        let waiter_owner = owner.clone();
        let waiter_task_id = task.task_id.clone();
        let waiter = tokio::spawn(async move {
            waiter_authority
                .wait(
                    &waiter_owner,
                    &waiter_task_id,
                    Some(initial.revision),
                    Duration::from_secs(2),
                    TaskWaitCondition::RevisionChange,
                )
                .await
        });

        context.set_status_message("working hard");
        let observed = waiter
            .await
            .expect("waiter join")
            .expect("wait result")
            .expect("changed snapshot");
        assert!(observed.revision > initial.revision);
        assert_eq!(
            observed.task.task.status_message.as_deref(),
            Some("working hard")
        );

        authority
            .cancel_task_for_principal(&owner, &task.task_id)
            .expect("cancel task");
    }

    #[tokio::test]
    async fn terminal_wait_ignores_intermediate_revision_and_returns_completion() {
        let authority = Arc::new(TaskAuthority::new());
        let owner = principal("owner-a");
        let (finish_tx, finish_rx) = oneshot::channel::<()>();
        let task = authority
            .spawn_for_principal(owner.clone(), TaskOptions::default(), move |ctx| {
                Box::pin(async move {
                    ctx.set_status_message("phase one");
                    let _ = finish_rx.await;
                    Ok(ok_result("done"))
                })
            })
            .expect("spawn task");

        let initial = authority
            .get_task_for_principal(&owner, &task.task_id)
            .expect("initial snapshot");
        let waiter_authority = authority.clone();
        let waiter_owner = owner.clone();
        let waiter_task_id = task.task_id.clone();
        let waiter = tokio::spawn(async move {
            waiter_authority
                .wait(
                    &waiter_owner,
                    &waiter_task_id,
                    Some(initial.revision),
                    Duration::from_secs(2),
                    TaskWaitCondition::Terminal,
                )
                .await
        });

        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(!waiter.is_finished());
        let _ = finish_tx.send(());

        let observed = waiter
            .await
            .expect("waiter join")
            .expect("wait result")
            .expect("terminal snapshot");
        assert_eq!(observed.task.status(), TaskStatus::Completed);
    }

    #[tokio::test]
    async fn owner_cancel_wakes_operation_and_terminal_waiter() {
        let authority = Arc::new(TaskAuthority::new());
        let owner = principal("owner-a");
        let task = authority
            .spawn_for_principal(owner.clone(), TaskOptions::default(), |ctx| {
                Box::pin(async move {
                    ctx.cancelled().await;
                    Err(TaskExit::Cancelled)
                })
            })
            .expect("spawn task");

        let waiter_authority = authority.clone();
        let waiter_owner = owner.clone();
        let waiter_task_id = task.task_id.clone();
        let waiter = tokio::spawn(async move {
            waiter_authority
                .wait(
                    &waiter_owner,
                    &waiter_task_id,
                    None,
                    Duration::from_secs(2),
                    TaskWaitCondition::Terminal,
                )
                .await
        });

        authority
            .cancel_task_for_principal(&owner, &task.task_id)
            .expect("cancel task");
        let observed = waiter
            .await
            .expect("waiter join")
            .expect("wait result")
            .expect("terminal snapshot");
        assert_eq!(observed.task.status(), TaskStatus::Cancelled);
    }
}
