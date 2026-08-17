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
//! * monotonic observed-state revisions;
//! * race-safe wait-for-change and wait-for-terminal observation;
//! * revision-aware wake-up hints around RMCP's task context.
//!
//! Revisions are observation generations, not a parallel task event log. They
//! advance only when a `TaskManager::get_task` read returns a `DetailedTask`
//! different from the last observed snapshot. Multiple RMCP transitions that
//! happen entirely between observations may therefore collapse into one local
//! revision. This keeps RMCP authoritative while still giving servers an
//! efficient bounded-wait primitive.
//!
//! The crate deliberately does not add another MCP Tasks wire protocol and does
//! not expose `tasks/list`.

use std::collections::HashMap;
use std::fmt;
use std::future::{poll_fn, Future};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use rmcp::model::{DetailedTask, InputRequest, Task};
use rmcp::task_manager::{TaskContext, TaskExit, TaskFuture, TaskManager, TaskOptions};
use tokio::sync::Notify;

const OBSERVATION_TICK: Duration = Duration::from_millis(250);

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
    /// Return after any observed revision strictly newer than `after_revision`.
    RevisionChange,
    /// Ignore intermediate revisions and return only once the task is terminal.
    Terminal,
}

/// Principal-authorized task snapshot with a monotonic observed-state revision.
#[derive(Debug, Clone)]
pub struct AuthorizedTaskSnapshot {
    pub task: DetailedTask,
    pub revision: u64,
}

#[derive(Debug)]
struct ObservedTaskState {
    revision: u64,
    task: DetailedTask,
}

#[derive(Debug)]
struct TaskBinding {
    principal: TaskPrincipal,
    observed: Mutex<ObservedTaskState>,
    notify: Arc<Notify>,
}

impl TaskBinding {
    fn new(principal: TaskPrincipal, task: DetailedTask, notify: Arc<Notify>) -> Self {
        Self {
            principal,
            observed: Mutex::new(ObservedTaskState { revision: 1, task }),
            notify,
        }
    }

    fn observe(&self, task: DetailedTask) -> Result<AuthorizedTaskSnapshot, TaskAuthorityError> {
        let mut observed = self
            .observed
            .lock()
            .map_err(|_| TaskAuthorityError::StateUnavailable)?;
        if observed.task != task {
            observed.revision = observed.revision.saturating_add(1);
            observed.task = task.clone();
            self.notify.notify_waiters();
        }
        Ok(AuthorizedTaskSnapshot {
            task,
            revision: observed.revision,
        })
    }

    fn hint(&self) {
        self.notify.notify_waiters();
    }
}

/// RMCP [`TaskContext`] wrapper that emits efficient observation wake-up hints.
///
/// Hints never advance the local revision directly. [`TaskAuthority`] validates
/// the current RMCP `DetailedTask` after waking and advances the revision only
/// when that authoritative snapshot actually changed.
#[derive(Clone)]
pub struct ManagedTaskContext {
    inner: TaskContext,
    notify: Arc<Notify>,
}

impl ManagedTaskContext {
    /// Returns the RMCP task id.
    pub fn task_id(&self) -> &str {
        self.inner.task_id()
    }

    /// Surface a mid-flight client input request and wait for its response.
    ///
    /// The RMCP future is polled once before the first wake-up hint. On the
    /// normal pending path this guarantees RMCP has installed the
    /// `input_required` request before local waiters are nudged. A second hint
    /// is emitted after the input wait resolves. Revisions are still assigned
    /// only after an authoritative `tasks/get` read observes each change.
    pub async fn request_input(
        &self,
        key: impl Into<String>,
        request: InputRequest,
    ) -> Result<serde_json::Value, TaskExit> {
        let mut request_future = Box::pin(self.inner.request_input(key, request));
        let immediate = poll_fn(|cx| match request_future.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(Some(result)),
            Poll::Pending => Poll::Ready(None),
        })
        .await;
        self.notify.notify_waiters();

        if let Some(result) = immediate {
            return result;
        }

        let result = request_future.await;
        self.notify.notify_waiters();
        result
    }

    /// Update the task status message and wake local observers.
    pub fn set_status_message(&self, message: impl Into<String>) {
        self.inner.set_status_message(message);
        self.notify.notify_waiters();
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
    /// The initial RMCP `DetailedTask` is read before the binding is installed,
    /// so revision 1 always names a real RMCP snapshot. If authority binding
    /// state is poisoned, the manager is shut down fail-closed rather than
    /// leaving an unbound task running.
    pub fn spawn_for_principal<F>(
        &self,
        principal: TaskPrincipal,
        options: TaskOptions,
        make_future: F,
    ) -> Result<Task, TaskAuthorityError>
    where
        F: FnOnce(ManagedTaskContext) -> TaskFuture,
    {
        let notify = Arc::new(Notify::new());
        let operation_notify = notify.clone();
        let task = self.manager.spawn(options, move |context| {
            make_future(ManagedTaskContext {
                inner: context,
                notify: operation_notify,
            })
        });

        let initial = match self.manager.get_task(&task.task_id) {
            Ok(task) => task,
            Err(error) => {
                let _ = self.manager.cancel_task(&task.task_id);
                return Err(TaskAuthorityError::Rmcp(error));
            }
        };
        let binding = Arc::new(TaskBinding::new(principal, initial, notify));

        let mut bindings = match self.bindings.lock() {
            Ok(bindings) => bindings,
            Err(_) => {
                self.manager.shutdown();
                return Err(TaskAuthorityError::StateUnavailable);
            }
        };
        bindings.insert(task.task_id.clone(), binding);
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
            Ok(task) => self.observe_or_shutdown(&binding, task),
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
        binding.hint();
        self.observe_current(&binding, task_id).map(|_| ())
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
        binding.hint();
        self.observe_current(&binding, task_id).map(|_| ())
    }

    /// Waits for an observed newer revision or a terminal RMCP task state.
    ///
    /// Wake-up hints cover Toolkit-controlled transitions immediately. A
    /// bounded 250 ms observation tick covers RMCP-owned transitions, including
    /// terminal completion and TTL expiry, without a tight polling loop.
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
        let initial = self.get_task_for_principal(principal, task_id)?;
        let baseline = after_revision.unwrap_or(initial.revision);

        if Self::wait_condition_ready(condition, baseline, &initial) {
            return Ok(Some(initial));
        }

        let wait = async {
            loop {
                // Register before the read so a hint arriving between the
                // authoritative state check and the await cannot be lost.
                let notified = binding.notify.notified();
                let snapshot = self.get_task_for_principal(principal, task_id)?;
                if Self::wait_condition_ready(condition, baseline, &snapshot) {
                    return Ok(snapshot);
                }

                tokio::select! {
                    _ = notified => {}
                    _ = tokio::time::sleep(OBSERVATION_TICK) => {}
                }
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

    fn wait_condition_ready(
        condition: TaskWaitCondition,
        baseline: u64,
        snapshot: &AuthorizedTaskSnapshot,
    ) -> bool {
        match condition {
            TaskWaitCondition::RevisionChange => snapshot.revision > baseline,
            TaskWaitCondition::Terminal => snapshot.task.status().is_terminal(),
        }
    }

    fn observe_current(
        &self,
        binding: &TaskBinding,
        task_id: &str,
    ) -> Result<AuthorizedTaskSnapshot, TaskAuthorityError> {
        match self.manager.get_task(task_id) {
            Ok(task) => self.observe_or_shutdown(binding, task),
            Err(_) => {
                self.remove_binding(task_id);
                Err(TaskAuthorityError::TaskNotFound)
            }
        }
    }

    fn observe_or_shutdown(
        &self,
        binding: &TaskBinding,
        task: DetailedTask,
    ) -> Result<AuthorizedTaskSnapshot, TaskAuthorityError> {
        match binding.observe(task) {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                self.manager.shutdown();
                Err(error)
            }
        }
    }

    fn binding_for(
        &self,
        principal: &TaskPrincipal,
        task_id: &str,
    ) -> Result<Arc<TaskBinding>, TaskAuthorityError> {
        let bindings = match self.bindings.lock() {
            Ok(bindings) => bindings,
            Err(_) => {
                self.manager.shutdown();
                return Err(TaskAuthorityError::StateUnavailable);
            }
        };
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
        match self.bindings.lock() {
            Ok(mut bindings) => {
                bindings.remove(task_id);
            }
            Err(_) => self.manager.shutdown(),
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
    async fn repeated_reads_keep_revision_stable_without_rmcp_change() {
        let authority = TaskAuthority::new();
        let owner = principal("owner-a");
        let task = authority
            .spawn_for_principal(owner.clone(), TaskOptions::default(), |ctx| {
                Box::pin(async move {
                    ctx.cancelled().await;
                    Err(TaskExit::Cancelled)
                })
            })
            .expect("spawn task");

        let first = authority
            .get_task_for_principal(&owner, &task.task_id)
            .expect("first snapshot");
        let second = authority
            .get_task_for_principal(&owner, &task.task_id)
            .expect("second snapshot");
        assert_eq!(first.revision, second.revision);
        assert_eq!(first.task, second.task);

        authority
            .cancel_task_for_principal(&owner, &task.task_id)
            .expect("cancel task");
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
    async fn terminal_wait_observes_rmcp_owned_completion_without_completion_hint() {
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
        assert!(observed.revision > initial.revision);
    }

    #[tokio::test]
    async fn owner_cancel_reaches_terminal_without_relying_on_cancel_revision_hint() {
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
