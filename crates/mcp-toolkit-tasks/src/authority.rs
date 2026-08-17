use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::{poll_fn, Future};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use rmcp::model::{CallToolResult, DetailedTask, InputRequest, Task};
use rmcp::task_manager::{TaskContext, TaskExit, TaskFuture, TaskManager, TaskOptions};
use tokio::sync::Notify;

const OBSERVATION_TICK: Duration = Duration::from_millis(250);

/// Stable opaque principal identifier used to bind an MCP task to its caller.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaskPrincipal(String);

impl TaskPrincipal {
    /// Creates an exact principal identifier.
    ///
    /// Security principal identifiers are treated as opaque values. Toolkit
    /// never trims or otherwise canonicalizes them because doing so could alias
    /// two identities that the upstream identity authority considers distinct.
    /// Surrounding Unicode whitespace is rejected instead of rewritten.
    ///
    /// # Errors
    /// Returns [`TaskAuthorityError::InvalidPrincipal`] when the identifier is
    /// empty, has surrounding whitespace, or exceeds 256 Unicode scalar values.
    pub fn new(value: impl Into<String>) -> Result<Self, TaskAuthorityError> {
        let value = value.into();
        let trimmed = value.trim();
        if value.is_empty() || trimmed != value.as_str() || value.chars().count() > 256 {
            return Err(TaskAuthorityError::InvalidPrincipal);
        }
        Ok(Self(value))
    }

    /// Returns the exact principal identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Errors exposed by the principal-bound task authority.
#[derive(Debug)]
pub enum TaskAuthorityError {
    /// Principal input was empty, ambiguous, or exceeded the metadata bound.
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
    /// Authoritative RMCP task state observed for this revision.
    pub task: DetailedTask,
    /// Monotonic local observation generation for the task.
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

#[derive(Default)]
struct AuthorityState {
    bindings: HashMap<String, Arc<TaskBinding>>,
    /// Round-robin liveness probes used to amortize stale binding cleanup.
    ///
    /// Entries removed through normal access are left in this queue lazily;
    /// probing skips them without touching RMCP.
    prune_queue: VecDeque<String>,
}

struct NotifyOnDrop {
    notify: Arc<Notify>,
}

impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        self.notify.notify_waiters();
    }
}

fn panic_task_exit(message: &'static str) -> TaskExit {
    TaskExit::Error(rmcp::ErrorData::internal_error(message.to_string(), None))
}

async fn catch_task_future_panic(mut future: TaskFuture) -> Result<CallToolResult, TaskExit> {
    poll_fn(
        move |cx| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(poll) => poll,
            Err(_panic) => Poll::Ready(Err(panic_task_exit("task operation panicked"))),
        },
    )
    .await
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
    ///
    /// Conversion into the concrete `String` happens before entering RMCP so a
    /// panicking caller-provided `Into<String>` implementation cannot unwind
    /// while RMCP holds its task-manager mutex.
    pub fn set_status_message(&self, message: impl Into<String>) {
        let message = message.into();
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
    state: Arc<Mutex<AuthorityState>>,
}

impl TaskAuthority {
    /// Creates an empty task authority.
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawns an RMCP task bound to `principal`.
    ///
    /// The initial RMCP `DetailedTask` is read before the binding is installed,
    /// so revision 1 always names a real RMCP snapshot. One existing binding is
    /// probed for RMCP liveness before each new task, amortizing stale cleanup
    /// without repeatedly sweeping the entire RMCP task set. If authority state
    /// is poisoned, the manager is shut down fail-closed rather than leaving an
    /// unbound task running.
    ///
    /// Panics from either the synchronous operation factory or polling the task
    /// future are contained and converted into an RMCP `failed` task result.
    pub fn spawn_for_principal<F>(
        &self,
        principal: TaskPrincipal,
        options: TaskOptions,
        make_future: F,
    ) -> Result<Task, TaskAuthorityError>
    where
        F: FnOnce(ManagedTaskContext) -> TaskFuture,
    {
        self.prune_one_stale_binding()?;

        let notify = Arc::new(Notify::new());
        let operation_notify = notify.clone();
        let task = self.manager.spawn(options, move |context| {
            let drop_hint = NotifyOnDrop {
                notify: operation_notify.clone(),
            };
            let managed = ManagedTaskContext {
                inner: context,
                notify: operation_notify,
            };
            let future: TaskFuture = match catch_unwind(AssertUnwindSafe(|| make_future(managed))) {
                Ok(future) => future,
                Err(_panic) => {
                    Box::pin(async { Err(panic_task_exit("task operation factory panicked")) })
                }
            };

            Box::pin(async move {
                let drop_hint = drop_hint;
                let result = catch_task_future_panic(future).await;
                drop(drop_hint);
                result
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

        let mut state = self.lock_state()?;
        if state.bindings.contains_key(&task.task_id) {
            drop(state);
            self.manager.shutdown();
            return Err(TaskAuthorityError::StateUnavailable);
        }
        state.prune_queue.push_back(task.task_id.clone());
        state.bindings.insert(task.task_id.clone(), binding);
        Ok(task)
    }

    /// Returns the current authorized task snapshot.
    pub fn get_task_for_principal(
        &self,
        principal: &TaskPrincipal,
        task_id: &str,
    ) -> Result<AuthorizedTaskSnapshot, TaskAuthorityError> {
        let binding = self.binding_for(principal, task_id)?;
        let task = self.manager.get_task(task_id);
        if let Ok(task) = task {
            return self.observe_or_shutdown(&binding, task);
        }
        self.remove_binding(task_id);
        Err(TaskAuthorityError::TaskNotFound)
    }

    /// Delivers RMCP `tasks/update` input responses after principal validation.
    ///
    /// The input iterator is fully materialized before entering RMCP. This keeps
    /// caller-controlled iterator code outside RMCP's global task-manager mutex;
    /// a panicking or slow iterator cannot poison or monopolize that mutex.
    pub fn update_task_for_principal(
        &self,
        principal: &TaskPrincipal,
        task_id: &str,
        input_responses: impl IntoIterator<Item = (String, serde_json::Value)>,
    ) -> Result<(), TaskAuthorityError> {
        let binding = self.binding_for(principal, task_id)?;
        let input_responses = input_responses.into_iter().collect::<Vec<_>>();
        if self.manager.update_task(task_id, input_responses).is_err() {
            self.remove_binding(task_id);
            return Err(TaskAuthorityError::TaskNotFound);
        }
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
        if self.manager.cancel_task(task_id).is_err() {
            self.remove_binding(task_id);
            return Err(TaskAuthorityError::TaskNotFound);
        }
        binding.hint();
        self.observe_current(&binding, task_id).map(|_| ())
    }

    /// Waits for an observed newer revision or a terminal RMCP task state.
    ///
    /// Wake-up hints cover Toolkit-controlled transitions immediately. A drop
    /// hint nudges observers when the operation future is cancelled, aborted,
    /// panics, or otherwise leaves scope. A bounded 250 ms observation tick
    /// remains the correctness fallback for RMCP-owned transitions, including
    /// terminal completion and TTL expiry. Returns `Ok(None)` when the timeout
    /// expires.
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
                // `notify_waiters` records its generation when `notified()` is
                // created, so constructing this future before the read closes
                // the read-to-await wake-up race even before the future is
                // polled.
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

        let outcome = tokio::time::timeout(timeout, wait).await;
        if let Ok(result) = outcome {
            return result.map(Some);
        }
        Ok(None)
    }

    /// Returns the number of currently non-terminal RMCP tasks.
    ///
    /// This is a global operator-oriented count, not a principal-scoped value.
    /// Do not expose it directly to tenants when aggregate activity is sensitive.
    pub fn running_task_count(&self) -> usize {
        self.manager.running_task_count()
    }

    /// Aborts all running RMCP tasks, clears principal bindings, and wakes local
    /// waiters so they can promptly observe that their task is no longer known.
    pub fn shutdown(&self) {
        self.manager.shutdown();
        let bindings = match self.state.lock() {
            Ok(mut state) => {
                let bindings = state
                    .bindings
                    .drain()
                    .map(|(_, binding)| binding)
                    .collect::<Vec<_>>();
                state.prune_queue.clear();
                bindings
            }
            Err(_) => return,
        };
        for binding in bindings {
            binding.hint();
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
        let task = self.manager.get_task(task_id);
        if let Ok(task) = task {
            return self.observe_or_shutdown(binding, task);
        }
        self.remove_binding(task_id);
        Err(TaskAuthorityError::TaskNotFound)
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
        let state = self.lock_state()?;
        let binding = state
            .bindings
            .get(task_id)
            .cloned()
            .ok_or(TaskAuthorityError::TaskNotFound)?;
        if &binding.principal != principal {
            return Err(TaskAuthorityError::TaskNotFound);
        }
        Ok(binding)
    }

    /// Probe one existing binding per spawn rather than probing every binding.
    ///
    /// RMCP 3.1.2 performs a full TTL sweep inside every `get_task`, so calling
    /// `get_task` for every local binding makes cleanup quadratic. The rotation
    /// queue bounds the extra RMCP liveness probes to one per new task while
    /// still eventually removing stale local authority records under continued
    /// task creation.
    fn prune_one_stale_binding(&self) -> Result<usize, TaskAuthorityError> {
        let candidate = {
            let mut state = self.lock_state()?;
            loop {
                match state.prune_queue.pop_front() {
                    Some(task_id) if state.bindings.contains_key(&task_id) => break Some(task_id),
                    Some(_) => {}
                    None => break None,
                }
            }
        };
        let Some(task_id) = candidate else {
            return Ok(0);
        };

        let live = self.manager.get_task(&task_id).is_ok();
        let mut state = self.lock_state()?;
        if live {
            if state.bindings.contains_key(&task_id) {
                state.prune_queue.push_back(task_id);
            }
            return Ok(0);
        }

        let removed = state.bindings.remove(&task_id);
        drop(state);
        if let Some(binding) = removed {
            binding.hint();
            return Ok(1);
        }
        Ok(0)
    }

    fn remove_binding(&self, task_id: &str) {
        let removed = match self.state.lock() {
            Ok(mut state) => state.bindings.remove(task_id),
            Err(_) => {
                self.manager.shutdown();
                return;
            }
        };
        if let Some(binding) = removed {
            binding.hint();
        }
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, AuthorityState>, TaskAuthorityError> {
        match self.state.lock() {
            Ok(state) => Ok(state),
            Err(_) => {
                self.manager.shutdown();
                Err(TaskAuthorityError::StateUnavailable)
            }
        }
    }
}

#[cfg(test)]
mod tests;
