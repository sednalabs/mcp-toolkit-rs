use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::{poll_fn, Future};
use std::num::NonZeroUsize;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use rmcp::model::{DetailedTask, InputRequest, Task};
use rmcp::task_manager::{TaskContext, TaskExit, TaskFuture, TaskManager, TaskOptions};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::Notify;

mod panic_future;
use panic_future::{contain_task_future, discard_panic_payload};

const SETTLEMENT_RECHECK: Duration = Duration::from_millis(250);

/// Stable opaque principal identifier used to bind an MCP task to its caller.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TaskPrincipal(String);

impl fmt::Debug for TaskPrincipal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskPrincipal(<redacted>)")
    }
}

impl TaskPrincipal {
    /// Creates an exact principal identifier.
    ///
    /// Security principal identifiers are treated as opaque values. Toolkit
    /// never trims or otherwise canonicalizes them because doing so could alias
    /// two identities that the upstream identity authority considers distinct.
    /// Surrounding Unicode whitespace is rejected instead of rewritten.
    ///
    /// `Debug` output is redacted so the opaque identity is not accidentally
    /// copied into logs through ordinary diagnostic formatting.
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
    ///
    /// Treat this value as security-sensitive. It is intentionally available to
    /// authorization code, but Toolkit does not expose it through `Debug`.
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
    /// Task spawning requires an entered Tokio runtime.
    RuntimeUnavailable,
    /// Task observation requires a Tokio runtime with its time driver enabled.
    RuntimeTimerUnavailable,
    /// The authority has been shut down and cannot be reopened.
    Closed,
    /// The caller-configured retained-task authority capacity is exhausted.
    CapacityReached,
    /// The caller-configured concurrent waiter capacity is exhausted.
    WaiterCapacityReached,
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
            Self::RuntimeUnavailable => write!(f, "task spawning requires a Tokio runtime"),
            Self::RuntimeTimerUnavailable => {
                write!(
                    f,
                    "task spawning requires a Tokio runtime with time enabled"
                )
            }
            Self::Closed => write!(f, "task authority is shut down"),
            Self::CapacityReached => write!(f, "task authority capacity reached"),
            Self::WaiterCapacityReached => write!(f, "task wait capacity reached"),
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

struct TaskBinding {
    principal: TaskPrincipal,
    observed: Mutex<ObservedTaskState>,
    signal: TaskSignal,
    read_gate: AsyncMutex<()>,
    last_read_at: Mutex<Option<std::time::Instant>>,
    observation_done: Notify,
}

impl TaskBinding {
    fn new(principal: TaskPrincipal, task: DetailedTask, signal: TaskSignal) -> Self {
        Self {
            principal,
            observed: Mutex::new(ObservedTaskState { revision: 1, task }),
            signal,
            read_gate: AsyncMutex::new(()),
            last_read_at: Mutex::new(None),
            observation_done: Notify::new(),
        }
    }

    fn snapshot(&self) -> Result<AuthorizedTaskSnapshot, TaskAuthorityError> {
        let observed = self
            .observed
            .lock()
            .map_err(|_| TaskAuthorityError::StateUnavailable)?;
        Ok(AuthorizedTaskSnapshot {
            task: observed.task.clone(),
            revision: observed.revision,
        })
    }

    fn observe(&self, task: DetailedTask) -> Result<AuthorizedTaskSnapshot, TaskAuthorityError> {
        let mut observed = self
            .observed
            .lock()
            .map_err(|_| TaskAuthorityError::StateUnavailable)?;
        if observed.task != task {
            observed.revision = observed.revision.saturating_add(1);
            observed.task = task.clone();
            self.signal.waiters.notify_waiters();
        }
        Ok(AuthorizedTaskSnapshot {
            task,
            revision: observed.revision,
        })
    }

    fn hint(&self) {
        self.signal.hint(false);
        self.observation_done.notify_waiters();
    }
}

#[derive(Clone)]
struct TaskSignal {
    waiters: Arc<Notify>,
    observer: Arc<Notify>,
    generation: Arc<AtomicU64>,
    settlement_pending: Arc<AtomicBool>,
}

impl TaskSignal {
    fn new(observer: Arc<Notify>) -> Self {
        Self {
            waiters: Arc::new(Notify::new()),
            observer,
            generation: Arc::new(AtomicU64::new(0)),
            settlement_pending: Arc::new(AtomicBool::new(false)),
        }
    }

    fn hint(&self, _settlement: bool) -> u64 {
        if _settlement {
            self.settlement_pending.store(true, Ordering::Release);
        }
        let generation = self
            .generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        self.waiters.notify_waiters();
        self.observer.notify_one();
        generation
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn is_settlement_pending(&self) -> bool {
        self.settlement_pending.load(Ordering::Acquire)
    }
}

struct LeaseInfo {
    ttl: Option<Duration>,
    created_at: std::time::Instant,
    next_probe_at: Option<std::time::Instant>,
    observed_signal_generation: u64,
}

struct WaiterLease {
    state: Arc<Mutex<AuthorityState>>,
}

impl Drop for WaiterLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.active_waiters = state.active_waiters.saturating_sub(1);
        }
    }
}

#[derive(Default)]
struct AuthorityState {
    bindings: HashMap<String, Arc<TaskBinding>>,
    /// Capacity leases are independent of waiter-held binding Arcs.
    leases: HashMap<String, LeaseInfo>,
    reserved_leases: usize,
    active_waiters: usize,
    observer_principals: VecDeque<TaskPrincipal>,
    observer_tasks: HashMap<TaskPrincipal, VecDeque<String>>,
}

/// Caller-selected limits for retained task authority and observation.
///
/// No task or waiter capacity is selected implicitly by Toolkit. A finite
/// retained-task limit is required because RMCP retains task records until a
/// later authoritative operation sweeps them.
#[derive(Debug, Clone, Copy)]
pub struct TaskAuthorityConfig {
    /// Maximum number of materialized or retained RMCP task records.
    pub max_retained_tasks: NonZeroUsize,
    /// Maximum number of authorized active waits across all principals.
    pub max_waiters: NonZeroUsize,
    /// Maximum RMCP fallback reads admitted per second across all task IDs.
    pub fallback_reads_per_second: NonZeroUsize,
}

/// Aggregate counters for task wait admission and observation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TaskAuthorityMetrics {
    /// Number of waiters currently registered with this authority.
    pub active_waiters: usize,
    /// Reads avoided because another waiter recently observed the same task.
    pub coalesced_reads: u64,
    /// Aggregate fallback RMCP reads issued by waiters.
    pub fallback_reads: u64,
    /// Total observed latency, in microseconds, across successful RMCP reads.
    pub observation_latency_micros: u64,
    /// Waits rejected by configured waiter admission.
    pub rejected_waits: u64,
}

struct AuthorityLifecycle {
    /// Publication gate and irreversible closed bit.
    ///
    /// The mutex gives spawn publication and shutdown a single linearization
    /// point without holding Toolkit state across caller-controlled factory
    /// code. Once true, the authority never transitions back to open.
    closed: Mutex<bool>,
    observer_stop: Arc<Notify>,
}

/// Arc-owned teardown guard.
///
/// `Arc` runs this destructor exactly once when the last authority clone drops,
/// including when the final handles are dropped concurrently. This avoids the
/// racy `Arc::strong_count == 1` heuristic that can miss teardown when two final
/// owners both observe a count greater than one before either decrement lands.
struct LastHandleGuard {
    manager: TaskManager,
    state: Arc<Mutex<AuthorityState>>,
    lifecycle: Arc<AuthorityLifecycle>,
}

impl Drop for LastHandleGuard {
    fn drop(&mut self) {
        close_and_drain(&self.manager, &self.state, &self.lifecycle);
    }
}

fn close_and_drain(
    manager: &TaskManager,
    state: &Arc<Mutex<AuthorityState>>,
    lifecycle: &Arc<AuthorityLifecycle>,
) {
    {
        let mut closed = match lifecycle.closed.lock() {
            Ok(closed) => closed,
            Err(poisoned) => poisoned.into_inner(),
        };
        *closed = true;
    }
    lifecycle.observer_stop.notify_one();
    manager.shutdown();
    let bindings = match state.lock() {
        Ok(mut state) => {
            let bindings = state
                .bindings
                .drain()
                .map(|(_, binding)| binding)
                .collect::<Vec<_>>();
            state.leases.clear();
            state.reserved_leases = 0;
            state.active_waiters = 0;
            state.observer_principals.clear();
            state.observer_tasks.clear();
            bindings
        }
        Err(_) => return,
    };
    for binding in bindings {
        binding.hint();
    }
}

struct NotifyOnDrop {
    signal: TaskSignal,
}

impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        self.signal.hint(true);
    }
}

fn panic_task_exit(message: &'static str) -> TaskExit {
    TaskExit::Error(rmcp::ErrorData::internal_error(message.to_string(), None))
}

/// RMCP [`TaskContext`] wrapper that emits efficient observation wake-up hints.
///
/// Hints never advance the local revision directly. [`TaskAuthority`] validates
/// the current RMCP `DetailedTask` after waking and advances the revision only
/// when that authoritative snapshot actually changed.
#[derive(Clone)]
pub struct ManagedTaskContext {
    inner: TaskContext,
    signal: TaskSignal,
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
        self.signal.hint(false);

        if let Some(result) = immediate {
            return result;
        }

        let result = request_future.await;
        self.signal.hint(false);
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
        self.signal.hint(false);
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
///
/// [`Self::shutdown`] is irreversible across every clone. Dropping the last
/// ordinary authority handle also shuts the RMCP manager down. Last-handle
/// teardown is owned by an Arc destructor rather than an observed strong count,
/// so concurrent final drops cannot skip shutdown. As with other `Arc`-backed
/// Rust runtimes, caller-created reference cycles can keep a deliberately
/// retained authority clone alive; avoid storing an authority clone indefinitely
/// inside its own unlimited-retention task.
#[derive(Clone)]
pub struct TaskAuthority {
    manager: TaskManager,
    config: TaskAuthorityConfig,
    state: Arc<Mutex<AuthorityState>>,
    lifecycle: Arc<AuthorityLifecycle>,
    metrics: Arc<AtomicMetrics>,
    observer_notify: Arc<Notify>,
    observer_started: Arc<AtomicBool>,
    fallback_window: Arc<Mutex<VecDeque<std::time::Instant>>>,
    _last_handle: Arc<LastHandleGuard>,
}

#[derive(Default)]
struct AtomicMetrics {
    coalesced_reads: AtomicU64,
    fallback_reads: AtomicU64,
    observation_latency_micros: AtomicU64,
    rejected_waits: AtomicU64,
}

impl TaskAuthority {
    /// Creates an empty task authority with explicit task and waiter limits.
    pub fn new(config: TaskAuthorityConfig) -> Self {
        let manager = TaskManager::new();
        let state = Arc::new(Mutex::new(AuthorityState::default()));
        let lifecycle = Arc::new(AuthorityLifecycle {
            closed: Mutex::new(false),
            observer_stop: Arc::new(Notify::new()),
        });
        let metrics = Arc::new(AtomicMetrics::default());
        let observer_notify = Arc::new(Notify::new());
        let observer_started = Arc::new(AtomicBool::new(false));
        let fallback_window = Arc::new(Mutex::new(VecDeque::new()));
        let last_handle = Arc::new(LastHandleGuard {
            manager: manager.clone(),
            state: state.clone(),
            lifecycle: lifecycle.clone(),
        });
        Self {
            manager,
            config,
            state,
            lifecycle,
            metrics,
            observer_notify,
            observer_started,
            fallback_window,
            _last_handle: last_handle,
        }
    }

    /// Returns bounded aggregate task-observation counters.
    pub fn metrics(&self) -> TaskAuthorityMetrics {
        let active_waiters = self
            .state
            .lock()
            .map(|state| state.active_waiters)
            .unwrap_or(0);
        TaskAuthorityMetrics {
            active_waiters,
            coalesced_reads: self.metrics.coalesced_reads.load(Ordering::Relaxed),
            fallback_reads: self.metrics.fallback_reads.load(Ordering::Relaxed),
            observation_latency_micros: self
                .metrics
                .observation_latency_micros
                .load(Ordering::Relaxed),
            rejected_waits: self.metrics.rejected_waits.load(Ordering::Relaxed),
        }
    }

    /// Spawns an RMCP task bound to `principal`.
    ///
    /// A current Tokio runtime is required because RMCP 3.5.0 materializes the
    /// task operation with `tokio::spawn`. Toolkit checks that requirement before
    /// entering RMCP so a synchronous caller gets [`TaskAuthorityError::RuntimeUnavailable`]
    /// instead of a Tokio panic or partially materialized task.
    ///
    /// The initial RMCP `DetailedTask` is read before the binding is published,
    /// so revision 1 always names a real RMCP snapshot. One existing binding is
    /// probed for RMCP liveness before each new task, amortizing stale cleanup
    /// without repeatedly sweeping the entire RMCP task set. If authority state
    /// is poisoned, the manager is shut down fail-closed rather than leaving an
    /// unbound task running.
    ///
    /// Panics from either the synchronous operation factory, polling the task
    /// future, or destroying that future are contained and converted into an
    /// RMCP `failed` task result where a task record still exists.
    ///
    /// Spawn publication and shutdown are linearized by the lifecycle gate. A
    /// shutdown that wins that gate prevents the newly materialized task from
    /// being published and RMCP is drained again to abort any task inserted
    /// after an earlier RMCP shutdown call.
    pub fn spawn_for_principal<F>(
        &self,
        principal: TaskPrincipal,
        options: TaskOptions,
        make_future: F,
    ) -> Result<Task, TaskAuthorityError>
    where
        F: FnOnce(ManagedTaskContext) -> TaskFuture,
    {
        self.ensure_open()?;
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(TaskAuthorityError::RuntimeUnavailable);
        }
        if catch_unwind(AssertUnwindSafe(|| tokio::time::sleep(Duration::ZERO))).is_err() {
            return Err(TaskAuthorityError::RuntimeTimerUnavailable);
        }
        self.reserve_capacity()?;
        self.ensure_open()?;

        let ttl = options.ttl_ms.map(Duration::from_millis);
        let signal = TaskSignal::new(self.observer_notify.clone());
        let operation_signal = signal.clone();
        let task = match catch_unwind(AssertUnwindSafe(|| {
            self.manager.spawn(options, move |context| {
                let drop_hint = NotifyOnDrop {
                    signal: operation_signal.clone(),
                };
                let managed = ManagedTaskContext {
                    inner: context,
                    signal: operation_signal,
                };
                let future: TaskFuture = match catch_unwind(AssertUnwindSafe(|| {
                    make_future(managed)
                })) {
                    Ok(future) => contain_task_future(future),
                    Err(panic) => {
                        discard_panic_payload(panic);
                        Box::pin(async { Err(panic_task_exit("task operation factory panicked")) })
                    }
                };

                Box::pin(async move {
                    let drop_hint = drop_hint;
                    let result = future.await;
                    drop(drop_hint);
                    result
                })
            })
        })) {
            Ok(task) => task,
            Err(panic) => {
                discard_panic_payload(panic);
                self.force_close();
                return Err(TaskAuthorityError::StateUnavailable);
            }
        };

        // Keep this reservation until the RMCP record is published, confirmed
        // absent, or drained by shutdown. The permit covers that interval.
        {
            let mut state = self.lock_state()?;
            state.reserved_leases = state.reserved_leases.saturating_sub(1);
            let created_at = std::time::Instant::now();
            state.leases.insert(
                task.task_id.clone(),
                LeaseInfo {
                    ttl,
                    created_at,
                    next_probe_at: ttl.and_then(|ttl| created_at.checked_add(ttl)),
                    observed_signal_generation: 0,
                },
            );
        }

        match self.is_closed() {
            Ok(true) => {
                self.force_close();
                return Err(TaskAuthorityError::Closed);
            }
            Ok(false) => {}
            Err(error) => {
                self.force_close();
                return Err(error);
            }
        }

        let initial = match self.manager.get_task(&task.task_id) {
            Ok(task) => task,
            Err(error) => {
                match self.is_closed() {
                    Ok(true) => {
                        self.force_close();
                        return Err(TaskAuthorityError::Closed);
                    }
                    Ok(false) => {}
                    Err(state_error) => {
                        self.force_close();
                        return Err(state_error);
                    }
                }
                // `get_task` is the authoritative absence confirmation. This
                // materialization never reached binding publication, so its
                // lease can now be released safely.
                if let Ok(mut state) = self.state.lock() {
                    state.leases.remove(&task.task_id);
                } else {
                    self.force_close();
                    return Err(TaskAuthorityError::StateUnavailable);
                }
                return Err(TaskAuthorityError::Rmcp(error));
            }
        };
        let binding = Arc::new(TaskBinding::new(principal, initial, signal));
        if let Ok(mut last_read_at) = binding.last_read_at.lock() {
            *last_read_at = Some(std::time::Instant::now());
        }

        let lifecycle = match self.lock_lifecycle() {
            Ok(lifecycle) => lifecycle,
            Err(error) => {
                self.force_close();
                return Err(error);
            }
        };
        if *lifecycle {
            drop(lifecycle);
            self.force_close();
            return Err(TaskAuthorityError::Closed);
        }
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                drop(lifecycle);
                self.force_close();
                return Err(TaskAuthorityError::StateUnavailable);
            }
        };
        if state.bindings.contains_key(&task.task_id) {
            drop(state);
            drop(lifecycle);
            self.force_close();
            return Err(TaskAuthorityError::StateUnavailable);
        }
        let principal_queue_was_empty = state
            .observer_tasks
            .get(&binding.principal)
            .is_none_or(VecDeque::is_empty);
        state
            .observer_tasks
            .entry(binding.principal.clone())
            .or_default()
            .push_back(task.task_id.clone());
        if principal_queue_was_empty {
            state
                .observer_principals
                .push_back(binding.principal.clone());
        }
        state.bindings.insert(task.task_id.clone(), binding);
        drop(state);
        drop(lifecycle);
        self.start_observer();
        self.observer_notify.notify_one();
        Ok(task)
    }

    /// Returns the current authorized task snapshot.
    pub fn get_task_for_principal(
        &self,
        principal: &TaskPrincipal,
        task_id: &str,
    ) -> Result<AuthorizedTaskSnapshot, TaskAuthorityError> {
        let binding = self.binding_for(principal, task_id)?;
        let signal_generation = binding.signal.generation();
        let task = self.manager.get_task(task_id);
        if let Ok(task) = task {
            return self.observe_or_close(&binding, task_id, task, signal_generation);
        }
        self.remove_binding(task_id);
        if self.is_closed()? {
            return Err(TaskAuthorityError::Closed);
        }
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
            if self.is_closed()? {
                return Err(TaskAuthorityError::Closed);
            }
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
            if self.is_closed()? {
                return Err(TaskAuthorityError::Closed);
            }
            return Err(TaskAuthorityError::TaskNotFound);
        }
        binding.hint();
        self.observe_current(&binding, task_id).map(|_| ())
    }

    /// Waits for an observed newer revision or a terminal RMCP task state.
    ///
    /// Wake-up hints cover Toolkit-controlled transitions immediately. A drop
    /// hint creates a settlement obligation that the shared observer retries
    /// until RMCP publishes terminal state, expires the record, or shutdown
    /// closes the authority. The shared observer schedules TTL readbacks and
    /// applies one aggregate caller-configured read budget across task IDs.
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
        let _waiter = self.register_waiter()?;
        let wait = async {
            let initial = self.observe_wait_initial(&binding, task_id).await?;
            let baseline = after_revision.unwrap_or(initial.revision);
            if Self::wait_condition_ready(condition, baseline, &initial) {
                return Ok(initial);
            }
            loop {
                let notified = binding.signal.waiters.notified();
                let snapshot = binding.snapshot()?;
                if Self::wait_condition_ready(condition, baseline, &snapshot) {
                    return Ok(snapshot);
                }
                if self.is_closed()? {
                    return Err(TaskAuthorityError::Closed);
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
    ///
    /// This is a global operator-oriented count, not a principal-scoped value.
    /// Do not expose it directly to tenants when aggregate activity is sensitive.
    pub fn running_task_count(&self) -> usize {
        self.manager.running_task_count()
    }

    /// Irreversibly closes the authority, aborts all running RMCP tasks, clears
    /// principal bindings, and wakes local waiters.
    ///
    /// Every clone shares the same closed state. Once this method begins, a
    /// later spawn cannot reopen the underlying RMCP manager even though RMCP's
    /// `TaskManager` itself is reusable after `shutdown()`.
    pub fn shutdown(&self) {
        close_and_drain(&self.manager, &self.state, &self.lifecycle);
    }

    fn start_observer(&self) {
        if self
            .observer_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        tokio::spawn(observation_loop(
            self.manager.clone(),
            Arc::downgrade(&self.state),
            Arc::downgrade(&self.lifecycle),
            self.observer_notify.clone(),
            self.fallback_window.clone(),
            self.config,
            self.metrics.clone(),
        ));
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
        let signal_generation = binding.signal.generation();
        let task = self.manager.get_task(task_id);
        if let Ok(task) = task {
            return self.observe_or_close(binding, task_id, task, signal_generation);
        }
        self.remove_binding(task_id);
        if self.is_closed()? {
            return Err(TaskAuthorityError::Closed);
        }
        Err(TaskAuthorityError::TaskNotFound)
    }

    fn observe_or_close(
        &self,
        binding: &TaskBinding,
        task_id: &str,
        task: DetailedTask,
        signal_generation: u64,
    ) -> Result<AuthorizedTaskSnapshot, TaskAuthorityError> {
        match binding.observe(task) {
            Ok(snapshot) => {
                if let Ok(mut last_read_at) = binding.last_read_at.lock() {
                    *last_read_at = Some(std::time::Instant::now());
                }
                let mut state = match self.state.lock() {
                    Ok(state) => state,
                    Err(_) => {
                        self.force_close();
                        return Err(TaskAuthorityError::StateUnavailable);
                    }
                };
                if let Some(lease) = state.leases.get_mut(task_id) {
                    lease.observed_signal_generation = signal_generation;
                    if snapshot.task.status().is_terminal() {
                        binding
                            .signal
                            .settlement_pending
                            .store(false, Ordering::Release);
                        lease.next_probe_at = lease
                            .ttl
                            .and_then(|ttl| std::time::Instant::now().checked_add(ttl));
                    } else if binding.signal.is_settlement_pending() {
                        lease.next_probe_at =
                            std::time::Instant::now().checked_add(SETTLEMENT_RECHECK);
                    }
                }
                drop(state);
                binding.observation_done.notify_waiters();
                Ok(snapshot)
            }
            Err(error) => {
                self.force_close();
                Err(error)
            }
        }
    }

    fn binding_for(
        &self,
        principal: &TaskPrincipal,
        task_id: &str,
    ) -> Result<Arc<TaskBinding>, TaskAuthorityError> {
        self.ensure_open()?;
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

    fn remove_binding(&self, task_id: &str) {
        let removed = match self.state.lock() {
            Ok(mut state) => {
                state.leases.remove(task_id);
                state.bindings.remove(task_id)
            }
            Err(_) => {
                self.force_close();
                return;
            }
        };
        if let Some(binding) = removed {
            binding.hint();
        }
    }

    fn ensure_open(&self) -> Result<(), TaskAuthorityError> {
        if self.is_closed()? {
            Err(TaskAuthorityError::Closed)
        } else {
            Ok(())
        }
    }

    fn reserve_capacity(&self) -> Result<(), TaskAuthorityError> {
        self.ensure_open()?;
        let mut state = self.lock_state()?;
        if state.leases.len() + state.reserved_leases >= self.config.max_retained_tasks.get() {
            return Err(TaskAuthorityError::CapacityReached);
        }
        state.reserved_leases += 1;
        Ok(())
    }

    fn register_waiter(&self) -> Result<WaiterLease, TaskAuthorityError> {
        let mut state = self.lock_state()?;
        if state.active_waiters >= self.config.max_waiters.get() {
            self.metrics.rejected_waits.fetch_add(1, Ordering::Relaxed);
            return Err(TaskAuthorityError::WaiterCapacityReached);
        }
        state.active_waiters += 1;
        Ok(WaiterLease {
            state: self.state.clone(),
        })
    }

    async fn observe_wait_initial(
        &self,
        binding: &TaskBinding,
        task_id: &str,
    ) -> Result<AuthorizedTaskSnapshot, TaskAuthorityError> {
        let clean_cached_read = binding
            .last_read_at
            .lock()
            .map_err(|_| TaskAuthorityError::StateUnavailable)?
            .is_some_and(|last| last.elapsed() < SETTLEMENT_RECHECK)
            && self
                .state
                .lock()
                .map_err(|_| TaskAuthorityError::StateUnavailable)?
                .leases
                .get(task_id)
                .is_some_and(|lease| {
                    lease.observed_signal_generation == binding.signal.generation()
                        && !binding.signal.is_settlement_pending()
                });
        if clean_cached_read {
            self.metrics.coalesced_reads.fetch_add(1, Ordering::Relaxed);
            return binding.snapshot();
        }

        // Initial waiter observations use the same fair coordinator and global
        // fallback budget as later readbacks. Multiple waiters on this task
        // advance one generation and can be satisfied by a shared read.
        let target_generation = binding.signal.hint(false);
        self.observer_notify.notify_one();
        loop {
            let notified = binding.observation_done.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let state = self.lock_state()?;
            let Some(lease) = state.leases.get(task_id) else {
                drop(state);
                return if self.is_closed()? {
                    Err(TaskAuthorityError::Closed)
                } else {
                    Err(TaskAuthorityError::TaskNotFound)
                };
            };
            let observed = lease.observed_signal_generation;
            drop(state);
            if observed >= target_generation {
                return binding.snapshot();
            }
            if self.is_closed()? {
                return Err(TaskAuthorityError::Closed);
            }
            notified.await;
        }
    }

    fn is_closed(&self) -> Result<bool, TaskAuthorityError> {
        match self.lifecycle.closed.lock() {
            Ok(closed) => Ok(*closed),
            Err(_) => {
                self.manager.shutdown();
                Err(TaskAuthorityError::StateUnavailable)
            }
        }
    }

    fn lock_lifecycle(&self) -> Result<std::sync::MutexGuard<'_, bool>, TaskAuthorityError> {
        match self.lifecycle.closed.lock() {
            Ok(closed) => Ok(closed),
            Err(_) => {
                self.manager.shutdown();
                Err(TaskAuthorityError::StateUnavailable)
            }
        }
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, AuthorityState>, TaskAuthorityError> {
        match self.state.lock() {
            Ok(state) => Ok(state),
            Err(_) => {
                self.force_close();
                Err(TaskAuthorityError::StateUnavailable)
            }
        }
    }

    fn force_close(&self) {
        close_and_drain(&self.manager, &self.state, &self.lifecycle);
    }
}

async fn observation_loop(
    manager: TaskManager,
    state: std::sync::Weak<Mutex<AuthorityState>>,
    lifecycle: std::sync::Weak<AuthorityLifecycle>,
    observer_notify: Arc<Notify>,
    fallback_window: Arc<Mutex<VecDeque<std::time::Instant>>>,
    config: TaskAuthorityConfig,
    metrics: Arc<AtomicMetrics>,
) {
    let Some(lifecycle_owner) = lifecycle.upgrade() else {
        return;
    };
    let stop = lifecycle_owner.observer_stop.clone();
    drop(lifecycle_owner);

    loop {
        let notified = observer_notify.notified();
        let next_probe = {
            let Some(lifecycle_owner) = lifecycle.upgrade() else {
                return;
            };
            let Ok(closed) = lifecycle_owner.closed.lock() else {
                manager.shutdown();
                return;
            };
            if *closed {
                return;
            }
            let Some(state_owner) = state.upgrade() else {
                return;
            };
            let Ok(mut state) = state_owner.lock() else {
                manager.shutdown();
                return;
            };
            drop(closed);
            drop(lifecycle_owner);

            let now = std::time::Instant::now();
            let mut earliest = state
                .leases
                .values()
                .filter_map(|lease| lease.next_probe_at)
                .min();
            let mut selected = None;
            let principal_turns = state.observer_principals.len();
            for _ in 0..principal_turns {
                let Some(principal) = state.observer_principals.pop_front() else {
                    break;
                };
                let Some(task_id) = state
                    .observer_tasks
                    .get_mut(&principal)
                    .and_then(VecDeque::pop_front)
                else {
                    state.observer_tasks.remove(&principal);
                    continue;
                };
                let queue_has_more = state
                    .observer_tasks
                    .get(&principal)
                    .is_some_and(|queue| !queue.is_empty());
                if queue_has_more {
                    state.observer_principals.push_back(principal.clone());
                }

                let binding = state.bindings.get(&task_id).cloned();
                if let Some(binding) = binding {
                    let generation = binding.signal.generation();
                    let lease = state.leases.get(&task_id);
                    let due = lease.is_some_and(|lease| {
                        generation != lease.observed_signal_generation
                            || lease.next_probe_at.is_some_and(|deadline| deadline <= now)
                            || (binding.signal.is_settlement_pending()
                                && lease.next_probe_at.is_none_or(|deadline| deadline <= now))
                    });
                    if due && selected.is_none() {
                        selected = Some((task_id.clone(), binding.clone(), generation));
                    }
                    if let Some(deadline) = lease.and_then(|lease| lease.next_probe_at) {
                        earliest = Some(earliest.map_or(deadline, |current| current.min(deadline)));
                    }

                    let bucket_was_empty = state
                        .observer_tasks
                        .get(&principal)
                        .is_none_or(VecDeque::is_empty);
                    state
                        .observer_tasks
                        .entry(principal.clone())
                        .or_default()
                        .push_back(task_id.clone());
                    if bucket_was_empty && !state.observer_principals.contains(&principal) {
                        state.observer_principals.push_back(principal);
                    }
                }
            }
            (selected, earliest)
        };

        let (selected, deadline) = next_probe;
        let Some((task_id, binding, generation)) = selected else {
            // No task is due yet. Wake on hints or the nearest known TTL edge.
            if let Some(deadline) = deadline {
                tokio::select! {
                    _ = notified => {},
                    _ = stop.notified() => return,
                    _ = tokio::time::sleep_until(deadline.into()) => {},
                }
            } else {
                tokio::select! {
                    _ = notified => {},
                    _ = stop.notified() => return,
                }
            }
            continue;
        };

        let delay = {
            let mut window = match fallback_window.lock() {
                Ok(window) => window,
                Err(_) => {
                    manager.shutdown();
                    return;
                }
            };
            let now = std::time::Instant::now();
            while window
                .front()
                .is_some_and(|time| now.duration_since(*time) >= Duration::from_secs(1))
            {
                window.pop_front();
            }
            if window.len() < config.fallback_reads_per_second.get() {
                window.push_back(now);
                Duration::ZERO
            } else {
                window
                    .front()
                    .map(|time| Duration::from_secs(1).saturating_sub(now.duration_since(*time)))
                    .unwrap_or(Duration::ZERO)
            }
        };
        if !delay.is_zero() {
            tokio::select! {
                _ = stop.notified() => return,
                _ = tokio::time::sleep(delay) => {},
            }
            // Re-evaluate deadlines and fair queues before spending a slot.
            continue;
        }

        let _read_guard = binding.read_gate.lock().await;
        let recent_read = binding
            .last_read_at
            .lock()
            .ok()
            .and_then(|last| *last)
            .filter(|last| last.elapsed() < SETTLEMENT_RECHECK);
        let clean_since_last_read = if let Some(state_owner) = state.upgrade() {
            match state_owner.lock() {
                Ok(state) => state.leases.get(&task_id).is_some_and(|lease| {
                    lease.observed_signal_generation == binding.signal.generation()
                        && !binding.signal.is_settlement_pending()
                }),
                Err(_) => false,
            }
        } else {
            false
        };
        if let Some(last_read) = recent_read.filter(|_| clean_since_last_read) {
            if let Some(state_owner) = state.upgrade() {
                if let Ok(mut state) = state_owner.lock() {
                    if let Some(lease) = state.leases.get_mut(&task_id) {
                        lease.next_probe_at = lease.ttl.and_then(|ttl| {
                            lease
                                .created_at
                                .checked_add(ttl)
                                .zip(last_read.checked_add(SETTLEMENT_RECHECK))
                                .map(|(deadline, coalesce_deadline)| {
                                    deadline.max(coalesce_deadline)
                                })
                        });
                    }
                }
            }
            continue;
        }

        metrics.fallback_reads.fetch_add(1, Ordering::Relaxed);
        let started = std::time::Instant::now();
        let result = manager.get_task(&task_id);
        metrics.observation_latency_micros.fetch_add(
            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
        if let Ok(mut last_read_at) = binding.last_read_at.lock() {
            *last_read_at = Some(std::time::Instant::now());
        }
        let Some(state_owner) = state.upgrade() else {
            return;
        };
        match result {
            Ok(task) => {
                if binding.observe(task.clone()).is_err() {
                    manager.shutdown();
                    return;
                }
                let now = std::time::Instant::now();
                let signal_generation = binding.signal.generation();
                let terminal = task.status().is_terminal();
                if terminal {
                    binding
                        .signal
                        .settlement_pending
                        .store(false, Ordering::Release);
                }
                let Ok(mut state) = state_owner.lock() else {
                    manager.shutdown();
                    return;
                };
                if let Some(lease) = state.leases.get_mut(&task_id) {
                    if signal_generation == generation {
                        lease.observed_signal_generation = signal_generation;
                    }
                    if terminal {
                        lease.next_probe_at = lease.ttl.and_then(|ttl| now.checked_add(ttl));
                    } else if binding.signal.is_settlement_pending() {
                        lease.next_probe_at = now.checked_add(SETTLEMENT_RECHECK);
                    } else {
                        lease.next_probe_at =
                            lease.ttl.and_then(|ttl| lease.created_at.checked_add(ttl));
                    }
                }
                drop(state);
                binding.observation_done.notify_waiters();
            }
            Err(_) => {
                let Ok(mut state) = state_owner.lock() else {
                    manager.shutdown();
                    return;
                };
                state.bindings.remove(&task_id);
                state.leases.remove(&task_id);
                drop(state);
                binding.hint();
            }
        }
    }
}

#[cfg(test)]
mod tests;
