//! Manager-owned Tokio child supervision.
//!
//! The manager retains every supervisor task and child until `Child::wait`
//! reports an exit. Public handles only observe status and request cleanup.

use std::{
    collections::BTreeMap,
    fmt, io,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use tokio::{
    process::{Child, ChildStderr, ChildStdout, Command},
    sync::watch,
    task::JoinHandle,
    time::timeout,
};

use crate::{
    configure_child_process_group, signal_process, signal_process_group, ProcessGroupError,
    ProcessSignal,
};

/// Selects the required process signal scope before a child is spawned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProcessGroupPolicy {
    /// Require a fresh process group and fail before spawning if unavailable.
    #[default]
    Required,
    /// Explicitly permit direct-child signaling when group setup is unsupported.
    AllowDirectChildFallback,
}

/// Identifies the effective target used for supervisor signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalScope {
    ProcessGroup,
    DirectChild,
}

/// Identifies one manager-owned child supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessId(u64);

impl ProcessId {
    /// Returns the stable identifier assigned by its process manager.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Records a signal error without treating signal delivery as exit evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalFailure {
    pub signal: ProcessSignal,
    pub scope: SignalScope,
    pub error: ProcessGroupError,
}

/// Records a `Child::wait` failure separately from signal delivery failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitFailure {
    pub scope: SignalScope,
    pub kind: io::ErrorKind,
    pub code: Option<i32>,
    pub message: String,
}

/// Identifies whether cleanup failed during signal delivery or child waiting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessFailure {
    Signal(SignalFailure),
    Wait(WaitFailure),
}

/// Describes the observed lifecycle state of a supervised child.
#[derive(Clone, Debug)]
pub enum ProcessStatus {
    Running {
        id: ProcessId,
        scope: SignalScope,
    },
    PendingCleanup {
        id: ProcessId,
        scope: SignalScope,
        failures: Vec<ProcessFailure>,
    },
    Exited {
        id: ProcessId,
        scope: SignalScope,
        status: std::process::ExitStatus,
        failures: Vec<ProcessFailure>,
    },
}

impl ProcessStatus {
    /// Returns the manager-assigned process identifier.
    pub fn id(&self) -> ProcessId {
        match self {
            Self::Running { id, .. }
            | Self::PendingCleanup { id, .. }
            | Self::Exited { id, .. } => *id,
        }
    }

    /// Returns true only when `Child::wait` supplied terminal status.
    pub fn is_exited(&self) -> bool {
        matches!(self, Self::Exited { .. })
    }
}

/// Reports failures that prevent a process from being spawned.
#[derive(Debug)]
pub enum ProcessManagerError {
    /// Compile-time group setup is unsupported or rejected before spawning.
    GroupSetup(ProcessGroupError),
    /// Preserves the OS spawn error, including Unix pre-exec process-group
    /// setup denial. The command is never retried without its configured group.
    Spawn(io::Error),
    RuntimeUnavailable,
}

impl fmt::Display for ProcessManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GroupSetup(error) => write!(f, "process group setup failed: {error}"),
            Self::Spawn(error) => write!(f, "child process spawn failed: {error}"),
            Self::RuntimeUnavailable => {
                write!(f, "a Tokio runtime is required to supervise children")
            }
        }
    }
}

impl std::error::Error for ProcessManagerError {}

struct Entry {
    cancel: watch::Sender<bool>,
    status: watch::Receiver<ProcessStatus>,
    _supervisor: JoinHandle<()>,
}

struct Inner {
    entries: Mutex<BTreeMap<ProcessId, Entry>>,
    next_id: AtomicU64,
}

/// Owns child supervisors independently of public handle and future lifetimes.
#[derive(Clone)]
pub struct ProcessManager {
    inner: Arc<Inner>,
    grace: Duration,
    policy: ProcessGroupPolicy,
}

impl ProcessManager {
    /// Creates a manager with caller-selected TERM grace and group policy.
    pub fn new(grace: Duration, policy: ProcessGroupPolicy) -> Self {
        Self {
            inner: Arc::new(Inner {
                entries: Mutex::new(BTreeMap::new()),
                next_id: AtomicU64::new(1),
            }),
            grace,
            policy,
        }
    }

    /// Spawns and supervises a command while retaining its child in the manager.
    ///
    /// # Errors
    /// Returns `GroupSetup` for unsupported or rejected setup before spawn,
    /// `Spawn` when the OS refuses to create the configured child (including
    /// Unix pre-exec group denial), or `RuntimeUnavailable` outside Tokio.
    ///
    /// # Security
    /// The caller supplies the command, arguments and environment and remains
    /// responsible for authorization and output handling.
    pub fn spawn(&self, mut command: Command) -> Result<RunningProcess, ProcessManagerError> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| ProcessManagerError::RuntimeUnavailable)?;
        let scope = resolve_scope(
            self.policy,
            configure_child_process_group(command.as_std_mut()),
        )?;
        let mut child = command.spawn().map_err(ProcessManagerError::Spawn)?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let id = ProcessId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        let os_pid = child.id();
        let (cancel, cancel_rx) = watch::channel(false);
        let (status_tx, status_rx) = watch::channel(ProcessStatus::Running { id, scope });
        let grace = self.grace;
        let supervisor = tokio::spawn(supervise(
            child, id, os_pid, scope, grace, cancel_rx, status_tx,
        ));
        let entry = Entry {
            cancel: cancel.clone(),
            status: status_rx.clone(),
            _supervisor: supervisor,
        };
        let mut entries = match self.inner.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };
        entries.insert(id, entry);
        Ok(RunningProcess {
            id,
            cancel,
            status: status_rx,
            stdout,
            stderr,
        })
    }

    /// Requests cleanup for all children and snapshots those not yet reaped.
    ///
    /// This call is intentionally non-blocking. A returned pending status keeps
    /// its supervisor and child in the registry; it is never cleanup completion.
    pub fn shutdown(&self) -> ShutdownReport {
        let entries = match self.inner.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut pending = Vec::new();
        for entry in entries.values() {
            let _ = entry.cancel.send(true);
            let status = entry.status.borrow().clone();
            if !status.is_exited() {
                pending.push(status);
            }
        }
        ShutdownReport { pending }
    }

    /// Returns the latest known status for a registered child.
    pub fn status(&self, id: ProcessId) -> Option<ProcessStatus> {
        self.inner
            .entries
            .lock()
            .ok()?
            .get(&id)
            .map(|entry| entry.status.borrow().clone())
    }
}

/// Observes one child and requests cleanup when dropped.
pub struct RunningProcess {
    id: ProcessId,
    cancel: watch::Sender<bool>,
    status: watch::Receiver<ProcessStatus>,
    /// Caller-owned stdout reader when the command configured piped stdout.
    /// Drain it concurrently while retaining this handle to avoid pipe blockage.
    pub stdout: Option<ChildStdout>,
    /// Caller-owned stderr reader when the command configured piped stderr.
    /// Drain it concurrently while retaining this handle to avoid pipe blockage.
    pub stderr: Option<ChildStderr>,
}

impl RunningProcess {
    /// Returns this process's manager-assigned identifier.
    pub fn id(&self) -> ProcessId {
        self.id
    }

    /// Returns its current observed status.
    pub fn status(&self) -> ProcessStatus {
        self.status.borrow().clone()
    }

    /// Waits until the supervisor publishes a new status.
    ///
    /// # Errors
    /// Returns `None` only if the manager supervisor unexpectedly disappears.
    pub async fn changed(&mut self) -> Option<ProcessStatus> {
        self.status.changed().await.ok()?;
        Some(self.status())
    }

    /// Requests cleanup while retaining the manager-owned child supervisor.
    pub fn cancel(&self) {
        let _ = self.cancel.send(true);
    }
}

impl Drop for RunningProcess {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Captures children that were still pending when graceful shutdown was requested.
#[derive(Clone, Debug)]
pub struct ShutdownReport {
    pub pending: Vec<ProcessStatus>,
}

fn resolve_scope(
    policy: ProcessGroupPolicy,
    setup: Result<(), ProcessGroupError>,
) -> Result<SignalScope, ProcessManagerError> {
    match setup {
        Ok(()) => Ok(SignalScope::ProcessGroup),
        Err(ProcessGroupError::UnsupportedPlatform)
            if policy == ProcessGroupPolicy::AllowDirectChildFallback =>
        {
            Ok(SignalScope::DirectChild)
        }
        Err(error) => Err(ProcessManagerError::GroupSetup(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[cfg(unix)]
    #[tokio::test]
    async fn manager_observes_and_retains_natural_exit() {
        let manager = ProcessManager::new(Duration::from_millis(20), ProcessGroupPolicy::Required);
        let process = manager
            .spawn(Command::new("true"))
            .expect("test process should spawn");
        let id = process.id();
        let mut observer = process;
        let observed = observer
            .changed()
            .await
            .expect("supervisor should remain alive");
        assert!(matches!(observed, ProcessStatus::Exited { id: exited, .. } if exited == id));
        assert!(manager.status(id).is_some_and(|status| status.is_exited()));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_handle_requests_cleanup_and_shutdown_reports_pending() {
        let manager = ProcessManager::new(Duration::from_millis(10), ProcessGroupPolicy::Required);
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 10"]);
        let process = manager.spawn(command).expect("test process should spawn");
        let id = process.id();
        let report = manager.shutdown();
        assert_eq!(report.pending.len(), 1);
        drop(process);

        let mut status = manager.status(id).expect("registry should retain child");
        while !status.is_exited() {
            tokio::time::sleep(Duration::from_millis(20)).await;
            status = manager.status(id).expect("registry should retain child");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn piped_streams_can_be_drained_concurrently_while_handle_is_retained() {
        let manager = ProcessManager::new(Duration::from_millis(20), ProcessGroupPolicy::Required);
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "head -c 131072 /dev/zero; head -c 131072 /dev/zero >&2",
        ]);
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());
        let mut process = manager.spawn(command).expect("test process should spawn");
        let mut stdout = process.stdout.take().expect("stdout should be piped");
        let mut stderr = process.stderr.take().expect("stderr should be piped");
        let stdout_read = async move {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).await.map(|_| bytes.len())
        };
        let stderr_read = async move {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).await.map(|_| bytes.len())
        };
        let (stdout_len, stderr_len) = tokio::join!(stdout_read, stderr_read);
        assert_eq!(stdout_len.expect("stdout read should finish"), 131072);
        assert_eq!(stderr_len.expect("stderr read should finish"), 131072);
        while !process.status().is_exited() {
            assert!(process.changed().await.is_some());
        }
    }

    #[test]
    fn direct_child_fallback_is_only_for_unsupported_platforms() {
        assert!(matches!(
            resolve_scope(
                ProcessGroupPolicy::AllowDirectChildFallback,
                Err(ProcessGroupError::UnsupportedPlatform),
            ),
            Ok(SignalScope::DirectChild)
        ));
        assert!(matches!(
            resolve_scope(
                ProcessGroupPolicy::AllowDirectChildFallback,
                Err(ProcessGroupError::SyscallFailed {
                    name: "setpgid",
                    code: libc::EPERM,
                }),
            ),
            Err(ProcessManagerError::GroupSetup(
                ProcessGroupError::SyscallFailed {
                    code: libc::EPERM,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn wait_and_signal_failures_have_distinct_types() {
        let wait = ProcessFailure::Wait(wait_failure(
            io::Error::other("synthetic wait failure"),
            SignalScope::ProcessGroup,
        ));
        assert!(matches!(wait, ProcessFailure::Wait(WaitFailure { .. })));

        let mut retained = Vec::new();
        record_wait_failure(
            &mut retained,
            io::Error::other("first synthetic wait failure"),
            SignalScope::ProcessGroup,
        );
        record_wait_failure(
            &mut retained,
            io::Error::other("latest synthetic wait failure"),
            SignalScope::ProcessGroup,
        );
        assert!(matches!(
            retained.as_slice(),
            [ProcessFailure::Wait(WaitFailure { message, .. })]
                if message == "latest synthetic wait failure"
        ));

        let mut failures = Vec::new();
        record_signal(
            &mut failures,
            0,
            SignalScope::ProcessGroup,
            ProcessSignal::Terminate,
        );
        let (status, _) = watch::channel(ProcessStatus::Running {
            id: ProcessId(7),
            scope: SignalScope::ProcessGroup,
        });
        publish_pending(ProcessId(7), SignalScope::ProcessGroup, &failures, &status);
        assert!(matches!(
            status.borrow().clone(),
            ProcessStatus::PendingCleanup {
                failures: [ProcessFailure::Signal(_)],
                ..
            }
        ));
    }
}

async fn supervise(
    mut child: Child,
    id: ProcessId,
    os_pid: Option<u32>,
    scope: SignalScope,
    grace: Duration,
    mut cancel: watch::Receiver<bool>,
    status: watch::Sender<ProcessStatus>,
) {
    let mut failures = Vec::new();
    let natural_exit = tokio::select! {
        result = child.wait() => Some(result),
        changed = cancel.changed() => {
            let _ = changed;
            None
        }
    };
    if let Some(result) = natural_exit {
        match result {
            Ok(exit) => {
                let _ = status.send(ProcessStatus::Exited {
                    id,
                    scope,
                    status: exit,
                    failures,
                });
                return;
            }
            Err(error) => {
                record_wait_failure(&mut failures, error, scope);
                publish_pending(id, scope, &failures, &status);
            }
        }
        reap_until_terminal(&mut child, id, scope, failures, &status).await;
        return;
    }

    if let Some(os_pid) = os_pid {
        record_signal(&mut failures, os_pid, scope, ProcessSignal::Terminate);
    }
    publish_pending(id, scope, &failures, &status);
    match timeout(grace, child.wait()).await {
        Ok(Ok(exit)) => {
            let _ = status.send(ProcessStatus::Exited {
                id,
                scope,
                status: exit,
                failures,
            });
            return;
        }
        Ok(Err(error)) => record_wait_failure(&mut failures, error, scope),
        Err(_) => {}
    }

    if let Some(os_pid) = os_pid {
        if scope == SignalScope::DirectChild {
            if let Err(error) = child.start_kill() {
                failures.push(ProcessFailure::Signal(SignalFailure {
                    signal: ProcessSignal::Kill,
                    scope,
                    error: ProcessGroupError::SyscallFailed {
                        name: "Child::start_kill",
                        code: error.raw_os_error().unwrap_or(-1),
                    },
                }));
            }
        } else {
            record_signal(&mut failures, os_pid, scope, ProcessSignal::Kill);
        }
    }
    publish_pending(id, scope, &failures, &status);
    reap_until_terminal(&mut child, id, scope, failures, &status).await;
}

fn wait_failure(error: io::Error, scope: SignalScope) -> WaitFailure {
    WaitFailure {
        scope,
        kind: error.kind(),
        code: error.raw_os_error(),
        message: error.to_string(),
    }
}

fn record_wait_failure(failures: &mut Vec<ProcessFailure>, error: io::Error, scope: SignalScope) {
    failures.retain(|failure| !matches!(failure, ProcessFailure::Wait(_)));
    failures.push(ProcessFailure::Wait(wait_failure(error, scope)));
}

async fn reap_until_terminal(
    child: &mut Child,
    id: ProcessId,
    scope: SignalScope,
    mut failures: Vec<ProcessFailure>,
    status: &watch::Sender<ProcessStatus>,
) {
    loop {
        match child.wait().await {
            Ok(exit) => {
                let _ = status.send(ProcessStatus::Exited {
                    id,
                    scope,
                    status: exit,
                    failures,
                });
                return;
            }
            Err(error) => {
                record_wait_failure(&mut failures, error, scope);
                publish_pending(id, scope, &failures, status);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

fn record_signal(
    failures: &mut Vec<ProcessFailure>,
    os_pid: u32,
    scope: SignalScope,
    signal: ProcessSignal,
) {
    let result = match scope {
        SignalScope::ProcessGroup => signal_process_group(os_pid, signal),
        SignalScope::DirectChild => signal_process(os_pid, signal),
    };
    if let Err(error) = result {
        if !error.is_process_missing() {
            failures.push(ProcessFailure::Signal(SignalFailure {
                signal,
                scope,
                error,
            }));
        }
    }
}

fn publish_pending(
    id: ProcessId,
    scope: SignalScope,
    failures: &[ProcessFailure],
    status: &watch::Sender<ProcessStatus>,
) {
    let _ = status.send(ProcessStatus::PendingCleanup {
        id,
        scope,
        failures: failures.to_vec(),
    });
}
