//! Bounded output capture over the existing process supervisor.
//!
//! This module bounds retained bytes and the time spent awaiting output. It is
//! not a sandbox or a whole-tree termination guarantee. The manager stops owning
//! the process group when the root is reaped (including during TERM grace).
//! Descendants can outlive that root and retain its pipes. In that case capture
//! closes its readers after an explicit EOF deadline, without signaling a stale
//! PID/PGID. Keep the Tokio runtime alive for manager-owned cleanup to progress.

use std::{ffi::OsString, fmt, path::Path, process::ExitStatus, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    time::Instant,
};

use crate::supervisor::{ProcessId, ProcessManager, ProcessStatus};

/// Specifies a literal executable and arguments, never a shell command string.
///
/// Environment inheritance is disabled. Callers must authorize the executable,
/// arguments and explicit environment; invoking a shell explicitly is still
/// possible and is not made safe by this type. Debug output omits all values.
#[derive(Clone)]
pub struct CaptureCommand {
    executable: OsString,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
}

impl CaptureCommand {
    /// Selects an absolute executable path without PATH lookup.
    ///
    /// # Errors
    /// Returns `InvalidExecutable` for a relative path.
    ///
    /// # Security
    /// An absolute path is not an authorization or integrity check.
    pub fn new(executable: impl Into<OsString>) -> Result<Self, CaptureError> {
        let executable = executable.into();
        if !Path::new(&executable).is_absolute() {
            return Err(CaptureError::InvalidExecutable);
        }
        Ok(Self {
            executable,
            args: Vec::new(),
            env: Vec::new(),
        })
    }

    /// Appends one literal argument, preserving non-UTF8 OS strings.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Sets an explicit child environment entry; no parent entries are inherited.
    ///
    /// # Security
    /// Environment entries can alter executable behavior. Only supply authorized
    /// entries, and do not log their values.
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }
}

impl fmt::Debug for CaptureCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CaptureCommand { values: [REDACTED] }")
    }
}

/// Sets independent byte caps and deadlines; zero-byte caps are supported.
#[derive(Clone, Copy, Debug)]
pub struct CaptureLimits {
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    /// Cooperative total capture budget including spawn; cleanup may continue later.
    /// Synchronous OS spawn and registry locking cannot be preempted.
    pub timeout: Duration,
    /// Maximum pipe-drain time after observing root exit. Zero permits no
    /// further drain unless both EOFs have already been observed.
    pub eof_timeout: Duration,
}

/// Identifies why capture stopped, independently of the root's exit code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureEnd {
    /// Root reaped and both streams reached EOF without exceeding their caps.
    Complete,
    Timeout,
    OutputLimitExceeded,
    ReadFailed,
    /// Root exited, but at least one stream did not reach EOF in time.
    IncompleteCapture,
    SupervisorUnavailable,
}

/// Returns retained bytes and root-exit evidence without logging output.
///
/// `exit_status: None` means cleanup may still be pending in the manager.
/// Even `Some` proves only root reaping, not descendant termination. Nonzero
/// exit codes are ordinary captured results, not library errors.
pub struct CapturedOutput {
    pub process_id: ProcessId,
    pub end: CaptureEnd,
    pub exit_status: Option<ExitStatus>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl fmt::Debug for CapturedOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedOutput")
            .field("process_id", &self.process_id)
            .field("end", &self.end)
            .field("exit_status", &self.exit_status)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .finish()
    }
}

/// Reports fixed, non-secret diagnostics; underlying OS messages are not retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureError {
    InvalidExecutable,
    InvalidDeadline,
    SpawnFailed,
    MissingPipe,
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidExecutable => "capture requires an absolute executable path",
            Self::InvalidDeadline => "capture deadline is out of range",
            Self::SpawnFailed => "capture could not start a supervised process",
            Self::MissingPipe => "capture pipe is unavailable",
        })
    }
}

impl std::error::Error for CaptureError {}

/// Captures stdout and stderr concurrently with bounded retained buffers.
///
/// Stdin is null. A cap is exceeded only when an additional byte is observed;
/// exactly-cap output can succeed. Timeout, read failure and overflow close the
/// readers and request manager cleanup without waiting indefinitely for reaping.
/// Dropping this future also drops its process handle and requests cleanup.
/// No detached reader tasks are created. Root exit starts a separate EOF deadline.
///
/// # Errors
/// Returns fixed diagnostics for a zero total timeout, out-of-range deadlines,
/// spawn/setup/runtime failure, or missing pipes.
///
/// # Panics
/// Tokio timers panic if the runtime has no time driver. Enable runtime time
/// support before calling; the process handle still requests cleanup on unwind.
///
/// # Security
/// Output may contain secrets; inspect it explicitly and do not log it blindly.
/// Limits bound retained stream bytes, not child memory, CPU, descendant lifetime,
/// or exact allocator overhead. This function does not authorize execution.
///
/// ```no_run
/// # async fn example() -> Result<(), mcp_toolkit_process::capture::CaptureError> {
/// use std::time::Duration;
/// use mcp_toolkit_process::{capture::*, supervisor::*};
/// let manager = ProcessManager::new(Duration::from_millis(100), ProcessGroupPolicy::Required);
/// let result = capture(&manager, CaptureCommand::new("/usr/bin/printf")?.arg("hello"),
///     CaptureLimits { stdout_bytes: 1024, stderr_bytes: 1024,
///         timeout: Duration::from_secs(5), eof_timeout: Duration::from_millis(100) }).await?;
/// assert_eq!(result.end, CaptureEnd::Complete);
/// # Ok(()) }
/// ```
pub async fn capture(
    manager: &ProcessManager,
    command: CaptureCommand,
    limits: CaptureLimits,
) -> Result<CapturedOutput, CaptureError> {
    if limits.timeout.is_zero() {
        return Err(CaptureError::InvalidDeadline);
    }
    let now = Instant::now();
    let deadline = now
        .checked_add(limits.timeout)
        .ok_or(CaptureError::InvalidDeadline)?;
    // Validate before creating a child. The post-exit deadline is checked again.
    now.checked_add(limits.eof_timeout)
        .ok_or(CaptureError::InvalidDeadline)?;
    let mut cmd = Command::new(command.executable);
    cmd.args(command.args)
        .env_clear()
        .envs(command.env)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut process = manager.spawn(cmd).map_err(|_| CaptureError::SpawnFailed)?;
    let stdout = process.stdout.take().ok_or(CaptureError::MissingPipe)?;
    let stderr = process.stderr.take().ok_or(CaptureError::MissingPipe)?;
    let mut output = CapturedOutput {
        process_id: process.id(),
        end: CaptureEnd::Complete,
        exit_status: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    {
        // try_join rotates polling order between the streams, avoiding a biased
        // stdout-first loop starving stderr while stdout stays readable.
        let reads = async {
            tokio::try_join!(
                read_bounded(stdout, &mut output.stdout, limits.stdout_bytes),
                read_bounded(stderr, &mut output.stderr, limits.stderr_bytes),
            )
        };
        tokio::pin!(reads);
        let mut streams_done = false;
        let mut eof_deadline = deadline;
        loop {
            if output.exit_status.is_none() {
                if let ProcessStatus::Exited { status, .. } = process.status() {
                    output.exit_status = Some(status);
                    eof_deadline = Instant::now()
                        .checked_add(limits.eof_timeout)
                        .unwrap_or(deadline)
                        .min(deadline);
                }
            }
            if output.exit_status.is_some() && streams_done {
                break;
            }
            tokio::select! {
                // Deadlines take priority even when a pipe is continuously ready.
                biased;
                _ = tokio::time::sleep_until(deadline) => {
                    output.end = CaptureEnd::Timeout;
                    break;
                }
                _ = tokio::time::sleep_until(eof_deadline), if output.exit_status.is_some() => {
                    output.end = CaptureEnd::IncompleteCapture;
                    break;
                }
                changed = process.changed(), if output.exit_status.is_none() => {
                    if changed.is_none() {
                        output.end = CaptureEnd::SupervisorUnavailable;
                        break;
                    }
                }
                result = &mut reads, if !streams_done => {
                    streams_done = true;
                    if let Err(end) = result {
                        output.end = end;
                        break;
                    }
                }
            }
        }
    }
    if let ProcessStatus::Exited { status, .. } = process.status() {
        output.exit_status = Some(status);
    }
    // Dropping the handle requests cleanup. Only the manager owns signaling.
    Ok(output)
}

async fn read_bounded(
    mut reader: impl AsyncRead + Unpin,
    bytes: &mut Vec<u8>,
    limit: usize,
) -> Result<(), CaptureEnd> {
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|_| CaptureEnd::ReadFailed)?;
        if count == 0 {
            return Ok(());
        }
        let remaining = limit - bytes.len();
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
        if count > remaining {
            return Err(CaptureEnd::OutputLimitExceeded);
        }
        // Keep timers and the other stream responsive even for a reader that
        // always returns Ready without Tokio's cooperative I/O budget.
        tokio::task::yield_now().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::supervisor::ProcessGroupPolicy;

    #[cfg(unix)]
    fn limits(bytes: usize) -> CaptureLimits {
        CaptureLimits {
            stdout_bytes: bytes,
            stderr_bytes: bytes,
            timeout: Duration::from_secs(3),
            eof_timeout: Duration::from_millis(50),
        }
    }

    #[cfg(unix)]
    fn manager() -> ProcessManager {
        ProcessManager::new(Duration::from_millis(10), ProcessGroupPolicy::Required)
    }

    #[tokio::test]
    async fn strict_raw_byte_boundaries_include_zero_and_binary() {
        for (input, cap, expected) in [
            (&b""[..], 0, Ok(())),
            (&b"a"[..], 0, Err(CaptureEnd::OutputLimitExceeded)),
            (&b"\xff\x00"[..], 2, Ok(())),
            (&b"\xff\x00z"[..], 2, Err(CaptureEnd::OutputLimitExceeded)),
        ] {
            let mut output = Vec::new();
            assert_eq!(read_bounded(input, &mut output, cap).await, expected);
            assert_eq!(output, input[..input.len().min(cap)]);
        }
    }

    #[tokio::test]
    async fn read_errors_are_fixed_and_do_not_retain_messages() {
        struct Broken;
        impl AsyncRead for Broken {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::Error::other("synthetic-secret")))
            }
        }
        let error = read_bounded(Broken, &mut Vec::new(), 1)
            .await
            .unwrap_err();
        assert_eq!(error, CaptureEnd::ReadFailed);
        assert!(!format!("{error:?}").contains("synthetic-secret"));
    }

    #[test]
    fn debug_never_contains_command_or_environment_secrets() {
        let command = CaptureCommand::new("/synthetic-secret-executable")
            .unwrap()
            .arg("synthetic-secret-argument")
            .env("synthetic-secret-key", "synthetic-secret-value");
        assert!(!format!("{command:?}").contains("synthetic-secret"));
        assert_eq!(
            CaptureCommand::new("relative").unwrap_err(),
            CaptureError::InvalidExecutable
        );
    }

    #[cfg(unix)]
    fn shell(script: &str) -> CaptureCommand {
        CaptureCommand::new("/bin/sh")
            .unwrap()
            .arg("-c")
            .arg(script)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn drains_concurrent_floods_without_pipe_deadlock() {
        let output = capture(
            &manager(),
            shell("head -c 131072 /dev/zero & head -c 131072 /dev/zero >&2 & wait"),
            limits(131072),
        )
        .await
        .unwrap();
        assert_eq!(output.end, CaptureEnd::Complete);
        assert!(output.exit_status.unwrap().success());
        assert_eq!(output.stdout.len(), 131072);
        assert_eq!(output.stderr.len(), 131072);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn overflow_requests_cleanup_and_retains_only_cap() {
        let manager = manager();
        let output = capture(
            &manager,
            shell("while :; do printf '0123456789'; done"),
            limits(11),
        )
        .await
        .unwrap();
        assert_eq!(output.end, CaptureEnd::OutputLimitExceeded);
        assert_eq!(output.stdout.len(), 11);
        wait_for_retirement(&manager, output.process_id).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_requests_cleanup_even_when_pipes_closed() {
        let manager = manager();
        let mut bounds = limits(10);
        bounds.timeout = Duration::from_millis(50);
        let output = capture(&manager, shell("exec 1>&- 2>&-; exec sleep 10"), bounds)
            .await
            .unwrap();
        assert_eq!(output.end, CaptureEnd::Timeout);
        wait_for_retirement(&manager, output.process_id).await;
    }

    #[tokio::test]
    async fn hot_reader_does_not_starve_deadlines() {
        let mut bytes = Vec::new();
        let result = tokio::time::timeout(
            Duration::from_millis(1),
            read_bounded(tokio::io::repeat(0), &mut bytes, usize::MAX),
        )
        .await;
        assert!(result.is_err());
        assert!(!bytes.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_capture_future_requests_manager_cleanup() {
        let manager = manager();
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("root.pid");
        let command = shell("printf '%s' \"$$\" > \"$1\"; exec sleep 10")
            .arg("fixture")
            .arg(pid_file.as_os_str());
        let mut future = Box::pin(capture(&manager, command, limits(10)));
        let ready = async {
            loop {
                if let Ok(pid) = std::fs::read_to_string(&pid_file) {
                    if let Ok(pid) = pid.parse::<u32>() {
                        break pid;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        let pid = tokio::select! {
            result = &mut future => panic!("capture ended before cancellation: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(2), ready) => result.unwrap(),
        };
        drop(future);
        // Read-only liveness checks avoid making shutdown the cancellation
        // mechanism. The supervisor must reap this direct child after drop.
        tokio::time::timeout(Duration::from_secs(3), async {
            while crate::process_exists(pid).unwrap() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(manager.shutdown().pending.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn descendant_held_pipes_are_explicitly_incomplete() {
        // Finite fixture: the descendant exits on its own, without any stale-PID
        // cleanup. Capture must return before that EOF rather than claim success.
        let output = capture(&manager(), shell("sleep 1 & exit 0"), limits(10))
            .await
            .unwrap();
        assert_eq!(output.end, CaptureEnd::IncompleteCapture);
        assert!(output.exit_status.unwrap().success());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn literal_non_utf8_args_and_explicit_environment() {
        use std::os::unix::ffi::OsStringExt;
        let command = shell("printf '%s' \"$1\"; printf '%s' \"${CAPTURE_TEST_VALUE-unset}\" >&2")
            .arg("fixture")
            .arg(OsString::from_vec(vec![0xff, b';', b'$']))
            .env("CAPTURE_TEST_VALUE", "synthetic-secret-value");
        let output = capture(&manager(), command, limits(100)).await.unwrap();
        assert_eq!(output.end, CaptureEnd::Complete);
        assert_eq!(output.stdout, [0xff, b';', b'$']);
        assert_eq!(output.stderr, b"synthetic-secret-value");
        assert!(!format!("{output:?}").contains("synthetic-secret"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn null_stdin_and_cleared_environment() {
        // Cargo supplies CARGO_MANIFEST_DIR to this test; it must not be inherited.
        assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
        let output = capture(
            &manager(),
            shell("if read value; then exit 8; fi; printf '%s' \"${CARGO_MANIFEST_DIR-unset}\""),
            limits(100),
        )
        .await
        .unwrap();
        assert_eq!(output.end, CaptureEnd::Complete);
        assert!(output.exit_status.unwrap().success());
        assert_eq!(output.stdout, b"unset");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn spawn_errors_do_not_retain_secret_diagnostics() {
        let command = CaptureCommand::new("/nonexistent/synthetic-secret")
            .unwrap()
            .arg("synthetic-secret");
        let error = capture(&manager(), command, limits(1))
            .await
            .unwrap_err();
        assert_eq!(error, CaptureError::SpawnFailed);
        assert!(!format!("{error} {error:?}").contains("synthetic-secret"));
        assert!(std::error::Error::source(&error).is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn zero_budget_is_rejected_before_spawn() {
        let mut bounds = limits(1);
        bounds.timeout = Duration::ZERO;
        let error = capture(&manager(), shell("exit 0"), bounds)
            .await
            .unwrap_err();
        assert_eq!(error, CaptureError::InvalidDeadline);
    }

    #[cfg(unix)]
    async fn wait_for_retirement(manager: &ProcessManager, id: ProcessId) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while manager.status(id).is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("manager should reap the root");
    }
}
