//! # OS Process Management
//!
//! Primitives for managing process groups, process-tree signalling, scheduling
//! (nice), and I/O priority.
//!
//! ## Ownership
//! This module owns the platform-specific syscall wrappers used by MCP services
//! that launch subprocess-backed operations. It centralizes process-group setup,
//! bounded signal targeting, process liveness probes, and scheduling controls.
//!
//! ## Non-ownership
//! This module does not decide which process a caller is authorized to control,
//! does not own operation/task state, and does not wait or reap child handles.
//!
//! ## Policy & Guarantees
//! * **Resource Governance**: Process groups allow coordinated control of child
//!   trees rather than only their root process.
//! * **Fail-closed Signal Targets**: Mutating signals reject pid 0, pid 1, and
//!   values that cannot be represented safely by the underlying Unix syscall.
//! * **Race-tolerant Fallback**: Callers may signal a process group first and
//!   fall back to the root process only when the group no longer exists.
//! * **Platform Isolation**: Unsupported operating systems return typed errors.
//!
//! ## Caller Responsibility
//! Callers are responsible for binding PIDs/PGIDs to authorized operation
//! handles and for waiting/reaping child processes after termination.

use std::fmt;

/// Errors arising from process group management operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessGroupError {
    UnsupportedPlatform,
    InvalidPid { pid: u32 },
    SyscallFailed { name: &'static str, code: i32 },
}

impl ProcessGroupError {
    /// Returns true when the underlying operating system reports that the
    /// process or process group no longer exists.
    pub fn is_process_missing(&self) -> bool {
        #[cfg(unix)]
        {
            matches!(self, Self::SyscallFailed { code, .. } if *code == libc::ESRCH)
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

impl fmt::Display for ProcessGroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessGroupError::UnsupportedPlatform => {
                write!(f, "process groups are not supported on this platform")
            }
            ProcessGroupError::InvalidPid { pid } => {
                write!(f, "refusing to signal special process id {pid}")
            }
            ProcessGroupError::SyscallFailed { name, code } => {
                write!(f, "{name} failed with errno {code}")
            }
        }
    }
}

impl std::error::Error for ProcessGroupError {}

/// Portable intent for signals used by subprocess-backed MCP operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessSignal {
    Terminate,
    Kill,
    Stop,
    Continue,
}

impl ProcessSignal {
    #[cfg(unix)]
    const fn raw(self) -> i32 {
        match self {
            Self::Terminate => libc::SIGTERM,
            Self::Kill => libc::SIGKILL,
            Self::Stop => libc::SIGSTOP,
            Self::Continue => libc::SIGCONT,
        }
    }

    const fn process_syscall_name(self) -> &'static str {
        match self {
            Self::Terminate => "kill(SIGTERM pid)",
            Self::Kill => "kill(SIGKILL pid)",
            Self::Stop => "kill(SIGSTOP pid)",
            Self::Continue => "kill(SIGCONT pid)",
        }
    }

    const fn process_group_syscall_name(self) -> &'static str {
        match self {
            Self::Terminate => "kill(SIGTERM pgid)",
            Self::Kill => "kill(SIGKILL pgid)",
            Self::Stop => "kill(SIGSTOP pgid)",
            Self::Continue => "kill(SIGCONT pgid)",
        }
    }
}

/// Describes where a group-first signal was ultimately delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessSignalDelivery {
    ProcessGroup,
    Process,
    AlreadyExited,
}

/// Errors arising from process scheduling operations (niceness/I/O priority).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessSchedulingError {
    UnsupportedPlatform,
    InvalidValue { name: &'static str, value: i64 },
    SyscallFailed { name: &'static str, code: i32 },
}

impl fmt::Display for ProcessSchedulingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessSchedulingError::UnsupportedPlatform => {
                write!(f, "process scheduling is not supported on this platform")
            }
            ProcessSchedulingError::InvalidValue { name, value } => {
                write!(f, "{name} has invalid value {value}")
            }
            ProcessSchedulingError::SyscallFailed { name, code } => {
                write!(f, "{name} failed with errno {code}")
            }
        }
    }
}

impl std::error::Error for ProcessSchedulingError {}

/// Configures a `std::process::Command` so its child becomes the leader of a
/// fresh process group when spawned.
///
/// Tokio callers can pass `tokio::process::Command::as_std_mut()`.
#[cfg(unix)]
pub fn configure_child_process_group(
    command: &mut std::process::Command,
) -> Result<(), ProcessGroupError> {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
    Ok(())
}

#[cfg(not(unix))]
pub fn configure_child_process_group(
    _command: &mut std::process::Command,
) -> Result<(), ProcessGroupError> {
    Err(ProcessGroupError::UnsupportedPlatform)
}

/// Sets the PGID of a running process to match its PID (Unix-only).
#[cfg(unix)]
pub fn set_process_group(pid: u32) -> Result<(), ProcessGroupError> {
    validate_mutating_pid(pid)?;
    let pgid = pid as i32;
    let rc = unsafe { libc::setpgid(pgid, pgid) };
    if rc != 0 {
        return Err(ProcessGroupError::SyscallFailed {
            name: "setpgid",
            code: errno_code(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn set_process_group(_pid: u32) -> Result<(), ProcessGroupError> {
    Err(ProcessGroupError::UnsupportedPlatform)
}

/// Checks whether a process currently exists without sending a mutating signal.
#[cfg(unix)]
pub fn process_exists(pid: u32) -> Result<bool, ProcessGroupError> {
    validate_probe_pid(pid)?;
    let rc = unsafe { libc::kill(pid as i32, 0) };
    if rc == 0 {
        return Ok(true);
    }
    let code = errno_code();
    if code == libc::EPERM {
        return Ok(true);
    }
    if code == libc::ESRCH {
        return Ok(false);
    }
    Err(ProcessGroupError::SyscallFailed {
        name: "kill(pid, 0)",
        code,
    })
}

#[cfg(not(unix))]
pub fn process_exists(_pid: u32) -> Result<bool, ProcessGroupError> {
    Err(ProcessGroupError::UnsupportedPlatform)
}

/// Sends one typed signal to an individual process.
#[cfg(unix)]
pub fn signal_process(pid: u32, signal: ProcessSignal) -> Result<(), ProcessGroupError> {
    validate_mutating_pid(pid)?;
    signal_raw(pid as i32, signal.raw(), signal.process_syscall_name())
}

#[cfg(not(unix))]
pub fn signal_process(_pid: u32, _signal: ProcessSignal) -> Result<(), ProcessGroupError> {
    Err(ProcessGroupError::UnsupportedPlatform)
}

/// Sends one typed signal to a process group whose PGID equals the supplied
/// root PID.
#[cfg(unix)]
pub fn signal_process_group(pid: u32, signal: ProcessSignal) -> Result<(), ProcessGroupError> {
    validate_mutating_pid(pid)?;
    signal_raw(
        -(pid as i32),
        signal.raw(),
        signal.process_group_syscall_name(),
    )
}

#[cfg(not(unix))]
pub fn signal_process_group(_pid: u32, _signal: ProcessSignal) -> Result<(), ProcessGroupError> {
    Err(ProcessGroupError::UnsupportedPlatform)
}

/// Signals a process group first, then falls back to the root process only when
/// the group is already absent. If both are absent, the operation is treated as
/// idempotently complete.
pub fn signal_process_group_or_process(
    pid: u32,
    signal: ProcessSignal,
) -> Result<ProcessSignalDelivery, ProcessGroupError> {
    match signal_process_group(pid, signal) {
        Ok(()) => Ok(ProcessSignalDelivery::ProcessGroup),
        Err(error) if error.is_process_missing() => match signal_process(pid, signal) {
            Ok(()) => Ok(ProcessSignalDelivery::Process),
            Err(error) if error.is_process_missing() => Ok(ProcessSignalDelivery::AlreadyExited),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

/// Sends SIGTERM to a process group identified by the PGID.
pub fn terminate_process_group(pid: u32) -> Result<(), ProcessGroupError> {
    signal_process_group(pid, ProcessSignal::Terminate)
}

/// Sends SIGKILL to a process group identified by the PGID.
pub fn kill_process_group(pid: u32) -> Result<(), ProcessGroupError> {
    signal_process_group(pid, ProcessSignal::Kill)
}

/// Sends SIGSTOP to a process group identified by the PGID.
pub fn stop_process_group(pid: u32) -> Result<(), ProcessGroupError> {
    signal_process_group(pid, ProcessSignal::Stop)
}

/// Sends SIGCONT to a process group identified by the PGID.
pub fn continue_process_group(pid: u32) -> Result<(), ProcessGroupError> {
    signal_process_group(pid, ProcessSignal::Continue)
}

/// Sends SIGTERM to one process.
pub fn terminate_process(pid: u32) -> Result<(), ProcessGroupError> {
    signal_process(pid, ProcessSignal::Terminate)
}

/// Sends SIGKILL to one process.
pub fn kill_process(pid: u32) -> Result<(), ProcessGroupError> {
    signal_process(pid, ProcessSignal::Kill)
}

/// Sends SIGSTOP to one process.
pub fn stop_process(pid: u32) -> Result<(), ProcessGroupError> {
    signal_process(pid, ProcessSignal::Stop)
}

/// Sends SIGCONT to one process.
pub fn continue_process(pid: u32) -> Result<(), ProcessGroupError> {
    signal_process(pid, ProcessSignal::Continue)
}

/// Sets process niceness value (Unix-only).
#[cfg(unix)]
pub fn set_process_niceness(pid: u32, niceness: i32) -> Result<(), ProcessSchedulingError> {
    if !(-20..=19).contains(&niceness) {
        return Err(ProcessSchedulingError::InvalidValue {
            name: "niceness",
            value: niceness as i64,
        });
    }
    let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid, niceness) };
    if rc != 0 {
        return Err(ProcessSchedulingError::SyscallFailed {
            name: "setpriority",
            code: errno_code(),
        });
    }
    Ok(())
}

/// Sets process-group niceness (Unix-only).
#[cfg(unix)]
pub fn set_process_group_niceness(pgid: u32, niceness: i32) -> Result<(), ProcessSchedulingError> {
    if !(-20..=19).contains(&niceness) {
        return Err(ProcessSchedulingError::InvalidValue {
            name: "niceness",
            value: niceness as i64,
        });
    }
    let rc = unsafe { libc::setpriority(libc::PRIO_PGRP, pgid, niceness) };
    if rc != 0 {
        return Err(ProcessSchedulingError::SyscallFailed {
            name: "setpriority(PRIO_PGRP)",
            code: errno_code(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn set_process_group_niceness(
    _pgid: u32,
    _niceness: i32,
) -> Result<(), ProcessSchedulingError> {
    Err(ProcessSchedulingError::UnsupportedPlatform)
}

#[cfg(not(unix))]
pub fn set_process_niceness(_pid: u32, _niceness: i32) -> Result<(), ProcessSchedulingError> {
    Err(ProcessSchedulingError::UnsupportedPlatform)
}

/// Sets process I/O priority (Linux-only).
#[cfg(target_os = "linux")]
pub fn set_process_ionice(pid: u32, class: u8, level: u8) -> Result<(), ProcessSchedulingError> {
    if !(1..=3).contains(&class) {
        return Err(ProcessSchedulingError::InvalidValue {
            name: "ionice_class",
            value: class as i64,
        });
    }
    if level > 7 {
        return Err(ProcessSchedulingError::InvalidValue {
            name: "ionice_level",
            value: level as i64,
        });
    }
    let ioprio = ((class as i32) << 13) | (level as i32 & 0xff);
    let rc = unsafe { libc::syscall(libc::SYS_ioprio_set, 1, pid as i32, ioprio) };
    if rc != 0 {
        return Err(ProcessSchedulingError::SyscallFailed {
            name: "ioprio_set",
            code: errno_code(),
        });
    }
    Ok(())
}

/// Sets process-group I/O priority (Linux-only).
#[cfg(target_os = "linux")]
pub fn set_process_group_ionice(
    pgid: u32,
    class: u8,
    level: u8,
) -> Result<(), ProcessSchedulingError> {
    if !(1..=3).contains(&class) {
        return Err(ProcessSchedulingError::InvalidValue {
            name: "ionice_class",
            value: class as i64,
        });
    }
    if level > 7 {
        return Err(ProcessSchedulingError::InvalidValue {
            name: "ionice_level",
            value: level as i64,
        });
    }
    let ioprio = ((class as i32) << 13) | (level as i32 & 0xff);
    let rc = unsafe { libc::syscall(libc::SYS_ioprio_set, 2, pgid as i32, ioprio) };
    if rc != 0 {
        return Err(ProcessSchedulingError::SyscallFailed {
            name: "ioprio_set(IOPRIO_WHO_PGRP)",
            code: errno_code(),
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_process_group_ionice(
    _pgid: u32,
    _class: u8,
    _level: u8,
) -> Result<(), ProcessSchedulingError> {
    Err(ProcessSchedulingError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub fn set_process_ionice(_pid: u32, _class: u8, _level: u8) -> Result<(), ProcessSchedulingError> {
    Err(ProcessSchedulingError::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_mutating_pid(pid: u32) -> Result<(), ProcessGroupError> {
    if pid <= 1 || pid > i32::MAX as u32 {
        Err(ProcessGroupError::InvalidPid { pid })
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn validate_probe_pid(pid: u32) -> Result<(), ProcessGroupError> {
    if pid == 0 || pid > i32::MAX as u32 {
        Err(ProcessGroupError::InvalidPid { pid })
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn signal_raw(target: i32, signal: i32, name: &'static str) -> Result<(), ProcessGroupError> {
    let rc = unsafe { libc::kill(target, signal) };
    if rc != 0 {
        return Err(ProcessGroupError::SyscallFailed {
            name,
            code: errno_code(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn errno_code() -> i32 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        *libc::__errno_location()
    }
    #[cfg(target_os = "macos")]
    unsafe {
        *libc::__error()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        libc::EINVAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn process_group_niceness_rejects_out_of_range() {
        let err = set_process_group_niceness(1, 25).unwrap_err();
        assert_eq!(
            err,
            ProcessSchedulingError::InvalidValue {
                name: "niceness",
                value: 25
            }
        );
    }

    #[test]
    #[cfg(unix)]
    fn process_signaling_rejects_special_pids() {
        assert_eq!(
            terminate_process_group(0).unwrap_err(),
            ProcessGroupError::InvalidPid { pid: 0 }
        );
        assert_eq!(
            kill_process_group(1).unwrap_err(),
            ProcessGroupError::InvalidPid { pid: 1 }
        );
        assert_eq!(
            stop_process(1).unwrap_err(),
            ProcessGroupError::InvalidPid { pid: 1 }
        );
        assert_eq!(
            kill_process(i32::MAX as u32 + 1).unwrap_err(),
            ProcessGroupError::InvalidPid {
                pid: i32::MAX as u32 + 1
            }
        );
    }

    #[test]
    #[cfg(unix)]
    fn process_exists_observes_current_process() {
        assert_eq!(process_exists(std::process::id()), Ok(true));
    }

    #[test]
    #[cfg(unix)]
    fn configure_child_process_group_is_supported() {
        let mut command = std::process::Command::new("true");
        assert_eq!(configure_child_process_group(&mut command), Ok(()));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_group_ionice_rejects_out_of_range() {
        let err = set_process_group_ionice(1, 0, 0).unwrap_err();
        assert_eq!(
            err,
            ProcessSchedulingError::InvalidValue {
                name: "ionice_class",
                value: 0
            }
        );
        let err = set_process_group_ionice(1, 2, 9).unwrap_err();
        assert_eq!(
            err,
            ProcessSchedulingError::InvalidValue {
                name: "ionice_level",
                value: 9
            }
        );
    }
}
