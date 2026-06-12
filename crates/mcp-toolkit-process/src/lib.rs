//! # OS Process Management
//!
//! Primitives for managing process groups, scheduling (nice), and I/O priority.
//!
//! ## Ownership
//! This module owns the platform-specific (Unix/Linux) syscall wrappers for process
//! group management, enabling coordinated lifecycle control of task trees.
//!
//! ## Non-ownership
//! This module does not manage process lifecycles beyond signaling or scheduling;
//! it strictly exposes functional wrappers for OS-level primitives.
//!
//! ## Policy & Guarantees
//! * **Resource Governance**: Facilitates management of process groups (PGIDs) to
//!   enable batch signaling (e.g., recursive termination) and resource throttling.
//! * **Platform Isolation**: Provides stubs to maintain cross-platform compilation
//!   where OS-specific features (e.g., `setpgid`, `ioprio`) are unavailable.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Validating that PIDs/PGIDs fall within the caller's authorized process scope.
//! * Handling platform-specific errors returned by the underlying system calls.
//!
//! ## References
//! * `libc` syscall documentation (man pages).

use std::fmt;

/// Errors arising from process group management operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessGroupError {
    UnsupportedPlatform,
    InvalidPid { pid: u32 },
    SyscallFailed { name: &'static str, code: i32 },
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

/// Sets the PGID of a process to match its PID (Unix-only).
#[cfg(unix)]
pub fn set_process_group(pid: u32) -> Result<(), ProcessGroupError> {
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

/// Sends SIGTERM to a process group identified by the PGID (Unix-only).
#[cfg(unix)]
pub fn terminate_process_group(pid: u32) -> Result<(), ProcessGroupError> {
    signal_process_group(pid, libc::SIGTERM, "kill(SIGTERM)")
}

/// Sends SIGKILL to a process group identified by the PGID (Unix-only).
#[cfg(unix)]
pub fn kill_process_group(pid: u32) -> Result<(), ProcessGroupError> {
    signal_process_group(pid, libc::SIGKILL, "kill(SIGKILL)")
}

#[cfg(not(unix))]
pub fn terminate_process_group(_pid: u32) -> Result<(), ProcessGroupError> {
    Err(ProcessGroupError::UnsupportedPlatform)
}

#[cfg(not(unix))]
pub fn kill_process_group(_pid: u32) -> Result<(), ProcessGroupError> {
    Err(ProcessGroupError::UnsupportedPlatform)
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
fn signal_process_group(
    pid: u32,
    signal: i32,
    name: &'static str,
) -> Result<(), ProcessGroupError> {
    if pid <= 1 {
        return Err(ProcessGroupError::InvalidPid { pid });
    }
    let pgid = -(pid as i32);
    let rc = unsafe { libc::kill(pgid, signal) };
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
    fn process_group_signaling_rejects_special_pids() {
        assert_eq!(
            terminate_process_group(0).unwrap_err(),
            ProcessGroupError::InvalidPid { pid: 0 }
        );
        assert_eq!(
            kill_process_group(1).unwrap_err(),
            ProcessGroupError::InvalidPid { pid: 1 }
        );
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
