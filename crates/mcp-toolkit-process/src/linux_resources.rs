//! # Linux Cgroup Resource Evidence
//!
//! Read-only, bounded snapshots of OOM counters and pressure stall information
//! for the cgroup containing the current process.
//!
//! ## Security Boundaries
//! * Reads only fixed kernel-provided membership, mount, OOM, and PSI files.
//! * Does not return host paths, cgroup names, raw file contents, or OS error
//!   strings.
//! * Reports containing-cgroup observations; it does not attribute counters to
//!   an individual process or infer policy, deltas, or estimates.

use std::io::{self, Read};

/// The reason current-cgroup discovery could not produce a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupDiscoveryError {
    /// The current process's cgroup membership could not be read or parsed.
    MembershipUnavailable(DiscoveryFailureReason),
    /// No mounted cgroup-v2 hierarchy contains the current process's cgroup.
    CgroupV2Unavailable,
    /// More than one mounted cgroup-v2 hierarchy contains the current cgroup.
    AmbiguousMount,
    /// The cgroup-v2 mount information could not be read or parsed.
    MountInfoUnavailable(DiscoveryFailureReason),
    /// The process changed cgroup while the files were being sampled.
    MembershipChanged,
    /// This operating system does not expose Linux cgroup-v2 resource files.
    UnsupportedPlatform,
}

/// A bounded reason a procfs discovery input was unavailable or invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryFailureReason {
    /// The expected procfs input was absent.
    NotPresent,
    /// Permission was denied while reading the input.
    PermissionDenied,
    /// The input exceeded its byte bound.
    TooLarge,
    /// The input did not match the supported kernel format.
    Malformed,
    /// Another read error occurred.
    IoFailure,
}

/// A bounded reason one cgroup resource file could not be read or parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceUnavailableReason {
    /// The resource file is not exposed by this kernel or cgroup.
    NotPresent,
    /// Permission was denied while reading the resource file.
    PermissionDenied,
    /// The file exceeded its byte bound.
    TooLarge,
    /// The file did not match the supported kernel format.
    Malformed,
    /// Another read error occurred.
    IoFailure,
}

/// The independent result for one fixed kernel resource file.
#[derive(Clone, Debug, PartialEq)]
pub enum SourceObservation<T> {
    /// The source file was read and parsed successfully.
    Available(T),
    /// This source alone could not be read or parsed.
    Unavailable(SourceUnavailableReason),
}

/// A snapshot of resource files associated with the current process's cgroup.
#[derive(Clone, Debug, PartialEq)]
pub struct LinuxResourceSnapshot {
    /// OOM event counters local to the containing cgroup.
    ///
    /// The counters can include other processes in the same cgroup. They are
    /// not per-process events. A missing kernel counter remains `None`.
    pub memory_events_local: SourceObservation<MemoryEvents>,
    /// CPU pressure stall information for the containing cgroup.
    pub cpu_pressure: SourceObservation<PressureMetrics>,
    /// Memory pressure stall information for the containing cgroup.
    pub memory_pressure: SourceObservation<PressureMetrics>,
    /// I/O pressure stall information for the containing cgroup.
    pub io_pressure: SourceObservation<PressureMetrics>,
}

/// Selected OOM counters from `memory.events.local`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryEvents {
    /// Times the cgroup reached its memory limit and an allocation was about
    /// to fail, when this kernel exports the counter.
    pub oom: Option<u64>,
    /// Processes from this cgroup killed by an OOM killer, when exported.
    pub oom_kill: Option<u64>,
    /// Group OOM events, when exported.
    pub oom_group_kill: Option<u64>,
}

/// Cumulative PSI values reported for one `some` or `full` line.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PressureLine {
    /// Percentage of time stalled in the most recent 10-second window.
    pub avg10: f64,
    /// Percentage of time stalled in the most recent 60-second window.
    pub avg60: f64,
    /// Percentage of time stalled in the most recent 300-second window.
    pub avg300: f64,
    /// Cumulative stalled time in microseconds.
    pub total_microseconds: u64,
}

/// PSI `some` data and an optional kernel-provided `full` record.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PressureMetrics {
    /// At least one non-idle task was stalled.
    pub some: PressureLine,
    /// All non-idle tasks were stalled, when this kernel exports the record.
    pub full: Option<PressureLine>,
}

const PROC_CGROUP: &str = "/proc/self/cgroup";
const PROC_MOUNTINFO: &str = "/proc/self/mountinfo";
const MAX_CGROUP_BYTES: usize = 65_536;
const MAX_MOUNTINFO_BYTES: usize = 1_048_576;
const MAX_DISCOVERY_LINES: usize = 4_096;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_RESOURCE_BYTES: usize = 16_384;
const MAX_RESOURCE_LINES: usize = 256;
const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 32;

/// Captures bounded OOM and PSI values for the current process's cgroup.
///
/// Discovery errors are separate from per-file observations: if cgroup-v2
/// membership cannot be identified this returns `Err`, while a missing PSI
/// file produces `SourceObservation::Unavailable(NotPresent)` and leaves other
/// available resource observations intact. The operation does not provide an
/// atomic multi-file snapshot.
///
/// # Errors
/// Returns [`CgroupDiscoveryError`] if procfs membership or mount resolution
/// is missing, malformed, unreadable, ambiguous, too large, unsupported, or
/// changes during capture. Individual OOM and PSI file errors are represented
/// in the returned snapshot.
///
/// # Security
/// Reads only fixed procfs and cgroup-v2 files for the current process's
/// containing cgroup. Resource values and error variants contain no filesystem
/// path, cgroup label, raw file content, or OS error string.
pub fn capture_current() -> Result<LinuxResourceSnapshot, CgroupDiscoveryError> {
    #[cfg(target_os = "linux")]
    {
        capture_linux()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(CgroupDiscoveryError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
fn capture_linux() -> Result<LinuxResourceSnapshot, CgroupDiscoveryError> {
    let membership = read_discovery_file::<MAX_CGROUP_BYTES>(PROC_CGROUP)
        .map_err(CgroupDiscoveryError::MembershipUnavailable)?;
    let cgroup_path = parse_unified_membership(&membership)
        .map_err(CgroupDiscoveryError::MembershipUnavailable)?;
    let mountinfo = read_discovery_file::<MAX_MOUNTINFO_BYTES>(PROC_MOUNTINFO)
        .map_err(CgroupDiscoveryError::MountInfoUnavailable)?;
    let directory = resolve_cgroup_directory(&cgroup_path, &mountinfo)?;

    let memory_events_local =
        read_source(&directory, "memory.events.local", parse_memory_events_local);
    let cpu_pressure = read_source(&directory, "cpu.pressure", parse_pressure);
    let memory_pressure = read_source(&directory, "memory.pressure", parse_pressure);
    let io_pressure = read_source(&directory, "io.pressure", parse_pressure);

    let after = read_discovery_file::<MAX_CGROUP_BYTES>(PROC_CGROUP)
        .map_err(CgroupDiscoveryError::MembershipUnavailable)?;
    let after_path =
        parse_unified_membership(&after).map_err(CgroupDiscoveryError::MembershipUnavailable)?;
    if after_path != cgroup_path {
        return Err(CgroupDiscoveryError::MembershipChanged);
    }

    Ok(LinuxResourceSnapshot {
        memory_events_local,
        cpu_pressure,
        memory_pressure,
        io_pressure,
    })
}

#[cfg(target_os = "linux")]
fn read_source<T>(
    directory: &std::path::Path,
    name: &str,
    parse: fn(&[u8]) -> Result<T, SourceUnavailableReason>,
) -> SourceObservation<T> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let path = directory.join(name);
    let result = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .and_then(|file| read_bounded(file, MAX_RESOURCE_BYTES));
    match result {
        Ok(bytes) => match parse(&bytes) {
            Ok(value) => SourceObservation::Available(value),
            Err(reason) => SourceObservation::Unavailable(reason),
        },
        Err(error) => SourceObservation::Unavailable(source_reason(&error)),
    }
}

#[cfg(target_os = "linux")]
fn read_discovery_file<const LIMIT: usize>(path: &str) -> Result<Vec<u8>, DiscoveryFailureReason> {
    use std::fs::File;

    let file = File::open(path).map_err(|error| discovery_reason(&error))?;
    read_bounded(file, LIMIT).map_err(|error| discovery_reason(&error))
}

#[cfg(target_os = "linux")]
fn read_bounded(reader: impl io::Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take((limit as u64) + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bounded input exceeded",
        ));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn discovery_reason(error: &io::Error) -> DiscoveryFailureReason {
    match error.kind() {
        io::ErrorKind::NotFound => DiscoveryFailureReason::NotPresent,
        io::ErrorKind::PermissionDenied => DiscoveryFailureReason::PermissionDenied,
        io::ErrorKind::InvalidData => DiscoveryFailureReason::TooLarge,
        _ => DiscoveryFailureReason::IoFailure,
    }
}

#[cfg(target_os = "linux")]
fn source_reason(error: &io::Error) -> SourceUnavailableReason {
    match error.kind() {
        io::ErrorKind::NotFound => SourceUnavailableReason::NotPresent,
        io::ErrorKind::PermissionDenied => SourceUnavailableReason::PermissionDenied,
        io::ErrorKind::InvalidData => SourceUnavailableReason::TooLarge,
        _ => SourceUnavailableReason::IoFailure,
    }
}

#[cfg(target_os = "linux")]
fn parse_unified_membership(input: &[u8]) -> Result<std::path::PathBuf, DiscoveryFailureReason> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    if input.len() > MAX_CGROUP_BYTES
        || input.split(|byte| *byte == b'\n').count() > MAX_DISCOVERY_LINES
    {
        return Err(DiscoveryFailureReason::TooLarge);
    }
    let mut unified = None;
    for line in input
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let mut fields = line.splitn(3, |byte| *byte == b':');
        let hierarchy = fields.next().ok_or(DiscoveryFailureReason::Malformed)?;
        let controllers = fields.next().ok_or(DiscoveryFailureReason::Malformed)?;
        let path = fields.next().ok_or(DiscoveryFailureReason::Malformed)?;
        if hierarchy.is_empty() || !hierarchy.iter().all(u8::is_ascii_digit) {
            return Err(DiscoveryFailureReason::Malformed);
        }
        if hierarchy == b"0" && controllers.is_empty() {
            if unified.is_some() || !path.starts_with(b"/") {
                return Err(DiscoveryFailureReason::Malformed);
            }
            if path.len() > MAX_PATH_BYTES {
                return Err(DiscoveryFailureReason::TooLarge);
            }
            let path = PathBuf::from(OsString::from_vec(path.to_vec()));
            if normal_components(&path).is_none() {
                return Err(DiscoveryFailureReason::Malformed);
            }
            unified = Some(path);
        }
        if fields.next().is_some() {
            return Err(DiscoveryFailureReason::Malformed);
        }
    }
    unified.ok_or(DiscoveryFailureReason::NotPresent)
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct Cgroup2Mount {
    root: std::path::PathBuf,
    point: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
fn resolve_cgroup_directory(
    membership: &std::path::Path,
    mountinfo: &[u8],
) -> Result<std::path::PathBuf, CgroupDiscoveryError> {
    use std::path::PathBuf;

    if mountinfo.len() > MAX_MOUNTINFO_BYTES
        || mountinfo.split(|byte| *byte == b'\n').count() > MAX_DISCOVERY_LINES
    {
        return Err(CgroupDiscoveryError::MountInfoUnavailable(
            DiscoveryFailureReason::TooLarge,
        ));
    }
    let mounts =
        parse_cgroup2_mounts(mountinfo).map_err(CgroupDiscoveryError::MountInfoUnavailable)?;
    let membership_components = normal_components(membership).ok_or(
        CgroupDiscoveryError::MembershipUnavailable(DiscoveryFailureReason::Malformed),
    )?;

    let mut matches = Vec::new();
    for mount in mounts {
        let root_components = normal_components(&mount.root).ok_or(
            CgroupDiscoveryError::MountInfoUnavailable(DiscoveryFailureReason::Malformed),
        )?;
        let point_components = normal_components(&mount.point).ok_or(
            CgroupDiscoveryError::MountInfoUnavailable(DiscoveryFailureReason::Malformed),
        )?;
        if root_components.len() > membership_components.len()
            || !root_components
                .iter()
                .zip(&membership_components)
                .all(|(root, member)| root == member)
        {
            continue;
        }
        let mut directory = PathBuf::from(&mount.point);
        for component in &membership_components[root_components.len()..] {
            directory.push(component);
        }
        // Re-check the result as a normalized path below the selected mount.
        let normalized = normal_components(&directory).ok_or(
            CgroupDiscoveryError::MountInfoUnavailable(DiscoveryFailureReason::Malformed),
        )?;
        if normalized.len() < point_components.len()
            || !point_components
                .iter()
                .zip(&normalized)
                .all(|(point, child)| point == child)
        {
            return Err(CgroupDiscoveryError::MountInfoUnavailable(
                DiscoveryFailureReason::Malformed,
            ));
        }
        matches.push(directory);
    }

    match matches.len() {
        0 => Err(CgroupDiscoveryError::CgroupV2Unavailable),
        1 => matches
            .pop()
            .ok_or(CgroupDiscoveryError::CgroupV2Unavailable),
        _ => Err(CgroupDiscoveryError::AmbiguousMount),
    }
}

#[cfg(target_os = "linux")]
fn normal_components(path: &std::path::Path) -> Option<Vec<std::ffi::OsString>> {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let bytes = path.as_os_str().as_bytes();
    if bytes.len() > MAX_PATH_BYTES || !bytes.starts_with(b"/") {
        return None;
    }
    let mut components = Vec::new();
    for part in bytes.split(|byte| *byte == b'/').skip(1) {
        if part.is_empty() {
            continue;
        }
        if part == b"." || part == b".." || part.contains(&0) {
            return None;
        }
        components.push(OsString::from_vec(part.to_vec()));
    }
    Some(components)
}

#[cfg(target_os = "linux")]
fn parse_cgroup2_mounts(input: &[u8]) -> Result<Vec<Cgroup2Mount>, DiscoveryFailureReason> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    let mut mounts = Vec::new();
    for line in input
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let fields: Vec<&[u8]> = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .collect();
        let separator = fields
            .iter()
            .position(|field| *field == b"-")
            .ok_or(DiscoveryFailureReason::Malformed)?;
        if separator < 6 || fields.len() < separator + 4 {
            return Err(DiscoveryFailureReason::Malformed);
        }
        if fields[separator + 1] != b"cgroup2" {
            continue;
        }
        let root = PathBuf::from(OsString::from_vec(decode_mount_path(fields[3])?));
        let point = PathBuf::from(OsString::from_vec(decode_mount_path(fields[4])?));
        if normal_components(&root).is_none() || normal_components(&point).is_none() {
            return Err(DiscoveryFailureReason::Malformed);
        }
        mounts.push(Cgroup2Mount { root, point });
    }
    Ok(mounts)
}

#[cfg(target_os = "linux")]
fn decode_mount_path(field: &[u8]) -> Result<Vec<u8>, DiscoveryFailureReason> {
    let mut decoded = Vec::with_capacity(field.len());
    let mut index = 0;
    while index < field.len() {
        if field[index] != b'\\' {
            decoded.push(field[index]);
            index += 1;
            continue;
        }
        if index + 3 >= field.len() {
            return Err(DiscoveryFailureReason::Malformed);
        }
        let code = &field[index + 1..index + 4];
        let byte = match code {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err(DiscoveryFailureReason::Malformed),
        };
        decoded.push(byte);
        index += 4;
    }
    if decoded.len() > MAX_PATH_BYTES {
        return Err(DiscoveryFailureReason::TooLarge);
    }
    Ok(decoded)
}

#[cfg(target_os = "linux")]
fn parse_memory_events_local(input: &[u8]) -> Result<MemoryEvents, SourceUnavailableReason> {
    let entries = parse_key_u64_lines(input)?;
    Ok(MemoryEvents {
        oom: entries.get("oom").copied(),
        oom_kill: entries.get("oom_kill").copied(),
        oom_group_kill: entries.get("oom_group_kill").copied(),
    })
}

#[cfg(target_os = "linux")]
fn parse_key_u64_lines(
    input: &[u8],
) -> Result<std::collections::BTreeMap<&str, u64>, SourceUnavailableReason> {
    use std::collections::BTreeMap;

    if input.len() > MAX_RESOURCE_BYTES {
        return Err(SourceUnavailableReason::TooLarge);
    }
    let lines: Vec<&[u8]> = input
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() > MAX_RESOURCE_LINES || lines.is_empty() {
        return Err(if lines.len() > MAX_RESOURCE_LINES {
            SourceUnavailableReason::TooLarge
        } else {
            SourceUnavailableReason::Malformed
        });
    }
    let mut entries = BTreeMap::new();
    for line in lines {
        let fields: Vec<&[u8]> = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .collect();
        if fields.len() != 2
            || fields[0].is_empty()
            || fields[0].len() > MAX_KEY_BYTES
            || fields[1].is_empty()
            || fields[1].len() > MAX_VALUE_BYTES
            || !fields[0]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            || !fields[1].iter().all(u8::is_ascii_digit)
        {
            return Err(SourceUnavailableReason::Malformed);
        }
        let key = std::str::from_utf8(fields[0]).map_err(|_| SourceUnavailableReason::Malformed)?;
        let value = std::str::from_utf8(fields[1])
            .map_err(|_| SourceUnavailableReason::Malformed)?
            .parse::<u64>()
            .map_err(|_| SourceUnavailableReason::Malformed)?;
        if entries.insert(key, value).is_some() {
            return Err(SourceUnavailableReason::Malformed);
        }
    }
    Ok(entries)
}

#[cfg(target_os = "linux")]
fn parse_pressure(input: &[u8]) -> Result<PressureMetrics, SourceUnavailableReason> {
    if input.len() > MAX_RESOURCE_BYTES {
        return Err(SourceUnavailableReason::TooLarge);
    }
    let lines: Vec<&[u8]> = input
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() || lines.len() > MAX_RESOURCE_LINES {
        return Err(if lines.len() > MAX_RESOURCE_LINES {
            SourceUnavailableReason::TooLarge
        } else {
            SourceUnavailableReason::Malformed
        });
    }
    let mut some = None;
    let mut full = None;
    for line in lines {
        let mut fields = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty());
        let kind = fields.next().ok_or(SourceUnavailableReason::Malformed)?;
        let mut values = std::collections::BTreeMap::new();
        for field in fields {
            let separator = field
                .iter()
                .position(|byte| *byte == b'=')
                .ok_or(SourceUnavailableReason::Malformed)?;
            let key = &field[..separator];
            let value = &field[separator + 1..];
            if key.is_empty()
                || key.len() > MAX_KEY_BYTES
                || value.is_empty()
                || value.len() > MAX_VALUE_BYTES
                || !key
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                return Err(SourceUnavailableReason::Malformed);
            }
            let key = std::str::from_utf8(key).map_err(|_| SourceUnavailableReason::Malformed)?;
            if !matches!(key, "avg10" | "avg60" | "avg300" | "total") {
                return Err(SourceUnavailableReason::Malformed);
            }
            if values.insert(key, value).is_some() {
                return Err(SourceUnavailableReason::Malformed);
            }
        }
        let metrics = PressureLine {
            avg10: parse_percentage(values.get("avg10"))?,
            avg60: parse_percentage(values.get("avg60"))?,
            avg300: parse_percentage(values.get("avg300"))?,
            total_microseconds: parse_u64(values.get("total"))?,
        };
        match kind {
            b"some" if some.is_none() => some = Some(metrics),
            b"full" if full.is_none() => full = Some(metrics),
            _ => return Err(SourceUnavailableReason::Malformed),
        }
    }
    Ok(PressureMetrics {
        some: some.ok_or(SourceUnavailableReason::Malformed)?,
        full,
    })
}

#[cfg(target_os = "linux")]
fn parse_percentage(value: Option<&&[u8]>) -> Result<f64, SourceUnavailableReason> {
    let value = value.ok_or(SourceUnavailableReason::Malformed)?;
    let mut parts = value.split(|byte| *byte == b'.');
    let integer = parts.next().ok_or(SourceUnavailableReason::Malformed)?;
    let fraction = parts.next().ok_or(SourceUnavailableReason::Malformed)?;
    if integer.is_empty()
        || fraction.is_empty()
        || !integer.iter().all(u8::is_ascii_digit)
        || !fraction.iter().all(u8::is_ascii_digit)
        || parts.next().is_some()
    {
        return Err(SourceUnavailableReason::Malformed);
    }
    let value = std::str::from_utf8(value).map_err(|_| SourceUnavailableReason::Malformed)?;
    let percentage = value
        .parse::<f64>()
        .map_err(|_| SourceUnavailableReason::Malformed)?;
    if !percentage.is_finite() || !(0.0..=100.0).contains(&percentage) {
        return Err(SourceUnavailableReason::Malformed);
    }
    Ok(percentage)
}

#[cfg(target_os = "linux")]
fn parse_u64(value: Option<&&[u8]>) -> Result<u64, SourceUnavailableReason> {
    let value = value.ok_or(SourceUnavailableReason::Malformed)?;
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(SourceUnavailableReason::Malformed);
    }
    std::str::from_utf8(value)
        .map_err(|_| SourceUnavailableReason::Malformed)?
        .parse::<u64>()
        .map_err(|_| SourceUnavailableReason::Malformed)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let nonce = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "mcp-toolkit-linux-resources-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create private resource test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parses_unified_membership_only() {
        let path =
            parse_unified_membership(b"2:cpu:/legacy\n0::/tenant/job\n").expect("one unified path");
        assert_eq!(path, std::path::Path::new("/tenant/job"));
        assert_eq!(
            parse_unified_membership(b"2:cpu:/legacy\n"),
            Err(DiscoveryFailureReason::NotPresent)
        );
        assert_eq!(
            parse_unified_membership(b"0::/a\n0::/b\n"),
            Err(DiscoveryFailureReason::Malformed)
        );
        assert_eq!(
            parse_unified_membership(b"0::/a/../b\n"),
            Err(DiscoveryFailureReason::Malformed)
        );
    }

    #[test]
    fn resolves_membership_inside_the_unique_mount_root() {
        let mountinfo = b"36 25 0:32 /tenant /sys/fs/cgroup rw - cgroup2 cgroup rw\n";
        let result =
            resolve_cgroup_directory(std::path::Path::new("/tenant/jobs/build"), mountinfo)
                .expect("matching mount");
        assert_eq!(result, std::path::Path::new("/sys/fs/cgroup/jobs/build"));
        assert_eq!(
            resolve_cgroup_directory(std::path::Path::new("/elsewhere"), mountinfo),
            Err(CgroupDiscoveryError::CgroupV2Unavailable)
        );
    }

    #[test]
    fn refuses_ambiguous_mount_roots_and_decodes_kernel_escapes() {
        let ambiguous = b"36 25 0:32 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n37 25 0:32 / /alt/cgroup rw - cgroup2 cgroup rw\n";
        assert_eq!(
            resolve_cgroup_directory(std::path::Path::new("/tenant"), ambiguous),
            Err(CgroupDiscoveryError::AmbiguousMount)
        );
        let escaped = b"36 25 0:32 / /sys/fs/cgroup\\040root rw - cgroup2 cgroup rw\n";
        let resolved = resolve_cgroup_directory(std::path::Path::new("/"), escaped)
            .expect("escaped mount point");
        assert_eq!(resolved.to_string_lossy(), "/sys/fs/cgroup root");
    }

    #[test]
    fn parses_local_oom_counters_without_synthesizing_missing_fields() {
        let events = parse_memory_events_local(b"low 2\noom 4\noom_kill 1\nfuture_key 8\n")
            .expect("well-formed counters");
        assert_eq!(events.oom, Some(4));
        assert_eq!(events.oom_kill, Some(1));
        assert_eq!(events.oom_group_kill, None);
        assert_eq!(
            parse_memory_events_local(b"oom 1\noom 2\n"),
            Err(SourceUnavailableReason::Malformed)
        );
        assert_eq!(
            parse_memory_events_local(b"oom 18446744073709551616\n"),
            Err(SourceUnavailableReason::Malformed)
        );
    }

    #[test]
    fn parses_pressure_values_and_preserves_missing_full_record() {
        let pressure = parse_pressure(b"some avg10=0.12 avg60=0.03 avg300=0.01 total=1234\n")
            .expect("valid some-only pressure");
        assert_eq!(pressure.some.avg10, 0.12);
        assert_eq!(pressure.some.total_microseconds, 1234);
        assert_eq!(pressure.full, None);
        assert_eq!(
            parse_pressure(b"some avg10=101.00 avg60=0.00 avg300=0.00 total=0\n"),
            Err(SourceUnavailableReason::Malformed)
        );
        assert_eq!(
            parse_pressure(b"some avg10=0.00 avg10=1.00 avg60=0.00 avg300=0.00 total=0\n"),
            Err(SourceUnavailableReason::Malformed)
        );
    }

    #[test]
    fn bounded_reads_detect_one_byte_over_the_limit() {
        assert_eq!(read_bounded(&b"1234"[..], 4).expect("at limit"), b"1234");
        assert_eq!(
            read_bounded(&b"12345"[..], 4).map_err(|error| source_reason(&error)),
            Err(SourceUnavailableReason::TooLarge)
        );
    }

    #[test]
    fn maps_absent_and_denied_resource_files_without_hiding_the_source_state() {
        assert_eq!(
            source_reason(&io::Error::from(io::ErrorKind::NotFound)),
            SourceUnavailableReason::NotPresent
        );
        assert_eq!(
            source_reason(&io::Error::from(io::ErrorKind::PermissionDenied)),
            SourceUnavailableReason::PermissionDenied
        );
        assert_eq!(
            discovery_reason(&io::Error::from(io::ErrorKind::PermissionDenied)),
            DiscoveryFailureReason::PermissionDenied
        );
    }

    #[test]
    fn reads_each_resource_independently_and_does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        fs::write(directory.path().join("memory.events.local"), b"oom 2\n")
            .expect("write local OOM fixture");
        fs::write(
            directory.path().join("cpu.pressure"),
            b"some avg10=1.00 avg60=0.50 avg300=0.25 total=42\n",
        )
        .expect("write CPU pressure fixture");
        fs::write(
            directory.path().join("outside.pressure"),
            b"some avg10=1.00 avg60=1.00 avg300=1.00 total=9\n",
        )
        .expect("write symlink target fixture");
        symlink(
            directory.path().join("outside.pressure"),
            directory.path().join("io.pressure"),
        )
        .expect("create symlink fixture");
        fs::create_dir(directory.path().join("memory.pressure"))
            .expect("create unreadable resource fixture");

        let oom = read_source(
            directory.path(),
            "memory.events.local",
            parse_memory_events_local,
        );
        let cpu = read_source(directory.path(), "cpu.pressure", parse_pressure);
        let missing = read_source(directory.path(), "missing.pressure", parse_pressure);
        let directory_read = read_source(directory.path(), "memory.pressure", parse_pressure);
        let symlink_read = read_source(directory.path(), "io.pressure", parse_pressure);

        assert!(matches!(
            oom,
            SourceObservation::Available(MemoryEvents { oom: Some(2), .. })
        ));
        assert!(matches!(
            cpu,
            SourceObservation::Available(PressureMetrics {
                some: PressureLine {
                    total_microseconds: 42,
                    ..
                },
                ..
            })
        ));
        assert_eq!(
            missing,
            SourceObservation::Unavailable(SourceUnavailableReason::NotPresent)
        );
        assert_eq!(
            directory_read,
            SourceObservation::Unavailable(SourceUnavailableReason::IoFailure)
        );
        assert_eq!(
            symlink_read,
            SourceObservation::Unavailable(SourceUnavailableReason::IoFailure)
        );
    }

    #[test]
    fn source_reads_apply_the_byte_limit_to_real_files() {
        let directory = TestDirectory::new();
        fs::write(
            directory.path().join("cpu.pressure"),
            vec![b'x'; MAX_RESOURCE_BYTES + 1],
        )
        .expect("write oversized resource fixture");
        assert_eq!(
            read_source(directory.path(), "cpu.pressure", parse_pressure),
            SourceObservation::Unavailable(SourceUnavailableReason::TooLarge)
        );
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod unsupported_platform_tests {
    use super::{capture_current, CgroupDiscoveryError};

    #[test]
    fn reports_unsupported_platform_without_fabricating_a_snapshot() {
        assert_eq!(
            capture_current(),
            Err(CgroupDiscoveryError::UnsupportedPlatform)
        );
    }
}
