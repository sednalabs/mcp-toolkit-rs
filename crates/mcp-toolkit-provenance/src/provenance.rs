use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const ATTESTATION_SCHEMA_VERSION: u32 = 2;
pub const UNKNOWN_VALUE: &str = "unknown";

/// A filesystem path that was selected from an operator-owned local root.
///
/// The constructor canonicalizes the path and rejects relative paths, traversal
/// components, paths outside the canonical root, and paths that do not yet
/// exist. Consumers should construct this value at a configuration boundary
/// and pass it through to runtime/provenance helpers; request data must never be
/// used to construct one. Admission reads and writes use the retained root and
/// relative path through directory handles, so later intermediate symlink or
/// junction replacement cannot redirect an operation outside the bound root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedLocalPath {
    path: PathBuf,
    root: PathBuf,
    relative: PathBuf,
    #[cfg(unix)]
    root_identity: DirectoryIdentity,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedLocalPathError {
    RootNotAbsolute,
    RootUnavailable(String),
    RootNotDirectory,
    PathNotAbsolute,
    PathTraversal,
    PathUnavailable(String),
    OutsideRoot,
}

impl std::fmt::Display for TrustedLocalPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootNotAbsolute => write!(f, "trusted local path root must be absolute"),
            Self::RootUnavailable(error) => {
                write!(f, "trusted local path root is unavailable: {error}")
            }
            Self::RootNotDirectory => write!(f, "trusted local path root must be a directory"),
            Self::PathNotAbsolute => write!(f, "trusted local path must be absolute"),
            Self::PathTraversal => {
                write!(
                    f,
                    "trusted local path must not contain traversal components"
                )
            }
            Self::PathUnavailable(error) => {
                write!(f, "trusted local path is unavailable: {error}")
            }
            Self::OutsideRoot => write!(f, "trusted local path is outside its configured root"),
        }
    }
}

impl std::error::Error for TrustedLocalPathError {}

impl TrustedLocalPath {
    /// Binds an operator-selected path to an existing local root.
    ///
    /// The root is canonicalized before the candidate is checked. The candidate
    /// is canonicalized as well, so symlinks cannot escape the root. Callers
    /// writing an atomic output must bind an existing placeholder before
    /// replacing it.
    pub fn from_root(
        root: impl AsRef<Path>,
        path: impl Into<PathBuf>,
    ) -> Result<Self, TrustedLocalPathError> {
        let root = root.as_ref();
        validate_absolute_without_traversal(root, true)?;
        let canonical_root = fs::canonicalize(root)
            .map_err(|error| TrustedLocalPathError::RootUnavailable(error.to_string()))?;
        let root_metadata = fs::metadata(&canonical_root)
            .map_err(|error| TrustedLocalPathError::RootUnavailable(error.to_string()))?;
        if !root_metadata.is_dir() {
            return Err(TrustedLocalPathError::RootNotDirectory);
        }

        let path = path.into();
        validate_absolute_without_traversal(&path, false)?;
        if !path.starts_with(root) {
            return Err(TrustedLocalPathError::OutsideRoot);
        }
        let canonical_path = fs::canonicalize(&path)
            .map_err(|error| TrustedLocalPathError::PathUnavailable(error.to_string()))?;
        if !canonical_path.starts_with(&canonical_root) {
            return Err(TrustedLocalPathError::OutsideRoot);
        }
        let relative = canonical_path
            .strip_prefix(&canonical_root)
            .map_err(|_| TrustedLocalPathError::OutsideRoot)?
            .to_path_buf();
        Ok(Self {
            path: canonical_path,
            root: canonical_root,
            relative,
            #[cfg(unix)]
            root_identity: directory_identity(&root_metadata),
        })
    }

    /// Binds the process executable to its own canonical parent directory.
    pub fn current_executable() -> io::Result<Self> {
        let path = std::env::current_exe()?;
        let root = path
            .parent()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "current executable has no parent",
                )
            })?
            .to_path_buf();
        Self::from_root(root, path)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn open_confined_read(&self) -> io::Result<File> {
        #[cfg(unix)]
        {
            open_confined_read(&self.root, &self.relative, self.root_identity)
        }
        #[cfg(not(unix))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "directory-handle-confined gate reads are unsupported on this platform",
            ))
        }
    }

    pub(crate) fn write_confined_atomic(&self, payload: &[u8]) -> io::Result<()> {
        #[cfg(unix)]
        {
            write_confined_atomic(&self.root, &self.relative, self.root_identity, payload)
        }
        #[cfg(not(unix))]
        {
            let _ = payload;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "directory-handle-confined gate writes are unsupported on this platform",
            ))
        }
    }
}

impl AsRef<Path> for TrustedLocalPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl From<TrustedLocalPath> for PathBuf {
    fn from(path: TrustedLocalPath) -> Self {
        path.path
    }
}

fn validate_absolute_without_traversal(
    path: &Path,
    root: bool,
) -> Result<(), TrustedLocalPathError> {
    if !path.is_absolute() {
        return Err(if root {
            TrustedLocalPathError::RootNotAbsolute
        } else {
            TrustedLocalPathError::PathNotAbsolute
        });
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(TrustedLocalPathError::PathTraversal);
    }
    Ok(())
}

#[cfg(unix)]
fn directory_identity(metadata: &fs::Metadata) -> DirectoryIdentity {
    DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(unix)]
fn open_confined_read(
    root: &Path,
    relative: &Path,
    root_identity: DirectoryIdentity,
) -> io::Result<File> {
    let (parent, name) = open_confined_parent(root, relative, root_identity)?;
    let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gate artifact is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn write_confined_atomic(
    root: &Path,
    relative: &Path,
    root_identity: DirectoryIdentity,
    payload: &[u8],
) -> io::Result<()> {
    let (parent, name) = open_confined_parent(root, relative, root_identity)?;
    let mut temp_relative = relative.to_path_buf();
    temp_relative.set_extension("tmp");
    let temp_name = temp_relative.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted gate path has no file name",
        )
    })?;
    let temp_name = cstring_os_str(temp_name)?;
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            temp_name.as_ptr(),
            flags,
            0o600 as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut temp_file = unsafe { File::from_raw_fd(fd) };
    temp_file.write_all(payload)?;
    temp_file.sync_all()?;
    drop(temp_file);

    let result = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            temp_name.as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn open_confined_parent(
    root: &Path,
    relative: &Path,
    root_identity: DirectoryIdentity,
) -> io::Result<(File, CString)> {
    let mut directory = open_directory_tree(root)?;
    if directory_identity(&directory.metadata()?) != root_identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "trusted root directory changed",
        ));
    }
    let mut components = relative.components().peekable();
    let mut final_name = None;

    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "trusted gate path contains a non-normal component",
            ));
        };
        if components.peek().is_none() {
            final_name = Some(cstring_os_str(name)?);
            break;
        }
        directory = open_directory_at(&directory, name)?;
    }

    let final_name = final_name.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted gate path has no file name",
        )
    })?;
    Ok((directory, final_name))
}

#[cfg(unix)]
fn open_directory_tree(root: &Path) -> io::Result<File> {
    let root_fd = open_directory_at_path(Path::new("/"))?;
    let mut directory = root_fd;
    for component in root.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = open_directory_at(&directory, name)?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "trusted root contains a non-normal component",
                ));
            }
        }
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_directory_at_path(path: &Path) -> io::Result<File> {
    let path = cstring_path(path)?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a new owned descriptor on success.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_directory_at(parent: &File, name: &std::ffi::OsStr) -> io::Result<File> {
    let name = cstring_os_str(name)?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor on success.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn cstring_path(path: &Path) -> io::Result<CString> {
    cstring_os_str(path.as_os_str())
}

#[cfg(unix)]
fn cstring_os_str(value: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted path contains an embedded NUL byte",
        )
    })
}

#[derive(Debug, Clone, Copy)]
pub struct BuildProvenanceInput<'a> {
    pub component: &'a str,
    pub server_version: &'a str,
    pub revision: Option<&'a str>,
    pub reference: Option<&'a str>,
    pub dirty: bool,
    pub profile: Option<&'a str>,
    pub target: Option<&'a str>,
    pub rustc_version: Option<&'a str>,
    pub source_date_epoch: Option<&'a str>,
    pub build_identity_override: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildProvenance {
    pub component: String,
    pub server_version: String,
    pub build_identity: String,
    pub source_fingerprint: String,
    pub source: SourceProvenance,
    pub build_metadata: BuildMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceProvenance {
    pub vcs: String,
    pub revision: String,
    pub reference: String,
    pub dirty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildMetadata {
    pub profile: String,
    pub target: String,
    pub rustc_version: String,
    pub source_date_epoch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessProvenance {
    pub pid: u32,
    pub executable_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryProvenance {
    pub file_size_bytes: Option<u64>,
    pub modified_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeProvenance {
    pub build: BuildProvenance,
    pub process: ProcessProvenance,
    pub binary: BinaryProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Ok,
    Degraded,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnavailableField {
    pub field: String,
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationIdentity {
    pub server_version: String,
    pub contract_version: Option<String>,
    pub build_identity: String,
    pub source_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationRuntime {
    pub pid: Option<u32>,
    pub executable_path: Option<String>,
    pub binary_size_bytes: Option<u64>,
    pub binary_modified_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationPayload {
    pub identity: AttestationIdentity,
    pub source: SourceProvenance,
    pub build_metadata: BuildMetadata,
    pub runtime: AttestationRuntime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationEnvelope {
    pub status: AttestationStatus,
    pub schema_version: u32,
    pub component: String,
    pub timestamp: String,
    pub request_id: Option<String>,
    pub attestation: AttestationPayload,
    pub unavailable: Vec<UnavailableField>,
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default)]
pub struct AttestationOptions {
    pub contract_version: Option<String>,
    pub request_id: Option<String>,
    pub extensions: BTreeMap<String, Value>,
}

impl AttestationOptions {
    pub fn with_contract_version(mut self, value: impl Into<String>) -> Self {
        self.contract_version = Some(value.into());
        self
    }

    pub fn with_request_id(mut self, value: impl Into<String>) -> Self {
        self.request_id = Some(value.into());
        self
    }

    pub fn with_extension(mut self, namespace: impl Into<String>, value: Value) -> Self {
        self.extensions.insert(namespace.into(), value);
        self
    }
}

impl BuildProvenance {
    pub fn from_input(input: BuildProvenanceInput<'_>) -> Self {
        let component = normalized_or(input.component, UNKNOWN_VALUE);
        let server_version = normalized_or(input.server_version, UNKNOWN_VALUE);
        let revision =
            normalized_option(input.revision).unwrap_or_else(|| UNKNOWN_VALUE.to_string());
        let reference =
            normalized_option(input.reference).unwrap_or_else(|| UNKNOWN_VALUE.to_string());
        let source_date_epoch = normalized_option(input.source_date_epoch);
        let source_fingerprint = source_fingerprint(&revision, input.dirty);
        let build_identity = normalized_option(input.build_identity_override)
            .unwrap_or_else(|| build_identity(&component, &server_version, &revision, input.dirty));

        Self {
            component,
            server_version,
            build_identity,
            source_fingerprint,
            source: SourceProvenance {
                vcs: "git".to_string(),
                revision,
                reference,
                dirty: input.dirty,
            },
            build_metadata: BuildMetadata {
                profile: normalized_option(input.profile)
                    .unwrap_or_else(|| UNKNOWN_VALUE.to_string()),
                target: normalized_option(input.target)
                    .unwrap_or_else(|| UNKNOWN_VALUE.to_string()),
                rustc_version: normalized_option(input.rustc_version)
                    .unwrap_or_else(|| UNKNOWN_VALUE.to_string()),
                source_date_epoch,
            },
        }
    }
}

pub fn capture_runtime_provenance(
    build: BuildProvenance,
    executable_path: &TrustedLocalPath,
) -> RuntimeProvenance {
    let executable_path = operator_local_executable_path(executable_path);
    let metadata = fs::metadata(executable_path).ok();
    let modified_unix_ms = metadata
        .as_ref()
        .and_then(|meta| meta.modified().ok())
        .and_then(system_time_to_unix_ms);

    RuntimeProvenance {
        build,
        process: ProcessProvenance {
            pid: std::process::id(),
            executable_path: executable_path.display().to_string(),
        },
        binary: BinaryProvenance {
            file_size_bytes: metadata.as_ref().map(|meta| meta.len()),
            modified_unix_ms,
        },
    }
}

/// Marks a path supplied by trusted startup/build configuration as a local
/// filesystem target. This is intentionally crate-private: callers must not
/// use it to launder request-derived paths into filesystem operations.
pub(crate) fn operator_local_executable_path(path: &TrustedLocalPath) -> &Path {
    path.as_path()
}

pub fn capture_current_runtime_provenance(
    build: BuildProvenance,
) -> std::io::Result<RuntimeProvenance> {
    let executable_path = TrustedLocalPath::current_executable()?;
    Ok(capture_runtime_provenance(build, &executable_path))
}

pub fn build_attestation_envelope(
    provenance: &RuntimeProvenance,
    options: AttestationOptions,
) -> AttestationEnvelope {
    let mut unavailable = Vec::new();

    if is_unknown(&provenance.build.source.revision) {
        unavailable.push(unavailable_field(
            "attestation.source.revision",
            "provenance.unavailable.git_revision",
            "git revision unavailable in build context",
        ));
    }
    if is_unknown(&provenance.build.source.reference) {
        unavailable.push(unavailable_field(
            "attestation.source.reference",
            "provenance.unavailable.git_reference",
            "git reference unavailable in build context",
        ));
    }
    if is_unknown(&provenance.build.build_metadata.rustc_version) {
        unavailable.push(unavailable_field(
            "attestation.build_metadata.rustc_version",
            "provenance.unavailable.rustc_version",
            "rustc version unavailable in build context",
        ));
    }
    if provenance.binary.file_size_bytes.is_none() {
        unavailable.push(unavailable_field(
            "attestation.runtime.binary_size_bytes",
            "provenance.unavailable.binary_size",
            "binary size unavailable at runtime",
        ));
    }
    if provenance.binary.modified_unix_ms.is_none() {
        unavailable.push(unavailable_field(
            "attestation.runtime.binary_modified_unix_ms",
            "provenance.unavailable.binary_mtime",
            "binary modification time unavailable at runtime",
        ));
    }

    let status = if unavailable.is_empty() {
        AttestationStatus::Ok
    } else {
        AttestationStatus::Degraded
    };

    AttestationEnvelope {
        status,
        schema_version: ATTESTATION_SCHEMA_VERSION,
        component: provenance.build.component.clone(),
        timestamp: now_rfc3339(),
        request_id: options.request_id,
        attestation: AttestationPayload {
            identity: AttestationIdentity {
                server_version: provenance.build.server_version.clone(),
                contract_version: options.contract_version,
                build_identity: provenance.build.build_identity.clone(),
                source_fingerprint: provenance.build.source_fingerprint.clone(),
            },
            source: provenance.build.source.clone(),
            build_metadata: provenance.build.build_metadata.clone(),
            runtime: AttestationRuntime {
                pid: Some(provenance.process.pid),
                executable_path: Some(provenance.process.executable_path.clone()),
                binary_size_bytes: provenance.binary.file_size_bytes,
                binary_modified_unix_ms: provenance.binary.modified_unix_ms,
            },
        },
        unavailable,
        extensions: options.extensions,
    }
}

pub fn source_fingerprint(revision: &str, dirty: bool) -> String {
    let cleanliness = if dirty { "dirty" } else { "clean" };
    format!("git:{revision}:{cleanliness}")
}

pub fn build_identity(
    component: &str,
    server_version: &str,
    revision: &str,
    dirty: bool,
) -> String {
    let mut value = format!("{component}@{server_version}+{revision}");
    if dirty {
        value.push_str("-dirty");
    }
    value
}

fn normalized_or(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalized_option(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn is_unknown(value: &str) -> bool {
    value.trim().is_empty() || value.eq_ignore_ascii_case(UNKNOWN_VALUE)
}

fn unavailable_field(field: &str, code: &str, reason: &str) -> UnavailableField {
    UnavailableField {
        field: field.to_string(),
        code: code.to_string(),
        reason: reason.to_string(),
    }
}

fn system_time_to_unix_ms(value: std::time::SystemTime) -> Option<u64> {
    let duration = value.duration_since(UNIX_EPOCH).ok()?;
    Some(duration.as_millis().min(u128::from(u64::MAX)) as u64)
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(dirty: bool) -> BuildProvenanceInput<'static> {
        BuildProvenanceInput {
            component: "example-mcp",
            server_version: "1.2.3",
            revision: Some("abc123"),
            reference: Some("main"),
            dirty,
            profile: Some("release"),
            target: Some("x86_64-unknown-linux-gnu"),
            rustc_version: Some("rustc test"),
            source_date_epoch: None,
            build_identity_override: None,
        }
    }

    #[test]
    fn canonical_identity_marks_dirty_builds() {
        let clean = BuildProvenance::from_input(input(false));
        assert_eq!(clean.build_identity, "example-mcp@1.2.3+abc123");
        assert_eq!(clean.source_fingerprint, "git:abc123:clean");

        let dirty = BuildProvenance::from_input(input(true));
        assert_eq!(dirty.build_identity, "example-mcp@1.2.3+abc123-dirty");
        assert_eq!(dirty.source_fingerprint, "git:abc123:dirty");
    }

    #[test]
    fn unknown_revision_degrades_attestation_explicitly() {
        let mut input = input(false);
        input.revision = None;
        let build = BuildProvenance::from_input(input);
        let runtime = RuntimeProvenance {
            build,
            process: ProcessProvenance {
                pid: 1,
                executable_path: "/tmp/example".to_string(),
            },
            binary: BinaryProvenance {
                file_size_bytes: Some(10),
                modified_unix_ms: Some(20),
            },
        };

        let envelope = build_attestation_envelope(&runtime, AttestationOptions::default());
        assert_eq!(envelope.status, AttestationStatus::Degraded);
        assert!(envelope
            .unavailable
            .iter()
            .any(|item| item.code == "provenance.unavailable.git_revision"));
    }

    #[test]
    fn trusted_local_path_rejects_relative_traversal_and_outside_paths() {
        assert!(matches!(
            TrustedLocalPath::from_root("/tmp", PathBuf::from("relative/gate")),
            Err(TrustedLocalPathError::PathNotAbsolute)
        ));
        assert!(matches!(
            TrustedLocalPath::from_root("/tmp", PathBuf::from("/tmp/../etc/gate")),
            Err(TrustedLocalPathError::PathTraversal)
        ));
        assert!(matches!(
            TrustedLocalPath::from_root("/tmp", PathBuf::from("/etc/gate")),
            Err(TrustedLocalPathError::OutsideRoot)
        ));
    }
}
