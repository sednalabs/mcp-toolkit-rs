//! # MCP Toolkit Private Artifact
//!
//! Descriptor-bound, read-only custody for private local artifacts.
//!
//! ## Rationale
//! MCP servers often consume operator-prepared files whose pathnames can be
//! replaced between admission and use. This crate keeps the admitted file and
//! every directory below its private root open, then revalidates the namespace
//! and exact content before releasing bytes to the caller.
//!
//! ## Security Boundaries
//! * The root, nested directories, and file must be owned by the effective user
//!   and deny group/world permissions.
//! * Each component is opened relative to a held descriptor without following
//!   symbolic links.
//! * The final node must be a single-link regular file within a caller-defined
//!   size bound capped by [`MAX_PRIVATE_ARTIFACT_BYTES`]. Empty files are valid
//!   exact artifacts.
//! * Subsequent reads must match the admitted identity, metadata, length, and
//!   SHA-256 digest.
//! * Errors contain stable codes only; paths and artifact bytes are omitted.
//! * The current implementation is Linux-specific and fails closed elsewhere.
//!
//! This crate does not browse directories, write artifacts, validate artifact
//! semantics, authenticate callers, or attest external provider state.
//!
//! ```no_run
//! use mcp_toolkit_private_artifact::{DescriptorBoundArtifact, PrivateArtifactPolicy};
//! use std::path::Path;
//!
//! # fn read_candidate() -> Result<(), Box<dyn std::error::Error>> {
//! let policy = PrivateArtifactPolicy::new(16 * 1024 * 1024)?;
//! let artifact = DescriptorBoundArtifact::open(
//!     Path::new("/srv/example/private"),
//!     Path::new("/srv/example/private/candidate.bin"),
//!     policy,
//! )?;
//! let admitted = artifact.read()?;
//! assert_eq!(admitted.proof(), artifact.proof());
//! let bytes = admitted.into_bytes();
//! # let _ = bytes;
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::path::Path;

/// Absolute ceiling for one in-memory private artifact read (256 MiB).
///
/// Callers must choose an equal or smaller limit through
/// [`PrivateArtifactPolicy::new`]. This ceiling prevents an untrusted or
/// mistaken caller from authorizing an effectively unbounded allocation.
pub const MAX_PRIVATE_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

/// Configures the maximum accepted artifact size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateArtifactPolicy {
    max_bytes: u64,
}

impl PrivateArtifactPolicy {
    /// Creates a policy with one non-zero inclusive byte limit.
    ///
    /// # Errors
    /// Returns [`PrivateArtifactError::InvalidSizeLimit`] when `max_bytes` is
    /// zero or exceeds [`MAX_PRIVATE_ARTIFACT_BYTES`].
    ///
    /// # Security
    /// Callers should choose the smallest bound that accommodates their
    /// artifact format. The bound is checked before allocation and again when
    /// the held descriptor is read.
    pub const fn new(max_bytes: u64) -> Result<Self, PrivateArtifactError> {
        if max_bytes == 0 || max_bytes > MAX_PRIVATE_ARTIFACT_BYTES {
            return Err(PrivateArtifactError::InvalidSizeLimit);
        }
        Ok(Self { max_bytes })
    }

    /// Returns the inclusive artifact byte limit.
    #[must_use]
    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }
}

/// Identifies the exact bytes admitted from a held artifact descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactProof {
    byte_count: u64,
    sha256: [u8; 32],
}

impl ArtifactProof {
    /// Returns the admitted byte count.
    #[must_use]
    pub const fn byte_count(self) -> u64 {
        self.byte_count
    }

    /// Returns the SHA-256 digest of the admitted bytes.
    #[must_use]
    pub const fn sha256(self) -> [u8; 32] {
        self.sha256
    }

    /// Renders the SHA-256 digest as lowercase hexadecimal.
    #[must_use]
    pub fn sha256_hex(self) -> String {
        self.sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// Couples bytes from a revalidated descriptor to their admission proof.
#[derive(PartialEq, Eq)]
pub struct ArtifactRead {
    bytes: Vec<u8>,
    proof: ArtifactProof,
}

impl fmt::Debug for ArtifactRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactRead")
            .field("byte_count", &self.proof.byte_count())
            .field("sha256", &self.proof.sha256_hex())
            .finish_non_exhaustive()
    }
}

impl ArtifactRead {
    /// Borrows the revalidated artifact bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the proof bound to these bytes.
    #[must_use]
    pub const fn proof(&self) -> ArtifactProof {
        self.proof
    }

    /// Consumes the read product and returns its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Enumerates path-free, content-free custody failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateArtifactError {
    PlatformUnsupported,
    InvalidSizeLimit,
    RootPathInvalid,
    RootUnavailable,
    RootOwnershipMismatch,
    RootModeMismatch,
    UnsafeRootAncestor,
    InputPathInvalid,
    InputOutsideRoot,
    InputAncestorUnsafe,
    InputUnavailable,
    FinalSymlink,
    InputNotRegular,
    InputOwnershipMismatch,
    InputModeMismatch,
    InputHardlinkAmbiguous,
    InputSizeInvalid,
    InputReadFailed,
    InputTruncated,
    InputGrew,
    InputIdentityDrift,
    InputMetadataDrift,
    DescriptorPathDisagreement,
    InputContentDrift,
}

impl PrivateArtifactError {
    /// Returns a stable path-free error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PlatformUnsupported => "private_artifact.platform_unsupported",
            Self::InvalidSizeLimit => "private_artifact.invalid_size_limit",
            Self::RootPathInvalid => "private_artifact.root_path_invalid",
            Self::RootUnavailable => "private_artifact.root_unavailable",
            Self::RootOwnershipMismatch => "private_artifact.root_owner_mismatch",
            Self::RootModeMismatch => "private_artifact.root_mode_mismatch",
            Self::UnsafeRootAncestor => "private_artifact.root_ancestor_unsafe",
            Self::InputPathInvalid => "private_artifact.path_invalid",
            Self::InputOutsideRoot => "private_artifact.outside_root",
            Self::InputAncestorUnsafe => "private_artifact.ancestor_unsafe",
            Self::InputUnavailable => "private_artifact.unavailable",
            Self::FinalSymlink => "private_artifact.final_symlink",
            Self::InputNotRegular => "private_artifact.not_regular",
            Self::InputOwnershipMismatch => "private_artifact.owner_mismatch",
            Self::InputModeMismatch => "private_artifact.mode_mismatch",
            Self::InputHardlinkAmbiguous => "private_artifact.hardlink_ambiguous",
            Self::InputSizeInvalid => "private_artifact.size_invalid",
            Self::InputReadFailed => "private_artifact.read_failed",
            Self::InputTruncated => "private_artifact.truncated",
            Self::InputGrew => "private_artifact.grew",
            Self::InputIdentityDrift => "private_artifact.identity_drift",
            Self::InputMetadataDrift => "private_artifact.metadata_drift",
            Self::DescriptorPathDisagreement => "private_artifact.path_disagreement",
            Self::InputContentDrift => "private_artifact.content_drift",
        }
    }
}

impl fmt::Display for PrivateArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PrivateArtifactError {}

/// Holds one admitted artifact and its directory namespace by descriptor.
pub struct DescriptorBoundArtifact {
    proof: ArtifactProof,
    #[cfg(target_os = "linux")]
    inner: linux::HeldArtifact,
}

impl fmt::Debug for DescriptorBoundArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescriptorBoundArtifact")
            .field("byte_count", &self.proof.byte_count())
            .field("sha256", &self.proof.sha256_hex())
            .finish_non_exhaustive()
    }
}

impl DescriptorBoundArtifact {
    /// Opens and admits one artifact beneath a private root.
    ///
    /// Both paths must be absolute and lexically normalized. The artifact path
    /// must be a descendant of `root_path`, and every node below the root is
    /// opened relative to a held descriptor.
    ///
    /// # Errors
    /// Returns a [`PrivateArtifactError`] when the platform is unsupported, a
    /// path or node violates policy, the file cannot be read exactly within the
    /// configured bound, or namespace/descriptor evidence disagrees.
    ///
    /// # Security
    /// This operation does not authorize the meaning of the artifact. Keep the
    /// returned value alive until the final [`Self::read`] so descriptor and
    /// namespace revalidation can detect replacement.
    pub fn open(
        root_path: &Path,
        input_path: &Path,
        policy: PrivateArtifactPolicy,
    ) -> Result<Self, PrivateArtifactError> {
        #[cfg(target_os = "linux")]
        {
            let (inner, proof) = linux::HeldArtifact::open(root_path, input_path, policy)?;
            Ok(Self { proof, inner })
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root_path, input_path, policy);
            Err(PrivateArtifactError::PlatformUnsupported)
        }
    }

    /// Returns the proof recorded during admission.
    #[must_use]
    pub const fn proof(&self) -> ArtifactProof {
        self.proof
    }

    /// Revalidates and reads the exact admitted bytes.
    ///
    /// # Errors
    /// Returns a [`PrivateArtifactError`] when the descriptor, file metadata,
    /// namespace, length, or content digest no longer matches admission, or
    /// when the exact bounded read fails.
    ///
    /// # Security
    /// The returned [`ArtifactRead`] couples the bytes with their admission
    /// proof. Callers remain responsible for parsing and semantic validation.
    pub fn read(&self) -> Result<ArtifactRead, PrivateArtifactError> {
        #[cfg(target_os = "linux")]
        {
            let bytes = self.inner.read(self.proof)?;
            Ok(ArtifactRead {
                bytes,
                proof: self.proof,
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(PrivateArtifactError::PlatformUnsupported)
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{ArtifactProof, PrivateArtifactError, PrivateArtifactPolicy};
    use libc::{O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, O_RDONLY};
    use sha2::{Digest, Sha256};
    use std::ffi::{CString, OsStr, OsString};
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
    use std::path::{Component, Path, PathBuf};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ArtifactSnapshot {
        identity: FileIdentity,
        length: u64,
        mode: u32,
        uid: u32,
        links: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }

    impl ArtifactSnapshot {
        fn from_metadata(metadata: &Metadata) -> Self {
            Self {
                identity: file_identity(metadata),
                length: metadata.len(),
                mode: metadata.mode(),
                uid: metadata.uid(),
                links: metadata.nlink(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            }
        }
    }

    struct HeldDirectory {
        name: OsString,
        file: File,
        identity: FileIdentity,
    }

    pub(super) struct HeldArtifact {
        root_path: PathBuf,
        root: File,
        root_identity: FileIdentity,
        directories: Vec<HeldDirectory>,
        file_name: OsString,
        file: File,
        snapshot: ArtifactSnapshot,
        policy: PrivateArtifactPolicy,
    }

    fn effective_uid() -> u32 {
        // SAFETY: geteuid has no arguments and no memory-safety preconditions.
        unsafe { libc::geteuid() }
    }

    fn file_identity(metadata: &Metadata) -> FileIdentity {
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn private_owner(uid: u32) -> bool {
        uid == effective_uid()
    }

    fn trusted_ancestor_owner(uid: u32) -> bool {
        uid == 0 || private_owner(uid)
    }

    fn private_mode(mode: u32) -> bool {
        mode & 0o077 == 0
    }

    fn private_directory(metadata: &Metadata) -> bool {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && private_owner(metadata.uid())
            && private_mode(metadata.mode())
    }

    fn safe_root_ancestor(metadata: &Metadata) -> bool {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && trusted_ancestor_owner(metadata.uid())
            && (metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0)
    }

    fn normal_absolute_path(path: &Path) -> bool {
        path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    }

    fn validate_root_and_ancestors(root: &Path) -> Result<Metadata, PrivateArtifactError> {
        if !normal_absolute_path(root) {
            return Err(PrivateArtifactError::RootPathInvalid);
        }
        let metadata =
            fs::symlink_metadata(root).map_err(|_| PrivateArtifactError::RootUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(PrivateArtifactError::RootUnavailable);
        }
        if !private_owner(metadata.uid()) {
            return Err(PrivateArtifactError::RootOwnershipMismatch);
        }
        if !private_mode(metadata.mode()) {
            return Err(PrivateArtifactError::RootModeMismatch);
        }
        for ancestor in root.ancestors().skip(1) {
            let metadata = fs::symlink_metadata(ancestor)
                .map_err(|_| PrivateArtifactError::UnsafeRootAncestor)?;
            if !safe_root_ancestor(&metadata) {
                return Err(PrivateArtifactError::UnsafeRootAncestor);
            }
        }
        Ok(metadata)
    }

    fn open_at(parent: &File, name: &OsStr, flags: i32) -> io::Result<File> {
        let name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"))?;
        // SAFETY: parent is a live descriptor, name is NUL-terminated, the call
        // requests read-only access, and a successful descriptor is immediately
        // transferred into File ownership exactly once.
        let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, 0) };
        if descriptor < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: openat returned a new owned descriptor on success.
            Ok(unsafe { File::from_raw_fd(descriptor) })
        }
    }

    fn open_directory(parent: &File, name: &OsStr) -> io::Result<File> {
        open_at(
            parent,
            name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
        )
    }

    fn open_regular(parent: &File, name: &OsStr) -> io::Result<File> {
        open_at(parent, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
    }

    fn classify_file_metadata(
        metadata: &Metadata,
        policy: PrivateArtifactPolicy,
    ) -> Result<(), PrivateArtifactError> {
        if metadata.file_type().is_symlink() {
            return Err(PrivateArtifactError::FinalSymlink);
        }
        if !metadata.is_file() {
            return Err(PrivateArtifactError::InputNotRegular);
        }
        if !private_owner(metadata.uid()) {
            return Err(PrivateArtifactError::InputOwnershipMismatch);
        }
        if !private_mode(metadata.mode()) {
            return Err(PrivateArtifactError::InputModeMismatch);
        }
        if metadata.nlink() != 1 {
            return Err(PrivateArtifactError::InputHardlinkAmbiguous);
        }
        if metadata.len() > policy.max_bytes() {
            return Err(PrivateArtifactError::InputSizeInvalid);
        }
        Ok(())
    }

    fn read_exact_snapshot(
        file: &File,
        snapshot: ArtifactSnapshot,
        policy: PrivateArtifactPolicy,
    ) -> Result<Vec<u8>, PrivateArtifactError> {
        let before = file
            .metadata()
            .map_err(|_| PrivateArtifactError::InputReadFailed)?;
        classify_file_metadata(&before, policy)?;
        let before = ArtifactSnapshot::from_metadata(&before);
        if before.identity != snapshot.identity {
            return Err(PrivateArtifactError::InputIdentityDrift);
        }
        if before.length < snapshot.length {
            return Err(PrivateArtifactError::InputTruncated);
        }
        if before.length > snapshot.length {
            return Err(PrivateArtifactError::InputGrew);
        }
        if before != snapshot {
            return Err(PrivateArtifactError::InputMetadataDrift);
        }

        let length =
            usize::try_from(snapshot.length).map_err(|_| PrivateArtifactError::InputSizeInvalid)?;
        let mut bytes = vec![0_u8; length];
        let mut offset = 0_usize;
        while offset < length {
            let read = file
                .read_at(&mut bytes[offset..], offset as u64)
                .map_err(|_| PrivateArtifactError::InputReadFailed)?;
            if read == 0 {
                return Err(PrivateArtifactError::InputTruncated);
            }
            offset += read;
        }

        let mut sentinel = [0_u8; 1];
        if file
            .read_at(&mut sentinel, snapshot.length)
            .map_err(|_| PrivateArtifactError::InputReadFailed)?
            != 0
        {
            return Err(PrivateArtifactError::InputGrew);
        }

        let after = file
            .metadata()
            .map_err(|_| PrivateArtifactError::InputReadFailed)?;
        classify_file_metadata(&after, policy)?;
        let after = ArtifactSnapshot::from_metadata(&after);
        if after.identity != snapshot.identity {
            return Err(PrivateArtifactError::InputIdentityDrift);
        }
        if after.length < snapshot.length {
            return Err(PrivateArtifactError::InputTruncated);
        }
        if after.length > snapshot.length {
            return Err(PrivateArtifactError::InputGrew);
        }
        if after != snapshot {
            return Err(PrivateArtifactError::InputMetadataDrift);
        }
        Ok(bytes)
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    impl HeldArtifact {
        pub(super) fn open(
            root_path: &Path,
            input_path: &Path,
            policy: PrivateArtifactPolicy,
        ) -> Result<(Self, ArtifactProof), PrivateArtifactError> {
            let root_metadata = validate_root_and_ancestors(root_path)?;
            if !normal_absolute_path(input_path) {
                return Err(PrivateArtifactError::InputPathInvalid);
            }
            let relative = input_path
                .strip_prefix(root_path)
                .map_err(|_| PrivateArtifactError::InputOutsideRoot)?;
            let components = relative
                .components()
                .map(|part| match part {
                    Component::Normal(value) => Ok(value.to_os_string()),
                    _ => Err(PrivateArtifactError::InputPathInvalid),
                })
                .collect::<Result<Vec<_>, _>>()?;
            let (file_name, directory_names) = components
                .split_last()
                .ok_or(PrivateArtifactError::InputPathInvalid)?;

            let root = OpenOptions::new()
                .read(true)
                .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                .open(root_path)
                .map_err(|_| PrivateArtifactError::RootUnavailable)?;
            let held_root = root
                .metadata()
                .map_err(|_| PrivateArtifactError::RootUnavailable)?;
            if !private_directory(&held_root)
                || file_identity(&held_root) != file_identity(&root_metadata)
            {
                return Err(PrivateArtifactError::RootUnavailable);
            }

            let mut directories = Vec::new();
            let mut parent = &root;
            for name in directory_names {
                let directory = open_directory(parent, name)
                    .map_err(|_| PrivateArtifactError::InputAncestorUnsafe)?;
                let metadata = directory
                    .metadata()
                    .map_err(|_| PrivateArtifactError::InputAncestorUnsafe)?;
                if !private_directory(&metadata) {
                    return Err(PrivateArtifactError::InputAncestorUnsafe);
                }
                directories.push(HeldDirectory {
                    name: name.clone(),
                    identity: file_identity(&metadata),
                    file: directory,
                });
                parent = directories
                    .last()
                    .map(|held| &held.file)
                    .ok_or(PrivateArtifactError::InputAncestorUnsafe)?;
            }

            let file = match open_regular(parent, file_name) {
                Ok(file) => file,
                Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                    return Err(PrivateArtifactError::FinalSymlink);
                }
                Err(_) => return Err(PrivateArtifactError::InputUnavailable),
            };
            let metadata = file
                .metadata()
                .map_err(|_| PrivateArtifactError::InputUnavailable)?;
            classify_file_metadata(&metadata, policy)?;
            let snapshot = ArtifactSnapshot::from_metadata(&metadata);
            let bytes = read_exact_snapshot(&file, snapshot, policy)?;
            let proof = ArtifactProof {
                byte_count: snapshot.length,
                sha256: sha256(&bytes),
            };
            let artifact = Self {
                root_path: root_path.to_path_buf(),
                root,
                root_identity: file_identity(&root_metadata),
                directories,
                file_name: file_name.clone(),
                file,
                snapshot,
                policy,
            };
            artifact.revalidate_namespace()?;
            Ok((artifact, proof))
        }

        pub(super) fn read(&self, proof: ArtifactProof) -> Result<Vec<u8>, PrivateArtifactError> {
            self.revalidate_namespace()?;
            let bytes = read_exact_snapshot(&self.file, self.snapshot, self.policy)?;
            if sha256(&bytes) != proof.sha256() {
                return Err(PrivateArtifactError::InputContentDrift);
            }
            self.revalidate_namespace()?;
            Ok(bytes)
        }

        fn revalidate_namespace(&self) -> Result<(), PrivateArtifactError> {
            let root_metadata = validate_root_and_ancestors(&self.root_path)?;
            let held_root = self
                .root
                .metadata()
                .map_err(|_| PrivateArtifactError::RootUnavailable)?;
            if !private_directory(&held_root)
                || file_identity(&held_root) != self.root_identity
                || file_identity(&root_metadata) != self.root_identity
            {
                return Err(PrivateArtifactError::DescriptorPathDisagreement);
            }

            let mut parent = &self.root;
            for directory in &self.directories {
                let held = directory
                    .file
                    .metadata()
                    .map_err(|_| PrivateArtifactError::InputAncestorUnsafe)?;
                let named = open_directory(parent, &directory.name)
                    .map_err(|_| PrivateArtifactError::InputAncestorUnsafe)?;
                let named = named
                    .metadata()
                    .map_err(|_| PrivateArtifactError::InputAncestorUnsafe)?;
                if !private_directory(&held)
                    || !private_directory(&named)
                    || file_identity(&held) != directory.identity
                    || file_identity(&named) != directory.identity
                {
                    return Err(PrivateArtifactError::DescriptorPathDisagreement);
                }
                parent = &directory.file;
            }

            let held = self
                .file
                .metadata()
                .map_err(|_| PrivateArtifactError::InputUnavailable)?;
            classify_file_metadata(&held, self.policy)?;
            let named = open_regular(parent, &self.file_name)
                .map_err(|_| PrivateArtifactError::DescriptorPathDisagreement)?;
            let named = named
                .metadata()
                .map_err(|_| PrivateArtifactError::DescriptorPathDisagreement)?;
            classify_file_metadata(&named, self.policy)?;
            if file_identity(&held) != self.snapshot.identity
                || file_identity(&named) != self.snapshot.identity
            {
                return Err(PrivateArtifactError::DescriptorPathDisagreement);
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            ArtifactProof, ArtifactRead, DescriptorBoundArtifact, PrivateArtifactError,
            PrivateArtifactPolicy, MAX_PRIVATE_ARTIFACT_BYTES,
        };
        use std::ffi::CString;
        use std::fs::Permissions;
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;
        use tempfile::TempDir;

        const CONTENT: &[u8] = b"synthetic artifact bytes\n";

        struct Fixture {
            base: TempDir,
            root: PathBuf,
            input: PathBuf,
        }

        impl Fixture {
            fn new(label: &str) -> Self {
                let base = tempfile::Builder::new()
                    .prefix(&format!("toolkit-private-artifact-{label}-"))
                    .tempdir()
                    .expect("create fixture base");
                let root = base.path().join("root");
                let nested = root.join("nested");
                fs::create_dir_all(&nested).expect("create fixture directories");
                fs::set_permissions(base.path(), Permissions::from_mode(0o700))
                    .expect("private base");
                fs::set_permissions(&root, Permissions::from_mode(0o700)).expect("private root");
                fs::set_permissions(&nested, Permissions::from_mode(0o700))
                    .expect("private nested directory");
                let input = nested.join("candidate.bin");
                fs::write(&input, CONTENT).expect("write candidate");
                fs::set_permissions(&input, Permissions::from_mode(0o600))
                    .expect("private candidate");
                Self { base, root, input }
            }

            fn policy(&self) -> PrivateArtifactPolicy {
                PrivateArtifactPolicy::new(1024).expect("valid fixture policy")
            }
        }

        fn replace_with_fifo(path: &Path) {
            let path = CString::new(path.as_os_str().as_bytes()).expect("FIFO path");
            // SAFETY: path is a valid NUL-terminated pathname and mode is valid.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        }

        fn bounded_custody_error(
            operation: impl FnOnce() -> Result<(), PrivateArtifactError> + Send + 'static,
        ) -> PrivateArtifactError {
            let (sender, receiver) = mpsc::channel();
            thread::spawn(move || {
                let _ = sender.send(operation());
            });
            receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("custody operation must not block")
                .expect_err("custody operation must fail closed")
        }

        #[test]
        fn round_trip_is_descriptor_bound_and_content_hashed() {
            let fixture = Fixture::new("round-trip");
            let artifact =
                DescriptorBoundArtifact::open(&fixture.root, &fixture.input, fixture.policy())
                    .expect("open artifact");
            let admitted = artifact.read().expect("stable read");
            assert_eq!(admitted.bytes(), CONTENT);
            assert_eq!(admitted.proof(), artifact.proof());
            assert_eq!(artifact.proof().byte_count(), CONTENT.len() as u64);
            assert_eq!(artifact.proof().sha256(), sha256(CONTENT));
            let debug = format!("{artifact:?}");
            assert!(!debug.contains(fixture.input.to_string_lossy().as_ref()));
            assert!(!debug.contains("synthetic artifact"));
        }

        #[test]
        fn empty_artifact_is_an_exact_whole_read_product() {
            let fixture = Fixture::new("empty-round-trip");
            fs::write(&fixture.input, b"").expect("write empty candidate");
            let artifact =
                DescriptorBoundArtifact::open(&fixture.root, &fixture.input, fixture.policy())
                    .expect("open empty artifact");
            let empty_sha256 = [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ];
            let expected_proof = ArtifactProof {
                byte_count: 0,
                sha256: empty_sha256,
            };
            let expected = ArtifactRead {
                bytes: Vec::new(),
                proof: expected_proof,
            };
            let hex_digits = b"0123456789abcdef";
            let mut expected_hex = String::with_capacity(64);
            for byte in empty_sha256 {
                expected_hex.push(char::from(hex_digits[usize::from(byte >> 4)]));
                expected_hex.push(char::from(hex_digits[usize::from(byte & 0x0f)]));
            }

            assert_eq!(artifact.proof(), expected_proof);
            assert_eq!(artifact.read().expect("read empty artifact"), expected);
            assert_eq!(artifact.proof().sha256_hex(), expected_hex);
        }

        #[test]
        fn final_symlink_unsafe_modes_and_hardlinks_fail_closed() {
            let final_symlink = Fixture::new("final-symlink");
            fs::remove_file(&final_symlink.input).expect("remove candidate");
            symlink("/dev/null", &final_symlink.input).expect("create symlink");
            assert_eq!(
                DescriptorBoundArtifact::open(
                    &final_symlink.root,
                    &final_symlink.input,
                    final_symlink.policy(),
                )
                .expect_err("final symlink must fail"),
                PrivateArtifactError::FinalSymlink
            );

            let ancestor_mode = Fixture::new("ancestor-mode");
            fs::set_permissions(ancestor_mode.base.path(), Permissions::from_mode(0o777))
                .expect("make ancestor unsafe");
            assert_eq!(
                DescriptorBoundArtifact::open(
                    &ancestor_mode.root,
                    &ancestor_mode.input,
                    ancestor_mode.policy(),
                )
                .expect_err("unsafe ancestor must fail"),
                PrivateArtifactError::UnsafeRootAncestor
            );

            let symlink_ancestor = Fixture::new("symlink-ancestor");
            let real_nested = symlink_ancestor.root.join("nested-real");
            fs::rename(symlink_ancestor.root.join("nested"), &real_nested)
                .expect("move nested directory");
            symlink(&real_nested, symlink_ancestor.root.join("nested"))
                .expect("replace ancestor with symlink");
            assert_eq!(
                DescriptorBoundArtifact::open(
                    &symlink_ancestor.root,
                    &symlink_ancestor.input,
                    symlink_ancestor.policy(),
                )
                .expect_err("symlink ancestor must fail"),
                PrivateArtifactError::InputAncestorUnsafe
            );

            let root_mode = Fixture::new("root-mode");
            fs::set_permissions(&root_mode.root, Permissions::from_mode(0o750))
                .expect("make root unsafe");
            assert_eq!(
                DescriptorBoundArtifact::open(
                    &root_mode.root,
                    &root_mode.input,
                    root_mode.policy(),
                )
                .expect_err("unsafe root mode must fail"),
                PrivateArtifactError::RootModeMismatch
            );

            let input_mode = Fixture::new("input-mode");
            fs::set_permissions(&input_mode.input, Permissions::from_mode(0o640))
                .expect("make input unsafe");
            assert_eq!(
                DescriptorBoundArtifact::open(
                    &input_mode.root,
                    &input_mode.input,
                    input_mode.policy(),
                )
                .expect_err("unsafe input mode must fail"),
                PrivateArtifactError::InputModeMismatch
            );

            let hardlink = Fixture::new("hardlink");
            fs::hard_link(&hardlink.input, hardlink.root.join("alias.bin"))
                .expect("create hardlink");
            assert_eq!(
                DescriptorBoundArtifact::open(&hardlink.root, &hardlink.input, hardlink.policy(),)
                    .expect_err("hardlink ambiguity must fail"),
                PrivateArtifactError::InputHardlinkAmbiguous
            );
        }

        #[test]
        fn fifo_candidates_fail_without_blocking_open_or_revalidation() {
            let initial = Fixture::new("initial-fifo");
            fs::remove_file(&initial.input).expect("remove regular candidate");
            replace_with_fifo(&initial.input);
            let root = initial.root.clone();
            let input = initial.input.clone();
            let policy = initial.policy();
            assert_eq!(
                bounded_custody_error(move || {
                    DescriptorBoundArtifact::open(&root, &input, policy).map(|_| ())
                }),
                PrivateArtifactError::InputNotRegular
            );

            let revalidation = Fixture::new("revalidation-fifo");
            let artifact = DescriptorBoundArtifact::open(
                &revalidation.root,
                &revalidation.input,
                revalidation.policy(),
            )
            .expect("open regular artifact");
            fs::rename(
                &revalidation.input,
                revalidation.input.with_extension("old"),
            )
            .expect("displace regular candidate");
            replace_with_fifo(&revalidation.input);
            assert_eq!(
                bounded_custody_error(move || artifact.read().map(|_| ())),
                PrivateArtifactError::InputNotRegular
            );
        }

        #[test]
        fn file_and_directory_substitution_fail_closed() {
            let file_replacement = Fixture::new("file-replacement");
            let artifact = DescriptorBoundArtifact::open(
                &file_replacement.root,
                &file_replacement.input,
                file_replacement.policy(),
            )
            .expect("open artifact");
            fs::rename(
                &file_replacement.input,
                file_replacement.input.with_extension("old"),
            )
            .expect("displace candidate");
            fs::write(&file_replacement.input, CONTENT).expect("write replacement");
            fs::set_permissions(&file_replacement.input, Permissions::from_mode(0o600))
                .expect("make replacement private");
            assert_eq!(
                artifact.read().expect_err("replacement must fail"),
                PrivateArtifactError::DescriptorPathDisagreement
            );

            let directory_replacement = Fixture::new("directory-replacement");
            let artifact = DescriptorBoundArtifact::open(
                &directory_replacement.root,
                &directory_replacement.input,
                directory_replacement.policy(),
            )
            .expect("open artifact");
            let nested = directory_replacement.root.join("nested");
            let displaced = directory_replacement.root.join("nested-old");
            fs::rename(&nested, &displaced).expect("displace directory");
            fs::create_dir(&nested).expect("create replacement directory");
            fs::set_permissions(&nested, Permissions::from_mode(0o700))
                .expect("make replacement directory private");
            fs::write(&directory_replacement.input, CONTENT).expect("write replacement input");
            fs::set_permissions(&directory_replacement.input, Permissions::from_mode(0o600))
                .expect("make replacement input private");
            assert_eq!(
                artifact
                    .read()
                    .expect_err("directory substitution must fail"),
                PrivateArtifactError::DescriptorPathDisagreement
            );
        }

        #[test]
        fn growth_truncation_and_equal_length_content_drift_fail_closed() {
            let growth = Fixture::new("growth");
            let artifact =
                DescriptorBoundArtifact::open(&growth.root, &growth.input, growth.policy())
                    .expect("open artifact");
            OpenOptions::new()
                .append(true)
                .open(&growth.input)
                .expect("open candidate for append")
                .write_all(b"growth")
                .expect("grow candidate");
            assert_eq!(
                artifact.read().expect_err("growth must fail"),
                PrivateArtifactError::InputGrew
            );

            let truncation = Fixture::new("truncation");
            let artifact = DescriptorBoundArtifact::open(
                &truncation.root,
                &truncation.input,
                truncation.policy(),
            )
            .expect("open artifact");
            OpenOptions::new()
                .write(true)
                .open(&truncation.input)
                .expect("open candidate for truncation")
                .set_len(4)
                .expect("truncate candidate");
            assert_eq!(
                artifact.read().expect_err("truncation must fail"),
                PrivateArtifactError::InputTruncated
            );

            let content = Fixture::new("content-drift");
            let artifact =
                DescriptorBoundArtifact::open(&content.root, &content.input, content.policy())
                    .expect("open artifact");
            let mut changed = CONTENT.to_vec();
            changed[0] ^= 1;
            fs::write(&content.input, changed).expect("replace equal-length content");
            assert!(matches!(
                artifact
                    .read()
                    .expect_err("equal-length content drift must fail"),
                PrivateArtifactError::InputMetadataDrift | PrivateArtifactError::InputContentDrift
            ));
        }

        #[test]
        fn path_size_and_error_surfaces_are_closed() {
            assert_eq!(
                PrivateArtifactPolicy::new(0).expect_err("zero bound must fail"),
                PrivateArtifactError::InvalidSizeLimit
            );

            let outside_fixture = Fixture::new("outside");
            let outside = outside_fixture.base.path().join("outside.bin");
            fs::write(&outside, CONTENT).expect("write outside file");
            fs::set_permissions(&outside, Permissions::from_mode(0o600))
                .expect("make outside file private");
            assert_eq!(
                DescriptorBoundArtifact::open(
                    &outside_fixture.root,
                    &outside,
                    outside_fixture.policy(),
                )
                .expect_err("outside path must fail"),
                PrivateArtifactError::InputOutsideRoot
            );

            let exact_ceiling = PrivateArtifactPolicy::new(MAX_PRIVATE_ARTIFACT_BYTES)
                .expect("absolute ceiling must be accepted without allocation");
            assert_eq!(exact_ceiling.max_bytes(), MAX_PRIVATE_ARTIFACT_BYTES);
            assert_eq!(
                PrivateArtifactPolicy::new(MAX_PRIVATE_ARTIFACT_BYTES + 1)
                    .expect_err("one byte over the absolute ceiling must fail"),
                PrivateArtifactError::InvalidSizeLimit
            );

            let oversized = Fixture::new("oversized");
            let policy = PrivateArtifactPolicy::new(8).expect("small policy");
            assert_eq!(
                DescriptorBoundArtifact::open(&oversized.root, &oversized.input, policy)
                    .expect_err("oversized candidate must fail"),
                PrivateArtifactError::InputSizeInvalid
            );

            let unsafe_mode = Fixture::new("error-leakage");
            fs::set_permissions(&unsafe_mode.input, Permissions::from_mode(0o644))
                .expect("make mode unsafe");
            let error = DescriptorBoundArtifact::open(
                &unsafe_mode.root,
                &unsafe_mode.input,
                unsafe_mode.policy(),
            )
            .expect_err("unsafe mode must fail");
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains(unsafe_mode.input.to_string_lossy().as_ref()));
            assert!(!rendered.contains("synthetic artifact"));
            assert_eq!(error.code(), "private_artifact.mode_mismatch");
        }

        #[test]
        fn ownership_and_device_inode_helpers_reject_mismatch() {
            assert!(!private_owner(effective_uid().wrapping_add(1)));
            assert!(trusted_ancestor_owner(0));
            assert!(trusted_ancestor_owner(effective_uid()));
            let foreign_uid = [1, 2, u32::MAX]
                .into_iter()
                .find(|uid| *uid != 0 && *uid != effective_uid())
                .expect("foreign uid fixture");
            assert!(!trusted_ancestor_owner(foreign_uid));

            let expected = FileIdentity {
                device: 1,
                inode: 2,
            };
            assert_ne!(
                expected,
                FileIdentity {
                    device: 2,
                    inode: 2,
                }
            );
            assert_ne!(
                expected,
                FileIdentity {
                    device: 1,
                    inode: 3,
                }
            );
        }
    }
}
