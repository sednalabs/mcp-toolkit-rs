# MCP Toolkit Private Artifact

`mcp-toolkit-private-artifact` provides descriptor-bound, read-only custody for
one private local file. It is intended for MCP servers that must consume an
operator-prepared artifact without trusting a pathname again after admission.

The crate:

- requires an absolute, normalized path beneath an explicitly private root;
- opens each path component below the root relative to a held directory
  descriptor and does not follow symbolic links;
- requires the effective user to own the root, nested directories, and file;
- rejects group/world-accessible nodes, non-regular files, and files with more
  than one hard link;
- reads an exact caller-bounded byte count (including a valid zero-byte
  artifact), then rechecks descriptor metadata and the complete namespace
  chain;
- binds later reads to the admitted device/inode, metadata snapshot, length,
  and SHA-256 digest; and
- returns closed, path-free errors.

Every caller limit must be non-zero and no greater than the exported 256 MiB
`MAX_PRIVATE_ARTIFACT_BYTES` absolute ceiling. The current implementation is
Linux-specific and fails closed on other platforms. It does not browse
directories, write files, manage manifests, authenticate callers, call
providers, or authorize what the bytes mean.

```rust,no_run
use mcp_toolkit_private_artifact::{DescriptorBoundArtifact, PrivateArtifactPolicy};
use std::path::Path;

# fn read_candidate() -> Result<(), Box<dyn std::error::Error>> {
let policy = PrivateArtifactPolicy::new(16 * 1024 * 1024)?;
let artifact = DescriptorBoundArtifact::open(
    Path::new("/srv/example/private"),
    Path::new("/srv/example/private/candidate.bin"),
    policy,
)?;
let admitted = artifact.read()?;
assert_eq!(admitted.proof(), artifact.proof());
let bytes = admitted.into_bytes();
# let _ = bytes;
# Ok(())
# }
```

Callers still own semantic validation of the returned bytes and must retain the
`DescriptorBoundArtifact` until their final read. A proof describes the bytes
admitted by this process; it is not a signature, provider receipt, or external
attestation.
