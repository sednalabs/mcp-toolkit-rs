# Startup provenance admission

`mcp-toolkit-provenance` separates startup admission from artifact publication.
The admission API has no writer and does not turn request data into a filesystem
path. Deployment or build machinery publishes the artifact through its own
trusted channel, then supplies the artifact's canonical `sha256:` digest in the
immutable launch/configuration policy.

At startup, bind an absolute operator-selected directory once with
`TrustedGateRoot`. Bind the relative artifact path to a `GateArtifactSource`,
which retains the final parent directory capability and one basename. Admission
opens that basename with symlink/reparse following disabled, rejects directories
and other non-regular files, and reads at most 64 KiB plus one byte. The bytes
are hashed and compared to the expected digest before JSON deserialization.
Consequently, malformed or semantically invalid bytes cannot become an admitted
artifact merely because they are reachable at the configured path.

The same opened handle supplies the bounded bytes used for hashing and parsing.
Replacing the root or an intermediate directory after binding cannot redirect
the retained capability. Replacing the final name before opening selects the
current name, whose bytes must still match the expected digest; replacing it
after opening does not change the retained handle's bytes. Hard links are
content-authenticated by the digest. FIFOs, sockets, devices, junctions,
symlinks, and reparse points are not regular gate artifacts and are rejected
without an unbounded blocking read.

Gate timestamps (`issued_at` and `expires_at`) and current build identity are
validated only after the exact bytes pass the digest check. Binary modification
time remains available in runtime attestation for observation, but it is never
used to accept or reject startup admission. Production mode requires
`StartupAdmissionMode::Strict`; production cannot use warning, disabled, or
bypass admission modes.

This contract assumes that the digest delivered through the launch/configuration
channel is itself trusted and that publication is governed outside this crate.
It does not claim adversary-resistant named-path publication, durable storage,
or production commissioning.
