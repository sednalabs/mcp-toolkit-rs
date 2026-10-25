# DPoP verifier provenance and local changes

This directory is an unpublished, locally maintained compatibility copy of
[`dpop-verifier` 4.4.0](https://crates.io/crates/dpop-verifier/4.4.0), not a new
upstream release. The package version `4.4.1` identifies the inherited internal
patch only; `publish = false` prevents publishing it as an upstream package.

## Source identity

- Upstream repository: <https://github.com/Ukonhattu/dpop-verifier>.
- Upstream base commit: `aae68f7ef479fa96e8da65d7aab4115205f869ca`.
- Upstream crates.io 4.4.0 archive SHA-256:
  `3ffe26542b84d85fc36fec8dfac45abf0d2f93c2d5ee9ffdebe3bb22a090d016`.
- Inherited internal P-256 compatibility port: `sednalabs/agent-ops` commit
  `971c76e145b0dbf86653c0808c0b2f314a81bbde`, directory
  `vendor/dpop-verifier`.
- Import snapshot: `sednalabs/agent-ops` commit
  `6ae1531336e79fcaf9008fdd334fa7523ba05cf4`, same directory. The imported files
  were checked against the frozen source bytes and Git blob identities.
- Original MIT and Apache-2.0 license files are retained unchanged.

## Narrow compatibility changes

The inherited port moves `p256` from 0.13 to 0.14 and adapts P-256 key parsing,
SEC1 point access, and signature-trait imports to that dependency's API. It uses
fixed valid P-256 test keys. Production proof parsing, signature verification,
claims, nonce policy, thumbprints, and replay admission otherwise retain the
upstream implementation; this is not a new protocol or cryptographic design.

MCP Toolkit additionally:

- Marks this package unpublished and adds crate-level context/documentation.
- Keeps the optional Actix request-helper API while disabling Actix's unrelated
  default server features. Only its test/helper macros are requested. In
  particular, the helper does not need the legacy HTTP/2 dependency; downstream
  applications select their own Actix server features.
- Preserves the deprecated `verify_proof` API and scopes deprecation allowances
  to its compatibility re-export and tests that intentionally exercise it.
- Makes the negative nonce/key-binding fixture use two distinct deterministic
  keys and asserts that their thumbprints differ.
- Turns discarded `matches!` expressions in tests into enforced assertions.
- Makes signature-tampering fixtures change signature bytes while retaining
  valid header/claims encoding; removes their unsafe string mutation and loop.
- Applies Rust formatting. No audit, scanner, or security-policy exceptions are
  supplied by this directory.

The upstream README is retained as historical upstream documentation. Its
registry installation examples do not select this local compatibility copy.
Consumers of MCP Toolkit must resolve the explicit vendored dependency path;
a root-only Cargo patch would not propagate to downstream consumers.

Keep future changes reviewable against these source identities. A dependency
or protocol update requires renewed compatibility, downstream-consumer, and
dependency-governance verification; passing those checks is not an independent
security audit of the original verifier.
