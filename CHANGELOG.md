# Changelog

All notable public package changes should be recorded here once the Rust crates
are approved for publication.

## Unreleased

- Clarified the independent Sedna Labs MCP Toolkit for Rust identity and
  non-affiliation boundary in the public README and release documentation.
- Added consistent crates.io metadata to the nine first-wave manifests,
  including component descriptions, keywords, categories, and the documented
  Rust 1.88 compatibility floor; the reviewed candidate enables only these
  nine manifests while publication execution remains disabled.
- Added hosted first-wave Cargo package readiness validation for the planned
  Rust crate set.
- Added docs.rs metadata requirements for first-wave crates.
- Expanded the approved 0.1.0 package-readiness candidate to exactly nine
  crates, including `mcp-toolkit-scratchpad` and `mcp-toolkit-server`.
- Documented ordered manual publication, yank/consumer rollback guidance, and
  the later-version OIDC trusted-publisher workflow path.
- Added the manual first-release GitHub bootstrap workflow and fail-closed
  crates.io registry evidence helper; it uses only the protected `crates-io`
  environment token path, supports exact-artifact resume, and records
  provenance without creating a tag or release.
- Kept crates unpublished pending explicit release-owner and publication-path
  approval.

## 0.1.0 - Unpublished

- Initial pre-1.0 Rust crate layout for public Git dependency consumers.
- Planned first-wave crates:
  `mcp-toolkit-core`, `mcp-toolkit-observability`,
  `mcp-toolkit-policy-core`, `mcp-toolkit-http`, `mcp-toolkit-scratchpad`,
  `mcp-toolkit-testing`, `mcp-toolkit-policy-conformance`, `mcp-toolkit-auth`,
  and `mcp-toolkit-server`.
