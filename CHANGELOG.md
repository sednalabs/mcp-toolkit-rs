# Changelog

All notable public package changes should be recorded here once the Rust crates
are approved for publication.

## Unreleased

- Raised the Toolkit compiler pin and declared compatibility floor to Rust
  1.99.0 / 1.99 across crates and templates; RMCP 3.5.0 retains its own 1.88
  MSRV, and generated-server checks report the compiler selected in each
  temporary project.
- Clarified the independent Sedna Labs MCP Toolkit for Rust identity and
  non-affiliation boundary in the public README and release documentation.
- Added consistent crates.io metadata to the nine first-wave manifests,
  including component descriptions, keywords, categories, and the then-current
  Rust 1.88 compatibility floor; the reviewed candidate enables only these
  nine manifests while publication execution remains disabled.
- Added hosted first-wave Cargo package readiness validation for the planned
  Rust crate set.
- Added docs.rs metadata requirements for first-wave crates.
- Expanded the approved 0.1.0 package-readiness candidate to exactly nine
  crates, including `mcp-toolkit-scratchpad` and `mcp-toolkit-server`.
- Documented ordered manual publication, yank/consumer rollback guidance, and
  the later-version OIDC trusted-publisher workflow path.
- Kept crates unpublished pending explicit release-owner and publication-path
  approval.

## 0.1.0 - Unpublished

- Initial pre-1.0 Rust crate layout for public Git dependency consumers.
- Planned first-wave crates:
  `mcp-toolkit-core`, `mcp-toolkit-observability`,
  `mcp-toolkit-policy-core`, `mcp-toolkit-http`, `mcp-toolkit-scratchpad`,
  `mcp-toolkit-testing`, `mcp-toolkit-policy-conformance`, `mcp-toolkit-auth`,
  and `mcp-toolkit-server`.
