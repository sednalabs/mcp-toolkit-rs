# mcp-toolkit-rs

Reusable Rust building blocks for Model Context Protocol (MCP) servers and
clients.

`mcp-toolkit-rs` is an early public workspace for the shared substrate that
keeps Rust MCP services consistent: auth discovery, HTTP/session support,
policy primitives, tool inventory helpers, observability, process utilities,
and test harnesses. It is pre-1.0 and the Rust crates are not published to
crates.io yet, so adopters should consume it from Git for now.

## What Is Included

| Crate | Purpose |
| --- | --- |
| `mcp-toolkit` | Umbrella crate with optional feature groups. |
| `mcp-toolkit-core` | Protocol-facing helpers, notifications, query-evidence helpers, and tool inventory types. |
| `mcp-toolkit-auth` | Bearer auth, token validation, replay protection, and auth-surface helpers. |
| `mcp-toolkit-http` | OAuth/PRM metadata helpers, device-authorization metadata, and optional streamable HTTP session support. |
| `mcp-toolkit-observability` | Redaction, sanitization, tracing bridge, metrics facade, and optional OTel helpers. |
| `mcp-toolkit-policy-core` | Pure policy decisions, claims helpers, route/scope checks, and SQL read-only classification. |
| `mcp-toolkit-policy-runtime` | Runtime policy authority adapters and capability guard helpers. |
| `mcp-toolkit-policy-conformance` | Reusable conformance harnesses for policy vectors and schemas. |
| `mcp-toolkit-policy-ffi` | Optional dynamic policy-runtime loader. |
| `mcp-toolkit-policy-kernel-adapters` | Compatibility adapters for exact external policy-kernel parity work. |
| `mcp-toolkit-postgres` | PostgreSQL connection and TLS helpers. |
| `mcp-toolkit-process` | Process and signal helpers. |
| `mcp-toolkit-server` | Optional stdio and hosted HTTP server composition helpers. |
| `mcp-toolkit-testing` | Tool-schema and auth-surface contract test helpers. |
| `mcp-toolkit-docs` | Documentation and tool metadata helpers. |
| `mcp-toolkit-gemini` | Optional process-backed Gemini CLI integration helpers. |

`mcp-toolkit-gemini` is intentionally API-key-only. It requires
`GEMINI_API_KEY`, clears inherited process environment state before launching
the Gemini CLI, and does not support browser, account, or home-directory based
Gemini CLI authentication.

## Quick Start

For the complete server creation, validation, review, and release route, start
with `docs/golden-path.md`. For a copyable checklist that turns that route into
a repeatable implementation lane, use `docs/new-server-delivery-lane.md`. For
the operator-facing details that make a server easy to try and debug, use
`docs/easy-server-ergonomics.md`.

Add the specific crates you need from Git:

```toml
[dependencies]
mcp-toolkit-core = { git = "https://github.com/sednalabs/mcp-toolkit-rs", branch = "main" }
mcp-toolkit-http = { git = "https://github.com/sednalabs/mcp-toolkit-rs", branch = "main", features = ["session"] }

[dev-dependencies]
mcp-toolkit-testing = { git = "https://github.com/sednalabs/mcp-toolkit-rs", branch = "main" }
```

Or use the umbrella crate when you want one dependency with explicit feature
selection:

```toml
[dependencies]
mcp-toolkit = {
  git = "https://github.com/sednalabs/mcp-toolkit-rs",
  branch = "main",
  features = ["auth", "http", "policy", "process", "server"]
}
```

Commit the consumer `Cargo.lock` after resolution. The lockfile records the
exact toolkit SHA; manifest `rev` pins are only needed for special cases where a
consumer intentionally wants a long-lived frozen toolkit ref.

See `docs/cargo-package-release.md` for the Rust package release and migration
path. The planned crates.io package names use the concise `mcp-toolkit-*` crate
prefix; npm and PyPI companion packages have separate naming constraints and must
not be inferred from the Rust crate names.

Run the baseline checks from the repository root:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

## A Minimal Adoption Path

For a new Rust MCP server, start with the smallest slice that gives you a
stable public surface:

1. Use `mcp-toolkit-core::tool_inventory` to register the tools your server can
   expose.
2. Use `mcp-toolkit-testing::assert_tool_schema_snapshot` to lock the exported
   `tools/list` contract.
3. Use `mcp-toolkit-core::openai_tool_search` when large OpenAI-facing MCP
   catalogs should publish a reusable `defer_loading` plus `tool_search`
   request fragment, a richer documentation/resource template, and a local
   `allowed_tools` discovery envelope.
4. Use `mcp-toolkit-http::oauth` and `mcp-toolkit-auth::surface` when serving
   MCP over HTTP with OAuth discovery, Protected Resource Metadata, and
   device-authorization metadata for headless MCP client login.
5. Use `mcp-toolkit-server` when you want the toolkit to assemble stdio startup,
   local Streamable HTTP runtime pieces, host guarding, auth-surface layers, and
   the default MCP route bundle.
6. Use `mcp-toolkit-observability` helpers for sanitized logs, bounded labels,
   and optional tracing/metrics integration.
7. Use `mcp-toolkit-core::query_evidence` when a tool response should expose
   provider query-cost and read-only evidence without returning raw provider
   payloads.
8. Add policy crates only when the service has an authorization, SQL
   read-only, or capability-guard boundary that needs reusable enforcement.

For a copyable starting point, see `templates/curated-stdio-intent-server` for
stdio intent tools and `templates/hosted-http-auth-server` for hosted HTTP with
OAuth Protected Resource Metadata, headless device-auth metadata, bearer
challenges, host guarding, schema snapshots, and contract tests.

For existing service adoption, migrate one runtime seam at a time and prove the
before/after contract through GitHub-hosted validation. The checklist in
`docs/golden-path.md` defines the expected handoff, review gate, and release
evidence.

## Example: Lock A Tool Schema

```rust
use mcp_toolkit_testing::assert_tool_schema_snapshot;
use serde_json::json;

#[test]
fn tool_schema_snapshot_matches_exported_tools() {
    let tools = vec![
        json!({
            "name": "example.search",
            "description": "Search the configured source index",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                },
                "required": ["query"]
            }
        }),
    ];

    assert_tool_schema_snapshot("spec/tool_schema_snapshot.v1.json", &tools);
}
```

Run this test in strict mode by default. To intentionally rebaseline snapshots,
set `MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1` for the test run and review the JSON
diff before merging.

## Security And Release Posture

This repository is public-facing and uses a conservative GitHub Actions posture:

- workflow tokens are read-only by default;
- external fork pull requests require maintainer approval before workflows run;
- workflows avoid `pull_request_target`;
- third-party Actions are pinned to immutable commits;
- CodeQL analyzes GitHub Actions workflow policy;
- Cobertura coverage reports upload to GitHub Code Quality for pull requests;
- changes to `main` should land through pull requests with required hosted
  checks, except for documented urgent security remediation.

Dependency policy is documented in `docs/dependency-governance.md`.
Security reporting guidance is documented in `SECURITY.md`.

## Documentation

- `docs/auth-surface.md` explains the OAuth, Protected Resource Metadata, and
  bearer-enforcement contract.
- `docs/contract-testing.md` covers reusable hard-path test helpers for stdio,
  auth metadata, bearer challenges, host guards, and snapshots.
- `docs/cargo-package-release.md` covers the public Git dependency contract,
  package release approval gate, and eventual crates.io migration path.
- `docs/deferred-loading-and-tool-search.md` covers lightweight tool discovery
  and deferred loading.
- `docs/dependency-governance.md` defines dependency selection and update
  gates.
- `docs/easy-server-ergonomics.md` lists the first-run, auth-status,
  discovery-tool, and diagnostic patterns that make toolkit-built servers easy
  to try.
- `docs/ecosystem-map.md` explains where toolkit, reference architecture, and
  service-specific code should live.
- `docs/golden-path.md` is the end-to-end path for creating, validating,
  reviewing, releasing, and adopting toolkit-built MCP servers.
- `docs/instant-server-generation.md` records the direction for generating
  secure MCP server scaffolds from OpenAPI, JSON Schema, docs, and examples.
- `docs/new-server-delivery-lane.md` defines the seven-gate lane for rapid,
  reviewable MCP server creation from toolkit templates through proven
  promotion.
- `docs/observability-evolution.md` and `docs/observability-rollout.md` cover
  observability adapters and adoption.
- `docs/public-landing-policy.md` defines the public repository landing,
  hosted-check, and break-glass remediation policy.
- `docs/security-profiles.md` describes auth profile selection.
- `docs/server-composition-layer.md` describes the optional stdio and HTTP
  server composition layer.
- `docs/starter-templates.md` explains the maintained server starter templates
  and their validation contracts.
- `docs/sql-policy-kernel-conformance.md` documents SQL policy vector
  conformance.
- `docs/tool-inventory-migration.md` and `docs/tool-schema-snapshots.md` cover
  exported tool-surface management.
- `docs/toolkit-boundary.md` defines what belongs in this public toolkit.

## Status

The workspace is useful today, but it is still pre-1.0. Expect APIs to tighten
as the public surface settles. Crates are marked `publish = false` until the
crate-level release process is approved; consumers should use public Git
dependencies plus committed lockfiles until crates are published.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
