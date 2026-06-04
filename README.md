# mcp-rs-toolkit

Reusable Rust building blocks for Model Context Protocol (MCP) servers and
clients.

`mcp-rs-toolkit` is an early public workspace for the shared substrate that
keeps Rust MCP services consistent: auth discovery, HTTP/session support,
policy primitives, tool inventory helpers, observability, process utilities,
and test harnesses. It is pre-1.0 and the crates are not published to
crates.io yet, so adopters should consume it from Git for now.

## What Is Included

| Crate | Purpose |
| --- | --- |
| `mcp-toolkit` | Umbrella crate with optional feature groups. |
| `mcp-toolkit-core` | Protocol-facing helpers, notifications, and tool inventory types. |
| `mcp-toolkit-auth` | Bearer auth, token validation, replay protection, and auth-surface helpers. |
| `mcp-toolkit-http` | OAuth/PRM metadata helpers plus optional streamable HTTP session support. |
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

Add the specific crates you need from Git:

```toml
[dependencies]
mcp-toolkit-core = { git = "https://github.com/sednalabs/mcp-rs-toolkit" }
mcp-toolkit-http = { git = "https://github.com/sednalabs/mcp-rs-toolkit", features = ["session"] }
mcp-toolkit-testing = { git = "https://github.com/sednalabs/mcp-rs-toolkit" }
```

Or use the umbrella crate when you want one dependency with explicit feature
selection:

```toml
[dependencies]
mcp-toolkit = {
  git = "https://github.com/sednalabs/mcp-rs-toolkit",
  features = ["auth", "http", "policy", "process", "server"]
}
```

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
3. Use `mcp-toolkit-http::oauth` and `mcp-toolkit-auth::surface` when serving
   MCP over HTTP with OAuth discovery and Protected Resource Metadata.
4. Use `mcp-toolkit-server` when you want the toolkit to assemble stdio startup,
   local Streamable HTTP runtime pieces, host guarding, auth-surface layers, and
   the default MCP route bundle.
5. Use `mcp-toolkit-observability` helpers for sanitized logs, bounded labels,
   and optional tracing/metrics integration.
6. Add policy crates only when the service has an authorization, SQL
   read-only, or capability-guard boundary that needs reusable enforcement.

For a copyable starting point, see `templates/curated-stdio-intent-server` for
stdio intent tools and `templates/hosted-http-auth-server` for hosted HTTP with
OAuth Protected Resource Metadata, bearer challenges, host guarding, schema
snapshots, and contract tests.

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
- CodeQL analyzes GitHub Actions workflow policy.

Dependency policy is documented in `docs/dependency-governance.md`.

## Documentation

- `docs/auth-surface.md` explains the OAuth, Protected Resource Metadata, and
  bearer-enforcement contract.
- `docs/deferred-loading-and-tool-search.md` covers lightweight tool discovery
  and deferred loading.
- `docs/dependency-governance.md` defines dependency selection and update
  gates.
- `docs/ecosystem-map.md` explains where toolkit, reference architecture, and
  service-specific code should live.
- `docs/observability-evolution.md` and `docs/observability-rollout.md` cover
  observability adapters and adoption.
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
crate-level release process is ready.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
