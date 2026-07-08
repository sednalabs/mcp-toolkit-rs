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
| `mcp-toolkit-scratchpad` | Optional DuckDB-backed sessions for large analytical result sets, bounded read-only SQL, table inventory, and evidence handles. |
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
with `docs/golden-path.md`. Use `docs/reference-server-atlas.md` to choose a
living reference pattern from existing MCP servers before adding new toolkit
abstractions. Use `docs/pattern-manifests.md` and `docs/pattern-recipes.md`
when you need the machine-readable pattern shape and the implementation recipe
that goes with it. For a copyable checklist that turns that route into a
repeatable implementation lane, use `docs/new-server-delivery-lane.md`. For
exact generator commands, flags, generated files, and customization points, use
`docs/new-server-cli-reference.md`. For the longer direction on turning API
specs and docs into safe server scaffolds, use
`docs/instant-server-generation.md`. For the operator-facing details that make
a server easy to try and debug, use `docs/easy-server-ergonomics.md`. For
legacy systems with partial APIs, admin HTML, scheduled jobs, or private
exports, use `docs/legacy-system-adapter-pattern.md` before exposing any
generic HTTP, SQL, or browser-style tool. For auth failure handling, use
`docs/auth-error-contracts.md`.

### Create A Server From A Maintained Template

From this checkout, list the available shapes and generate the smallest stdio
starter:

```bash
cargo run -p mcp-toolkit --bin mcp-toolkit -- templates
cargo run -p mcp-toolkit --bin mcp-toolkit -- patterns
cargo run -p mcp-toolkit --bin mcp-toolkit -- new \
  --name my-mcp-server \
  --template curated-stdio-intent
cargo run -p mcp-toolkit --bin mcp-toolkit -- doctor my-mcp-server
cargo run -p mcp-toolkit --bin mcp-toolkit -- client-config my-mcp-server
cd my-mcp-server
cargo run -- --doctor
cargo run -- --print-tools
cargo run -- --print-tool-schema
cargo run -- --print-client-config
cargo test --all-targets --all-features
```

If you already have an API description, draft the first tool surface before
generating or editing provider code:

```bash
cargo run -p mcp-toolkit --bin mcp-toolkit -- draft-tools ./openapi.json
cargo run -p mcp-toolkit --bin mcp-toolkit -- draft-tools ./openapi.json --json
```

`draft-tools` reads a local OpenAPI JSON file, standalone JSON Schema, or
endpoint-shaped markdown/text and prints a conservative review report. It does
not fetch remote references, call the upstream API, or generate a generic
endpoint proxy. Read operations are proposed for the `read_only` profile;
write, destructive, and uncertain operations stay disabled by default under
`operator` review.

For a portable service repository, generate outside the toolkit checkout and
rewrite toolkit dependencies to public Git sources immediately:

```bash
cd ..
cargo run --manifest-path /path/to/mcp-toolkit-rs/crates/mcp-toolkit/Cargo.toml \
  --bin mcp-toolkit -- new \
  --name my-mcp-server \
  --template single-crate-public-stdio \
  --output my-mcp-server \
  --toolkit-git https://github.com/sednalabs/mcp-toolkit-rs
```

Generated servers include the starter code and the proof files reviewers should
expect on day one:

- `src/lib.rs` and `src/main.rs` with a small typed tool surface;
- `spec/tool_schema_snapshot.v1.json` for the exported `tools/list` contract;
- `tests/tool_schema_snapshot.rs` and `tests/catalog_profile_contract.rs`;
- a transport test such as `tests/stdio_smoke.rs` or
  `tests/http_auth_contract.rs`;
- `spec/mcp_probe_stdio_smoke.v1.json` or
  `spec/mcp_probe_http_auth_smoke.v1.json` for an optional scripted MCP client
  probe;
- `.github/workflows/rust-baseline.yml` so the first PR has hosted validation.

Run `mcp-toolkit doctor <generated-server-dir>` after generation whenever you
want a static scaffold check before building. The doctor reports the inferred
starter shape, missing source or proof files, and the next commands for schema
inspection and validation.

Run `mcp-toolkit client-config <generated-server-dir>` to print a Codex-style
TOML snippet for the generated transport. For stdio starters it points at the
expected release binary and pins `EXAMPLE_MCP_TOOL_PROFILE=read_only`; for the
hosted HTTP/auth starter it prints the local `/mcp` URL unless you pass
`--url`.

Run `mcp-toolkit release-preflight <generated-server-dir>` before publishing or
installing a generated repository. It is stricter than `doctor`: it expects
public-ready README, license, Cargo metadata, CI, CodeQL, coverage, dependency
governance, schema/probe proof, portable toolkit dependencies, no committed
Cargo path overrides, and no high-confidence secret markers. The small curated
starter is expected to report `Public ready: no` until those public release
files are added; the standalone public stdio template is designed to satisfy
this gate from generation when created with `--toolkit-git`.

For stdio servers, build the binary and point your MCP client at the generated
command path. The default served profile is `read_only`; add mutation tools
behind the explicit `operator` profile before exposing them. For hosted
HTTP/auth servers, start from the generated README environment block, check the
public `/health` route, and point clients at the generated `/mcp` URL with the
published OAuth Protected Resource Metadata. If the server calls an upstream
provider such as Google, add an `auth_status` or equivalent diagnostic before
release; `docs/upstream-oauth.md` and `docs/easy-server-ergonomics.md` describe
that pattern.

Keep the generated contract tests in CI. The generated GitHub workflow is the
shared proof surface for review; local commands are useful while editing, but a
mergeable branch should record the hosted run URL.

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

Add `scratchpad` to the umbrella feature list only when the server needs local
DuckDB sessions for large-result workflows.

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

1. Optionally run `mcp-toolkit draft-tools <openapi-or-docs>` to turn an
   existing OpenAPI JSON file, JSON Schema, or endpoint notes into a reviewable
   catalog draft. Treat this as input to design review, not as an exposed tool
   surface.
2. Use `mcp-toolkit-core::tool_inventory::ToolCatalog` to declare the tools,
   schemas, examples, handler symbols, and inventory metadata your server can
   expose.
3. Register the standard generated profiles with
   `ToolCatalog::with_standard_profiles(["read"])` when the server may grow
   beyond a pure read-only surface. This adds a default `read_only` profile and
   an explicit `operator` profile; gate mutation tools with
   `ToolCatalogEntry::with_operator_profile_gate()` so they can ship in the
   binary without appearing in the default profile.
4. Define additional native catalog profiles with `ToolCatalogProfile` when a
   server has large or role-shaped tool surfaces. Emit `ToolCatalogContract`
   artifacts from the same catalog-derived inventory and validate them with
   `mcp_toolkit_testing::catalog_profile_contract` so required tools and groups
   are probe-visible without adding production `find_tools` workarounds.
5. Use `mcp-toolkit-testing::assert_tool_schema_snapshot` to lock the exported
   `tools/list` contract.
6. Use `mcp-toolkit-core::openai_tool_search` when large OpenAI-facing MCP
   catalogs should publish a reusable `defer_loading` plus `tool_search`
   request fragment, a richer documentation/resource template, and a local
   `allowed_tools` discovery envelope.
7. Use `mcp-toolkit-http::oauth` and `mcp-toolkit-auth::surface` when serving
   MCP over HTTP with OAuth discovery, Protected Resource Metadata, and
   device-authorization metadata for headless MCP client login.
8. Use `mcp-toolkit-server` when you want the toolkit to assemble stdio startup,
   local Streamable HTTP runtime pieces, host guarding, auth-surface layers, and
   the default MCP route bundle. Server authors can import the underlying
   `rmcp` authoring surface through `mcp_toolkit::rmcp` or
   `mcp_toolkit_server::rmcp` instead of declaring `rmcp` directly.
9. Use `mcp-toolkit-scratchpad` when a read-only or analytics server needs to
   keep large rowsets out of chat while still giving agents bounded DuckDB SQL,
   table inventory, query projections, and cleanup/export affordances. Enable
   `mcp-toolkit-scratchpad/tokio` or the umbrella `scratchpad-tokio` feature
   when calling scratchpad operations from Tokio-backed async MCP handlers; use
   `run_scratchpad_blocking` so DuckDB work stays off the async executor. Keep
   provider-specific ingest and evidence wording in the service repository.
10. Use `mcp-toolkit-observability` helpers for sanitized logs, bounded labels,
   and optional tracing/metrics integration.
11. Use `mcp-toolkit-core::query_evidence` when a tool response should expose
   provider query-cost and read-only evidence without returning raw provider
   payloads.
12. Add policy crates only when the service has an authorization, SQL
   read-only, or capability-guard boundary that needs reusable enforcement.

For a legacy backend, first map source authority and blocked operations using
`docs/legacy-system-adapter-pattern.md`. A narrow adapter with explicit
operator-intent tools is safer than a generic HTTP, SQL, API, or browser MCP
surface.

For a copyable starting point, see `templates/curated-stdio-intent-server` for
stdio intent tools and `templates/hosted-http-auth-server` for hosted HTTP with
OAuth Protected Resource Metadata, headless device-auth metadata, bearer
challenges, host guarding, schema snapshots, and contract tests.

To start from a maintained template through the toolkit front door:

```bash
cargo run -p mcp-toolkit --bin mcp-toolkit -- new --name my-mcp-server --template curated-stdio-intent
cargo run -p mcp-toolkit --bin mcp-toolkit -- doctor my-mcp-server
cargo run -p mcp-toolkit --bin mcp-toolkit -- client-config my-mcp-server
```

Run `cargo run -p mcp-toolkit --bin mcp-toolkit -- patterns` to choose by
server archetype, then use `--pattern <id>` when you want the generator to
select the maintained template for that shape. Run
`cargo run -p mcp-toolkit --bin mcp-toolkit -- templates` when you already know
the template id.

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
- `docs/auth-token-dependency-posture.md` defines the crate-backed posture for
  auth/token mechanics and the guardrail against bespoke token parsing.
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
- `docs/legacy-system-adapter-pattern.md` explains how to wrap older systems
  with split APIs, admin HTML, scheduled jobs, and private artifacts without
  exposing generic backend access.
- `docs/new-server-delivery-lane.md` defines the seven-gate lane for rapid,
  reviewable MCP server creation from toolkit templates through proven
  promotion.
- `docs/observability-evolution.md` and `docs/observability-rollout.md` cover
  observability adapters and adoption.
- `docs/pattern-manifests.md` defines the machine-readable reference pattern
  manifest contract and links the example manifest files.
- `docs/pattern-recipes.md` turns atlas archetypes into implementation recipes
  with crate ownership, proof expectations, and reference manifests.
- `docs/policy-kernel-provenance-acceptance.md` defines the runtime metadata,
  hosted manifest, artifact identity, and consumer evidence needed before
  server adoption claims.
- `docs/public-landing-policy.md` defines the public repository landing,
  hosted-check, and break-glass remediation policy.
- `docs/provider-auth-and-client-config.md` explains provider auth setup,
  read-only/operator profile selection, Google quota-project troubleshooting,
  service-account notes, and MCP client configuration.
- `docs/reference-server-atlas.md` maps reusable server patterns to real MCP
  services so new abstractions start from existing evidence instead of toy
  examples.
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
- `docs/upstream-oauth.md` covers browser-based upstream OAuth helpers for
  servers that call provider APIs such as Google.

## Status

The workspace is useful today, but it is still pre-1.0. Expect APIs to tighten
as the public surface settles. Crates are marked `publish = false` until the
crate-level release process is approved; consumers should use public Git
dependencies plus committed lockfiles until crates are published.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
