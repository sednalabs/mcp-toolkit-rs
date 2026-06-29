# Starter Templates

The `templates/` directory contains maintained, copyable Rust MCP server
starters. They are intentionally small applications, not hidden framework
examples. Some are lightweight in-repo examples; others are full standalone
repository skeletons.

Use this page with `docs/golden-path.md`: the templates show the first copyable
server shape, while the golden path covers crate selection, review handoff,
hosted validation, and release evidence.

## Curated Stdio Intent Server

Use `templates/curated-stdio-intent-server` when the server should run as a
process-local stdio MCP service with a small curated tool surface.

It demonstrates:

- `mcp-toolkit-server::stdio::serve_stdio` for stdio startup and shutdown;
- rmcp `#[tool_router]` plus `#[tool_handler]` wiring so tools are callable at
  the actual MCP boundary;
- typed tool input schemas;
- explicit `ToolInventory` metadata for the exposed tools;
- `assert_tool_schema_snapshot` drift protection;
- `stdio_contract::assert_stdio_tools_list` for a JSON-RPC stdio smoke test
  that initializes the server and runs `tools/list`.

Validate it with:

```bash
cargo fmt --manifest-path templates/curated-stdio-intent-server/Cargo.toml --all --check
cargo clippy --manifest-path templates/curated-stdio-intent-server/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path templates/curated-stdio-intent-server/Cargo.toml --all-targets --all-features
```

This template is intentionally lean. It does not carry its own `.github`
directory or standalone release scaffolding.

## Single-Crate Public Stdio Server

Use `templates/single-crate-public-stdio-server` when you are starting a new
public repository for a stdio MCP server and want the public CI and security
posture included from the start.

It demonstrates:

- the same stdio server shape as the curated template;
- vendored CodeQL workflow-security queries for downstream reuse;
- standalone GitHub workflows for baseline validation, CodeQL, coverage, and
  dependency governance;
- a public-safe `.gitignore`, `LICENSE`, and starter `deny.toml`;
- repo-local governance and snapshot-rebaseline helper scripts.

Validate it with:

```bash
cargo fmt --manifest-path templates/single-crate-public-stdio-server/Cargo.toml --all --check
cargo clippy --manifest-path templates/single-crate-public-stdio-server/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path templates/single-crate-public-stdio-server/Cargo.toml --all-targets --all-features
./templates/single-crate-public-stdio-server/scripts/dependency_governance_check.sh
```

## Hosted HTTP/Auth Server

Use `templates/hosted-http-auth-server` when the server should expose MCP over
Streamable HTTP with an explicit hosted auth surface.

It demonstrates:

- `LocalMcpHttpRuntimeBuilder` and `LocalMcpHttpRouterBuilder` route assembly;
- `HttpBindSafety` for fail-closed non-loopback bind checks;
- host allowlists for request guardrails;
- `AuthSurfaceBuilder` with public health and protected `/mcp` routes;
- OAuth Protected Resource Metadata with device authorization metadata;
- bearer-auth challenge contract tests;
- authorization-server metadata contract tests for device grants and grant
  type lists;
- pre-auth bad-host `/mcp` checks using
  `assert_forbidden_without_bearer_challenge`;
- tool-schema snapshots for exported tools.

Validate it with:

```bash
cargo fmt --manifest-path templates/hosted-http-auth-server/Cargo.toml --all --check
cargo clippy --manifest-path templates/hosted-http-auth-server/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path templates/hosted-http-auth-server/Cargo.toml --all-targets --all-features
```

## Snapshot Workflow

Strict snapshot tests are part of normal validation. To intentionally rebaseline
a template snapshot, run the matching test with:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test --manifest-path templates/curated-stdio-intent-server/Cargo.toml tool_schema_snapshot_contract_is_stable
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test --manifest-path templates/hosted-http-auth-server/Cargo.toml tool_schema_snapshot_contract_is_stable
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test --manifest-path templates/single-crate-public-stdio-server/Cargo.toml tool_schema_snapshot_contract_is_stable
```

Review the JSON diff before merging. A schema snapshot change is a public tool
contract change for that template.

For repositories that carry the helper wrapper, you can also use:

```bash
./scripts/rebaseline_tool_schema_snapshot.sh templates/single-crate-public-stdio-server/Cargo.toml
```

## GitHub Actions

The root `rust-baseline` workflow validates the in-repo templates with
formatting, clippy, and tests. The standalone public template also carries its
own `.github/workflows/` directory so copied repositories can keep the same
hosted proof posture.

See `docs/codeql-query-pack-reuse.md` for the supported workflow-security query
pack reuse model.
