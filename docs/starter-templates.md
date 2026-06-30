# Starter Templates

The `templates/` directory contains maintained, copyable Rust MCP server
starters. They are intentionally small applications, not hidden framework
examples. Some are lightweight in-repo examples; others are full standalone
repository skeletons.

Use this page with `docs/golden-path.md`: the templates show the first copyable
server shape, while the golden path covers crate selection, review handoff,
hosted validation, and release evidence.

## Fast Generator

Use the generator when starting from a maintained template:

```bash
cargo run -p mcp-toolkit --bin mcp-toolkit -- new --name my-mcp-server --template curated-stdio-intent
```

The generator writes a new directory named after the package, rewrites the
template package name, keeps toolkit dependencies pointed at the current local
checkout by default, and refuses to overwrite changed files. Output paths are
relative to the current directory. Use `mcp-toolkit patterns` to choose from
living server archetypes, `mcp-toolkit patterns <id>` to inspect the manifest
evidence behind an archetype, and `mcp-toolkit templates` when you already know
the exact template id. Use
`--toolkit-git https://github.com/sednalabs/mcp-toolkit-rs` for portable Git
dependencies, `--pattern <id>` to let the generator choose the recommended
template, and `--force` only when replacing generated files intentionally.

## Curated Stdio Intent Server

Use `templates/curated-stdio-intent-server` when the server should run as a
process-local stdio MCP service with a small curated tool surface.

It demonstrates:

- `mcp-toolkit-server::stdio::StdioServerBuilder` for stdio startup and
  shutdown;
- toolkit-provided `rmcp` `#[tool_router]` plus `#[tool_handler]` wiring so
  tools are callable at the actual MCP boundary without a direct `rmcp`
  dependency in the starter;
- typed tool input schemas;
- explicit `ToolCatalog` metadata for the exposed tools, with `ToolInventory`
  derived from the catalog;
- `assert_tool_schema_snapshot` drift protection;
- `stdio_contract::assert_stdio_tools_list` for a JSON-RPC stdio smoke test
  that initializes the server and runs `tools/list`.

Validate it with:

```bash
cargo fmt --manifest-path templates/curated-stdio-intent-server/Cargo.toml --all --check
cargo clippy --manifest-path templates/curated-stdio-intent-server/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path templates/curated-stdio-intent-server/Cargo.toml --all-targets --all-features
```

This template is intentionally lean. It carries only a minimal
`.github/workflows/rust-baseline.yml` for generated-project smoke validation;
it does not carry the standalone public template's CodeQL, coverage, dependency
governance, license, or release scaffolding.

## Single-Crate Public Stdio Server

Use `templates/single-crate-public-stdio-server` when you are starting a new
public repository for a stdio MCP server and want the standalone public stdio
starter to carry the public CI and security posture from the start.

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

- `LocalMcpHttpServerBuilder` for hosted Streamable HTTP route assembly;
- lower-level `LocalMcpHttpRuntimeBuilder` and `LocalMcpHttpRouterBuilder`
  adoption points when a service needs to split runtime and routing itself;
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

From this toolkit repository root, you can use the helper wrapper against an
in-repo template:

```bash
./scripts/rebaseline_tool_schema_snapshot.sh templates/single-crate-public-stdio-server/Cargo.toml
```

Inside a generated standalone repository that carries the helper wrapper, use
the copied-repo form:

```bash
./scripts/rebaseline_tool_schema_snapshot.sh
```

## GitHub Actions

The root `rust-baseline` workflow validates the in-repo templates with
formatting, clippy, and tests. The standalone public template also carries its
own `.github/workflows/` directory so copied repositories can keep the same
hosted proof posture.

See `docs/codeql-query-pack-reuse.md` for the supported workflow-security query
pack reuse model.
