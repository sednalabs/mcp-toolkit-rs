# Starter Templates

The `templates/` directory contains maintained, copyable Rust MCP server
starters. They are intentionally small applications, not hidden framework
examples. Some are lightweight in-repo examples; others are full standalone
repository skeletons.

Use this page with `docs/golden-path.md`: the templates show the first copyable
server shape, while the golden path covers crate selection, review handoff,
hosted validation, and release evidence.

For exact generator command syntax, flags, generated file trees, client-config
overrides, and safe customization points, see
`docs/new-server-cli-reference.md`.

## Fast Generator

Use the generator when starting from a maintained template:

```bash
cargo run -p mcp-toolkit --bin mcp-toolkit -- new --name my-mcp-server --template curated-stdio-intent
cargo run -p mcp-toolkit --bin mcp-toolkit -- doctor my-mcp-server
cargo run -p mcp-toolkit --bin mcp-toolkit -- client-config my-mcp-server
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

Run `mcp-toolkit doctor <generated-server-dir>` after generation to check the
starter source, tool-schema snapshot, profile contract test, transport test,
probe scenario, and baseline GitHub workflow before building or configuring an
MCP client. The doctor also prints the generated project's local setup commands,
including `cargo run -- --doctor`, `cargo run -- --print-tools`,
`cargo run -- --print-tool-schema`, and
`cargo run -- --print-client-config`, so handoff can stay inside the generated
repository.

Run `mcp-toolkit client-config <generated-server-dir>` when you are ready to
wire the scaffold into an MCP client. It renders a Codex-style TOML snippet for
the inferred transport, with `--transport`, `--name`, `--command`, `--url`, and
`--profile` overrides for real deployment paths.

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
- generated `read_only` and `operator` profiles, with the live `tools/list`,
  `get_tool`, and `call_tool` path using `EXAMPLE_MCP_TOOL_PROFILE=read_only`
  by default;
- `--print-tools` and `--print-tool-schema` commands backed by the same active
  profile filtering as `tools/list`;
- catalog-profile contract tests that pin the expected `read_only` and
  `operator` surfaces;
- `assert_tool_schema_snapshot` drift protection;
- `stdio_contract::assert_stdio_tools_list` for a JSON-RPC stdio smoke test
  that initializes the server and runs `tools/list`;
- `spec/mcp_probe_stdio_smoke.v1.json` for an optional scripted MCP client
  probe of the generated binary.

Validate it with:

```bash
cargo fmt --manifest-path templates/curated-stdio-intent-server/Cargo.toml --all --check
cargo clippy --manifest-path templates/curated-stdio-intent-server/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path templates/curated-stdio-intent-server/Cargo.toml --all-targets --all-features
```

Inspect the active served surface before configuring an MCP client:

```bash
cargo run --manifest-path templates/curated-stdio-intent-server/Cargo.toml -- --print-tools
cargo run --manifest-path templates/curated-stdio-intent-server/Cargo.toml -- --print-tool-schema
```

Inside a generated project, use the project-local setup commands:

```bash
cargo run -- --doctor
cargo run -- --print-client-config
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
- catalog-profile, schema-snapshot, stdio-smoke, response-safety, and
  `mcp-probe` scenario files carried from the curated stdio starter, including
  binary tests for local tool-surface inspection flags;
- a public-safe `.gitignore`, `LICENSE`, and starter `deny.toml`;
- repo-local governance and snapshot-rebaseline helper scripts.

Validate it with:

```bash
cargo fmt --manifest-path templates/single-crate-public-stdio-server/Cargo.toml --all --check
cargo clippy --manifest-path templates/single-crate-public-stdio-server/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path templates/single-crate-public-stdio-server/Cargo.toml --all-targets --all-features
./templates/single-crate-public-stdio-server/scripts/dependency_governance_check.sh
```

Inside a copied standalone repository, inspect the active served surface before
configuring an MCP client:

```bash
cargo run -- --doctor
cargo run -- --print-tools
cargo run -- --print-tool-schema
cargo run -- --print-client-config
```

## Hosted HTTP/Auth Server

Use `templates/hosted-http-auth-server` when the server should expose MCP over
Streamable HTTP with an explicit hosted auth surface.

It demonstrates:

- `LocalMcpHttpServerBuilder` for hosted Streamable HTTP route assembly;
- lower-level `LocalMcpHttpRuntimeBuilder` and `LocalMcpHttpRouterBuilder`
  adoption points when a service needs to split runtime and routing itself;
- `HttpBindSafety` for fail-closed non-loopback bind checks;
- host and full-origin allowlists for request guardrails;
- `AuthSurfaceBuilder` with public health and protected `/mcp` routes;
- generated `read_only` and `operator` profiles, with mutation-ready tools
  kept behind an explicit profile gate before they appear in the hosted tool
  surface;
- OAuth Protected Resource Metadata with device authorization metadata;
- bearer-auth challenge contract tests;
- authorization-server metadata contract tests for device grants and grant
  type lists;
- pre-auth bad-host `/mcp` checks using
  `assert_forbidden_without_bearer_challenge`;
- tool-schema snapshots for exported tools;
- `--print-tools` and `--print-tool-schema` commands that inspect the active
  served surface without binding the HTTP listener;
- `spec/mcp_probe_http_auth_smoke.v1.json` for a bearer-token-backed scripted
  MCP client probe against a running local server.

Validate it with:

```bash
cargo fmt --manifest-path templates/hosted-http-auth-server/Cargo.toml --all --check
cargo clippy --manifest-path templates/hosted-http-auth-server/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path templates/hosted-http-auth-server/Cargo.toml --all-targets --all-features
```

Inspect the active served surface before binding the listener:

```bash
cargo run --manifest-path templates/hosted-http-auth-server/Cargo.toml -- --print-tools
cargo run --manifest-path templates/hosted-http-auth-server/Cargo.toml -- --print-tool-schema
```

Inside a generated hosted project, use the project-local setup commands without
binding the listener:

```bash
cargo run -- --doctor
cargo run -- --print-client-config
```

## Snapshot Workflow

Strict snapshot tests are part of normal validation. To intentionally rebaseline
a template snapshot, run the matching test with. Template snapshots use the
default `read_only` profile, so future operator-only tools do not enter the
served default contract unless that profile changes intentionally.

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test --manifest-path templates/curated-stdio-intent-server/Cargo.toml tool_schema_snapshot_contract_is_stable
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test --manifest-path templates/hosted-http-auth-server/Cargo.toml tool_schema_snapshot_contract_is_stable
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test --manifest-path templates/single-crate-public-stdio-server/Cargo.toml tool_schema_snapshot_contract_is_stable
```

Review the JSON diff before merging. A schema snapshot change is a public tool
contract change for that template.

## Probe Scenario Workflow

Each maintained template includes a generated `spec/mcp_probe_*.v1.json`
scenario. These scripts are optional local and CI probes for teams that carry a
compatible MCP probe runner. They are deliberately committed beside the
snapshots so a reviewer can see the first runtime call a generated server is
expected to satisfy.

For stdio templates, allow stdio process launch and run the generated scenario:

```bash
MCP_PROBE_ALLOW_STDIO=1 \
node /path/to/mcp-probe/dist/index.js run \
  --script spec/mcp_probe_stdio_smoke.v1.json
```

For the hosted HTTP/auth template, start the local server first, provide the
test access token named by the scenario, and allow loopback hosts:

```bash
MCP_PROBE_ALLOWED_HOSTS=127.0.0.1,localhost \
node /path/to/mcp-probe/dist/index.js run \
  --script spec/mcp_probe_http_auth_smoke.v1.json
```

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
