# Single-Crate Public Stdio MCP Server Starter

This template is the repo-shaped public starting point for a small Rust MCP
server. It keeps the code surface intentionally modest while bundling the CI
and security scaffolding that public service repositories usually need on day
one:

- stdio transport via `mcp-toolkit-server::stdio::StdioServerBuilder`;
- typed intent tools plus explicit `ToolCatalog` metadata with derived
  `ToolInventory` checks;
- standard `read_only` and `operator` catalog profiles, with
  `EXAMPLE_MCP_TOOL_PROFILE=read_only` as the default live MCP surface;
- local `--print-tools` and `--print-tool-schema` commands that inspect that
  active surface before a client is configured;
- generated catalog-profile contract tests for `read_only` and `operator`;
- strict tool-schema snapshot and installed-binary stdio smoke tests, including
  a starter tool response-safety check;
- `spec/mcp_probe_stdio_smoke.v1.json` for a portable scripted `mcp-probe`
  smoke scenario;
- pinned GitHub Actions workflows for baseline validation, CodeQL Advanced,
  GitHub Code Quality coverage upload, dependency governance, and CodeQL query
  pack compilation;
- a vendored CodeQL Actions workflow-security query pack for downstream reuse;
- public-safe `.gitignore`, `LICENSE`, `deny.toml`, and governance scripts.

## When To Use It

Use this starter when you are creating a new public repository for a process-
local MCP server and you want a sane first release posture without rebuilding
the same GitHub setup from scratch.

If you only need a tiny in-tree example inside `mcp-toolkit-rs`, use
`templates/curated-stdio-intent-server` instead. That template is smaller and
is intentionally not a full standalone repository skeleton.

## First Copy Checklist

After copying this directory into a new repository:

1. Rename the crate, binary, and repository-specific strings.
2. Replace the path dependencies in `Cargo.toml` with either:
   - Git dependencies pinned to a reviewed `sednalabs/mcp-toolkit-rs` commit, or
   - released crate versions when those are available for your service.
3. Update the package metadata:
   - `name`
   - `description`
   - `license` if you are not using Apache-2.0
   - repository/homepage/documentation fields if you add them
4. Commit `Cargo.lock` once the dependency source is settled for the new repo.
5. Replace the example tools with three to seven real intent tools.
6. Review the vendored CodeQL query pack wording and keep only repository-
   neutral invariants that make sense for the new service.

## Validation

Run the normal baseline:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
./scripts/dependency_governance_check.sh
```

The hosted GitHub workflows in `.github/workflows/` should be the shared proof
surface for public review and merge.

Inspect the active profile's tool surface without starting a client:

```bash
cargo run -- --print-tools
cargo run -- --print-tool-schema
```

The scripted probe scenario exercises the generated binary through a real MCP
client:

```bash
MCP_PROBE_ALLOW_STDIO=1 \
node /path/to/mcp-probe/dist/index.js run \
  --script spec/mcp_probe_stdio_smoke.v1.json
```

## Snapshot Rebaseline

Strict mode is the default:

```bash
cargo test tool_schema_snapshot_contract_is_stable
```

Intentional rebaseline:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 \
cargo test tool_schema_snapshot_contract_is_stable
```

If you prefer the helper wrapper:

```bash
./scripts/rebaseline_tool_schema_snapshot.sh
```

Review the generated `spec/tool_schema_snapshot.v1.json` diff before merging.
Snapshot updates are public contract changes.

## Dependency Governance

This starter includes:

- `deny.toml`
- `scripts/dependency_governance_check.sh`
- `scripts/rmcp_macro_runtime_pin_check.py`
- `docs/dependency-governance.md`

The default policy keeps `cargo-deny` and `cargo-audit` blocking, while
`cargo-outdated` stays advisory unless `STRICT_OUTDATED=1` is set.

## CodeQL Query Pack Reuse

The workflow-security query pack under `.github/codeql/actions-workflow-security`
is vendored on purpose so forked or copied repositories can keep a maintained
local pack without depending on private paths or ad hoc copy steps. The
`codeql-query-tests` workflow compiles that pack directly in GitHub Actions.
