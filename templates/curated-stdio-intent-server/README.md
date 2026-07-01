# Curated Stdio Intent Server Starter

This template is the smallest maintained path for a process-local MCP server
with a curated set of read-only intent tools.

It demonstrates:

- `mcp-toolkit-server::stdio::StdioServerBuilder` for the stdio transport;
- an rmcp `ToolRouter` with typed input schemas;
- `mcp-toolkit-core::tool_inventory::ToolCatalog` for explicit tool exposure
  metadata with derived inventory checks;
- standard `read_only` and `operator` catalog profiles, with
  `EXAMPLE_MCP_TOOL_PROFILE=read_only` as the default live MCP surface;
- generated catalog-profile contract tests for `read_only` and `operator`;
- `mcp-toolkit-testing::assert_tool_schema_snapshot` for contract drift;
- a real stdio JSON-RPC smoke test that initializes, runs `tools/list`, and
  checks a starter tool response for common secret substrings;
- `--print-tools` and `--print-tool-schema` for local tool-surface inspection
  without starting an MCP client;
- `spec/mcp_probe_stdio_smoke.v1.json` for a portable scripted `mcp-probe`
  smoke scenario.

## Use

From this repository:

```bash
cargo test --manifest-path templates/curated-stdio-intent-server/Cargo.toml
```

When copying the template into a new repository, replace the path dependencies
in `Cargo.toml` with Git dependencies, then keep the same tests in CI.

Inspect the active profile's tool surface without starting a client:

```bash
cargo run --manifest-path templates/curated-stdio-intent-server/Cargo.toml -- --print-tools
cargo run --manifest-path templates/curated-stdio-intent-server/Cargo.toml -- --print-tool-schema
```

## Contract And Probe Checks

The generated tests cover profile contracts, schema drift, stdio startup, and a
small response-safety check:

```bash
cargo test --manifest-path templates/curated-stdio-intent-server/Cargo.toml \
  --all-targets --all-features
```

The scripted probe scenario exercises the same binary boundary with a real MCP
client:

```bash
MCP_PROBE_ALLOW_STDIO=1 \
node /path/to/mcp-probe/dist/index.js run \
  --script spec/mcp_probe_stdio_smoke.v1.json
```

## Snapshot Workflow

Strict mode:

```bash
cargo test --manifest-path templates/curated-stdio-intent-server/Cargo.toml \
  tool_schema_snapshot_contract_is_stable
```

Intentional rebaseline:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 \
cargo test --manifest-path templates/curated-stdio-intent-server/Cargo.toml \
  tool_schema_snapshot_contract_is_stable
```

Review the generated `spec/tool_schema_snapshot.v1.json` diff before merging.
