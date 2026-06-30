# Curated Stdio Intent Server Starter

This template is the smallest maintained path for a process-local MCP server
with a curated set of read-only intent tools.

It demonstrates:

- `mcp-toolkit-server::stdio::StdioServerBuilder` for the stdio transport;
- an rmcp `ToolRouter` with typed input schemas;
- `mcp-toolkit-core::tool_inventory::ToolCatalog` for explicit tool exposure
  metadata with derived inventory checks;
- `mcp-toolkit-testing::assert_tool_schema_snapshot` for contract drift;
- a real stdio JSON-RPC smoke test that initializes and runs `tools/list`.

## Use

From this repository:

```bash
cargo test --manifest-path templates/curated-stdio-intent-server/Cargo.toml
```

When copying the template into a new repository, replace the path dependencies
in `Cargo.toml` with Git dependencies, then keep the same tests in CI.

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
