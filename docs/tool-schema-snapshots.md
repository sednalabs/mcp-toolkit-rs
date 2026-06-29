# Tool Schema Snapshot Contracts

This document defines the shared snapshot workflow for Rust MCP tool schemas
and other structured JSON contract artifacts.

## Purpose

`mcp-toolkit-testing::assert_tool_schema_snapshot` enforces a deterministic JSON
snapshot for tool metadata: name, description, and input schema.

`mcp-toolkit-testing::assert_json_contract_snapshot` extends the same
strict-vs-update model to other structured JSON payloads such as discovery
documents, help resources, example indexes, and other server-advertised
contract surfaces.

Together they catch accidental MCP surface drift before release.

If your server loads tools lazily, run the snapshot after the final tool list
has been assembled. The committed file should reflect the exported `tools/list`
shape, not internal construction steps.

## Snapshot Format

- Snapshot file path per server: `spec/tool_schema_snapshot.v1.json`.
- Canonical payload:
  - `schema = "mcp_tool_schema_snapshot"`;
  - `version = 1`;
  - `tools = [...]`, sorted by tool name.
- JSON object keys are canonicalized to keep diffs stable.

## Enforcement Model

- Strict mode: tests fail if the committed snapshot differs.
- Update mode: set `MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1` during test execution
  to rewrite snapshot files with the canonical current values.
- Generic JSON contract snapshots use
  `MCP_TOOLKIT_UPDATE_JSON_CONTRACT_SNAPSHOTS=1`.

## Choosing The Helper

- Use `assert_tool_schema_snapshot` for MCP tool metadata snapshots.
- Use `assert_json_contract_snapshot` for other structured JSON payloads that
  need canonical key ordering but do not fit the dedicated tool-schema format.
- `assert_json_contract_snapshot` preserves array order exactly as provided. If
  a payload includes semantically unordered arrays, normalize or sort those
  arrays before snapshotting.

Minimal example:

```rust
use mcp_toolkit_testing::assert_tool_schema_snapshot;
use serde_json::json;

#[test]
fn tool_schema_snapshot_matches_exported_tools() {
    let tools = vec![
        json!({
            "name": "example.search",
            "description": "Search indexed source and docs",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                },
                "required": ["query"]
            }
        }),
        json!({
            "name": "example.list_sources",
            "description": "List available sources",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
    ];

    assert_tool_schema_snapshot("spec/tool_schema_snapshot.v1.json", &tools);
}
```

## Preset Workflow

The toolkit provides helper APIs, not a universal build preset namespace. Each
server should wire strict and update modes into its own test runner.

Example strict check:

```bash
cargo test -p your-server-crate tool_schema_snapshot_matches_exported_tools
```

Example intentional rebaseline:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 \
cargo test -p your-server-crate tool_schema_snapshot_matches_exported_tools
```

If the repository provides a helper wrapper, prefer using that so the update
mode stays discoverable for new contributors. In `mcp-toolkit-rs` the helper is:

```bash
./scripts/rebaseline_tool_schema_snapshot.sh templates/curated-stdio-intent-server/Cargo.toml
```

Toolkit harness self-tests run through the workspace test suite:

```bash
cargo test -p mcp-toolkit-testing
```

## Review Expectations

When a snapshot changes:

1. Confirm the tool API change is intentional.
2. Review the snapshot diff for each affected server.
3. Include a short note in the PR explaining why the contract drift is expected.
