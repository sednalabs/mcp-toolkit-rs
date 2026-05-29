# Deferred Loading and Tool Search Stratification

This guide covers the seam that is easiest to miss when adopting the toolkit:
how to keep tool discovery lightweight without making the server surface vague.

## Use this guide when

- your tool catalog is large
- some tools are expensive to construct
- tool availability depends on session state, backend capability, or feature flags
- users need a search or discovery step before the final tool list is materialized

If your tool list is small and static, start with `ToolInventory` and skip the
rest of this guide.

## Recommended split

1. Use `ToolInventory` for the authoritative, exported tool surface.
   - Keep it explicit so `tools/list` reflects the real contract.
2. Use `ToolListTracker` when that surface can change per session.
   - It tells you when a session needs `notifications/tools/list_changed`.
3. Use deferred loading for heavy implementation details.
   - Delay expensive clients, large schemas, or backend discovery until a tool
     is actually needed.
4. Use tool search when discovery needs an intermediate narrowing step.
   - Search narrows the candidate set; inventory publishes the final visible set.

That split keeps the exported contract stable while still letting the
implementation load only what it needs.

## Practical pattern

Think of the flow as three layers:

- discovery: a small, cheap way to narrow candidate tools
- publication: the inventory that defines what the session can actually see
- execution: the deferred implementation that loads or initializes on demand

In practice, that usually means:

- a lightweight search or browse tool for broad user intent
- a curated inventory of the tools that are currently available
- lazy construction of the expensive tool internals

## When to choose each helper

- `ToolInventory`
  - use for explicit capability registration and method-aware exposure
- `ToolListTracker`
  - use for session-aware change detection
- `rmcp_models`
  - use for protocol wrapper construction at transport boundaries
- `mcp-toolkit-testing::assert_tool_schema_snapshot`
  - use to lock the exported tool contract once the final tool list is built

## Rule of thumb

If you are asking "which tools should be visible?", use `ToolInventory`.
If you are asking "did the visible tool list change for this session?", use
`ToolListTracker`.
If you are asking "how do users find the right tool without loading everything
up front?", use search plus deferred loading.

## Good and bad fits

Good fits:

- servers with feature-gated tools
- servers that discover backend capabilities lazily
- servers where a broad tool catalog would be slow to instantiate eagerly

Poor fits:

- tiny tool sets with no startup cost
- servers that already have a fixed, always-on tool list
- changes that only affect transport or auth, not discovery

## Next step

If you are adopting the toolkit from scratch, read:

- `README.md`
- `docs/tool-inventory-migration.md`
- `docs/tool-schema-snapshots.md`

That path gives you the explicit inventory, the session-change tracker, the
deferred-loading strategy, and the snapshot contract in one pass.
