# Tool Inventory Migration Guide

This guide describes how to adopt `mcp_toolkit_core::tool_inventory` for explicit
tool capability composition without changing your auth authority model.

## Why adopt this

- Makes capability exposure explicit in code rather than implicit in router macros.
- Supports reusable policy filters:
  - group allowlists
  - read-only-only mode
  - feature-flag gates
  - method-aware visibility (`tools/list` vs `tools/call`)
- Keeps auth and policy authority separate from tool exposure plumbing.
- Pairs well with deferred loading: keep the inventory explicit even when some
  tool implementations are loaded lazily.

## Migration steps

1. Declare your tool catalog in server construction:
   - create `ToolCatalog` from `ToolCatalogEntry` values
   - attach discovery metadata, schemas, examples, tags, and handler symbols
   - derive `ToolInventory` from the catalog with `catalog.inventory()`
   - set `ToolInventoryPolicy` (`strict()` recommended once registrations are complete)
   - call `catalog.with_standard_profiles(["read"])` or
     `catalog.register_standard_profiles(["read"])` for generated servers that
     should default to `read_only` while still supporting an explicit
     `operator` profile
   - mark mutation-capable entries with
     `ToolCatalogEntry::with_operator_profile_gate()` so strict non-operator
     policies do not expose them accidentally
2. Filter `list_tools` with:
   - `inventory.filter_tools(..., ToolOperation::List, ...)`
3. Gate `call_tool` with:
   - `inventory.is_allowed(request.name, ToolOperation::Call, ...)`
   - or `inventory.decision_for_profile(...)` when you need a caller-visible
     denial reason such as `TOOL_DENIED_READ_ONLY_PROFILE`
4. Use filtered names for tool-list-change tracking/notifications.

If the published tool list can change after startup, pair this with
`ToolListTracker` from `mcp-toolkit-core::notifications` and the guidance in
`docs/deferred-loading-and-tool-search.md`.

## Example Registration Shape

A server using this pattern should register each exported tool explicitly:

- explicit registration for:
  - `example.search`
  - `example.list_sources`
  - `example.get_doc`
- `ToolCatalogEntry` metadata for schema snapshots, generated docs, and
  deferred-loading search responses;
- standard `read_only` and `operator` profiles for production behavior;
- a deliberately reviewed fallback only if registration initialization fails.

## Design boundary

This inventory system is capability composition only. It does not perform token
validation, scope checks, or policy authorization decisions. Keep auth/policy
enforcement where it already belongs.

If your problem is not "which tools are allowed?" but instead "how should users
find the right tool without loading everything up front?", start with
`docs/deferred-loading-and-tool-search.md` instead of pushing that logic into
the inventory itself.
