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

## OpenAI Responses API

For OpenAI Responses API clients, tool search is configured by the client
request, not by hiding tools inside the MCP server. The server should continue
to expose its authoritative `tools/list` surface under its normal inventory and
authorization policy. The client can then choose to defer loading those tool
definitions.

For an MCP server, the client-side `tools` array should include:

```json
[
  {
    "type": "mcp",
    "server_label": "example",
    "server_description": "Example operational MCP tools.",
    "server_url": "https://example.com/mcp",
    "defer_loading": true
  },
  {
    "type": "tool_search"
  }
]
```

OpenAI hosted tool search searches the deferred tools declared in the request.
Local MCP discovery helpers such as `find_tools` are normal MCP tools; hosted
OpenAI tool search does not call them automatically. Use a local discovery tool
when non-hosted clients need a narrow `allowed_tools` list, optional schemas, or
extra application-owned search results before making a follow-up request.

Do not confuse hosted `tool_search` with OpenAI retrievable apps. A retrievable
app must expose literal `search` and `fetch` tools for document retrieval, while
hosted `tool_search` searches deferred MCP tool definitions. The toolkit
provides `mcp-toolkit-core::openai_retrievable` schema and response builders for
the retrievable pair, and
`OpenAiAppsConformanceProfile::assert_retrievable_tool_descriptors` for
descriptor contract tests.

`mcp-toolkit-core::openai_tool_search` provides generic builders for two
closely related shapes:

- `OpenAiMcpToolSearchConfig::to_request_value()`
  - use when you need an API-postable Responses request fragment with `model`
    and the deferred MCP plus `tool_search` tools array
- `OpenAiMcpToolSearchConfig::to_documentation_value()`
  - use when you need a richer resource or docs payload that also carries model
    support guidance, optional reviewed approval examples, or notes for
    operators

`ToolSearchResponse` provides the matching local discovery envelope with
`openai_allowed_tools` and optional schemas. When a local discovery result
needs companion allowed tools or extra result records, wrap it with
`ToolSearchResponse::into_openai_response()` and add those OpenAI-specific
extensions there.

The default OpenAI MCP config leaves `require_approval` unset. If a trusted
workflow wants to reduce approval friction for read-only tools, supply an
explicit reviewed read-only override with service-owned tool names. The toolkit
request helper writes that override into the MCP tool's
`require_approval.never` filter with the reviewed `tool_names` list. The
documentation helper keeps that override separate so docs or resources can show
the safer default config first. Keep mutating tools behind approval unless
another workflow-level review gate applies.

## When to choose each helper

- `ToolInventory`
  - use for explicit capability registration and method-aware exposure
- `openai_tool_search`
  - use for OpenAI MCP `defer_loading` and `tool_search` config payloads
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
