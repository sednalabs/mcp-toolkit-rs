# Deferred Loading and Tool Search Stratification

This guide covers the seam that is easiest to miss when adopting the toolkit:
how to keep tool discovery lightweight without making the server surface vague.

## Use this guide when

- your tool catalog is large
- some tools are expensive to construct
- tool availability depends on session state, backend capability, or feature flags
- users need a search or discovery step before the final tool list is materialized

If your tool list is small and static, start with `ToolCatalog` plus the
derived `ToolInventory`, then skip the rest of this guide.

## Recommended split

1. Use `ToolCatalog` for the authoritative declaration and derive
   `ToolInventory` for the exported tool surface.
   - Keep the catalog explicit so `tools/list`, docs, schemas, and search
     metadata reflect the same contract.
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

Think of the host flow as four ordered layers:

- collection: drain every non-null opaque `nextCursor` and build one complete
  catalogue
- publication: atomically expose only that complete catalogue as the current
  inventory
- discovery: index the complete inventory for direct selection or deferred
  search
- execution: load or initialize the selected implementation on demand

`mcp-toolkit-core::pagination::collect_paginated_list` provides a bounded,
cycle-safe collection seam for hosts or adapters whose metadata wrappers cannot
use `rmcp::Peer::list_all_tools` directly. A failed or non-terminating walk must
not publish its partial items. If a server advertises `listChanged`, the host
should invalidate and rebuild the complete snapshot before updating its search
index.

Some non-hosted clients may also use a lightweight search or browse tool to
construct an `allowed_tools` subset. That is an application tool, not an MCP
replacement for collecting `tools/list`.

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

MCP itself does not define a semantic `tools/search` operation. `tool_search`
and `defer_loading` are OpenAI host/API mechanisms layered over the catalogue
the host has collected. They cannot recover tools omitted because an MCP client
stopped after page one.

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

Use `ToolInventory::search` when a caller depends on strict all-terms substring
matching. Use the additive `ToolInventory::search_ranked` or
`ToolCatalog::ranked_search_response` path for natural-language agent queries.
Ranked search ignores common conversational stop words, down-weights query terms
that appear across most visible tools, matches conservative canonical tokens
rather than unsafe substrings, and uses guarded-action posture as a deterministic
tie-break. It preserves original terms while adding conservative singular
variants, and excludes tools matching explicitly negated terms such as `not
apply` or `without delete`; negated terms are reported separately in
`excluded_query_terms`. A truncated query, dangling negation, or truncated
negative-term list fails closed. A genuine
browse request is safety-ordered; a supplied query that has no searchable terms
returns no matches instead of widening to the whole catalog.
Ranked search defaults to 20 results, hard-caps requested limits at 100, and
bounds query, group-filter, and result metadata. An overlong group filter fails
closed instead of matching a truncated prefix. Its `match_summary` reports
normalized, excluded, and ignored terms, total matches, returned count, the effective
result limit, and stable reasons for every applied truncation. Metadata bounds
across the visible search corpus are reported even when the bounded-away text
would otherwise hide a match.

Both standard and ranked response types provide `to_compact_value()` for the
selection step. The compact shape retains result metadata and
`openai_allowed_tools`, but deliberately omits schemas and hosted-client metadata.
Ranked compact serialization additionally enforces a 32 KiB byte budget by
dropping lowest-ranked results and recording `compact_response_bytes` in the
truncation reasons. If caller-constructed selection metadata alone exceeds the
budget after all results are removed, the compact fallback omits echoed query,
group, and term lists while retaining counts and the byte-budget reason. Call
`to_value()` when the same response must also carry
schemas and deferred-load configuration; the full shape is intentionally not
subject to the compact byte budget. Use the ranked response's
`into_openai_response()` builder when adding companion allowed tools, extra
results, or custom deferred-loading metadata so the match summary is preserved.

The default OpenAI MCP config leaves `require_approval` unset. If a trusted
workflow wants to reduce approval friction for read-only tools, supply an
explicit reviewed read-only override with service-owned tool names. The toolkit
request helper writes that override into the MCP tool's
`require_approval.never` filter with the reviewed `tool_names` list. The
documentation helper keeps that override separate so docs or resources can show
the safer default config first. Keep mutating tools behind approval unless
another workflow-level review gate applies.

## When to choose each helper

- `ToolCatalog`
  - use for explicit tool declarations, schemas, examples, and generated docs
- `ToolInventory`
  - use for the derived capability registration and method-aware exposure checks
- `openai_tool_search`
  - use for OpenAI MCP `defer_loading` and `tool_search` config payloads
- `ToolListTracker`
  - use for session-aware change detection
- `rmcp_models`
  - use for protocol wrapper construction at transport boundaries
- `mcp-toolkit-testing::assert_tool_schema_snapshot`
  - use to lock the exported tool contract once the final tool list is built

## Rule of thumb

If you are asking "which tools exist and what metadata should ship with them?",
use `ToolCatalog`.
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
