# MCP/rmcp Alignment Review

This review records the custom MCP-adjacent layers the toolkit maintains on
top of `rmcp` and the invariants that keep those layers aligned with the
official MCP specification and the official Rust SDK.

Review date: 2026-07-01.

Primary references:

- MCP specification entry point: <https://modelcontextprotocol.io/specification>
- MCP tools: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>
- MCP pagination: <https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination>
- MCP transports: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>
- `rmcp` Rust SDK: <https://github.com/modelcontextprotocol/rust-sdk>

## Current Posture

The toolkit should stay a thin policy and ergonomics layer over `rmcp`, not a
parallel MCP implementation. Server authors should import `rmcp` through
`mcp_toolkit::rmcp` and let `rmcp` own the JSON-RPC types, macro wiring,
stdio transport, Streamable HTTP service, and standard handler traits.

The toolkit-owned layers are appropriate where they encode reusable deployment
or server-authoring policy:

- profile-aware tool inventory and capability projection;
- generated server templates and schema snapshots;
- cursor pagination helpers for list operations;
- host and Origin guards around Streamable HTTP route bundles;
- bounded session manager composition;
- OAuth metadata and protected-resource helpers;
- provider-auth UX helpers that sit outside the MCP transport itself.

## Alignment Inventory

| Area | Toolkit behavior | Alignment decision |
| --- | --- | --- |
| `rmcp` dependency | The facade crate re-exports `rmcp` and templates avoid direct `rmcp` dependencies. | Keep. This prevents template and service drift across different SDK versions. |
| stdio transport | `mcp-toolkit-server::stdio` delegates to `rmcp::serve_server(..., stdio())`. | Keep. The toolkit must not write non-MCP data to stdout; diagnostics belong on stderr/logging. |
| Server macros | Templates use `#[tool_router]`, `#[tool_handler]`, and `ToolRouter`. | Keep. This matches official Rust SDK idioms while still allowing profile gates. |
| `tools/list` | Templates filter tools by profile and now delegate cursor mechanics to `server::tools::list_tools_result`. | Keep. Custom visibility is service policy; pagination is centralized protocol hygiene. |
| Tool-call denial | Hidden or profile-denied tools return `CallToolResult::error` with a caller-facing message. | Keep for profile denials. Unknown tool/protocol-shape errors should continue to use `rmcp` protocol errors where the tool router sees them. |
| Tool annotations and schemas | `mcp-toolkit-core::capability` projects safety hints, input schemas, output schemas, and metadata into `rmcp::model::Tool`. | Keep. Tool annotations are hints, not authorization. Runtime policy must still enforce scopes and risk posture. |
| Tool list changes | `ToolListTracker` fingerprints stable tool names and exposes `notifications/tools/list_changed` method metadata. | Keep with invariant: a negotiated session's tool list must not vary as an incidental side effect of ordinary requests. Emit list-changed only for explicit refresh/profile changes. |
| Streamable HTTP session routing | Route bundles use `rmcp` Streamable HTTP services plus bounded local session management and optional stateless fallback. | Keep. This is deployment assembly, not protocol reimplementation. |
| DNS rebinding defense | Route bundles validate Host/authority and now validate present `Origin` headers against the same allowlist. | Keep. MCP Streamable HTTP requires Origin validation when Origin is present; Host validation remains useful for non-browser and proxy paths. |
| Session errors | Toolkit route bundles return HTTP errors for missing/invalid sessions before forwarding to `rmcp`. | Keep, but periodically compare with `rmcp` Streamable HTTP behavior when upgrading the SDK. |
| Auth metadata | Toolkit auth helpers generate protected-resource and authorization-server metadata. | Keep. Resource URL, issuer, scopes, and challenges are deployment-owned configuration. |

## Drift Fixed In This Review

1. Generated templates no longer ignore `PaginatedRequestParams` in
   `list_tools`; they use a shared server helper that returns `nextCursor` and
   maps invalid cursors to JSON-RPC `Invalid params`.
2. Streamable HTTP route bundles now validate present `Origin` headers in
   addition to Host/authority, aligning the hosted path with the MCP transport
   security guidance.
3. Stale documentation links that pointed at draft or old concepts pages now
   point at the versioned 2025-11-25 specification pages.

## Invariants For New Servers

- Start from a maintained template or pattern recipe before copying code from a
  service repository.
- Import `rmcp` through `mcp_toolkit::rmcp` unless a crate has a deliberate
  low-level SDK integration reason.
- Prefer `#[tool_router(server_handler)]` for simple tools-only servers. Use an
  explicit `#[tool_handler]` implementation only when the server needs custom
  profile filtering, metadata, resources, prompts, or transport policy.
- When overriding `list_tools`, call `mcp_toolkit::server::tools::list_tools_result`
  after applying service-owned visibility filtering.
- Treat `ToolAnnotations` as client-facing hints. Do not rely on annotations as
  authorization or safety enforcement.
- Keep generated `tools/list` surfaces stable for a negotiated session. If an
  explicit profile or capability refresh changes the surface, emit
  `notifications/tools/list_changed` when the server declared that capability.
- For Streamable HTTP, keep local binds loopback by default, configure allowed
  hosts, keep Origin validation enabled, and require auth for non-loopback
  exposure.
- Do not add bespoke JSON-RPC envelopes or transport behavior when an `rmcp`
  type or service hook already exists.

## Follow-Up Watchlist

- Re-check route-bundle session error bodies whenever `rmcp` changes
  Streamable HTTP session handling. The toolkit should keep pre-forwarding
  errors small and compatible.
- Add generated contract probes for cursor pagination once probe fixtures cover
  multi-page tool lists.
- Review tool-name validation through the `rmcp` router during each SDK upgrade;
  the toolkit should avoid duplicating SDK validation unless it is enforcing a
  stricter public template policy.
