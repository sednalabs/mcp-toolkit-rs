# MCP/rmcp Alignment Review

This review records the custom MCP-adjacent layers the toolkit maintains on
top of `rmcp` and the invariants that keep those layers aligned with the
official MCP specification and the official Rust SDK.

Review date: 2026-07-07.

Primary references:

- MCP specification entry point: <https://modelcontextprotocol.io/specification>
- MCP tools: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>
- MCP pagination: <https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination>
- MCP transports: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>
- `rmcp` Rust SDK: <https://github.com/modelcontextprotocol/rust-sdk>
- `rmcp` API docs: <https://docs.rs/rmcp>

Second-pass review note: the custom layers below were rechecked against the
current public MCP specification, the public `rmcp` docs, and the exact
workspace-pinned `rmcp` `2.1.0` source. The pinned SDK already owns Host
validation, optional full `Origin` validation, Streamable HTTP session routing,
protocol-version header checks, `Mcp-Session-Id`, `Last-Event-Id`, SSE event-id
formatting, and `SessionManager` restoration hooks. Toolkit code must therefore
stay in one of two categories: thin deployment assembly around those SDK
surfaces, or explicit server-authoring policy that the SDK intentionally does
not own.

Third-pass review note: the OAuth/OIDC discovery helpers were rechecked against
the MCP 2025-11-25 authorization discovery order. Toolkit auth discovery now
tries OAuth path-insertion, OIDC path-insertion, then path-appended OIDC for
issuer URLs with path components, and validates the returned issuer and endpoint
metadata before accepting a result.

Fourth-pass review note: toolkit-owned protocol defaults were rechecked against
the pinned SDK. Toolkit-owned fallbacks should use `ProtocolVersion::LATEST`
from the pinned SDK unless a compatibility test deliberately passes an older
version. The stdio contract harness now defaults to `2025-11-25`, and
`mcp-toolkit-gemini` uses `ProtocolVersion::LATEST` as its server fallback.

Fifth-pass review note: the workspace RMCP SDK pin has moved through the
toolkit facade to `rmcp` and `rmcp-macros` `2.1.0`. `mcp-toolkit-core` now also
re-exports the pinned SDK so facade consumers can route direct SDK model and
macro support through toolkit-owned version policy.

## SDK Version Posture

As of this review, the workspace pins `rmcp` and `rmcp-macros` to the same
published runtime version, `=2.1.0`, and the lockfile resolves both crates to
`2.1.0`. That is intentional: the toolkit facade owns the SDK version used by
generated servers, and generated templates import the server-authoring surface
through `mcp_toolkit::rmcp` instead of declaring their own direct `rmcp` or
`rmcp-macros` dependencies.

Treat future SDK-major or behavior-changing SDK-minor releases as coordinated
facade upgrades, not as a reason for generated servers to bypass the facade.
Before moving this workspace to the next such SDK version, re-run this
alignment review and specifically compare:

- `StreamableHttpService` and session-manager behavior against the toolkit's
  route-bundle preflight responses;
- SSE event-id shape and resume semantics against `RecordingSessionManager`;
- `#[tool_router]` / `#[tool_handler]` macro output and generated
  `tools/list` pagination;
- feature flags needed by the facade versus template dependencies;
- migration guidance from the official SDK release notes.

## Automated Guardrails

The dependency-governance workflow now treats rmcp alignment as a workspace-wide
SDK pin rule, not only a macro/runtime rule:

- every direct `rmcp` dependency must use a concrete exact version pin;
- every direct `rmcp` dependency must use the same version across workspace
  crates;
- any direct `rmcp-macros` dependency must match the direct `rmcp` runtime pin;
- starter-template integrity tests keep generated templates importing the
  authoring surface through `mcp_toolkit::rmcp`.

This means the intended shape is enforced in CI: shared toolkit crates may bind
to the SDK deliberately, generated services consume the facade, and a future
SDK major upgrade is a single coordinated review instead of gradual service
drift.

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
| Tool inventory defaults | `ToolInventoryPolicy::default()` is fail-closed for unknown tools, with an explicit `permissive()` migration helper for incomplete legacy catalogs. | Keep. Generated and public-facing servers should not list or call unregistered tools by accident. |
| Profile-filtered schema discovery | Catalog `search_response` attaches schemas only for the tools visible in the filtered result set. Full catalog snapshots may still include all registered schemas. | Keep. Deferred discovery must not leak hidden operator or profile-specific tool schemas through a profile-filtered search response. |
| Tool list changes | `ToolListTracker` fingerprints stable tool names and exposes `notifications/tools/list_changed` method metadata. | Keep with invariant: a negotiated session's tool list must not vary as an incidental side effect of ordinary requests. Emit list-changed only for explicit refresh/profile changes. |
| Streamable HTTP session routing | Route bundles use `rmcp` Streamable HTTP services plus bounded local session management and optional stateless fallback for sessionless POSTs. Requests that carry an unknown or expired `MCP-Session-Id` return HTTP 404 instead of falling back to stateless handling. | Keep. This is deployment assembly, not protocol reimplementation. |
| DNS rebinding defense | Route bundles validate Host/authority and validate present `Origin` headers. Explicit `allowed_origins` are now wired through to the underlying `rmcp` stateful and stateless services and use full origin tuple matching in the outer route guard. When explicit origins are not configured, the toolkit keeps the older host-derived Origin guard for safer local defaults. | Keep for route-bundle preflight and endpoint-ready hints. Do not add more custom parsing here when an `rmcp` configuration surface exists. Public browser-facing deployments should configure explicit `allowed_origins`. |
| Session errors | Toolkit route bundles return HTTP errors for missing/invalid sessions before forwarding to `rmcp`. | Keep, but periodically compare with `rmcp` Streamable HTTP behavior when upgrading the SDK. |
| Auth metadata | Toolkit auth helpers generate protected-resource and authorization-server metadata. | Keep. Resource URL, issuer, scopes, and challenges are deployment-owned configuration. |
| OAuth/OIDC issuer discovery | Toolkit auth helpers fetch and validate authorization-server metadata for configured issuers. | Keep centrally. Discovery must follow MCP 2025-11-25 order for pathful issuers and must validate issuer/endpoint metadata before accepting fallback results. |
| SDK pin guardrails | The umbrella crate re-exports `rmcp`, templates avoid direct `rmcp` and `rmcp-macros` dependencies, and dependency governance enforces one exact direct `rmcp` pin across the workspace. | Keep. Use this as the workspace-level upgrade checkpoint before adopting the next SDK major. |

## Drift Fixed In This Review

1. Generated templates no longer ignore `PaginatedRequestParams` in
   `list_tools`; they use a shared server helper that returns `nextCursor` and
   maps invalid cursors to JSON-RPC `Invalid params`.
2. Streamable HTTP route bundles now validate present `Origin` headers in
   addition to Host/authority, aligning the hosted path with the MCP transport
   security guidance.
3. Stale documentation links that pointed at draft or old concepts pages now
   point at the versioned 2025-11-25 specification pages.
4. Dependency governance now fails if direct `rmcp` dependencies drift to
   different SDK versions across the workspace.
5. Hosted route-bundle builders now expose explicit `allowed_origins`, copy
   them into stateless fallback services, and validate full origin tuples in
   the outer guard when configured. This keeps route-level hints aligned with
   the SDK's native `StreamableHttpServerConfig::with_allowed_origins` posture.
6. The optional SSE event-store parser now accepts only the SDK-shaped
   non-negative `index` or `index/request_id` event IDs. Malformed IDs such as
   `1/` or negative indexes no longer get treated as valid replay positions.
7. OIDC issuer discovery no longer relies only on the older
   `{issuer}/.well-known/openid-configuration` shape. It now follows the
   MCP 2025-11-25 OAuth/OIDC discovery order for pathful issuers, while keeping
   the path-appended OIDC endpoint as the compatibility fallback.
8. Route-bundle stateless fallback no longer accepts POST requests that carry an
   unknown or expired `MCP-Session-Id`. Those requests now return HTTP 404 so
   clients re-initialize the session as required by Streamable HTTP session
   semantics.
9. The hosted HTTP/auth starter now validates deployment settings before router
   construction. Loopback development still works with scaffold values, but
   non-loopback serving rejects the development delegation secret, placeholder
   issuer, and non-HTTPS public metadata URLs.
10. Tool inventory policy now fails closed by default for unknown tools, keeps
    permissive fallback behind an explicit migration helper, and profile-filtered
    tool search now returns schemas only for visible search results.
11. Toolkit-owned protocol defaults no longer fall back to `2024-11-05` by
    default. The stdio contract helper requests `2025-11-25`, and
    `mcp-toolkit-gemini` uses the pinned SDK's `ProtocolVersion::LATEST`.
12. HTTP route-bundle and Streamable HTTP tests now serialize
    `rmcp::model::ProtocolVersion::LATEST` in initialize fixtures instead of
    carrying a stale literal protocol version.
13. The RMCP SDK pin now moves through the toolkit facade at `2.1.0`; direct
    runtime and macro pins remain aligned, and facade consumers can import SDK
    model types through toolkit-owned re-exports.

## Current Risk Notes

- The toolkit intentionally carries custom session-bounding and optional SSE
  replay layers around `rmcp`'s Streamable HTTP service. Keep these layers only
  as deployment policy; do not add JSON-RPC envelope handling or standard
  transport parsing here when an `rmcp` hook exists.
- The toolkit's Host/Origin guard intentionally duplicates part of the pinned
  SDK's DNS-rebinding protection so route-level health and endpoint-hint
  responses receive the same preflight. Keep the helper aligned with `rmcp`
  semantics, prefer explicit `allowed_origins` for browser-facing deployments,
  and replace local parsing with a public SDK middleware if one becomes
  available.
- The optional `EventStore` records SDK-emitted SSE event IDs but is not wired
  into default route-bundle replay. If a future server exposes persistent
  replay through it, review that flow against the SDK's `EventId` parser and
  session-store support before shipping.
- Compatibility smoke tests may still pass explicit older protocol versions to
  the stdio harness. Keep the helper default aligned with the pinned SDK's
  latest stable protocol version.
- HTTP route bundles rely on `rmcp` to process accepted JSON-RPC requests after
  local preflight checks. On each future SDK upgrade, compare accepted/missing
  `MCP-Protocol-Version`, session-id, and SSE-resume behavior before landing.

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
- Keep default inventory policy fail-closed. Use `ToolInventoryPolicy::permissive()`
  only as a reviewed migration bridge while completing legacy registrations.
- When publishing profile-filtered tool search, include schemas only for tools
  visible in that response.
- Keep generated `tools/list` surfaces stable for a negotiated session. If an
  explicit profile or capability refresh changes the surface, emit
  `notifications/tools/list_changed` when the server declared that capability.
- For Streamable HTTP, keep local binds loopback by default, configure allowed
  hosts, configure explicit allowed origins for browser-facing deployments,
  keep Origin validation enabled, require auth for non-loopback exposure, and
  replace scaffold issuer/secret values before public serving.
- Do not add bespoke JSON-RPC envelopes or transport behavior when an `rmcp`
  type or service hook already exists.

## Follow-Up Watchlist

- Re-check route-bundle session error bodies whenever `rmcp` changes
  Streamable HTTP session handling. The toolkit should keep pre-forwarding
  errors small and compatible.
- Re-check `RecordingSessionManager` whenever `rmcp` changes SSE event IDs,
  resume behavior, or Streamable HTTP session-manager trait contracts.
- Re-check OAuth/OIDC discovery helpers whenever the MCP authorization section
  changes discovery ordering, Client ID Metadata Document requirements, or
  PKCE metadata requirements.
- Re-check facade feature flags and generated template imports before adopting
  the next `rmcp` release that changes feature, macro, model, or transport
  requirements.
- Re-check whether route-bundle Host/Origin preflight can delegate to a public
  `rmcp` middleware or hook instead of local parsing.
- Add generated contract probes for cursor pagination once probe fixtures cover
  multi-page tool lists.
- Review tool-name validation through the `rmcp` router during each SDK upgrade;
  the toolkit should avoid duplicating SDK validation unless it is enforcing a
  stricter public template policy.
