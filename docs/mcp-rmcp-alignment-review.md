# MCP/rmcp Alignment Review

This document is the current alignment review for `mcp-toolkit-rs` against the
official MCP Rust SDK and the MCP 2026 protocol cut line.

Review date: 2026-08-17.

## Reviewed baseline

- Rust SDK: `rmcp = 3.1.2`, exact published release `rmcp-v3.1.2`.
- Toolkit protocol cut line for maintained starters and contract tests:
  `2026-07-28`.
- Legacy compatibility remains deliberate for pre-2026 clients where the SDK
  still supports it.
- `mcp-toolkit-gemini` has been retired from the active workspace. Provider
  specific compatibility code is not an architectural precedent for new
  Toolkit abstractions.

The migration was reviewed against the exact pinned RMCP 3.1.2 source, not the
moving Rust SDK main branch.

## Governing rule

> RMCP owns MCP protocol semantics. Toolkit owns reusable production substrate
> around RMCP.

Toolkit must not become a parallel MCP implementation.

Protocol-level behavior belongs in RMCP whenever the SDK exposes the required
surface. Toolkit may add deployment policy, production hardening, authority,
observability, persistence adapters, process supervision, testing helpers, and
server-authoring ergonomics without replacing RMCP's protocol state machines.

## SDK version posture

The Toolkit is the RMCP version authority for the workspace. Direct RMCP
runtime dependencies use the exact coordinated pin `=3.1.2`.

Exact lockstep is intentional. A behavior-changing RMCP patch must be treated as
an SDK migration with hosted conformance evidence rather than silently accepted
through Cargo resolution.

Maintained starter templates consume the server-authoring surface through
Toolkit facade features and do not independently select an RMCP version.

Some low-level consumer crates may still require a direct dependency named
`rmcp` because RMCP procedural macros can emit literal `rmcp::...` paths. Such a
dependency is an implementation requirement, not permission for version drift.
It must remain exactly aligned with the Toolkit-owned RMCP version.

Dependency governance therefore requires:

- every direct RMCP dependency to use a concrete exact version;
- all direct RMCP dependencies in the workspace to agree;
- any direct macro/runtime dependency combination to remain aligned;
- maintained templates to avoid introducing an independent SDK version policy.

## ProtocolVersion nuance

RMCP 3.1.2 supports `ProtocolVersion::V_2026_07_28`, but its
`ProtocolVersion::LATEST` constant deliberately remains
`ProtocolVersion::V_2025_11_25`.

Toolkit must not equate the SDK's conservative `LATEST` alias with the newest
protocol version supported by that SDK release.

For this migration:

- Toolkit's current-protocol test harness deliberately selects `2026-07-28`;
- legacy session tests deliberately select an explicit pre-2026 version;
- protocol-era classification uses the SDK model or an explicit 2026 boundary,
  rather than assuming `LATEST` means current Toolkit policy;
- future SDK upgrades must re-audit this relationship rather than inheriting
  the current constants by assumption.

## MCP 2026 lifecycle

MCP 2026-07-28 removes the protocol-level session lifecycle used by earlier
versions. Current requests carry protocol and client context per request.

Toolkit's maintained stdio contract therefore uses the current request model:

- no initialize/initialized handshake for the 2026 path;
- every ordinary request carries the required current-protocol `_meta`;
- explicit older versions retain the legacy initialize/initialized flow for
  compatibility testing.

The harness must not infer lifecycle solely from one literal equality in a way
that would send a newer supported protocol through legacy initialization.

## Streamable HTTP ownership

RMCP 3.1.2's primary `StreamableHttpService` already understands both protocol
eras.

For current MCP requests:

- POST is stateless;
- GET may be used for native retained-event replay when an RMCP `EventStore` is
  available;
- DELETE does not perform legacy session termination;
- current request routing must not depend on `Mcp-Session-Id`.

For legacy requests, RMCP may still use the initialize/session lifecycle.
Toolkit's bounded session manager remains a compatibility and deployment layer
around that SDK behavior.

The Toolkit HTTP front door must therefore follow this ordering:

1. apply deployment-level Host, Origin, authentication, and route policy;
2. identify an explicitly current request using SDK protocol metadata;
3. delegate current GET/POST/DELETE semantics to RMCP;
4. apply Toolkit legacy-session preflight only to legacy or genuinely ambiguous
   compatibility traffic.

A stale, malformed, unknown, or expired legacy `Mcp-Session-Id` must not steal
routing authority from an otherwise valid current-protocol request.

## Ambiguous headerless POSTs

A headerless POST can be ambiguous because compatibility traffic may include a
legacy initialize request while a current request may identify its protocol in
request metadata.

Toolkit may buffer a strictly bounded request body only to classify this outer
routing ambiguity. It must not implement a second JSON-RPC engine.

Once the route is classified, RMCP remains authoritative for protocol parsing,
validation, dispatch, and response framing.

## SEP-2243 standard HTTP headers

RMCP 3.1.2 enforces SEP-2243 standard headers for requests declaring protocol
version `2026-07-28` or newer.

Current HTTP contract tests must therefore model a complete request, including:

- `MCP-Protocol-Version`;
- required current request `_meta`;
- `Mcp-Method` matching the JSON-RPC method;
- `Mcp-Name` only for methods whose protocol shape carries a routable name,
  URI, or task ID;
- applicable `Mcp-Param-*` headers when a tool schema promotes annotated
  primitive arguments.

A 400 from RMCP for an incomplete SEP-2243 request is correct behavior and must
not be worked around by weakening server validation.

## Tool and result models

RMCP 3 changed several protocol-facing Rust types. Toolkit migration must use
SDK models instead of recreating old structures.

Current decisions include:

- generic descriptor/result metadata uses `MetaObject` where that is the exact
  RMCP field type;
- request and notification metadata retain their distinct SDK metadata types;
- tool calls use RMCP's `CallToolResponse` union rather than forcing every call
  back into a plain `CallToolResult`;
- list results use RMCP constructors so cache/result metadata evolves with the
  SDK rather than being hand-built from stale fields.

This preserves native paths for Tasks and future RMCP result variants.

## MCP Tasks

MCP Tasks are the official `io.modelcontextprotocol/tasks` extension.

RMCP owns:

- task protocol methods and result models;
- task statuses and status-specific payloads;
- `input_required` and `tasks/update` behavior;
- cooperative cancellation semantics;
- TTL behavior;
- terminal result/error projection.

Toolkit must not reintroduce removed legacy methods such as `tasks/list` or
`tasks/result` as wire protocol.

Toolkit may add production authority around RMCP. The task-authority work in
#186 therefore uses RMCP's native `TaskManager` and adds only reusable concerns
such as principal binding, concealed cross-principal access, race-safe
observation generations, bounded waiting, and stale authority-record cleanup.

A Toolkit task revision is an observed snapshot generation, not a duplicate
task event log. It advances only after an authoritative RMCP `DetailedTask`
read actually changes.

## Task durability boundary

RMCP 3.1.2's native task manager is process-local. A process restart cannot
honestly resurrect an in-flight Rust future merely because its last task record
was persisted.

Durable task support must first define an RMCP-native persistence/restoration
boundary and explicit crash semantics. This is tracked in #191.

Any future implementation must preserve principal ownership, TTL semantics,
terminal integrity, and duplicate-execution safety without copying RMCP's task
state machine into Toolkit.

## Replay and event retention

Toolkit's historical legacy-session replay format is not equivalent to RMCP 3
native stateless retained-event replay.

The legacy recorder uses session-era event identity such as
`index[/request_id]` together with an already-known session. RMCP's native
`EventStore` requires opaque globally unique event IDs that can resolve the
originating stream from `Last-Event-Id` alone.

Those contracts must not be conflated merely because both persist SSE events.

A bounded RMCP-native current-protocol replay adapter is tracked in #190.
Until that lands:

- legacy `allow_resume` must not be advertised as native MCP 2026 replay;
- current GET routing should still delegate to RMCP so the future native store
  can be connected without another protocol rewrite.

## Host, Origin, authentication, and policy

Deployment-level security remains an appropriate Toolkit responsibility.

Toolkit may enforce:

- loopback-first bind posture;
- explicit non-loopback authorization requirements;
- Host/authority validation;
- Origin validation;
- OAuth protected-resource and authorization-server metadata;
- route/method/scope policy;
- actor/session binding stronger than transport-level session membership.

These controls must not reinterpret valid MCP protocol messages after RMCP has
become authoritative for protocol handling.

`LiveMcpSessionId` proves only that a legacy session ID was live in the
configured session store at routing time. It does not authenticate an actor and
must never be treated as application authorization by itself.

## Tool inventory and discovery policy

Toolkit may continue to own server-authoring policy that is not protocol state:

- fail-closed tool inventory registration;
- profile-aware tool visibility;
- capability and safety-hint projection;
- schema snapshots;
- bounded cursor helpers;
- deferred tool search and compact discovery responses;
- list-change observation for deliberate capability/profile changes.

Tool annotations are client-facing hints, not authorization.

## Current alignment inventory

| Area | Authority | Toolkit decision |
| --- | --- | --- |
| RMCP dependency version | Toolkit workspace policy | Exact coordinated `=3.1.2` pin. |
| JSON-RPC models and handler traits | RMCP | Reuse directly. Do not duplicate. |
| stdio MCP 2026 lifecycle | RMCP semantics, Toolkit test harness | Current path uses per-request metadata without initialize. |
| legacy stdio lifecycle | RMCP | Retain only for explicit compatibility tests. |
| Streamable HTTP protocol routing | RMCP | Current GET/POST/DELETE delegate to the primary RMCP service. |
| legacy session capacity | Toolkit deployment policy around RMCP | Keep bounded and explicitly legacy. |
| legacy session preflight | Toolkit compatibility policy | Must never intercept valid current requests. |
| SEP-2243 headers | RMCP | Tests and clients must send the exact SDK-standard header contract. |
| MCP Tasks state machine | RMCP | Wrap with production authority; do not fork. |
| task principal ownership | Toolkit | Keep fail-closed and cross-principal concealed. |
| durable task recovery | unresolved RMCP/Toolkit boundary | Track in #191 before implementing. |
| current retained-event replay | RMCP `EventStore` contract | Build a compatible bounded adapter under #190. |
| Host/Origin/bind posture | Toolkit deployment layer plus RMCP native guards | Keep aligned; prefer SDK hooks where available. |
| OAuth metadata and deployment auth | Toolkit | Keep provider-neutral and configuration driven. |
| tool inventory/profile policy | Toolkit | Keep as server-authoring policy. |
| generated server templates | Toolkit | Exercise the current supported path and exact SDK policy. |

## Automated guardrails

The coordinated SDK migration is not complete merely because `cargo check`
passes. Hosted validation should cover:

- one exact RMCP pin across direct workspace dependencies;
- maintained template fmt, Clippy, and tests;
- full workspace fmt, Clippy, and tests;
- Rust 2024 compatibility;
- dependency audit and deny policy;
- CodeQL/query policy checks used by the repository;
- current HTTP contract tests;
- deliberate legacy compatibility tests;
- exact task lifecycle race tests for any production task wrapper.

A PR is review-ready only when the final remote head and the correct synthetic
PR merge commit have the required evidence. Green checks from an older head or
an older base are useful diagnostic evidence but are not final promotion proof.

## Invariants for new servers

- Start from a maintained Toolkit template or documented adoption path.
- Let Toolkit own the coordinated RMCP version.
- Declare a direct `rmcp` dependency only when the SDK/macro integration truly
  requires the crate name, and keep it in exact lockstep.
- Do not use `ProtocolVersion::LATEST` as a synonym for Toolkit's chosen current
  protocol without checking the exact pinned SDK.
- Do not add bespoke JSON-RPC envelope handling when RMCP exposes the needed
  model or service hook.
- Treat current MCP HTTP traffic as stateless unless the specification and SDK
  say otherwise.
- Keep legacy session compatibility explicit and isolated.
- Send the complete SEP-2243 header contract for MCP 2026 HTTP requests.
- Treat tool annotations as hints, never authorization.
- Keep inventory policy fail-closed for public and generated servers.
- Bind long-running task authority to authenticated principals without
  replacing RMCP's task state machine.
- Make crash, persistence, replay, and recovery identity contracts explicit
  before sharing storage implementations across protocol eras.

## Upgrade watchlist

For every future RMCP upgrade, recheck at minimum:

1. supported protocol versions and the meaning of `ProtocolVersion::LATEST`;
2. Streamable HTTP current/legacy classification;
3. standard HTTP header requirements;
4. session-manager and `EventStore` contracts;
5. Tasks models, manager behavior, TTL, cancellation, and restoration hooks;
6. proc-macro emitted crate paths and downstream direct-dependency needs;
7. `CallToolResponse`, list-result, and metadata model changes;
8. maintained template feature flags;
9. Toolkit preflight behavior against the exact SDK implementation;
10. whether any Toolkit compatibility layer can now be deleted in favor of a
    public RMCP hook.

The desired long-term shape remains simple:

- RMCP is the protocol/SDK implementation;
- `mcp-toolkit-rs` is the hardened reusable production substrate;
- downstream MCP servers contain domain behavior and service-specific policy.
