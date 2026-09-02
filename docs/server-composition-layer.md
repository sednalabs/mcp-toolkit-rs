# Rust Server Composition Layer

This note scopes the public generic server composition layer for
`mcp-toolkit-rs`.

The goal is not to turn Toolkit into an application framework or a parallel MCP
implementation. The goal is to remove repeated production wiring around RMCP
while keeping MCP protocol semantics in RMCP and domain behavior in service
repositories.

## Ownership model

The composition layer follows one rule:

> RMCP owns MCP. Toolkit owns reusable production substrate around RMCP.

For Streamable HTTP under RMCP 3.1.2 this means one primary
`StreamableHttpService` is capable of serving both protocol eras:

- MCP 2026-07-28 requests are stateless and carry protocol/client metadata per
  request;
- pre-2026 compatibility traffic may use the legacy initialize/session
  lifecycle;
- Toolkit must not pre-route a valid current-protocol request through legacy
  `Mcp-Session-Id` lookup merely because a stale session header is present.

Toolkit owns deployment concerns around that service, including:

- bind safety;
- Host and Origin guarding;
- auth-surface composition;
- health and discovery route assembly;
- bounded legacy-session capacity and retention;
- legacy live-session context markers;
- cancellation and shutdown wiring;
- reusable contract tests and starter templates.

RMCP continues to own:

- JSON-RPC request and response semantics;
- current-versus-legacy protocol classification;
- Streamable HTTP response framing;
- protocol-version validation;
- MCP Tasks and other protocol extensions;
- current-protocol stateless request dispatch.

## Why this belongs in Toolkit

Rust MCP services repeatedly need the same production wiring:

- auth surface setup;
- protected-resource and OIDC discovery routing;
- safe HTTP bind and host policy;
- bounded legacy-session compatibility;
- graceful shutdown;
- request-level observability;
- tool-surface contract tests.

That repetition is a signal for a small optional composition layer. It is not a
reason to duplicate RMCP lifecycle or protocol state machines.

## Streamable HTTP runtime

`crates/mcp-toolkit-server` exposes the preferred hosted HTTP front door.

`LocalMcpHttpRuntimeBuilder` constructs a primary RMCP 3 Streamable HTTP
service. The historical public field name `stateful_service` is retained for
compatibility, but the service is dual-era:

- current MCP requests are stateless;
- only legacy traffic uses Toolkit's bounded session manager.

`allow_resume(true)` currently controls legacy session-era resumability. It does
not imply native MCP 2026 retained-event replay.

### Legacy sessionless fallback

`stateless_fallback(true)` is retained only as a compatibility path for
pre-2026 clients that issue sessionless non-initialize POST requests. It is not
needed for MCP 2026-07-28, because RMCP's primary service already handles current
requests statelessly.

New code should not interpret the existence of this fallback as a second normal
MCP runtime.

### Current-protocol routing

The route bundle deliberately delegates current-protocol POST, GET, and DELETE
requests to RMCP before applying legacy session preflight. This prevents an old
or stale `Mcp-Session-Id` header from stealing routing authority from a valid
current request.

Headerless POSTs without an explicit protocol-version header are ambiguous. The
Toolkit route may inspect a bounded request body only to distinguish:

- a legacy initialize request;
- a current request carrying the 2026 protocol version in request `_meta`;
- an older sessionless compatibility request.

After that bounded classification, RMCP remains the protocol engine.

## Replay and event retention

Do not conflate Toolkit's existing legacy session recorder with RMCP 3 native
stateless replay.

The legacy recorder preserves session-era identifiers such as
`index[/request_id]` and resolves events with an already-known session. RMCP's
current `EventStore` contract requires opaque globally unique event identifiers
that can recover the originating stream from `Last-Event-Id` alone.

Those are different identity contracts even though both persist events.

Native bounded MCP 2026 replay is therefore a separate adaptation, tracked by
issue #190. Until that work lands, documentation and health output must not
claim that legacy `allow_resume` enables current-protocol retained-event replay.

## Low-level HTTP crate

`mcp-toolkit-http` owns HTTP-adjacent helpers and bounded legacy-session
substrate. It does not own the current MCP front door.

In particular, `streamable::handle_stateful_mcp_request` is a legacy
session-era compatibility helper. New hosted MCP services should use
`mcp-toolkit-server` or RMCP directly for current protocol routing.

The low-level crate remains useful for:

- Host and Origin validation;
- OAuth metadata URL construction;
- bounded legacy session management;
- legacy session persistence and retention;
- constructing RMCP Streamable HTTP services.

## Live session context

Legacy route helpers attach
`mcp_toolkit_http::streamable::LiveMcpSessionId` only after the authoritative
session manager confirms exact live membership.

That marker proves only transport-scoped session membership at routing time. It
does not authenticate an actor or authorize a tool. Services that require
actor-bound sessions must derive a stronger service-owned authority marker after
authentication and session binding.

## Public pieces

The current composition surface includes:

- `stdio::StdioServerBuilder` for stdio startup;
- `stdio::serve_stdio` for the common stdio serve and wait loop;
- `auth::AuthSurfaceBuilder` for auth-surface normalization and layer assembly;
- `http::HttpBindSafety` for fail-closed non-loopback exposure checks;
- `http::LocalMcpHttpRuntimeBuilder` for RMCP 3 HTTP runtime composition;
- `http::LocalMcpHttpServerBuilder` for the common hosted route bundle;
- `http::LocalMcpHttpRouterBuilder` for partial adoption into an existing
  router.

The public API should stay small and driven by repeated adopter code.

## What must stay out

The composition layer should not absorb:

- business logic;
- backend client construction;
- domain-specific routes or response payloads;
- product-specific capability names;
- service-specific policy decisions;
- a duplicate MCP task or transport state machine;
- provider-specific endpoint heuristics that can be expressed through standard
  discovery or caller configuration.

Those concerns belong in service repositories, reference architectures, or the
upstream SDK when they are protocol-level capabilities.

## Adoption posture

The layer supports three adoption styles:

1. Full adoption: use `StdioServerBuilder` or `LocalMcpHttpServerBuilder` for the
   standard front door.
2. Partial adoption: use selected runtime, auth, host, or route helpers inside an
   existing service architecture.
3. No adoption: highly specialized services may use lower-level Toolkit crates
   or RMCP directly.

The objective is to make the correct production path convenient, not mandatory.

## Maintained templates

The maintained starters exercise the supported path:

- `templates/curated-stdio-intent-server` demonstrates a current-protocol stdio
  server with typed tools, explicit inventory metadata, schema snapshots, and a
  real JSON-RPC smoke test;
- `templates/single-crate-public-stdio-server` demonstrates the public minimal
  stdio shape;
- `templates/hosted-http-auth-server` demonstrates RMCP 3 Streamable HTTP
  composition, Host/Origin guarding, OAuth Protected Resource Metadata, bearer
  challenges, tool-schema snapshots, and route-level contract tests.

Contract tests should cover current-protocol callability as well as deliberately
named legacy compatibility behavior. Tests that expect a legacy session must use
an explicit pre-2026 protocol rather than an ambiguous SDK alias.

## Next slices

Further work should be driven by repeated production need:

1. implement bounded RMCP-native current-protocol replay under #190;
2. expand reusable transport contract tests without duplicating RMCP's own
   protocol suite;
3. add standard tool/task lifecycle observability around RMCP;
4. keep auth, provenance, admission, process supervision, and task authority as
   optional production substrate;
5. prove each new abstraction in at least one real adopter before broadening the
   API.

Use `docs/golden-path.md` when adopting this layer in a new server. The golden
path defines contract testing, hosted CI evidence, review handoff, and release
readiness expectations.
