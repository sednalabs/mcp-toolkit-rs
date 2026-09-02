# Rust Server Composition Layer

This note scopes the public-generic server composition layer for
`mcp-toolkit-rs`.

The goal is not to turn the toolkit into an application framework. The goal is
to reduce repeated MCP server bootstrap wiring while keeping domain logic,
backend clients, and deployment-specific contracts out of the toolkit.

## Why This May Belong In The Toolkit

Rust MCP services often repeat the same setup work:

- auth surface setup;
- protected-resource and OIDC discovery routing;
- streamable HTTP session and replay wiring;
- stateful plus stateless fallback service wiring;
- host and auth middleware composition;
- graceful shutdown and bind handling;
- request-level observability scaffolding.

That repetition is a signal that a small composition layer helps, as long as it
stays optional and transport-specific.

## Possible Extraction Targets

### Auth-Surface Runtime Helper

Package the common steps for:

- deriving canonical resource URLs from a public base URL;
- building `AuthSurfaceConfig`;
- creating `AuthSurfaceLayer`;
- wiring standard public and protected path handling.

This should stay generic and avoid issuer or audience heuristics beyond values
configured explicitly by the caller.

### Streamable HTTP Session Runtime Helper

Package the common steps for:

- building `SessionConfig`;
- creating bounded session managers;
- optional event-store construction;
- optional recording session managers;
- resume mode and stateless fallback wiring;
- cancellation-token propagation.

This helper should build runtime pieces, not the domain server itself.

### Discovery Route Bundle

Package the standard route set for:

- health;
- protected-resource metadata;
- authorization-server metadata;
- OIDC metadata;
- `/mcp`.

Servers should be able to opt into the bundle and add their own routes around
it.

### HTTP Serve Helper

Package repeated serve logic for:

- bind address handling;
- optional TLS setup;
- graceful shutdown;
- `axum_server` launch.

This should stay compatible with all-in-one routers and partially prebuilt
routers.

### Request Observability Hooks

Package common request-level observability hooks so servers can opt into:

- request outcome logging;
- safe host and header capture;
- transport and auth-mode startup events.

This should provide reusable hooks, not force one logging policy on every
service.

## What Must Stay Out

The composition layer should not absorb:

- business logic;
- backend client construction;
- domain-specific routes or response payloads;
- product-specific capability names;
- service-specific policy decisions;
- one-off admin or gateway behavior.

Those concerns belong in reference services or reference architectures.

## Implemented First Slice

The first slice lives in `crates/mcp-toolkit-server`. It is a small, opinionated
assembly crate layered above the existing low-level crates:

- `mcp-toolkit-auth`;
- `mcp-toolkit-http`;
- `mcp-toolkit-core`;
- `mcp-toolkit-observability`.

Current public pieces:

- `stdio::StdioServerBuilder` for the stdio starter front door;
- `stdio::serve_stdio` for the common stdio startup and wait loop;
- `auth::AuthSurfaceBuilder` for auth-surface normalization and layer assembly;
- `http::HttpBindSafety` for fail-closed non-loopback bind posture checks;
- `http::LocalMcpHttpServerBuilder` for the common hosted HTTP route bundle;
- `http::LocalMcpHttpRuntimeBuilder` for bounded Streamable HTTP sessions and
  optional stateless fallback; every MCP POST body is buffered under one
  fail-closed limit (64 KiB by default) before either service parses it;
- `http::LocalMcpHttpRouterBuilder` for `/mcp`, `/mcp/`, `/health`, optional
  OAuth-not-configured placeholder discovery routes, and host/origin guarding.

Stateful route helpers also attach
`mcp_toolkit_http::streamable::LiveMcpSessionId` to the forwarded HTTP request
after the authoritative session manager confirms exact live membership.
Downstream MCP handlers can recover it from the `http::request::Parts` carried
by `rmcp`, avoiding a second session-store lookup. The marker is deliberately
transport-scoped: it does not authenticate an actor or authorize tools.
Services that need actor-bound sessions must derive a stronger, service-owned
marker after applying their own authentication and session-binding policy.

The guiding rule remains: keep the public API small and obviously reusable.
Service-specific health payloads, attestation payloads, backend clients, tool
handlers, and product policy stay in service repositories.

## Adoption Posture

The composition layer should support three adoption styles:

1. Full adoption: the server wants `StdioServerBuilder` or
   `LocalMcpHttpServerBuilder` to assemble the standard transport front door.
2. Partial adoption: the server already has a router or runtime split and wants
   selected helpers.
3. No adoption: stdio-only or highly specialized services should not be forced
   into the composition layer.

## Next Implementation Slices

Maintained starter templates now cover the first adoption path:

- `templates/curated-stdio-intent-server` shows a small stdio server with typed
  intent tools, explicit inventory metadata, tool-schema snapshots, and a real
  JSON-RPC stdio smoke test.
- `templates/hosted-http-auth-server` shows hosted Streamable HTTP assembly,
  host/origin guarding, OAuth Protected Resource Metadata, bearer challenges,
  device authorization metadata, tool-schema snapshots, and route-level
  contract tests.

The remaining slices should build on this crate rather than copying old wiring:

1. expand reusable contract tests for auth metadata, host/origin rejection,
   sessions, tool schema snapshots, and stdio callability;
2. prove the API in one reference server slice;
3. keep route-bundle additions driven by repeated adopter code, not speculative
   framework growth.

That keeps the toolkit public, composable, and honest about what is truly
shared.

Use `docs/golden-path.md` when turning this composition layer into a new server
or an adoption PR. The golden path defines the expected contract tests,
GitHub-hosted validation evidence, review gate handoff, and release checklist.
