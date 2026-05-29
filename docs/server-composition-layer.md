# Rust Server Composition Layer

This note scopes a possible public-generic server composition layer for
`mcp-rs-toolkit`.

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

That repetition is a signal that a small composition layer could help, as long
as it stays optional and transport-specific.

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

## Proposed Shape

The likely shape is a small, opinionated assembly crate or module family layered
above the existing low-level crates:

- `mcp-toolkit-auth`;
- `mcp-toolkit-http`;
- `mcp-toolkit-core`;
- `mcp-toolkit-observability`.

Possible public pieces:

- `auth_surface_runtime`;
- `streamable_http_runtime`;
- `discovery_routes`;
- `serve_http`;
- `request_observability`.

Whether these land as one crate or a small family should be decided only after
the first extraction pass. The guiding rule is to keep the public API small and
obviously reusable.

## Adoption Posture

The composition layer should support three adoption styles:

1. Full adoption: the server wants the toolkit to assemble most of the HTTP and
   MCP runtime.
2. Partial adoption: the server already has a router or runtime split and wants
   selected helpers.
3. No adoption: stdio-only or highly specialized services should not be forced
   into the composition layer.

## First Implementation Slice

The first code slice should stay narrow:

1. inventory the common inputs and outputs for auth-surface and streamable HTTP
   runtime helpers;
2. extract one helper family with focused tests;
3. prove it in one or two reference services;
4. only then decide whether broader route-bundle extraction is worth the API
   surface.

That keeps the toolkit public, composable, and honest about what is truly
shared.
