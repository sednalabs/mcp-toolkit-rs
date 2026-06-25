# Auth Surface (OAuth + PRM + Enforcement)

This document defines the **Auth Surface** contract implemented by the Rust MCP toolkit.
It exists to keep OAuth discovery, Protected Resource Metadata (PRM), and auth enforcement
consistent and spec-aligned across all MCP HTTP servers.

## Goals

- Provide a single, reusable implementation of OAuth discovery and PRM endpoints.
- Enforce auth consistently for protected MCP paths.
- Prevent issuer confusion by making issuer selection deterministic.
- Align behavior with public specifications for open-source compatibility.

## Required Contract vs Recommended Convention

The toolkit contract is intentionally smaller than any one deployment recipe.

Required contract:

- deterministic issuer selection
- correct RFC 8414 and RFC 9728 metadata
- bearer enforcement with RFC 6750-compatible challenges
- explicit protected-resource URLs

Recommended deployment convention:

- one shared OIDC issuer realm for a fleet
- explicit optional client scopes such as `ops:read` / `ops:write`
- a stable logical audience such as `example-mcp`
- the concrete MCP resource URL as a custom audience, such as
  `https://ops.example.com/mcp`

That convention has worked well operationally because it keeps resource metadata, audience
validation, and client configuration aligned. It should be documented as recommended rather than
mandatory.

## Specs (Alignment Targets)

- **RFC 8414** — OAuth 2.0 Authorization Server Metadata (well-known paths)
- **RFC 9728** — OAuth 2.0 Protected Resource Metadata (PRM)
- **RFC 6750** — Bearer Token Usage (WWW-Authenticate error semantics)
- **MCP Authorization Spec** — resource metadata + bearer challenges

## Option A / B / C Decision

### Option A (Operational Default)
**Single issuer everywhere.**
Every MCP server advertises a single issuer in PRM and returns a single
authorization-server metadata response. This is the default operational mode.

### Option B (Structural Design)
**Issuer registry keyed by resource path.**
The toolkit supports multiple issuers by binding each issuer to a **resource path**
(e.g., `/mcp`, `/mcp/github`). This is path-selected and deterministic.

### Option C (Explicitly Forbidden)
**Per-request issuer selection (token-based or claim-based).**
This is forbidden because it creates issuer confusion and expands the attack surface.
If a future ADR explicitly approves it, it must include:
- threat modeling (issuer mix-up, SSRF, downgrade risks),
- a deterministic selection rule,
- conformance tests that detect ambiguous issuer selection.

## Auth Surface Behavior

### Discovery Endpoints
For each resource path, the auth surface serves RFC 8414 discovery at the well-known
candidate paths (including the canonical path-inserted route). Authorization-server
metadata is published inline by the MCP server from a generic metadata source model.
OIDC discovery endpoints are served as redirects to the configured issuer’s OIDC metadata.

The auth surface is not itself a full OAuth authorization server. It publishes
metadata and enforces bearer auth for protected resource paths; it does not
mint tokens, host consent UI, or implement dynamic client registration.
`registration_endpoint` is published only when the configured metadata source
provides one. For OIDC-derived metadata that means reflecting the issuer's
advertised endpoint; for explicit metadata it means serving the caller-supplied
endpoint. The toolkit still does not proxy or implement dynamic client registration.

### Authorization-Server Metadata Sources
The toolkit owns a generic source model for published authorization-server metadata.
Servers can configure each issuer entry from either:

- **Explicit metadata**
  - the server supplies the full authorization-server metadata document directly
- **OIDC discovery metadata**
  - the server supplies trusted OIDC discovery output and the toolkit derives the
    published authorization-server metadata from it

This keeps inline metadata publication generic across public MCP servers while avoiding
provider-specific assumptions in consumer services.
### PRM Endpoints
PRM metadata is served per RFC 9728 using a canonical resource URL plus `authorization_servers`.
Root aliases are only served if there is a single resource entry (or the resource itself is `/`).

The `resource` value should normally be the externally reachable MCP URL, not an internal
loopback origin. For example, if a server listens on `127.0.0.1:8000` behind Cloudflare Tunnel but
is published at `https://example-mcp.example.com/mcp`, the PRM `resource` should be
`https://example-mcp.example.com/mcp`.

### Auth Enforcement
Protected resource paths require valid bearer tokens. Failures return:
- `401` or `403` as appropriate
- `WWW-Authenticate: Bearer` with `resource_metadata=...`
- RFC 6750 error codes only (`invalid_request`, `invalid_token`, `insufficient_scope`)

Services that need to extract bearer tokens before handing them to an auth
backend should use `mcp_toolkit_auth::parse_strict_bearer_authorization`. The
helper enforces the toolkit strict-mode shape: one `Authorization` header,
case-insensitive `Bearer`, exactly one ASCII space, no control characters, and
a non-empty token.

### Public Paths
Some endpoints (health checks, metrics) can bypass auth enforcement by configuring:
- `public_paths` for exact path matches
- `public_prefixes` for subtree matches (e.g., `/metrics`)

Avoid using `/` as a public prefix unless you intentionally want to disable auth.

### Unmatched Routes
By default, routes that are not public and do not match any configured resource path
fail closed with `404 Not Found`.

Servers that intentionally allow unrelated routes to bypass the auth surface should
construct the layer or registry with:
- `AuthSurfaceLayer::from_config_with_unmatched_route_policy(config, UnmatchedRoutePolicy::PassThrough)`
  or `IssuerRegistry::new_with_unmatched_route_policy(config, UnmatchedRoutePolicy::PassThrough)`

Keep the default fail-closed posture when the auth surface is expected to protect
the whole server except for explicitly declared public paths.

### URL Validation
All metadata URLs must be absolute HTTPS by default. Set `allow_insecure_http`
to `true` only for local development environments.

## External App Pattern

For browser-based external apps, especially remote MCP consumers, the recommended identity model
is:

- separate user principal for actor attribution
- separate OAuth client for channel/application policy

Example:

- user: `example-user`
- client: `example-remote-mcp-client`

This lets servers attribute actions via `preferred_username` while operators still control redirect
URIs, refresh-token posture, consent, and client-specific scope allowlists independently.

## Gateway Audience Caveat

Some deployments insert an internal gateway between the MCP server and the privileged admin API.
Those architectures can require an extra audience for token exchange, such as
`admin-gateway`, in addition to the MCP resource audience.

That is a legitimate deployment requirement, but it is not a universal `mcp-toolkit-rs`
requirement. Toolkit docs should call it out as an operator-facing caveat, not part of the base
auth-surface contract.

## ChatGPT-Facing Guidance

For ChatGPT Web App and similar remote MCP consumers:

- publish a stable remote MCP URL
- advertise a public issuer and PRM resource that match that URL
- support refresh-token capable OAuth, typically via `offline_access`
- prefer a static confidential client for the first rollout before adding dynamic client
  registration policy complexity

## Conformance
Auth surface behavior must be tested using a shared contract test.
This first slice currently covers:
- PRM endpoint returns expected `resource` and `authorization_servers`
- protected paths return a missing-token Bearer challenge with `resource_metadata`
- for the current toolkit contract slice, any configured `scope` hint must match the toolkit's emitted `scopes_supported.join(" ")` value
- RFC 6750 `error` and `error_description` fields are optional for missing-token challenges and are not part of this shared conformance requirement
- the shared helper accepts the RFC 9110 `1*SP` separator between `Bearer` and auth-params, but still rejects tabs/newlines and malformed non-space separators
- the shared helper intentionally does not parse the full Bearer auth-param grammar or re-interpret `scope` as generic content
- reusable assertions for this slice live in `mcp-toolkit-testing::auth_surface_contract`, including:
  - `AuthSurfaceContract` for PRM and missing-token bearer challenges
  - `AuthorizationServerMetadataContract` for issuer metadata, device authorization endpoints, and grant type lists
  - `AuthSurfaceProbeClient` and `AuthSurfaceProbeResponse` for runtime HTTP probes driven by each server's own test client
  - `assert_forbidden_without_bearer_challenge` for pre-auth guard failures such as host rejection

This first slice does not yet cover invalid-token, insufficient-scope, or auth-server
discovery variants.

OpenAI Apps connectors should additionally use
`mcp-toolkit-testing::openai_apps_contract::OpenAiAppsConformanceProfile`. That
profile composes the generic auth-surface expectations with Apps-specific
checks for descriptor-level and `_meta["securitySchemes"]` parity, PKCE `S256`,
declared client registration mode, compatible token endpoint auth methods, and
runtime `_meta["mcp/www_authenticate"]` challenge details.

The contract test is required for every new HTTP MCP server.

## Server Adoption Checklist

1. Configure a canonical `public_base_url` for the server.
2. Create one `IssuerEntry` per protected resource path (single issuer by default),
   preferably via the generic authorization-server metadata source model.
3. Wrap the HTTP service/router with `AuthSurfaceLayer`.
4. Configure any `public_paths` or `public_prefixes` for unauthenticated endpoints.
5. Keep the default unmatched-route behavior unless unrelated routes should
   intentionally pass through the auth surface.
6. Add the shared auth-surface contract test to CI.
