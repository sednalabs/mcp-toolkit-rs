# Shared Capability Projections

This note scopes the generic capability model that lets toolkit consumers define
one operation and project it into multiple AI-client contracts.

## Rationale

MCP servers increasingly need more than one client-facing surface. A server may
publish MCP tools for native clients and also publish an OpenAPI contract for
HTTP-native clients. If each surface hand-maintains names, schemas, scopes,
safety hints, and audit identifiers, the contracts drift.

The toolkit should provide reusable substrate for that shared metadata without
absorbing a service's domain model, backend clients, deployment topology, or
operator workflow.

## Ownership

`mcp-toolkit-core` owns the generic data model:

- canonical capability identity;
- model-facing title and description;
- JSON Schema input and output contracts;
- required OAuth scope metadata;
- safety hints that can be projected into MCP annotations;
- audit event identity;
- examples suitable for docs and contract fixtures.

Projection helpers may turn the same capability into:

- `rmcp::model::Tool` values for MCP hosts;
- Apps-compatible MCP tool descriptor JSON with `securitySchemes` mirrored at
  both the descriptor field and `_meta["securitySchemes"]`;
- OpenAPI operation objects for REST/OpenAPI hosts;
- OpenAPI OAuth 2 authorization-code security scheme metadata from
  caller-supplied endpoint URLs and scopes;
- parity fixtures that compare the projected scopes, schemas, and safety
  metadata.

## Non-Ownership

The toolkit does not own:

- service-specific tool handlers;
- backend clients;
- database or data-access semantics;
- deployment-specific hosts, tunnels, client IDs, or secrets;
- product-specific domain vocabulary;
- authorization decisions beyond carrying required scope metadata.

Those remain in the consuming server or application repository. The toolkit
helps keep the contracts aligned; it does not decide what a service is allowed
to do.

## Public API Boundary

The first public shape is deliberately small:

- `Capability` describes one operation.
- `CapabilityRegistry` stores a deduplicated list of operations.
- `CapabilitySafety` carries read-only, destructive, idempotent, and open-world
  hints.
- `ScopePolicy` carries normalized OAuth scope names.
- `AuditPolicy` carries a stable event name for logs and downstream audit.
- `OpenApiOAuth2AuthorizationCodeSecurityScheme` builds generic OpenAPI OAuth 2
  security metadata when callers provide their own authorization and token URLs.
- `Capability::to_mcp_apps_tool_descriptor()` builds the Apps-facing descriptor
  projection from the same capability scopes. Scoped capabilities emit `oauth2`;
  unscoped capabilities emit `noauth`.
- Projection helpers produce MCP and OpenAPI operation metadata without
  registering handlers.

The API should remain generic. Prefer names such as capability, projection,
scope policy, and safety hints. Avoid crate names or public promises that imply
ownership of a vendor SDK unless the implementation actually covers that
contract.

## Adapter Strategy

Capability metadata is canonical, but adapters can differ:

- MCP projection emits tool metadata and annotations.
- Apps projection emits the same MCP tool fields plus per-tool
  `securitySchemes` at the standard descriptor field and `_meta` compatibility
  mirror. This projection is intentionally JSON-shaped because the current
  `rmcp` tool model may not expose every host extension field.
- OpenAPI projection emits operation metadata, request/response schemas, and
  security requirements. An empty scope policy emits an explicit OpenAPI
  `security: []` requirement so a document-level security requirement cannot
  accidentally make a public capability authenticated. When no output schema
  is supplied, the output remains unspecified: native MCP and Apps omit
  `outputSchema`, while OpenAPI omits the response media type's `schema` rather
  than inventing a placeholder object schema.
- OAuth security scheme projection emits only standard OpenAPI metadata; callers
  still choose real authorization URLs, token URLs, public hosts, client IDs,
  and client secrets.
- Service repositories decide route paths, handlers, request execution, and
  deployment settings.

The same capability can therefore serve a native MCP client and an HTTP/OpenAPI
client while preserving the same schemas, required scopes, safety class, and
audit identity.

## Validation

Every projection helper should have whole-object tests that prove:

- required scopes are preserved across MCP metadata and OpenAPI security;
- required scopes are preserved across Apps descriptor-level and `_meta`
  `securitySchemes`;
- unscoped Apps capabilities are explicitly projected as `noauth`;
- read-only and destructive hints project to MCP annotations;
- input and output schemas are preserved;
- duplicate capability identifiers are rejected by registries;
- OpenAPI security scheme names are required when scoped capabilities are
  projected;
- unscoped capabilities explicitly override global OpenAPI security with
  `security: []`;
- OAuth 2 authorization-code security scheme metadata preserves caller URLs and
  scopes;
- generated OpenAPI operation identifiers are stable;
- registry projections preserve deterministic registration order.

Hosted validation remains the merge gate for public toolkit changes. Local test
commands are not the shared proof surface for this repository.

## References

- `docs/toolkit-boundary.md`
- `docs/golden-path.md`
- `docs/server-composition-layer.md`
- OpenAI GPT Actions documentation
- OpenAI Apps SDK MCP server documentation
