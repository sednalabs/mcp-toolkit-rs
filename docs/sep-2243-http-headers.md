# SEP-2243 standard HTTP headers

This note records the Streamable HTTP header contract used by the Toolkit's
current MCP protocol path. It is a documentation and acceptance boundary, not
a second HTTP or JSON-RPC implementation.

The protocol authority is RMCP `3.2.0`. RMCP parses the request, validates the
standard headers against the JSON-RPC body and negotiated protocol, dispatches
the method, and frames the response. Toolkit may compose deployment concerns
around that service, such as host/origin policy, authentication, route policy,
and bounded request bodies; it must not reinterpret valid MCP messages or
weaken RMCP validation.

See the MCP [Streamable HTTP request-metadata section](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#request-metadata),
especially [standard request headers](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#standard-request-headers),
and the [RMCP `3.2.0` API](https://docs.rs/rmcp/3.2.0/rmcp/).

## Version boundary

The standard-header contract applies to current MCP requests declaring
`2026-07-28` or a later supported protocol version. The current path is
stateless: protocol and client context travel with each request. The retained
pre-2026 compatibility path is different: it may use the explicit legacy
initialize/initialized and session lifecycle, and it is not required to supply
the current standard-header set.

`MCP-Protocol-Version` identifies the protocol version for the HTTP request. In
the current path it must agree with the protocol version carried in the
request's `_meta`; the HTTP header is not a substitute for that metadata. An
initialize request is part of the legacy negotiation boundary and is handled
according to the negotiated protocol rather than being treated as an ordinary
current request.

## Required current request shape

For a current request, send all of the following as one coherent contract:

| Surface | Requirement | Authority |
| --- | --- | --- |
| `MCP-Protocol-Version` | Present, supported, and consistent with the request's protocol metadata. | RMCP version negotiation and validation |
| JSON-RPC `_meta` | Present on every current request. RMCP `RequestMetaObject` carries the per-request protocol/client context; in `3.2.0`, the current required keys are the protocol-version and client-capabilities entries. | RMCP request model |
| `Mcp-Method` | Present and exactly equal to the JSON-RPC `method` value. | RMCP SEP-2243 validator |
| `Mcp-Name` | Present only when that method's parameters carry a routable name, URI, or task identifier, and equal to the body value. | RMCP method-specific mapping |
| `Mcp-Param-*` | Present for each applicable annotated primitive tool argument and equal to its body value; absent when the argument is absent or null. | RMCP tool schema and validator |

The request metadata types are intentionally distinct. General descriptor and
result metadata uses `MetaObject`; request envelopes use
`RequestMetaObject`; notification envelopes use `NotificationMetaObject`.
Do not satisfy a current request by copying notification metadata or by moving
the required context into an unrelated header.

## Conditional headers

`Mcp-Name` is not a universal header. RMCP derives it only for methods whose
protocol shape has a routable identifier:

- `params.name` for `tools/call` and `prompts/get`;
- `params.uri` for the current `resources/read` operation;
- `params.taskId` for `tasks/get`, `tasks/update`, and `tasks/cancel`.

The pre-2026 compatibility operations `resources/subscribe` and
`resources/unsubscribe` may use their URI mapping only within that explicit
legacy lifecycle. They are not current-protocol mappings. The current
`subscriptions/listen` operation is their replacement for opening a long-lived
notification stream; RMCP `3.2.0` does not define an `Mcp-Name` source for
`subscriptions/listen`, so clients and intermediaries must not invent one.

Other methods do not acquire an invented name value. A name header that is
present when no name is defined is not a reason for Toolkit to route the
request through a compatibility path.

`Mcp-Param-*` headers are also conditional. A tool schema may mark a top-level
primitive property with an `x-mcp-header` annotation. For that property, the
request carries the corresponding `Mcp-Param-<annotation>` header when the
argument is present and non-null. Header names are non-empty RFC 9110 tokens
and are case-insensitively unique within the schema. Structured or otherwise
non-primitive values are not promoted by this contract.

### RMCP 3.2.0 interoperability boundary

The normative SEP-2243 schema extension permits an `x-mcp-header` annotation on
a nested property reachable through a chain of `properties` keys. RMCP
`3.2.0`'s documented interoperable subset for this guidance is deliberately
narrower: only top-level primitive (`string`, `integer`, or `boolean`) tool
properties are promoted. Nested-property promotion is a residual capability
boundary, not an unspoken promise that Toolkit or a downstream service
supports the normative nested form.

The owner of this boundary is the Toolkit maintainer. Promote it only after a
future RMCP release defines and proves nested-property extraction with
spec-conformant positive and negative contract tests, followed by an explicit
documentation and review update. Until that trigger is met, keep nested
annotations out of the maintained interoperability guidance and do not claim
runtime support for them.

Header values that cannot safely travel as bare HTTP values may use RMCP's
base64 wrapper. The body and header must still decode to the same value; a
wrapper is not permission to change or normalize the argument.

## Validation and failure behavior

For current requests RMCP compares the standard headers to the JSON-RPC body
and relevant tool schema. Missing, mismatched, unexpected, or undecodable
standard-header values are a bad request. RMCP `3.2.0` maps a SEP-2243 header
mismatch to HTTP `400` with its JSON-RPC error response (the SDK's conformance
tests identify the header-mismatch error as `-32020`).

That `400` is correct protocol behavior. Toolkit and downstream services must
not:

- synthesize a weaker request by dropping the header or `_meta` field;
- retry the request through legacy session lookup merely because validation
  failed;
- duplicate RMCP's JSON-RPC parser or standard-header validator; or
- claim that a route reached tool dispatch when RMCP rejected it at the
  protocol boundary.

A valid current request with a stale or unknown legacy `Mcp-Session-Id` remains
owned by the current RMCP path. Legacy session preflight must not steal its
routing authority.

## Acceptance matrix

Current HTTP contract evidence should include at least:

1. a complete request with matching `MCP-Protocol-Version`, `_meta`,
   `Mcp-Method`, and any applicable conditional headers;
2. a missing or mismatched `Mcp-Method` that RMCP rejects with HTTP `400`;
3. a missing or mismatched conditional `Mcp-Name` that RMCP rejects with HTTP
   `400`;
4. a tool schema with an `x-mcp-header` primitive and matching, missing,
   unexpected, and mismatched `Mcp-Param-*` values;
5. a pre-2026 request using an explicit legacy protocol version, proving that
   current standard-header enforcement is not silently applied to the legacy
   compatibility lifecycle; and
6. a current request carrying a stale legacy session header, proving that
   current-protocol routing remains with RMCP.

These checks prove the acceptance boundary only. They do not claim that the
Toolkit implements native retained-event replay, durable task recovery,
production deployment, or commissioning. Those capabilities require their own
implementation, authority, and review records.
