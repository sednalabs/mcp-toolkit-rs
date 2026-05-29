# Toolkit Boundary

`mcp-rs-toolkit` should stay useful to external teams building their own MCP
systems. The toolkit can be opinionated about quality, security, and
ergonomics, but it should not require adopters to inherit one service family's
domain model, backend topology, or operational vocabulary.

## What belongs in the toolkit

Good toolkit candidates are reusable substrate concerns such as:

- auth primitives, auth-surface wiring, and shared OAuth or discovery helpers
- streamable HTTP and HTTP transport helpers
- session, event-store, and protocol-adjacent infrastructure
- observability, logging, redaction, and tracing helpers
- generic policy primitives, conformance helpers, and testing seams
- tool inventory registration, schema shaping, and snapshot testing
- generic Rust server-composition helpers that reduce repeated MCP boilerplate

The common test is: could an unrelated external MCP project adopt this without
also adopting our business logic or deployment model?

## What does not belong in the toolkit

Keep these concerns in service repos, application repos, or reference
architectures:

- service-specific business logic
- product-specific contracts and payloads
- backend clients tied to one product or one data model
- domain models with product vocabulary
- infrastructure-specific deployment code
- gateway semantics that only make sense for one service family
- admin or operator flows that depend on one organisation's trust model

Those pieces may still be public and useful, but they should be demonstrated as
reference architectures or reference services rather than promoted into the
toolkit API.

## Reference architectures versus toolkit APIs

A public reference architecture can show how to combine toolkit crates with a
gateway, backend, or stronger policy boundary. That is valuable. It is still
different from adding the same logic to the toolkit itself.

Use a reference architecture when the lesson is:

- "this is a good way to assemble the toolkit for a class of systems"

Use the toolkit when the lesson is:

- "this primitive is broadly reusable across many MCP systems"

## Extraction checklist

Before moving code into `mcp-rs-toolkit`, confirm that all of these are true:

1. The abstraction is useful to third-party adopters outside our repos.
2. The API can be described without internal product names or domain terms.
3. The behavior does not depend on one backend client, one schema, or one
   deployment topology.
4. The docs can explain when to use it without assuming our infrastructure.
5. The tests can exercise it with generic fixtures instead of one service's
   business objects.

If any answer is "no", keep the logic in a reference service or application and
document the pattern there instead.
