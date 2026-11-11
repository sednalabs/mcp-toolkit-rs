# ChatGPT Events integration helpers

The optional RMCP Events capability model only advertises a feature. It does not
implement the ChatGPT webhook lifecycle. Do not advertise it until the complete
service is implemented and qualified.

`mcp_toolkit_core::chatgpt_events` provides a bounded webhook subscribe decoder,
unsubscribe selector, finite-lifetime policy and stable subscription identity.
It uses the existing toolkit canonical JSON implementation. The identity binds
the authenticated principal, exact callback URL, event name and canonical
arguments, while refresh-only values do not change identity. Debug output omits
callbacks, selectors, cursors and signing secrets. Input errors do not echo
sensitive values.

The helpers distinguish an omitted `ttlMs`, explicit null and an integer. A
server can grant finite lifetimes to all three without accidentally treating
null as the default at parse time. The request budget is a local policy limit,
not the separate 256 KiB event delivery limit.

## Server responsibilities

The module performs no I/O or persistence. The server still must:

- Authenticate the principal and validate the selected event's argument schema.
- Apply current domain/project rights on create, refresh and every send/retry.
- Protect durable subscription state and secret custody for the granted lifetime.
- Use the optional [guarded HTTPS transport](webhook-egress.md), or an equally
  qualified transport, to validate every DNS-to-socket connection, block
  non-public destinations and redirects, and bound challenge/delivery requests.
- Verify the callback, sign exact body bytes using Standard Webhooks, and implement
  expiry, refresh, rotation, idempotent unsubscribe and bounded delivery outcomes.
- Preserve source identity and honest replay/cursor semantics using its authoritative
  event source; transport receipt never acknowledges source work or proves task response.

Existing `resource_invalidation`, `notifications` and `scoped_cursor` modules
remain useful for connected-client hints and request continuation. The HTTP
legacy-session event store is for transport retention. None substitutes for a
domain event ledger or durable webhook lifecycle. Reuse those abstractions where
their guarantees fit; do not introduce another generic event bus.

Source-specific selectors, source ordering, current authorization and durable
invariants belong to the consuming service. Callback validation/transport and
protocol utilities reusable by multiple services belong in the toolkit.

This helper does not register `events/list`, `events/subscribe` or
`events/unsubscribe`, enable a capability, create a subscription or demonstrate
live ChatGPT acceptance. The [OpenAI integration guide](https://developers.openai.com/plugins/build/mcp-events)
is the current integration contract. Its webhook subset is distinct from MCP
resource subscriptions and the broader experimental Events proposal.

## Qualification

The request parser tests include reproducible arbitrary-byte and valid-corpus
mutation fuzzing for both subscribe and unsubscribe paths, plus explicit budget,
nesting, field-shape, identity and lifetime boundary cases. This bounded fuzz pass
runs in ordinary cargo tests; it is not a sustained coverage-guided campaign.
