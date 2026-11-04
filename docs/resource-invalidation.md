# Bounded resource invalidations

`mcp_toolkit_core::resource_invalidation::InvalidationSet` is a
dependency-free, in-memory *dirty-resource set*. It is useful for MCP
`notifications/resources/updated` producers and `subscriptions/listen`
implementations with a finite, caller-authorised resource inventory.

The constructor refuses empty/duplicated/oversized inventories. A key
cannot appear more than once in the pending FIFO. A hot resource cannot
starve another pending resource; once a marker has been taken, a later
update to the same resource is accepted as new.

This is deliberately **not** a replayable event stream or a message
delivery queue. Multiple independent messages may legitimately coalesce
into a single resource invalidation, but they must remain separately
retrievable from the application's bounded history or inbox. An MCP
notification does not prove a model was awakened, consumed a message or
acknowledged work.

The caller is responsible for deriving the authorised inventory,
rechecking permissions at send/read time, registering/acknowledging a
subscription without gaps, managing cancellation/backpressure, and
reporting any message-history discontinuity. No IRC, agent, Ops, OAuth,
networking, timers or persistent state are introduced.

The scoped cursor helper under review in
[#325](https://github.com/sednalabs/mcp-toolkit-rs/pull/325)
addresses a different concern: caller-bound continuation tokens. Do
not build another cursor store as part of the invalidation primitive.

This pattern was motivated by a hosted IRC MCP adapter, whose inbox
stores individual messages independently of coalesced notification
markers: https://github.com/sednalabs/irc-mcp/pull/1.
