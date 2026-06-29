# Rust MCP Ecosystem Map

This document describes where `mcp-toolkit-rs` fits in a public Rust MCP
ecosystem.

## Toolkit Layer

The toolkit layer provides reusable substrate that should make sense to
external teams:

- protocol-facing Rust helpers;
- auth discovery and bearer-enforcement support;
- HTTP/session infrastructure;
- observability and redaction helpers;
- policy primitives and conformance harnesses;
- tool inventory, documentation, and test utilities.

The toolkit should not contain one service's business rules, backend client
logic, deployment topology, or product vocabulary.

## Reference Architecture Layer

Reference architectures show how to combine toolkit pieces into a complete
deployment shape. Examples might include:

- an MCP server paired with a credential-bearing gateway;
- an HTTP MCP service with OAuth discovery and protected-resource metadata;
- a stdio-first MCP service with a narrow policy guard.
- a legacy-system adapter that wraps split APIs, admin HTML, scheduled pages,
  and private artifacts behind operator-intent tools.

These examples are valuable because they show integration choices, but they are
not automatically part of the toolkit API surface.

## Reference Service Layer

Reference services demonstrate concrete MCP servers built with the toolkit.
They may include real backend clients, domain-specific tools, or operational
choices that do not belong in the generic toolkit.

Keep reusable substrate in this repository. Keep service behavior in the
service repository.

## Adjacent Consumers

Some applications reuse the same auth, policy, HTTP, or observability substrate
outside a pure MCP server shape. Those consumers are useful proof that the
toolkit is composable, but they should not drive MCP-specific APIs unless the
abstraction remains broadly useful.

## Placement Rule

Use this rule of thumb:

- put it in the toolkit if it is reusable substrate for external teams;
- put it in a reference architecture if it demonstrates a deployment pattern;
- put it in a reference service if it expresses domain logic, product
  contracts, or backend-specific behavior.

When in doubt, keep the logic out of the toolkit until the abstraction is
clearly generic.
