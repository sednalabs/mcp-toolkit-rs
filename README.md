# mcp-toolkit-rs

Reusable Rust building blocks for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers and clients.

This pre-1.0 workspace provides protocol-adjacent substrate—authentication
helpers, HTTP/session support, policy primitives, tool inventories,
observability, process utilities, and test harnesses—without becoming a
provider or deployment framework. The Rust crates are not published to
crates.io yet; consumers should use Git dependencies and commit their own
`Cargo.lock`.

## Find your starting point

- **Evaluating or consuming the toolkit:** read [the documentation map](docs/README.md), then [the golden path](docs/golden-path.md) and [the toolkit boundary](docs/toolkit-boundary.md).
- **Authoring a new server:** choose a maintained [starter template](docs/starter-templates.md), consult the [reference-server atlas](docs/reference-server-atlas.md), and follow the [new-server delivery lane](docs/new-server-delivery-lane.md).
- **Adopting an existing server:** begin with [tool inventory migration](docs/tool-inventory-migration.md), [provider auth and client configuration](docs/provider-auth-and-client-config.md), and [contract testing](docs/contract-testing.md).
- **Designing a security-sensitive surface:** read [security profiles](docs/security-profiles.md), [auth surface](docs/auth-surface.md), [guarded actions](docs/guarded-action-pattern.md), and [upstream OAuth](docs/upstream-oauth.md).
- **Reporting a vulnerability:** follow [SECURITY.md](SECURITY.md). Do not include credentials or sensitive deployment details in a public issue.
- **Contributing or preparing a release:** read [CONTRIBUTING.md](CONTRIBUTING.md), [public landing policy](docs/public-landing-policy.md), and [dependency governance](docs/dependency-governance.md).

## Workspace crates

| Crate | Purpose |
| --- | --- |
| `mcp-toolkit` | Umbrella crate with optional feature groups. |
| `mcp-toolkit-core` | Protocol helpers, notifications, query evidence, and tool inventories. |
| `mcp-toolkit-auth` | Bearer authentication, token validation, replay protection, and auth-surface helpers. |
| `mcp-toolkit-http` | OAuth/PRM metadata, device-authorization metadata, and optional Streamable HTTP sessions. |
| `mcp-toolkit-observability` | Redaction, sanitization, tracing, metrics, and optional OTel helpers. |
| `mcp-toolkit-policy-core` / `mcp-toolkit-policy-runtime` | Pure policy decisions and runtime authority adapters. |
| `mcp-toolkit-policy-conformance` / `mcp-toolkit-policy-ffi` / `mcp-toolkit-policy-kernel-adapters` | Policy conformance, optional FFI loading, and compatibility adapters. |
| `mcp-toolkit-postgres` | PostgreSQL connection, TLS, and target-identity helpers. |
| `mcp-toolkit-private-artifact` | Descriptor-bound, bounded reads of private local artifacts. |
| `mcp-toolkit-process` | Process and signal helpers. |
| `mcp-toolkit-scratchpad` | Optional DuckDB-backed sessions and bounded read-only SQL. |
| `mcp-toolkit-server` | Optional stdio and hosted HTTP server composition. |
| `mcp-toolkit-testing` | Tool-schema and auth-surface contract-test helpers. |
| `mcp-toolkit-docs` | Documentation and tool-metadata helpers. |

## Git dependency example

Use only the crates and features your service needs:

```toml
[dependencies]
mcp-toolkit-core = { git = "https://github.com/sednalabs/mcp-toolkit-rs", branch = "main" }
mcp-toolkit-http = { git = "https://github.com/sednalabs/mcp-toolkit-rs", branch = "main", features = ["session"] }

[dev-dependencies]
mcp-toolkit-testing = { git = "https://github.com/sednalabs/mcp-toolkit-rs", branch = "main" }
```

The umbrella crate is available when explicit feature selection from one
dependency is preferable. Resolve dependencies in the consuming repository,
commit its lockfile, and treat that lockfile as the record of the toolkit SHA.
The toolkit currently has no crates.io package or docs.rs publication to rely
on.

## Scope and status

Keep provider clients, domain tools, deployment policy, and deployment-specific
terminology in the service repository. Toolkit APIs should remain useful to
unrelated MCP servers. This workspace is pre-1.0, so review the linked
decision records and current contract tests before depending on behavior.

For contribution workflow, hosted validation, security reporting, and release
boundaries, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
