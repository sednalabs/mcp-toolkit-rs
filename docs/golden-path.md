# Golden Path For Rust MCP Servers

This guide is the end-to-end route for creating, validating, reviewing, and
releasing a Rust MCP server with `mcp-rs-toolkit`.

The toolkit should make common MCP server work easy without becoming a product
framework. Keep backend clients, domain tools, deployment policy, and
deployment-specific terminology in the service repository. Use toolkit crates
for protocol-adjacent substrate that an unrelated MCP server could also adopt.

## 1. Choose The Server Shape

Start by naming the transport and trust boundary.

| Shape | Use when | Toolkit defaults |
| --- | --- | --- |
| Curated stdio | The MCP server is process-local and exposes a small intentional tool surface. | `mcp-toolkit-server::stdio::serve_stdio`, `ToolInventory`, schema snapshots, and stdio contract tests. |
| Hosted HTTP/auth | The MCP server serves Streamable HTTP and must publish OAuth Protected Resource Metadata. | `LocalMcpHttpRuntimeBuilder`, `LocalMcpHttpRouterBuilder`, `AuthSurfaceBuilder`, `HttpBindSafety`, host guards, bearer challenges, and auth-surface contract tests. |
| Service adoption | An existing server wants less runtime boilerplate. | Adopt the smallest helper that removes repeated wiring while preserving the service's public contract. |

If a helper needs product-specific inputs, backend-specific payloads, or one
deployment's trust model, keep that logic in the service repository and document
the pattern as an adopter note instead of moving it into the toolkit.

## 2. Start From A Maintained Template

Use one of the maintained templates when creating a new server:

- `templates/curated-stdio-intent-server` for a stdio intent server.
- `templates/hosted-http-auth-server` for hosted Streamable HTTP with OAuth
  metadata, bearer challenges, host guarding, and session support.

Copy the template into the service repository, rename the package, then replace
only the example tool handlers and config with service-specific code. Keep the
template's validation tests unless the service has a documented reason to use a
stronger local equivalent.

## 3. Pick Crates By Boundary

Add only the crates that match the server shape:

- `mcp-toolkit-core` for tool inventory, exported schema surfaces, and
  protocol-facing helpers.
- `mcp-toolkit-server` for stdio startup, local Streamable HTTP runtime
  assembly, route bundles, host guards, and auth layer composition.
- `mcp-toolkit-auth` and `mcp-toolkit-http` for hosted auth metadata,
  bearer-token validation, OAuth helpers, and HTTP session support.
- `mcp-toolkit-testing` for schema snapshots, stdio smoke tests, auth metadata
  contracts, bearer challenges, and pre-auth host rejection assertions.
- `mcp-toolkit-observability` for redaction, sanitization, tracing bridge,
  bounded labels, and optional metrics.
- Policy crates only when the service has a real authorization, SQL read-only,
  capability, or policy-runtime boundary.

The umbrella `mcp-toolkit` crate is useful when a service wants explicit feature
groups from one dependency. Direct crate dependencies are clearer when the
service is intentionally small.

## 4. Lock The Runtime Contract

Every toolkit-built server should have a strict contract suite.

For all servers:

- an exported tool-schema snapshot;
- a real runtime smoke test for the served transport;
- GitHub-hosted CI that runs strict tests without update-mode environment
  variables.

For stdio servers:

- use `stdio_contract::assert_stdio_tools_list` or a service-specific stdio
  JSON-RPC equivalent that initializes the real binary and calls `tools/list`.

For hosted HTTP/auth servers:

- assert OAuth Protected Resource Metadata;
- assert authorization-server metadata when discovery is served;
- assert missing-token bearer challenges;
- assert pre-auth host rejection does not emit a bearer challenge;
- assert public health and protected MCP routes through the actual router.

See `docs/contract-testing.md` for helper examples.

## 5. Validate On GitHub

Use GitHub-hosted validation as the shared proof surface. Local commands are
useful for quick syntax checks, but the mergeable evidence should be a GitHub
Actions run URL.

For this repository, the root baseline is:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo fmt --manifest-path templates/curated-stdio-intent-server/Cargo.toml --all --check
cargo clippy --manifest-path templates/curated-stdio-intent-server/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path templates/curated-stdio-intent-server/Cargo.toml --all-targets --all-features
cargo fmt --manifest-path templates/hosted-http-auth-server/Cargo.toml --all --check
cargo clippy --manifest-path templates/hosted-http-auth-server/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path templates/hosted-http-auth-server/Cargo.toml --all-targets --all-features
```

The `rust-baseline` workflow runs those checks on pull requests, pushes to the
primary branch, and manual dispatches. Record the run URL in the PR or work
item before merging.

Snapshot updates are exceptional. To intentionally rebaseline a snapshot:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test <snapshot-test-name>
```

Review the JSON diff and explain why the public contract changed.

## 6. Review Gate Handoff

Before an implementation slice is treated as done, hand it to an independent
reviewer. The handoff should include:

- repository, branch, PR, and commit;
- the intended server shape;
- changed files and the behavior they affect;
- exact local commands, if any;
- GitHub Actions run URLs;
- release artifacts or hashes when a binary was produced;
- rollback notes;
- known coverage gaps.

The reviewer should inspect the diff and validation evidence, then either
approve the gate or leave concrete required fixes. A green workflow is evidence,
not a substitute for reviewing whether the abstraction stayed inside the
toolkit boundary.

## 7. Release Checklist

Before publishing or promoting a toolkit-built server:

1. The working tree is clean and the branch is current with its base.
2. Tool schema snapshots and runtime contract tests are committed.
3. GitHub-hosted validation passed on the exact commit being promoted.
4. The PR or work item records the validation run URL.
5. Any release artifact has a stable name and SHA256 digest.
6. Fresh runtime smoke proof was captured after the final build.
7. Existing long-lived MCP client sessions are restarted or explicitly called
   out as stale until restart.
8. Rollback is a normal revert, prior binary, or previous deployment pointer.
9. The review gate is approved and closed.

For service repositories, also verify that service-specific policy, secrets,
hostnames, backend schemas, and deployment-specific wording remain out of this
public toolkit unless they are intentionally part of that service's public
surface.

## 8. Adopting An Existing Server

For an existing server, migrate one runtime seam at a time:

1. Choose a helper that replaces repeated boilerplate without changing the
   service's tool, auth, session, or startup contract.
2. Pin the toolkit revision in the service manifest.
3. Keep domain policy and backend clients in the service repository.
4. Add or preserve a runtime smoke test at the actual MCP boundary.
5. Document the before/after in the service README or PR.
6. Validate the branch on GitHub before merge.
7. Capture reviewer approval before closing the adoption work item.

Good first adoption seams are stdio startup, route-bundle host guarding,
auth-surface metadata contracts, schema snapshot helpers, and hosted HTTP
runtime assembly.
