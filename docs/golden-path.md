# Golden Path For Rust MCP Servers

This guide is the end-to-end route for creating, validating, reviewing, and
releasing a Rust MCP server with `mcp-toolkit-rs`. For the operational checklist
that turns this route into a repeatable delivery lane, see
`docs/new-server-delivery-lane.md`. For the exact generator commands, flags,
generated file layout, and customization points, see
`docs/new-server-cli-reference.md`.

The toolkit should make common MCP server work easy without becoming a product
framework. Keep backend clients, domain tools, deployment policy, and
deployment-specific terminology in the service repository. Use toolkit crates
for protocol-adjacent substrate that an unrelated MCP server could also adopt.

## 1. Choose The Server Shape

Start by naming the transport and trust boundary. Before designing a new
abstraction, check `docs/reference-server-atlas.md` and record the closest
living reference pattern. The atlas keeps reusable lessons tied to real MCP
servers while this toolkit keeps provider and deployment semantics out of
generic APIs. When a row fits, also check `docs/pattern-manifests.md` and
`docs/pattern-recipes.md`; those files give future generators a stable pattern
shape and give reviewers a concrete crate-ownership checklist.

| Shape | Use when | Toolkit defaults |
| --- | --- | --- |
| Curated stdio | The MCP server is process-local and exposes a small intentional tool surface. | `mcp-toolkit-server::stdio::StdioServerBuilder`, `ToolCatalog`, schema snapshots, and stdio contract tests. |
| Hosted HTTP/auth | The MCP server serves Streamable HTTP and must publish OAuth Protected Resource Metadata. | `LocalMcpHttpServerBuilder`, `AuthSurfaceBuilder`, `HttpBindSafety`, host/origin guards, bearer challenges, and auth-surface contract tests. |
| Analytics scratchpad | The MCP server can fetch more tabular data than should be returned through chat. | `mcp-toolkit-scratchpad::ScratchpadSessionManager`, DuckDB-backed bounded sessions, read-only SQL policy, table inventory, and concise handles. |
| Service adoption | An existing server wants less runtime boilerplate. | Adopt the smallest helper that removes repeated wiring while preserving the service's public contract. |

If a helper needs product-specific inputs, backend-specific payloads, or one
deployment's trust model, keep that logic in the service repository and document
the pattern as an adopter note instead of moving it into the toolkit.

The toolkit intentionally does not ship a monolithic `ToolkitMcpServer`
abstraction. Prefer composing `StdioServerBuilder`, HTTP route builders,
auth-surface helpers, and `ToolCatalog`/`ToolInventory` until repeated evidence
shows a higher-level wrapper would remove real duplication without hiding trust
boundaries.

## 2. Start From A Maintained Template

Use one of the maintained templates when creating a new server:

- `templates/curated-stdio-intent-server` for a stdio intent server.
- `templates/single-crate-public-stdio-server` for a standalone public stdio
  server repository with GitHub CI and security scaffolding included.
- `templates/hosted-http-auth-server` for hosted Streamable HTTP with OAuth
  metadata, bearer challenges, host guarding, and session support.

The quickest copy-paste path from this checkout is:

```bash
cargo run -p mcp-toolkit --bin mcp-toolkit -- patterns
cargo run -p mcp-toolkit --bin mcp-toolkit -- new \
  --name my-mcp-server \
  --template curated-stdio-intent
cd my-mcp-server
cargo test --all-targets --all-features
```

For a standalone service repository, run the generator from the parent directory
that should contain the new repository and use public Git dependencies from the
first commit:

```bash
cd ..
cargo run --manifest-path /path/to/mcp-toolkit-rs/crates/mcp-toolkit/Cargo.toml \
  --bin mcp-toolkit -- new \
  --name my-mcp-server \
  --template single-crate-public-stdio \
  --output my-mcp-server \
  --toolkit-git https://github.com/sednalabs/mcp-toolkit-rs
```

Generate or copy the template into the service repository, rename the package
if needed, then replace only the example tool handlers and config with
service-specific code. Keep the template's validation tests unless the service
has a documented reason to use a stronger local equivalent. For a new public
repository, start from the standalone public stdio template unless the hosted
HTTP/auth template is a better fit.

Treat the generated files as the initial review contract. A healthy generated
server should keep its schema snapshot, catalog-profile contract test,
transport smoke test, optional `mcp_probe` scenario, README first-run block, and
GitHub `rust-baseline` workflow until an equal or stronger service-specific
replacement exists.

Before the first release, add a credential-free setup or status path for the
real backend. For provider-backed servers this is usually an `auth_status` or
`connection_status` tool that reports redacted credential sources, selected
scopes, and the next login step. For hosted HTTP/auth servers, also verify
`/health`, Protected Resource Metadata, bearer challenges, and client
configuration against the generated README. Use
`docs/provider-auth-and-client-config.md` for provider auth, profile, quota
project, service-account, and client configuration details.

Before adding generic API, SQL, or HTTP escape hatches, define three to seven
first-class intent tools that answer the primary operator questions. The
delivery-lane checklist in `docs/new-server-delivery-lane.md` records the
required evidence for that tool-design gate.

For legacy systems with partial APIs, admin HTML, scheduled pages, or private
exports, first apply `docs/legacy-system-adapter-pattern.md`. That pattern keeps
the source-authority map, blocked operation list, preview/apply boundary, and
private artifact lane in the service design before any generic backend access is
considered.

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
- `mcp-toolkit-scratchpad` for optional DuckDB-backed sessions, table
  inventory, append/drop helpers, bounded read-only SQL, query projections, and
  local cleanup when large analytical results should be handled by table
  handles instead of chat payloads.
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
- catalog-profile contract tests when the server exposes filtered discovery
  profiles such as `read_only`, `scratchpad`, or `operator`;
- an optional scripted MCP probe scenario beside the snapshots when a compatible
  probe runner is available;
- GitHub-hosted CI that runs strict tests without update-mode environment
  variables.

For stdio servers:

- use `stdio_contract::assert_stdio_tools_list` or a service-specific stdio
  JSON-RPC equivalent that initializes the real binary and calls `tools/list`;
- use `stdio_contract::assert_stdio_tool_response_excludes_substrings` for
  starter tools or sensitive readbacks that should prove serialized responses
  exclude common secret material.

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
cargo fmt --manifest-path templates/single-crate-public-stdio-server/Cargo.toml --all --check
cargo clippy --manifest-path templates/single-crate-public-stdio-server/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path templates/single-crate-public-stdio-server/Cargo.toml --all-targets --all-features
```

The `rust-baseline` workflow runs those checks on pull requests, pushes to the
primary branch, and manual dispatches. Record the run URL in the PR or work
item before merging.

Snapshot updates are exceptional. To intentionally rebaseline a snapshot:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test <snapshot-test-name>
```

If the repository carries the helper wrapper, you can use:

```bash
./scripts/rebaseline_tool_schema_snapshot.sh <manifest-path>
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

Use `docs/new-server-delivery-lane.md` as the review checklist for new server
work. It pins the seven required gates: template selection, intent-tool design,
toolkit contract tests, domain output tests, GitHub validation, reviewer
sidecar signoff, and proven promotion.

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
10. Public repository README, license, and Cargo metadata match the intended
    service shape.
11. Hosted CodeQL, code coverage upload, and dependency governance are present
    when the server is expected to be publicly maintained.
12. Public wording has been scrubbed for secrets, hostnames, and internal-only
    terminology.

For service repositories, also verify that service-specific policy, secrets,
hostnames, backend schemas, and deployment-specific wording remain out of this
public toolkit unless they are intentionally part of that service's public
surface.

## 8. Adopting An Existing Server

For an existing server, migrate one runtime seam at a time:

1. Choose a helper that replaces repeated boilerplate without changing the
   service's tool, auth, session, or startup contract.
2. Consume the public toolkit Git repository and commit the service lockfile so
   Cargo records the exact resolved toolkit SHA. Use a manifest `rev` pin only
   when the service intentionally needs a long-lived frozen toolkit ref.
3. Keep domain policy and backend clients in the service repository.
4. Add or preserve a runtime smoke test at the actual MCP boundary.
5. Document the before/after in the service README or PR.
6. Validate the branch on GitHub before merge.
7. Capture reviewer approval before closing the adoption work item.

Good first adoption seams are stdio startup, route-bundle host guarding,
auth-surface metadata contracts, schema snapshot helpers, and hosted HTTP
runtime assembly.
