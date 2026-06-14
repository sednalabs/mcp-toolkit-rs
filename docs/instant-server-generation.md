# Instant MCP Server Generation

This note describes the toolkit direction for spinning up secure, useful MCP
servers in moments from existing API descriptions and documentation.

The target is a helper workflow, and eventually a small toolkit CLI, that can
turn OpenAPI, JSON Schema, documented endpoints, example requests, and service
README material into a reviewable Rust MCP server scaffold.

## Goal

Make the fast path feel like this:

```bash
mcp-toolkit generate server \
  --name example-api-mcp \
  --openapi ./openapi.yaml \
  --auth oauth2 \
  --transport stdio \
  --profile read-only-first
```

The generated output should include:

- a compiling Rust crate using the current toolkit template;
- a curated MCP tool inventory, not a raw generic API proxy;
- one centralized visible-tool policy reused by `tools/list`, `find_tools`,
  schema printing, and generated docs;
- typed request/response models generated from the source schema;
- upstream auth configuration with safe diagnostics;
- read-only defaults and explicit mutation gates;
- schema snapshots and transport contract tests;
- fake-adapter or fixture-backed output contract tests;
- README, tool guide, security notes, and GitHub Actions validation;
- a short review report naming assumptions, risky operations, and skipped
  endpoints.

The dream is instant scaffolding with secure defaults, followed by a short
human review pass to decide which generated tools deserve to be public.

## Inputs

The generator should support layered evidence rather than one fragile source:

- OpenAPI 3.x documents;
- JSON Schema and standalone request/response schemas;
- Postman or HTTP collection exports when OpenAPI is unavailable;
- provider documentation pages or markdown guides;
- example curl commands;
- existing SDK method names and type definitions;
- operator-provided allowlists and deny rules.

OpenAPI is the best machine-readable input, but docs and examples often carry
the intent that API specs miss. The helper should preserve source references in
generated comments, fixtures, and review notes.

## Generation Pipeline

1. Parse source documents into a normalized operation graph.
2. Classify operations as read-only, mutating, destructive, auth/setup, or
   advanced/debug.
3. Propose MCP intent tools by grouping related operations around user goals.
4. Generate one profile-aware visible-tool policy for list/search/schema/docs
   surfaces.
5. Generate typed upstream client methods and request validation.
6. Generate contract-shaped MCP handlers with toolkit tool inventory metadata.
7. Generate auth/status/get-started tools using `docs/easy-server-ergonomics.md`.
8. Generate tests, schema snapshots, fake adapters, and fixture contracts.
9. Emit a review report that names every generated, skipped, and gated
   operation.

The tool should default to an allowlist. Unclassified operations should be
generated into a review report, not exposed as callable MCP tools.

## Security Defaults

Generated servers must be conservative by construction:

- read-only profile by default;
- mutations require explicit profile or capability gates;
- destructive operations require a separate operator decision;
- no raw token, key, password, cookie, or private-key fields in tool responses
  or logs;
- bounded upstream timeouts and response sizes;
- HTTPS-only upstream URLs by default;
- no generated generic `call_any_endpoint` tool;
- path, query, and body parameters validated before dispatch;
- secrets reported only as present or absent in diagnostics;
- generated errors include next steps without leaking upstream credentials.
- generated MCP Auth configurations keep ordinary bearer tokens reusable by
  default across the default, L2, and L3 security profiles, with one-time bearer
  replay enforcement requiring an explicit opt-in.

If the source schema marks OAuth scopes or security schemes, those should flow
into generated profile docs and tool metadata. If the source schema does not
mark safety, the generator should choose the safer classification and require
review.

## Human Review Boundary

The generator accelerates setup; it does not replace review.

Before a generated server is public, a maintainer should confirm:

- tool names match operator intent rather than provider endpoint names;
- mutations and destructive paths are correctly gated;
- auth setup works through standard provider flows;
- generated examples do not include private tenant, host, user, or token data;
- tests prove both happy path and common denial/error paths;
- hosted validation passes on the generated commit.

The generated review report should be short enough to paste into a PR or Ops
work item.

## Toolkit Pieces To Build

This direction likely wants these reusable pieces:

- `mcp-toolkit-generate`: CLI entrypoint for scaffold generation;
- OpenAPI/JSON Schema parser and operation classifier;
- intent-tool proposal engine with allowlist output;
- auth-profile templates for common upstream schemes;
- generated fake-adapter and fixture-test helpers;
- redaction policy generation from schema field names and formats;
- operation review report renderer;
- template tests that prove generated projects follow
  `docs/new-server-delivery-lane.md`.

Keep provider-specific API behavior outside the toolkit. The toolkit should
generate the scaffolding, review report, tests, and safe defaults; the generated
service owns its domain model and final tool decisions.

## First Useful Slice

The smallest valuable slice is not a full AI code generator. It is a deterministic
scaffold helper that accepts:

- an OpenAPI file;
- a server name;
- a transport choice;
- an explicit list of operations to expose;
- a read-only or operator profile.

That slice can produce a compiling server with placeholder fake fixtures,
tool-schema snapshots, and a review report. Later slices can add documentation
mining, intent grouping, and richer operation classification.
