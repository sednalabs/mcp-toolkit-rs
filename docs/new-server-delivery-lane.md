# New MCP Server Delivery Lane

This lane is the repeatable delivery contract for creating Rust MCP servers
with `mcp-toolkit-rs`. Use it when starting a new server or when an existing
service is being reshaped enough that its MCP surface, tests, or release proof
need a fresh gate.

The lane keeps rapid server creation disciplined. The toolkit should remove
transport, auth, schema, and validation boilerplate; the service repository
still owns product-specific tools, backend clients, policy, data fixtures,
secrets handling, and deployment wording.

## Required Evidence

Every implementation should leave one reviewable evidence block in the PR,
work item, or release note:

```text
Server shape:
Toolkit template:
Intent tools:
Toolkit contract tests:
Domain output contract tests:
GitHub Actions run:
Reviewer signoff:
Promotion source:
Rollback:
```

Use `none` only when a line is genuinely not applicable, and explain why. A
missing evidence line means the lane is not complete.

## Gate 1: Start From The Appropriate mcp-toolkit-rs Template

Choose the server shape before writing domain code.

Use `templates/curated-stdio-intent-server` when the MCP server is
process-local and should expose a compact curated tool surface over stdio.

Use `templates/hosted-http-auth-server` when the server exposes Streamable HTTP,
publishes OAuth Protected Resource Metadata, and needs bearer challenges, host
guarding, or session behavior.

Use an adoption slice only for an existing server where replacing one runtime
seam is safer than copying a full template.

Required evidence:

- the selected template or adoption helper;
- the transport and trust boundary;
- the reason any raw `rmcp` runtime wiring remains;
- the validation commands or workflow that cover the chosen shape.

Do not start from an empty crate unless the template would add more behavior
than it removes and the PR records that reason.

## Gate 2: Define 3-7 First-Class Intent Tools

Define the operator surface before adding generic escape hatches. A new server
should normally expose three to seven first-class intent tools. Fewer tools may
mean the server does not need to exist yet. More tools may mean the server
needs clearer product boundaries or deferred discovery.

For each intent tool, record:

- name and purpose;
- inputs and defaults;
- output contract, including empty-state behavior;
- redaction and public-output hygiene;
- error shape for the common failure modes;
- one example operator question it answers.

Before finalizing the tool surface, check `docs/easy-server-ergonomics.md`.
New servers should usually include a credential-free setup/status path and a
first real discovery tool, so a user can get from install to useful data without
reading implementation details.

Generic API, SQL, or HTTP escape hatches are allowed only after the curated
tools cover the primary workflows and safety policy. They must be labeled as
debug, admin, or advanced surfaces and must not replace the curated path.

## Gate 3: Add mcp-toolkit-testing Contract Coverage

Every server must prove the MCP boundary it actually serves.

For all servers:

- commit a strict tool-schema snapshot;
- test the real served transport;
- run the tests in strict mode in GitHub Actions.

For stdio servers:

- use `mcp_toolkit_testing::stdio_contract::assert_stdio_tools_list`, or a
  service-specific equivalent that spawns the real binary, initializes the MCP
  session, and calls `tools/list`.

For hosted HTTP/auth servers:

- assert Protected Resource Metadata;
- assert authorization-server metadata when discovery is served;
- assert missing-token bearer challenges;
- assert pre-auth host rejection when host allowlists are configured.

Tests that call handlers directly are useful, but they do not satisfy this
gate by themselves.

## Gate 4: Add Domain Output Contract Tests For Every Intent Tool

Every first-class intent tool needs at least one live-ish or fixture-backed
domain output contract test. This protects the compact answer shape agents
consume, not only the protocol wrapper around it.

Prefer recorded fixtures, fake adapters, local catalog fixtures, or bounded
live-ish tests with safe credentials. Avoid brittle assertions against
uncontrolled production data.

Each test should prove:

- the returned object shape agents rely on;
- grouped totals or summary fields when the tool aggregates data;
- compact evidence fields;
- redaction behavior;
- empty-state or common-denial behavior when that is part of the contract.

Assert at the natural output boundary. A handful of field-level assertions is
not enough when a whole response shape is the contract.

## Gate 5: Validate On GitHub Actions

The mergeable proof is a GitHub-hosted run on the commit being reviewed.
Local checks are useful while editing, but they are not the shared proof
surface for this lane.

Required evidence:

- workflow name;
- run URL;
- head SHA;
- terminal conclusion;
- any relevant artifact name or digest.

Use the repository's normal workflow when it covers formatting, clippy, tests,
schema snapshots, and template or server-specific checks. Add a workflow only
when the existing one cannot prove the lane.

## Gate 6: Require Reviewer Sidecar Signoff Before Merge

Review is explicit work. Dispatch an independent reviewer after implementation
and GitHub validation evidence are available.

The reviewer must check:

- template or adoption-helper selection;
- whether the 3-7 intent tools match real operator questions;
- toolkit contract test coverage;
- domain output contract test coverage;
- GitHub Actions evidence;
- promotion source and rollback notes when deployment is part of the change.

Material findings must be fixed or explicitly dispositioned before merge. A
green workflow is evidence, not reviewer signoff.

## Gate 7: Install Or Promote Only From A Proven Artifact Or Tagged Commit

Promotion must be traceable to something already validated.

Acceptable sources:

- a GitHub Actions artifact produced by the passing run;
- a release artifact with a stable name and SHA256 digest;
- a tagged commit whose validation run is recorded.

Before promotion, record:

- source run, artifact, release, or tag;
- commit SHA;
- expected digest when a binary or package exists;
- target host, service, or deployment pointer;
- rollback target.

After promotion, verify the installed thing, not only the pointer:

- binary or package hash;
- service status or process path where applicable;
- `tools/list`, health, or a minimal runtime smoke check;
- stale-session notes for stdio MCP clients that keep old inodes until restart.

Untracked local builds are not promotion sources for this lane.

## Completion Checklist

- Gate 1 evidence records the selected template or adoption helper.
- Gate 2 evidence lists three to seven first-class intent tools, or explains a
  deliberate exception.
- Gate 3 evidence names the toolkit contract tests.
- Gate 4 evidence maps every intent tool to a domain output contract test.
- Gate 5 evidence links the GitHub Actions run on the reviewed commit.
- Gate 6 evidence records reviewer sidecar approval or resolved findings.
- Gate 7 evidence records the artifact, release, or tag used for promotion, or
  states that no install or promotion happened in this slice.

Close the work item only when each checklist line has concrete evidence.

## Maintenance Rules

Keep this lane stable and boring. Add a new gate only when a repeated failure
mode cannot be caught by strengthening one of the existing gates. When a new
template or transport shape is added, update this document, `docs/golden-path.md`,
and the doc contract test that pins the lane gates.
