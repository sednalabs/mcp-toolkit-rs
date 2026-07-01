# Easy Server Ergonomics

This guide captures the small product decisions that make toolkit-built MCP
servers easy to try, easy to debug, and hard to misuse. Use it with
`docs/new-server-delivery-lane.md` before adding provider-specific code.

The toolkit should centralize repeatable server ergonomics. Service
repositories still own API-specific clients, credential scopes, resource names,
fixtures, and safety policy.

For provider-auth command names, Google quota-project troubleshooting,
read-only/operator profile alignment, and MCP client configuration examples,
use `docs/provider-auth-and-client-config.md`.

## First-Run Shape

Every new server should make the first successful tool call obvious:

- expose a `get_started` or equivalent setup tool that does not require
  upstream credentials;
- expose an `auth_status`, `connection_status`, or equivalent diagnostic tool
  that reports configured sources without returning secrets;
- provide a copyable login or configuration command when the upstream ecosystem
  has a standard local auth flow;
- make the first real data tool a discovery tool such as `list_projects`,
  `list_sites`, `list_accounts`, or `list_resources`;
- describe exact resource identifiers in tool schemas and error messages, not
  only in README prose.

For stdio servers, remember that MCP clients may keep a long-lived child
process. Auth and install guidance should tell operators when to restart the
client after changing environment variables, credentials, or binaries.

## Auth And Credentials

Prefer the upstream provider's standard credential chain when it exists. That
keeps local trials familiar and lets teams reuse their existing secret
management path.

A low-friction server normally supports these sources, in this order:

- server-specific explicit credential source for sealed deployments;
- standard provider environment variables or credential files;
- local application-default or CLI-backed user credentials;
- metadata-service credentials for cloud runtimes.

When a provider's lowest-friction trial path is browser OAuth, use
`mcp_toolkit_auth::upstream_oauth` rather than hand-rolling client-file
parsing, PKCE, callback listeners, refresh-token caches, and redaction. Keep
browser login as an explicit setup or CLI action; ordinary data tools should
reuse cached credentials and must not open a browser as a side effect.
Servers should not accept or configure raw token-exchange HTTP clients for this
flow; the toolkit owns the no-redirect exchange client internally.

Diagnostic tools may report whether an environment variable is present, a file
path is configured, or a token request succeeded. They must not return access
tokens, refresh tokens, private keys, raw client secrets, bearer headers, or
whole credential files.

For MCP Auth configurations, ordinary bearer tokens should remain reusable by
default across the default, L2, and L3 security profiles. One-time bearer replay
enforcement is an explicit opt-in, and sender-constrained replay protection
should not be implied without a dedicated validator.

If a provider offers both personal OAuth and service accounts, support both
when the dependency already makes that cheap. Personal OAuth is usually the
lowest-friction trial path; service accounts are usually the lowest-friction
unattended path.

Do not conflate upstream OAuth with MCP Auth. MCP device authorization helps a
client log in to the MCP server. Upstream OAuth helps the MCP server call the
provider API. A server may need both, but they are different trust boundaries.

## Tool Surface

Keep first-class tools intent-shaped:

- prefer `query_report`, `inspect_url`, or `list_properties` over generic HTTP
  pass-throughs;
- keep read-only tools available by default;
- put mutations behind an explicit profile, capability, or confirmation layer;
- include a local `find_tools` path when the catalog may grow or clients use
  deferred loading;
- include `--print-tools` and `--print-tool-schema` so operators can inspect
  the served surface without starting a client.

Profile filtering should be centralized once. The same visible-tool helper or
inventory policy should drive `tools/list`, local discovery tools, schema
printing, and generated documentation. If a read-only profile denies a mutation
at call time, it should normally hide that mutation from discovery too.
Generated servers should start from `ToolCatalog::with_standard_profiles(...)`,
keep `EXAMPLE_MCP_TOOL_PROFILE=read_only` as the default, and require an
explicit `operator` profile before `ToolCatalogEntry::with_operator_profile_gate()`
tools appear or run. Use `ToolInventoryDecision::caller_message()` for denial
responses so clients see `TOOL_DENIED_READ_ONLY_PROFILE` instead of an opaque
transport failure.

Do not hide setup behind README-only instructions. If the server can explain
what is missing through a safe tool response, add that tool.

For legacy systems, ergonomics must not become a generic admin escape hatch.
Use `docs/legacy-system-adapter-pattern.md` to turn partial APIs, admin HTML,
scheduled-job pages, and private exports into named intent tools with explicit
blocked operations.

## Guarded Preview/Apply

When a service genuinely needs a narrow administrative action, keep the runtime
shape explicit:

- classify the action with `GuardedActionPosture`;
- attach that posture to tool inventory metadata with
  `ToolCapability::with_risk_posture(...)`;
- gate the live action with `GuardedActionRuntimeMode::assert_allowed(...)`;
- bind preview and apply through a deterministic non-secret plan id;
- return fresh redacted readback evidence after apply.

Use `docs/guarded-action-pattern.md` for the generic toolkit shape. The service
repository still owns provider-specific allowlists, backend reads, and the
exact approval boundary.

## Errors And Empty States

The easiest server is usually the one that fails well. Common errors should
name the next action:

- no credentials configured;
- token acquisition failed;
- authenticated principal lacks access to the requested resource;
- resource identifier does not match an upstream canonical form;
- mutation requested while the server is in a read-only profile.

Empty successful responses should still be useful. Include the upstream empty
object or list, plus compact metadata such as the queried resource, time window,
or filter.

## Redacted Structured Output

Do not force operators to choose between useful output and safe output. Prefer
structured shapes that keep identifiers, counts, and state transitions while
dropping secrets and raw payloads.

Read-oriented example:

```json
{
  "resource": "queue/jobs",
  "status": "paused",
  "items": 14,
  "checked_at": "2026-06-29T05:00:00Z",
  "evidence": {
    "source": "admin_status_page",
    "operator_visible_fields": ["resource", "status", "items"]
  }
}
```

Guarded apply example:

```json
{
  "plan_id": "gap.queue-control.tenant-42.jobs-pause",
  "posture": {
    "operation_class": "guarded_apply",
    "requires_runtime_enablement": true,
    "writes_enabled_by_default": false,
    "post_apply_readback_required": true
  },
  "applied": {
    "requested_state": "paused"
  },
  "evidence": {
    "before": "running",
    "after": "paused",
    "checked_at": "2026-06-29T05:02:00Z"
  }
}
```

The important property is not the exact field names. It is that the service
returns evidence a human or agent can act on without exposing tokens, raw
session cookies, hidden form fields, or whole upstream payload dumps.

## Validation

Pair ergonomic setup with a small proof surface:

- schema snapshot for every exported tool;
- transport-level `tools/list` contract test;
- fixture or fake-adapter output contract tests for the setup/status tools;
- redaction tests for credential diagnostics;
- GitHub-hosted validation before public landing.

Local smoke runs are useful while editing, but the reviewable proof for public
servers should come from GitHub Actions whenever the repository has a hosted
path.

## What Belongs In The Toolkit

Move a pattern into `mcp-toolkit-rs` when at least two services need it and it
does not encode a provider's product semantics.

Good toolkit candidates:

- tool inventory and deferred-loading helpers;
- guarded read-only and preview/apply posture helpers;
- schema snapshot and transport contract tests;
- auth-surface metadata, bearer challenges, and safe diagnostic shapes;
- redaction and bounded logging helpers;
- starter templates and delivery checklists.

Keep these in service repositories:

- provider-specific OAuth scopes and credential precedence;
- API clients and endpoint paths;
- product resource normalization;
- domain output contracts;
- service README wording and examples.

For the larger automation path, see `docs/instant-server-generation.md`. The
long-term goal is a generator that can turn OpenAPI, JSON Schema, docs, and
examples into a secure toolkit server scaffold in moments, while still forcing
review for public tool exposure and mutation policy.
