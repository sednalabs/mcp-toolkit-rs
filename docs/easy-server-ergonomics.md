# Easy Server Ergonomics

This guide captures the small product decisions that make toolkit-built MCP
servers easy to try, easy to debug, and hard to misuse. Use it with
`docs/new-server-delivery-lane.md` before adding provider-specific code.

The toolkit should centralize repeatable server ergonomics. Service
repositories still own API-specific clients, credential scopes, resource names,
fixtures, and safety policy.

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

Diagnostic tools may report whether an environment variable is present, a file
path is configured, or a token request succeeded. They must not return access
tokens, refresh tokens, private keys, raw client secrets, bearer headers, or
whole credential files.

If a provider offers both personal OAuth and service accounts, support both
when the dependency already makes that cheap. Personal OAuth is usually the
lowest-friction trial path; service accounts are usually the lowest-friction
unattended path.

## Tool Surface

Keep first-class tools intent-shaped:

- prefer `query_report`, `inspect_url`, or `list_properties` over generic HTTP
  pass-throughs;
- keep read-only tools available by default;
- put mutations behind an explicit profile, capability, or confirmation layer;
- include a local `find_tools` path when the catalog may grow or clients use
  deferred loading;
- add `--print-tools` and `--print-tool-schema` so operators can inspect the
  served surface without starting a client.

Profile filtering should be centralized once. The same visible-tool helper or
inventory policy should drive `tools/list`, local discovery tools, schema
printing, and generated documentation. If a read-only profile denies a mutation
at call time, it should normally hide that mutation from discovery too.

Do not hide setup behind README-only instructions. If the server can explain
what is missing through a safe tool response, add that tool.

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
