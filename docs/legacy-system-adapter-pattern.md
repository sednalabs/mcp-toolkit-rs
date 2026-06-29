# Legacy-System Adapter Pattern

This pattern is for MCP servers that wrap older operational systems with split
or incomplete control surfaces: partial APIs, admin HTML pages, hidden form
state, scheduled-job screens, local exports, or private file artifacts.

The goal is not to turn an old product into a generic HTTP, SQL, browser, or
admin automation endpoint. The goal is to expose a small, auditable set of
operator-intent tools that answer important questions and gate dangerous
actions.

## When To Use It

Use a legacy-system adapter when the upstream system has one or more of these
traits:

- a stable API that covers only part of the operational workflow;
- admin pages that are the only source for some state;
- form submissions with hidden fields, selected options, or brittle query
  shapes;
- scheduled jobs that should be inspected or canceled without exposing send or
  trigger controls;
- exports that may contain sensitive rows and must stay outside the public
  repository;
- old permission models that cannot express the narrower tool surface agents
  should receive.

Do not use this pattern as a shortcut for exposing arbitrary backend access. If
the system has a complete modern API with least-privilege credentials, build
first-class tools against that API directly.

## Core Shape

A legacy-system adapter should define a source-authority map before it defines
tools:

1. Prefer the stable API where it can answer the question.
2. Treat admin HTML, local files, and scheduled-job pages as unsafe substrates.
3. Allowlist the exact pages, query shapes, actions, fields, and file roots that
   have reviewed operator purpose.
4. Convert upstream state into redacted, typed, task-shaped MCP output.
5. Keep private row-level artifacts outside git and return aggregate evidence
   through MCP.
6. Bind mutations to preview/apply plans, runtime gates, fresh readback, and
   redacted post-apply proof.

The public tool contract should describe the operator question, not the legacy
mechanism. Prefer `queue_control_preview`, `settings_audit`, or
`owner_readback` style tools over `fetch_admin_page`, `run_sql`, or
`click_button`.

## Negative Tool Surface

The adapter's blocked surface is part of the design. Document the things the
server refuses to expose, especially when the upstream credentials could do
them:

- generic HTTP, browser, SQL, XML, or RPC escape hatches;
- raw row dumps or whole admin-page responses;
- send, trigger, import, export, or irreversible action tools unless each has a
  dedicated safety design;
- credential, provider, DNS, billing, or account-control mutations;
- contact or user-state mutations that bypass the upstream product's consent
  and suppression model;
- broad local file reads or writes outside approved private artifact roots.

This list should be visible in the service README and safety model. It lets
operators understand that a missing tool is intentional, not an implementation
gap.

## Preview/Apply Writes

When a mutation is genuinely necessary, use a two-step guard:

1. Preview reads the current upstream state, normalizes the requested change,
   and returns a deterministic plan id with warnings.
2. Apply requires the exact plan id plus the runtime enablement flag for that
   write family.
3. Apply re-reads the upstream page or API object before submitting the change.
4. Apply submits only allowlisted fields or actions.
5. Apply re-reads after the mutation and reports redacted readback evidence.

Avoid direct one-shot mutations. A preview plan for one upstream row, page, or
form state must not become a general write token.

## Private Artifact Lanes

Some legacy operations need row-level exports or validation artifacts. Those
files should be treated as private custody data:

- require explicit absolute output roots;
- reject repository paths, relative paths, symlinks, path escapes, and broad
  filesystem roots;
- write artifacts with stable names, hashes, and manifests;
- return counts, warnings, paths, sizes, and hashes through MCP;
- never imply that a private export is ready for a send, import, or mutation by
  itself.

Keep public docs and examples free of real recipient rows, hostnames,
credential file paths, account ids, and provider payloads.

## Design Checklist

Before exposing a tool, answer these questions:

1. What exact operator question does this tool answer?
2. Which upstream surface is the source authority for that answer?
3. Is there a safer API source than admin HTML or local files?
4. Which routes, query parameters, fields, or file roots are allowed?
5. What is redacted, capped, summarized, or kept out of MCP output?
6. What operation remains intentionally unavailable?
7. If the tool mutates state, where are preview, plan binding, runtime gates,
   fresh readback, and post-apply proof enforced?
8. Which tests prove the tool contract, blocked routes, redaction, and empty or
   failure states?

## What Belongs In The Toolkit

`mcp-toolkit-rs` should provide a reusable substrate for this pattern:

- tool inventory and profile filtering;
- schema snapshot and transport contract tests;
- redaction, bounded labels, and sanitized diagnostics;
- guarded preview/apply posture and runtime policy helpers;
- local server composition and ergonomic discovery;
- documentation templates and checklists.

Keep service-specific details out of the toolkit:

- backend clients and endpoint paths;
- product vocabulary and resource ids;
- admin-page parsers and hidden-field semantics;
- route allowlists and form-field allowlists;
- private artifact formats tied to one product;
- operator wording that only makes sense for one deployment.

## Reference Implementation

[`sednalabs/interspire-6-mcp`](https://github.com/sednalabs/interspire-6-mcp)
is a concrete reference implementation of this pattern for a legacy newsletter
system. It uses the toolkit substrate for MCP server shape and contract discipline
while keeping product-specific XML semantics, admin HTML parsing, route
allowlists, and operator safety wording in the service repository.
