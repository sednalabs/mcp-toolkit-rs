# Reference Server Atlas

This atlas maps reusable MCP server patterns to real servers in the wider
public Rust MCP ecosystem. Use it before adding a new toolkit abstraction,
template, or generator archetype.

The goal is to learn from living services without turning this repository into
a pile of example apps. The toolkit should extract substrate that is useful to
unrelated MCP projects. Service repositories should keep provider clients,
domain payloads, deployment choices, and product-specific policy.

Machine-readable pattern summaries live in `docs/pattern-manifests/*.json`.
Implementation guidance for each archetype lives in `docs/pattern-recipes.md`.
Use the atlas to understand the source service, the manifest to summarize the
shape, and the recipe to decide what a new server should copy, adopt, or defer.

## How To Use This Atlas

1. Pick the closest server shape from the archetype map.
2. Read the source landmarks for that row before designing a new abstraction.
3. Check the matching pattern manifest and recipe when one exists.
4. Start from the maintained toolkit template named by the delivery lane.
5. Extract only the generic substrate that at least two unrelated servers need.
6. Record the reference row, manifest, and recipe used in the PR or work item
   evidence block.

If a pattern is valuable but still tied to one provider, document it as a
reference-service pattern first. Promote it into `mcp-toolkit-rs` only after the
boundary is generic enough to explain without provider vocabulary.

## Archetype Map

| Archetype | Start here | Use when |
| --- | --- | --- |
| `minimal-stdio-intent` | `templates/curated-stdio-intent-server`; `sednalabs/google-admin-mcp` | A process-local server needs a small curated tool surface, schema snapshots, and a low-friction first useful call. |
| `google-provider-read-only` | `sednalabs/google-admin-mcp`; `sednalabs/ga4-mcp`; `sednalabs/google-search-console-mcp` | A Google API server needs Application Default Credentials, quota-project guidance, redacted auth diagnostics, and read-only defaults. |
| `analytics-scratchpad` | `sednalabs/ga4-mcp`; `sednalabs/google-search-console-mcp` | Large analytical results need local DuckDB-backed sessions, bounded SQL, evidence export, and profile gating. |
| `hosted-http-auth` | `templates/hosted-http-auth-server`; `sednalabs/cloudflare-mcp` | A server exposes Streamable HTTP and must serve OAuth metadata, bearer challenges, host guards, and session behavior. |
| `operator-mutation` | `sednalabs/cloudflare-mcp`; `sednalabs/google-search-console-mcp`; `sednalabs/keycloak-admin-mcp` | Mutating tools must be explicit, profile-gated, separately documented, and hidden from read-only discovery where possible. |
| `database-policy` | `sednalabs/postgres-mcp`; `mcp-toolkit-policy-core`; `mcp-toolkit-policy-runtime` | SQL or database access needs read-only classification, capability guards, response profiles, startup checks, and release safety gates. |
| `public-release-ready` | `templates/single-crate-public-stdio-server`; `sednalabs/cloudflare-mcp`; `sednalabs/postgres-mcp` | A new public MCP repository needs CI, CodeQL, dependency governance, schema snapshots, release evidence, and public wording hygiene. |

## Reference Rows

### `sednalabs/google-admin-mcp`

Use this as the smallest Google auth and discovery reference.

Reusable patterns:

- `find_tools` over `ToolInventory` for deferred-loading clients.
- Safe `gcloud auth application-default login` command construction.
- OAuth client JSON validation that does not return client secrets.
- Read-only default profile with explicit future operator posture.
- Redacted local auth state inspection instead of credential copying.

Source landmarks:

- `README.md` for first-run operator flow.
- `docs/GETTING_STARTED.md` for ADC and OAuth-client setup.
- `docs/TOOL_GUIDE.md` for the compact auth helper surface.
- `src/tool_surface.rs` for inventory-backed `find_tools`.
- `src/server.rs` for profile-aware tool discovery.

Do not extract:

- Google product scopes as generic toolkit defaults.
- Provider-specific `gcloud` wording outside a named provider helper.

### `sednalabs/ga4-mcp`

Use this as the richest Google analytics and scratchpad reference.

Reusable patterns:

- Low-friction browser/ADC login commands with cloud-platform scope guidance.
- `auth status` diagnostics that distinguish missing auth, missing scopes,
  quota-project problems, and upstream permission failures.
- `read_only` versus `scratchpad` capability profiles.
- Contract-shaped report responses with redacted metadata.
- DuckDB scratchpad sessions, bounded SQL, table inventory, and evidence
  bundles for large analytical workflows.
- Hosted HTTP auth configuration for services that need MCP Auth as well as
  upstream Google auth.

Source landmarks:

- `README.md` and `docs/GETTING_STARTED.md` for the happy path.
- `docs/auth-modes.md` for credential-source tradeoffs.
- `docs/scratchpad-operator-guide.md` for DuckDB session behavior.
- `docs/payload-contract-v1.md` for response envelopes.
- `src/auth_ux.rs` for CLI auth UX and quota-project guidance.
- `src/tool_surface.rs` for profile-aware tool inventory.
- `tests/scratchpad_integration_load.rs` and
  `tests/contract_safety_conformance.rs` for scratchpad safety coverage.

Do not extract:

- GA4 dimensions, metrics, report semantics, or analytics-specific output
  contracts.
- Provider-specific ingest or evidence wording. Generic DuckDB session,
  bounded SQL, and table lifecycle behavior now belongs in
  `mcp-toolkit-scratchpad`.

### `sednalabs/google-search-console-mcp`

Use this as the lean Search Console service reference.

Reusable patterns:

- A direct REST adapter for a Google API where a generated SDK would add
  more weight than value.
- Default read-only Search Console scope with explicit operator scope for site
  and sitemap mutations.
- Auth-status and auth-login helper tools with clear restart guidance for
  long-lived stdio clients.
- `find_tools` and profile-filtered tool discovery.
- Search Analytics scratchpad ingestion that keeps large evidence out of chat.

Source landmarks:

- `README.md` for Search Console first-run and operator profile flow.
- `docs/TOOL_GUIDE.md` for read, scratchpad, and operator tool groups.
- `src/config.rs` for read-only/operator scope and profile settings.
- `src/gsc_client.rs` for direct REST and credential-source selection.
- `src/tool_surface.rs` for profile-aware inventory.
- `src/tools.rs` for scratchpad and operator tool behavior.

Do not extract:

- Search Console site, sitemap, or URL Inspection semantics.
- Search Console-specific ingest, metric, or evidence-bundle wording into the
  generic scratchpad crate.

### `sednalabs/cloudflare-mcp`

Use this as the hosted HTTP/auth, deferred-loading, and release-provenance
reference.

Reusable patterns:

- Streamable HTTP server assembly with auth-on-non-loopback safety.
- OAuth Protected Resource Metadata and authorization-server metadata.
- Bearer challenges, session behavior, and host-header guardrails.
- OpenAI-facing deferred-loading support through `find_tools` and resources.
- Read-only discovery that hides mutation surfaces.
- Release provenance tying binary digest, schema snapshot, and toolkit revision.
- Public repository CodeQL, dependency-governance, and workflow-security checks.

Source landmarks:

- `README.md` and `docs/GETTING_STARTED.md` for operator setup.
- `docs/CLIENT-CONTRACT.md` for HTTP/session/auth expectations.
- `docs/CONFORMANCE_DOGFOOD.md` for self-check coverage.
- `docs/AGENT_ROUTING.md` for client profile composition.
- `spec/README.md` for schema and release provenance artifacts.
- `src/main.rs` for HTTP/auth surface assembly.
- `src/tool_surface.rs` and `tests/mcp_stdio_smoke.rs` for discovery coverage.

Do not extract:

- Cloudflare API clients, resource names, or account-specific policy.
- Provider-specific mutation semantics.

### `sednalabs/postgres-mcp`

Use this as the database policy, response-profile, and release-safety
reference.

Reusable patterns:

- SQL read-only classification through toolkit policy primitives.
- Capability guards and degraded startup behavior for optional database
  features.
- Response profiles such as compact agent loops versus human-debug output.
- Tool-schema snapshot contracts for a large surface.
- Dependency governance, runtime safety, and release checklists.
- Build-helper and hosted-validation documentation for expensive proof.

Source landmarks:

- `README.md` for operator value and documentation map.
- `docs/GETTING_STARTED.md` for first run.
- `docs/payload-v2-contract.md` for response shaping and profiles.
- `docs/sql-policy-contract.md` for SQL policy behavior.
- `docs/SAFETY_CHECKLIST.md` and `docs/release-checklist.md` for release gates.
- `src/sql_safety.rs`, `src/server.rs`, and `src/tools/query.rs` for policy and
  response-profile implementation.
- `spec/tool_schema_snapshot.v1.json` for the served surface contract.

Do not extract:

- PostgreSQL connection policy or database object semantics as generic MCP
  behavior.
- Performance thresholds that only make sense for one deployment.

### `sednalabs/keycloak-admin-mcp`

Use this as an adjacent auth-policy reference, not as a Rust scaffold source.

Reusable patterns:

- Centralized authorization checks that return stable auth reason buckets.
- Read versus write role requirements with an explicit operator role.
- OAuth metadata and protected resource endpoints for HTTP clients.
- Request-id and audit-log propagation through protected tools.
- Scope-policy and realm setup documentation for security-sensitive operators.

Source landmarks:

- `README.md` for the server and auth metadata surface.
- `docs/auth-philosophy.md` for the no-hand-rolled-token-crypto principle.
- `docs/scope-policy.md` for read/write role mapping.
- `docs/RUNBOOK.md` and `docs/SAFETY_CHECKLIST.md` for operator checks.
- `src/auth.ts`, `src/http_bootstrap.ts`, and `src/tools/guards.ts` for auth
  enforcement shape.

Do not extract:

- TypeScript runtime APIs into Rust toolkit crates.
- Keycloak realm, role, or admin-client semantics.

## Extraction Checklist

Before turning a reference pattern into toolkit code, confirm:

- At least two unrelated servers need the same substrate.
- The proposed API can be documented without provider-specific terms.
- The tests can use generic fixtures rather than one service's backend data.
- The generated docs can point to a starter template and a reference row.
- The delivery lane records GitHub-hosted validation and reviewer signoff.

If any answer is uncertain, keep the pattern in this atlas and create a recipe
or manifest entry before adding a toolkit API.
