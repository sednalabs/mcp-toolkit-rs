# Pattern Recipes

Recipes turn the reference atlas and pattern manifests into repeatable starting
points for new MCP servers. They are intentionally short and operational:
choose the nearest recipe, start from the named template or adoption slice, and
keep service-specific code in the service repository.

Use `docs/pattern-manifests.md` for the manifest contract and
`docs/reference-server-atlas.md` for source landmarks before adding toolkit API.

## How To Use A Recipe

1. Pick one primary archetype and at most two secondary archetypes.
2. Record the atlas row and manifest file in the delivery-lane evidence block.
3. Start from the named template or smallest adoption helper.
4. Add only the toolkit crates named by the recipe.
5. Prove the served MCP boundary with hosted validation before promotion.

If the recipe asks for substrate that the toolkit does not have yet, create or
claim the relevant work item before adding service-local copies of the same
boilerplate again.

## `minimal-stdio-intent`

Use when a local stdio server exposes a compact set of high-value intent tools.

Minimal shape:

- start from `templates/curated-stdio-intent-server`;
- use `mcp-toolkit-core::tool_inventory` as the source of served tools;
- expose a setup/status or first discovery path that does not require reading
  implementation details;
- commit a strict tool-schema snapshot;
- add a stdio smoke that initializes the real binary and calls `tools/list`.

Required proof:

- schema snapshot in strict mode;
- stdio contract test;
- domain output tests for every first-class intent tool;
- GitHub-hosted validation on the reviewed commit.

Toolkit owner: `mcp-toolkit-core`, `mcp-toolkit-server`,
`mcp-toolkit-testing`.

Reference manifests:

- `docs/pattern-manifests/google-admin-mcp.json`

## `google-provider-read-only`

Use when a Google API server should be easy to authenticate without exposing
operator mutations by default.

Minimal shape:

- prefer Application Default Credentials and a browser or headless login helper;
- include quota-project and missing-scope diagnostics;
- use the shared Google auth-login response shape with argv, shell, headless,
  client-id-file, quota-project, API-enable, selected ADC path, and shared-ADC
  fields;
- keep product scopes in the service repository;
- default to a read-only profile;
- separate operator scopes, write tools, and restart guidance from the happy
  path.

Required proof:

- auth status covers missing credentials, missing scope, quota-project failure,
  and upstream denial;
- auth status exposes `token_check`, `access_check`, `operator_scope_check`,
  `adc_quota_project`, and `runtime_quota_project` with secret-safe values;
- profile-filtered discovery hides operator tools from the read-only profile;
- docs explain the client-id or quota-project path without requiring users to
  understand token exchange internals.

Toolkit owner: `mcp-toolkit-core` for discovery and profiles,
`mcp-toolkit-testing` for contracts, and provider-specific auth UX helpers only
when they remain generic across multiple Google services.

Reference manifests:

- `docs/pattern-manifests/google-admin-mcp.json`
- `docs/pattern-manifests/ga4-mcp.json`
- `docs/pattern-manifests/google-search-console-mcp.json`

## `analytics-scratchpad`

Use when an analytics server can return more data than chat should carry.

Minimal shape:

- make scratchpad behavior profile-gated;
- store large tabular results in a local bounded session;
- expose table inventory, preview, bounded SQL, and export evidence tools;
- keep provider query semantics in the service repository;
- document retention and cleanup behavior.

Required proof:

- scratchpad session tests with bounded reads;
- denial tests for disabled profiles or disallowed SQL;
- output contract tests that prove chat responses return handles and summaries,
  not unbounded result dumps.

Toolkit owner: `mcp-toolkit-scratchpad` for DuckDB session lifecycle,
restricted SQL, table inventory, append/drop helpers, and query projections;
`mcp-toolkit-testing` for safety/conformance fixtures; and
`mcp-toolkit-core` for response metadata helpers. Provider-specific ingest,
evidence bundle wording, and upstream query semantics stay in the service
repository.

Reference manifests:

- `docs/pattern-manifests/ga4-mcp.json`
- `docs/pattern-manifests/google-search-console-mcp.json`

## `hosted-http-auth`

Use when a server exposes Streamable HTTP and must publish MCP auth discovery.

Minimal shape:

- start from `templates/hosted-http-auth-server`;
- use server builders for route assembly, session behavior, and host guards;
- publish Protected Resource Metadata;
- serve authorization-server metadata when the deployment owns that surface;
- return bearer challenges on protected routes and reject hostile hosts before
  auth challenges leak.

Required proof:

- metadata contract tests;
- missing-token bearer challenge tests;
- pre-auth host rejection tests;
- hosted validation that exercises the actual router.

Toolkit owner: `mcp-toolkit-server`, `mcp-toolkit-http`,
`mcp-toolkit-auth`, and `mcp-toolkit-testing`.

Reference manifests:

- `docs/pattern-manifests/cloudflare-mcp.json`
- `docs/pattern-manifests/keycloak-admin-mcp.json`

## `operator-mutation`

Use when mutation tools are legitimate but must not be the default surface.

Minimal shape:

- split read, scratchpad, and operator profiles;
- mark write tools with explicit capability and risk posture;
- hide mutation tools from read-only discovery where the client surface allows;
- document preview/apply behavior or the equivalent safe mutation posture;
- keep backend-specific mutation semantics in the service repository.

Required proof:

- profile-filtered discovery tests;
- denial tests when operator mode is not enabled;
- domain tests for preview, idempotency, or rollback behavior where applicable;
- docs that make the operator profile opt-in.

Toolkit owner: `mcp-toolkit-core` for catalog/profile mechanics,
policy crates when capability checks are reusable, and service repositories for
provider mutations.

Reference manifests:

- `docs/pattern-manifests/cloudflare-mcp.json`
- `docs/pattern-manifests/google-search-console-mcp.json`
- `docs/pattern-manifests/keycloak-admin-mcp.json`

## `database-policy`

Use when the server exposes SQL or database-backed tools.

Minimal shape:

- keep database credentials and object semantics in the service repository;
- use toolkit policy primitives for read-only classification and capability
  checks;
- expose response profiles for agent loops and human debugging;
- degrade startup clearly when optional database features are unavailable;
- commit schema snapshots for large tool surfaces.

Required proof:

- SQL policy conformance vectors;
- runtime tests for allowed and denied query shapes;
- response-profile contract tests;
- dependency and release safety checks for public repositories.

Toolkit owner: `mcp-toolkit-policy-core`,
`mcp-toolkit-policy-runtime`, `mcp-toolkit-policy-conformance`,
`mcp-toolkit-postgres`, and `mcp-toolkit-testing`.

Reference manifests:

- `docs/pattern-manifests/postgres-mcp.json`

## `public-release-ready`

Use when a new MCP repository should be publishable from its first useful
commit.

Minimal shape:

- start from `templates/single-crate-public-stdio-server` unless another
  template is a better shape fit;
- include README, license, Cargo metadata, hosted Rust baseline checks, CodeQL,
  dependency governance, coverage upload, and schema snapshots;
- keep public wording neutral and service-owned;
- promote only from a passing GitHub run, release artifact, or tagged commit.

Required proof:

- GitHub-hosted checks on the reviewed commit;
- public README and license review;
- dependency governance and workflow-security checks;
- release evidence with commit SHA and artifact digest when a binary exists.

Toolkit owner: templates, repository policy docs, `mcp-toolkit-testing`, and
release-preflight tooling.

Reference manifests:

- `docs/pattern-manifests/cloudflare-mcp.json`
- `docs/pattern-manifests/postgres-mcp.json`
