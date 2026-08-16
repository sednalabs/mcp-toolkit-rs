# New-Server CLI And Generated File Reference

This page is the command and file reference for the executable new-server lane.
Use it after the quick path in `docs/golden-path.md` and before changing
generated files by hand.

The generator is intentionally small. It copies maintained templates, rewrites
the package name and toolkit dependency source, then leaves provider-specific
domain logic in the generated repository.

## Command Map

Run commands from the `mcp-toolkit-rs` checkout while developing the toolkit:

```bash
cargo run -p mcp-toolkit --bin mcp-toolkit -- <command>
```

In an installed environment, the binary form is:

```bash
mcp-toolkit <command>
```

| Command | Purpose | Normal next step |
| --- | --- | --- |
| `mcp-toolkit templates` | List maintained template ids. | Choose `--template <id>` when you already know the transport shape. |
| `mcp-toolkit patterns` | List maintained archetypes and their recommended templates. | Use `patterns <id>` before generating from a pattern. |
| `mcp-toolkit patterns <id>` | Show manifest evidence for one archetype. | Record the recipe and reference manifests in the review evidence. |
| `mcp-toolkit pattern <id>` | Alias for `patterns <id>`. | Same as above. |
| `mcp-toolkit draft-tools <source>` | Draft a conservative MCP tool report from local OpenAPI JSON, JSON Schema, or endpoint notes. | Review names, profiles, auth, pagination, and tests before copying approved entries into code. |
| `mcp-toolkit new --name <package>` | Generate a new server from a maintained template. | Run `doctor`, inspect generated files, then run generated tests. |
| `mcp-toolkit doctor [generated-server-dir]` | Check generated source, proof files, probe files, and baseline workflow. | Fix missing scaffold files or continue to validation. |
| `mcp-toolkit release-preflight [generated-server-dir]` | Check public-readiness files, workflows, release proof scaffolding, and high-confidence secret markers. | Fix missing public repository evidence before publishing or installing. |
| `mcp-toolkit client-config [generated-server-dir]` | Print a Codex-style client snippet for the generated transport. | Replace placeholder command paths, URLs, or profiles for the real deployment. |
| `mcp-toolkit conformance` | Print downstream manifest conformance posture. | Use `--strict` in PRs that change pattern manifests. |

The top-level help is deliberately short:

```bash
mcp-toolkit --help
mcp-toolkit new --help
mcp-toolkit draft-tools --help
mcp-toolkit doctor --help
mcp-toolkit release-preflight --help
mcp-toolkit client-config --help
mcp-toolkit conformance --help
```

## Draft Tools

Use `draft-tools` when an existing API description or provider docs can seed
the first catalog discussion:

```bash
mcp-toolkit draft-tools ./openapi.json
mcp-toolkit draft-tools ./openapi.json --format json
mcp-toolkit draft-tools ./endpoints.md --json
```

Supported inputs are deliberately local and deterministic:

- OpenAPI JSON with a top-level `paths` object;
- standalone JSON Schema or schema-like JSON objects;
- markdown or text lines shaped like `GET /items List items`.

The command emits a review report with the stable JSON schema marker
`mcp_toolkit_draft_tools_report`. It does not execute generated code, fetch
remote `$ref` targets, call upstream APIs, or expose tools. Read-like operations
are proposed for the `read_only` profile; write, destructive, and uncertain
operations are proposed as disabled-by-default `operator` work.

Treat the report as planning input. Before copying a proposed entry into a real
`ToolCatalogEntry`, confirm user-intent naming, auth scopes, pagination,
rate-limit behavior, timeout/error mapping, fake-adapter fixtures, schema
snapshots, and catalog-profile tests.

## Generator Options

`mcp-toolkit new` accepts either `--name <package>` or a positional package
name:

```bash
mcp-toolkit new --name my-mcp-server
mcp-toolkit new my-mcp-server
```

Useful options:

| Option | Use when | Notes |
| --- | --- | --- |
| `--template <id>` or `-t <id>` | You know the exact maintained template. | Current ids are `curated-stdio-intent`, `single-crate-public-stdio`, and `hosted-http-auth`. |
| `--pattern <id>` or `--archetype <id>` | You want the generator to choose the recommended template for an archetype. | Inspect the archetype first with `mcp-toolkit patterns <id>`. |
| `--output <dir>` or `-o <dir>` | The output directory should differ from the package name. | The directory must be relative and under the current working directory. |
| `--toolkit-root <dir>` | You want generated manifests to use a local toolkit checkout. | This is the default during toolkit development. |
| `--toolkit-git <url>` | You want a portable service repository. | Use `https://github.com/sednalabs/mcp-toolkit-rs` for public Git dependencies; `release-preflight` rejects local toolkit path dependencies and committed Cargo path overrides for public-ready output. |
| `--force` | You are intentionally replacing generated files. | Without this, changed files are protected from overwrite. |

Do not pass both `--toolkit-root` and `--toolkit-git`. A generated public or
portable repository should normally be created with `--toolkit-git` from the
first commit so the manifest does not point at a developer machine path.

## Archetype Selection

Use archetypes when you know the server shape but not the exact scaffold:

```bash
mcp-toolkit patterns
mcp-toolkit patterns minimal-stdio-intent
mcp-toolkit conformance --pattern minimal-stdio-intent
mcp-toolkit new --name my-mcp-server --pattern minimal-stdio-intent
```

The pattern output shows:

- the recommended template;
- the recipe anchor in `docs/pattern-recipes.md`;
- reference manifests under `docs/pattern-manifests/`;
- transports, auth modes, profiles, scratchpad posture, and conformance flags
  observed in real servers.

Record that evidence in the delivery-lane evidence block before review. If no
archetype fits, record why and use `--template` directly.

## Doctor Checks

Run doctor immediately after generation:

```bash
mcp-toolkit doctor my-mcp-server
```

Doctor infers the starter shape and checks for the scaffold files reviewers
expect. The exact checks vary by template, but a healthy generated project
usually includes:

- `Cargo.toml`;
- `src/lib.rs`;
- `src/main.rs`;
- `spec/tool_schema_snapshot.v1.json`;
- one `spec/mcp_probe_*.v1.json` scenario;
- catalog/profile and schema snapshot tests;
- a transport contract test;
- `.github/workflows/rust-baseline.yml`.

Doctor also prints the generated repository's local setup commands:

```bash
cargo run -- --doctor
cargo run -- --print-tools
cargo run -- --print-tool-schema
cargo run -- --print-client-config
cargo fmt --all --check
cargo test --all-targets --all-features
```

Those generated binary-local commands are part of the operator UX. Keep them
working unless the service provides a stronger equivalent.

## Release Preflight

Run release preflight before publishing a generated repository, attaching a
binary, or installing it on a shared host:

```bash
mcp-toolkit release-preflight my-mcp-server
```

Release preflight is stricter than doctor. It expects a public-ready repository
shape with README guidance, a license file, Cargo license and description
metadata, baseline CI, CodeQL, coverage, dependency governance, schema/probe
proof for the generated transport, governance docs, portable toolkit
dependencies, no committed Cargo path overrides, a pinned dual-native Linux
artifact workflow, an exact archive verifier, and no high-confidence secret
markers in generated text files. The native workflow must use literal x86_64
and arm64 hosted-runner matrix rows, exact candidate readback, locked builds,
ELF machine plus GNU interpreter/GLIBC checks, source/input/dependency-bound
CycloneDX SBOMs, complete checksums, canonical tool inventory/schema parity,
SHA-qualified artifacts, consumer reverification, and trusted-push GitHub
attestations.

The `single-crate-public-stdio` template is designed to pass release preflight
after generation with `--toolkit-git` and a committed `Cargo.lock`. Smaller
starter templates may pass `doctor` but fail `release-preflight` until the
service repository adds public release files and workflows.

The generated public stdio workflow is artifact-only and runs only for `main`
pushes or `v...` tags. Generate and commit `Cargo.lock` before that trusted
push. Pull-request and arbitrary manual feature-branch code receive no OIDC or
attestation authority. Release preflight structurally parses the workflow,
including folded YAML action references, but does not build, attest, publish,
or install a binary. A trusted successful run produces and attests a run-bound
`release-authorization.json` receipt only after consumer reverification. Its exact path is
`.github/workflows/native-release-artifacts.yml`.

## Client Config

Use `client-config` after the generated project has the intended transport:

```bash
mcp-toolkit client-config my-mcp-server
```

Overrides:

| Option | Applies to | Purpose |
| --- | --- | --- |
| `--name <server-name>` | stdio and HTTP | MCP client server key. |
| `--transport stdio` | any generated project | Force stdio output when inference is ambiguous. |
| `--transport http` | any generated project | Force HTTP output when inference is ambiguous. |
| `--command <path>` | stdio | Set the release binary path. |
| `--url <url>` | HTTP | Set the hosted `/mcp` URL. |
| `--profile <profile>` | stdio | Set the generated tool profile environment value. |

The default stdio profile is `read_only`. Operator or mutation tools should
only appear when the generated service explicitly enables an operator profile or
a stronger service-specific policy gate.

Generated analytics servers should add `mcp-toolkit-scratchpad` when large
provider results need local DuckDB-backed sessions instead of chat-sized
payloads. Keep provider ingest, upstream evidence wording, and retention policy
in the service repository.

## Generated File Layout

The three maintained templates have overlapping proof files. This is the normal
shape after generation.

The stdio templates carry `spec/mcp_probe_stdio_smoke.v1.json`; the hosted
HTTP template carries `spec/mcp_probe_http_auth_smoke.v1.json`. Common proof
tests include `tests/catalog_profile_contract.rs` and
`tests/tool_schema_snapshot.rs`. Keep these probe and snapshot files together
so reviewers can inspect the first runtime MCP call without hunting through
tests.

### Curated Stdio Intent

```text
my-mcp-server/
  Cargo.toml
  README.md
  .github/workflows/rust-baseline.yml
  spec/
    mcp_probe_stdio_smoke.v1.json
    tool_schema_snapshot.v1.json
  src/
    lib.rs
    main.rs
  tests/
    catalog_profile_contract.rs
    stdio_smoke.rs
    tool_schema_snapshot.rs
```

Use this for a process-local server with a small curated tool surface.

### Hosted HTTP Auth

```text
my-mcp-server/
  Cargo.toml
  README.md
  .github/workflows/rust-baseline.yml
  spec/
    mcp_probe_http_auth_smoke.v1.json
    tool_schema_snapshot.v1.json
  src/
    lib.rs
    main.rs
  tests/
    catalog_profile_contract.rs
    cli_introspection.rs
    http_auth_contract.rs
    tool_schema_snapshot.rs
```

Use this for Streamable HTTP, local host/origin guardrails, OAuth Protected Resource Metadata,
authorization-server metadata, and bearer challenges.

### Single-Crate Public Stdio

```text
my-mcp-server/
  Cargo.toml
  LICENSE
  README.md
  deny.toml
  .github/workflows/
    code-coverage.yml
    codeql-query-tests.yml
    codeql.yml
    dependency-governance.yml
    native-release-artifacts.yml
    rust-baseline.yml
  docs/
    dependency-governance.md
  scripts/
    dependency_governance_check.sh
    native_release_artifact.py
    rebaseline_tool_schema_snapshot.sh
    rmcp_macro_runtime_pin_check.py
    workflow_runner_policy_check.py
  spec/
    mcp_probe_stdio_smoke.v1.json
    tool_schema_snapshot.v1.json
  src/
    lib.rs
    main.rs
  tests/
    catalog_profile_contract.rs
    stdio_smoke.rs
    tool_schema_snapshot.rs
```

Use this when the generated repository is intended to be public and should
start with license, CI, CodeQL, dependency governance, and workflow-security
posture.

## Safe Customization Points

Generated files are meant to be edited, but each file has a job.

| File | Edit when | Keep stable |
| --- | --- | --- |
| `src/lib.rs` | Replacing example tools with provider-specific intent tools. | Tool catalog/profile gating should remain the source for discovery and schema output. |
| `src/main.rs` | Adding service config, auth setup, or transport options. | `--doctor`, `--print-tools`, `--print-tool-schema`, and `--print-client-config` should keep working. |
| `tests/*` | Adding stronger service-specific coverage. | Do not delete schema, profile, or transport proof without an equal replacement. |
| `spec/tool_schema_snapshot.v1.json` | The served public tool contract intentionally changes. | Rebaseline only in update mode and review the JSON diff. |
| `spec/mcp_probe_*.v1.json` | The first runtime probe changes with the transport or first useful tool. | Keep it credential-safe and deterministic. |
| `.github/workflows/*` | The repository has a stronger hosted validation path. | Keep GitHub-hosted proof for formatting, tests, and public-readiness checks. |
| `README.md` | Explaining the service's real first-run path. | Keep install, auth/status, tool-surface inspection, client config, and validation commands copyable. |

Avoid editing generated toolkit dependency paths by hand after the first commit.
Regenerate with `--toolkit-git` for portable repositories or with
`--toolkit-root` for a local adoption branch.

## Validation Commands

For generated stdio or hosted projects:

```bash
cargo fmt --all --check
cargo test --all-targets --all-features
```

For the standalone public stdio template, also keep the copied governance
script green:

```bash
./scripts/dependency_governance_check.sh
mcp-toolkit release-preflight .
```

When editing the toolkit templates themselves, use the template manifest paths
from `docs/starter-templates.md`, then record hosted GitHub validation before
merge.
