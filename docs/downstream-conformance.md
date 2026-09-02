# Downstream Conformance

`mcp-toolkit conformance` is the advisory harness that keeps the toolkit's
new-server lane grounded in real MCP servers. It reads the checked-in pattern
manifests under `docs/pattern-manifests/*.json` and reports whether each
reference currently has evidence for the toolkit contracts it demonstrates.

The first version is intentionally static and credential-free. It does not run
provider APIs, launch downstream repositories, or require private CI secrets.
That keeps toolkit pull requests reviewable while still making drift visible.

## Protocol-era conformance

The protocol date and the Rust SDK release are separate compatibility axes. The
current migration is pinned to `rmcp = 3.2.0` and records both protocol eras
explicitly:

| Protocol date | Lifecycle exercised | Required evidence |
| --- | --- | --- |
| `2025-11-25` | Legacy `initialize`/`notifications/initialized` handshake, with `ProtocolVersion::LATEST` remaining an honest SDK alias for this era. | A hosted contract run must show the initialize response echoes `2025-11-25` and that the subsequent legacy `tools/list`/`tools/call` requests succeed. |
| `2026-07-28` | Current stateless request model; no initialize handshake, and each request carries protocol version, client identity, and client capabilities in `params._meta`. | A hosted contract run must show current `tools/list`/`tools/call` requests with the complete `_meta` object and must bind the exact commit, workflow run, and `rmcp = 3.2.0` lockfile. |

`ProtocolVersion::LATEST` must not be used as a synonym for the newest protocol
date supported by RMCP. The shared stdio contract harness selects
`2026-07-28` explicitly for maintained current behavior and exposes an
explicit legacy entry point for `2025-11-25` compatibility checks.

Hosted proof is authoritative for this migration. A green local compile or
static manifest check does not prove either protocol lifecycle. Record the
repository, workflow/run URL, exact head SHA, lockfile version, and the
protocol-era case that the run exercised before treating conformance as
accepted. Do not claim provider or production acceptance from these
credential-free tests.

## What It Checks

Each manifest exposes these proof areas:

| Area | Meaning |
| --- | --- |
| `schema_snapshot` | Tool schemas or generated snapshots exist for the reference. |
| `transport_contract` | The stdio or hosted HTTP transport has a contract or smoke test. |
| `auth_surface_contract` | Auth metadata, challenges, login/status UX, or provider diagnostics are covered when relevant. |
| `domain_contracts` | Service-specific behavior has tests or documented evidence. |
| `hosted_validation` | A hosted CI or release lane has proved the reference recently enough to use as evidence. |
| `release_evidence` | Public release, provenance, or package-readiness evidence exists where the pattern depends on it. |

The checker treats impossible or contradictory manifest claims as hard findings.
Examples include an `analytics-scratchpad` pattern without scratchpad support, a
`public-release-ready` row without release evidence, or a schema-snapshot
discovery claim whose conformance state is not `present`.

Gaps that are still useful to see but should not block every toolkit change are
advisory findings. Planned release evidence for a server that is not itself the
public-release archetype is advisory. Unknown hosted validation for an adjacent
reference is also advisory.

## Commands

```sh
mcp-toolkit conformance
mcp-toolkit conformance --pattern analytics-scratchpad
mcp-toolkit conformance --server google-search-console-mcp
mcp-toolkit conformance --strict
```

`--strict` fails only when hard manifest contradictions are present. Advisory
findings still print and keep exit status success.

`mcp-toolkit patterns <pattern-id>` also prints the same six conformance states
for every manifest that demonstrates the selected archetype. Use that view when
choosing a server shape; use `mcp-toolkit conformance` when reviewing the fleet.

## Adding A Reference

When adding or changing a manifest:

1. Choose conservative states. Prefer `planned`, `reference-only`, or `unknown`
   over claiming `present` without evidence.
2. Add references to public docs, tests, workflows, snapshots, or source
   landmarks that explain the claim.
3. Run `mcp-toolkit conformance --strict` before opening the PR.
4. If the manifest adds a hard finding, either fix the contradiction or explain
   why the schema needs a new state before landing.

## Graduation Path

This harness should grow in layers:

1. Keep static manifest invariants in `mcp-toolkit` so the CLI can explain the
   fleet without external dependencies.
2. Add optional repository-local commands that can validate a checked-out
   downstream server against its manifest.
3. Add GitHub-hosted advisory workflows that run selected downstream checks
   without credentials.
4. Promote only stable, low-noise checks into required gates.

Live provider calls, private credentials, and service-specific authorization
remain outside the default toolkit conformance lane.
