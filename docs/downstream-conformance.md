# Downstream Conformance

`mcp-toolkit conformance` is the advisory harness that keeps the toolkit's
new-server lane grounded in real MCP servers. It reads the checked-in pattern
manifests under `docs/pattern-manifests/*.json` and reports whether each
reference currently has evidence for the toolkit contracts it demonstrates.

The first version is intentionally static and credential-free. It does not run
provider APIs, launch downstream repositories, or require private CI secrets.
That keeps toolkit pull requests reviewable while still making drift visible.

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
