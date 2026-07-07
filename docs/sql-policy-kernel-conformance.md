# SQL Policy Kernel Conformance

This note defines how `mcp-toolkit-policy-conformance` and
`mcp-toolkit-policy-core` prove behavioral alignment with the canonical SQL
restricted-policy vectors from a policy-kernel checkout.

## Authority model

- Source of truth for SQL restricted-policy semantics is in
  the policy-kernel contract repository:
  - `spec/sql_restricted_policy_contract.source.json`
  - `vectors/sql_restricted_policy.json`
- `mcp-toolkit-policy-core` is the consumer implementation of the SQL
  classifier.
- `mcp-toolkit-policy-conformance` is the reusable vector/schema harness that
  validates toolkit behavior against those artifacts.
- Service runtimes (for example postgres or GA4 scratchpad overlays) may add
  engine-specific guardrails, but must not redefine canonical SQL deny-code
  semantics without first updating kernel contract/vectors.

## Conformance command

Run from the `mcp-toolkit-rs` repository root:

```bash
./scripts/sql_policy_kernel_conformance.sh
```

Default artifact:

- `.tmp/sql_policy_conformance/sql_policy_core_vs_kernel_report.json`

The script resolves policy-kernel inputs in this order:

1. `--vectors <path>` passed directly to the command.
2. `KERNEL_ROOT` pointing at a policy-kernel checkout.
3. `PK_POLICY_KERNEL_ROOT` pointing at a policy-kernel checkout.
4. `../../policy-kernel` relative to this repository.

Override vectors/report path:

```bash
./scripts/sql_policy_kernel_conformance.sh \
  --vectors /path/to/policy-kernel/vectors/sql_restricted_policy.json \
  --report /tmp/sql_policy_core_vs_kernel_report.json
```

## Decision mapping

The conformance harness maps classifier output to canonical decision shape:

- allow: `allow=true`, no `code`, no `reason`
- deny: `allow=false`, `code=<classifier code>`, `reason=restricted_sql`

Any mismatch is a regression until contract/vectors are intentionally changed in
the policy-kernel contract repository.

## Hosted consumption lane

`.github/workflows/policy-kernel-consumption.yml` is the canonical hosted proof
that toolkit policy crates can consume policy-kernel contracts and vectors.
It checks out this repository plus an operator-configured policy-kernel target,
sets `PK_POLICY_KERNEL_ROOT`, runs policy crate tests, runs SQL conformance, and
uploads `policy-kernel-consumption-<run_id>` with:

- `manifest.json`
- `sql_policy_core_vs_kernel_report.json`
- optional downloaded policy-kernel validation artifacts with SHA-256 values

Public policy-kernel repositories can be consumed by passing
`policy_kernel_repository` to `workflow_dispatch` without an extra secret.
Private policy-kernel repositories are intentionally out of scope for this
public workflow. If the configured policy-kernel target is private or
inaccessible, the workflow emits a skipped manifest on pull requests and fails
manual dispatch with a clear setup error. Run private target validation from a
separate trusted environment rather than adding secret-backed private checkout
logic to this public repository.

Use `workflow_dispatch` to test against a non-default policy-kernel ref:

```bash
gh workflow run policy-kernel-consumption.yml \
  --repo sednalabs/mcp-toolkit-rs \
  --ref <toolkit-branch> \
  -f policy_kernel_ref=<policy-kernel-ref>
```

To include a policy-kernel validation artifact as provenance, also pass
`policy_kernel_run_id` and, optionally, `policy_kernel_artifact_name`.

For server adoption claims, combine this hosted manifest with
`docs/policy-kernel-provenance-acceptance.md`. The manifest proves toolkit
consumption and artifact identity; the server still owns request mapping,
runtime placement, and deny-before-mutation evidence.
