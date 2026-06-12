# SQL Policy Kernel Conformance

This note defines how `mcp-toolkit-policy-conformance` and
`mcp-toolkit-policy-core` prove behavioral alignment with the canonical SQL
restricted-policy vectors in `mcp-policy-kernel`.

## Authority model

- Source of truth for SQL restricted-policy semantics is in
  `mcp-policy-kernel`:
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

Override vectors/report path:

```bash
./scripts/sql_policy_kernel_conformance.sh \
  --vectors /path/to/mcp-policy-kernel/vectors/sql_restricted_policy.json \
  --report /tmp/sql_policy_core_vs_kernel_report.json
```

## Decision mapping

The conformance harness maps classifier output to canonical decision shape:

- allow: `allow=true`, no `code`, no `reason`
- deny: `allow=false`, `code=<classifier code>`, `reason=restricted_sql`

Any mismatch is a regression until contract/vectors are intentionally changed in
`mcp-policy-kernel`.
