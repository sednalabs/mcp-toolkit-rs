# CodeQL Workflow-Security Query Pack Reuse

`mcp-toolkit-rs` carries a small custom CodeQL Actions query pack under:

```text
.github/codeql/actions-workflow-security
```

The pack exists because generic CodeQL coverage is useful, but public MCP
service repositories also need a few repository-shaped invariants around runner
choice, trigger posture, release publication, and log hygiene.

## Reuse Model

For standalone public service repositories, prefer vendoring the pack into the
service repository rather than depending on an unpublished local path.

The supported path in this toolkit is:

1. start from `templates/single-crate-public-stdio-server`;
2. keep the vendored pack in `.github/codeql/actions-workflow-security`;
3. keep the `codeql-query-tests` workflow that installs and compiles the pack;
4. review any repository-specific wording so the queries stay neutral and
   accurate for the new service.

This model is fork-safe because the pack lives in the repository that runs the
workflow, and the template's `codeql.yml` keeps the trusted-base fallback
behavior for Actions query-pack resolution on forked pull requests.

## Versioning Guidance

Treat the pack as part of repository policy, not as an untracked copy-paste
artifact.

- Update it when the root toolkit pack changes materially.
- Keep `qlpack.yml` and `codeql-pack.lock.yml` committed together.
- Re-run the query-pack compile workflow after any `.ql`, `.qll`, `.qls`, or
  CodeQL workflow changes.
- If `Actions workflow security query tests` is a required branch-protection
  context, keep the pull request trigger unfiltered. Path-filtering a required
  check can leave unrelated pull requests permanently blocked because the
  required context is never created for that head SHA.
- Prefer repository-neutral invariant wording over organization-private
  phrasing.

## Validation

The minimum proof is a hosted run of:

- `.github/workflows/codeql-query-tests.yml`

That workflow should:

- install the CodeQL CLI through `github/codeql-action/setup-codeql`;
- `pack install` the vendored pack;
- resolve the query suite;
- compile the custom queries.

## References

- `.github/codeql/actions-workflow-security`
- `.github/workflows/codeql.yml`
- `templates/single-crate-public-stdio-server/.github/workflows/codeql-query-tests.yml`
