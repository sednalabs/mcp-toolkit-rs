# CodeQL Query Packs and Coverage

`mcp-toolkit-rs` uses stock CodeQL security analysis plus repository-owned query
packs where the toolkit has a narrow contract that generic analysis cannot know.

The repository-owned packs are:

```text
.github/codeql/actions-workflow-security
.github/codeql/rust-toolkit-contract
```

The Actions pack covers workflow and release-security invariants. The Rust pack
covers high-confidence toolkit contract drift: shared policy constants,
safety-metadata projection, guarded-action/read-only coupling, and process PID
validation. These queries are deliberately narrow. They supplement rather than
replace `security-and-quality`.

The advanced CodeQL workflow also scans Python control-plane code under
`.github/scripts`, `scripts`, and the maintained public-stdio template's release
scripts. Python planners, release helpers, and governance checks are executable
security surfaces and should not sit outside CodeQL merely because the product
runtime is primarily Rust.

## Actions Pack Reuse

For standalone public service repositories, prefer vendoring the Actions pack
into the service repository rather than depending on an unpublished local path.

The supported path in this toolkit is:

1. start from `templates/single-crate-public-stdio-server`;
2. keep the vendored pack in `.github/codeql/actions-workflow-security`;
3. keep the `codeql-query-tests` workflow that installs and compiles the pack;
4. review repository-specific wording so the queries stay neutral and accurate
   for the new service.

The Rust toolkit-contract pack is not intended for automatic vendoring. Its
queries name toolkit-owned source paths and source-of-truth functions, so a
standalone service should create its own contract pack only for similarly
stable, high-signal invariants.

## Query-Test Policy

Compiling a custom query proves only that its QL is syntactically and
semantically accepted by the current CodeQL libraries. It does not prove that
the query still detects the intended regression.

`codeql-query-tests` therefore has two proof levels:

- the Actions packs are installed, resolved, and compiled;
- the Rust toolkit-contract pack is installed, resolved, compiled, and executed
  with `codeql test run` against committed positive/negative contract fixtures.

New Rust contract queries should include a `.qlref`, expected result, and minimal
fixture source. Prefer fixtures that isolate one owned invariant and produce one
high-confidence result.

The same workflow also runs `.github/scripts/test_codeql_static_workflow.py` so
language coverage, config linkage, query-test execution, and fork-policy
hardening cannot drift silently.

## Trusted Pull-Request Policy

Forked pull requests must not be able to replace the repository's scanner policy
with their own weaker configuration. Rust and Python analysis restore
`.github/codeql` from the exact base SHA before initialization. The Actions lane
likewise resolves its custom pack from the exact base SHA and now fails closed if
that trusted pack cannot be recovered.

Same-repository pull requests intentionally exercise candidate CodeQL policy so
maintainers can validate new packs and configs before landing them. Query-pack
changes still require the independent query-test gate before their results are
trusted for review.

## Versioning Guidance

Treat CodeQL packs as repository policy, not as untracked copy-paste artifacts.

- Update vendored Actions packs when the root toolkit pack changes materially.
- Keep the Actions pack's `qlpack.yml` and `codeql-pack.lock.yml` committed
  together.
- Re-run query tests after any `.ql`, `.qll`, `.qls`, CodeQL config, or CodeQL
  workflow change.
- If `Actions workflow security query tests` is a required branch-protection
  context, keep the pull request trigger unfiltered. Path-filtering a required
  check can leave unrelated pull requests permanently blocked because the
  required context is never created for that head SHA.
- Start repository-contract rules as high-precision warnings. Promote their
  enforcement only after the rule has survived real review without noisy false
  positives.
- Do not teach CodeQL that a validator is a sanitizer unless the validator
  actually establishes the security property the stock query is tracking.

## Validation

The minimum hosted proof is:

- `.github/workflows/codeql-query-tests.yml` for custom-pack and workflow-shape
  validation;
- `.github/workflows/codeql.yml` for Actions, Python, and Rust analysis on the
  exact candidate or integration generation.

A green CodeQL workflow proves the analyzer completed for that generation. It
must not be described as proof that every reported alert is acceptable; alert
triage and any configured code-scanning merge protection remain separate
admission decisions.

## References

- `.github/codeql/actions-workflow-security`
- `.github/codeql/rust-toolkit-contract`
- `.github/codeql/codeql-python.yml`
- `.github/codeql/codeql-rust.yml`
- `.github/workflows/codeql.yml`
- `.github/workflows/codeql-query-tests.yml`
- `.github/scripts/test_codeql_static_workflow.py`
