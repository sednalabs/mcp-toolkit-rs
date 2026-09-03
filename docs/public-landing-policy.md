# Public Landing Policy

This repository is public-facing. Code, workflow definitions, documentation,
branch names, pull request text, release notes, and CI output should be treated
as publication surfaces.

## Normal Landing Path

Normal changes must:

1. branch from current `main`;
2. open a pull request targeting `main`;
3. pass required hosted checks;
4. merge through GitHub after checks are green.

Reviews are encouraged, but this repository does not require a human approval
for every change. Required hosted checks are the minimum merge gate.

## Required Hosted Checks

The required checks for `main` are:

- `Run targeted Rust baseline`;
- `CodeQL required gate`;
- `First-wave Cargo package readiness`;
- `dependency-governance`;
- `Rust Cobertura coverage`;
- `DevSkim`;
- `scan-pr / osv-scan`;
- `Actions workflow security query tests`;
- `Rust 2024 compatibility guard`.

These checks must appear on every pull request and every push to `main`, so the
workflows intentionally avoid path filters on their pull request and main-push
triggers.

The Rust admission surface deliberately avoids running the same full workspace
test suite twice. `Run targeted Rust baseline` owns formatting, all-target and
all-feature Clippy compilation, and maintained-template baseline tests.
`Rust Cobertura coverage` owns execution of the root workspace
`--workspace --all-targets --all-features` test surface while generating the
required coverage evidence. `scripts/check_rust_baseline_workflow.py` binds
those two workflow contracts so the optimization cannot silently become a loss
of workspace test coverage.

## Public Wording

Public change descriptions should use repository-neutral wording. Do not include
secrets, private hostnames, local user paths, customer or stakeholder names,
internal-only project labels, sensitive reproduction steps, or details of local
publication policy patterns.

Security-sensitive pull requests should describe the maintained invariant and
the validation performed without publishing a step-by-step misuse path.

## Break-Glass Security Remediation

Direct pushes to `main` are reserved for urgent, validated high-impact security
remediation where public pre-merge discussion would increase exposure or delay
would leave the default branch at avoidable risk.

A break-glass landing must:

1. fetch current `main` and confirm the fix is based on that head;
2. stage only the intended files;
3. run cheap local hygiene checks such as `git diff --check`;
4. use bland public commit wording;
5. push explicitly to the canonical public repository;
6. verify the remote `main` SHA after push;
7. watch required hosted checks to terminal success;
8. record a private or sanitized remediation receipt.

The receipt should include the commit SHA, remote verification, hosted run URLs,
validation outcome, and any advisory or disclosure follow-up decision. It should
not include secrets, private infrastructure details, or sensitive reproduction
steps.
