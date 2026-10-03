# DPoP Verifier Dependency Custody

## Decision

As of 2026-10-03, continue using the exact `dpop-verifier` 4.4.0 release under
a time-bounded exception to the repository's normal adoption/reputation gate.
Sedna Labs maintainers own this decision. Reassess no later than 2027-01-01 UTC,
or earlier if a newer release, advisory, relevant verifier defect, or package
provenance change appears. Do not silently extend the exception.

This decision supersedes the 2026-08-26 expiry recorded in issue #166. Issue
#166 remains open until this decision is documented in the repository and its
required hosted qualification and protected landing evidence are complete.

The 90-day interval is longer than the dependency-governance target of 30 days.
It gives maintainers one bounded upstream monitoring interval while retaining
automatic reassessment triggers. The exception accepts weak independent-use
evidence only; it does not waive source, license, advisory, compatibility,
review, or hosted qualification gates.

## Exact package and provenance

- Package: `dpop-verifier` 4.4.0, from crates.io; direct dependency in
  `mcp-toolkit-auth`.
- Crate archive SHA-256: `3ffe26542b84d85fc36fec8dfac45abf0d2f93c2d5ee9ffdebe3bb22a090d016`,
  matching the workspace lockfile.
- Published `.cargo_vcs_info.json` names upstream commit
  `aae68f7ef479fa96e8da65d7aab4115205f869ca`; that exact commit is the
  upstream default-branch head and declares version 4.4.0.
- The live crates.io sparse index lists 4.4.0 as the latest version and not
  yanked, published 2025-11-13.
- License: `MIT OR Apache-2.0`, both allowed by the repository policy.

The published source commit and immutable package checksum join successfully.
The GitHub repository has no v4.4.0 tag, but the package's VCS metadata
provides the exact source commit, so the missing tag alone is not a provenance
failure.

## Reassessment evidence

The upstream repository is public and not archived, but its latest source
change and release activity are from 2025-11-13. Its GitHub repository reports
two stars, one fork, and no open issues. The crate describes itself as a small
implementation made for the author's own needs. This is weak and stale
maintenance evidence and remains below the repository's adoption/reputation
threshold; no current download count was available from the crates.io API at
the time of review.

The current OSV query for crates.io package `dpop-verifier` 4.4.0 returned no
known vulnerability records. This does not replace the repository's hosted
`cargo audit`, advisory, source, license, and compatibility checks, which must
pass for the exact PR candidate before landing. The existing PR #163 result is
historical evidence only.

No generally useful verifier change was identified in this reassessment. The
Toolkit already sends the compact proof, access token, canonical method and
target, verifier policy, and replay store through the crate's atomic verifier
entrypoint. It compares the verified proof-key thumbprint with the validated
token's `cnf.jkt` before replay insertion; ordinary Bearer entrypoints reject
confirmation-bearing tokens. Existing authentication tests exercise signed
proofs, request and token binding, key mismatch, replay, freshness, nonce, and
replay-store failures. No verifier defect or reusable upstream hardening
proposal is evidenced, so no upstream change is proposed. Reopen this
assessment if a concrete defect or cross-consumer hardening need is reported.

## Alternatives and rollback

No drop-in maintained Rust verifier meeting this Toolkit boundary was
identified. The visible Rust options are embedded in broader OAuth/server
stacks or are specialized to a particular protocol/application; replacing the
current crate would expand scope without stronger maintenance, adoption, or
conformance evidence. Implementing proof verification locally would also move
cryptographic and protocol logic into Toolkit-owned code.

If a hard gate fails, a relevant defect appears, or no acceptable renewal is
approved by the reassessment date, disable DPoP support at the public Toolkit
boundary and continue rejecting confirmation-bearing tokens from Bearer-only
entrypoints until a separately reviewed replacement is available. Do not
silently fork or weaken verification.

## References

- [Issue #166](https://github.com/sednalabs/mcp-toolkit-rs/issues/166) records
  the original exception and reassessment lineage.
- [Issue #280](https://github.com/sednalabs/mcp-toolkit-rs/issues/280) owns the
  next scheduled reassessment and its early resume triggers.
- [Upstream repository](https://github.com/ukonhattu/dpop-verifier) and
  [published 4.4.0 documentation](https://docs.rs/crate/dpop-verifier/4.4.0)
  provide the upstream API and source context.
- [Crates.io sparse index](https://index.crates.io/dp/op/dpop-verifier) is the
  live registry version/yank record.
- [OSV query API](https://api.osv.dev/v1/query) was queried for the exact crate
  and version on 2026-10-03; hosted repository checks remain authoritative for
  landing.
- The Toolkit integration contract remains in
  `docs/design/dpop-atomic-authentication-boundary.md`.
