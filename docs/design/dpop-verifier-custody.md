# DPoP Verifier Dependency Custody

## Decision and expiry

As of 2026-10-25, Sedna Labs maintainers temporarily own the narrow verifier
compatibility port in `vendor/dpop-verifier`. The locally identified version
`4.4.1` is **not an upstream release**. This replaces the earlier decision to
consume the upstream 4.4.0 registry release unchanged; it does not replace DPoP
with toolkit-authored cryptography or weaken authentication.

Reassess and end or explicitly renew this custody **no later than 2026-11-24
00:00 UTC**, and immediately on an upstream compatible release, new advisory,
verification defect, or provenance change. Do not silently extend it. Sedna
Labs maintainers own patch review, security response, downstream compatibility,
and the return to a maintained upstream source. Issue #280 retains the
reassessment lineage; this earlier deadline supersedes its prior interval.

The approved exception is limited to local source custody and the existing weak
independent-adoption evidence. It does not waive advisory, license, review,
compatibility, hosted checks, or publication gates. `deny.toml` ignores remain
empty. No live deployment, release, or merge is implied by this decision.

## Exact source and permitted delta

- Upstream: `dpop-verifier` 4.4.0, commit
  `aae68f7ef479fa96e8da65d7aab4115205f869ca`.
- Original crates.io archive SHA-256:
  `3ffe26542b84d85fc36fec8dfac45abf0d2f93c2d5ee9ffdebe3bb22a090d016`.
- The initial P-256 compatibility port was previously recorded in
  `sednalabs/agent-ops` commit `971c76e145b0dbf86653c0808c0b2f314a81bbde`.
  The source was read back at `6ae1531336e79fcaf9008fdd334fa7523ba05cf4`;
  each imported file was verified against its Git blob identity before review.
- Retained license: `MIT OR Apache-2.0`, with both upstream license files.
- Authoritative local provenance and changes:
  [`vendor/dpop-verifier/UPSTREAM.md`](../../vendor/dpop-verifier/UPSTREAM.md).

The port moves P-256 key/SEC1 handling to `p256` 0.14, permitting patched
`crypto-bigint` and `ctutils` versions. Test-fixture repairs, real assertions,
formatting, warning-free compatibility annotations, and minimum required
optional adapter dependency features are reviewed maintenance changes. Proof
parsing, signature validation, thumbprints, method/URI normalization, HMAC nonce
policy, freshness and replay admission retain the upstream implementation.
Public helpers that expose P-256 types now use the 0.14 types; this is not a
claim of general upstream semver compatibility.

Do not expand this copy with new algorithms, custom JOSE/token parsing,
cryptographic primitives or policy changes without a separate design and review.
Do not maintain a second divergent copy for toolkit consumers.

## Why this bounded route

The upstream registry release still requires `p256` 0.13, which retains
`crypto-bigint` 0.5.5. RUSTSEC-2026-0387 only identifies versions >=0.7.6 as
patched. Compatible lockfile updates and default-off optional features cannot
remove that mandatory chain. The earlier adoption exception did not waive this
advisory gate.

The reviewed maintained alternatives did not provide a qualified drop-in
replacement for the existing confirmation-before-replay contract and configurable
context-bound HMAC nonce policies. A broader library or verifier API migration
therefore remains separate. Reusing the small, independently reviewed port
preserves the existing integration contract with less new security-sensitive code than a
replacement protocol implementation.

## Consumer and publication contract

`mcp-toolkit-auth` directly depends on the repository-relative verifier path,
with exact local version `=4.4.1`. This follows a Git dependency into downstream
consumers; a workspace-root `[patch]` would not. Import public verifier types
through `mcp_toolkit_auth::dpop_verifier`, or the toolkit facade's auth re-export.
Remove duplicate direct verifier dependencies when migrating. Test a fresh Git
consumer without a DPoP patch table or copied workspace lockfile.

The vendor remains `publish = false`. Its local version is not available from
crates.io. Auth and dependent crates are **not registry-release-ready** while
that unpublished dependency remains: `cargo package --list` is not proof that a
published package resolves. Return to a reviewed published upstream release,
or obtain separately reviewed publication authority and a valid distribution
plan before attempting a registry release. No new source allowlist or advisory
ignore is needed for the checked-in source.

## Required qualification

- Keep the verifier an explicit workspace member so all-feature tests, Clippy,
  coverage and advisory checks include the custodied source.
- Keep vendor source in the hosted source-cache fingerprint and preserve
  `publish = false` enforcement for vendored packages.
- Exercise both default and all-feature verifier tests, including genuinely
  distinct-key negative fixtures and asserted error variants.
- Retain toolkit signed-proof, token/key/method/URI, nonce, freshness, replay and
  store-failure tests; ordinary Bearer authentication must reject every `cnf`.
- Require full-lock `cargo audit --deny warnings` and all cargo-deny lanes to
  pass without exceptions, and all required hosted gates on the exact head.
- Verify a fresh downstream Git consumer uses exactly one canonical verifier
  from that toolkit revision, including HMAC nonce policy and typed replay/errors.

Tests establish the exercised contracts, not an independent security audit of
upstream. Existing protocol-normalization and backend-storage decisions remain
separate review subjects; do not claim they were newly hardened by the port.

## Review follow-up boundary

Fixed-format nonce, access-token-hash and public-key fields are length-checked
before base64 decoding, bounding those decoder allocations without changing
valid accepted inputs. Impossible `ath` lengths are classified as `AthMalformed`;
valid-length unequal digests remain `AthMismatch`. This is not an overall proof
or request-size limit.

The optional Actix URI helper's inherited proxy trust behavior needs separate
review: selecting the first comma-separated forwarded value would broaden
accepted inputs and choose a trusted hop. Moreover, its `connection_info()`
fallback can itself consult forwarded headers even when `trust_proxies` is
false. No toolkit production call uses this helper. Do not treat its flag as an
independently qualified proxy-trust boundary; deployments must constrain/sanitize
forwarded headers at their trusted ingress. This dependency repair does not
silently change that policy or claim live deployment validation.

## Exit and rollback

Prefer a reviewed upstream release that removes the affected dependency chain,
then remove the local copy and its temporary exception after toolkit and fresh
consumer compatibility checks. Preserve a narrow, reproducible upstreamable
diff; upstream publication or outreach is a separate authorized action.

Reverting to the vulnerable registry chain is not a security rollback. If the
custodied implementation fails a hard gate or its authority expires, stop
landing/releasing it and obtain an explicit remediation decision. Do not silently
disable DPoP, weaken nonce/replay policy, extend custody, or suppress findings.

## References

- [Upstream source](https://github.com/ukonhattu/dpop-verifier/tree/aae68f7ef479fa96e8da65d7aab4115205f869ca)
- [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html)
- [Issue #280](https://github.com/sednalabs/mcp-toolkit-rs/issues/280)
- [Atomic authentication boundary](dpop-atomic-authentication-boundary.md)
- [Dependency governance](../dependency-governance.md)
