# Dependency Governance

This document defines dependency selection and upgrade policy for this repository's Rust components.

## Goal

Keep Rust components secure, maintainable, and release-friendly by preferring well-maintained crates with clear operational risk signals.

## Scope

- Direct dependencies declared in Cargo manifests for the governed Rust workspaces
- Tooling dependencies used in release checks
- New crates and major/minor dependency upgrades
- Auth/token mechanics that validate, parse, introspect, exchange, or project
  credentials into canonical policy inputs

## Go/No-Go Criteria

All new direct crates and major upgrades must meet every hard gate below.

1. `security`: No unresolved RustSec advisory for selected version.
2. `license`: License is allowlisted by `deny.toml`.
3. `source`: Registry source is trusted (`crates.io` only by default).
4. `maintenance`: Evidence of active maintenance (recent releases, active issue/PR activity, non-abandoned project).
5. `adoption/reputation`: Evidence the crate is broadly used or maintained by a trusted team/project.
6. `fit`: Clear justification that existing dependencies or stdlib cannot solve the need with lower risk.

If any hard gate fails, the change is `no-go` unless an explicit, time-bounded exception is approved and documented.

## Required Evidence for Dependency Changes

Every dependency change (new crate, removed crate, major/minor upgrade) must include a policy note in the associated PR description.

Use this template:

```text
Dependency change note
- crate: <name> <old -> new>
- change type: <new | upgrade | removal>
- purpose: <why needed>
- alternatives considered: <stdlib/existing crates/other crates>
- maintenance evidence: <release recency + repo activity>
- adoption/reputation evidence: <reverse-deps/downloads/known users or maintainer org>
- security status: <cargo deny + cargo audit result>
- license status: <allowlisted license(s)>
- startup impact: <expected effect on cold start/steady state>
- rollback plan: <how to revert safely>
- exception (if any): <risk accepted, owner, expiry date>
```

## Enforcement

Prerequisites:

- Rust toolchain matching this workspace.
- `cargo-deny`.
- `cargo-audit`.
- `cargo-outdated`.

Install the current tool set with:

```bash
cargo install cargo-deny cargo-audit cargo-outdated
```

Run:

```bash
./scripts/dependency_governance_check.sh
```

The script enforces:

0. auth/token dependency posture via `scripts/auth_dependency_posture_check.py`
   (blocking)
1. `rmcp` SDK pin consistency: every direct `rmcp` dependency must use the
   same exact version pin, and any direct `rmcp-macros` dependency must match
   the runtime pin
2. advisory/license/source policy via `cargo-deny` (blocking)
3. RustSec check via `cargo-audit` (blocking)
4. stale-risk scan on direct dependencies via `cargo-outdated` (report-only by default)

Phase-2 tightening option:

```bash
STRICT_OUTDATED=1 ./scripts/dependency_governance_check.sh
```

When `STRICT_OUTDATED=1`, outdated direct dependencies become a failing gate.

Relevant environment variables:

- `STRICT_OUTDATED=1`: fail on outdated direct dependencies.
- `CARGO_HOME`: optional Cargo tool/cache location for CI.
- `RUSTFLAGS`: optional project-specific compiler flags.

## Exceptions

Exceptions are allowed only when there is a clear delivery blocker and no safer near-term option.

Exception requirements:

1. Documented in PR with rationale, owner, and explicit expiry date.
2. Bounded duration (target <= 30 days).
3. Follow-up issue/work item created before merge.

## Auth/token mechanics

Auth, OAuth/OIDC, JWT/JWS/JWK/JWKS, token introspection, sender constraints,
and token-exchange mechanics have an additional posture documented in
`docs/auth-token-dependency-posture.md`.

For those mechanics:

- prefer public, maintained crates for cryptography, JOSE/JWT, OAuth/OIDC,
  DPoP/mTLS, introspection, and token-exchange protocol handling;
- keep local code limited to reviewed glue such as header-shape parsing,
  canonicalization, bounded caching, typed configuration, error mapping, and
  policy-input projection;
- add or update the posture inventory when introducing a new auth/token
  mechanic;
- create a follow-up work item for any temporary bespoke token logic that
  cannot be removed before merge.

## RMCP SDK pinning

Prefer importing the server-authoring surface through the toolkit facade
(`mcp_toolkit::rmcp` or `mcp_toolkit_server::rmcp`) instead of declaring
service-local `rmcp` dependencies in generated servers.

When a workspace crate has a deliberate low-level SDK integration reason to
declare `rmcp` directly, it must use the same exact version pin as every other
direct `rmcp` dependency in the workspace. This keeps the toolkit from becoming
a mix of subtly different MCP model, transport, and macro contracts.

Prefer the `rmcp` crate with its `macros` feature over a separate direct
`rmcp-macros` dependency.

When a crate still declares `rmcp-macros` directly, pin it to the same exact
version as the `rmcp` runtime.

The repo-level checker enforces direct SDK pin alignment while allowing crates
that rely on `rmcp`'s built-in macro surface and carry no separate
`rmcp-macros` entry. Treat a new upstream `rmcp` major as an explicit alignment
review event, not as a reason for generated servers to bypass the facade.

## Generated repository portability

Generated service repositories should use toolkit Git dependencies from their
first public commit unless they intentionally live inside the toolkit workspace.
Local toolkit `path` dependencies are useful while developing templates, but
they make copied repositories depend on a maintainer's filesystem layout.

`mcp-toolkit release-preflight` parses the generated `Cargo.toml` and fails the
public-readiness gate when any `mcp-toolkit*` dependency or Cargo override still
points at a local path. It also rejects committed `.cargo/config.toml` path
overrides. Regenerate portable repositories with `--toolkit-git`, or replace
those dependencies with reviewed Git or crate-version sources before publishing,
installing, or cutting release artifacts.

## License exceptions for transitive infrastructure crates

`deny.toml` keeps the global license allowlist narrow. Transitive
infrastructure crates that are acceptable only in a specific dependency tree
must use scoped `[[licenses.exceptions]]` entries rather than broad global
license admission.

Current scoped exceptions:

- `webpki-root-certs` / `webpki-roots`: `CDLA-Permissive-2.0`, inherited from
  WebPKI root trust bundles used by TLS stacks.
- `tiny-keccak`: `CC0-1.0`, pulled transitively through hashing/data-frame
  dependencies used by DuckDB/Arrow-backed scratchpad support.
