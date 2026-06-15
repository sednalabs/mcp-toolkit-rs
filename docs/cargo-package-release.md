# Cargo Package Release

`mcp-toolkit-rs` is public, but its crates are not published to crates.io yet.
Until the crate release process is approved, service repositories should consume
the public Git repository and commit the resulting `Cargo.lock` entries.

This gives consumers a reproducible resolved SHA without forcing every service
manifest to carry a hand-maintained `rev` pin. Use an explicit toolkit ref only
when a workflow checks out this repository outside Cargo and needs to prove a
specific cross-repository commit.

## Current Consumer Contract

Use public Git dependencies for service adoption:

```toml
[dependencies]
mcp-toolkit-core = { git = "https://github.com/sednalabs/mcp-toolkit-rs", branch = "main" }
mcp-toolkit-http = { git = "https://github.com/sednalabs/mcp-toolkit-rs", branch = "main", features = ["session"] }

[dev-dependencies]
mcp-toolkit-testing = { git = "https://github.com/sednalabs/mcp-toolkit-rs", branch = "main" }
```

Commit the consumer lockfile after Cargo resolves the dependency. The lockfile
records the exact toolkit commit used for builds, reviews, and rollbacks.

When a workflow clones or checks out `mcp-toolkit-rs` directly, pass the lockfile
SHA or another explicit reviewed ref into that workflow. That keeps hosted proof
stable without spreading manifest `rev` pins across every adopting service.

## Release Approval Gate

Do not publish crates from routine pull request validation. A crates.io release
requires an approved release owner and an approved publication path before any
`cargo publish` step runs.

The first public release build should be a GitHub draft prerelease, using a tag
such as `v0.1.0-alpha.1`, until hosted validation, downstream adoption smoke
tests, and the review gate are complete. Treat that alpha as a Git consumption
and operator artifact milestone, not a crates.io stability promise. Promote to a
normal `0.1.0` release only after the public API and package publication path
are intentionally approved.

The release owner must record:

1. the crate set included in the release;
2. the semantic version for each crate;
3. whether publication is manual or performed by an approved release workflow;
4. the exact commit being published;
5. the hosted validation run URL for that commit;
6. the rollback plan for consumers.

## Public Package Names

The Rust crates should keep the concise `mcp-toolkit-*` names for crates.io
unless the release owner records a different decision before publication.
These names are the public Rust package names, not a claim of vendor
endorsement or official MCP/OpenAI status. Repository metadata, README text,
release notes, and docs should make the Sedna Labs maintenance boundary clear.

Other ecosystems have different naming constraints:

- npm packages should use the scoped `@sednalabs/*` names because npm supports
  organization scopes and the unscoped `mcp-toolkit` name is already occupied.
- PyPI names should be decided per package when a Python companion is actually
  ready. In particular, do not assume `mcp-probe` or `mcp-forge`; those names
  are occupied by unrelated packages.

Recheck every registry name immediately before publication. Availability checks
in planning notes are evidence, not a reservation.

## First Rust Package Set

The first package set should be as small as the adopting services need. Start
with the Rust crates that define the reusable public surface and the proof
helpers needed by downstream MCP services:

- `mcp-toolkit-core`
- `mcp-toolkit-testing`
- `mcp-toolkit-observability`
- `mcp-toolkit-auth`
- `mcp-toolkit-http`
- `mcp-toolkit-policy-core`
- `mcp-toolkit-policy-conformance`

Hold back the umbrella, server, policy-runtime, policy-ffi,
policy-kernel-adapters, process, docs, Gemini, Postgres, and other
service-specific or convenience crates until their public API, dependency
graph, and adopting-service evidence are ready for the same semver promise.

## Readiness Checklist

Before a crate can move from Git-only consumption to crates.io publication:

1. Remove `publish = false` only for crates in the approved package set.
2. Confirm each package has `description`, `license`, `repository`,
   `documentation`, and `readme` metadata.
3. Confirm internal dependencies include both `version` and `path`, so local
   workspace development remains ergonomic and registry publication resolves by
   version.
4. Publish or dry-run the dependency graph in order, starting with leaf crates
   that have no unpublished toolkit dependencies.
5. Run the required hosted checks on the exact commit being released.
6. Record the validation run, package names, versions, and consumer migration
   notes in the release work item or PR.

Routine pull requests keep publication disabled, but they should still prove
the first-wave package shape. The `cargo-package-readiness` workflow runs
`scripts/cargo_package_readiness.py`, which checks required manifest metadata,
keeps the routine `publish = false` guard in place, verifies internal toolkit
dependencies have both `version` and `path`, runs `cargo package --list` for
the first-wave crates, runs full `cargo package` verification for first-wave
crates without unpublished toolkit dependencies, and explicitly marks registry
package verification as deferred for crates whose verification requires
predecessor toolkit crates to be published or available in an approved staging
registry first.

## Docs.rs and Version Notes

First-wave crates should set `documentation = "https://docs.rs/<crate-name>"`
and `[package.metadata.docs.rs] all-features = true` before publication. This
keeps crates.io and docs.rs aligned and makes optional feature documentation
visible unless a crate has a documented reason to build docs with a smaller
feature set.

The first public package versions are currently `0.1.0`. Treat all pre-1.0
versions as semver-minor-compatible at the crate level but not as a 1.0 API
stability promise. Any publication approval should include a changelog entry
for the exact crate set and should call out consumer-facing breaking changes
before increasing any published version.

The likely first-wave order is:

1. `mcp-toolkit-core`, `mcp-toolkit-observability`,
   `mcp-toolkit-policy-core`
2. `mcp-toolkit-http`
3. `mcp-toolkit-testing`, `mcp-toolkit-policy-conformance`
4. `mcp-toolkit-auth`

`mcp-toolkit-testing` currently depends on `mcp-toolkit-core` and
`mcp-toolkit-http`; `mcp-toolkit-policy-conformance` depends on
`mcp-toolkit-policy-core`; and `mcp-toolkit-auth` uses `mcp-toolkit-testing` as
a dev-dependency for contract tests. Adjust the order if the approved package
set or dependency graph changes.

Do not include server-generation or scaffold tooling in the required first Rust
release path until that product shape and name are explicitly approved.

## Consumer Migration After Publication

After the relevant crates are published, consumer repositories can move from Git
dependencies to semver package dependencies:

```toml
[dependencies]
mcp-toolkit-core = "0.1.0"
mcp-toolkit-http = { version = "0.1.0", features = ["session"] }

[dev-dependencies]
mcp-toolkit-testing = "0.1.0"
```

For each consumer migration:

1. update the manifests from Git dependencies to package versions;
2. refresh the consumer lockfile;
3. run the smallest relevant hosted validation on the consumer branch;
4. record the old Git SHA, new package versions, and validation run URL.

If publication is not approved yet, keep the public Git dependency and committed
lockfile in place. That is the intended pre-package contract, not a temporary
private dependency.
