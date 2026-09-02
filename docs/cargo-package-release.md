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

The approved 0.1.0 candidate contains exactly these nine crates:

- `mcp-toolkit-core`
- `mcp-toolkit-testing`
- `mcp-toolkit-observability`
- `mcp-toolkit-auth`
- `mcp-toolkit-http`
- `mcp-toolkit-policy-core`
- `mcp-toolkit-policy-conformance`
- `mcp-toolkit-scratchpad`
- `mcp-toolkit-server`

Hold back the umbrella, policy-runtime, policy-ffi,
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

## Publish-disabled archive and hosted-proof closure

The release candidate remains explicitly `publish = false` for all workspace
members, including the nine-crate first-wave set. A package-readiness result is
therefore an archive and reproducibility receipt, not publication authority.
For each of the nine approved crates, retain the exact candidate commit and
tree, the resolved `Cargo.lock`, the `cargo package --list` file inventory, and
the package verification result (or the recorded predecessor-availability
deferral). The receipt must identify the crate name and version and must not
claim that a registry artifact exists.

The native stdio workflows provide a separate, hosted-only proof archive for
the checked-in public template. They build the five declared target archives,
bind each archive to the exact candidate, manifest and lockfile digests, and
compare the canonical tool inventory and schema before generating the trusted
authorization receipt. These workflows use the pinned Rust 1.88.0 toolchain
and remain publish-disabled: they do not create tags, invoke `cargo publish`,
or change a registry, environment, secret, or release configuration. A green
native archive proof cannot substitute for package-readiness evidence for any
of the nine crates, and package-readiness evidence cannot claim native runtime
or attestation coverage.

Close the candidate only when both evidence sets are available on the same
exact SHA: the nine-package readiness/archive receipt and every applicable
native hosted proof/authorization receipt. If either set is incomplete, retain
the candidate as release-preparation work and record the precise missing
artifact or deferred predecessor rather than treating the candidate as
publishable.

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

The approved first-wave order is:

1. `mcp-toolkit-core`, `mcp-toolkit-observability`,
   `mcp-toolkit-policy-core`
2. `mcp-toolkit-http`
3. `mcp-toolkit-testing`, `mcp-toolkit-policy-conformance`,
   `mcp-toolkit-scratchpad`
4. `mcp-toolkit-auth`
5. `mcp-toolkit-server`

`mcp-toolkit-testing` currently depends on `mcp-toolkit-core` and
`mcp-toolkit-http`; `mcp-toolkit-policy-conformance` depends on
`mcp-toolkit-policy-core`; and `mcp-toolkit-auth` uses `mcp-toolkit-testing` as
a dev-dependency for contract tests, while `mcp-toolkit-server` composes the
HTTP and auth crates. Adjust the order only through a new approved release
candidate and refreshed readiness receipt.

Do not include server-generation or scaffold tooling in the required first Rust
release path until that product shape and name are explicitly approved.

## First manual publication procedure

Routine pull requests and the package-readiness workflow never publish. After
the release owner approves the exact commit and hosted run, use a clean
checkout of that commit and the following order:

1. Record the repository, commit SHA, nine package names, versions, and the
   successful hosted readiness run.
2. Recheck every registry name immediately before publication with
   `cargo search <name>`; an occupied or changed name stops the release.
3. Run `cargo package --locked --package <name>` for each package in the
   approved order.
4. Run `cargo publish --locked --dry-run --package <name>` for each package,
   resolving all failures before continuing.
5. Publish one package at a time with `cargo publish --locked --package <name>`.
   Wait for each version to appear in the registry index before publishing a
   dependent package. Never use `--all` or publish the workspace umbrella.
6. Run consumer smoke checks against the published versions and record
   lockfile changes and the validation run.

If a publication is defective, stop the train and preserve the registry
record. With release-owner confirmation, yank only the affected version using
`cargo yank --vers 0.1.0 --package <name>`. Yanking blocks new resolution but
does not erase existing downloads. Consumers move to a corrected version, or
restore their previously recorded lockfile and toolkit commit. Published
versions must never be overwritten or silently replaced under another name.

## Trusted publishing for later versions

After 0.1.0, the preferred path is a dedicated protected workflow at
`.github/workflows/crates-oidc-publish.yml`, activated only from a reviewed
release tag and explicit release-owner dispatch. It should verify the exact
tag commit and ancestry, use `permissions: { contents: read, id-token: write }`
with a protected `crates-io` environment, publish only an enumerated package
matrix in dependency order with `--locked`, and reject pull-request-controlled
refs or package names. Use crates.io trusted publishing (OIDC), never a stored
registry token. Emit an immutable run summary with tag, commit,
package/version set, and per-package result, followed by consumer readback.

This later-version path is not part of routine readiness and does not
authorize publication of this candidate. Its first use requires independent
review of the workflow and exact protected-environment/trusted-publisher
configuration readback.

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
