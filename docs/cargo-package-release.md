# Cargo Package Release

`mcp-toolkit-rs` is the independent, open-source Sedna Labs MCP Toolkit for
Rust. It is published and maintained by Sedna Labs, is not affiliated with
other Sedna-branded products, and is not the official Model Context Protocol
implementation. Its crates are not published to crates.io yet.
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
- `mcp-toolkit-observability`
- `mcp-toolkit-policy-core`
- `mcp-toolkit-http`
- `mcp-toolkit-scratchpad`
- `mcp-toolkit-testing`
- `mcp-toolkit-policy-conformance`
- `mcp-toolkit-auth`
- `mcp-toolkit-server`

Hold back the umbrella, policy-runtime, policy-ffi,
policy-kernel-adapters, process, docs, Gemini, Postgres, and other
service-specific or convenience crates until their public API, dependency
graph, and adopting-service evidence are ready for the same semver promise.

## Readiness Checklist

Before a crate can move from Git-only consumption to crates.io publication:

1. Remove `publish = false` only for crates in the approved package set.
2. Confirm each package has the complete publication metadata contract:
   `description`, `license`, `repository`, `documentation`, `readme`,
   `rust-version`, `keywords`, and `categories`.
3. Confirm internal dependencies include both `version` and `path`, so local
   workspace development remains ergonomic and registry publication resolves by
   version.
4. Publish or dry-run the dependency graph in order, starting with leaf crates
   that have no unpublished toolkit dependencies.
5. Run the required hosted checks on the exact commit being released.
6. Record the validation run, package names, versions, and consumer migration
   notes in the release work item or PR.

Routine pull requests keep publication disabled, but a reviewed first-wave
release candidate may enable exactly the nine approved package manifests. The
`cargo-package-readiness` workflow runs
`scripts/cargo_package_readiness.py`, which checks required manifest metadata,
rejects a partial first-wave enablement, keeps every non-first-wave package
publish-disabled, verifies internal toolkit dependencies have both `version`
and `path`, runs `cargo package --list` for the first-wave crates, runs full
`cargo package` verification for first-wave crates without unpublished toolkit
dependencies, and explicitly marks registry package verification as deferred
for crates whose verification requires predecessor toolkit crates to be
published or available in an approved staging registry first. The workflow
never invokes `cargo publish`, even when the candidate manifests are enabled.

## Package-readiness archive and hosted-proof closure

The package-readiness result is an archive and reproducibility receipt, not
publication authority. Routine candidates keep `publish = false` throughout;
the approved release candidate enables only the nine first-wave manifests while
the publication path and release-owner approval remain separate gates.
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

All first-wave manifests use `rust-version = "1.88"`, matching the workspace
compatibility floor and the hosted stable-toolchain package and baseline lanes.
No homepage is declared: the repository URL is already the canonical project
link, and an unresolved `sednalabs.io` homepage is deliberately rejected by the
readiness verifier.

The first public package versions are currently `0.1.0`. Treat all pre-1.0
versions as semver-minor-compatible at the crate level but not as a 1.0 API
stability promise. Any publication approval should include a changelog entry
for the exact crate set and should call out consumer-facing breaking changes
before increasing any published version.

The approved first-wave order is:

1. `mcp-toolkit-core`, `mcp-toolkit-observability`,
   `mcp-toolkit-policy-core`
2. `mcp-toolkit-http`
3. `mcp-toolkit-scratchpad`, `mcp-toolkit-testing`,
   `mcp-toolkit-policy-conformance`
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

## First-release GitHub bootstrap workflow

The reviewed first-release path is
`.github/workflows/crates-io-first-release.yml`. It is `workflow_dispatch`
only, checks out protected `main` (never a pull-request or user-supplied ref),
and requires all of the following inputs:

1. `expected_main_sha`: the exact lowercase 40-hex SHA currently at protected
   `main`;
2. `confirmation`: `PUBLISH_MCP_TOOLKIT_V0_1_0`; and
3. `release_tag`: `v0.1.0`.

The preflight and publish jobs both read back `main` and fail closed if it has
moved. The publish job references the dedicated GitHub environment named
`crates-io` and the only required environment-scoped secret is
`CARGO_REGISTRY_TOKEN`. Do not create a repository-level copy of that secret,
and do not put the value in a workflow input, command-line argument, artifact,
or log. Configure environment reviewers and branch restrictions before the
first dispatch; the workflow itself does not create or modify the environment
or secret.

The workflow packages and publishes only the nine approved crates, in the
checked-in dependency order. Immediately before each publish it queries both
the crates.io version API and sparse index. A missing crate name and version is
the only state that permits a publish. If the version already exists, the
workflow downloads it and requires all of these to match the local package
made from the expected SHA: the API checksum, sparse-index checksum, download
SHA-256, `.cargo_vcs_info.json` source SHA, and normalized packaged
`Cargo.toml` digest. It also requires a non-empty authenticated owners response
and an explicitly unyanked index entry. Any occupied name, checksum/source
mismatch, owner/API failure, or indeterminate state stops without a retry,
publish, or yank.

After a new publish, the workflow waits for the API version, sparse-index
entry, downloadable artifact, checksum agreement, source identity, owner
evidence, and version state before advancing to the next package. This makes a
rerun safe for a partial first release: already accepted versions are consumed
only when the exact artifact identity is proven; a different artifact is a
hard stop.

Once all nine registry identities are accepted, the workflow records and
attests an immutable provenance receipt containing the accepted package set,
checksums, source SHA, and tag status. It never creates a Git tag or GitHub
release itself. The current candidate changes workflow files, and GitHub's
release API documents that the default Actions `GITHUB_TOKEN` cannot create a
release for such a commit without workflow-write authorization. A separately
authorized maintainer must therefore create `v0.1.0` after the acceptance
receipt, then verify that the peeled tag resolves to the exact accepted source
SHA before creating or publishing release notes. The provenance attestation
does not claim that a tag or release exists.

This bootstrap token path is first-release-only. Immediately after the nine
crates and provenance receipt are accepted, configure crates.io trusted
publishing for all nine packages, review and land the replacement workflow,
and read back the exact publisher bindings. Only after that readback should
the bootstrap token path be removed and the `CARGO_REGISTRY_TOKEN` secret
deleted. The transition is a separate authority boundary; a successful
bootstrap run does not authorize its own teardown or trusted-publisher setup.

The workflow follows the Cargo registry contracts for package creation,
publishing, registry API authentication, sparse-index checksums, and owner
lookups described in the [Cargo publish command](https://doc.rust-lang.org/cargo/commands/cargo-publish.html),
[Cargo publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html),
[Cargo registry web API](https://doc.rust-lang.org/cargo/reference/registry-web-api.html),
and [registry index](https://doc.rust-lang.org/cargo/reference/registry-index.html).
Its dispatch, minimal permissions, environment, and secret behavior follows
the [GitHub Actions workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax),
[deployment-environment](https://docs.github.com/en/actions/concepts/workflows-and-actions/deployment-environments),
and [Actions secrets](https://docs.github.com/en/actions/concepts/security/secrets)
contracts.

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
