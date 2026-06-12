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

The release owner must record:

1. the crate set included in the release;
2. the semantic version for each crate;
3. whether publication is manual or performed by an approved release workflow;
4. the exact commit being published;
5. the hosted validation run URL for that commit;
6. the rollback plan for consumers.

## First Package Set

The first package set should be as small as the adopting services need. Start
with the stable helper crates already used by downstream MCP services:

- `mcp-toolkit-core`
- `mcp-toolkit-http`
- `mcp-toolkit-observability`
- `mcp-toolkit-postgres`
- `mcp-toolkit-testing`
- `mcp-toolkit-auth`

Add the umbrella, server, policy, process, docs, and Gemini crates only when
their public API and dependency graph are ready for the same semver promise.

## Readiness Checklist

Before a crate can move from Git-only consumption to crates.io publication:

1. Remove `publish = false` only for crates in the approved package set.
2. Confirm each package has `description`, `license`, `repository`, and
   `readme` metadata.
3. Confirm internal dependencies include both `version` and `path`, so local
   workspace development remains ergonomic and registry publication resolves by
   version.
4. Publish or dry-run the dependency graph in order, starting with leaf crates
   that have no unpublished toolkit dependencies.
5. Run the required hosted checks on the exact commit being released.
6. Record the validation run, package names, versions, and consumer migration
   notes in the release work item or PR.

The likely first-wave order is:

1. `mcp-toolkit-core`, `mcp-toolkit-http`, `mcp-toolkit-observability`,
   `mcp-toolkit-postgres`
2. `mcp-toolkit-testing`
3. `mcp-toolkit-auth`

`mcp-toolkit-testing` currently depends on `mcp-toolkit-core` and
`mcp-toolkit-http`, while `mcp-toolkit-auth` uses `mcp-toolkit-testing` as a
dev-dependency for contract tests. Adjust the order if the approved package set
or dependency graph changes.

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
