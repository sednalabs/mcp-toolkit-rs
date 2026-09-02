# Toolkit Frontier validation lab

The Frontier is a **development-ready hosted diagnostic** for the public
`sednalabs/mcp-toolkit-rs` repository. It is a repeatable way to exercise
target-pinned planner, catalog, lane, and aggregation contracts on GitHub-hosted
runners. It does not publish a crate, release an artifact, commission a service,
or grant production authority. Results labelled `sandbox-dogfoodable` or
`development-ready` must not be described as production or commissioned proof.

## Candidate and profile contract

Every invocation resolves one exact candidate before planning. The workflow
checks out the immutable invocation SHA (`github.sha`); an optional requested
`candidate_sha` and `ref` must identify that same SHA, so a mutable branch or
tag cannot select executable validation code during a run:

* repository owner/name;
* ref/display identity (when supplied, it must equal the immutable SHA);
* 40-character commit SHA; and
* the candidate tree identity.

The planner carries those four values into every lane and into the aggregate.
An omitted, ambiguous, or changed identity is an unknown result and fails the
aggregate. Profiles are deliberately explicit:

* `targeted` runs the small named contract set;
* `frontier` runs the bounded cross-target and failure-class matrix; and
* `checkpoint` repeats identity and artifact-custody checks at a workflow
  boundary.

Each lane has a unique stable `lane_id`, one declared target, a finite stop
budget, and one artifact identity. A lane may fail slowly within its cap so one
stalled target does not prevent independent lanes from uploading their evidence.
The aggregate is fail-closed for blockers, unknowns, and no-op lanes. It ranks
independently actionable failures so a target or contract defect is not hidden by
an optional evidence improvement.

## Artifact custody and run attempts

Lane artifacts are uploaded even when the lane fails. Aggregation accepts an
artifact only when its repository, candidate ref/SHA/tree, lane ID, target,
workflow run ID, and `run_attempt` match the planned identity. A same-name
artifact from another run or another attempt is not interchangeable; name-only
lookup is an origin-confusion bug. The negative fixture in
`tests/validation_lab/artifact_origin_negative.json` keeps this seam explicit.

The aggregate also checks that every planned lane has a terminal outcome. Missing
or duplicate lane IDs, stale derived identities, and a result with no changed
or verified surface are not successful completion signals.

## Existing five-target release journey

The Frontier reuses the existing native artifact contract as a diagnostic input;
it does not replace or widen its authority. The established journey is:

1. **package** one archive per target with the exact candidate, source tree,
   manifest, lockfile, inventory, schema, SBOM, and checksums;
2. **verify** each archive, including its archive-root identity, PAX paths,
   payload name, metadata, runtime identity, and source bindings;
3. **compare** all five target reports for common source/input bindings and the
   canonical tool inventory/schema;
4. **authorize** only the verified, trusted-source set with a run-bound
   `workflow_run_id` and `workflow_run_attempt`; and
5. preserve the **root/PAX** checks so serialized archive paths cannot be
   replaced by a renamed or otherwise tampered root.

The five targets are `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-apple-darwin`, `aarch64-apple-darwin`, and
`x86_64-pc-windows-msvc`. This is an exact five-target diagnostic contract;
adding a target requires a separately reviewed planner, verifier, and workflow
change.

## Generated-workflow coupling

The generated Frontier workflow and its planner/catalog/aggregator inputs are a
coupled contract. The canonical generator or verifier must prove that the
workflow's lane IDs, profile names, target list, artifact names, and identity
fields are the same values tested by the fixtures. Adjacency, a comment, or an
assertion that happens to mention a target is not coupling evidence. If the
generator changes, regenerate the workflow and rerun the exact contract tests on
the same candidate before interpreting a hosted result.

`package` and `rmcp` remain catalog-only entries until their implementations are
materialized. Their presence in a planner or catalog is not an acceptance claim,
and it does not authorize publication or dependency promotion.

## Reading a result

Treat a green lane as evidence for that lane's exact candidate and profile only.
Treat the aggregate as the diagnostic answer for the exact run and attempt. A
blocker or unknown returns `repair-required` (or an explicit external blocker
with its clearing authority); it is never converted into a pass by a later
optional lane. Preserve the run URL, workflow run ID/attempt, head SHA, lane
artifact names, and aggregate output with any report so another operator can
rehydrate the same evidence without relying on a mutable branch name.
