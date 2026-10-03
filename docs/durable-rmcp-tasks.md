# Durable RMCP Tasks boundary

This note specifies the persistence boundary required before the Toolkit can
offer restart-safe RMCP Tasks. It is a design and upstream handoff proposal;
the repository does not currently provide durable task storage or recovery.
RMCP must remain the protocol state-machine owner.

## Current boundary

The admitted workspace pins `rmcp = 3.5.0` in `Cargo.lock` (registry
checksum `fae7019994ae0fe4ada40b732f798f3ff26f0f04facb1477f1bf37eb4f18a2d3`).
The exact 3.5.0 artifact audit recorded for this issue identifies
`TaskManager` operations for construction, spawn, get, update, cancellation,
running-count observation, and shutdown. Its task entries contain
`DetailedTask` plus in-process execution and coordination state. The manager
uses process-local instants for expiry/terminal retention and keeps futures,
cancellation tokens, and pending input response channels in memory. It exposes
no import/restore or durable commit/store seam. The pinned API therefore does
not let a Toolkit wrapper restore protocol-correct Tasks without duplicating
RMCP internals.

The durable record and the live execution are different things:

| State | Persist across restart | Recovery behavior |
| --- | --- | --- |
| Task ID, complete `DetailedTask` snapshot, SDK status/result/error and persisted generation | Yes, after a successful commit | RMCP restores terminal records only while their retention deadline remains valid. A nonterminal task past its task-expiry deadline follows the RMCP TTL-failure transition; an unexpired nonterminal task is reconciled as interrupted. |
| Ownership envelope required by the configured authorization boundary | Yes, atomically with the task record | Missing, unknown, or mismatched ownership fails closed; no global listing or cross-principal fallback. |
| Absolute task-expiry and terminal-retention deadlines | Yes | Compare with wall-clock UTC on load and before reads/transitions. An active task past its task deadline follows RMCP's TTL-failure transition and receives a persisted terminal-retention deadline; only records whose terminal-retention deadline has passed are evicted. Timers may wake cleanup but are not the source of truth. |
| Rust future, task executor handle, cooperative cancellation token | No | Never deserialize or recreate them. A recovered nonterminal task past its task-expiry deadline follows RMCP's TTL-failure transition; otherwise RMCP reconciles it as interrupted. It is never rerun automatically. |
| Pending input response sender/channel | No | A restored `input_required` task cannot accept a response through its lost channel. If its task-expiry deadline passed, RMCP applies the TTL-failure transition; otherwise RMCP reconciles it as interrupted. |
| Cancellation intent | Persist the intent before signalling the in-memory token | Intent is not proof of cancellation or task completion. Recovery does not report `cancelled` solely from the intent. |

Principal identity is not inferred from a task ID. The store record must include
the same opaque ownership binding used by the surrounding authority layer,
without logging or normalizing principal values. The SDK hook must make the
ownership envelope part of the same atomic commit as task state. If the SDK
cannot carry this binding without changing its authority boundary, that is an
upstream design decision; Toolkit must not paper over it with a process-local
map that disappears on restart.

## Proposed smallest upstream hook

Add persistence at the RMCP `TaskManager` boundary, where RMCP can observe every
protocol transition and can restore its private task representation. The
following names and signatures are conceptual, not an API commitment:

```rust
trait TaskStore {
    async fn load(&self, now: SystemTime) -> Result<Vec<StoredTask>, StoreError>;
    async fn commit(
        &self,
        task_id: TaskId,
        expected_generation: Option<u64>,
        record: StoredTask,
    ) -> Result<u64, StoreError>;
    async fn evict(
        &self,
        task_id: TaskId,
        expected_generation: u64,
        reason: EvictionReason,
    ) -> Result<(), StoreError>;
}
```

`StoredTask` needs the complete SDK-owned serializable task snapshot, ownership
envelope, monotonically increasing persisted generation, creation time,
absolute task expiry, and absolute terminal retention deadline. A store commit
must atomically compare the expected generation and replace the whole record;
the resulting generation is returned only after commit. The store must not be
allowed to reinterpret MCP statuses or produce task results.

The stored fields must preserve the exact TTL and retention semantics of the
configured RMCP version. The existing [task authority](task-authority.md)
summary's five-minute default and one further observation window describe RMCP
3.4.1; they are not a hard-coded duration for the current 3.5.0 pin. The SDK
hook implementation must confirm the version-specific mapping before setting
deadlines, while keeping the absolute task-expiry and terminal-retention
deadlines distinct.

RMCP should expose a builder/configuration hook to install the store and an
explicit restore result before serving requests. Its internal transition path
must enforce this order:

1. Construct the next SDK-owned record and its ownership/deadline metadata.
2. Commit it with generation compare-and-swap.
3. Only after commit succeeds, publish the transition through `TaskManager` or
   expose it to readers.

The hook must cover create/spawn publication, input-request registration,
`tasks/update`, cancellation intent, terminal completion, TTL failure, and
expiry/retention eviction. Failure to commit must not silently publish the
transition. In particular, a terminal result must not become observable as
durable until the terminal record is committed. RMCP must document the
operation's failure behavior when execution has finished but that commit
fails; replaying the operation is not an acceptable implicit retry.

Storage I/O must not run under the manager-wide task map mutex. RMCP can
serialize writes per task or use a dedicated transition coordinator, but the
generation check and publication order must remain atomic from readers'
perspective. Concurrent updates/cancellation/completion must have a defined
winner or conflict result. The hook must not add a second Toolkit-owned
protocol state machine.

## Restart and crash contract

Restoration first loads records and validates their shape and ownership
metadata, then compares persisted absolute deadlines with wall-clock time.
RMCP applies its ordinary TTL-failure transition to an active task whose task
deadline passed during downtime. It commits that terminal failure and its
absolute terminal-retention deadline before serving reads. A non-expired
`working` or `input_required` task is instead failed as interrupted because its
execution future or input channel cannot be restored. Both are SDK-owned
terminal transitions; neither invents an operation result or reports
cancellation as successful. If reconciliation cannot be committed, manager
restore fails closed. Already-terminal records are restored exactly only until
their persisted terminal-retention deadline; once that deadline passes,
RMCP durably evicts them. The retention deadline is fixed when the terminal
transition commits and must not slide forward on another process restart.
An application resumption callback is a separate contract requiring explicit
idempotency and ownership semantics; persistence does not imply or trigger
automatic work replay.

| Crash point | Durable state after restart | Required behavior |
| --- | --- | --- |
| Before create commit | No published task | No task is discoverable. |
| After create commit, before future spawn/publication | `working` record and owner exist | If the task deadline passed, persist TTL failure; otherwise reconcile as interrupted. Never spawn twice on restore. |
| While operation future is running | Last committed nonterminal snapshot | If the task deadline passed, persist TTL failure; otherwise reconcile as interrupted. No future or cancellation token is fabricated. |
| Input request committed, before response | `input_required` snapshot and owner exist; response channel is gone | If the task deadline passed, persist TTL failure; otherwise reconcile as interrupted unless an explicit SDK recovery hook proves continuation. |
| Cancellation intent committed, before token signal | Intent exists, outcome does not | Do not report cancellation as complete. Apply TTL failure if its deadline passed; otherwise reconcile interruption or expose the SDK-defined pending state. |
| Token signalled, before cancellation outcome commit | Intent exists; actual future disposition may be unknown | Do not infer terminal cancellation from intent. Apply TTL failure if its deadline passed; otherwise reconcile according to SDK interruption policy. |
| Update commit fails | Previous generation remains authoritative | Do not publish the uncommitted update; return/record the documented persistence error. |
| Future completes, before terminal commit | Previous nonterminal generation remains authoritative | Do not expose an uncommitted result; retain enough live state to retry commit without re-executing the operation, or close/fail the manager explicitly. |
| Terminal commit succeeds, before response | Terminal snapshot and generation exist | Restore and return that exact terminal snapshot if still within retention. |
| Active task's TTL deadline passes during downtime | Active task and owner remain durable; no process-local future exists | Persist RMCP's TTL-failure terminal state and its retention deadline before serving reads; do not treat task expiry as immediate eviction. |
| Terminal-retention deadline passes during downtime | Terminal record is past its absolute retention deadline | Durably evict before reporting absence; a restarted timer must not extend its lifetime. |
| Interrupted task is reconciled, then the process restarts again | Failure snapshot and fixed terminal-retention deadline are durable | Return that exact failure until the stored deadline, then evict; do not reset the deadline at restart. |
| Store returns a record with absent/unknown owner or inconsistent generation | Provenance is incomplete | Fail closed; do not make the task enumerable or readable under another owner. |

Cancellation intent and cancellation outcome are separate durable facts. A
persisted generation is a compare-and-swap version for the current record,
not an event log and not proof that every intermediate transition was
observed. Toolkit's local observation generation remains an observation
snapshot counter; it must not be represented as this persisted generation.

## Required conformance once the SDK hook exists

Executable qualification must use the actual RMCP manager and configured
store, terminate the process, create a fresh manager, and exercise the
protocol-facing read path. The suite must cover:

- terminal success, failure, and cancellation records restored exactly until
  their absolute retention deadline;
- a running task whose TTL passes during downtime is durably recorded as the
  RMCP TTL failure and retained until its absolute terminal deadline;
- terminal records whose retention deadline passes during downtime are
  evicted, while repeated restarts do not extend a still-retained deadline;
- non-expired `working` and `input_required` records reconciled as SDK-defined
  interruption failures, with no resumed future, fabricated result, or
  duplicate spawn;
- expired `working` and `input_required` records take the TTL-failure path
  instead of interruption, with their terminal retention deadline committed;
- cancellation intent before and after token signalling remaining distinct
  from an authoritative cancellation outcome;
- task ownership restored with the record, cross-principal reads/listing
  concealed, and unknown/missing provenance rejected;
- competing generations and updates resolved through conditional atomic
  commits;
- injected crashes around every transition commit/publication boundary,
  including completion before terminal commit and expiry before eviction;
- store failure semantics that keep uncommitted transitions unobservable and
  never retry user work implicitly.

Until that SDK hook exists, Toolkit can qualify only its in-process authority
and observation behavior. A documentation matrix or mock store is not restart
conformance and does not complete issue #191.

## Upstream handoff and scope boundary

The concrete contribution requested from RMCP maintainers is: (1) an SDK-owned
serializable task record plus ownership envelope and persisted generation;
(2) a pluggable store hook for atomic conditional commit and restore/eviction;
(3) manager-owned interruption reconciliation for recovered non-expired
`working` and `input_required` records, with TTL failure taking precedence
after task expiry; and (4) executable crash/restart conformance against
the public protocol-facing manager API. The RMCP contribution must decide its
public trait/error/API shape, serialization compatibility policy, failure
semantics after operation completion when persistence fails, wall-clock/time
source policy, and whether storage I/O coordination belongs in the manager or
a separate per-task transition coordinator.

This proposal is prepared for review and handoff only. No RMCP issue, pull
request, branch, or source file is changed by this repository slice. The
upstream repository selector, receiving maintainer/owner, and authority to
publish remain unassigned; `/root` retains this decision and must establish
scope-specific authority before any external mutation. Repository issue #191
remains open until the SDK seam exists and executable restart conformance
passes on an exact candidate.
