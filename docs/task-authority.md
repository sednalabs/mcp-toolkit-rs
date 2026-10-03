# RMCP Tasks authority

`mcp-toolkit-tasks` adds production authority and observation substrate around
RMCP's native Tasks implementation. It does not implement a second MCP task
state machine.

RMCP remains authoritative for task status, TTL expiry, `input_required`,
cooperative cancellation, and terminal result/error projection. Toolkit binds
task IDs to opaque caller principals, conceals cross-principal IDs, assigns
local observation generations only after authoritative RMCP reads, contains
caller panics at the Toolkit/RMCP operation boundary, and removes local
bindings after RMCP evicts their task records.

## Principal identity

A `TaskPrincipal` is an opaque security identity. Toolkit does not lowercase,
trim, Unicode-normalize, or otherwise canonicalize it. Empty identifiers,
identifiers with surrounding Unicode whitespace, and identifiers longer than
256 Unicode scalar values are rejected. Callers should pass the stable identity
issued by their authentication/authorization authority, not a display name.

Ordinary `Debug` formatting is redacted. Code that explicitly calls `as_str()`
receives the exact identifier and must treat it as security-sensitive data.

## Runtime contract

RMCP 3.5.0 materializes task operations with `tokio::spawn`, so
`TaskAuthority::spawn_for_principal` requires an entered Tokio runtime. Toolkit
checks that requirement before entering RMCP and returns
`TaskAuthorityError::RuntimeUnavailable` instead of allowing Tokio to panic or
RMCP to partially materialize a task.

Task observation also uses Tokio timers for bounded settlement retries and TTL
readback. Spawn checks for the time driver before reserving or materializing a
task and returns `TaskAuthorityError::RuntimeTimerUnavailable` when it is
disabled. This keeps the shared observer available for later terminal and
expiry observations instead of allowing a detached timer panic to stop it.

`TaskAuthority::wait` uses Tokio timers for its timeout and bounded authoritative
readback fallback. Toolkit does not introduce a second executor or timer runtime
around RMCP.

## Failure boundary

RMCP 3.5.0 materializes a task before invoking the operation factory, and it
records terminal state only after the returned future finishes. Toolkit
therefore contains both synchronous factory panics and asynchronous operation
panics so an unlimited-retention task is not stranded indefinitely in
`working`. Caller-supplied future destruction is also panic-contained, including
destruction caused by cancellation, TTL abort, or shutdown.

Inputs whose user code RMCP would otherwise evaluate while holding its global
task-manager mutex are materialized before crossing that boundary. In
particular, status-message conversion and `tasks/update` response iteration do
not execute under the RMCP mutex through the Toolkit API.

## Retention and capacity

Construct `TaskAuthority` with an explicit `TaskAuthorityConfig`. It requires a
maximum retained-task count, a maximum number of concurrent authorized waits,
and an aggregate fallback-read budget per second. Toolkit chooses no
product-specific default. A failed task admission returns the stable
`TaskAuthorityError::CapacityReached` error.

Admission reserves a lease before calling RMCP and counts that reservation
through task publication. Leases are kept in a registry separate from task
bindings, so an outstanding wait cannot extend a task's capacity lease. A lease
is released only after RMCP reports the record absent or shutdown drains the
manager. `ttl_ms: None` consumes a lease for the manager lifetime. Completion,
cancellation intent, and TTL failure do not release capacity while RMCP retains
the record.

When TTL knowledge says a read may find expiry, the shared observer performs an
authoritative RMCP read. A running task's read is scheduled at its creation TTL;
after RMCP reports terminal state, the next read is scheduled at one TTL after
that observation. RMCP remains the only source of expiry and eviction truth.
The observer queue rotates fairly across principals and tasks, and one
caller-configured rolling read budget covers all task IDs. The SDK's internal
`get_task` still performs an O(N) sweep over retained records per read.

## Wait and observation scaling

`TaskAuthority::wait` authorizes the principal before registering a waiter.
Waiters for a task share its initial read and cached state changes. One observer
services hints, task settlement obligations, and TTL deadlines; individual
waiter cancellation releases only that waiter's admission slot. A dropped
operation future creates a settlement obligation that is retried until RMCP
shows terminal state, the record is absent, or the authority closes. The
observer never holds a strong `TaskAuthority` clone, so it cannot prevent
last-handle shutdown.

The public metrics snapshot reports aggregate active waiters, coalesced reads,
fallback reads, observation latency, and rejected waits. It does not label
metrics with principal or task IDs.

## Shutdown

`TaskAuthority::shutdown` is an irreversible authority transition shared by all
clones. It marks the Toolkit authority closed before asking RMCP to abort and
drain current tasks. Later get/update/cancel/wait/spawn operations fail with
`TaskAuthorityError::Closed`; Toolkit never relies on RMCP's otherwise reusable
`TaskManager::shutdown()` as the authority lifecycle itself.

Spawn publication and shutdown share a small lifecycle gate. Caller-controlled
operation-factory code runs outside that gate, so a factory may itself trigger
shutdown without deadlocking. If shutdown occurs after RMCP materializes the
record but before Toolkit publishes the principal binding, publication is
rejected and RMCP is drained again so the operation cannot escape the closed
authority.

Call `TaskAuthority::shutdown` for deterministic server teardown. Dropping the
last ordinary authority handle performs the same close-and-drain transition. A
task that deliberately retains a clone of its own authority is deliberately
retaining an authority handle as well; avoid self-retaining reference cycles,
especially with `ttl_ms: None`.

Durable restart/recovery semantics are intentionally separate and tracked in
#191. A Rust future cannot be truthfully reconstructed after process death.
