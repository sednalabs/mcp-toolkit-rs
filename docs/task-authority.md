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

RMCP 3.4.1 materializes task operations with `tokio::spawn`, so
`TaskAuthority::spawn_for_principal` requires an entered Tokio runtime. Toolkit
checks that requirement before entering RMCP and returns
`TaskAuthorityError::RuntimeUnavailable` instead of allowing Tokio to panic or
RMCP to partially materialize a task.

`TaskAuthority::wait` uses Tokio timers for its timeout and bounded authoritative
readback fallback. Custom Tokio runtimes that use this API must enable the time
driver. Toolkit does not introduce a second executor or timer runtime around
RMCP.

## Failure boundary

RMCP 3.4.1 materializes a task before invoking the operation factory, and it
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

Toolkit follows RMCP's retention truth. The documented RMCP 3.4.1 default is a
five-minute TTL with terminal state retained for one further TTL observation
window; this is historical version-specific behavior, not a hard-coded period
for the workspace's current RMCP 3.5.0 pin. `ttl_ms: None` is an explicit
unlimited-retention choice. Durable recovery must preserve the configured
version's task-expiry and terminal-retention semantics as separate absolute
deadlines; see [durable RMCP Tasks](durable-rmcp-tasks.md).

Local binding cleanup uses amortized round-robin liveness probing. It does not
scan every binding on every spawn because each RMCP `get_task` already performs
a global TTL sweep. Absolute retained-task admission and capacity are tracked in
#192.

## Wait and observation scaling

`TaskAuthority::wait` uses Toolkit/RMCP transition hints plus a bounded 250 ms
authoritative readback fallback. RMCP 3.4.1 performs a global TTL sweep during
every `get_task`, so many simultaneous long-poll waiters can amplify readback
work with the number of retained tasks.

Until the coalesced-observation/admission layer tracked in #193 exists, hosted
servers must bound caller-facing concurrent task waits at their request or
capacity boundary. Do not expose unbounded parallel long polls directly to
untrusted tenants. This is a throughput/admission concern rather than a reason
to invent a second task state machine.

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
[#191](https://github.com/sednalabs/mcp-toolkit-rs/issues/191). A Rust future
cannot be truthfully reconstructed after process death. The proposed RMCP
storage hook and crash contract are specified in
[durable RMCP Tasks](durable-rmcp-tasks.md); they are not implemented by the
current SDK pin.
