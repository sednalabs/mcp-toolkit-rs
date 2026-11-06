# Bounded process capture

Use `mcp_toolkit_process::capture::capture` for a single subprocess whose stdout
and stderr need strict retained-byte limits. It composes the existing
`supervisor::ProcessManager`; it does not introduce another process manager.

Supply a trusted absolute executable path through `CaptureCommand`, append
literal `OsString` arguments, and explicitly set required environment entries.
The child receives null stdin and no inherited environment. When migrating an
existing invocation, explicitly account for required home/configuration paths,
locale and tool configuration. Do not silently inherit credentials or broaden
the operation's authorization. This API does not parse JSON or interpret output.

Set independent stdout/stderr byte caps, a total cooperative timeout and an EOF
wait timeout after root exit. Both pipes are drained concurrently. Exact-cap
output is accepted if followed by EOF; observing one additional byte stops capture
with `OutputLimitExceeded`. Retained raw bytes never exceed their respective caps.
Child resource usage and allocator overhead are not bounded by those byte caps.

Inspect `CapturedOutput.end` before using output as a complete response:

- `Complete` means both EOFs and a reaped root, not a zero exit code.
- `Timeout`, `OutputLimitExceeded` and `ReadFailed` can leave partial output.
- `IncompleteCapture` means root exit was observed but pipe EOF was not observed
  before its separate deadline. A shorter total timeout still takes precedence.
- `SupervisorUnavailable` means root supervision could not be observed further.

`exit_status` is root-only evidence. On early return or future drop, pipe readers
are closed and the retained process handle requests cleanup from the manager.
Cleanup may remain pending; keep the Tokio runtime alive and use the manager's
status/shutdown interfaces when coordinating service shutdown. Capture does not
wait indefinitely for cleanup and never signals a cached PID/PGID itself.

The existing supervisor retires when the root is reaped, including a root that
exits during TERM grace. Descendants may survive and retain output pipes. Capture
bounds its own waiting, not descendant lifetime, and does not claim whole-tree
termination. A stronger containment policy belongs outside this helper.

The timeout cannot preempt synchronous OS spawn or registry locking. A zero or
unrepresentable timeout is rejected before spawn. Root EOF grace can be zero.

Command and output `Debug` omit executable, arguments, environment and output
bytes. Errors contain only fixed diagnostics with no nested OS message. Captured
bytes can still contain secrets; callers must avoid logging or transmitting them
without authorization. An explicitly invoked shell still interprets its script;
literal argument passing is not a sandbox or an executable allowlist.
