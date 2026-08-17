# Observability Adapter Migration And Rollout Checklist

This runbook explains how to migrate Rust MCP servers onto the
`mcp-toolkit-observability` adapters.

It is written as a template. Replace placeholder server names, binary names,
and environment variables with values from your service.

## Goals

- Standardize tracing events through toolkit `tracing-bridge` helpers.
- Standardize baseline metrics names and labels through `metrics_facade`.
- Keep OpenTelemetry export optional and deployment-specific.
- Preserve sanitize/redaction invariants across all paths.

## Feature Defaults

Toolkit crate: `mcp-toolkit-observability`

- Default features:
  - sanitize/redaction helpers;
  - no metrics recorder or OpenTelemetry exporter required.
- Optional features:
  - `tracing-bridge`: adapter event/span primitives;
  - `metrics-facade`: baseline counters and histograms;
  - `otel-export`: OTLP wiring helpers.

Recommended server adoption order:

1. Enable `tracing-bridge` first.
2. Enable `metrics-facade` once tracing events are stable.
3. Enable `otel-export` only where distributed tracing is required.

## Before / After Pattern

Before:

```rust
let error = sanitize_error_message(&err.to_string(), 512);
tracing::warn!(error = %error, "event store replay failed");
```

After:

```rust
use mcp_toolkit_observability::{emit_error, EventContext, Level};

emit_error(
    Level::WARN,
    "mcp.event_store.replay.failed",
    &EventContext::new(),
    &err,
);
```

Before:

```rust
tracing::info!("tool started");
tracing::info!("tool finished");
```

After:

```rust
use std::time::Duration;
use mcp_toolkit_observability::{
    DiagnosticToolName, RequestCorrelationId, ToolCallTerminalDiagnostic,
};

ToolCallTerminalDiagnostic::success(
    RequestCorrelationId::new("request-123")?,
    DiagnosticToolName::new("example.search")?,
    Duration::from_millis(12),
)
.emit();
# Ok::<(), Box<dyn std::error::Error>>(())
```

The typed terminal record is the preferred tool-call completion boundary. It
emits one `mcp.tool_call.terminal` event with a fixed schema and consumes the
record. This guarantees at-most-once emission for that record instance; the
server lifecycle remains responsible for constructing one record per real tool
call. Failure records accept only validated program-static error code and class
identifiers. There is deliberately no API for arguments, request or response
bodies, tokens, claims, or raw errors.

Optional session and principal correlation values accept only fixed-size keyed
digest output produced by the caller's identity boundary. Use distinct domain
separators and a secret-keyed construction; an unkeyed hash of an enumerable
identifier is insufficient. Schema/catalogue revisions accept only a SHA-256
fingerprint. The toolkit does not accept raw session or principal identifiers.

## Server Migration Checklist

Use this checklist per server.

1. Add dependency features in the server `Cargo.toml`.
   - Minimum: `mcp-toolkit-observability` with `features = ["tracing-bridge"]`.
   - Optional metrics: add `metrics-facade`.
   - Optional OTel: add `otel-export`.
2. Introduce a local `observability.rs` helper module.
   - Centralize event names.
   - Centralize context construction.
   - Avoid ad hoc event naming at call sites.
3. Replace startup and error-path logs.
   - Startup listening event.
   - Auth failure path.
   - Transport/session replay failures.
4. Replace tool completion logs with one typed terminal record.
   - `mcp.tool_call.terminal` with `outcome=success`.
   - `mcp.tool_call.terminal` with `outcome=failure` and static error identifiers.
   - Keep start/progress events separate and low-volume only when operationally required.
   - Make the server lifecycle construct and consume one terminal record on
     every success, denial, failure, cancellation, and panic-safe exit path.
5. Add task lifecycle logs if the server uses tasks.
6. Add metrics facade calls if metrics are enabled.
7. Validate with toolkit tests, server smoke tests, and log redaction checks.

## Rollout Sequence

Use a staged rollout:

1. Pilot one low-risk reference service.
   - Validate event names and payload quality.
   - Validate no secret leakage in emitted logs.
2. Apply the same pattern to read-only services.
   - These are usually safer than mutation-capable services.
   - Reuse the pilot helper module shape where possible.
3. Apply to mutation-capable or data-sensitive services.
   - Add stronger redaction and failure-path checks.
   - Enable metrics only after labels are reviewed for bounded cardinality.

## Operator Verification Checklist

After deploying a migrated server, verify:

1. Startup and auth diagnostics.
   - Expect a structured startup event.
   - Trigger an auth failure and confirm no raw token or secret appears.
2. Tool lifecycle diagnostics.
   - Run at least one successful tool call and one failing tool call.
   - Confirm the server integration creates exactly one terminal record for
     each call; the toolkit enforces only at-most-once emission per record.
   - Confirm the terminal event has the same request correlation identifier as
     the enclosing request path.
   - Confirm session and principal fields contain opaque keyed digests rather
     than raw identifiers or unkeyed hashes.
3. Metrics health if `metrics-facade` is enabled.
   - Confirm metrics exist and labels are bounded.
4. Redaction guarantees.
   - Inject a benign test token, URL, or control characters.
   - Confirm logs and metrics labels do not contain raw sensitive values.
5. Optional OTel health if `otel-export` is enabled.
   - Confirm the endpoint is configured.
   - Confirm absence of an endpoint keeps the server operating normally.

## Troubleshooting

`No adapter events appear`

- Confirm the server enabled the `tracing-bridge` feature.
- Confirm the tracing subscriber filter includes the relevant levels.

`Metrics missing`

- Confirm the `metrics-facade` feature is enabled.
- Confirm a metrics recorder or exporter is installed by the runtime.

`OTel init error on startup`

- Confirm the `otel-export` feature is enabled where needed.
- Confirm `OTEL_EXPORTER_OTLP_ENDPOINT` is valid.
- For this build, use protocol `grpc`.

`Unexpected high-cardinality labels`

- Route dynamic values through `safe_text` or label normalizers.
- Remove user-input dimensions from per-event or per-metric labels.

`A terminal event needs additional payload`

- Do not add an arbitrary field map or raw error to the terminal contract.
- Map failures to a stable code and class.
- Put high-volume debugging data behind a separately reviewed diagnostic path.

`A dynamic error value needs to be recorded`

- Map it onto a documented static code and class at the service boundary.
- Do not leak dynamic error text, tenant identifiers, or dependency payloads
  through error identifiers.

## Rollback Strategy

1. Disable optional features in the server dependency declaration.
   - Drop `otel-export` first.
   - Drop `metrics-facade` next if needed.
   - Retain `tracing-bridge` unless a full rollback is required.
2. Revert server-local call-site migration commits if event semantics need a
   reset.
3. Re-run startup and auth-failure smoke checks after rollback.

## Validation Commands

Toolkit-level checks:

```bash
cargo test -p mcp-toolkit-observability --lib --tests
cargo test -p mcp-toolkit-observability --features tracing-bridge,metrics-facade,otel-export --lib --tests
```

Server-level template checks:

```bash
cargo test
EXAMPLE_MCP_AUTH_MODE=delegation \
EXAMPLE_MCP_AUTH_DELEGATION_SECRET=dev-secret \
EXAMPLE_MCP_AUTH_DELEGATION_ISSUER=example-issuer \
EXAMPLE_MCP_AUTH_DELEGATION_AUDIENCE=example-service \
cargo run --release --bin <your-mcp-server-binary>
```

## References

- `docs/observability-evolution.md`
- `crates/mcp-toolkit-observability/src/tracing_bridge.rs`
- `crates/mcp-toolkit-observability/src/metrics_facade.rs`
- `crates/mcp-toolkit-observability/src/otel_export.rs`
