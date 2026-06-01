# Observability Evolution: Toolkit And Ecosystem Composition

This note defines the architecture and acceptance criteria for evolving
`mcp-toolkit-observability` so it composes with widely adopted Rust
observability crates while preserving toolkit-owned safety guarantees.

## Rationale

MCP servers need consistent logs, spans, metrics, and redaction behavior.
Application teams should be able to use familiar Rust ecosystem crates without
reimplementing sensitive-value handling in every service.

## Scope

In scope:

- additive `mcp-toolkit-observability` APIs for tracing and metrics;
- optional OpenTelemetry export integration behind explicit features;
- migration guidance for Rust MCP servers.

Out of scope:

- rewriting existing auth or session subsystems;
- forcing one exporter or backend choice for all deployments;
- removing established sanitize/redaction helpers in this phase.

## Responsibilities

Toolkit-owned responsibilities:

- sanitize-by-default helpers for fields, messages, and errors;
- stable APIs for safe event/span context;
- safe label/value normalization for metrics;
- redaction policy invariants and conformance tests.

Ecosystem-owned responsibilities:

- `tracing`: event/span model and subscriber interoperability;
- `metrics`: metric emission API and instrument semantics;
- `opentelemetry`: backend export pipelines and propagation.

Principle: the toolkit provides safety and MCP conventions; ecosystem crates
provide transport/runtime instrumentation machinery.

## Feature-Flag Strategy

`mcp-toolkit-observability` uses additive feature flags:

- default features: existing sanitize/redaction/log formatting behavior;
- `tracing-bridge`: high-level tracing adapter API with safe field/context
  helpers;
- `metrics-facade`: typed metric facade and MCP baseline instruments;
- `otel-export`: optional OpenTelemetry bridge, not required for local or dev
  use.

Rules:

- no existing API removal in this phase;
- enabling extra features must not weaken sanitization defaults;
- disabling optional features must still compile and preserve existing behavior.

## Data Classification And Boundaries

Data classes for observability payloads:

- `Public`: safe to emit directly after control-character stripping;
- `Sensitive`: never emitted raw; replaced with a redacted marker;
- `Structured-Untrusted`: allowed only through sanitizer/redactor pipelines.

Boundary rules:

- dynamic user/tool inputs are `Structured-Untrusted`;
- error messages are sanitized and redacted before emission;
- secret-bearing fields such as tokens, secrets, authorization headers, and
  database URLs are masked;
- context identifiers are sanitized and length-bounded.

## Migration Expectations

Server migration pattern:

1. Keep existing `tracing` subscriber setup in place.
2. Replace ad hoc formatting/sanitization at call sites with toolkit adapter
   helpers.
3. Add baseline MCP events/metrics for request lifecycle and tool execution.
4. Validate output with conformance tests and smoke logs.

## Stability Policy

- Existing exports in `sanitize.rs` and `redaction.rs` remain supported.
- New adapter APIs are additive and feature-gated.
- Optional features must not change default behavior when disabled.

If an established helper becomes superseded, mark it deprecated only after at
least one full server migration cycle and documentation update.

## Acceptance Criteria

Architecture acceptance criteria:

- responsibilities are explicitly split between toolkit and ecosystem crates;
- feature flags and fallback behavior are defined;
- data classification boundaries are explicit and testable;
- migration path and stability stance are documented.

Implementation acceptance:

- tracing adapter emits only sanitized/redacted values;
- metrics facade enforces safe labels/values;
- OTel path is optional and does not block default startup;
- feature combinations compile and pass conformance tests.

## Test Matrix

1. Default-only:
   - existing sanitize/redaction tests pass;
   - existing server startup behavior is unchanged.
2. `tracing-bridge`:
   - event/span helpers compile and emit sanitized context;
   - secret and control-character misuse tests pass.
3. `metrics-facade`:
   - counter/gauge/histogram helpers compile;
   - label sanitization and cardinality guard tests pass.
4. `otel-export`:
   - compiles when enabled;
   - no runtime dependency is required when disabled.
5. Combined features:
   - conformance suite passes;
   - representative server integration tests pass.

## Explicit Non-Goals

- Building a custom tracing runtime.
- Replacing `tracing` or `metrics` APIs across all servers in one big-bang
  change.
- Shipping mandatory remote exporters in local development defaults.

## References

- `crates/mcp-toolkit-observability/src/redaction.rs`
- `crates/mcp-toolkit-observability/src/sanitize.rs`
- `crates/mcp-toolkit-observability/src/tracing_bridge.rs`
- `crates/mcp-toolkit-observability/src/metrics_facade.rs`
