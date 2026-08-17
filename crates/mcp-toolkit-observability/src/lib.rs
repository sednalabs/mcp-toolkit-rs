//! # MCP Toolkit Observability
//!
//! Shared logging, tracing, and sanitization utilities.
//!
//! ## Ownership
//! This crate owns the standardized telemetry emission, field redaction, and
//! input sanitization infrastructure for MCP services.
//!
//! ## Non-ownership
//! This crate does not provide absolute security guarantees against data exfiltration.
//! It is not a substitute for proper secure secret handling in application business logic.
//!
//! ## Policy & Guarantees
//! * **Telemetry Sanitization**: Provides best-effort redaction and normalization
//!   to reduce the risk of sensitive data exposure in logs.
//! * **Structured Logging**: Facilitates standard log routing and format rendering.
//! * **Observability Adapters**: Exposes standardized interfaces for OTel tracing
//!   and metrics.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Adopting these sanitization helpers across all telemetry emitters.
//! * Ensuring sensitive data is handled securely at the source, treating this crate
//!   only as a defense-in-depth layer.
//!
//! ## References
//! * **DESIGN**: `docs/design/telemetry-standards.md`

pub mod logging;
pub mod metrics_facade;
pub mod otel_export;
pub mod redaction;
pub mod sanitize;
pub mod tool_call_diagnostic;
#[cfg(feature = "tracing-bridge")]
pub mod tracing_bridge;

pub use logging::{
    empty_context, render_logfmt, render_plain, LogFormat, LogFormatter, LogTargets, RoutingWriter,
};
pub use metrics_facade::{
    normalize_label_value, record_request, record_tool_call, OutcomeClass, TransportMode,
    METRIC_REQUESTS_TOTAL, METRIC_REQUEST_DURATION_SECONDS, METRIC_TOOL_CALLS_TOTAL,
    METRIC_TOOL_CALL_DURATION_SECONDS,
};
pub use otel_export::{
    init_otel_from_env, init_otel_runtime, load_otel_config_from_env, OTelConfig, OTelInitError,
    OTelRuntime, OtlpProtocol,
};
#[cfg(feature = "otel-export")]
pub use otel_export::{otel_tracing_layer, OpenTelemetryLayer};
pub use redaction::{
    redact_json_keys, redact_kv_pairs, redact_telemetry_text, truncate, DEFAULT_REDACT_KEYS,
    DEFAULT_REDACT_VALUE,
};
pub use sanitize::{
    sanitize_error_message, sanitize_exchange_error, sanitize_header_name, sanitize_header_value,
    sanitize_log_value, sanitize_log_value_opt, sanitize_log_value_with_limit, strip_control_chars,
    truncate_bytes,
};
pub use tool_call_diagnostic::{
    emit_tool_call_terminal, CatalogueFingerprint, DiagnosticField, DiagnosticToolName,
    DiagnosticValueError, DiagnosticValueErrorKind, RequestCorrelationId, SafePrincipalId,
    SafeSessionId, StableErrorClass, StableErrorCode, ToolCallTerminalDiagnostic,
    ToolCallTerminalOutcome,
};
#[cfg(feature = "tracing-bridge")]
pub use tracing_bridge::{
    emit_error, emit_event, make_span, safe_error, safe_secret, safe_text, EventContext, Level,
    SafeField,
};
