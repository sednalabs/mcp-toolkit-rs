//! # Tracing Bridge
//!
//! Feature-gated adapter API for safe tracing events and spans.
//!
//! ## Ownership
//! This module owns the adapters and construction helpers for `tracing` spans and
//! events, ensuring consistent sanitization and field normalization across the toolkit.
//!
//! ## Non-ownership
//! This module does not guarantee sanitization or redact all possible secret
//! leaks. It relies on provided heuristic sanitization and best-effort field cleaning.
//!
//! ## Policy & Guarantees
//! * **Sanitized Emission**: Forces all traced field values through a normalization
//!   and sanitization pipeline before emission.
//! * **Field Normalization**: Normalizes trace keys to consistent, safe formats.
//! * **Risk Mitigation**: Integrates heuristic redaction to reduce the risk of
//!   credential leakage in trace payloads.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying only non-sensitive or explicitly sanitized payload data to tracing helpers.
//! * Accepting that tracing helpers perform best-effort, heuristic redaction, not
//!   comprehensive secure scrubbing.
//!
//! ## References
//! * `crate::sanitize`
//! * `crate::redaction`

use std::collections::BTreeMap;
use std::error::Error;

use serde_json::Value;
use tracing::{event, span, Span};

use crate::redaction::{redact_telemetry_text, DEFAULT_REDACT_VALUE};
use crate::sanitize::{sanitize_error_message, sanitize_log_value_with_limit};

const DEFAULT_FIELD_MAX_LEN: usize = 256;
const DEFAULT_CONTEXT_MAX_LEN: usize = 128;
const DEFAULT_ERROR_MAX_LEN: usize = 512;
const DEFAULT_KEY_MAX_LEN: usize = 64;

pub use tracing::Level;

/// Sanitized field payload for tracing events.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SafeField {
    pub key: &'static str,
    pub value: String,
}

impl SafeField {
    /// Create a sanitized textual field.
    pub fn text(key: &'static str, value: impl AsRef<str>) -> Self {
        Self {
            key,
            value: sanitize_value(value.as_ref(), DEFAULT_FIELD_MAX_LEN),
        }
    }

    /// Create an always-redacted secret field.
    pub fn secret(key: &'static str) -> Self {
        Self {
            key,
            value: DEFAULT_REDACT_VALUE.to_string(),
        }
    }

    /// Create a field from an error value, redacting secrets and bounding output.
    pub fn error(key: &'static str, err: &dyn Error, max_len: usize) -> Self {
        Self {
            key,
            value: sanitize_error_message(&err.to_string(), max_len),
        }
    }
}

/// Contextual identifiers associated with MCP telemetry events.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct EventContext<'a> {
    pub request_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub tool_name: Option<&'a str>,
    pub actor: Option<&'a str>,
}

impl<'a> EventContext<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_request_id(mut self, request_id: &'a str) -> Self {
        self.request_id = Some(request_id);
        self
    }

    pub fn with_session_id(mut self, session_id: &'a str) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn with_tool_name(mut self, tool_name: &'a str) -> Self {
        self.tool_name = Some(tool_name);
        self
    }

    pub fn with_actor(mut self, actor: &'a str) -> Self {
        self.actor = Some(actor);
        self
    }

    fn sanitize_opt(value: Option<&str>) -> Option<String> {
        let value = value?;
        let sanitized = sanitize_value(value, DEFAULT_CONTEXT_MAX_LEN);
        if sanitized.is_empty() {
            None
        } else {
            Some(sanitized)
        }
    }

    fn sanitized(&self) -> SanitizedContext {
        SanitizedContext {
            request_id: Self::sanitize_opt(self.request_id),
            session_id: Self::sanitize_opt(self.session_id),
            tool_name: Self::sanitize_opt(self.tool_name),
            actor: Self::sanitize_opt(self.actor),
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct SanitizedContext {
    request_id: Option<String>,
    session_id: Option<String>,
    tool_name: Option<String>,
    actor: Option<String>,
}

/// Emits a structured tracing event with sanitized payload.
///
/// # Security
/// * All event fields are sanitized and redacted before emission.
/// * Callers should treat this as a best-effort defense, not absolute sanitization.
pub fn emit_event(
    level: Level,
    event_name: &'static str,
    ctx: &EventContext<'_>,
    fields: &[SafeField],
) {
    let safe_ctx = ctx.sanitized();
    let fields_json = fields_to_json(fields);

    let request_id = safe_ctx.request_id.unwrap_or_default();
    let session_id = safe_ctx.session_id.unwrap_or_default();
    let tool_name = safe_ctx.tool_name.unwrap_or_default();
    let actor = safe_ctx.actor.unwrap_or_default();

    match level {
        Level::TRACE => event!(
            Level::TRACE,
            event = event_name,
            request_id = %request_id,
            session_id = %session_id,
            tool_name = %tool_name,
            actor = %actor,
            fields_json = %fields_json,
        ),
        Level::DEBUG => event!(
            Level::DEBUG,
            event = event_name,
            request_id = %request_id,
            session_id = %session_id,
            tool_name = %tool_name,
            actor = %actor,
            fields_json = %fields_json,
        ),
        Level::INFO => event!(
            Level::INFO,
            event = event_name,
            request_id = %request_id,
            session_id = %session_id,
            tool_name = %tool_name,
            actor = %actor,
            fields_json = %fields_json,
        ),
        Level::WARN => event!(
            Level::WARN,
            event = event_name,
            request_id = %request_id,
            session_id = %session_id,
            tool_name = %tool_name,
            actor = %actor,
            fields_json = %fields_json,
        ),
        Level::ERROR => event!(
            Level::ERROR,
            event = event_name,
            request_id = %request_id,
            session_id = %session_id,
            tool_name = %tool_name,
            actor = %actor,
            fields_json = %fields_json,
        ),
    }
}

/// Emits a tracing event containing a sanitized error field.
///
/// # Security
/// * Error messages are sanitized and redacted to mitigate secret leakage.
pub fn emit_error(level: Level, event_name: &'static str, ctx: &EventContext<'_>, err: &dyn Error) {
    let field = safe_error("error", err);
    emit_event(level, event_name, ctx, &[field]);
}

/// Creates a tracing span with sanitized context.
///
/// # Security
/// * Contextual span fields are sanitized before emission to mitigate info leakage.
pub fn make_span(name: &'static str, ctx: &EventContext<'_>) -> Span {
    let safe_ctx = ctx.sanitized();
    let request_id = safe_ctx.request_id.unwrap_or_default();
    let session_id = safe_ctx.session_id.unwrap_or_default();
    let tool_name = safe_ctx.tool_name.unwrap_or_default();
    let actor = safe_ctx.actor.unwrap_or_default();

    span!(
        Level::INFO,
        "mcp.observability",
        span_name = name,
        request_id = %request_id,
        session_id = %session_id,
        tool_name = %tool_name,
        actor = %actor,
    )
}

/// Constructor for textual fields; applies sanitization and redaction.
pub fn safe_text(key: &'static str, value: impl AsRef<str>) -> SafeField {
    SafeField::text(key, value)
}

/// Constructor for fields containing hard-coded secrets.
pub fn safe_secret(key: &'static str) -> SafeField {
    SafeField::secret(key)
}

/// Constructor for error fields; applies sanitization and redaction.
pub fn safe_error(key: &'static str, err: &dyn Error) -> SafeField {
    SafeField::error(key, err, DEFAULT_ERROR_MAX_LEN)
}

fn fields_to_json(fields: &[SafeField]) -> String {
    let mut payload = BTreeMap::new();
    for field in fields {
        payload.insert(normalize_key(field.key), Value::String(field.value.clone()));
    }
    serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
}

fn normalize_key(key: &str) -> String {
    let mut normalized = String::new();
    for ch in key.chars().take(DEFAULT_KEY_MAX_LEN) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
            normalized.push(ch);
        } else if !normalized.ends_with('_') {
            normalized.push('_');
        }
    }
    if normalized.is_empty() {
        "field".to_string()
    } else {
        normalized
    }
}

fn sanitize_value(value: &str, max_len: usize) -> String {
    let cleaned = sanitize_log_value_with_limit(value, max_len);
    redact_telemetry_text(&cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Debug)]
    struct StaticError(&'static str);

    impl std::fmt::Display for StaticError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Error for StaticError {}

    #[test]
    fn safe_text_strips_controls_and_redacts() {
        let field = SafeField::text("db", "postgresql://user:pass@host/db\n");
        assert_eq!(field.key, "db");
        assert!(!field.value.contains('\n'));
        assert!(field.value.contains("REDACTED"));
    }

    #[test]
    fn safe_secret_ignores_input_and_masks() {
        let field = SafeField::secret("token");
        assert_eq!(field.value, DEFAULT_REDACT_VALUE);
    }

    #[test]
    fn safe_error_redacts_message() {
        let err = StaticError("Authorization: Bearer topsecret");
        let field = SafeField::error("error", &err, 256);
        assert!(field.value.contains("REDACTED"));
        assert!(!field.value.contains("topsecret"));
    }

    #[test]
    fn event_context_sanitizes_empty_and_control_chars() {
        let ctx = EventContext {
            request_id: Some("req\n1"),
            session_id: Some(""),
            tool_name: Some("tool\u{0001}name"),
            actor: None,
        };
        let sanitized = ctx.sanitized();
        assert_eq!(sanitized.request_id.as_deref(), Some("req1"));
        assert!(sanitized.session_id.is_none());
        assert_eq!(sanitized.tool_name.as_deref(), Some("toolname"));
        assert!(sanitized.actor.is_none());
    }

    #[test]
    fn event_context_builder_helpers_assign_fields() {
        let ctx = EventContext::new()
            .with_request_id("r1")
            .with_session_id("s1")
            .with_tool_name("build.start")
            .with_actor("agent");
        assert_eq!(ctx.request_id, Some("r1"));
        assert_eq!(ctx.session_id, Some("s1"));
        assert_eq!(ctx.tool_name, Some("build.start"));
        assert_eq!(ctx.actor, Some("agent"));
    }

    #[test]
    fn normalize_key_rewrites_unsafe_characters() {
        let key = normalize_key("tool name=\n");
        assert_eq!(key, "tool_name_");
    }

    #[test]
    fn emit_event_outputs_redacted_fields() {
        let sink = SharedSink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_level(false)
            .compact()
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let ctx = EventContext::new().with_request_id("req\n1");
            emit_event(
                Level::INFO,
                "tool.call.started",
                &ctx,
                &[SafeField::text("authorization", "Bearer topsecret")],
            );
        });

        let output = sink.contents();
        assert!(output.contains("REDACTED"));
        assert!(!output.contains("topsecret"));
        assert!(!output.contains("req\n1"));
        assert!(output.contains("req1"));
    }

    #[test]
    fn emit_error_adds_redacted_error_field() {
        let sink = SharedSink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_level(false)
            .compact()
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let ctx = EventContext::new().with_tool_name("build.start");
            let err = StaticError("Authorization: Bearer ultra-secret");
            emit_error(Level::ERROR, "tool.call.failed", &ctx, &err);
        });

        let output = sink.contents();
        assert!(output.contains("tool.call.failed"));
        assert!(output.contains("REDACTED"));
        assert!(!output.contains("ultra-secret"));
    }

    #[test]
    fn make_span_uses_stable_metadata_name() {
        let span = make_span("tool.call", &EventContext::new());
        let metadata = span.metadata().expect("span metadata available");
        assert_eq!(metadata.name(), "mcp.observability");
    }

    #[derive(Clone, Default)]
    struct SharedSink {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedSink {
        fn contents(&self) -> String {
            let bytes = self.buffer.lock().expect("sink lock poisoned").clone();
            String::from_utf8(bytes).expect("sink should contain valid utf8")
        }
    }

    impl<'a> MakeWriter<'a> for SharedSink {
        type Writer = SharedSinkWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedSinkWriter {
                buffer: self.buffer.clone(),
            }
        }
    }

    struct SharedSinkWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for SharedSinkWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buffer
                .lock()
                .expect("sink lock poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
