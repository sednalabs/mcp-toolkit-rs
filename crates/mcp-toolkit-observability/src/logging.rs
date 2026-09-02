//! # Structured Logging
//!
//! Multi-stream, multi-format logging engine for MCP services.
//!
//! ## Ownership
//! This module owns the routing logic, format rendering (logfmt/JSON/Plain), and
//! the orchestration of log redaction for sensitive patterns.
//!
//! ## Non-ownership
//! This module does not guarantee secret detection or sanitization integrity. It is
//! not a replacement for proper secure handling of sensitive data at the source.
//!
//! ## Policy & Guarantees
//! * **Structured Routing**: Supports splitting logs by target (e.g., Access vs Auth) to separate files.
//! * **Heuristic Masking**: Integrates global redaction filters to reduce the risk of accidental secret exposure.
//! * **Context Injection**: Enables binding of task-local metadata (e.g., request IDs) to logs.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Configuring appropriate log formats and output destinations.
//! * Ensuring that highly sensitive data is never passed to log emitters, as heuristic redaction is a "last line of defense" and not a substitute for secure application design.
//!
//! ## References
//! * [Tracing Subscriber] https://docs.rs/tracing-subscriber

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::fs::{create_dir_all, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use once_cell::sync::OnceCell;
use regex::Regex;
use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::fmt as fmt_subscriber;
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::registry::LookupSpan;

use crate::redaction::redact_telemetry_text;
use crate::sanitize::strip_control_chars;

pub type ContextMap = BTreeMap<String, String>;

/// Supported log output formats.
#[derive(Clone, Copy, Debug)]
pub enum LogFormat {
    /// Key-value pairs (e.g. `ts=... level=info msg="..."`).
    Logfmt,
    /// Newline-delimited JSON objects.
    Json,
    /// Human-readable text with request headers.
    Plain,
}

impl LogFormat {
    /// Load the log format from an environment variable.
    pub fn from_env(env: &str, default: LogFormat) -> LogFormat {
        match std::env::var(env)
            .unwrap_or_else(|_| default.as_str().to_string())
            .trim()
            .to_lowercase()
            .as_str()
        {
            "plain" => LogFormat::Plain,
            "json" => LogFormat::Json,
            _ => LogFormat::Logfmt,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LogFormat::Logfmt => "logfmt",
            LogFormat::Json => "json",
            LogFormat::Plain => "plain",
        }
    }
}

/// Identifiers for specialized log targets.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogTargets {
    /// Target for access log events.
    pub access: Option<&'static str>,
    /// Target for authentication log events.
    pub auth: Option<&'static str>,
}

impl LogTargets {
    /// Create a new target mapping.
    pub fn new(access: &'static str, auth: &'static str) -> LogTargets {
        LogTargets {
            access: Some(access),
            auth: Some(auth),
        }
    }
}

#[derive(Clone)]
struct FileHandle {
    path: Option<PathBuf>,
    file: Arc<Mutex<Option<std::fs::File>>>,
}

impl FileHandle {
    fn new(path: Option<PathBuf>) -> Self {
        if let Some(path) = path.as_ref() {
            if let Some(parent) = path.parent() {
                let _ = create_dir_all(parent);
            }
        }
        Self {
            path,
            file: Arc::new(Mutex::new(None)),
        }
    }

    fn writer(&self) -> Option<std::fs::File> {
        let _path = self.path.as_ref()?;
        let mut guard = self.file.lock().expect("log file lock poisoned");
        if let Some(file) = guard.as_ref() {
            return file.try_clone().ok().or_else(|| self.open_file());
        }
        let file = self.open_file()?;
        *guard = file.try_clone().ok().or_else(|| self.open_file());
        Some(file)
    }

    fn open_file(&self) -> Option<std::fs::File> {
        let path = self.path.as_ref()?;
        OpenOptions::new().create(true).append(true).open(path).ok()
    }
}

/// A `MakeWriter` implementation that routes events to files based on their target.
#[derive(Clone)]
pub struct RoutingWriter {
    general: FileHandle,
    access: FileHandle,
    auth: FileHandle,
    targets: LogTargets,
}

impl RoutingWriter {
    /// Create a new routing writer with optional file paths.
    pub fn new(
        general: Option<PathBuf>,
        access: Option<PathBuf>,
        auth: Option<PathBuf>,
        targets: LogTargets,
    ) -> Self {
        Self {
            general: FileHandle::new(general),
            access: FileHandle::new(access),
            auth: FileHandle::new(auth),
            targets,
        }
    }

    fn select_writers(&self, metadata: Option<&Metadata<'_>>) -> MultiWriter {
        let mut sinks: Vec<Box<dyn Write + Send>> = Vec::new();
        sinks.push(Box::new(std::io::stderr()));
        if let Some(file) = self.general.writer() {
            sinks.push(Box::new(file));
        }
        if let Some(meta) = metadata {
            if let Some(access_target) = self.targets.access {
                if meta.target() == access_target {
                    if let Some(file) = self.access.writer() {
                        sinks.push(Box::new(file));
                    }
                }
            }
            if let Some(auth_target) = self.targets.auth {
                if meta.target() == auth_target {
                    if let Some(file) = self.auth.writer() {
                        sinks.push(Box::new(file));
                    }
                }
            }
        }
        MultiWriter { sinks }
    }
}

impl<'writer> fmt_subscriber::writer::MakeWriter<'writer> for RoutingWriter {
    type Writer = MultiWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        self.select_writers(None)
    }

    fn make_writer_for(&'writer self, meta: &Metadata<'_>) -> Self::Writer {
        self.select_writers(Some(meta))
    }
}

/// A writer that broadcasts log events to multiple sinks.
pub struct MultiWriter {
    sinks: Vec<Box<dyn Write + Send>>,
}

impl Write for MultiWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut error: Option<io::Error> = None;
        for sink in &mut self.sinks {
            if let Err(err) = sink.write_all(buf) {
                if error.is_none() {
                    error = Some(err);
                }
            }
        }
        if let Some(err) = error {
            return Err(err);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut error: Option<io::Error> = None;
        for sink in &mut self.sinks {
            if let Err(err) = sink.flush() {
                if error.is_none() {
                    error = Some(err);
                }
            }
        }
        if let Some(err) = error {
            return Err(err);
        }
        Ok(())
    }
}

/// A tracing `FormatEvent` implementation that injects context and redacts secrets.
pub struct LogFormatter<C, R> {
    format: LogFormat,
    context_provider: C,
    redactor: R,
}

impl<C> LogFormatter<C, fn(&str) -> String>
where
    C: Fn() -> ContextMap + Send + Sync + 'static,
{
    pub fn new(format: LogFormat, context_provider: C) -> Self {
        Self {
            format,
            context_provider,
            redactor: redact_log_text_default,
        }
    }
}

impl<C, R> LogFormatter<C, R> {
    pub fn with_redactor<R2>(self, redactor: R2) -> LogFormatter<C, R2> {
        LogFormatter {
            format: self.format,
            context_provider: self.context_provider,
            redactor,
        }
    }
}

impl<S, N, C, R> FormatEvent<S, N> for LogFormatter<C, R>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
    N: for<'writer> FormatFields<'writer> + 'static,
    C: Fn() -> ContextMap + Send + Sync + 'static,
    R: Fn(&str) -> String + Send + Sync + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let metadata = event.metadata();
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);

        let mut payload: BTreeMap<String, String> = BTreeMap::new();
        payload.insert("ts".to_string(), now_iso());
        payload.insert(
            "level".to_string(),
            metadata.level().to_string().to_lowercase(),
        );
        payload.insert("logger".to_string(), metadata.target().to_string());
        if let Some(message) = visitor.message.take() {
            payload.insert("msg".to_string(), message);
        } else {
            payload.insert("msg".to_string(), metadata.name().to_string());
        }

        for (key, value) in (self.context_provider)() {
            if !value.is_empty() {
                payload.insert(key, value);
            }
        }

        for (key, value) in visitor.fields {
            if key == "message" {
                continue;
            }
            payload.insert(key, value);
        }

        let rendered = match self.format {
            LogFormat::Json => serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string()),
            LogFormat::Plain => render_plain(&payload),
            LogFormat::Logfmt => render_logfmt(&payload),
        };
        let redacted = (self.redactor)(&rendered);
        writeln!(writer, "{redacted}")?;
        Ok(())
    }
}

#[derive(Default)]
struct EventVisitor {
    fields: BTreeMap<String, String>,
    message: Option<String>,
}

impl tracing::field::Visit for EventVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        let text = format!("{value:?}");
        self.record(field, text);
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record(field, value.to_string());
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.record(field, value.to_string());
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.record(field, value.to_string());
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.record(field, value.to_string());
    }
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.record(field, value.to_string());
    }
}

impl EventVisitor {
    fn record(&mut self, field: &tracing::field::Field, value: String) {
        let name = field.name();
        if name == "message" {
            self.message = Some(value);
            return;
        }
        self.fields.insert(name.to_string(), value);
    }
}

fn now_iso() -> String {
    let now = time::OffsetDateTime::now_utc();
    now.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Render a log payload in human-readable plain text.
pub fn render_plain(payload: &BTreeMap<String, String>) -> String {
    let mut line = String::new();
    let ts = clean_log_value(payload.get("ts").map(String::as_str).unwrap_or_default());
    let level = clean_log_value(payload.get("level").map(String::as_str).unwrap_or_default());
    let logger = clean_log_value(
        payload
            .get("logger")
            .map(String::as_str)
            .unwrap_or_default(),
    );
    let msg = clean_log_value(payload.get("msg").map(String::as_str).unwrap_or_default());
    let _ = write!(line, "{ts} {level} {logger}");
    if let Some(request_id) = payload.get("request_id") {
        let request_id = clean_log_value(request_id);
        let _ = write!(line, " request_id={request_id}");
    }
    if let Some(actor) = payload.get("actor") {
        let actor = clean_log_value(actor);
        let _ = write!(line, " actor={actor}");
    }
    if !msg.is_empty() {
        let _ = write!(line, ": {msg}");
    }
    line
}

/// Render a log payload in standard logfmt format.
pub fn render_logfmt(payload: &BTreeMap<String, String>) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (key, value) in payload {
        if value.is_empty() {
            continue;
        }
        let key = clean_logfmt_key(key);
        if key.is_empty() {
            continue;
        }
        let value = clean_log_value(value);
        let needs_quotes = value
            .chars()
            .any(|ch| ch.is_whitespace() || ch == '"' || ch == '=' || ch == '\\');
        if needs_quotes {
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            parts.push(format!("{key}=\"{escaped}\""));
        } else {
            parts.push(format!("{key}={value}"));
        }
    }
    parts.join(" ")
}

fn clean_log_value(value: &str) -> String {
    strip_control_chars(value)
}

fn clean_logfmt_key(key: &str) -> String {
    strip_control_chars(key)
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '=' && *ch != '"')
        .collect()
}

/// Scrub sensitive data from log text using heuristic patterns and environment secrets.
///
/// # Security
/// * Aids in mitigating accidental secret exposure through best-effort heuristic pattern matching.
/// * Callers should treat this as a defense-in-depth measure, not absolute sanitization.
pub fn redact_log_text_default(text: &str) -> String {
    let mut scrubbed = redact_telemetry_text(text);
    let auth_re =
        AUTH_REDACT.get_or_init(|| Regex::new(r"(?i)(authorization:\s*bearer\s+)\S+").unwrap());
    scrubbed = auth_re.replace_all(&scrubbed, "$1REDACTED").to_string();
    let api_key_re = API_KEY_REDACT.get_or_init(|| Regex::new(r"(?i)(x-api-key:\s*)\S+").unwrap());
    scrubbed = api_key_re.replace_all(&scrubbed, "$1REDACTED").to_string();

    for (name, value) in std::env::vars() {
        if value.len() < 8 {
            continue;
        }
        let upper = name.to_ascii_uppercase();
        if upper.contains("KEY")
            || upper.contains("TOKEN")
            || upper.contains("SECRET")
            || upper.contains("PASSWORD")
            || upper.contains("PASS")
            || upper.contains("BEARER")
        {
            scrubbed = scrubbed.replace(&value, &format!("<redacted:{name}>"));
        }
    }

    scrubbed
}

static AUTH_REDACT: OnceCell<Regex> = OnceCell::new();
static API_KEY_REDACT: OnceCell<Regex> = OnceCell::new();

/// Convenience provider for log contexts with no metadata.
pub fn empty_context() -> ContextMap {
    BTreeMap::new()
}

#[cfg(test)]
mod tests {
    use super::{render_logfmt, render_plain};
    use std::collections::BTreeMap;

    #[test]
    fn plain_renderer_strips_control_characters() {
        let mut payload = BTreeMap::new();
        payload.insert("ts".to_string(), "2026-06-12T00:00:00Z".to_string());
        payload.insert("level".to_string(), "INFO".to_string());
        payload.insert("logger".to_string(), "auth".to_string());
        payload.insert("request_id".to_string(), "req-1\nlevel=ERROR".to_string());
        payload.insert("actor".to_string(), "user\tname".to_string());
        payload.insert("msg".to_string(), "ok\r\nforged=true".to_string());

        let rendered = render_plain(&payload);
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains('\r'));
        assert!(!rendered.contains('\t'));
        assert!(rendered.contains("request_id=req-1level=ERROR"));
        assert!(rendered.contains(": okforged=true"));
    }

    #[test]
    fn logfmt_renderer_strips_control_characters() {
        let mut payload = BTreeMap::new();
        payload.insert("msg".to_string(), "started\nlevel=ERROR".to_string());
        payload.insert("request_id".to_string(), "req\t1".to_string());
        payload.insert("bad\nkey".to_string(), "value".to_string());

        let rendered = render_logfmt(&payload);
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains('\t'));
        assert!(rendered.contains("msg=\"startedlevel=ERROR\""));
        assert!(rendered.contains("request_id=req1"));
        assert!(rendered.contains("badkey=value"));
    }
}
