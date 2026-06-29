//! # Gemini Invocation Observability
//!
//! Event contract for live Gemini tool-call inspection.
//!
//! ## Rationale
//! Provide a stable, transport-agnostic event stream so servers can surface
//! live progress dashboards without changing model-facing tool outputs.
//!
//! ## Security Boundaries
//! * Event payloads are emitted to in-process observers only.
//! * Persistence/authorization is the responsibility of the embedding server.
//!
//! ## References
//! * Live inspection surfaces for Gemini CLI-backed MCP tools.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Summary: identifies the transport stream that produced chunk data.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Stream labels contain no user-controlled data.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeminiOutputStream {
    Stdout,
    Stderr,
}

impl GeminiOutputStream {
    /// Summary: returns a static stream label for serialization and logging.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Labels are static constants.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// Summary: execution phase markers emitted for observable Gemini tool calls.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Phase values are server-generated and contain no payload text.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeminiInvocationPhase {
    ToolCallStarted,
    Spawned,
    WaitingForOutput,
    ToolCallFinished,
    Completed,
}

/// Summary: token-usage snapshot attached to terminal invocation events.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Contains numeric usage counters only.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeminiUsageSnapshot {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
}

/// Summary: identity and execution metadata for one Gemini tool invocation.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Server-controlled metadata fields only.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiInvocationMetadata {
    pub invocation_id: String,
    pub tool_name: String,
    pub actor: String,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub model_requested: Option<String>,
    pub model_used: Option<String>,
    pub resume_requested: bool,
    pub resume_selector: Option<String>,
    pub resume_strategy: Option<String>,
    pub effective_scope_roots: Vec<String>,
    pub nested_mcp_policy: String,
    pub sandbox: bool,
}

/// Summary: describes one observable invocation event.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Payload visibility decisions are enforced by the observer host.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum GeminiInvocationEventKind {
    Started,
    ValidationFailed {
        error_category: String,
    },
    AttemptStarted {
        attempt: u32,
    },
    Phase {
        attempt: u32,
        phase: GeminiInvocationPhase,
        pid: Option<u32>,
    },
    RetryScheduled {
        next_attempt: u32,
        reason: String,
        delay_ms: u64,
    },
    Heartbeat {
        attempt: u32,
        pid: Option<u32>,
        elapsed_ms: u64,
        stdout_bytes: u64,
        stderr_bytes: u64,
        last_output_age_ms: Option<u64>,
        stalled: bool,
    },
    Chunk {
        attempt: u32,
        stream: GeminiOutputStream,
        text: String,
    },
    Finished {
        ok: bool,
        error_category: Option<String>,
        failure_class: Option<String>,
        retryability: Option<String>,
        salvageability: Option<String>,
        result_source: String,
        degraded: bool,
        stale_age_ms: Option<u64>,
        live_error_category: Option<String>,
        duration_ms: u64,
        gemini_invocations: u32,
        retry_count: u32,
        usage: GeminiUsageSnapshot,
        usage_source: Option<String>,
        context_window_percent_used: Option<f64>,
        context_window_percent_remaining: Option<f64>,
        context_window_source: Option<String>,
        session_compression_mode: Option<String>,
        session_compression_attempted: bool,
        session_compression_ok: Option<bool>,
        session_compression_skipped_reason: Option<String>,
        context_guardrail_warned: bool,
        context_guardrail_threshold_percent: Option<u64>,
        resume_applied: bool,
        resume_outcome: Option<String>,
        fallback_mode: String,
        fallback_reason: Option<String>,
    },
}

/// Summary: envelope emitted for each live invocation event.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Timestamp is generated locally and does not trust client input.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiInvocationEvent {
    pub timestamp_ms: u64,
    pub metadata: GeminiInvocationMetadata,
    pub kind: GeminiInvocationEventKind,
}

impl GeminiInvocationEvent {
    /// Summary: creates a new event with an auto-populated timestamp.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Timestamp uses trusted local system clock.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn new(metadata: GeminiInvocationMetadata, kind: GeminiInvocationEventKind) -> Self {
        Self {
            timestamp_ms: current_unix_timestamp_ms(),
            metadata,
            kind,
        }
    }
}

/// Summary: observer contract for Gemini invocation events.
///
/// # Errors
/// * Observer implementations must handle internal failures without panicking.
///
/// # Security
/// * Implementers should treat incoming event payloads as sensitive.
///
/// # Panics
/// * Implementations should avoid panics.
pub trait GeminiInvocationObserver: Send + Sync {
    fn on_event(&self, event: GeminiInvocationEvent);
}

/// Summary: no-op observer used when live inspection is disabled.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Drops all events immediately.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Default)]
pub struct NoopGeminiInvocationObserver;

impl GeminiInvocationObserver for NoopGeminiInvocationObserver {
    fn on_event(&self, _event: GeminiInvocationEvent) {}
}

fn current_unix_timestamp_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis().min(u128::from(u64::MAX)) as u64,
        Err(_) => 0,
    }
}
