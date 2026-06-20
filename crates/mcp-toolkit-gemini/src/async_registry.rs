//! # Gemini Async Invocation Registry
//!
//! In-memory lifecycle tracking for detached Gemini tool invocations.
//!
//! ## Rationale
//! Provide first-class async start/status/cancel semantics without moving
//! Gemini execution logic into transport-specific server crates.
//!
//! ## Security Boundaries
//! * Stores invocation metadata and final structured payloads in-process only.
//! * Relies on embedding tool handlers to enforce actor visibility.
//!
//! ## References
//! * Transport wrappers that expose detached Gemini invocation tools.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::config::GeminiExecutionConfig;
use crate::observe::{
    GeminiInvocationEvent, GeminiInvocationEventKind, GeminiInvocationMetadata,
    GeminiInvocationObserver, GeminiInvocationPhase,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeminiAsyncInvocationState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Canceled,
}

impl GeminiAsyncInvocationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Canceled)
    }
}

#[derive(Debug, Clone)]
pub struct GeminiAsyncInvocationSnapshot {
    pub invocation_id: String,
    pub tool_name: String,
    pub actor: String,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub model_requested: Option<String>,
    pub model_used: Option<String>,
    pub resume_selector: Option<String>,
    pub resume_strategy: Option<String>,
    pub effective_scope_roots: Vec<String>,
    pub nested_mcp_policy: String,
    pub state: GeminiAsyncInvocationState,
    pub cancel_requested: bool,
    pub created_at_unix_ms: u64,
    pub started_at_unix_ms: Option<u64>,
    pub last_event_unix_ms: u64,
    pub finished_at_unix_ms: Option<u64>,
    pub latest_attempt: u32,
    pub retry_count: u32,
    pub last_phase: Option<String>,
    pub pid: Option<u32>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub last_output_age_ms: Option<u64>,
    pub stalled: bool,
    pub result: Option<Value>,
}

impl GeminiAsyncInvocationSnapshot {
    pub fn terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeminiAsyncRegistryError {
    CapacityReached,
}

impl GeminiAsyncRegistryError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::CapacityReached => "GEMINI_ASYNC_INVOCATION_CAPACITY_REACHED",
        }
    }

    pub const fn reason(self) -> &'static str {
        match self {
            Self::CapacityReached => "gemini_async_invocation_capacity_reached",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::CapacityReached => {
                "async Gemini invocation capacity reached; poll existing invocations or retry later"
            }
        }
    }
}

#[derive(Debug)]
struct RegistryEntryState {
    snapshot: GeminiAsyncInvocationSnapshot,
    expires_at: Option<Instant>,
}

#[derive(Debug)]
pub struct GeminiAsyncInvocationHandle {
    state: Mutex<RegistryEntryState>,
    notify: Notify,
    revision: AtomicU64,
    cancellation_token: CancellationToken,
}

impl GeminiAsyncInvocationHandle {
    fn new(metadata: &GeminiInvocationMetadata) -> Self {
        let now = current_unix_timestamp_ms();
        Self {
            state: Mutex::new(RegistryEntryState {
                snapshot: GeminiAsyncInvocationSnapshot {
                    invocation_id: metadata.invocation_id.clone(),
                    tool_name: metadata.tool_name.clone(),
                    actor: metadata.actor.clone(),
                    session_id: metadata.session_id.clone(),
                    request_id: metadata.request_id.clone(),
                    model_requested: metadata.model_requested.clone(),
                    model_used: metadata.model_used.clone(),
                    resume_selector: metadata.resume_selector.clone(),
                    resume_strategy: metadata.resume_strategy.clone(),
                    effective_scope_roots: metadata.effective_scope_roots.clone(),
                    nested_mcp_policy: metadata.nested_mcp_policy.clone(),
                    state: GeminiAsyncInvocationState::Pending,
                    cancel_requested: false,
                    created_at_unix_ms: now,
                    started_at_unix_ms: None,
                    last_event_unix_ms: now,
                    finished_at_unix_ms: None,
                    latest_attempt: 0,
                    retry_count: 0,
                    last_phase: None,
                    pid: None,
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                    last_output_age_ms: None,
                    stalled: false,
                    result: None,
                },
                expires_at: None,
            }),
            notify: Notify::new(),
            revision: AtomicU64::new(0),
            cancellation_token: CancellationToken::new(),
        }
    }

    pub fn snapshot(&self) -> GeminiAsyncInvocationSnapshot {
        self.state
            .lock()
            .map(|state| state.snapshot.clone())
            .unwrap_or_else(|_| GeminiAsyncInvocationSnapshot {
                invocation_id: "unknown".to_string(),
                tool_name: "unknown".to_string(),
                actor: "unknown".to_string(),
                session_id: None,
                request_id: None,
                model_requested: None,
                model_used: None,
                resume_selector: None,
                resume_strategy: None,
                effective_scope_roots: Vec::new(),
                nested_mcp_policy: "__none__".to_string(),
                state: GeminiAsyncInvocationState::Failed,
                cancel_requested: false,
                created_at_unix_ms: current_unix_timestamp_ms(),
                started_at_unix_ms: None,
                last_event_unix_ms: current_unix_timestamp_ms(),
                finished_at_unix_ms: Some(current_unix_timestamp_ms()),
                latest_attempt: 0,
                retry_count: 0,
                last_phase: Some("registry_error".to_string()),
                pid: None,
                stdout_bytes: 0,
                stderr_bytes: 0,
                last_output_age_ms: None,
                stalled: false,
                result: Some(serde_json::json!({
                    "ok": false,
                    "error_category": "tool_runtime",
                    "error": "async invocation registry lock poisoned",
                })),
            })
    }

    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }

    pub async fn wait_for_update_since(&self, revision: u64, wait_for: Option<Duration>) -> bool {
        if self.revision() != revision {
            return true;
        }
        let notified = self.notify.notified();
        match wait_for {
            Some(wait_for) => tokio::time::timeout(wait_for, notified).await.is_ok(),
            None => {
                notified.await;
                true
            }
        }
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation_token.clone()
    }

    pub fn request_cancel(&self) -> GeminiAsyncInvocationSnapshot {
        let snapshot = if let Ok(mut state) = self.state.lock() {
            state.snapshot.cancel_requested = true;
            state.snapshot.clone()
        } else {
            self.snapshot()
        };
        self.cancellation_token.cancel();
        self.bump_revision();
        snapshot
    }

    pub fn complete(
        &self,
        state: GeminiAsyncInvocationState,
        result: Value,
        retention: Duration,
    ) -> GeminiAsyncInvocationSnapshot {
        let snapshot = if let Ok(mut entry) = self.state.lock() {
            entry.snapshot.state = state;
            entry.snapshot.result = Some(result);
            entry.snapshot.finished_at_unix_ms = Some(current_unix_timestamp_ms());
            entry.snapshot.last_event_unix_ms = entry
                .snapshot
                .finished_at_unix_ms
                .unwrap_or(entry.snapshot.last_event_unix_ms);
            entry.expires_at = Some(Instant::now() + retention);
            entry.snapshot.clone()
        } else {
            self.snapshot()
        };
        self.bump_revision();
        snapshot
    }

    pub fn ingest_event(&self, event: &GeminiInvocationEvent) {
        if let Ok(mut entry) = self.state.lock() {
            let snapshot = &mut entry.snapshot;
            snapshot.tool_name = event.metadata.tool_name.clone();
            snapshot.actor = event.metadata.actor.clone();
            snapshot.session_id = event.metadata.session_id.clone();
            snapshot.request_id = event.metadata.request_id.clone();
            snapshot.model_requested = event.metadata.model_requested.clone();
            snapshot.model_used = event.metadata.model_used.clone();
            snapshot.resume_selector = event.metadata.resume_selector.clone();
            snapshot.resume_strategy = event.metadata.resume_strategy.clone();
            snapshot.effective_scope_roots = event.metadata.effective_scope_roots.clone();
            snapshot.nested_mcp_policy = event.metadata.nested_mcp_policy.clone();
            snapshot.last_event_unix_ms = event.timestamp_ms;
            match &event.kind {
                GeminiInvocationEventKind::Started => {
                    snapshot
                        .started_at_unix_ms
                        .get_or_insert(event.timestamp_ms);
                    snapshot.state = GeminiAsyncInvocationState::Pending;
                    snapshot.last_phase = Some("tool_call_started".to_string());
                }
                GeminiInvocationEventKind::ValidationFailed { .. } => {
                    snapshot.last_phase = Some("validation_failed".to_string());
                }
                GeminiInvocationEventKind::AttemptStarted { attempt } => {
                    snapshot
                        .started_at_unix_ms
                        .get_or_insert(event.timestamp_ms);
                    snapshot.latest_attempt = *attempt;
                    if !snapshot.state.is_terminal() {
                        snapshot.state = GeminiAsyncInvocationState::Running;
                    }
                }
                GeminiInvocationEventKind::Phase {
                    attempt,
                    phase,
                    pid,
                } => {
                    snapshot
                        .started_at_unix_ms
                        .get_or_insert(event.timestamp_ms);
                    snapshot.latest_attempt = *attempt;
                    snapshot.last_phase = Some(phase_label(*phase).to_string());
                    if pid.is_some() {
                        snapshot.pid = *pid;
                    }
                    if !snapshot.state.is_terminal() {
                        snapshot.state = GeminiAsyncInvocationState::Running;
                    }
                }
                GeminiInvocationEventKind::RetryScheduled { .. } => {
                    snapshot.retry_count = snapshot.retry_count.saturating_add(1);
                }
                GeminiInvocationEventKind::Heartbeat {
                    attempt,
                    pid,
                    stdout_bytes,
                    stderr_bytes,
                    last_output_age_ms,
                    stalled,
                    ..
                } => {
                    snapshot
                        .started_at_unix_ms
                        .get_or_insert(event.timestamp_ms);
                    snapshot.latest_attempt = *attempt;
                    if pid.is_some() {
                        snapshot.pid = *pid;
                    }
                    snapshot.stdout_bytes = *stdout_bytes;
                    snapshot.stderr_bytes = *stderr_bytes;
                    snapshot.last_output_age_ms = *last_output_age_ms;
                    snapshot.stalled = *stalled;
                    if !snapshot.state.is_terminal() {
                        snapshot.state = GeminiAsyncInvocationState::Running;
                    }
                }
                GeminiInvocationEventKind::Chunk { attempt, .. } => {
                    snapshot
                        .started_at_unix_ms
                        .get_or_insert(event.timestamp_ms);
                    snapshot.latest_attempt = *attempt;
                    if !snapshot.state.is_terminal() {
                        snapshot.state = GeminiAsyncInvocationState::Running;
                    }
                }
                GeminiInvocationEventKind::Finished {
                    ok,
                    retry_count,
                    gemini_invocations,
                    ..
                } => {
                    snapshot.finished_at_unix_ms = Some(event.timestamp_ms);
                    snapshot.retry_count = snapshot
                        .retry_count
                        .max((*retry_count).max(gemini_invocations.saturating_sub(1)));
                    snapshot.last_phase = Some("completed".to_string());
                    if !snapshot.state.is_terminal() {
                        snapshot.state = if *ok {
                            GeminiAsyncInvocationState::Succeeded
                        } else if snapshot.cancel_requested {
                            GeminiAsyncInvocationState::Canceled
                        } else {
                            GeminiAsyncInvocationState::Failed
                        };
                    }
                }
            }
        }
        self.bump_revision();
    }

    fn is_expired(&self) -> bool {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.expires_at)
            .map(|expires_at| Instant::now() >= expires_at)
            .unwrap_or(false)
    }

    fn is_terminal(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.snapshot.state.is_terminal())
            .unwrap_or(true)
    }

    fn created_at_unix_ms(&self) -> u64 {
        self.state
            .lock()
            .map(|state| state.snapshot.created_at_unix_ms)
            .unwrap_or(0)
    }

    fn bump_revision(&self) {
        self.revision.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_waiters();
    }
}

#[derive(Debug, Default)]
struct GeminiAsyncRegistryInner {
    invocations: HashMap<String, Arc<GeminiAsyncInvocationHandle>>,
}

#[derive(Clone)]
pub struct GeminiAsyncInvocationRegistry {
    max_tracked_invocations: usize,
    retention: Duration,
    inner: Arc<Mutex<GeminiAsyncRegistryInner>>,
}

#[derive(Clone)]
struct GeminiAsyncRegistryObserver {
    registry: GeminiAsyncInvocationRegistry,
}

impl GeminiAsyncInvocationRegistry {
    pub fn new(config: &GeminiExecutionConfig) -> Self {
        Self {
            max_tracked_invocations: config.async_max_tracked_invocations.max(1),
            retention: config.async_retention,
            inner: Arc::new(Mutex::new(GeminiAsyncRegistryInner::default())),
        }
    }

    pub fn observer(&self) -> Arc<dyn GeminiInvocationObserver> {
        Arc::new(GeminiAsyncRegistryObserver {
            registry: self.clone(),
        })
    }

    pub fn retention(&self) -> Duration {
        self.retention
    }

    pub fn register(
        &self,
        metadata: &GeminiInvocationMetadata,
    ) -> Result<Arc<GeminiAsyncInvocationHandle>, GeminiAsyncRegistryError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| GeminiAsyncRegistryError::CapacityReached)?;
        self.prune_locked(&mut inner);
        while inner.invocations.len() >= self.max_tracked_invocations {
            let Some(oldest_terminal_id) = inner
                .invocations
                .iter()
                .filter(|(_, handle)| handle.is_terminal())
                .min_by_key(|(_, handle)| handle.created_at_unix_ms())
                .map(|(invocation_id, _)| invocation_id.clone())
            else {
                return Err(GeminiAsyncRegistryError::CapacityReached);
            };
            inner.invocations.remove(&oldest_terminal_id);
        }
        let handle = Arc::new(GeminiAsyncInvocationHandle::new(metadata));
        inner
            .invocations
            .insert(metadata.invocation_id.clone(), handle.clone());
        Ok(handle)
    }

    pub fn get(&self, invocation_id: &str) -> Option<Arc<GeminiAsyncInvocationHandle>> {
        let mut inner = self.inner.lock().ok()?;
        self.prune_locked(&mut inner);
        inner.invocations.get(invocation_id).cloned()
    }

    pub fn ingest_event(&self, event: &GeminiInvocationEvent) {
        let handle = self.get(&event.metadata.invocation_id);
        if let Some(handle) = handle {
            handle.ingest_event(event);
        }
    }

    fn prune_locked(&self, inner: &mut GeminiAsyncRegistryInner) {
        inner
            .invocations
            .retain(|_, handle| !(handle.is_terminal() && handle.is_expired()));
    }
}

impl GeminiInvocationObserver for GeminiAsyncRegistryObserver {
    fn on_event(&self, event: GeminiInvocationEvent) {
        self.registry.ingest_event(&event);
    }
}

fn phase_label(phase: GeminiInvocationPhase) -> &'static str {
    match phase {
        GeminiInvocationPhase::ToolCallStarted => "tool_call_started",
        GeminiInvocationPhase::Spawned => "spawned",
        GeminiInvocationPhase::WaitingForOutput => "waiting_for_output",
        GeminiInvocationPhase::ToolCallFinished => "tool_call_finished",
        GeminiInvocationPhase::Completed => "completed",
    }
}

fn current_unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GeminiExecutionConfig;

    fn sample_metadata(invocation_id: &str) -> GeminiInvocationMetadata {
        GeminiInvocationMetadata {
            invocation_id: invocation_id.to_string(),
            tool_name: "ask-gemini".to_string(),
            actor: "local".to_string(),
            session_id: Some("session-1".to_string()),
            request_id: Some("request-1".to_string()),
            model_requested: Some("gemini-3-pro".to_string()),
            model_used: Some("gemini-3-pro-preview".to_string()),
            resume_requested: false,
            resume_selector: None,
            resume_strategy: None,
            effective_scope_roots: vec!["/repo".to_string()],
            nested_mcp_policy: "__none__".to_string(),
            sandbox: false,
        }
    }

    #[test]
    fn registry_register_cancel_and_complete_tracks_state() {
        let registry = GeminiAsyncInvocationRegistry::new(&GeminiExecutionConfig::default());
        let handle = registry
            .register(&sample_metadata("gmi-test-1"))
            .expect("register async invocation");
        assert_eq!(handle.snapshot().state, GeminiAsyncInvocationState::Pending);

        let cancelled = handle.request_cancel();
        assert!(cancelled.cancel_requested);

        let completed = handle.complete(
            GeminiAsyncInvocationState::Canceled,
            serde_json::json!({"ok": false, "error": "cancelled"}),
            Duration::from_secs(60),
        );
        assert_eq!(completed.state, GeminiAsyncInvocationState::Canceled);
        assert!(completed.result.is_some());
        assert!(completed.finished_at_unix_ms.is_some());
    }

    #[test]
    fn registry_observer_updates_runtime_fields() {
        let registry = GeminiAsyncInvocationRegistry::new(&GeminiExecutionConfig::default());
        let metadata = sample_metadata("gmi-test-2");
        let handle = registry
            .register(&metadata)
            .expect("register async invocation");

        registry.ingest_event(&GeminiInvocationEvent::new(
            metadata.clone(),
            GeminiInvocationEventKind::Started,
        ));
        registry.ingest_event(&GeminiInvocationEvent::new(
            metadata.clone(),
            GeminiInvocationEventKind::Phase {
                attempt: 1,
                phase: GeminiInvocationPhase::Spawned,
                pid: Some(4242),
            },
        ));
        registry.ingest_event(&GeminiInvocationEvent::new(
            metadata.clone(),
            GeminiInvocationEventKind::Heartbeat {
                attempt: 1,
                pid: Some(4242),
                elapsed_ms: 500,
                stdout_bytes: 123,
                stderr_bytes: 9,
                last_output_age_ms: Some(25),
                stalled: false,
            },
        ));
        registry.ingest_event(&GeminiInvocationEvent::new(
            metadata,
            GeminiInvocationEventKind::Finished {
                ok: true,
                error_category: None,
                failure_class: None,
                retryability: None,
                salvageability: None,
                result_source: "live".to_string(),
                degraded: false,
                stale_age_ms: None,
                live_error_category: None,
                duration_ms: 500,
                gemini_invocations: 1,
                retry_count: 0,
                usage: Default::default(),
                usage_source: Some("json_usage".to_string()),
                context_window_percent_used: None,
                context_window_percent_remaining: None,
                context_window_source: None,
                session_compression_mode: None,
                session_compression_attempted: false,
                session_compression_ok: None,
                session_compression_skipped_reason: None,
                context_guardrail_warned: false,
                context_guardrail_threshold_percent: None,
                resume_applied: false,
                resume_outcome: None,
                fallback_mode: "none".to_string(),
                fallback_reason: None,
            },
        ));

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.state, GeminiAsyncInvocationState::Succeeded);
        assert_eq!(snapshot.latest_attempt, 1);
        assert_eq!(snapshot.pid, Some(4242));
        assert_eq!(snapshot.stdout_bytes, 123);
        assert_eq!(snapshot.stderr_bytes, 9);
        assert_eq!(snapshot.last_phase.as_deref(), Some("completed"));
        assert!(snapshot.finished_at_unix_ms.is_some());
    }
}
