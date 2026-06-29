//! # Streamable HTTP Session Resumption
//!
//! Session helpers for bounded concurrency and SSE event replay when clients
//! reconnect with `Last-Event-ID`.
//!
//! ## Rationale
//! Provide reusable building blocks for MCP servers that need resumable
//! Streamable HTTP sessions without re-implementing eviction and event storage.
//!
//! ## Security Boundaries
//! * **Retention Limits**: Stored SSE events are capped by stream count and TTL limits to mitigate memory exhaustion.
//! * **Replay Surface**: Events are replayed to authorized clients based on valid session IDs.
//! * **Input Validation**: All session identifiers and event IDs are normalized and validated.
//!
//! ## References
//! * **MCP HTTP Transport**: https://modelcontextprotocol.io/docs/concepts/transports#http-sse
//!
//! ## Notes
//! * Event stores can be memory-based or persistent (via SQLite).
//! * Session lifecycle management ensures stale, disconnected sessions are reclaimed.

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::{Stream, StreamExt};
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::streamable_http_server::session::local::{
    LocalSessionManager, LocalSessionManagerError, SessionConfig,
};
use rmcp::transport::streamable_http_server::session::{
    ServerSseMessage, SessionId, SessionManager,
};
use tokio::sync::{Mutex as AsyncMutex, RwLock};

#[cfg(feature = "session-sqlite")]
use crate::session_sqlite::SqliteEventStore;
#[cfg(feature = "session-sqlite")]
use base64::Engine;

/// Configuration for SSE event retention.
#[derive(Debug, Clone)]
pub struct EventStoreConfig {
    pub max_streams: usize,
    pub max_events: usize,
    pub ttl: Option<Duration>,
    pub encryption: Option<EventStoreEncryption>,
}

/// Optional encryption settings for persisted event payloads.
///
/// # Security
/// Encryption keys should be treated as high-value secrets. This structure
/// holds key material in memory; ensure the host environment is secure.
#[derive(Debug, Clone)]
pub struct EventStoreEncryption {
    #[cfg(feature = "session-sqlite")]
    key: [u8; 32],
}

impl EventStoreEncryption {
    /// Build encryption settings from raw key bytes.
    ///
    /// # Errors
    /// Returns `EventStoreError` if key length is not exactly 32 bytes (AES-256).
    pub fn from_bytes(key: &[u8]) -> Result<Self, EventStoreError> {
        if key.len() != 32 {
            return Err(EventStoreError::new("event store key must be 32 bytes"));
        }
        #[cfg(feature = "session-sqlite")]
        {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(key);
            Ok(Self { key: buf })
        }
        #[cfg(not(feature = "session-sqlite"))]
        Err(EventStoreError::new(
            "event store encryption requires session-sqlite feature",
        ))
    }

    /// Build encryption settings from base64-encoded key material.
    ///
    /// # Errors
    /// Returns `EventStoreError` if decoding fails or key length is invalid.
    #[cfg(feature = "session-sqlite")]
    pub fn from_base64(value: &str) -> Result<Self, EventStoreError> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .map_err(|_| EventStoreError::new("event store key must be base64 encoded"))?;
        Self::from_bytes(&decoded)
    }

    #[cfg(feature = "session-sqlite")]
    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Error returned by the event store.
#[derive(Debug, Clone)]
pub struct EventStoreError {
    message: String,
}

impl EventStoreError {
    /// Creates a new `EventStoreError`.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for EventStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "event store error: {}", self.message)
    }
}

impl std::error::Error for EventStoreError {}

/// SSE event store with bounded retention.
///
/// # Security
/// Provides controlled event replay. Stored data is subject to retention
/// policies defined in `EventStoreConfig`.
#[derive(Debug, Clone)]
pub struct EventStore {
    inner: Arc<EventStoreInner>,
}

#[derive(Debug)]
enum EventStoreInner {
    Memory(MemoryEventStore),
    #[cfg(feature = "session-sqlite")]
    Sqlite(SqliteEventStore),
}

impl EventStore {
    /// Create an in-memory event store.
    pub fn memory(config: EventStoreConfig) -> Self {
        Self {
            inner: Arc::new(EventStoreInner::Memory(MemoryEventStore::new(config))),
        }
    }

    /// Create a SQLite-backed event store.
    ///
    /// # Errors
    /// Returns `EventStoreError` if database initialization fails.
    #[cfg(feature = "session-sqlite")]
    pub fn sqlite(path: String, config: EventStoreConfig) -> Result<Self, EventStoreError> {
        let store = SqliteEventStore::new(path, config)?;
        Ok(Self {
            inner: Arc::new(EventStoreInner::Sqlite(store)),
        })
    }

    /// Persists an outbound SSE message.
    ///
    /// # Errors
    /// Returns `EventStoreError` if persistence fails.
    ///
    /// # Security
    /// Messages without a valid event ID are ignored to maintain replay consistency.
    pub async fn store_event(
        &self,
        session_id: &str,
        message: &ServerSseMessage,
    ) -> Result<(), EventStoreError> {
        let Some(event_id) = message.event_id.as_deref() else {
            return Ok(());
        };
        let Some(parsed) = parse_event_id(event_id) else {
            tracing::warn!(event_id = %event_id, "unable to parse streamable HTTP event id");
            return Ok(());
        };
        let stream_id = stream_id(session_id, parsed.http_request_id);
        let created_at = current_epoch_seconds() as i64;
        match &*self.inner {
            EventStoreInner::Memory(store) => {
                store
                    .store_event(
                        stream_id,
                        parsed.index,
                        event_id.to_string(),
                        message.message.clone(),
                        created_at,
                    )
                    .await;
                Ok(())
            }
            #[cfg(feature = "session-sqlite")]
            EventStoreInner::Sqlite(store) => {
                let payload = serialize_message(message)?;
                store
                    .store_event(
                        stream_id,
                        parsed.index,
                        event_id.to_string(),
                        payload,
                        created_at,
                    )
                    .await
            }
        }
    }

    /// Replays events for a session after the specified event ID.
    ///
    /// # Errors
    /// Returns `EventStoreError` if event payloads cannot be retrieved or decoded.
    pub async fn replay_after(
        &self,
        session_id: &str,
        last_event_id: &str,
    ) -> Result<Vec<ServerSseMessage>, EventStoreError> {
        let Some(parsed) = parse_event_id(last_event_id) else {
            return Ok(Vec::new());
        };
        let stream_id = stream_id(session_id, parsed.http_request_id);
        let rows = match &*self.inner {
            EventStoreInner::Memory(store) => store.replay_after(stream_id, parsed.index).await,
            #[cfg(feature = "session-sqlite")]
            EventStoreInner::Sqlite(store) => store.replay_after(stream_id, parsed.index).await?,
        };
        Ok(rows
            .into_iter()
            .filter_map(|row| match row.payload {
                Some(payload) => match serde_json::from_str::<ServerJsonRpcMessage>(&payload) {
                    Ok(message) => Some(ServerSseMessage::new(row.event_id, message)),
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to parse stored event payload");
                        None
                    }
                },
                None => None,
            })
            .collect())
    }
}

#[derive(Debug, Clone, Copy)]
struct ParsedEventId {
    index: i64,
    http_request_id: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct StoredRow {
    pub(crate) event_id: String,
    pub(crate) payload: Option<String>,
}

#[derive(Debug)]
struct MemoryEventStore {
    config: EventStoreConfig,
    state: AsyncMutex<MemoryState>,
}

#[derive(Debug)]
struct MemoryState {
    streams: HashMap<String, VecDeque<StoredEvent>>,
    order: VecDeque<String>,
}

#[derive(Debug, Clone)]
struct StoredEvent {
    seq: i64,
    event_id: String,
    message: Option<Arc<ServerJsonRpcMessage>>,
    created_at: i64,
}

impl MemoryEventStore {
    fn new(config: EventStoreConfig) -> Self {
        Self {
            config,
            state: AsyncMutex::new(MemoryState {
                streams: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    async fn store_event(
        &self,
        stream_id: String,
        seq: i64,
        event_id: String,
        message: Option<Arc<ServerJsonRpcMessage>>,
        created_at: i64,
    ) {
        let mut state = self.state.lock().await;
        let queue = state
            .streams
            .entry(stream_id.clone())
            .or_insert_with(|| VecDeque::with_capacity(self.config.max_events));
        if queue.len() >= self.config.max_events {
            queue.pop_front();
        }
        queue.push_back(StoredEvent {
            seq,
            event_id,
            message,
            created_at,
        });
        touch_stream(&mut state.order, &stream_id);
        trim_streams(&mut state, self.config.max_streams);
        prune_expired(&mut state, self.config.ttl);
    }

    async fn replay_after(&self, stream_id: String, last_seq: i64) -> Vec<StoredRow> {
        let mut state = self.state.lock().await;
        prune_expired(&mut state, self.config.ttl);
        let Some(queue) = state.streams.get(&stream_id) else {
            return Vec::new();
        };
        queue
            .iter()
            .filter(|event| event.seq > last_seq)
            .map(|event| {
                let payload = match event.message.as_ref() {
                    Some(message) => serde_json::to_string(message.as_ref()).ok(),
                    None => None,
                };
                StoredRow {
                    event_id: event.event_id.clone(),
                    payload,
                }
            })
            .collect()
    }
}

/// Session statistics snapshot.
///
/// # Errors
/// None.
///
/// # Security
/// Intended for observability only; do not expose externally without auth.
///
/// # Panics
/// None.
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub active_sessions: usize,
    pub max_sessions: usize,
    pub resume_enabled: bool,
    pub lifecycle_mode: SessionLifecycleMode,
    pub lifecycle_connected_streams: u32,
    pub lifecycle_disconnected_sessions: usize,
    pub lifecycle_expired_sessions_total: u64,
}

/// Session lifecycle modes for bounded session management.
///
/// # Errors
/// None.
///
/// # Security
/// Connected mode prevents active-stream expiry but still requires bounded
/// disconnected cleanup configuration.
///
/// # Panics
/// None.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLifecycleMode {
    LegacyKeepAlive,
    ConnectedUnboundedDisconnectedIdle,
}

/// Lifecycle configuration for streamable HTTP sessions.
///
/// # Errors
/// None.
///
/// # Security
/// Prefer finite disconnected idle timeouts to avoid stale session buildup.
///
/// # Panics
/// None.
#[derive(Debug, Clone)]
pub struct SessionLifecycleConfig {
    pub mode: SessionLifecycleMode,
    pub disconnected_idle_timeout: Option<Duration>,
}

impl Default for SessionLifecycleConfig {
    fn default() -> Self {
        Self {
            mode: SessionLifecycleMode::LegacyKeepAlive,
            disconnected_idle_timeout: None,
        }
    }
}

impl SessionLifecycleConfig {
    /// Build connected-aware lifecycle config.
    ///
    /// # Errors
    /// None.
    ///
    /// # Security
    /// Provide a finite timeout to bound disconnected session retention.
    ///
    /// # Panics
    /// None.
    pub fn connected(disconnected_idle_timeout: Option<Duration>) -> Self {
        Self {
            mode: SessionLifecycleMode::ConnectedUnboundedDisconnectedIdle,
            disconnected_idle_timeout,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SessionLifecycleState {
    active_streams: u32,
    last_activity_s: u64,
    disconnected_since_s: Option<u64>,
}

#[derive(Debug)]
struct SessionLifecycleRuntime {
    config: SessionLifecycleConfig,
    states: HashMap<SessionId, SessionLifecycleState>,
    expired_sessions_total: u64,
    last_sweep_s: u64,
}

impl SessionLifecycleRuntime {
    fn new(config: SessionLifecycleConfig) -> Self {
        Self {
            config,
            states: HashMap::new(),
            expired_sessions_total: 0,
            last_sweep_s: 0,
        }
    }
}

/// Session manager that bounds the number of concurrent sessions.
///
/// # Errors
/// Errors propagate from the underlying session manager.
///
/// # Security
/// Bounding sessions limits memory pressure and mitigates DoS risk.
///
/// # Panics
/// None.
#[derive(Debug)]
pub struct BoundedSessionManager {
    inner: LocalSessionManager,
    max_sessions: usize,
    allow_resume: bool,
    order: RwLock<VecDeque<SessionId>>,
    lifecycle: StdMutex<SessionLifecycleRuntime>,
}

/// Errors raised by the bounded session manager.
///
/// # Errors
/// This type wraps inner session manager errors and resume disablement.
///
/// # Security
/// Surface errors to logs only; client responses should be sanitized.
///
/// # Panics
/// None.
#[derive(Debug)]
pub enum BoundedSessionManagerError {
    Inner(LocalSessionManagerError),
    ResumeDisabled,
}

impl std::fmt::Display for BoundedSessionManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inner(err) => write!(f, "session manager error: {err}"),
            Self::ResumeDisabled => write!(f, "event resume is disabled"),
        }
    }
}

impl std::error::Error for BoundedSessionManagerError {}

impl From<LocalSessionManagerError> for BoundedSessionManagerError {
    fn from(err: LocalSessionManagerError) -> Self {
        Self::Inner(err)
    }
}

impl BoundedSessionManager {
    const DEFAULT_LIFECYCLE_SWEEP_INTERVAL_S: u64 = 5;

    fn lifecycle_lock(&self) -> std::sync::MutexGuard<'_, SessionLifecycleRuntime> {
        match self.lifecycle.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    "session lifecycle state lock poisoned; continuing with inner state"
                );
                poisoned.into_inner()
            }
        }
    }

    /// Create a new bounded session manager.
    ///
    /// # Errors
    /// None.
    ///
    /// # Security
    /// Ensure `max_sessions` is sized to prevent session exhaustion.
    ///
    /// # Panics
    /// None.
    pub fn new(
        inner: LocalSessionManager,
        max_sessions: usize,
        allow_resume: bool,
        session_config: SessionConfig,
    ) -> Self {
        Self::new_with_lifecycle(
            inner,
            max_sessions,
            allow_resume,
            session_config,
            SessionLifecycleConfig::default(),
        )
    }

    /// Create a new bounded session manager with lifecycle policy controls.
    ///
    /// # Errors
    /// None.
    ///
    /// # Security
    /// Prefer finite disconnected idle timeouts for connected-aware mode.
    ///
    /// # Panics
    /// None.
    pub fn new_with_lifecycle(
        mut inner: LocalSessionManager,
        max_sessions: usize,
        allow_resume: bool,
        session_config: SessionConfig,
        lifecycle_config: SessionLifecycleConfig,
    ) -> Self {
        inner.session_config = session_config;
        Self {
            inner,
            max_sessions: max_sessions.max(1),
            allow_resume,
            order: RwLock::new(VecDeque::new()),
            lifecycle: StdMutex::new(SessionLifecycleRuntime::new(lifecycle_config)),
        }
    }

    async fn record_session(&self, session_id: &SessionId) -> Option<SessionId> {
        let mut order = self.order.write().await;
        order.push_back(session_id.clone());
        if order.len() > self.max_sessions {
            return order.pop_front();
        }
        None
    }

    async fn remove_session(&self, session_id: &SessionId) {
        let mut order = self.order.write().await;
        if let Some(pos) = order
            .iter()
            .position(|id| id.as_ref() == session_id.as_ref())
        {
            order.remove(pos);
        }
        drop(order);
        let mut lifecycle = self.lifecycle_lock();
        lifecycle.states.remove(session_id);
    }

    async fn close_evicted(&self, session_id: SessionId) {
        if let Err(err) = self.inner.close_session(&session_id).await {
            tracing::warn!(error = %err, session_id = %session_id, "failed to close evicted session");
        }
        self.remove_session(&session_id).await;
    }

    fn touch_session_activity(&self, session_id: &SessionId, now_s: u64) {
        let mut lifecycle = self.lifecycle_lock();
        let state = lifecycle
            .states
            .entry(session_id.clone())
            .or_insert(SessionLifecycleState {
                active_streams: 0,
                last_activity_s: now_s,
                disconnected_since_s: Some(now_s),
            });
        state.last_activity_s = now_s;
        if state.active_streams == 0 {
            state.disconnected_since_s = Some(now_s);
        }
    }

    fn mark_stream_open(&self, session_id: &SessionId, now_s: u64) {
        let mut lifecycle = self.lifecycle_lock();
        let state = lifecycle
            .states
            .entry(session_id.clone())
            .or_insert(SessionLifecycleState {
                active_streams: 0,
                last_activity_s: now_s,
                disconnected_since_s: Some(now_s),
            });
        state.active_streams = state.active_streams.saturating_add(1);
        state.last_activity_s = now_s;
        state.disconnected_since_s = None;
    }

    fn mark_stream_closed(&self, session_id: &SessionId, now_s: u64) {
        let mut lifecycle = self.lifecycle_lock();
        let Some(state) = lifecycle.states.get_mut(session_id) else {
            return;
        };
        state.active_streams = state.active_streams.saturating_sub(1);
        state.last_activity_s = now_s;
        if state.active_streams == 0 {
            state.disconnected_since_s = Some(now_s);
        }
    }

    fn disconnected_session_should_expire(&self, session_id: &SessionId, now_s: u64) -> bool {
        let lifecycle = self.lifecycle_lock();
        if lifecycle.config.mode != SessionLifecycleMode::ConnectedUnboundedDisconnectedIdle {
            return false;
        }
        let Some(timeout) = lifecycle.config.disconnected_idle_timeout else {
            return false;
        };
        let Some(state) = lifecycle.states.get(session_id) else {
            return false;
        };
        if state.active_streams > 0 {
            return false;
        }
        let Some(disconnected_since_s) = state.disconnected_since_s else {
            return false;
        };
        now_s.saturating_sub(disconnected_since_s) >= timeout.as_secs()
    }

    fn note_session_expired(&self, session_id: &SessionId) {
        let mut lifecycle = self.lifecycle_lock();
        lifecycle.states.remove(session_id);
        lifecycle.expired_sessions_total = lifecycle.expired_sessions_total.saturating_add(1);
    }

    async fn sweep_disconnected_sessions(&self, now_s: u64) {
        let maybe_to_expire = {
            let mut lifecycle = self.lifecycle_lock();
            if lifecycle.config.mode != SessionLifecycleMode::ConnectedUnboundedDisconnectedIdle {
                return;
            }
            let Some(timeout) = lifecycle.config.disconnected_idle_timeout else {
                return;
            };
            if now_s.saturating_sub(lifecycle.last_sweep_s)
                < Self::DEFAULT_LIFECYCLE_SWEEP_INTERVAL_S
            {
                return;
            }
            lifecycle.last_sweep_s = now_s;
            Some(
                lifecycle
                    .states
                    .iter()
                    .filter_map(|(session_id, state)| {
                        if state.active_streams > 0 {
                            return None;
                        }
                        let disconnected_since_s = state.disconnected_since_s?;
                        if now_s.saturating_sub(disconnected_since_s) >= timeout.as_secs() {
                            return Some(session_id.clone());
                        }
                        None
                    })
                    .collect::<Vec<_>>(),
            )
        };

        let Some(to_expire) = maybe_to_expire else {
            return;
        };

        for session_id in to_expire {
            match self.inner.close_session(&session_id).await {
                Ok(()) => {
                    self.remove_session(&session_id).await;
                    self.note_session_expired(&session_id);
                }
                Err(err) => {
                    tracing::debug!(
                        error = %err,
                        session_id = %session_id,
                        "lifecycle sweeper failed to close session"
                    );
                }
            }
        }
    }

    /// Run a disconnected-idle lifecycle sweep using current wall clock time.
    ///
    /// # Errors
    /// None. Sweep failures for individual sessions are logged and skipped.
    ///
    /// # Security
    /// Connected sessions are never expired by this sweep.
    ///
    /// # Panics
    /// None.
    pub async fn sweep_expired_sessions(&self) {
        self.sweep_disconnected_sessions(current_epoch_seconds())
            .await;
    }

    /// Return a snapshot of session statistics.
    ///
    /// # Errors
    /// None.
    ///
    /// # Security
    /// Expose only to authenticated operators.
    ///
    /// # Panics
    /// None.
    pub async fn stats(&self) -> SessionStats {
        let order = self.order.read().await;
        let lifecycle = self.lifecycle_lock();
        let lifecycle_connected_streams: u32 = lifecycle
            .states
            .values()
            .map(|state| state.active_streams)
            .sum();
        let lifecycle_disconnected_sessions = lifecycle
            .states
            .values()
            .filter(|state| state.active_streams == 0)
            .count();
        SessionStats {
            active_sessions: order.len(),
            max_sessions: self.max_sessions,
            resume_enabled: self.allow_resume,
            lifecycle_mode: lifecycle.config.mode,
            lifecycle_connected_streams,
            lifecycle_disconnected_sessions,
            lifecycle_expired_sessions_total: lifecycle.expired_sessions_total,
        }
    }
}

impl SessionManager for BoundedSessionManager {
    type Error = BoundedSessionManagerError;
    type Transport = <LocalSessionManager as SessionManager>::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        let now_s = current_epoch_seconds();
        self.sweep_disconnected_sessions(now_s).await;
        let (session_id, transport) = self.inner.create_session().await?;
        if let Some(evicted) = self.record_session(&session_id).await {
            self.close_evicted(evicted).await;
        }
        self.touch_session_activity(&session_id, now_s);
        Ok((session_id, transport))
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        let response = self.inner.initialize_session(id, message).await?;
        self.touch_session_activity(id, current_epoch_seconds());
        Ok(response)
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        let now_s = current_epoch_seconds();
        self.sweep_disconnected_sessions(now_s).await;
        let exists = self.inner.has_session(id).await?;
        if !exists {
            self.remove_session(id).await;
            return Ok(false);
        }
        if self.disconnected_session_should_expire(id, now_s) {
            match self.inner.close_session(id).await {
                Ok(()) => {
                    self.remove_session(id).await;
                    self.note_session_expired(id);
                    return Ok(false);
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        session_id = %id,
                        "failed to close disconnected idle session"
                    );
                }
            }
        }
        Ok(true)
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.inner.close_session(id).await?;
        self.remove_session(id).await;
        Ok(())
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        let stream = self.inner.create_stream(id, message).await?;
        self.touch_session_activity(id, current_epoch_seconds());
        Ok(stream)
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        self.inner.accept_message(id, message).await?;
        self.touch_session_activity(id, current_epoch_seconds());
        Ok(())
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        let stream = self.inner.create_standalone_stream(id).await?;
        self.touch_session_activity(id, current_epoch_seconds());
        Ok(stream)
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        let stream: Pin<Box<dyn Stream<Item = ServerSseMessage> + Send + Sync>> =
            if !self.allow_resume {
                Box::pin(self.inner.create_standalone_stream(id).await?)
            } else {
                Box::pin(self.inner.resume(id, last_event_id).await?)
            };
        self.touch_session_activity(id, current_epoch_seconds());
        Ok(stream)
    }
}

type BoxServerSseStream = Pin<Box<dyn Stream<Item = ServerSseMessage> + Send + Sync + 'static>>;

struct LifecycleTrackedStream {
    inner: BoxServerSseStream,
    manager: Arc<BoundedSessionManager>,
    session_id: SessionId,
    closed: bool,
}

impl LifecycleTrackedStream {
    fn new(
        manager: Arc<BoundedSessionManager>,
        session_id: SessionId,
        inner: BoxServerSseStream,
    ) -> Self {
        manager.mark_stream_open(&session_id, current_epoch_seconds());
        Self {
            inner,
            manager,
            session_id,
            closed: false,
        }
    }

    fn close_once(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.manager
            .mark_stream_closed(&self.session_id, current_epoch_seconds());
    }
}

impl Drop for LifecycleTrackedStream {
    fn drop(&mut self) {
        self.close_once();
    }
}

impl Stream for LifecycleTrackedStream {
    type Item = ServerSseMessage;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(cx) {
            std::task::Poll::Ready(None) => {
                self.close_once();
                std::task::Poll::Ready(None)
            }
            other => other,
        }
    }
}

/// Session manager wrapper that records outbound SSE events for replay.
///
/// # Errors
/// Errors propagate from the inner session manager.
///
/// # Security
/// Recorded events may contain sensitive output; use strict retention limits.
///
/// # Panics
/// None.
#[derive(Debug, Clone)]
pub struct RecordingSessionManager {
    inner: Arc<BoundedSessionManager>,
    event_store: Option<EventStore>,
}

impl RecordingSessionManager {
    /// Create a new recording session manager.
    ///
    /// # Errors
    /// None.
    ///
    /// # Security
    /// Keep event store limits aligned with retention policy.
    ///
    /// # Panics
    /// None.
    pub fn new(inner: Arc<BoundedSessionManager>, event_store: Option<EventStore>) -> Self {
        Self { inner, event_store }
    }

    fn record_stream(
        &self,
        session_id: SessionId,
        stream: impl Stream<Item = ServerSseMessage> + Send + Sync + 'static,
    ) -> BoxServerSseStream {
        let stream: BoxServerSseStream = match self.event_store.clone() {
            Some(event_store) => {
                let session = session_id.to_string();
                Box::pin(stream.then(move |message| {
                    let event_store = event_store.clone();
                    let session = session.clone();
                    async move {
                        if let Err(err) = event_store.store_event(&session, &message).await {
                            let error = err.to_string();
                            tracing::warn!(%error, "failed to persist streamable HTTP event");
                        }
                        message
                    }
                }))
            }
            None => Box::pin(stream),
        };
        Box::pin(LifecycleTrackedStream::new(
            self.inner.clone(),
            session_id,
            stream,
        ))
    }
}

impl SessionManager for RecordingSessionManager {
    type Error = BoundedSessionManagerError;
    type Transport = <BoundedSessionManager as SessionManager>::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        self.inner.create_session().await
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        self.inner.initialize_session(id, message).await
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        self.inner.has_session(id).await
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.inner.close_session(id).await
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        let inner = self.inner.clone();
        let session_id = id.clone();
        let stream = inner.create_stream(&session_id, message).await?;
        Ok(self.record_stream(session_id, stream))
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        self.inner.accept_message(id, message).await
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        let inner = self.inner.clone();
        let session_id = id.clone();
        let stream = inner.create_standalone_stream(&session_id).await?;
        Ok(self.record_stream(session_id, stream))
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        let inner = self.inner.clone();
        let session_id = id.clone();
        let stream = inner.resume(&session_id, last_event_id).await?;
        Ok(self.record_stream(session_id, stream))
    }
}

#[cfg(feature = "session-sqlite")]
fn serialize_message(message: &ServerSseMessage) -> Result<Option<String>, EventStoreError> {
    let Some(payload) = message.message.as_ref() else {
        return Ok(None);
    };
    serde_json::to_string(payload.as_ref())
        .map(Some)
        .map_err(|err| EventStoreError::new(err.to_string()))
}

fn parse_event_id(event_id: &str) -> Option<ParsedEventId> {
    if event_id.trim().is_empty() {
        return None;
    }
    let (index_raw, request_raw) = match event_id.split_once('/') {
        Some((index, request)) => (index, Some(request)),
        None => (event_id, None),
    };
    let index = index_raw.parse::<i64>().ok()?;
    let http_request_id = match request_raw {
        Some(raw) if !raw.trim().is_empty() => raw.parse::<u64>().ok(),
        _ => None,
    };
    Some(ParsedEventId {
        index,
        http_request_id,
    })
}

fn stream_id(session_id: &str, http_request_id: Option<u64>) -> String {
    match http_request_id {
        Some(id) => format!("{session_id}|req:{id}"),
        None => format!("{session_id}|common"),
    }
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn touch_stream(order: &mut VecDeque<String>, stream_id: &str) {
    if let Some(pos) = order.iter().position(|id| id == stream_id) {
        order.remove(pos);
    }
    order.push_back(stream_id.to_string());
}

fn trim_streams(state: &mut MemoryState, max_streams: usize) {
    while state.order.len() > max_streams {
        if let Some(evicted) = state.order.pop_front() {
            state.streams.remove(&evicted);
        }
    }
}

fn prune_expired(state: &mut MemoryState, ttl: Option<Duration>) {
    let Some(ttl) = ttl else {
        return;
    };
    let cutoff = current_epoch_seconds() as i64 - ttl.as_secs() as i64;
    state.streams.retain(|stream_id, queue| {
        queue.retain(|event| event.created_at >= cutoff);
        if queue.is_empty() {
            if let Some(pos) = state.order.iter().position(|id| id == stream_id) {
                state.order.remove(pos);
            }
            return false;
        }
        true
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_connected_manager(timeout_s: u64) -> BoundedSessionManager {
        BoundedSessionManager::new_with_lifecycle(
            LocalSessionManager::default(),
            8,
            true,
            SessionConfig::default(),
            SessionLifecycleConfig::connected(Some(Duration::from_secs(timeout_s))),
        )
    }

    #[test]
    fn connected_lifecycle_config_sets_mode_and_timeout() {
        let config = SessionLifecycleConfig::connected(Some(Duration::from_secs(120)));
        assert_eq!(
            config.mode,
            SessionLifecycleMode::ConnectedUnboundedDisconnectedIdle
        );
        assert_eq!(
            config.disconnected_idle_timeout,
            Some(Duration::from_secs(120))
        );
    }

    #[test]
    fn disconnected_session_expires_after_idle_timeout() {
        let manager = make_connected_manager(30);
        let session_id: SessionId = "session-a".into();
        manager.touch_session_activity(&session_id, 100);
        assert!(!manager.disconnected_session_should_expire(&session_id, 129));
        assert!(manager.disconnected_session_should_expire(&session_id, 130));
    }

    #[test]
    fn connected_stream_prevents_disconnected_idle_expiry() {
        let manager = make_connected_manager(10);
        let session_id: SessionId = "session-b".into();
        manager.touch_session_activity(&session_id, 50);
        manager.mark_stream_open(&session_id, 51);
        assert!(!manager.disconnected_session_should_expire(&session_id, 5_000));
        manager.mark_stream_closed(&session_id, 5_001);
        assert!(!manager.disconnected_session_should_expire(&session_id, 5_010));
        assert!(manager.disconnected_session_should_expire(&session_id, 5_011));
    }

    #[tokio::test]
    async fn manual_sweep_expires_disconnected_idle_session() {
        let manager = make_connected_manager(1);
        let (session_id, _transport) = manager
            .create_session()
            .await
            .expect("create session for sweep test");
        manager.touch_session_activity(&session_id, 0);
        manager.sweep_expired_sessions().await;
        let exists = manager
            .has_session(&session_id)
            .await
            .expect("check session after sweep");
        assert!(!exists);
        let stats = manager.stats().await;
        assert_eq!(stats.lifecycle_expired_sessions_total, 1);
    }

    #[cfg(not(feature = "session-sqlite"))]
    #[test]
    fn event_store_encryption_requires_session_sqlite_feature() {
        let err = EventStoreEncryption::from_bytes(&[7u8; 32])
            .expect_err("encryption should fail without session-sqlite support");
        assert_eq!(
            err.to_string(),
            "event store error: event store encryption requires session-sqlite feature"
        );
    }
}
