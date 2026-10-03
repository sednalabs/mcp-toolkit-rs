//! # RMCP Native Event Store
//!
//! Bounded process-local storage for RMCP's native Streamable HTTP replay hook.
//! This is separate from the toolkit's legacy session-era event recorder.
//!
//! ## Security Boundaries
//! Replay IDs are opaque bearer capabilities. Possession permits replay of later
//! events from the stream that issued the ID, subject to the HTTP route's existing
//! authentication and Host/Origin checks. IDs are not principal-bound.

use std::{
    collections::{HashMap, VecDeque},
    io::Write,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use futures::stream;
use rmcp::transport::{
    common::server_side_http::{session_id, ServerSseMessage},
    streamable_http_server::session::{
        EventStore as RmcpEventStore, EventStoreError as RmcpError, EventStream,
    },
};

/// Positive limits for the process-local native replay store.
#[derive(Debug, Clone)]
pub struct NativeEventStoreConfig {
    pub ttl: Duration,
    pub max_streams: usize,
    pub max_events_per_stream: usize,
    pub max_stream_id_bytes: usize,
    pub max_event_id_bytes: usize,
    pub max_payload_bytes: usize,
    pub max_total_payload_bytes: usize,
}

impl Default for NativeEventStoreConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(300),
            max_streams: 1_024,
            max_events_per_stream: 256,
            max_stream_id_bytes: 256,
            max_event_id_bytes: 128,
            max_payload_bytes: 1024 * 1024,
            max_total_payload_bytes: 16 * 1024 * 1024,
        }
    }
}

impl NativeEventStoreConfig {
    fn validate(&self) -> Result<(), RmcpError> {
        if self.ttl.is_zero()
            || self.max_streams == 0
            || self.max_events_per_stream == 0
            || self.max_stream_id_bytes == 0
            || self.max_event_id_bytes == 0
            || self.max_payload_bytes == 0
            || self.max_total_payload_bytes == 0
        {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native event store limits must be positive",
            )));
        }
        if self.max_payload_bytes > self.max_total_payload_bytes
            || self.max_streams > 100_000
            || self.max_events_per_stream > 100_000
            || self.max_stream_id_bytes > 4_096
            || self.max_event_id_bytes > 4_096
            || self.max_payload_bytes > 64 * 1024 * 1024
            || self.max_total_payload_bytes > 1024 * 1024 * 1024
        {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native event store limits exceed their maximum values",
            )));
        }
        Ok(())
    }
}

/// RMCP-native bounded process-local event store.
#[derive(Debug, Clone)]
pub struct NativeEventStore {
    config: Arc<NativeEventStoreConfig>,
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Default)]
struct State {
    streams: HashMap<String, StreamEvents>,
    stream_order: VecDeque<String>,
    anchors: HashMap<String, Anchor>,
    total_payload_bytes: usize,
}

#[derive(Debug)]
struct StreamEvents {
    events: VecDeque<StoredEvent>,
    touched: Instant,
}

#[derive(Debug, Clone)]
struct StoredEvent {
    id: String,
    message: ServerSseMessage,
    created: Instant,
    payload_bytes: usize,
}

#[derive(Debug, Clone)]
struct Anchor {
    stream_id: String,
    created: Instant,
}

impl NativeEventStore {
    /// Create a new bounded native event store.
    ///
    /// # Errors
    /// Returns an error when a configured limit is invalid or exceeds its cap.
    pub fn new(config: NativeEventStoreConfig) -> Result<Self, RmcpError> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            state: Arc::new(Mutex::new(State::default())),
        })
    }

    fn payload_bytes(event: &ServerSseMessage) -> Result<usize, RmcpError> {
        #[derive(serde::Serialize)]
        struct Encoded<'a> {
            message: Option<&'a ServerJsonRpcMessage>,
            retry_seconds: Option<u64>,
            retry_nanos: Option<u32>,
        }
        let encoded = Encoded {
            message: event.message.as_deref(),
            retry_seconds: event.retry.map(|value| value.as_secs()),
            retry_nanos: event.retry.map(|value| value.subsec_nanos()),
        };
        struct ByteCounter(usize);
        impl Write for ByteCounter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_add(bytes.len())
                    .ok_or_else(|| std::io::Error::other("payload byte count overflow"))?;
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut counter = ByteCounter(0);
        serde_json::to_writer(&mut counter, &encoded)
            .map_err(|error| Box::new(error) as RmcpError)?;
        Ok(counter.0)
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, RmcpError> {
        self.state.lock().map_err(|_| {
            Box::new(std::io::Error::other("native event store lock poisoned")) as RmcpError
        })
    }

    fn expire(state: &mut State, ttl: Duration) -> Result<(), RmcpError> {
        let now = Instant::now();
        let stream_ids: Vec<_> = state.streams.keys().cloned().collect();
        for stream_id in stream_ids {
            loop {
                let should_expire = state
                    .streams
                    .get(&stream_id)
                    .and_then(|stream| stream.events.front())
                    .is_some_and(|event| now.saturating_duration_since(event.created) >= ttl);
                if !should_expire {
                    break;
                }
                Self::remove_oldest_in_stream(state, &stream_id)?;
            }
        }
        let expired_streams: Vec<_> = state
            .streams
            .iter()
            .filter(|(_, stream)| now.saturating_duration_since(stream.touched) >= ttl)
            .map(|(id, _)| id.clone())
            .collect();
        for stream_id in expired_streams {
            Self::remove_stream(state, &stream_id)?;
        }
        state
            .anchors
            .retain(|_, anchor| now.saturating_duration_since(anchor.created) < ttl);
        Ok(())
    }

    fn remove_stream(state: &mut State, stream_id: &str) -> Result<(), RmcpError> {
        if let Some(stream) = state.streams.remove(stream_id) {
            let bytes = stream
                .events
                .iter()
                .try_fold(0usize, |total, event| {
                    total.checked_add(event.payload_bytes)
                })
                .ok_or_else(|| {
                    Box::new(std::io::Error::other(
                        "native event byte accounting overflow",
                    )) as RmcpError
                })?;
            state.total_payload_bytes =
                state
                    .total_payload_bytes
                    .checked_sub(bytes)
                    .ok_or_else(|| {
                        Box::new(std::io::Error::other(
                            "native event byte accounting underflow",
                        )) as RmcpError
                    })?;
        }
        state.stream_order.retain(|id| id != stream_id);
        state
            .anchors
            .retain(|_, anchor| anchor.stream_id != stream_id);
        Ok(())
    }

    fn remove_oldest_in_stream(state: &mut State, stream_id: &str) -> Result<bool, RmcpError> {
        let mut removed = None;
        let mut remove_stream = false;
        if let Some(stream) = state.streams.get_mut(stream_id) {
            removed = stream.events.pop_front();
            remove_stream = stream.events.is_empty();
        }
        let Some(event) = removed else {
            return Ok(false);
        };
        state.total_payload_bytes = state
            .total_payload_bytes
            .checked_sub(event.payload_bytes)
            .ok_or_else(|| {
                Box::new(std::io::Error::other(
                    "native event byte accounting underflow",
                )) as RmcpError
            })?;
        state.anchors.remove(&event.id);
        if remove_stream {
            Self::remove_stream(state, stream_id)?;
        }
        Ok(true)
    }

    fn remove_oldest_event(state: &mut State) -> Result<bool, RmcpError> {
        let oldest_stream = state
            .streams
            .iter()
            .filter_map(|(id, stream)| stream.events.front().map(|event| (id, event.created)))
            .min_by_key(|(_, created)| *created)
            .map(|(id, _)| id.clone());
        let Some(stream_id) = oldest_stream else {
            return Ok(false);
        };
        Self::remove_oldest_in_stream(state, &stream_id)
    }
}

#[async_trait::async_trait]
impl RmcpEventStore for NativeEventStore {
    async fn store_event(
        &self,
        stream_id: &str,
        event: &ServerSseMessage,
    ) -> Result<String, RmcpError> {
        if stream_id.is_empty() || stream_id.len() > self.config.max_stream_id_bytes {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid stream ID",
            )));
        }
        let payload_bytes = Self::payload_bytes(event)?;
        if payload_bytes > self.config.max_payload_bytes {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "event payload exceeds configured limit",
            )));
        }
        let id = session_id().to_string();
        if id.len() > self.config.max_event_id_bytes {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "generated event ID exceeds configured limit",
            )));
        }
        let now = Instant::now();
        let mut state = self.lock()?;
        Self::expire(&mut state, self.config.ttl)?;
        if state.anchors.contains_key(&id) {
            return Err(Box::new(std::io::Error::other(
                "generated event ID collision",
            )));
        }
        if !state.streams.contains_key(stream_id) {
            while state.streams.len() >= self.config.max_streams {
                if let Some(evicted) = state.stream_order.pop_front() {
                    Self::remove_stream(&mut state, &evicted)?;
                } else {
                    break;
                }
            }
            state.stream_order.push_back(stream_id.to_owned());
            state.streams.insert(
                stream_id.to_owned(),
                StreamEvents {
                    events: VecDeque::new(),
                    touched: now,
                },
            );
        }
        let mut evicted_ids = Vec::new();
        {
            let stream = state.streams.get_mut(stream_id).ok_or_else(|| {
                Box::new(std::io::Error::other("native event stream disappeared")) as RmcpError
            })?;
            stream.touched = now;
            while stream.events.len() >= self.config.max_events_per_stream {
                if let Some(evicted) = stream.events.pop_front() {
                    evicted_ids.push((evicted.id, evicted.payload_bytes));
                }
            }
        }
        for (evicted_id, bytes) in evicted_ids {
            state.total_payload_bytes =
                state
                    .total_payload_bytes
                    .checked_sub(bytes)
                    .ok_or_else(|| {
                        Box::new(std::io::Error::other(
                            "native event byte accounting underflow",
                        )) as RmcpError
                    })?;
            state.anchors.remove(&evicted_id);
        }
        let available_bytes = self.config.max_total_payload_bytes - payload_bytes;
        while state.total_payload_bytes > available_bytes {
            if !Self::remove_oldest_event(&mut state)? {
                return Err(Box::new(std::io::Error::other(
                    "native event store byte limit cannot be satisfied",
                )));
            }
        }
        if !state.streams.contains_key(stream_id) {
            state.stream_order.push_back(stream_id.to_owned());
            state.streams.insert(
                stream_id.to_owned(),
                StreamEvents {
                    events: VecDeque::new(),
                    touched: now,
                },
            );
        }
        let stream = state.streams.get_mut(stream_id).ok_or_else(|| {
            Box::new(std::io::Error::other("native event stream disappeared")) as RmcpError
        })?;
        stream.touched = now;
        let mut stored = event.clone();
        stored.event_id = Some(id.clone());
        stream.events.push_back(StoredEvent {
            id: id.clone(),
            message: stored,
            created: now,
            payload_bytes,
        });
        state.anchors.insert(
            id.clone(),
            Anchor {
                stream_id: stream_id.to_owned(),
                created: now,
            },
        );
        state.total_payload_bytes = state
            .total_payload_bytes
            .checked_add(payload_bytes)
            .ok_or_else(|| {
                Box::new(std::io::Error::other(
                    "native event byte accounting overflow",
                )) as RmcpError
            })?;
        Ok(id)
    }

    async fn replay_events_after(&self, last_event_id: &str) -> Result<EventStream, RmcpError> {
        if last_event_id.is_empty() || last_event_id.len() > self.config.max_event_id_bytes {
            return Ok(Box::pin(stream::empty()) as EventStream);
        }
        let mut state = self.lock()?;
        Self::expire(&mut state, self.config.ttl)?;
        let Some(anchor) = state.anchors.get(last_event_id).cloned() else {
            return Ok(Box::pin(stream::empty()) as EventStream);
        };
        let Some(events) = state.streams.get(&anchor.stream_id) else {
            return Ok(Box::pin(stream::empty()) as EventStream);
        };
        let mut after_anchor = false;
        let replay = events
            .events
            .iter()
            .filter_map(|event| {
                if after_anchor {
                    Some(event.message.clone())
                } else {
                    after_anchor = event.id == last_event_id;
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(Box::pin(stream::iter(replay)) as EventStream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn config() -> NativeEventStoreConfig {
        NativeEventStoreConfig {
            max_streams: 2,
            max_events_per_stream: 3,
            ..NativeEventStoreConfig::default()
        }
    }

    #[tokio::test]
    async fn replay_is_ordered_later_only_and_stream_scoped() {
        let store = NativeEventStore::new(config()).expect("valid limits");
        let first = store
            .store_event("stream-a", &ServerSseMessage::retry(Duration::from_secs(2)))
            .await
            .expect("first event");
        let _other = store
            .store_event("stream-b", &ServerSseMessage::retry(Duration::from_secs(3)))
            .await
            .expect("interleaved event");
        let second = store
            .store_event(
                "stream-a",
                &ServerSseMessage::priming("placeholder", Duration::from_secs(4)),
            )
            .await
            .expect("second event");

        let replay = store
            .replay_events_after(&first)
            .await
            .expect("replay stream")
            .collect::<Vec<_>>()
            .await;
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].event_id.as_deref(), Some(second.as_str()));
        assert_eq!(replay[0].message, None);
        assert_eq!(replay[0].retry, Some(Duration::from_secs(4)));

        let at_end = store
            .replay_events_after(&second)
            .await
            .expect("known final anchor")
            .collect::<Vec<_>>()
            .await;
        assert!(at_end.is_empty());
        let unknown = store
            .replay_events_after("unknown")
            .await
            .expect("unknown anchor is unavailable")
            .collect::<Vec<_>>()
            .await;
        assert!(unknown.is_empty());
    }

    #[tokio::test]
    async fn store_enforces_payload_stream_and_count_bounds() {
        let config = NativeEventStoreConfig {
            max_streams: 1,
            max_events_per_stream: 1,
            max_payload_bytes: 1,
            ..config()
        };
        let store = NativeEventStore::new(config).expect("valid limits");
        assert!(store
            .store_event("stream-a", &ServerSseMessage::retry(Duration::from_secs(1)))
            .await
            .is_err());

        let config = NativeEventStoreConfig {
            max_streams: 1,
            max_events_per_stream: 1,
            ..config()
        };
        let store = NativeEventStore::new(config).expect("valid limits");
        let first = store
            .store_event("stream-a", &ServerSseMessage::retry(Duration::from_secs(1)))
            .await
            .expect("first event");
        store
            .store_event("stream-a", &ServerSseMessage::retry(Duration::from_secs(2)))
            .await
            .expect("second event evicts first");
        let unavailable = store
            .replay_events_after(&first)
            .await
            .expect("evicted anchors return empty");
        assert!(unavailable.collect::<Vec<_>>().await.is_empty());

        store
            .store_event("stream-b", &ServerSseMessage::retry(Duration::from_secs(3)))
            .await
            .expect("second stream evicts first stream");
        let unavailable = store
            .replay_events_after(&first)
            .await
            .expect("evicted stream anchors return empty");
        assert!(unavailable.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn byte_budget_evicts_old_events_and_their_anchors() {
        let store = NativeEventStore::new(NativeEventStoreConfig {
            max_payload_bytes: 90,
            max_total_payload_bytes: 90,
            max_streams: 2,
            max_events_per_stream: 3,
            ..NativeEventStoreConfig::default()
        })
        .expect("valid limits");
        let first = store
            .store_event("stream-a", &ServerSseMessage::retry(Duration::from_secs(1)))
            .await
            .expect("first event");
        store
            .store_event("stream-b", &ServerSseMessage::retry(Duration::from_secs(2)))
            .await
            .expect("second event exceeds combined byte budget");
        let unavailable = store
            .replay_events_after(&first)
            .await
            .expect("byte-evicted anchor is unavailable");
        assert!(unavailable.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn concurrent_appends_assign_distinct_ids() {
        let store = Arc::new(NativeEventStore::new(config()).expect("valid limits"));
        let mut appends = Vec::new();
        for _ in 0..32 {
            let store = store.clone();
            appends.push(tokio::spawn(async move {
                store
                    .store_event("shared", &ServerSseMessage::retry(Duration::from_secs(1)))
                    .await
                    .expect("append event")
            }));
        }
        let mut ids = Vec::new();
        for append in appends {
            ids.push(append.await.expect("append task"));
        }
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 32);
    }

    #[tokio::test]
    async fn ttl_and_identifier_bounds_remove_replay_capabilities() {
        let store = NativeEventStore::new(NativeEventStoreConfig {
            ttl: Duration::from_millis(5),
            ..config()
        })
        .expect("valid limits");
        let id = store
            .store_event("stream", &ServerSseMessage::retry(Duration::from_secs(1)))
            .await
            .expect("event");
        tokio::time::sleep(Duration::from_millis(10)).await;
        let expired = store
            .replay_events_after(&id)
            .await
            .expect("expired anchor is unavailable");
        assert!(expired.collect::<Vec<_>>().await.is_empty());

        let short_id_store = NativeEventStore::new(NativeEventStoreConfig {
            max_event_id_bytes: 8,
            ..config()
        })
        .expect("positive limits");
        assert!(short_id_store
            .store_event("stream", &ServerSseMessage::retry(Duration::from_secs(1)))
            .await
            .is_err());
    }
}
