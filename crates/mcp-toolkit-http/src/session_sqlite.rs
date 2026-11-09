//! # SQLite Event Store
//!
//! Durable storage for SSE event replay.
//!
//! ## Ownership
//! This module owns the SQLite-backed storage implementation, managing event
//! persistence, expiration, and encryption for streamable HTTP session replay.
//!
//! ## Non-ownership
//! This module does not manage higher-level session lifecycle or transport protocols.
//! It assumes the calling `EventStore` has properly initialized the database and
//! enforced retention policies.
//!
//! ## Policy & Guarantees
//! * **Best-Effort Persistence**: Prunes data based on configurable TTL and retention
//!   limits to mitigate database growth.
//! * **Optional Encryption**: Provides best-effort AES-256-GCM encryption for stored payloads
//!   to reduce the risk of credential exposure at rest.
//! * **Database Durability**: Uses SQLite WAL mode to improve performance and consistency.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Ensuring filesystem-level security (ACLs) for the database file.
//! * Properly managing keys for event payload encryption.
//! * Providing a consistent path for the SQLite database.
//!
//! ## References
//! * [MCP Streamable HTTP Transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use getrandom::fill;
use rusqlite::{params, Connection};
use tokio::sync::{mpsc, oneshot};

use crate::session::{EventStoreConfig, EventStoreError, StoredRow};

const ENC_PREFIX: &str = "enc:v1:";

/// SQLite-backed store for SSE event persistence and replay.
#[derive(Debug)]
pub struct SqliteEventStore {
    sender: mpsc::Sender<SqliteCommand>,
}

impl SqliteEventStore {
    /// Creates a new `SqliteEventStore` and initializes the background worker.
    pub fn new(path: String, config: EventStoreConfig) -> Result<Self, EventStoreError> {
        initialize_db(&path).map_err(|err| EventStoreError::new(err.to_string()))?;
        let (sender, receiver) = mpsc::channel(512);
        thread::spawn(move || {
            if let Err(err) = run_worker(path, config, receiver) {
                tracing::error!(error = %err, "sqlite event store worker stopped");
            }
        });
        Ok(Self { sender })
    }

    pub(crate) async fn store_event(
        &self,
        stream_id: String,
        seq: i64,
        event_id: String,
        payload: Option<String>,
        created_at: i64,
    ) -> Result<(), EventStoreError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(SqliteCommand::Store {
                stream_id,
                seq,
                event_id,
                payload,
                created_at,
                response: tx,
            })
            .await
            .map_err(|_| EventStoreError::new("event store worker unavailable"))?;
        rx.await
            .map_err(|_| EventStoreError::new("event store response dropped"))?
    }

    pub(crate) async fn replay_after(
        &self,
        stream_id: String,
        last_seq: i64,
    ) -> Result<Vec<StoredRow>, EventStoreError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(SqliteCommand::Replay {
                stream_id,
                last_seq,
                response: tx,
            })
            .await
            .map_err(|_| EventStoreError::new("event store worker unavailable"))?;
        rx.await
            .map_err(|_| EventStoreError::new("event store response dropped"))?
    }
}

impl Drop for SqliteEventStore {
    fn drop(&mut self) {
        let _ = self.sender.try_send(SqliteCommand::Shutdown);
    }
}

enum SqliteCommand {
    Store {
        stream_id: String,
        seq: i64,
        event_id: String,
        payload: Option<String>,
        created_at: i64,
        response: oneshot::Sender<Result<(), EventStoreError>>,
    },
    Replay {
        stream_id: String,
        last_seq: i64,
        response: oneshot::Sender<Result<Vec<StoredRow>, EventStoreError>>,
    },
    Shutdown,
}

fn run_worker(
    path: String,
    config: EventStoreConfig,
    mut receiver: mpsc::Receiver<SqliteCommand>,
) -> Result<(), EventStoreError> {
    let mut conn = Connection::open(path).map_err(|err| EventStoreError::new(err.to_string()))?;
    configure_db(&mut conn).map_err(|err| EventStoreError::new(err.to_string()))?;

    loop {
        let Some(command) = receiver.blocking_recv() else {
            break;
        };
        match command {
            SqliteCommand::Store {
                stream_id,
                seq,
                event_id,
                payload,
                created_at,
                response,
            } => {
                let result = store_event_sync(
                    &mut conn,
                    &config,
                    &stream_id,
                    seq,
                    &event_id,
                    payload.as_deref(),
                    created_at,
                );
                let _ = response.send(result.map_err(EventStoreError::new));
            }
            SqliteCommand::Replay {
                stream_id,
                last_seq,
                response,
            } => {
                let result = replay_events_sync(&mut conn, &config, &stream_id, last_seq)
                    .map_err(EventStoreError::new);
                let _ = response.send(result);
            }
            SqliteCommand::Shutdown => break,
        }
    }

    Ok(())
}

fn initialize_db(path: &str) -> Result<(), rusqlite::Error> {
    if path != ":memory:" {
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
    }
    let mut conn = Connection::open(path)?;
    configure_db(&mut conn)?;
    Ok(())
}

fn configure_db(conn: &mut Connection) -> Result<(), rusqlite::Error> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS mcp_event_streams (stream_id TEXT PRIMARY KEY, last_seen INTEGER NOT NULL)",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS mcp_events (stream_id TEXT NOT NULL, seq INTEGER NOT NULL, event_id TEXT NOT NULL, payload TEXT, created_at INTEGER NOT NULL, PRIMARY KEY (stream_id, seq))",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS mcp_events_created_at ON mcp_events(created_at)",
        [],
    )?;
    Ok(())
}

fn store_event_sync(
    conn: &mut Connection,
    config: &EventStoreConfig,
    stream_id: &str,
    seq: i64,
    event_id: &str,
    payload: Option<&str>,
    created_at: i64,
) -> Result<(), String> {
    let tx = conn.transaction().map_err(|err| err.to_string())?;
    let payload = maybe_encrypt_payload(config, payload)?;
    tx.execute(
        concat!(
            "INSERT INTO mcp_event_streams(stream_id, last_seen) VALUES (?1, ?2) ",
            "ON CONFLICT(stream_id) DO UPDATE SET last_seen=excluded.last_seen"
        ),
        params![stream_id, created_at],
    )
    .map_err(|err| err.to_string())?;
    tx.execute(
        concat!(
            "INSERT OR IGNORE INTO mcp_events(stream_id, seq, event_id, payload, created_at) ",
            "VALUES (?1, ?2, ?3, ?4, ?5)"
        ),
        params![stream_id, seq, event_id, payload.as_deref(), created_at],
    )
    .map_err(|err| err.to_string())?;

    prune_stream_events(&tx, stream_id, config.max_events)?;
    prune_expired(&tx, config.ttl)?;
    prune_streams(&tx, config.max_streams)?;

    tx.commit().map_err(|err| err.to_string())?;
    Ok(())
}

fn prune_stream_events(
    conn: &Connection,
    stream_id: &str,
    max_events: usize,
) -> Result<(), String> {
    let row: Option<i64> = conn
        .query_row(
            "SELECT MAX(seq) FROM mcp_events WHERE stream_id = ?1",
            params![stream_id],
            |row| row.get(0),
        )
        .map_err(|err| err.to_string())?;
    let Some(max_seq) = row else {
        return Ok(());
    };
    let cutoff = max_seq - max_events as i64;
    if cutoff <= 0 {
        return Ok(());
    }
    conn.execute(
        "DELETE FROM mcp_events WHERE stream_id = ?1 AND seq <= ?2",
        params![stream_id, cutoff],
    )
    .map_err(|err| err.to_string())?;
    Ok(())
}

fn prune_expired(conn: &Connection, ttl: Option<Duration>) -> Result<(), String> {
    let Some(ttl) = ttl else {
        return Ok(());
    };
    let now = current_epoch_seconds() as i64;
    let cutoff = now - ttl.as_secs() as i64;
    if cutoff <= 0 {
        return Ok(());
    }
    conn.execute(
        "DELETE FROM mcp_events WHERE created_at < ?1",
        params![cutoff],
    )
    .map_err(|err| err.to_string())?;
    conn.execute(
        "DELETE FROM mcp_event_streams WHERE last_seen < ?1",
        params![cutoff],
    )
    .map_err(|err| err.to_string())?;
    Ok(())
}

fn prune_streams(conn: &Connection, max_streams: usize) -> Result<(), String> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcp_event_streams", [], |row| {
            row.get(0)
        })
        .map_err(|err| err.to_string())?;
    if count <= max_streams as i64 {
        return Ok(());
    }
    let overflow = count - max_streams as i64;
    let mut stmt = conn
        .prepare("SELECT stream_id FROM mcp_event_streams ORDER BY last_seen ASC LIMIT ?1")
        .map_err(|err| err.to_string())?;
    let stream_ids: Vec<String> = stmt
        .query_map(params![overflow], |row| row.get(0))
        .map_err(|err| err.to_string())?
        .filter_map(|row| row.ok())
        .collect();
    for stream_id in stream_ids {
        conn.execute(
            "DELETE FROM mcp_events WHERE stream_id = ?1",
            params![stream_id],
        )
        .map_err(|err| err.to_string())?;
        conn.execute(
            "DELETE FROM mcp_event_streams WHERE stream_id = ?1",
            params![stream_id],
        )
        .map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn replay_events_sync(
    conn: &mut Connection,
    config: &EventStoreConfig,
    stream_id: &str,
    last_seq: i64,
) -> Result<Vec<StoredRow>, String> {
    prune_expired(conn, config.ttl)?;
    let mut stmt = conn
        .prepare(
            "SELECT event_id, payload FROM mcp_events WHERE stream_id = ?1 AND seq > ?2 ORDER BY seq ASC",
        )
        .map_err(|err| err.to_string())?;
    let rows = stmt
        .query_map(params![stream_id, last_seq], |row| {
            Ok(StoredRow {
                event_id: row.get(0)?,
                payload: row.get::<_, Option<String>>(1)?,
            })
        })
        .map_err(|err| err.to_string())?;
    let mut events = Vec::new();
    for row in rows {
        let event = row.map_err(|err| err.to_string())?;
        let payload = match event.payload {
            Some(payload) => Some(maybe_decrypt_payload(config, &payload)?),
            None => None,
        };
        events.push(StoredRow {
            event_id: event.event_id,
            payload,
        });
    }
    Ok(events)
}

fn maybe_encrypt_payload(
    config: &EventStoreConfig,
    payload: Option<&str>,
) -> Result<Option<String>, String> {
    let Some(payload) = payload else {
        return Ok(None);
    };
    let Some(encryption) = &config.encryption else {
        return Ok(Some(payload.to_string()));
    };
    let cipher = Aes256Gcm::new_from_slice(encryption.key())
        .map_err(|_| "event store encryption key is invalid".to_string())?;
    let mut nonce_bytes = [0u8; 12];
    fill(&mut nonce_bytes).map_err(|err| format!("event store nonce generation failed: {err}"))?;
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, payload.as_bytes())
        .map_err(|_| "event store encryption failed".to_string())?;
    let mut blob = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    let encoded = base64::engine::general_purpose::STANDARD.encode(blob);
    Ok(Some(format!("{ENC_PREFIX}{encoded}")))
}

fn maybe_decrypt_payload(config: &EventStoreConfig, payload: &str) -> Result<String, String> {
    let Some(encryption) = &config.encryption else {
        if payload.starts_with(ENC_PREFIX) {
            return Err("event store payload is encrypted but no key is configured".to_string());
        }
        return Ok(payload.to_string());
    };
    let Some(encoded) = payload.strip_prefix(ENC_PREFIX) else {
        return Err("event store encryption key configured but payload is plaintext".to_string());
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "event store payload base64 decode failed".to_string())?;
    if decoded.len() < 13 {
        return Err("event store payload is too short to decrypt".to_string());
    }
    let (nonce_bytes, ciphertext) = decoded.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(encryption.key())
        .map_err(|_| "event store encryption key is invalid".to_string())?;
    let nonce = Nonce::try_from(nonce_bytes)
        .map_err(|_| "event store payload nonce is invalid".to_string())?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| "event store decryption failed".to_string())?;
    String::from_utf8(plaintext).map_err(|_| "event store payload is not valid UTF-8".to_string())
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        configure_db, current_epoch_seconds, maybe_decrypt_payload, maybe_encrypt_payload,
        replay_events_sync, store_event_sync, ENC_PREFIX,
    };
    use crate::session::{EventStoreConfig, EventStoreEncryption};
    use rusqlite::Connection;
    use std::path::PathBuf;
    use std::time::Duration;

    fn config(encryption: Option<EventStoreEncryption>) -> EventStoreConfig {
        EventStoreConfig {
            max_streams: 8,
            max_events: 8,
            ttl: None,
            encryption,
        }
    }

    // Each test owns its directory; dropping connections before this guard also
    // removes SQLite's WAL and shared-memory sidecars without racing other tests.
    struct TestDatabase(PathBuf);

    impl TestDatabase {
        fn new() -> Self {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).expect("test database identifier");
            // Keep fixture paths inside the checkout instead of trusting TMPDIR.
            std::fs::create_dir_all(".tmp").expect("create test database root");
            let dir = PathBuf::from(".tmp").join(format!(
                "mcp-toolkit-sqlite-{:032x}",
                u128::from_le_bytes(random)
            ));
            std::fs::create_dir(&dir).expect("create test database directory");
            Self(dir)
        }

        fn open(&self) -> Connection {
            Connection::open(self.0.join("events.db")).expect("open test database")
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn bundled_sqlite_meets_security_floor() {
        // RUSTSEC-2026-0459 is fixed in SQLite 3.54.0. Test the linked runtime,
        // not merely Cargo metadata; the committed lock selects SQLite 3.54.1.
        assert!(
            rusqlite::version_number() >= 3_054_000,
            "SQLite {} is below the patched 3.54.0 floor",
            rusqlite::version()
        );
        let conn = Connection::open_in_memory().expect("open database");
        let sql_version: String = conn
            .query_row("SELECT sqlite_version()", [], |row| row.get(0))
            .expect("query linked SQLite version");
        assert_eq!(sql_version, rusqlite::version());
    }

    #[test]
    fn sqlite_reopen_preserves_wal_schema_replay_and_duplicate_semantics() {
        let database = TestDatabase::new();
        let config = config(None);
        {
            let mut conn = database.open();
            configure_db(&mut conn).expect("configure database");
            for (seq, payload) in [(2, Some("second")), (1, Some("first")), (3, None)] {
                store_event_sync(
                    &mut conn,
                    &config,
                    "session|common",
                    seq,
                    &seq.to_string(),
                    payload,
                    100,
                )
                .expect("persist event");
            }
            store_event_sync(
                &mut conn,
                &config,
                "session|common",
                2,
                "duplicate",
                Some("replacement"),
                101,
            )
            .expect("ignore duplicate event");
            store_event_sync(
                &mut conn,
                &config,
                "other|common",
                1,
                "other",
                Some("isolated"),
                102,
            )
            .expect("persist separate stream");
        }
        let mut conn = database.open();
        configure_db(&mut conn).expect("reopen existing schema without migration");
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal mode");
        assert_eq!(mode, "wal");
        let rows = replay_events_sync(&mut conn, &config, "session|common", 1)
            .expect("replay strictly after cursor");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].event_id, "2");
        assert_eq!(rows[0].payload.as_deref(), Some("second"));
        assert_eq!(rows[1].event_id, "3");
        assert_eq!(rows[1].payload, None);
    }

    #[test]
    fn sqlite_retains_event_stream_and_ttl_limits() {
        let mut conn = Connection::open_in_memory().expect("open database");
        configure_db(&mut conn).expect("configure database");
        let mut config = config(None);
        config.max_events = 2;
        config.max_streams = 2;
        let now = current_epoch_seconds() as i64;
        for seq in 1..=3 {
            store_event_sync(
                &mut conn,
                &config,
                "first",
                seq,
                &seq.to_string(),
                Some("payload"),
                now - 120,
            )
            .expect("store event");
        }
        let rows =
            replay_events_sync(&mut conn, &config, "first", 0).expect("replay retained events");
        assert_eq!(
            rows.iter()
                .map(|row| row.event_id.as_str())
                .collect::<Vec<_>>(),
            ["2", "3"]
        );
        store_event_sync(&mut conn, &config, "second", 1, "second", None, now - 60)
            .expect("store second stream");
        store_event_sync(&mut conn, &config, "third", 1, "third", None, now)
            .expect("store third stream");
        assert!(replay_events_sync(&mut conn, &config, "first", 0)
            .expect("oldest stream evicted")
            .is_empty());
        config.ttl = Some(Duration::from_secs(30));
        assert!(replay_events_sync(&mut conn, &config, "second", 0)
            .expect("expired event pruned")
            .is_empty());
        let rows =
            replay_events_sync(&mut conn, &config, "third", 0).expect("fresh event retained");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_id, "third");
    }

    #[test]
    fn sqlite_encrypted_replay_survives_reopen_and_rejects_wrong_key() {
        let database = TestDatabase::new();
        let config = config(Some(
            EventStoreEncryption::from_bytes(&[9u8; 32]).expect("valid key"),
        ));
        {
            let mut conn = database.open();
            configure_db(&mut conn).expect("configure database");
            store_event_sync(
                &mut conn,
                &config,
                "encrypted",
                1,
                "1",
                Some("secret payload"),
                100,
            )
            .expect("persist encrypted event");
            let stored: String = conn
                .query_row("SELECT payload FROM mcp_events", [], |row| row.get(0))
                .expect("read stored ciphertext");
            assert!(stored.starts_with(ENC_PREFIX));
            assert!(!stored.contains("secret payload"));
        }
        let mut conn = database.open();
        configure_db(&mut conn).expect("reopen encrypted database");
        let rows = replay_events_sync(&mut conn, &config, "encrypted", 0).expect("decrypt replay");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].payload.as_deref(), Some("secret payload"));
        let wrong_key = EventStoreConfig {
            encryption: Some(
                EventStoreEncryption::from_bytes(&[7u8; 32]).expect("valid wrong key"),
            ),
            ..config
        };
        assert!(replay_events_sync(&mut conn, &wrong_key, "encrypted", 0).is_err());
    }

    #[test]
    fn decrypt_rejects_plaintext_when_encryption_is_configured() {
        let encryption = EventStoreEncryption::from_bytes(&[7u8; 32]).expect("valid key");
        let err = maybe_decrypt_payload(&config(Some(encryption)), "plaintext")
            .expect_err("plaintext should fail closed");
        assert_eq!(
            err,
            "event store encryption key configured but payload is plaintext"
        );
    }

    #[test]
    fn decrypt_allows_plaintext_without_encryption() {
        let payload =
            maybe_decrypt_payload(&config(None), "plaintext").expect("plaintext without key");
        assert_eq!(payload, "plaintext");
    }

    #[test]
    fn decrypt_rejects_encrypted_payload_without_key() {
        let err = maybe_decrypt_payload(&config(None), "enc:v1:not-real")
            .expect_err("encrypted payload without key should fail");
        assert_eq!(
            err,
            "event store payload is encrypted but no key is configured"
        );
    }

    #[test]
    fn encrypted_payload_round_trips() {
        let encryption = EventStoreEncryption::from_bytes(&[9u8; 32]).expect("valid key");
        let config = config(Some(encryption));
        let encrypted = maybe_encrypt_payload(&config, Some("secret payload"))
            .expect("encrypt")
            .expect("payload");
        assert!(encrypted.starts_with(ENC_PREFIX));

        let decrypted = maybe_decrypt_payload(&config, &encrypted).expect("decrypt");
        assert_eq!(decrypted, "secret payload");
    }
}
