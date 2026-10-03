# Native Streamable HTTP event replay

The HTTP toolkit can expose RMCP's native `EventStore` hook through
`LocalStreamableHttpServiceConfig::with_event_store`. This is separate from the
legacy session recorder and does not enable RMCP session restoration. Native
replay is process-local and is lost when the process exits.

The in-memory store assigns each event an opaque ID using RMCP's
`server_side_http::session_id` generator and checks generated IDs against
retained anchors. The
ID is a bearer replay capability: a holder can request later events from its
issuing stream. It is not bound to an authenticated principal. Existing route
authentication and Host/Origin checks must run before RMCP handles replay.
Unknown, malformed, expired, and evicted anchors produce an empty finite replay
stream. A retained final anchor produces the same finite empty result.

## Migration-safe SQLite table shape

The optional durable implementation is deliberately not supplied here. A future
backend can use versioned, native-only tables without altering the legacy
`mcp_events` or `mcp_event_streams` schema:

```sql
CREATE TABLE mcp_native_event_streams_v1 (
    stream_id TEXT PRIMARY KEY,
    last_sequence INTEGER NOT NULL,
    last_seen_unix_ms INTEGER NOT NULL
);

CREATE TABLE mcp_native_events_v1 (
    event_id TEXT PRIMARY KEY,
    stream_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    message_json TEXT,
    retry_seconds INTEGER,
    retry_nanos INTEGER,
    created_unix_ms INTEGER NOT NULL,
    UNIQUE (stream_id, sequence),
    FOREIGN KEY (stream_id) REFERENCES mcp_native_event_streams_v1(stream_id)
);
```

Each append must update the stream sequence and insert the complete SSE event in
one transaction before returning its ID. `message_json = NULL` represents a
priming/retry event and must not be confused with a missing row. Retention must
remove associated reverse-lookup IDs in the same transaction as event eviction.
The schema is a migration contract only; it does not claim that the toolkit
currently provides a SQLite replay backend.

Legacy recording retains its existing event-ID and session semantics. In
particular, `allow_resume` remains a legacy session-manager setting and does not
claim ownership of the native replay stream.
