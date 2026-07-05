# DuckDB Scratchpad

`mcp-toolkit-scratchpad` provides optional DuckDB-backed local sessions for MCP
servers that need to handle large tabular results without returning every row
through chat. It is a toolkit substrate crate, not a provider integration:
servers still own upstream API calls, row shaping, profile policy, and
domain-specific evidence wording.

## Use It When

- a tool can return thousands of rows or requires iterative analysis;
- the server can represent upstream data as rows and typed columns;
- agents need table inventory, bounded previews, and read-only SQL follow-up;
- deployment policy allows local temporary DuckDB files.

Keep smaller result sets in ordinary tool responses. A scratchpad is useful
when returning a handle and summary is clearer and safer than returning the full
payload.

## What The Crate Owns

- bounded scratchpad sessions with TTL, maximum sessions, maximum tables,
  maximum rows, query timeout, SQL byte limit, and DuckDB memory limit;
- session open, list, info, cleanup, and release behavior;
- table creation, append, drop, schema preview, and row accounting;
- restricted read-only SQL validation for `SELECT`, `WITH`, `EXPLAIN`,
  `DESCRIBE`, and `SUMMARIZE`;
- DuckDB file, extension, attach/import/export, and external scan denial;
- paged query projections with row totals, columns, query hints, and page
  metadata;
- contract-friendly error codes and hints.

The crate deliberately does not own provider-specific ingest tools, OAuth,
quota handling, service-specific table naming, markdown evidence bundle wording,
or default profile decisions.

## Async MCP Handlers

`ScratchpadSessionManager` is synchronous because DuckDB work is blocking. In
Tokio-backed MCP servers, enable the crate's `tokio` feature and call
`run_scratchpad_blocking` from async tool handlers instead of querying DuckDB on
the async executor:

```toml
[dependencies]
mcp-toolkit-scratchpad = {
  git = "https://github.com/sednalabs/mcp-toolkit-rs",
  branch = "main",
  features = ["tokio"]
}
```

```rust
use mcp_toolkit_scratchpad::run_scratchpad_blocking;

let sessions = self.scratchpad_sessions().clone();
let session_id = args.session_id.clone();
let sql = args.sql.clone();
let projection =
    run_scratchpad_blocking(move || sessions.query_rows(&session_id, &sql, 0, 100)).await?;
```

The umbrella crate exposes the same helper when both `scratchpad` and
`scratchpad-tokio` are enabled.

## Minimal Shape

```rust
use std::sync::Arc;
use std::time::Duration;

use mcp_toolkit_scratchpad::{
    DuckDbEngine, ScratchpadIngestColumn, ScratchpadSessionConfig,
    ScratchpadSessionManager, SharedScratchpadEngine,
};

let engine: SharedScratchpadEngine = Arc::new(DuckDbEngine::new()?);
let config = ScratchpadSessionConfig::new(
    Duration::from_secs(900),
    64,
    32,
    1_000_000,
    256,
)
.with_query_timeout(Duration::from_secs(15))
.with_max_sql_bytes(65_536);
let scratchpad = ScratchpadSessionManager::new(engine, config)?;

scratchpad.open_session("analysis_2026_07")?;
let columns = vec![ScratchpadIngestColumn {
    name: "page".to_string(),
    logical_type: "string".to_string(),
}];
```

Server tools should return concise handles, summaries, and bounded projections,
for example a session id, table name, row count, table schema, and suggested
follow-up query. Avoid serializing complete upstream responses into the MCP chat
response when the scratchpad path is selected.

## Safety Defaults

- Default to a private, randomly named scratchpad directory under the process
  temp directory. On Unix this directory is created with owner-only
  permissions.
- Require custom scratchpad root directories to be absolute, already present,
  and free of parent-directory components.
- Salt session database filenames per manager so two managers using the same
  custom root and session id do not reuse the same DuckDB file.
- Keep scratchpad tools out of the default `read_only` profile unless the
  server explicitly chooses a combined profile.
- Reject mutating or file-reading SQL before it reaches DuckDB.
- Bound result pages and export samples separately from upstream fetch limits.
- Clean up local session databases on explicit close and expired-session prune.
  Empty default directories may remain after a process crash and should be
  treated as disposable local working data.
- Treat scratchpad files as local working data; do not put secrets or provider
  credentials into scratchpad tables.

## Validation Checklist

- unit tests for session limits, table limits, row limits, TTL cleanup, and
  custom root validation;
- SQL policy tests for allowed read-only helpers and denied mutation, extension,
  import/export, and external scan shapes;
- integration tests that ingest enough rows to prove paged query behavior;
- profile tests showing scratchpad tools are hidden or denied when the selected
  deployment profile does not enable them;
- output contract tests showing tools return handles, summaries, and bounded
  projections rather than full large result sets.

The strongest current references are `sednalabs/ga4-mcp` and
`sednalabs/google-search-console-mcp`; use their manifests and
`docs/pattern-recipes.md#analytics-scratchpad` when starting a new adoption.
