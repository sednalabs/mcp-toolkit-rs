//! # MCP Toolkit Scratchpad
//!
//! Reusable DuckDB-backed scratchpad sessions for MCP servers that need bounded
//! local analysis without repeatedly returning large rowsets through chat.
//!
//! ## Rationale
//! Many data-oriented MCP servers need the same local workflow: ingest rows from
//! an upstream API, query them with restricted read-only SQL, summarize tables,
//! and export bounded evidence. Centralizing that lifecycle keeps server crates
//! focused on their upstream API shape instead of reimplementing DuckDB session
//! management.
//!
//! ## Security Boundaries
//! * SQL execution is restricted to read-only statements plus DuckDB describe
//!   and summarize helpers.
//! * DuckDB file/external scan primitives are denied.
//! * Sessions, tables, rows, SQL size, memory, and query runtime are bounded.

pub mod error;
pub mod scratchpad;
pub mod sql_safety;

pub use error::ScratchpadError;
pub use scratchpad::{
    DuckDbEngine, ScratchpadCancelToken, ScratchpadDropTableStats, ScratchpadEngine,
    ScratchpadExecutionHooks, ScratchpadIngestColumn, ScratchpadIngestMode, ScratchpadIngestStats,
    ScratchpadQueryProjection, ScratchpadSessionConfig, ScratchpadSessionInfo,
    ScratchpadSessionManager, ScratchpadSessionSnapshot, ScratchpadTableColumnInfo,
    ScratchpadTableInfo, SessionDatabaseConfig, SharedScratchpadEngine,
    SharedScratchpadSessionManager,
};
pub use sql_safety::{ScratchpadSqlPolicyCode, ScratchpadSqlPolicyError, validate_scratchpad_sql};
