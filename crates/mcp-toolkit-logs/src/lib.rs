//! # MCP Toolkit Logs
//!
//! Storage-independent selection over caller-owned operation log records.
//!
//! ## Rationale
//! This crate applies bounded cursor, record-count, and UTF-8 payload-byte
//! queries without owning a log store or transport.
//!
//! ## Security Boundaries
//! * Callers must authorize and redact records before passing them here.
//! * This crate does not grant access, persist records, or expose process data.

mod query;

pub use query::{
    select_operation_logs, OperationLogQuery, OperationLogQueryError,
    OperationLogQueryResult, OperationLogRecordRef,
};
