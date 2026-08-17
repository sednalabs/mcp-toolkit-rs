//! # MCP Toolkit Tasks
//!
//! Production-oriented task authority built around RMCP's native
//! `io.modelcontextprotocol/tasks` implementation.
//!
//! RMCP remains responsible for the MCP task state machine, TTL semantics,
//! `input_required`, terminal result/error projection, and cooperative
//! cancellation. This crate adds reusable server substrate that the protocol
//! SDK intentionally does not own:
//!
//! * exact task-to-principal binding;
//! * fail-closed cross-principal access;
//! * monotonic observed-state revisions;
//! * race-safe wait-for-change and wait-for-terminal observation;
//! * panic containment around task factories and task futures;
//! * stale authority-binding cleanup after RMCP evicts task records.
//!
//! Revisions are observation generations, not a parallel task event log. They
//! advance only when an RMCP `TaskManager::get_task` read returns a
//! `DetailedTask` different from the last observed snapshot. Multiple RMCP
//! transitions that happen entirely between observations may therefore collapse
//! into one local revision. This keeps RMCP authoritative while still giving
//! servers an efficient bounded-wait primitive.
//!
//! The crate deliberately does not add another MCP Tasks wire protocol and does
//! not expose `tasks/list`.
//!
//! RMCP task models and [`rmcp::task_manager::TaskOptions`] appear directly in
//! this crate's public API. Use the [`rmcp`] re-export here rather than selecting
//! an independent SDK version in direct consumers; the re-export is the exact
//! RMCP release coordinated by this Toolkit revision.

mod authority;

pub use authority::{
    AuthorizedTaskSnapshot, ManagedTaskContext, TaskAuthority, TaskAuthorityError, TaskPrincipal,
    TaskWaitCondition,
};
/// Exact RMCP SDK coordinated with this Toolkit Tasks crate.
pub use rmcp;
