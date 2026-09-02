//! # MCP Toolkit HTTP
//!
//! HTTP deployment and legacy-session helpers around RMCP's Model Context
//! Protocol transport implementation.
//!
//! ## Ownership
//! This crate owns reusable HTTP-adjacent deployment substrate: Host/Origin
//! validation, OAuth metadata helpers, bounded legacy-session management,
//! optional event retention, and construction helpers for RMCP Streamable HTTP
//! services.
//!
//! ## Non-ownership
//! RMCP owns MCP JSON-RPC and Streamable HTTP protocol semantics. This crate does
//! not implement a parallel MCP transport, built-in TLS termination, or
//! authentication middleware. The dual-era MCP 2026/legacy route front door
//! lives in `mcp-toolkit-server`; `streamable::handle_stateful_mcp_request`
//! remains a legacy session-era compatibility helper and must not be used as the
//! current-protocol router.
//!
//! ## Policy & Guarantees
//! * **Protocol Delegation**: Accepted MCP requests are delegated to RMCP.
//! * **Session Management**: Provides bounded infrastructure for legacy and
//!   resumable session deployments where compatibility requires it.
//! * **Metadata Discovery**: Enables standard OAuth discovery paths.
//! * **Fail-Closed Legacy Routing**: Malformed, unknown, or expired legacy
//!   session identifiers cannot acquire sessionless fallback authority.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Configuring transport-layer security (TLS).
//! * Implementing appropriate access control middleware.
//! * Managing the lifecycle of session stores if persistence is required.
//! * Using `mcp-toolkit-server` or RMCP directly for current MCP protocol
//!   routing rather than the legacy stateful helper.
//!
//! ## References
//! * [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)

pub mod host;
pub mod oauth;

#[cfg(feature = "session")]
pub mod session;

#[cfg(feature = "session")]
pub mod streamable;

#[cfg(feature = "session-sqlite")]
mod session_sqlite;
