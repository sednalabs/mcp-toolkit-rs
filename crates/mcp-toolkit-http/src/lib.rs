//! # MCP Toolkit HTTP
//!
//! HTTP transport and session management for the Model Context Protocol (MCP).
//!
//! ## Ownership
//! This crate owns the implementation of MCP-compliant HTTP transport bindings,
//! including SSE event streaming, OAuth 2.0 discovery, and session state persistence.
//!
//! ## Non-ownership
//! This crate does not provide built-in TLS termination or authentication middleware;
//! it assumes these are provided by the deployment environment (e.g., reverse proxy).
//!
//! ## Policy & Guarantees
//! * **Protocol Compliance**: Implements MCP-compliant SSE and POST bindings.
//! * **Session Management**: Provides infrastructure for managing resumable SSE sessions.
//! * **Metadata Discovery**: Enables standard OAuth discovery paths.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Configuring transport-layer security (TLS).
//! * Implementing appropriate access control middleware.
//! * Managing the lifecycle of session stores if persistence is required.
//!
//! ## References
//! * [MCP Streamable HTTP Transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

pub mod host;
pub mod oauth;

#[cfg(feature = "session")]
pub mod session;

#[cfg(feature = "session")]
pub mod streamable;

#[cfg(feature = "session-sqlite")]
mod session_sqlite;
