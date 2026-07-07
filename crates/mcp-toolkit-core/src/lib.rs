//! # MCP Toolkit Core
//!
//! Foundational data structures and primitives for the Model Context Protocol (MCP).
//!
//! ## Ownership
//! This crate owns the common trait definitions, protocol message structures,
//! standard utility primitives, and lightweight provider-facing configuration
//! helpers required around MCP-compliant communication.
//!
//! ## Non-ownership
//! This crate does not manage transport logic, I/O streams, or security
//! policies. It focuses on protocol-level type definitions, serialization, and
//! small configuration payloads that do not require a transport dependency.
//!
//! ## Policy & Guarantees
//! * **Type Safety**: Enforces the MCP protocol specification through strictly typed
//!   JSON-RPC envelopes.
//! * **Serialization Correctness**: Uses `serde` to ensure protocol-compliant
//!   serialization and deserialization.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Implementing appropriate transport layers to facilitate communication.
//! * Enforcing security policies on input/output messages before transmission.
//! * Ensuring that the protocol version matches their host implementation.
//!
//! ## References
//! * [Model Context Protocol Specification](https://modelcontextprotocol.io)

pub mod capability;
pub mod guarded_action;
pub mod mcp_apps;
pub mod notifications;
pub mod openai_tool_search;
pub mod pagination;
pub mod query_evidence;
pub mod response_contract;
pub mod rmcp_models;
pub mod tool_inventory;
pub mod tool_schema;

/// Re-export the pinned RMCP SDK used by toolkit helpers.
///
/// Downstream MCP servers can import `mcp_toolkit_core::rmcp` to keep model
/// types aligned with toolkit helper return values instead of independently
/// drifting to a different RMCP version.
pub use rmcp;
