//! # MCP Toolkit Core
//!
//! Foundational data structures and primitives for the Model Context Protocol (MCP).
//!
//! ## Ownership
//! This crate owns the common trait definitions, protocol message structures,
//! and standard utility primitives required for MCP-compliant communication.
//!
//! ## Non-ownership
//! This crate does not manage transport logic, I/O streams, or security policies.
//! It focuses purely on protocol-level type definitions and serialization.
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

pub mod notifications;
pub mod rmcp_models;
pub mod tool_inventory;
