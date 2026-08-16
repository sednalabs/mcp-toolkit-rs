//! # MCP Toolkit
//!
//! A unified Rust SDK for Model Context Protocol (MCP) server and client development.
//!
//! ## Ownership
//! This crate functions as the primary facade for the MCP toolkit, orchestrating
//! access to modular sub-crates (Core, Auth, HTTP, Policy, Process, Tasks,
//! Scratchpad).
//!
//! ## Non-ownership
//! This crate does not perform functional operations itself; it facilitates
//! re-exporting and ecosystem-wide crate integration.
//!
//! ## Policy & Guarantees
//! * **Ecosystem Integration**: Provides a single entry point for all toolkit
//!   features, gated by feature flags to minimize dependency overhead.
//! * **Modular Security**: Orchestrates features which retain their own specific
//!   security boundaries defined in their respective sub-crates.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Enabling only the necessary feature flags to maintain minimal build dependencies
//!   and runtime footprints.
//!
//! ## References
//! * [Model Context Protocol Specification](https://modelcontextprotocol.io)

pub use mcp_toolkit_core as core;

pub mod client_config;
pub mod doctor;
pub mod draft_generator;
pub mod new_server;
pub mod patterns;
pub mod release_preflight;

#[cfg(feature = "http")]
pub use mcp_toolkit_http as http;

#[cfg(feature = "auth")]
pub use mcp_toolkit_auth as auth;

#[cfg(feature = "policy")]
pub use mcp_toolkit_policy_core as policy_core;

#[cfg(feature = "policy")]
pub use mcp_toolkit_policy_runtime as policy_runtime;

#[cfg(feature = "policy-ffi")]
pub use mcp_toolkit_policy_ffi as policy_ffi;

#[cfg(feature = "process")]
pub use mcp_toolkit_process as process;

#[cfg(feature = "tasks")]
pub use mcp_toolkit_tasks as tasks;

#[cfg(feature = "scratchpad")]
pub use mcp_toolkit_scratchpad as scratchpad;

#[cfg(feature = "gemini")]
pub use mcp_toolkit_gemini as gemini;

#[cfg(any(
    feature = "server",
    feature = "server-stdio",
    feature = "server-http",
    feature = "server-auth"
))]
pub use mcp_toolkit_server as server;

#[cfg(any(
    feature = "server",
    feature = "server-stdio",
    feature = "server-http",
    feature = "server-auth"
))]
pub use rmcp;
