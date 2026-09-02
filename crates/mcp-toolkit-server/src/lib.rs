//! # MCP Toolkit Server
//!
//! Composable server bootstrap helpers for Rust MCP services.
//!
//! ## Rationale
//! Repeated MCP servers hand-wire stdio startup, Streamable HTTP sessions,
//! host checks, OAuth discovery surfaces, and shutdown tokens even though the
//! lower-level primitives already live in focused toolkit crates. This crate
//! provides a thin assembly layer over those primitives without becoming an
//! application framework.
//!
//! ## Security Boundaries
//! * Domain tool handlers, backend clients, and service-specific authorization
//!   policies stay in service crates.
//! * HTTP helpers keep loopback and auth posture explicit; callers still choose
//!   deployment-specific bind, TLS, and reverse-proxy settings.
//! * Auth helpers validate metadata through `mcp-toolkit-auth` and do not infer
//!   issuers, audiences, or scopes beyond caller-supplied configuration.
//! * Server authors can import the underlying `rmcp` authoring surface through
//!   this crate instead of declaring `rmcp` directly.
//!
//! ## References
//! * **DESIGN**: `docs/server-composition-layer.md`
//! * **BOUNDARY**: `docs/toolkit-boundary.md`
//! * **MCP**: <https://modelcontextprotocol.io>

#[cfg(feature = "auth")]
pub mod auth;
#[cfg(feature = "http")]
pub mod http;
pub mod opaque_token;
#[cfg(feature = "stdio")]
pub mod stdio;
#[cfg(any(feature = "stdio", feature = "http", feature = "auth"))]
pub mod tools;

#[cfg(any(feature = "stdio", feature = "http", feature = "auth"))]
pub use rmcp;
