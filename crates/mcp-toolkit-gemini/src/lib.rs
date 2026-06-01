//! # MCP Toolkit Gemini
//!
//! Gemini model and CLI integration primitives for MCP servers.
//!
//! ## Ownership
//! This module owns the integration interfaces, execution policies, and tool
//! contracts for interacting with Gemini models and associated CLI tools.
//!
//! ## Non-ownership
//! This module does not manage the underlying model runtime or network
//! connectivity to Gemini APIs.
//!
//! ## Policy & Guarantees
//! * **Safe Execution**: Invokes Gemini CLI via direct subprocess execution to avoid
//!   shell-injection vulnerabilities.
//! * **Exposure Policy**: Implements an explicit allowlist for downstream MCP tool
//!   servers to mitigate accidental exposure of the local tool surface.
//! * **API-key-only Auth**: Requires `GEMINI_API_KEY` and does not support
//!   browser, account, or inherited home-directory Gemini CLI authentication.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying valid execution configurations with a `GEMINI_API_KEY`.
//! * Defining and maintaining a secure allowlist of downstream MCP servers.
//!
//! ## References
//! * `mcp-workspace/servers/gemini-cli-mcp-rs`

pub mod config;
pub mod executor;
pub mod service;

pub use config::{
    load_execution_config_from_env_map, load_execution_config_from_process_env, AllowedMcpServers,
    AskGeminiPolicy, GeminiExecutionConfig, GeminiExecutionRawConfig,
};
pub use executor::{execute_gemini, GeminiExecutionError, GeminiRequest, GeminiResponse};
pub use service::GeminiMcp;
