//! # MCP Toolkit Gemini
//!
//! Reusable Gemini CLI integration primitives for Rust MCP servers.
//!
//! ## Rationale
//! Centralize Gemini execution policy and tool contracts in one dedicated
//! module so multiple servers can share behavior without duplicating wrappers.
//!
//! ## Security Boundaries
//! * Executes Gemini CLI without invoking a shell.
//! * Defaults to denying downstream Gemini MCP servers unless explicitly allowed.
//!
//! ## References
//! * MCP servers that embed Gemini CLI-backed tools behind a transport layer.

// Preserve the promoted runtime surface first so downstream servers can move
// from local path dependencies to a hosted toolkit revision. Follow-up cleanup
// can tighten these style lints without changing the public API in the same PR.
#![allow(
    clippy::bool_assert_comparison,
    clippy::collapsible_if,
    clippy::derivable_impls,
    clippy::field_reassign_with_default,
    clippy::large_enum_variant,
    clippy::manual_pattern_char_comparison,
    clippy::question_mark,
    clippy::redundant_locals,
    clippy::too_many_arguments,
    clippy::unnecessary_map_or,
    clippy::unnecessary_min_or_max,
    clippy::while_let_loop,
    clippy::while_let_on_iterator
)]

mod async_registry;
mod compression_bridge;
pub mod config;
pub mod executor;
pub mod observe;
mod resume;
pub mod service;

pub use config::{
    AllowedMcpServers, AskGeminiPolicy, GeminiExecutionConfig, GeminiExecutionRawConfig,
    load_execution_config_from_env_map, load_execution_config_from_process_env,
};
pub use executor::{GeminiExecutionError, GeminiRequest, GeminiResponse, execute_gemini};
pub use observe::{
    GeminiInvocationEvent, GeminiInvocationEventKind, GeminiInvocationMetadata,
    GeminiInvocationObserver, GeminiInvocationPhase, GeminiOutputStream, GeminiUsageSnapshot,
    NoopGeminiInvocationObserver,
};
pub use resume::ResumeStrategy;
pub use service::GeminiMcp;
