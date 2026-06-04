//! # Stdio Server Helpers
//!
//! Small wrappers for the common stdio MCP startup path.
//!
//! ## Rationale
//! Stdio-only MCP servers should not have to repeat the same transport startup
//! and wait-loop boilerplate in every binary.
//!
//! ## Security Boundaries
//! * Stdio transport is process-local; this module does not expose HTTP bearer
//!   auth or network listener behavior.
//! * Callers remain responsible for deciding whether stdio is allowed for their
//!   configured auth posture.
//!
//! ## References
//! * **MCP Transport**: <https://modelcontextprotocol.io/docs/concepts/transports>

use std::fmt;

use rmcp::{
    serve_server,
    service::{QuitReason, ServerInitializeError},
    transport::stdio,
    RoleServer, Service,
};

/// Error returned while serving an MCP server over stdio.
#[derive(Debug)]
pub enum StdioServeError {
    /// The MCP initialize handshake failed before the server started.
    Initialize(Box<ServerInitializeError>),
    /// The background service task failed while waiting for shutdown.
    Wait(tokio::task::JoinError),
}

impl fmt::Display for StdioServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialize(err) => write!(f, "stdio initialize failed: {err}"),
            Self::Wait(err) => write!(f, "stdio wait failed: {err}"),
        }
    }
}

impl std::error::Error for StdioServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Initialize(err) => Some(err.as_ref()),
            Self::Wait(err) => Some(err),
        }
    }
}

impl From<ServerInitializeError> for StdioServeError {
    fn from(value: ServerInitializeError) -> Self {
        Self::Initialize(Box::new(value))
    }
}

impl From<tokio::task::JoinError> for StdioServeError {
    fn from(value: tokio::task::JoinError) -> Self {
        Self::Wait(value)
    }
}

/// Serves an MCP server over stdio and waits until the service exits.
///
/// # Errors
/// Returns `StdioServeError::Initialize` when the MCP initialize handshake
/// fails. Returns `StdioServeError::Wait` when the spawned service task fails.
///
/// # Security
/// This helper only wires process-local stdio transport. Callers must reject
/// stdio when their service policy requires HTTP bearer-auth endpoints.
///
/// # Panics
/// This function does not panic.
///
/// ```rust,no_run
/// # async fn example<S>(server: S) -> Result<(), mcp_toolkit_server::stdio::StdioServeError>
/// # where
/// #     S: rmcp::Service<rmcp::RoleServer> + Send + Sync + 'static,
/// # {
/// let _quit = mcp_toolkit_server::stdio::serve_stdio(server).await?;
/// # Ok(())
/// # }
/// ```
pub async fn serve_stdio<S>(server: S) -> Result<QuitReason, StdioServeError>
where
    S: Service<RoleServer> + Send + Sync + 'static,
{
    let service = serve_server(server, stdio()).await?;
    let quit = service.waiting().await?;
    Ok(quit)
}
