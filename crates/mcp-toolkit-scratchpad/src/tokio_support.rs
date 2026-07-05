//! Tokio helpers for running synchronous scratchpad work from async handlers.
//!
//! Enable the `tokio` feature when an MCP server exposes scratchpad tools from
//! Tokio-backed async tool handlers.

use super::ScratchpadError;

/// Runs blocking scratchpad work on Tokio's blocking thread pool.
///
/// Use this from async MCP tool handlers before calling synchronous DuckDB
/// scratchpad APIs. It keeps database work off the async executor while
/// preserving the scratchpad crate's `ScratchpadError` contract.
///
/// ```rust
/// # #[cfg(feature = "tokio")]
/// # async fn example() -> Result<(), mcp_toolkit_scratchpad::ScratchpadError> {
/// use mcp_toolkit_scratchpad::run_scratchpad_blocking;
///
/// let value = run_scratchpad_blocking(|| Ok(42)).await?;
/// assert_eq!(value, 42);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
/// Returns the operation's `ScratchpadError`, or `ScratchpadError::Internal`
/// if the blocking task is cancelled or panics before returning.
pub async fn run_scratchpad_blocking<T, F>(operation: F) -> Result<T, ScratchpadError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ScratchpadError> + Send + 'static,
{
    match tokio::task::spawn_blocking(operation).await {
        Ok(result) => result,
        Err(err) => Err(ScratchpadError::Internal(format!(
            "scratchpad blocking task failed: {err}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_scratchpad_blocking_returns_operation_result() {
        let result = run_scratchpad_blocking(|| Ok(7)).await;

        assert!(matches!(result, Ok(7)));
    }

    #[tokio::test]
    async fn run_scratchpad_blocking_maps_join_error() {
        let result = run_scratchpad_blocking(|| -> Result<(), ScratchpadError> {
            panic!("simulated scratchpad worker panic");
        })
        .await;

        assert!(matches!(
            result,
            Err(ScratchpadError::Internal(message))
                if message.contains("scratchpad blocking task failed")
        ));
    }
}
