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
/// if the blocking task is cancelled before returning.
///
/// # Panics
/// Resumes panics raised by the blocking operation on the calling task.
pub async fn run_scratchpad_blocking<T, F>(operation: F) -> Result<T, ScratchpadError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ScratchpadError> + Send + 'static,
{
    match tokio::task::spawn_blocking(operation).await {
        Ok(result) => result,
        Err(err) => {
            if err.is_panic() {
                std::panic::resume_unwind(err.into_panic());
            }
            Err(ScratchpadError::Internal(format!(
                "scratchpad blocking task cancelled: {err}"
            )))
        }
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
    #[should_panic(expected = "simulated scratchpad worker panic")]
    async fn run_scratchpad_blocking_propagates_panic() {
        let _ = run_scratchpad_blocking(|| -> Result<(), ScratchpadError> {
            panic!("simulated scratchpad worker panic");
        })
        .await;
    }
}
