use std::any::Any;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::task::{Context, Poll};

use rmcp::model::CallToolResult;
use rmcp::task_manager::{TaskExit, TaskFuture};

/// Drops a panic payload without allowing a panic from its destructor to
/// escape the existing panic boundary.
///
/// A caller can use `panic_any` with a payload whose `Drop` implementation
/// panics. Dropping the `Err` returned by `catch_unwind` would otherwise unwind
/// through the RMCP/Tokio boundary after the original panic was caught. If the
/// payload destructor panics, its replacement payload is intentionally leaked
/// because attempting to drop that replacement could recurse indefinitely.
pub(super) fn discard_panic_payload(payload: Box<dyn Any + Send>) {
    if let Err(drop_panic) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        std::mem::forget(drop_panic);
    }
}

fn panic_task_exit(message: &'static str) -> TaskExit {
    TaskExit::Error(rmcp::ErrorData::internal_error(message.to_string(), None))
}

/// Own a caller-provided task future behind a panic boundary.
///
/// Panics while polling are converted into a task failure. The inner future is
/// then destroyed behind a second panic boundary, because destructors are
/// caller-controlled code too. The same protected destruction runs if RMCP
/// aborts the wrapper while the operation is still pending.
pub(super) struct PanicContainedTaskFuture {
    inner: Option<TaskFuture>,
}

impl PanicContainedTaskFuture {
    pub(super) fn new(future: TaskFuture) -> Self {
        Self {
            inner: Some(future),
        }
    }

    fn drop_inner(&mut self) -> bool {
        let Some(future) = self.inner.take() else {
            return false;
        };
        match catch_unwind(AssertUnwindSafe(|| drop(future))) {
            Ok(()) => false,
            Err(panic) => {
                discard_panic_payload(panic);
                true
            }
        }
    }
}

impl Future for PanicContainedTaskFuture {
    type Output = Result<CallToolResult, TaskExit>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Moving a `Pin<Box<dyn Future>>` does not move its pointee, so this
        // wrapper is safely Unpin and can project through `get_mut`.
        let this = self.get_mut();
        let Some(future) = this.inner.as_mut() else {
            return Poll::Ready(Err(panic_task_exit(
                "task operation polled after completion",
            )));
        };

        match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(result)) => {
                if this.drop_inner() {
                    Poll::Ready(Err(panic_task_exit("task operation destructor panicked")))
                } else {
                    Poll::Ready(result)
                }
            }
            Err(panic) => {
                // A future that panicked while being polled is not polled
                // again. Destroy it behind its own panic boundary and report
                // one stable task failure to RMCP.
                discard_panic_payload(panic);
                let _drop_panicked = this.drop_inner();
                Poll::Ready(Err(panic_task_exit("task operation panicked")))
            }
        }
    }
}

impl Drop for PanicContainedTaskFuture {
    fn drop(&mut self) {
        // Cancellation, TTL abort, or server shutdown can destroy a still
        // pending user future. Never allow its destructor to unwind through
        // RMCP/Tokio cancellation machinery.
        let _drop_panicked = self.drop_inner();
    }
}

pub(super) fn contain_task_future(future: TaskFuture) -> TaskFuture {
    Box::pin(PanicContainedTaskFuture::new(future))
}
