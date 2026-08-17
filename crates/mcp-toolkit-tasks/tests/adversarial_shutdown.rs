use std::sync::{Arc, Barrier};

use mcp_toolkit_tasks::{TaskAuthority, TaskAuthorityError, TaskPrincipal};
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::task_manager::TaskOptions;
use tokio::sync::oneshot;

fn principal(value: &str) -> TaskPrincipal {
    TaskPrincipal::new(value).expect("valid principal")
}

fn ok_result(text: &str) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text.to_string())])
}

#[test]
fn spawn_without_tokio_runtime_returns_typed_error() {
    let authority = TaskAuthority::new();
    let result =
        authority.spawn_for_principal(principal("owner-a"), TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(ok_result("must not run")) })
        });

    assert!(matches!(
        result,
        Err(TaskAuthorityError::RuntimeUnavailable)
    ));
    assert_eq!(authority.running_task_count(), 0);
}

#[test]
fn principal_debug_is_redacted() {
    let principal = principal("tenant-secret-identity");
    let debug = format!("{principal:?}");

    assert!(!debug.contains("tenant-secret-identity"));
    assert!(debug.contains("redacted"));
    assert_eq!(principal.as_str(), "tenant-secret-identity");
}

#[tokio::test]
async fn explicit_shutdown_is_irreversible_across_clones() {
    let authority = TaskAuthority::new();
    let surviving_clone = authority.clone();

    authority.shutdown();

    assert!(matches!(
        surviving_clone.spawn_for_principal(principal("owner-a"), TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(ok_result("must not run")) })
        },),
        Err(TaskAuthorityError::Closed)
    ));
    assert!(matches!(
        surviving_clone.get_task_for_principal(&principal("owner-a"), "unknown-task"),
        Err(TaskAuthorityError::Closed)
    ));
    assert_eq!(surviving_clone.running_task_count(), 0);
}

#[tokio::test]
async fn shutdown_inside_factory_prevents_task_publication() {
    let authority = TaskAuthority::new();
    let shutdown_handle = authority.clone();

    let result = authority.spawn_for_principal(
        principal("owner-a"),
        TaskOptions::new().with_ttl_ms(None),
        move |_ctx| {
            // RMCP has already materialized the task record when it calls the
            // factory. Shutdown must win before Toolkit publishes a principal
            // binding, and RMCP must abort the operation it creates afterward.
            shutdown_handle.shutdown();
            Box::pin(async { Ok(ok_result("must not be published")) })
        },
    );

    assert!(matches!(result, Err(TaskAuthorityError::Closed)));
    assert_eq!(authority.running_task_count(), 0);
    assert!(matches!(
        authority.spawn_for_principal(principal("owner-b"), TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(ok_result("still closed")) })
        },),
        Err(TaskAuthorityError::Closed)
    ));
}

struct DropSignal(Option<oneshot::Sender<()>>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        if let Some(signal) = self.0.take() {
            let _ = signal.send(());
        }
    }
}

#[tokio::test]
async fn concurrent_final_handle_drops_abort_unlimited_task() {
    let (dropped_tx, dropped_rx) = oneshot::channel();
    let authority = TaskAuthority::new();
    authority
        .spawn_for_principal(
            principal("owner-a"),
            TaskOptions::new().with_ttl_ms(None),
            move |_ctx| {
                let drop_signal = DropSignal(Some(dropped_tx));
                Box::pin(async move {
                    let _drop_signal = drop_signal;
                    std::future::pending::<()>().await;
                    Ok(ok_result("unreachable"))
                })
            },
        )
        .expect("spawn task");

    let left = authority.clone();
    let right = authority.clone();
    drop(authority);

    let barrier = Arc::new(Barrier::new(3));
    let left_barrier = barrier.clone();
    let left_drop = std::thread::spawn(move || {
        left_barrier.wait();
        drop(left);
    });
    let right_barrier = barrier.clone();
    let right_drop = std::thread::spawn(move || {
        right_barrier.wait();
        drop(right);
    });

    barrier.wait();
    left_drop.join().expect("left drop thread");
    right_drop.join().expect("right drop thread");

    tokio::time::timeout(std::time::Duration::from_secs(2), dropped_rx)
        .await
        .expect("task future should be dropped after concurrent final handles")
        .expect("drop signal");
}
