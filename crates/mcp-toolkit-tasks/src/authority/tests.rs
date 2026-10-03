use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::task::{Context, Poll};

use super::*;
use rmcp::model::{CallToolResult, ContentBlock, TaskStatus};
use tokio::sync::oneshot;

fn principal(value: &str) -> TaskPrincipal {
    TaskPrincipal::new(value).expect("valid principal")
}

fn test_config() -> TaskAuthorityConfig {
    limited_config(1024, 1024, 1024)
}

fn limited_config(tasks: usize, waiters: usize, reads_per_second: usize) -> TaskAuthorityConfig {
    TaskAuthorityConfig {
        max_retained_tasks: NonZeroUsize::new(tasks).expect("nonzero task capacity"),
        max_waiters: NonZeroUsize::new(waiters).expect("nonzero waiter capacity"),
        fallback_reads_per_second: NonZeroUsize::new(reads_per_second)
            .expect("nonzero read budget"),
    }
}

fn ok_result(text: &str) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text.to_string())])
}

fn input_request(message: &str) -> InputRequest {
    serde_json::from_value(serde_json::json!({
        "method": "elicitation/create",
        "params": {
            "message": message,
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "approved": {"type": "boolean"}
                }
            }
        }
    }))
    .expect("valid input request")
}

fn binding_count(authority: &TaskAuthority) -> usize {
    authority
        .state
        .lock()
        .expect("authority state")
        .bindings
        .len()
}

#[tokio::test]
async fn synchronous_observation_does_not_consume_a_hint_that_arrived_during_read() {
    let authority = TaskAuthority::new(test_config());
    let owner = principal("owner-a");
    let task = authority
        .spawn_for_principal(
            owner.clone(),
            TaskOptions::new().with_ttl_ms(None),
            |_ctx| Box::pin(std::future::pending::<Result<CallToolResult, TaskExit>>()),
        )
        .expect("task admitted");
    let binding = authority
        .binding_for(&owner, &task.task_id)
        .expect("binding");
    let generation_before_read = binding.signal.generation();

    // Model a task transition/drop hint between the RMCP read and cache update.
    binding.hint();
    let snapshot = authority
        .manager
        .get_task(&task.task_id)
        .expect("RMCP task remains present");
    authority
        .observe_or_close(&binding, &task.task_id, snapshot, generation_before_read)
        .expect("snapshot observed");

    let state = authority.state.lock().expect("authority state");
    assert_eq!(
        state
            .leases
            .get(&task.task_id)
            .expect("retained lease")
            .observed_signal_generation,
        generation_before_read
    );
    assert_ne!(binding.signal.generation(), generation_before_read);
    drop(state);
    authority.shutdown();
}

#[test]
fn spawn_rejects_runtime_without_time_driver_before_rmcp_materialization() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime without time driver");
    let authority = TaskAuthority::new(test_config());
    let owner = principal("owner-a");
    let result = {
        let _entered = runtime.enter();
        authority.spawn_for_principal(owner, TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(ok_result("must not materialize")) })
        })
    };
    assert!(matches!(
        result,
        Err(TaskAuthorityError::RuntimeTimerUnavailable)
    ));
    assert_eq!(authority.metrics().active_waiters, 0);
    assert_eq!(authority.running_task_count(), 0);
    authority.shutdown();
}

#[test]
fn public_wait_future_is_send_for_tokio_task_consumers() {
    fn assert_send<T: Send>(_: T) {}

    let authority = TaskAuthority::new(test_config());
    let owner = principal("owner-a");
    let wait = authority.wait(
        &owner,
        "task-id",
        None,
        Duration::from_secs(1),
        TaskWaitCondition::Terminal,
    );
    assert_send(wait);
    authority.shutdown();
}

#[tokio::test]
async fn retained_capacity_counts_terminal_records_and_unlimited_ttl() {
    let authority = TaskAuthority::new(limited_config(1, 4, 4));
    let owner = principal("owner-a");
    let first = authority
        .spawn_for_principal(owner.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(ok_result("done")) })
        })
        .expect("first task admitted");
    let terminal = authority
        .wait(
            &owner,
            &first.task_id,
            None,
            Duration::from_secs(2),
            TaskWaitCondition::Terminal,
        )
        .await
        .expect("wait succeeds")
        .expect("terminal task returned");
    assert!(terminal.task.status().is_terminal());
    assert!(matches!(
        authority.spawn_for_principal(owner.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(ok_result("must not run")) })
        }),
        Err(TaskAuthorityError::CapacityReached)
    ));

    authority.shutdown();
    let unlimited = TaskAuthority::new(limited_config(1, 4, 4));
    unlimited
        .spawn_for_principal(
            owner.clone(),
            TaskOptions::new().with_ttl_ms(None),
            |_ctx| Box::pin(async { Ok(ok_result("retained")) }),
        )
        .expect("unlimited-retention task admitted");
    assert!(matches!(
        unlimited.spawn_for_principal(owner, TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(ok_result("must not run")) })
        }),
        Err(TaskAuthorityError::CapacityReached)
    ));
}

#[tokio::test]
async fn ttl_failure_keeps_capacity_until_rmcp_evicts_the_record() {
    let authority = TaskAuthority::new(limited_config(1, 4, 4));
    let owner = principal("owner-a");
    let task = authority
        .spawn_for_principal(owner.clone(), TaskOptions::new().with_ttl_ms(10), |_ctx| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(ok_result("must expire"))
            })
        })
        .expect("task admitted");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let failed = authority
        .manager
        .get_task(&task.task_id)
        .expect("RMCP retains the failed task before eviction");
    assert_eq!(failed.status(), TaskStatus::Failed);
    assert!(matches!(
        authority.spawn_for_principal(owner.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(ok_result("too early")) })
        }),
        Err(TaskAuthorityError::CapacityReached)
    ));
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            match authority.spawn_for_principal(owner.clone(), TaskOptions::default(), |_ctx| {
                Box::pin(async { Ok(ok_result("after eviction")) })
            }) {
                Ok(_) => return,
                Err(TaskAuthorityError::CapacityReached) => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => panic!("unexpected task admission failure: {error}"),
            }
        }
    })
    .await
    .expect("capacity releases only after actual RMCP eviction");
}

#[tokio::test]
async fn waiter_capacity_is_authorized_before_registration_and_released_on_cancel() {
    let authority = Arc::new(TaskAuthority::new(limited_config(4, 1, 2)));
    let owner = principal("owner-a");
    let (started_tx, started_rx) = oneshot::channel();
    let task = authority
        .spawn_for_principal(owner.clone(), TaskOptions::default(), move |_ctx| {
            Box::pin(async move {
                let _ = started_tx.send(());
                std::future::pending::<Result<CallToolResult, TaskExit>>().await
            })
        })
        .expect("task admitted");
    let waiter_authority = authority.clone();
    let waiter_owner = owner.clone();
    let task_id = task.task_id.clone();
    let waiter = tokio::spawn(async move {
        waiter_authority
            .wait(
                &waiter_owner,
                &task_id,
                None,
                Duration::from_secs(30),
                TaskWaitCondition::Terminal,
            )
            .await
    });
    let _ = started_rx.await;
    tokio::task::yield_now().await;
    assert!(matches!(
        authority
            .wait(
                &owner,
                &task.task_id,
                None,
                Duration::from_secs(1),
                TaskWaitCondition::Terminal,
            )
            .await,
        Err(TaskAuthorityError::WaiterCapacityReached)
    ));
    waiter.abort();
    let _ = waiter.await;
    assert_eq!(authority.metrics().active_waiters, 0);
}

#[tokio::test]
async fn retained_tasks_and_same_task_waiter_fanout_share_the_read_budget() {
    let authority = Arc::new(TaskAuthority::new(limited_config(8, 32, 2)));
    let owner = principal("owner-a");
    let mut task_ids = Vec::new();
    for _ in 0..4 {
        let task = authority
            .spawn_for_principal(
                owner.clone(),
                TaskOptions::new().with_ttl_ms(None),
                |_ctx| {
                    Box::pin(async {
                        std::future::pending::<Result<CallToolResult, TaskExit>>().await
                    })
                },
            )
            .expect("task admitted");
        task_ids.push(task.task_id);
    }

    tokio::time::sleep(SETTLEMENT_RECHECK + Duration::from_millis(25)).await;
    let mut waiters = Vec::new();
    for task_id in &task_ids {
        for _ in 0..3 {
            let authority = authority.clone();
            let owner = owner.clone();
            let task_id = task_id.clone();
            waiters.push(tokio::spawn(async move {
                authority
                    .wait(
                        &owner,
                        &task_id,
                        None,
                        Duration::from_secs(2),
                        TaskWaitCondition::Terminal,
                    )
                    .await
            }));
        }
    }

    for waiter in waiters {
        let result = waiter.await.expect("waiter task joins");
        assert!(result.expect("wait succeeds").is_none());
    }
    let metrics = authority.metrics();
    assert_eq!(metrics.active_waiters, 0);
    assert!(metrics.fallback_reads <= 8);
    authority.shutdown();
}

#[test]
fn principal_identity_is_exact_and_surrounding_whitespace_is_rejected() {
    let owner = TaskPrincipal::new("owner-a").expect("principal");
    assert_eq!(owner.as_str(), "owner-a");
    assert!(matches!(
        TaskPrincipal::new(" owner-a"),
        Err(TaskAuthorityError::InvalidPrincipal)
    ));
    assert!(matches!(
        TaskPrincipal::new("owner-a "),
        Err(TaskAuthorityError::InvalidPrincipal)
    ));
    assert!(matches!(
        TaskPrincipal::new(""),
        Err(TaskAuthorityError::InvalidPrincipal)
    ));
    assert!(matches!(
        TaskPrincipal::new("x".repeat(257)),
        Err(TaskAuthorityError::InvalidPrincipal)
    ));
}

#[tokio::test]
async fn concurrent_creation_reserves_the_exact_retained_capacity_limit() {
    let authority = Arc::new(TaskAuthority::new(limited_config(1, 4, 2)));
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let runtime = tokio::runtime::Handle::current();
    let mut workers = Vec::new();
    for owner in ["owner-a", "owner-b"] {
        let authority = authority.clone();
        let barrier = barrier.clone();
        let runtime = runtime.clone();
        workers.push(std::thread::spawn(move || {
            let _entered = runtime.enter();
            barrier.wait();
            authority.spawn_for_principal(
                principal(owner),
                TaskOptions::new().with_ttl_ms(None),
                |_ctx| {
                    Box::pin(async {
                        std::future::pending::<Result<CallToolResult, TaskExit>>().await
                    })
                },
            )
        }));
    }
    barrier.wait();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker returns"))
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(TaskAuthorityError::CapacityReached)))
            .count(),
        1
    );
}

#[tokio::test]
async fn cross_principal_task_access_is_concealed() {
    let authority = TaskAuthority::new(test_config());
    let owner = principal("owner-a");
    let other = principal("owner-b");
    let task = authority
        .spawn_for_principal(owner.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(ok_result("done")) })
        })
        .expect("spawn task");

    assert!(matches!(
        authority.get_task_for_principal(&other, &task.task_id),
        Err(TaskAuthorityError::TaskNotFound)
    ));
    assert!(matches!(
        authority.cancel_task_for_principal(&other, &task.task_id),
        Err(TaskAuthorityError::TaskNotFound)
    ));
    assert!(matches!(
        authority.update_task_for_principal(
            &other,
            &task.task_id,
            [("unknown".to_string(), serde_json::json!(true))]
        ),
        Err(TaskAuthorityError::TaskNotFound)
    ));
    assert!(authority
        .get_task_for_principal(&owner, &task.task_id)
        .is_ok());
}

#[tokio::test]
async fn repeated_reads_keep_revision_stable_without_rmcp_change() {
    let authority = TaskAuthority::new(test_config());
    let owner = principal("owner-a");
    let task = authority
        .spawn_for_principal(owner.clone(), TaskOptions::default(), |ctx| {
            Box::pin(async move {
                ctx.cancelled().await;
                Err(TaskExit::Cancelled)
            })
        })
        .expect("spawn task");

    let first = authority
        .get_task_for_principal(&owner, &task.task_id)
        .expect("first snapshot");
    let second = authority
        .get_task_for_principal(&owner, &task.task_id)
        .expect("second snapshot");
    assert_eq!(first.revision, second.revision);
    assert_eq!(first.task, second.task);

    authority
        .cancel_task_for_principal(&owner, &task.task_id)
        .expect("cancel task");
}

#[tokio::test]
async fn status_message_change_wakes_revision_waiter() {
    let authority = Arc::new(TaskAuthority::new(test_config()));
    let owner = principal("owner-a");
    let (context_tx, context_rx) = oneshot::channel::<ManagedTaskContext>();
    let task = authority
        .spawn_for_principal(owner.clone(), TaskOptions::default(), move |ctx| {
            Box::pin(async move {
                let _ = context_tx.send(ctx.clone());
                ctx.cancelled().await;
                Err(TaskExit::Cancelled)
            })
        })
        .expect("spawn task");
    let context = context_rx.await.expect("task context");
    let initial = authority
        .get_task_for_principal(&owner, &task.task_id)
        .expect("initial snapshot");

    let waiter_authority = authority.clone();
    let waiter_owner = owner.clone();
    let waiter_task_id = task.task_id.clone();
    let waiter = tokio::spawn(async move {
        waiter_authority
            .wait(
                &waiter_owner,
                &waiter_task_id,
                Some(initial.revision),
                Duration::from_secs(2),
                TaskWaitCondition::RevisionChange,
            )
            .await
    });

    context.set_status_message("working hard");
    let observed = waiter
        .await
        .expect("waiter join")
        .expect("wait result")
        .expect("changed snapshot");
    assert!(observed.revision > initial.revision);
    assert_eq!(
        observed.task.task.status_message.as_deref(),
        Some("working hard")
    );

    authority
        .cancel_task_for_principal(&owner, &task.task_id)
        .expect("cancel task");
}

#[tokio::test]
async fn input_required_update_and_completion_are_observed_from_rmcp_state() {
    let authority = Arc::new(TaskAuthority::new(test_config()));
    let owner = principal("owner-a");
    let task = authority
        .spawn_for_principal(owner.clone(), TaskOptions::default(), |ctx| {
            Box::pin(async move {
                let response = ctx
                    .request_input("approval", input_request("Approve this operation?"))
                    .await?;
                if response.get("approved").and_then(|value| value.as_bool()) == Some(true) {
                    Ok(ok_result("approved"))
                } else {
                    Ok(ok_result("rejected"))
                }
            })
        })
        .expect("spawn task");

    let initial = authority
        .get_task_for_principal(&owner, &task.task_id)
        .expect("initial snapshot");
    let input_snapshot = authority
        .wait(
            &owner,
            &task.task_id,
            Some(initial.revision),
            Duration::from_secs(2),
            TaskWaitCondition::RevisionChange,
        )
        .await
        .expect("wait result")
        .expect("input-required snapshot");
    assert_eq!(input_snapshot.task.status(), TaskStatus::InputRequired);
    assert!(input_snapshot.revision > initial.revision);

    authority
        .update_task_for_principal(
            &owner,
            &task.task_id,
            [(
                "approval".to_string(),
                serde_json::json!({"approved": true}),
            )],
        )
        .expect("update task");

    let terminal = authority
        .wait(
            &owner,
            &task.task_id,
            Some(input_snapshot.revision),
            Duration::from_secs(2),
            TaskWaitCondition::Terminal,
        )
        .await
        .expect("terminal wait")
        .expect("terminal snapshot");
    assert_eq!(terminal.task.status(), TaskStatus::Completed);
    assert!(terminal.revision > input_snapshot.revision);
}

#[tokio::test]
async fn owner_cancel_reaches_terminal_state() {
    let authority = Arc::new(TaskAuthority::new(test_config()));
    let owner = principal("owner-a");
    let task = authority
        .spawn_for_principal(owner.clone(), TaskOptions::default(), |ctx| {
            Box::pin(async move {
                ctx.cancelled().await;
                Err(TaskExit::Cancelled)
            })
        })
        .expect("spawn task");

    authority
        .cancel_task_for_principal(&owner, &task.task_id)
        .expect("cancel task");
    let observed = authority
        .wait(
            &owner,
            &task.task_id,
            None,
            Duration::from_secs(2),
            TaskWaitCondition::Terminal,
        )
        .await
        .expect("wait result")
        .expect("terminal snapshot");
    assert_eq!(observed.task.status(), TaskStatus::Cancelled);
}

#[tokio::test]
async fn synchronous_factory_panic_is_contained_as_failed_task() {
    let authority = TaskAuthority::new(test_config());
    let owner = principal("owner-a");
    let task = authority
        .spawn_for_principal(
            owner.clone(),
            TaskOptions::new().with_ttl_ms(None),
            |_ctx| std::panic::panic_any(PanicOnDrop),
        )
        .expect("factory panic should be contained");

    let terminal = authority
        .wait(
            &owner,
            &task.task_id,
            None,
            Duration::from_secs(2),
            TaskWaitCondition::Terminal,
        )
        .await
        .expect("wait result")
        .expect("terminal snapshot");
    assert_eq!(terminal.task.status(), TaskStatus::Failed);
    assert_eq!(authority.running_task_count(), 0);
}

#[tokio::test]
async fn asynchronous_operation_panic_is_contained_as_failed_task() {
    let authority = TaskAuthority::new(test_config());
    let owner = principal("owner-a");
    let task = authority
        .spawn_for_principal(
            owner.clone(),
            TaskOptions::new().with_ttl_ms(None),
            |_ctx| {
                Box::pin(async {
                    tokio::task::yield_now().await;
                    std::panic::panic_any(PanicOnDrop);
                    #[allow(unreachable_code)]
                    Ok(ok_result("never"))
                })
            },
        )
        .expect("spawn task");

    let terminal = authority
        .wait(
            &owner,
            &task.task_id,
            None,
            Duration::from_secs(2),
            TaskWaitCondition::Terminal,
        )
        .await
        .expect("wait result")
        .expect("terminal snapshot");
    assert_eq!(terminal.task.status(), TaskStatus::Failed);
    assert_eq!(authority.running_task_count(), 0);
}

struct PanicOnDrop;

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        panic!("panic payload destructor panic")
    }
}

struct ReadyDropPanicFuture;

impl Future for ReadyDropPanicFuture {
    type Output = Result<CallToolResult, TaskExit>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(ok_result("would have succeeded")))
    }
}

impl Drop for ReadyDropPanicFuture {
    fn drop(&mut self) {
        std::panic::panic_any(PanicOnDrop)
    }
}

#[tokio::test]
async fn operation_destructor_panic_is_contained_as_failed_task() {
    let authority = TaskAuthority::new(test_config());
    let owner = principal("owner-a");
    let task = authority
        .spawn_for_principal(
            owner.clone(),
            TaskOptions::new().with_ttl_ms(None),
            |_ctx| Box::pin(ReadyDropPanicFuture),
        )
        .expect("spawn task");

    let terminal = authority
        .wait(
            &owner,
            &task.task_id,
            None,
            Duration::from_secs(2),
            TaskWaitCondition::Terminal,
        )
        .await
        .expect("wait result")
        .expect("terminal snapshot");
    assert_eq!(terminal.task.status(), TaskStatus::Failed);

    let follow_up = authority
        .spawn_for_principal(owner.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(ok_result("manager survived destructor panic")) })
        })
        .expect("manager should remain usable");
    assert!(authority
        .get_task_for_principal(&owner, &follow_up.task_id)
        .is_ok());
}

struct PanicMessage;

impl From<PanicMessage> for String {
    fn from(_value: PanicMessage) -> Self {
        panic!("message conversion panic")
    }
}

#[tokio::test]
async fn status_message_conversion_panic_does_not_poison_rmcp_manager() {
    let authority = TaskAuthority::new(test_config());
    let owner = principal("owner-a");
    let task = authority
        .spawn_for_principal(owner.clone(), TaskOptions::new().with_ttl_ms(None), |ctx| {
            Box::pin(async move {
                ctx.set_status_message(PanicMessage);
                Ok(ok_result("never"))
            })
        })
        .expect("spawn task");

    let terminal = authority
        .wait(
            &owner,
            &task.task_id,
            None,
            Duration::from_secs(2),
            TaskWaitCondition::Terminal,
        )
        .await
        .expect("wait result")
        .expect("terminal snapshot");
    assert_eq!(terminal.task.status(), TaskStatus::Failed);

    let follow_up = authority
        .spawn_for_principal(owner.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(ok_result("manager survived")) })
        })
        .expect("manager should remain usable");
    assert!(authority
        .get_task_for_principal(&owner, &follow_up.task_id)
        .is_ok());
}

#[tokio::test]
async fn panicking_update_iterator_does_not_poison_rmcp_manager() {
    let authority = TaskAuthority::new(test_config());
    let owner = principal("owner-a");
    let task = authority
        .spawn_for_principal(owner.clone(), TaskOptions::default(), |ctx| {
            Box::pin(async move {
                ctx.cancelled().await;
                Err(TaskExit::Cancelled)
            })
        })
        .expect("spawn task");

    let bad_iter =
        std::iter::from_fn(|| -> Option<(String, serde_json::Value)> { panic!("iterator panic") });
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = authority.update_task_for_principal(&owner, &task.task_id, bad_iter);
    }));
    assert!(panic.is_err());
    assert!(authority
        .get_task_for_principal(&owner, &task.task_id)
        .is_ok());

    authority
        .cancel_task_for_principal(&owner, &task.task_id)
        .expect("cancel task");
}

struct DropSignalFuture {
    dropped: Option<oneshot::Sender<()>>,
}

impl Future for DropSignalFuture {
    type Output = Result<CallToolResult, TaskExit>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for DropSignalFuture {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

#[tokio::test]
async fn dropping_last_authority_handle_aborts_unlimited_task() {
    let (dropped_tx, dropped_rx) = oneshot::channel();
    {
        let authority = TaskAuthority::new(test_config());
        let owner = principal("owner-a");
        authority
            .spawn_for_principal(owner, TaskOptions::new().with_ttl_ms(None), move |_ctx| {
                Box::pin(DropSignalFuture {
                    dropped: Some(dropped_tx),
                })
            })
            .expect("spawn task");
    }

    tokio::time::timeout(Duration::from_secs(2), dropped_rx)
        .await
        .expect("task future should be dropped after final authority handle")
        .expect("drop signal");
}

#[tokio::test]
async fn stale_cancel_is_normalized_to_task_not_found_and_drops_binding() {
    let authority = TaskAuthority::new(test_config());
    let owner = principal("owner-a");
    let task = authority
        .spawn_for_principal(owner.clone(), TaskOptions::new().with_ttl_ms(10), |_ctx| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(ok_result("never"))
            })
        })
        .expect("spawn task");

    tokio::time::sleep(Duration::from_millis(20)).await;
    let first = authority
        .manager
        .get_task(&task.task_id)
        .expect("first sweep retains failed task");
    assert_eq!(first.status(), TaskStatus::Failed);
    tokio::time::sleep(Duration::from_millis(20)).await;

    assert!(matches!(
        authority.cancel_task_for_principal(&owner, &task.task_id),
        Err(TaskAuthorityError::TaskNotFound)
    ));
    assert_eq!(binding_count(&authority), 0);
}

#[tokio::test]
async fn observer_releases_stale_bindings_after_rmcp_global_sweep() {
    let authority = TaskAuthority::new(test_config());
    let owner = principal("owner-a");
    let first = authority
        .spawn_for_principal(owner.clone(), TaskOptions::new().with_ttl_ms(10), |_ctx| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(ok_result("never"))
            })
        })
        .expect("spawn first task");
    let second = authority
        .spawn_for_principal(owner, TaskOptions::new().with_ttl_ms(10), |_ctx| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(ok_result("never"))
            })
        })
        .expect("spawn second task");

    assert_eq!(binding_count(&authority), 2);
    tokio::time::timeout(Duration::from_secs(2), async {
        while binding_count(&authority) != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("observer eventually confirms both evictions");
    assert_eq!(binding_count(&authority), 0);

    assert!(authority.manager.get_task(&first.task_id).is_err());
    assert!(authority.manager.get_task(&second.task_id).is_err());
}
