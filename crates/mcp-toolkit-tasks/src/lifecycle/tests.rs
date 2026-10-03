use super::*;
use crate::ManagedTaskContext;
use rmcp::task_manager::TaskOptions;
use tokio::sync::oneshot;

#[tokio::test]
async fn fetches_authorized_snapshots_and_records_each_new_revision() {
    let authority = TaskAuthority::new();
    let principal = TaskPrincipal::new("owner").expect("principal");
    let (context_tx, context_rx) = oneshot::channel::<ManagedTaskContext>();
    let first_task = authority
        .spawn_for_principal(principal.clone(), TaskOptions::default(), move |ctx| {
            Box::pin(async move {
                let _ = context_tx.send(ctx.clone());
                ctx.cancelled().await;
                Err(rmcp::task_manager::TaskExit::Cancelled)
            })
        })
        .expect("first");
    let second_task = authority
        .spawn_for_principal(principal.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { std::future::pending().await })
        })
        .expect("second");
    let context = context_rx.await.expect("task context");
    let mut observer = LifecycleObserver::new();
    assert!(matches!(
        observer.observe(&authority, &principal, &first_task.task_id),
        Ok(ObserveResult::Recorded)
    ));
    assert!(matches!(
        observer.observe(&authority, &principal, &first_task.task_id),
        Ok(ObserveResult::Duplicate)
    ));
    context.set_status_message("progress changed");
    assert!(matches!(
        observer.observe(&authority, &principal, &first_task.task_id),
        Ok(ObserveResult::Recorded)
    ));
    assert!(matches!(
        observer.observe(&authority, &principal, &second_task.task_id),
        Ok(ObserveResult::DifferentTask)
    ));
    let other = TaskPrincipal::new("other").expect("principal");
    assert!(matches!(
        observer.observe(&authority, &other, &first_task.task_id),
        Err(TaskAuthorityError::TaskNotFound)
    ));
    authority
        .cancel_task_for_principal(&principal, &first_task.task_id)
        .expect("cancel first");
    authority
        .cancel_task_for_principal(&principal, &second_task.task_id)
        .expect("cancel second");
}
