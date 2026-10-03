use super::*;
use crate::{TaskAuthority, TaskPrincipal};
use rmcp::task_manager::TaskOptions;

#[tokio::test]
async fn records_authorized_snapshot_once_and_rejects_another_task() {
    let authority = TaskAuthority::new();
    let principal = TaskPrincipal::new("owner").expect("principal");
    let make_task = || |_ctx| Box::pin(async { std::future::pending().await });
    let first_task = authority
        .spawn_for_principal(principal.clone(), TaskOptions::default(), make_task())
        .expect("first");
    let second_task = authority
        .spawn_for_principal(principal.clone(), TaskOptions::default(), make_task())
        .expect("second");
    let first = authority
        .get_task_for_principal(&principal, &first_task.task_id)
        .expect("snapshot");
    let second = authority
        .get_task_for_principal(&principal, &second_task.task_id)
        .expect("snapshot");
    let mut observer = LifecycleObserver::new();
    assert_eq!(observer.observe(&first), ObserveResult::Recorded);
    assert_eq!(observer.observe(&first), ObserveResult::Duplicate);
    let newer_same_snapshot = crate::AuthorizedTaskSnapshot {
        task: first.task.clone(),
        revision: first.revision + 1,
    };
    assert_eq!(
        observer.observe(&newer_same_snapshot),
        ObserveResult::Recorded
    );
    assert_eq!(observer.observe(&second), ObserveResult::DifferentTask);
    authority
        .cancel_task_for_principal(&principal, &first_task.task_id)
        .expect("cancel");
    authority
        .cancel_task_for_principal(&principal, &second_task.task_id)
        .expect("cancel");
}
