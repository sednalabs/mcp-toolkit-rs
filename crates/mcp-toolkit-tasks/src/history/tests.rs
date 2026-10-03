use super::*;
use rmcp::task_manager::TaskOptions;

#[tokio::test]
async fn records_and_lists_only_after_principal_authorization() {
    let authority = TaskAuthority::new();
    let owner = TaskPrincipal::new("owner-a").expect("principal");
    let other = TaskPrincipal::new("owner-b").expect("principal");
    let task = authority
        .spawn_for_principal(owner.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { std::future::pending().await })
        })
        .expect("spawn");
    let history = OperationHistory::new(HistoryLimits {
        max_entries: 2,
        max_terminal_age: Duration::from_secs(60),
    });
    history
        .record(&authority, &owner, &task.task_id)
        .expect("authorized record");
    assert!(matches!(
        history.record(&authority, &other, &task.task_id),
        Err(HistoryError::Authority(TaskAuthorityError::TaskNotFound))
    ));
    assert!(history.get(&other, &task.task_id).expect("read").is_none());
    assert!(history.list(&other, 10).expect("list").is_empty());
    assert_eq!(history.list(&owner, 10).expect("owner list").len(), 1);
    authority
        .cancel_task_for_principal(&owner, &task.task_id)
        .expect("cancel");
}

#[tokio::test]
async fn global_capacity_preserves_active_entries_across_principals() {
    let authority = TaskAuthority::new();
    let first = TaskPrincipal::new("first").expect("principal");
    let second = TaskPrincipal::new("second").expect("principal");
    let first_task = authority
        .spawn_for_principal(first.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { std::future::pending().await })
        })
        .expect("first task");
    let second_task = authority
        .spawn_for_principal(second.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { std::future::pending().await })
        })
        .expect("second task");
    let history = OperationHistory::new(HistoryLimits {
        max_entries: 1,
        max_terminal_age: Duration::from_secs(60),
    });
    history
        .record(&authority, &first, &first_task.task_id)
        .expect("first record");
    assert!(matches!(
        history.record(&authority, &second, &second_task.task_id),
        Err(HistoryError::CapacityFull)
    ));
    assert!(history
        .get(&first, &first_task.task_id)
        .expect("first read")
        .is_some());
    assert!(history
        .get(&second, &second_task.task_id)
        .expect("second read")
        .is_none());
    authority
        .cancel_task_for_principal(&first, &first_task.task_id)
        .expect("cancel first");
    authority
        .cancel_task_for_principal(&second, &second_task.task_id)
        .expect("cancel second");
}

#[tokio::test]
async fn zero_terminal_age_hides_entry_from_get_and_list() {
    let authority = TaskAuthority::new();
    let principal = TaskPrincipal::new("owner").expect("principal");
    let task = authority
        .spawn_for_principal(principal.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(rmcp::model::CallToolResult::success(vec![])) })
        })
        .expect("task");
    let history = OperationHistory::new(HistoryLimits {
        max_entries: 1,
        max_terminal_age: Duration::ZERO,
    });
    history
        .record(&authority, &principal, &task.task_id)
        .expect("record");
    assert!(history
        .get(&principal, &task.task_id)
        .expect("get")
        .is_none());
    assert!(history.list(&principal, 10).expect("list").is_empty());
}
