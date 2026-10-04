use super::*;
use rmcp::task_manager::TaskOptions;

#[test]
fn application_summary_keeps_application_identity_and_revision_explicit() {
    let summary = ApplicationTaskSummary {
        application_task_id: "app-task-17".to_owned(),
        state: OperationState::Working,
        created_at: "2026-10-04T05:00:00Z".to_owned(),
        started_at: None,
        last_updated_at: "2026-10-04T05:00:00Z".to_owned(),
        finished_at: None,
        application_revision: 1,
    };

    assert_eq!(summary.application_task_id, "app-task-17");
    assert_eq!(summary.application_revision, 1);
    assert_eq!(summary.state, OperationState::Working);
    assert!(summary.started_at.is_none());
    assert!(summary.finished_at.is_none());
}

fn test_authority() -> TaskAuthority {
    let capacity = std::num::NonZeroUsize::new(16).expect("nonzero test capacity");
    TaskAuthority::new(crate::TaskAuthorityConfig {
        max_retained_tasks: capacity,
        max_waiters: capacity,
        fallback_reads_per_second: capacity,
    })
}

#[tokio::test]
async fn records_and_lists_only_after_principal_authorization() {
    let authority = test_authority();
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
    let authority = test_authority();
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
    let authority = test_authority();
    let principal = TaskPrincipal::new("owner").expect("principal");
    let task = authority
        .spawn_for_principal(principal.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(rmcp::model::CallToolResult::success(vec![])) })
        })
        .expect("task");
    authority
        .wait(
            &principal,
            &task.task_id,
            None,
            Duration::from_secs(2),
            crate::TaskWaitCondition::Terminal,
        )
        .await
        .expect("terminal wait")
        .expect("terminal snapshot");
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

#[tokio::test]
async fn terminal_summary_has_only_authoritative_terminal_timestamp() {
    let authority = test_authority();
    let principal = TaskPrincipal::new("terminal-owner").expect("principal");
    let task = authority
        .spawn_for_principal(principal.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(rmcp::model::CallToolResult::success(vec![])) })
        })
        .expect("task");
    let snapshot = authority
        .wait(
            &principal,
            &task.task_id,
            None,
            Duration::from_secs(2),
            crate::TaskWaitCondition::Terminal,
        )
        .await
        .expect("terminal wait")
        .expect("terminal snapshot");
    assert!(snapshot.task.status().is_terminal());
    let history = OperationHistory::new(HistoryLimits {
        max_entries: 1,
        max_terminal_age: Duration::from_secs(3600),
    });

    let summary = history
        .record(&authority, &principal, &task.task_id)
        .expect("record");

    assert_eq!(summary.started_at, None);
    assert_eq!(
        summary.finished_at.as_deref(),
        Some(snapshot.task.task.last_updated_at.as_str())
    );
}

#[tokio::test]
async fn terminal_reread_preserves_first_monotonic_age_instant() {
    let authority = test_authority();
    let principal = TaskPrincipal::new("terminal-owner").expect("principal");
    let task = authority
        .spawn_for_principal(principal.clone(), TaskOptions::default(), |_ctx| {
            Box::pin(async { Ok(rmcp::model::CallToolResult::success(vec![])) })
        })
        .expect("task");
    authority
        .wait(
            &principal,
            &task.task_id,
            None,
            Duration::from_secs(2),
            crate::TaskWaitCondition::Terminal,
        )
        .await
        .expect("terminal wait")
        .expect("terminal snapshot");
    let history = OperationHistory::new(HistoryLimits {
        max_entries: 1,
        max_terminal_age: Duration::from_secs(3600),
    });
    history
        .record(&authority, &principal, &task.task_id)
        .expect("first record");
    let first_terminal_at = Instant::now() - Duration::from_secs(30);
    {
        let mut partitions = history.partitions.lock().expect("history lock");
        let item = partitions
            .get_mut(principal.as_str())
            .and_then(|items| items.first_mut())
            .expect("stored terminal summary");
        item.terminal_at = Some(first_terminal_at);
    }

    history
        .record(&authority, &principal, &task.task_id)
        .expect("terminal reread");

    let partitions = history.partitions.lock().expect("history lock");
    let item = partitions
        .get(principal.as_str())
        .and_then(|items| items.first())
        .expect("retained terminal summary");
    assert_eq!(item.terminal_at, Some(first_terminal_at));
}
