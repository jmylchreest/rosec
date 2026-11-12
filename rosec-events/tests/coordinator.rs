use rosec_core::changes::{ChangesSince, RefreshOutcome};
use rosec_events::EventCoordinator;

#[tokio::test]
async fn coordinator_runs_without_a_transport_and_rejects_stale_results() {
    let events = EventCoordinator::new(|m| (m.provider_id.clone(), m.id.clone()));
    let mut changes = events.subscribe();
    let epoch = events.begin_refresh();
    events.registry_change(|| ());
    assert!(!events.commit_refresh(epoch, vec![], |inventory| inventory.items()));
    let epoch = events.begin_refresh();
    assert!(events.commit_refresh(
        epoch,
        vec![("a".into(), RefreshOutcome::Complete(vec![]))],
        |inventory| inventory.items()
    ));
    events.set_locked(Some("a"), true, &["a".into()]);
    changes.changed().await.unwrap();
    assert!(!matches!(
        events.changes_since(0),
        ChangesSince::ResyncRequired { .. }
    ));
    assert!(events.snapshot().0 > 0);
}
