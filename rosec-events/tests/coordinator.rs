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

#[tokio::test]
async fn confirmed_secret_change_wakes_consumers_without_a_metadata_listing() {
    let events = EventCoordinator::new(|m| (m.provider_id.clone(), m.id.clone()));
    let mut subscription = events.subscribe();
    events.confirm_content_changed("hidden-provider");
    subscription.changed().await.unwrap();
    match events.changes_since(0) {
        ChangesSince::Batches(batches) => {
            assert_eq!(batches.len(), 1);
            assert_eq!(batches[0].providers_changed, ["hidden-provider"]);
            assert!(batches[0].changed.is_empty());
        }
        _ => panic!("expected a replayable provider change"),
    }
    assert!(events.snapshot().1.is_empty());
}
