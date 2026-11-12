mod support;
use rosec_core::changes::ChangesSince;
use std::sync::atomic::Ordering;
use support::{MutableProvider, setup};
#[tokio::test]
async fn failed_refresh_retains_items_and_empty_success_removes_them() {
    let a = MutableProvider::new("a");
    a.put("one", "one");
    let b = MutableProvider::new("b");
    b.put("two", "two");
    let (_conn, state) = setup(vec![a.clone(), b.clone()]).await;
    assert_eq!(state.rebuild_cache().await.unwrap().len(), 2);
    let before = state.change_snapshot().0;
    a.fail.store(true, Ordering::SeqCst);
    b.items.lock().unwrap().clear();
    let entries = state.rebuild_cache().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1.provider_id, "a");
    match state.changes_since(before) {
        ChangesSince::Batches(batches) => {
            assert_eq!(batches.len(), 1);
            assert_eq!(batches[0].removed[0].provider_id, "b");
        }
        _ => panic!("unexpected lag"),
    }
    let before = state.change_snapshot().0;
    state.rebuild_cache().await.unwrap();
    assert_eq!(state.change_snapshot().0, before);
}
#[tokio::test]
async fn hidden_duplicate_survives_failure_and_becomes_visible_after_winner_removal() {
    let a = MutableProvider::new("a");
    a.put("one", "same");
    let b = MutableProvider::new("b");
    b.put("two", "same");
    let (_conn, state) = setup(vec![a.clone(), b.clone()]).await;
    let first = state.rebuild_cache().await.unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].1.provider_id, "a");
    a.items.lock().unwrap().clear();
    b.fail.store(true, Ordering::SeqCst);
    let next = state.rebuild_cache().await.unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].1.provider_id, "b");
}
#[tokio::test]
async fn empty_provider_lock_still_produces_a_domain_event() {
    let provider = MutableProvider::new("a");
    let (_conn, state) = setup(vec![provider]).await;
    state.mark_provider_locked_in_cache("a");
    assert!(
        matches!(state.changes_since(0), ChangesSince::Batches(b) if b[0].providers_changed == ["a"])
    );
    let before = state.change_snapshot().0;
    state.mark_provider_locked_in_cache("a");
    assert_eq!(before, state.change_snapshot().0);
}

#[tokio::test]
async fn a_refresh_started_before_lock_cannot_restore_unlocked_metadata() {
    let provider = MutableProvider::new("a");
    provider.put("one", "one");
    let (_conn, state) = setup(vec![provider.clone()]).await;
    state.rebuild_cache().await.unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (resume, wait) = tokio::sync::oneshot::channel();
    *provider.pause.lock().unwrap() = Some((started, wait));
    let refresh_state = state.clone();
    let task = tokio::spawn(async move { refresh_state.rebuild_cache().await.unwrap() });
    ready.await.unwrap();
    state.mark_provider_locked_in_cache("a");
    resume.send(()).unwrap();
    let entries = task.await.unwrap();
    assert!(entries[0].1.locked);
    assert!(state.change_snapshot().1[0].locked);
}

#[tokio::test]
async fn hidden_provider_changes_are_available_to_non_dbus_consumers() {
    let a = MutableProvider::new("a");
    a.put("one", "same");
    let b = MutableProvider::new("b");
    b.put("two", "same");
    let (_conn, state) = setup(vec![a, b.clone()]).await;
    state.rebuild_cache().await.unwrap();
    let before = state.change_snapshot().0;
    // The priority winner is unchanged, but the hidden provider changed.
    b.items.lock().unwrap()[0].modified = Some(std::time::SystemTime::now());
    state.rebuild_cache().await.unwrap();
    match state.changes_since(before) {
        ChangesSince::Batches(batches) => {
            assert_eq!(batches.len(), 1);
            assert_eq!(batches[0].providers_changed, ["b"]);
            assert!(
                batches[0].added.is_empty()
                    && batches[0].changed.is_empty()
                    && batches[0].removed.is_empty()
            );
        }
        _ => panic!("unexpected lag"),
    }
}

#[tokio::test]
async fn removal_during_refresh_cannot_resurrect_the_removed_provider() {
    let provider = MutableProvider::new("a");
    provider.put("one", "one");
    let (_conn, state) = setup(vec![provider.clone()]).await;
    state.rebuild_cache().await.unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (resume, wait) = tokio::sync::oneshot::channel();
    *provider.pause.lock().unwrap() = Some((started, wait));
    let refresh_state = state.clone();
    let task = tokio::spawn(async move { refresh_state.rebuild_cache().await.unwrap() });
    ready.await.unwrap();
    assert!(state.hotreload_remove_provider("a").await);
    resume.send(()).unwrap();
    assert!(task.await.unwrap().is_empty());
    assert!(state.change_snapshot().1.is_empty());
}
