use rosec_core::{
    ItemMeta,
    changes::{ChangeJournal, ChangesSince, Inventory, RefreshOutcome},
};
use std::collections::HashMap;
fn item(provider: &str, id: &str) -> ItemMeta {
    ItemMeta {
        id: id.into(),
        provider_id: provider.into(),
        label: id.into(),
        attributes: HashMap::new(),
        created: None,
        modified: None,
        locked: false,
        attribute_hashes: None,
    }
}
#[test]
fn empty_success_removes_items_but_unavailable_preserves_them() {
    let mut inventory = Inventory::default();
    inventory.refresh("a", RefreshOutcome::Complete(vec![item("a", "one")]));
    inventory.refresh("b", RefreshOutcome::Complete(vec![item("b", "two")]));
    inventory.refresh("a", RefreshOutcome::Unavailable);
    inventory.refresh("b", RefreshOutcome::Complete(vec![]));
    let items = inventory.items();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].provider_id, "a");
    inventory.refresh("a", RefreshOutcome::Locked);
    assert!(inventory.items()[0].locked);
}
#[test]
fn journal_is_idempotent_and_reports_lag_with_a_current_revision() {
    let mut journal = ChangeJournal::new(2);
    let one = item("a", "one");
    assert!(journal.commit(std::slice::from_ref(&one)).is_some());
    assert!(journal.commit(std::slice::from_ref(&one)).is_none());
    let mut edited = one.clone();
    edited.label = "edited".into();
    journal.commit(&[edited]);
    journal.commit(&[]);
    assert!(matches!(
        journal.since(0),
        ChangesSince::ResyncRequired { revision: 3 }
    ));
    match journal.since(1) {
        ChangesSince::Batches(batches) => {
            assert_eq!(batches.len(), 2);
            assert_eq!(batches[1].removed[0].item_id, "one");
        }
        _ => panic!("retained revisions should replay"),
    }
}
#[test]
fn inventory_keeps_hidden_candidates_and_supports_local_mutations() {
    let mut inventory = Inventory::default();
    inventory.refresh("a", RefreshOutcome::Complete(vec![item("a", "same")]));
    inventory.refresh("b", RefreshOutcome::Complete(vec![item("b", "same")]));
    assert_eq!(inventory.items().len(), 2);
    inventory.remove("a", "same");
    assert_eq!(inventory.items()[0].provider_id, "b");
    inventory.upsert(item("b", "new"));
    inventory.remove_provider("b");
    assert!(inventory.items().is_empty());
}

#[test]
fn oversized_change_requires_resnapshot_and_history_has_a_byte_budget() {
    let mut journal = ChangeJournal::with_history_limit(256, 1024);
    let entries: Vec<_> = (0..100).map(|i| item("a", &format!("item-{i}"))).collect();
    journal.commit(&entries);
    assert!(journal.retained_history_bytes() <= 1024);
    assert!(matches!(
        journal.since(0),
        ChangesSince::ResyncRequired { revision: 1 }
    ));
    assert!(matches!(journal.since(1), ChangesSince::Batches(b) if b.is_empty()));
}

#[test]
fn large_inventory_history_stays_bounded() {
    let started = std::time::Instant::now();
    let mut items: Vec<_> = (0..10_000)
        .map(|i| {
            let mut meta = item("provider", &format!("item-{i:05}"));
            meta.attributes
                .insert("description".into(), "x".repeat(512));
            meta
        })
        .collect();
    let mut journal = ChangeJournal::new(256);
    journal.commit(&items);
    for revision in 0..12 {
        for meta in &mut items {
            meta.locked = revision % 2 == 0;
        }
        journal.commit(&items);
        assert!(journal.retained_history_bytes() <= 4 * 1024 * 1024);
    }
    println!(
        "inventory=10000 revisions=13 retained_payload_bytes={} elapsed_ms={}",
        journal.retained_history_bytes(),
        started.elapsed().as_millis()
    );
    assert!(matches!(
        journal.since(0),
        ChangesSince::ResyncRequired { .. }
    ));
}

#[test]
fn inventory_preserves_the_existing_winner_for_equal_priority_duplicates() {
    let mut first = item("a", "z-first");
    first.label = "duplicate".into();
    let mut second = item("a", "a-second");
    second.label = "duplicate".into();
    let input = vec![first, second];
    let router = rosec_core::router::Router::new(rosec_core::router::RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    });
    let expected = router.dedup(input.clone(), &["a".into()]);
    let mut inventory = Inventory::default();
    inventory.refresh("a", RefreshOutcome::Complete(input));
    assert_eq!(router.dedup(inventory.items(), &["a".into()]), expected);
}
