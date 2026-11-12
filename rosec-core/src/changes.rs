//! Transport-independent inventory reconciliation and bounded change history.
//!
//! Callers serialize response processing and commit after updating their read
//! model. Events contain identities only; metadata stays in the read model.
use crate::ItemMeta;
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ItemIdentity {
    pub provider_id: String,
    pub item_id: String,
}
impl From<&ItemMeta> for ItemIdentity {
    fn from(item: &ItemMeta) -> Self {
        Self {
            provider_id: item.provider_id.clone(),
            item_id: item.id.clone(),
        }
    }
}

/// Only a complete successful listing is authoritative about absence.
pub enum RefreshOutcome {
    Complete(Vec<ItemMeta>),
    Locked,
    Unavailable,
}

/// Retains candidates before deduplication, including temporarily unavailable providers.
#[derive(Default)]
pub struct Inventory {
    items: BTreeMap<ItemIdentity, ItemMeta>,
    // Preserve provider listing order: existing deduplication breaks equal
    // priority/time ties using the first candidate, not lexical item IDs.
    order: Vec<ItemIdentity>,
}
impl Inventory {
    pub fn refresh(&mut self, provider: &str, outcome: RefreshOutcome) -> bool {
        match outcome {
            RefreshOutcome::Complete(mut items) => {
                for item in &mut items {
                    item.provider_id = provider.to_owned();
                }
                let changed = self
                    .items
                    .keys()
                    .filter(|key| key.provider_id == provider)
                    .count()
                    != items.len()
                    || items
                        .iter()
                        .any(|item| self.items.get(&ItemIdentity::from(item)) != Some(item));
                self.remove_provider(provider);
                for item in items {
                    self.upsert(item);
                }
                changed
            }
            RefreshOutcome::Locked => {
                let changed = self
                    .items
                    .values()
                    .any(|item| item.provider_id == provider && !item.locked);
                self.mark_locked(Some(provider));
                changed
            }
            RefreshOutcome::Unavailable => false,
        }
    }
    pub fn upsert(&mut self, item: ItemMeta) {
        let key = ItemIdentity::from(&item);
        if !self.items.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.items.insert(key, item);
    }
    pub fn remove(&mut self, provider: &str, id: &str) {
        self.order
            .retain(|key| key.provider_id != provider || key.item_id != id);
        self.items
            .retain(|key, _| key.provider_id != provider || key.item_id != id);
    }
    pub fn remove_provider(&mut self, provider: &str) {
        self.order.retain(|key| key.provider_id != provider);
        self.items.retain(|key, _| key.provider_id != provider);
    }
    pub fn mark_locked(&mut self, provider: Option<&str>) {
        self.set_locked(provider, true);
    }
    pub fn set_locked(&mut self, provider: Option<&str>, locked: bool) {
        for item in self.items.values_mut() {
            if provider.is_none_or(|id| id == item.provider_id) {
                item.locked = locked;
            }
        }
    }
    pub fn items(&self) -> Vec<ItemMeta> {
        self.order
            .iter()
            .filter_map(|key| self.items.get(key))
            .cloned()
            .collect()
    }
}

/// One committed change to the application's visible inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeBatch {
    pub revision: u64,
    pub added: Vec<ItemIdentity>,
    pub changed: Vec<ItemIdentity>,
    pub removed: Vec<ItemIdentity>,
    pub providers_changed: Vec<String>,
}
#[derive(Debug)]
pub enum ChangesSince {
    Batches(Vec<ChangeBatch>),
    /// The subscriber must reconcile its own view with a current snapshot.
    ResyncRequired {
        revision: u64,
    },
}

pub struct ChangeJournal {
    revision: u64,
    capacity: usize,
    snapshot: BTreeMap<ItemIdentity, ItemMeta>,
    history: VecDeque<ChangeBatch>,
    provider_locks: BTreeMap<String, bool>,
    history_bytes: usize,
    max_history_bytes: usize,
}
impl ChangeJournal {
    pub fn new(capacity: usize) -> Self {
        Self::with_history_limit(capacity, 4 * 1024 * 1024)
    }
    /// Bound retained event payloads as well as batch count. Snapshots remain
    /// proportional to the current inventory, never the number of revisions.
    pub fn with_history_limit(capacity: usize, max_history_bytes: usize) -> Self {
        Self {
            revision: 0,
            capacity: capacity.max(1),
            snapshot: BTreeMap::new(),
            history: VecDeque::new(),
            provider_locks: BTreeMap::new(),
            history_bytes: 0,
            max_history_bytes,
        }
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn commit(&mut self, items: &[ItemMeta]) -> Option<ChangeBatch> {
        self.commit_with_provider_changes(items, &[])
    }
    /// Provider changes include hidden inventory so non-UI consumers are not
    /// constrained to the application's deduplicated item view.
    pub fn commit_with_provider_changes(
        &mut self,
        items: &[ItemMeta],
        providers: &[String],
    ) -> Option<ChangeBatch> {
        let next: BTreeMap<_, _> = items
            .iter()
            .map(|item| (ItemIdentity::from(item), item.clone()))
            .collect();
        let added = next
            .keys()
            .filter(|key| !self.snapshot.contains_key(*key))
            .cloned()
            .collect::<Vec<_>>();
        let changed = next
            .iter()
            .filter(|(key, item)| self.snapshot.get(*key).is_some_and(|old| old != *item))
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let removed = self
            .snapshot
            .keys()
            .filter(|key| !next.contains_key(*key))
            .cloned()
            .collect::<Vec<_>>();
        if added.is_empty() && changed.is_empty() && removed.is_empty() && providers.is_empty() {
            return None;
        }
        self.revision = self.revision.saturating_add(1);
        let batch = ChangeBatch {
            revision: self.revision,
            added,
            changed,
            removed,
            providers_changed: providers.to_vec(),
        };
        self.snapshot = next;
        self.retain_batch(&batch);
        Some(batch)
    }
    /// Record confirmed lock state, including providers with no items.
    pub fn provider_lock(&mut self, provider: &str, locked: bool) -> Option<ChangeBatch> {
        if self.provider_locks.insert(provider.to_owned(), locked) == Some(locked) {
            return None;
        }
        self.revision = self.revision.saturating_add(1);
        let batch = ChangeBatch {
            revision: self.revision,
            added: vec![],
            changed: vec![],
            removed: vec![],
            providers_changed: vec![provider.to_owned()],
        };
        self.retain_batch(&batch);
        Some(batch)
    }
    /// A provider confirmed content changes without identifying which public
    /// metadata changed. Invalidate its visible items without reading secrets.
    pub fn invalidate_provider(&mut self, provider: &str) -> Option<ChangeBatch> {
        let changed: Vec<_> = self
            .snapshot
            .keys()
            .filter(|key| key.provider_id == provider)
            .cloned()
            .collect();
        self.revision = self.revision.saturating_add(1);
        let batch = ChangeBatch {
            revision: self.revision,
            added: vec![],
            changed,
            removed: vec![],
            providers_changed: vec![provider.to_owned()],
        };
        self.retain_batch(&batch);
        Some(batch)
    }
    pub fn retained_history_bytes(&self) -> usize {
        self.history_bytes
    }

    pub fn forget_provider(&mut self, provider: &str) {
        self.provider_locks.remove(provider);
    }

    fn retain_batch(&mut self, batch: &ChangeBatch) {
        let retained = batch.clone();
        let bytes = retained.allocated_bytes();
        // An oversized batch cannot be replayed. Advancing the revision while
        // clearing history makes older readers request a current snapshot.
        if bytes > self.max_history_bytes {
            self.history.clear();
            self.history_bytes = 0;
            return;
        }
        self.history_bytes += bytes;
        self.history.push_back(retained);
        while self.history.len() > self.capacity || self.history_bytes > self.max_history_bytes {
            if let Some(removed) = self.history.pop_front() {
                self.history_bytes -= removed.allocated_bytes();
            }
        }
    }

    pub fn since(&self, revision: u64) -> ChangesSince {
        if revision > self.revision
            || (revision < self.revision && self.history.is_empty())
            || self
                .history
                .front()
                .is_some_and(|first| revision < first.revision.saturating_sub(1))
        {
            return ChangesSince::ResyncRequired {
                revision: self.revision,
            };
        }
        ChangesSince::Batches(
            self.history
                .iter()
                .filter(|batch| batch.revision > revision)
                .cloned()
                .collect(),
        )
    }
}

impl ChangeBatch {
    fn allocated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + [&self.added, &self.changed, &self.removed]
                .iter()
                .map(|items| {
                    items.capacity() * std::mem::size_of::<ItemIdentity>()
                        + items
                            .iter()
                            .map(|id| id.provider_id.capacity() + id.item_id.capacity())
                            .sum::<usize>()
                })
                .sum::<usize>()
            + self.providers_changed.capacity() * std::mem::size_of::<String>()
            + self
                .providers_changed
                .iter()
                .map(String::capacity)
                .sum::<usize>()
    }
}
