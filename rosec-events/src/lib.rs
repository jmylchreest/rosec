//! Transport-independent reconciliation, bounded replay and consumer revocation.
//! Keys are supplied by the caller; the coordinator has no transport dependency.
mod consumer_gate;
pub use consumer_gate::ConsumerGate;
use rosec_core::ItemMeta;
use rosec_core::changes::{ChangeJournal, ChangesSince, Inventory, RefreshOutcome};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::{Arc, Mutex};

struct DomainState {
    inventory: Inventory,
    journal: ChangeJournal,
    epoch: u64,
    dirty: HashSet<String>,
}

/// Owns the committed view and its history. Projection readers share the same
/// map; every writer must use this coordinator to preserve revision consistency.
pub struct EventCoordinator<K> {
    domain: Mutex<DomainState>,
    items: Arc<Mutex<HashMap<K, ItemMeta>>>,
    key: fn(&ItemMeta) -> K,
    revision: tokio::sync::watch::Sender<u64>,
    refresh: tokio::sync::Mutex<()>,
}
impl<K: Eq + Hash> EventCoordinator<K> {
    pub fn new(key: fn(&ItemMeta) -> K) -> Self {
        Self {
            domain: Mutex::new(DomainState {
                inventory: Inventory::default(),
                journal: ChangeJournal::new(256),
                epoch: 0,
                dirty: HashSet::new(),
            }),
            items: Arc::new(Mutex::new(HashMap::new())),
            key,
            revision: tokio::sync::watch::channel(0).0,
            refresh: tokio::sync::Mutex::new(()),
        }
    }
    /// Shared read projection for existing adapters. Mutations go through `edit`.
    pub fn projection(&self) -> Arc<Mutex<HashMap<K, ItemMeta>>> {
        Arc::clone(&self.items)
    }
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.revision.subscribe()
    }
    pub fn wake(&self) {
        self.revision.send_modify(|_| {});
    }
    pub fn changes_since(&self, revision: u64) -> ChangesSince {
        self.domain
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .journal
            .since(revision)
    }
    pub fn snapshot(&self) -> (u64, Vec<ItemMeta>) {
        let domain = self.domain.lock().unwrap_or_else(|e| e.into_inner());
        let items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        (domain.journal.revision(), items.values().cloned().collect())
    }
    pub fn note_hint(&self, provider: &str) {
        let mut domain = self.domain.lock().unwrap_or_else(|e| e.into_inner());
        domain.dirty.insert(provider.to_owned());
        domain.epoch += 1;
    }
    /// Invalidate pending listings atomically with a registry mutation.
    pub fn registry_change<T>(&self, change: impl FnOnce() -> T) -> T {
        let mut domain = self.domain.lock().unwrap_or_else(|e| e.into_inner());
        let result = change();
        domain.epoch += 1;
        result
    }
    pub fn remove_provider<T>(&self, id: &str, remove: impl FnOnce() -> Option<T>) -> Option<T> {
        let mut domain = self.domain.lock().unwrap_or_else(|e| e.into_inner());
        let provider = remove()?;
        let mut items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        domain.inventory.remove_provider(id);
        domain.dirty.remove(id);
        domain.journal.forget_provider(id);
        domain.epoch += 1;
        items.retain(|_, meta| meta.provider_id != id);
        if let Some(batch) = domain.journal.commit_with_provider_changes(
            &items.values().cloned().collect::<Vec<_>>(),
            &[id.to_owned()],
        ) {
            self.revision.send_replace(batch.revision);
        }
        Some(provider)
    }
    pub fn set_locked(&self, provider: Option<&str>, locked: bool, providers: &[String]) {
        let mut domain = self.domain.lock().unwrap_or_else(|e| e.into_inner());
        let mut items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        domain.inventory.set_locked(provider, locked);
        for meta in items.values_mut() {
            if provider.is_none_or(|id| meta.provider_id == id) {
                meta.locked = locked;
            }
        }
        domain.epoch += 1;
        if let Some(batch) = domain
            .journal
            .commit(&items.values().cloned().collect::<Vec<_>>())
        {
            self.revision.send_replace(batch.revision);
        }
        for provider in providers {
            if let Some(batch) = domain.journal.provider_lock(provider, locked) {
                self.revision.send_replace(batch.revision);
            }
        }
    }
    pub fn edit(&self, edit: impl FnOnce(&mut Inventory, &mut HashMap<K, ItemMeta>)) {
        let mut domain = self.domain.lock().unwrap_or_else(|e| e.into_inner());
        let mut items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        edit(&mut domain.inventory, &mut items);
        domain.epoch += 1;
        if let Some(batch) = domain
            .journal
            .commit(&items.values().cloned().collect::<Vec<_>>())
        {
            self.revision.send_replace(batch.revision);
        }
    }
    pub async fn refresh_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.refresh.lock().await
    }
    pub fn begin_refresh(&self) -> u64 {
        self.domain.lock().unwrap_or_else(|e| e.into_inner()).epoch
    }
    /// Return false when a concurrent mutation made these results stale.
    pub fn commit_refresh(
        &self,
        epoch: u64,
        outcomes: Vec<(String, RefreshOutcome)>,
        project: impl FnOnce(&Inventory) -> Vec<ItemMeta>,
    ) -> bool {
        let mut domain = self.domain.lock().unwrap_or_else(|e| e.into_inner());
        if domain.epoch != epoch {
            return false;
        }
        let mut items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        let mut changed = Vec::new();
        let mut inventory_changes = Vec::new();
        for (provider, outcome) in outcomes {
            if matches!(&outcome, RefreshOutcome::Complete(_)) && domain.dirty.remove(&provider) {
                changed.push(provider.clone());
            }
            if domain.inventory.refresh(&provider, outcome) {
                inventory_changes.push(provider);
            }
        }
        let visible = project(&domain.inventory);
        items.clear();
        for meta in &visible {
            items.insert((self.key)(meta), meta.clone());
        }
        domain.epoch += 1;
        if let Some(batch) = domain
            .journal
            .commit_with_provider_changes(&visible, &inventory_changes)
        {
            self.revision.send_replace(batch.revision);
        }
        for provider in changed {
            if let Some(batch) = domain.journal.invalidate_provider(&provider) {
                self.revision.send_replace(batch.revision);
            }
        }
        true
    }
}
