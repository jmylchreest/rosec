//! Item cache state owned by `ServiceState`.
//!
//! Single canonical map of every item the service knows about, keyed by D-Bus
//! object path.  Each entry carries an [`ItemMeta::locked`] flag tracking the
//! live lock state of its owning provider, which is what makes the
//! Secret Service spec's `(unlocked, locked)` partition possible without
//! erroring on locked providers during `SearchItems`.
//!
//! Per spec, attributes are stored unencrypted, so they remain queryable even
//! while a provider is locked.  When a provider locks, its entries' `locked`
//! flags are flipped to `true` (entries are NOT removed).  When a provider
//! unlocks and syncs, the next cache rebuild replaces those entries with
//! fresh data.
//!
//! `Arc<Mutex<...>>` is preserved so [`crate::collection::CollectionState`]
//! and individual [`crate::item::SecretItem`] objects can share the same map
//! for direct lookup.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rosec_core::ItemMeta;

#[derive(Default)]
pub struct ItemCache {
    /// All items the service knows about, keyed by D-Bus object path.
    pub items: Arc<Mutex<HashMap<String, ItemMeta>>>,
    /// Set of D-Bus item paths currently registered on the object server.
    pub registered_items: Arc<Mutex<HashSet<String>>>,
    /// Timestamp of the last successful cache rebuild.
    pub last_sync: Arc<Mutex<Option<SystemTime>>>,
}

impl ItemCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear the registered-items set (used during bus migration so the
    /// caller can re-register items on the new connection).
    pub fn clear_registered(&self) {
        if let Ok(mut g) = self.registered_items.lock() {
            g.clear();
        }
    }
}
