//! Item cache state owned by `ServiceState`.
//!
//! The cache has two layers:
//!
//! - `items` — the currently-mounted D-Bus items by object path.  Built
//!   from unlocked providers on each cache rebuild.
//! - `metadata_cache` — a persistent metadata-only cache that survives
//!   lock/unlock cycles.  Used by `SearchItems` so it can return locked
//!   items in the `locked` partition without erroring.
//!
//! `Arc<Mutex<...>>` is preserved so [`crate::collection::CollectionState`]
//! can share the `items` map with the cache for direct lookup.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rosec_core::ItemMeta;

#[derive(Default)]
pub struct ItemCache {
    /// Currently-mounted D-Bus items, keyed by object path.
    pub items: Arc<Mutex<HashMap<String, ItemMeta>>>,
    /// Set of D-Bus item paths currently registered on the object server.
    pub registered_items: Arc<Mutex<HashSet<String>>>,
    /// Timestamp of the last successful cache rebuild.
    pub last_sync: Arc<Mutex<Option<SystemTime>>>,
    /// Persistent metadata cache that survives provider lock/unlock cycles.
    ///
    /// Per the Secret Service spec, `SearchItems` is a metadata-only
    /// operation that MUST never error when providers are locked — items
    /// from locked providers go in the `locked` return list.  Attributes
    /// are stored unencrypted per spec, so they are always available.
    ///
    /// This cache is populated during cache rebuilds and **never cleared**
    /// when providers lock.  When a provider locks, items belonging to it
    /// have their `locked` flag flipped to `true`.  When a provider
    /// unlocks and syncs, the cache rebuild replaces those entries with
    /// fresh data.
    pub metadata_cache: Arc<Mutex<HashMap<String, ItemMeta>>>,
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
