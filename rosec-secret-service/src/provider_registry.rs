//! Provider registry owned by `ServiceState`.
//!
//! Holds the live set of `Arc<dyn Provider>` instances, their config-driven
//! ordering (used by the Priority dedup strategy), and per-provider config
//! lookups (`return_attr` patterns and optional collection label).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use rosec_core::Provider;

const DEFAULT_RETURN_ATTR: &[&str] = &["password", "number", "private_key", "notes"];

pub struct ProviderRegistry {
    /// All registered providers, keyed by provider ID.  `RwLock` to support
    /// hot-reload without restarting the daemon.
    providers: RwLock<HashMap<String, Arc<dyn Provider>>>,
    /// Provider IDs in the order they were configured (fan-out order).
    provider_order: RwLock<Vec<String>>,
    /// Per-provider ordered list of attribute name glob patterns used to
    /// select which sensitive attribute to return for standard Secret Service
    /// `GetSecret` calls.  Falls back to [`DEFAULT_RETURN_ATTR`] when a
    /// provider has no entry.
    return_attr_map: RwLock<HashMap<String, Vec<String>>>,
    /// Optional collection label per provider.  Stamped onto every item from
    /// that provider as the `"collection"` attribute at cache-build time.
    collection_map: RwLock<HashMap<String, String>>,
}

impl ProviderRegistry {
    pub fn new(
        providers: Vec<Arc<dyn Provider>>,
        return_attr_map: HashMap<String, Vec<String>>,
        collection_map: HashMap<String, String>,
    ) -> Self {
        let provider_order: Vec<String> = providers.iter().map(|b| b.id().to_string()).collect();
        let providers_map: HashMap<String, Arc<dyn Provider>> = providers
            .into_iter()
            .map(|b| (b.id().to_string(), b))
            .collect();
        Self {
            providers: RwLock::new(providers_map),
            provider_order: RwLock::new(provider_order),
            return_attr_map: RwLock::new(return_attr_map),
            collection_map: RwLock::new(collection_map),
        }
    }

    /// Return providers in configured order (Arc clones).
    pub fn ordered(&self) -> Vec<Arc<dyn Provider>> {
        let order = self
            .provider_order
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let map = self.providers.read().unwrap_or_else(|e| e.into_inner());
        order
            .iter()
            .filter_map(|id| map.get(id))
            .map(Arc::clone)
            .collect()
    }

    pub fn by_id(&self, id: &str) -> Option<Arc<dyn Provider>> {
        self.providers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .map(Arc::clone)
    }

    pub fn order_snapshot(&self) -> Vec<String> {
        self.provider_order
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Number of currently registered providers.
    pub fn count(&self) -> usize {
        self.providers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// `true` if a provider with this ID is currently registered.
    pub fn contains(&self, id: &str) -> bool {
        self.providers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(id)
    }

    /// Hot-add a new provider.  No-op if the ID is already registered.
    pub fn add(&self, provider: Arc<dyn Provider>) {
        let id = provider.id().to_string();
        let mut map = self.providers.write().unwrap_or_else(|e| e.into_inner());
        if map.contains_key(&id) {
            return;
        }
        map.insert(id.clone(), provider);
        drop(map);
        self.provider_order
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(id);
    }

    /// Reorder `provider_order` to match `new_order`.  Returns `true` if the
    /// ordering actually changed.
    pub fn reorder(&self, new_order: &[String]) -> bool {
        let mut order = self
            .provider_order
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let current: HashSet<&str> = order.iter().map(String::as_str).collect();
        let reordered: Vec<String> = new_order
            .iter()
            .filter(|id| current.contains(id.as_str()))
            .cloned()
            .collect();
        let new_set: HashSet<&str> = new_order.iter().map(String::as_str).collect();
        let mut result = reordered;
        for id in order.iter() {
            if !new_set.contains(id.as_str()) {
                result.push(id.clone());
            }
        }
        if *order != result {
            *order = result;
            true
        } else {
            false
        }
    }

    /// Remove a provider from the registry and return it.  The caller is
    /// responsible for locking it and dropping it (so in-memory secrets are
    /// zeroized).  Returns `None` if no provider with that ID was found.
    pub fn remove(&self, id: &str) -> Option<Arc<dyn Provider>> {
        let provider = {
            let mut map = self.providers.write().unwrap_or_else(|e| e.into_inner());
            map.remove(id)
        };
        if provider.is_some() {
            self.provider_order
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|existing| existing != id);
        }
        provider
    }

    /// Return the `return_attr` patterns for a given provider ID, or the
    /// default list when no override is configured.
    pub fn return_attr_patterns(&self, provider_id: &str) -> Vec<String> {
        let map = self
            .return_attr_map
            .read()
            .unwrap_or_else(|e| e.into_inner());
        map.get(provider_id).cloned().unwrap_or_else(|| {
            DEFAULT_RETURN_ATTR
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        })
    }

    /// Look up the optional collection label stamped onto items from this
    /// provider.
    pub fn collection_label(&self, provider_id: &str) -> Option<String> {
        self.collection_map
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(provider_id)
            .cloned()
    }
}
