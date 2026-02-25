use std::sync::RwLock;

use crate::dedup::{DedupConfig, backend_priority_map, dedup};
use crate::{DedupStrategy, DedupTimeFallback, VaultItemMeta};

#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub dedup_strategy: DedupStrategy,
    pub dedup_time_fallback: DedupTimeFallback,
}

#[derive(Debug)]
pub struct Router {
    config: RwLock<RouterConfig>,
}

impl Router {
    pub fn new(config: RouterConfig) -> Self {
        Self {
            config: RwLock::new(config),
        }
    }

    /// Replace the router config atomically. Called by the config hot-reload watcher.
    pub fn update_config(&self, config: RouterConfig) {
        if let Ok(mut c) = self.config.write() {
            *c = config;
        }
    }

    pub fn dedup(&self, items: Vec<VaultItemMeta>, backend_order: &[String]) -> Vec<VaultItemMeta> {
        let (strategy, time_fallback) = self
            .config
            .read()
            .map(|c| (c.dedup_strategy, c.dedup_time_fallback))
            .unwrap_or((DedupStrategy::Newest, DedupTimeFallback::Created));
        let config = DedupConfig {
            strategy,
            time_fallback,
        };
        let priorities = backend_priority_map(backend_order.iter().cloned());
        dedup(items, config, &priorities).items
    }

    pub fn partition_locked(items: Vec<VaultItemMeta>) -> (Vec<VaultItemMeta>, Vec<VaultItemMeta>) {
        let mut unlocked = Vec::new();
        let mut locked = Vec::new();
        for item in items {
            if item.locked {
                locked.push(item);
            } else {
                unlocked.push(item);
            }
        }
        (unlocked, locked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Attributes;

    #[test]
    fn partitions_locked_items() {
        let items = vec![
            VaultItemMeta {
                id: "1".to_string(),
                backend_id: "a".to_string(),
                label: "one".to_string(),
                attributes: Attributes::new(),
                created: None,
                modified: None,
                locked: false,
            },
            VaultItemMeta {
                id: "2".to_string(),
                backend_id: "b".to_string(),
                label: "two".to_string(),
                attributes: Attributes::new(),
                created: None,
                modified: None,
                locked: true,
            },
        ];

        let (unlocked, locked) = Router::partition_locked(items);
        assert_eq!(unlocked.len(), 1);
        assert_eq!(locked.len(), 1);
    }
}
