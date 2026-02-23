use crate::dedup::{backend_priority_map, dedup, DedupConfig};
use crate::{DedupStrategy, DedupTimeFallback, VaultItemMeta};

#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub dedup_strategy: DedupStrategy,
    pub dedup_time_fallback: DedupTimeFallback,
}

#[derive(Debug)]
pub struct Router {
    config: RouterConfig,
}

impl Router {
    pub fn new(config: RouterConfig) -> Self {
        Self { config }
    }

    pub fn dedup(&self, items: Vec<VaultItemMeta>, backend_order: &[String]) -> Vec<VaultItemMeta> {
        let config = DedupConfig {
            strategy: self.config.dedup_strategy,
            time_fallback: self.config.dedup_time_fallback,
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
