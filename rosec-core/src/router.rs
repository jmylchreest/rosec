use std::sync::RwLock;

use crate::dedup::{DedupConfig, dedup, provider_priority_map};
use crate::{DedupStrategy, DedupTimeFallback, ItemMeta};

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

    pub fn dedup(&self, items: Vec<ItemMeta>, provider_order: &[String]) -> Vec<ItemMeta> {
        let (strategy, time_fallback) = self
            .config
            .read()
            .map(|c| (c.dedup_strategy, c.dedup_time_fallback))
            .unwrap_or((DedupStrategy::Newest, DedupTimeFallback::Created));
        let config = DedupConfig {
            strategy,
            time_fallback,
        };
        let priorities = provider_priority_map(provider_order.iter().cloned());
        dedup(items, config, &priorities).items
    }
}
