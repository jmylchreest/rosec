use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::{DedupStrategy, DedupTimeFallback, VaultItemMeta};

type DedupKey = (String, Vec<(String, String)>);

#[derive(Debug, Clone, Copy)]
pub struct DedupConfig {
    pub strategy: DedupStrategy,
    pub time_fallback: DedupTimeFallback,
}

#[derive(Debug, Clone)]
pub struct DedupResult {
    pub items: Vec<VaultItemMeta>,
}

pub fn dedup(
    mut items: Vec<VaultItemMeta>,
    config: DedupConfig,
    backend_priority: &HashMap<String, usize>,
) -> DedupResult {
    if items.is_empty() {
        return DedupResult { items };
    }

    let mut by_key: HashMap<DedupKey, Vec<VaultItemMeta>> = HashMap::new();
    for item in items.drain(..) {
        let mut attrs: Vec<(String, String)> = item
            .attributes
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        attrs.sort();
        let key = (item.label.clone(), attrs);
        by_key.entry(key).or_default().push(item);
    }

    let mut result = Vec::new();
    for (_key, candidates) in by_key {
        let winner = match config.strategy {
            DedupStrategy::Priority => select_by_priority(&candidates, backend_priority),
            DedupStrategy::Newest => {
                select_by_newest(&candidates, config.time_fallback, backend_priority)
            }
        };
        result.push(winner);
    }

    DedupResult { items: result }
}

fn select_by_priority(
    candidates: &[VaultItemMeta],
    backend_priority: &HashMap<String, usize>,
) -> VaultItemMeta {
    // Callers always pass non-empty slices (grouped from a non-empty HashMap entry).
    // We use `unwrap_or_else` with the first element as a safe fallback rather than
    // panicking, since `min_by_key` only returns None on an empty iterator and we
    // have a debug_assert guarding that invariant.
    debug_assert!(!candidates.is_empty(), "candidates must be non-empty");
    candidates
        .iter()
        .min_by_key(|item| {
            backend_priority
                .get(&item.backend_id)
                .copied()
                .unwrap_or(usize::MAX)
        })
        .cloned()
        .unwrap_or_else(|| candidates[0].clone())
}

fn select_by_newest(
    candidates: &[VaultItemMeta],
    fallback: DedupTimeFallback,
    backend_priority: &HashMap<String, usize>,
) -> VaultItemMeta {
    // Callers always pass non-empty slices (grouped from a non-empty HashMap entry).
    debug_assert!(!candidates.is_empty(), "candidates must be non-empty");
    // Use iterator destructuring so there is no index-based access.
    let (first, rest) = match candidates.split_first() {
        Some(pair) => pair,
        // Empty slice: debug_assert above catches this in test builds;
        // in release builds return a zero-value item rather than panic.
        None => {
            return VaultItemMeta {
                id: String::new(),
                backend_id: String::new(),
                label: String::new(),
                attributes: crate::Attributes::new(),
                created: None,
                modified: None,
                locked: true,
            };
        }
    };
    let mut winner = first.clone();
    for candidate in rest {
        let candidate_time = timestamp(candidate, fallback);
        let winner_time = timestamp(&winner, fallback);
        if candidate_time > winner_time {
            winner = candidate.clone();
            continue;
        }
        if candidate_time == winner_time {
            let candidate_priority = backend_priority
                .get(&candidate.backend_id)
                .copied()
                .unwrap_or(usize::MAX);
            let winner_priority = backend_priority
                .get(&winner.backend_id)
                .copied()
                .unwrap_or(usize::MAX);
            if candidate_priority < winner_priority {
                winner = candidate.clone();
            }
        }
    }
    winner
}

fn timestamp(item: &VaultItemMeta, fallback: DedupTimeFallback) -> SystemTime {
    if let Some(modified) = item.modified {
        return modified;
    }
    match fallback {
        DedupTimeFallback::Created => item.created.unwrap_or(SystemTime::UNIX_EPOCH),
        DedupTimeFallback::None => SystemTime::UNIX_EPOCH,
    }
}

pub fn backend_priority_map<I>(ids: I) -> HashMap<String, usize>
where
    I: IntoIterator<Item = String>,
{
    ids.into_iter()
        .enumerate()
        .map(|(idx, id)| (id, idx))
        .collect()
}

pub fn is_stale(last_access: SystemTime, timeout_minutes: u64) -> bool {
    match SystemTime::now().duration_since(last_access) {
        Ok(elapsed) => elapsed >= Duration::from_secs(timeout_minutes * 60),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Attributes, VaultItemMeta};

    fn meta(
        id: &str,
        backend_id: &str,
        label: &str,
        modified: Option<SystemTime>,
    ) -> VaultItemMeta {
        VaultItemMeta {
            id: id.to_string(),
            backend_id: backend_id.to_string(),
            label: label.to_string(),
            attributes: Attributes::new(),
            created: None,
            modified,
            locked: false,
        }
    }

    #[test]
    fn dedup_prefers_newest() {
        let older = meta("1", "a", "item", Some(SystemTime::UNIX_EPOCH));
        let newer = meta(
            "2",
            "b",
            "item",
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(60)),
        );

        let config = DedupConfig {
            strategy: DedupStrategy::Newest,
            time_fallback: DedupTimeFallback::Created,
        };
        let map = backend_priority_map(vec!["a".to_string(), "b".to_string()]);
        let result = dedup(vec![older, newer], config, &map);
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].id, "2");
    }

    #[test]
    fn dedup_prefers_priority_when_equal() {
        let a = meta("1", "a", "item", Some(SystemTime::UNIX_EPOCH));
        let b = meta("2", "b", "item", Some(SystemTime::UNIX_EPOCH));

        let config = DedupConfig {
            strategy: DedupStrategy::Newest,
            time_fallback: DedupTimeFallback::Created,
        };
        let map = backend_priority_map(vec!["b".to_string(), "a".to_string()]);
        let result = dedup(vec![a, b], config, &map);
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].backend_id, "b");
    }
}
