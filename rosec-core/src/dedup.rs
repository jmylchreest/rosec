use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::{DedupStrategy, DedupTimeFallback, ItemMeta};

type DedupKey = (String, Vec<(String, String)>);

#[derive(Debug, Clone, Copy)]
pub struct DedupConfig {
    pub strategy: DedupStrategy,
    pub time_fallback: DedupTimeFallback,
}

#[derive(Debug, Clone)]
pub struct DedupResult {
    pub items: Vec<ItemMeta>,
}

pub fn dedup(
    mut items: Vec<ItemMeta>,
    config: DedupConfig,
    provider_priority: &HashMap<String, usize>,
) -> DedupResult {
    if items.is_empty() {
        return DedupResult { items };
    }

    let mut by_key: HashMap<DedupKey, Vec<ItemMeta>> = HashMap::new();
    for item in items.drain(..) {
        // Exclude rosec-internal attributes (`rosec:*`) and freedesktop
        // schema metadata (`xdg:*`) from the dedup key.  The `rosec:*` attrs
        // are stamped by the service layer or provider plugins and carry
        // per-provider metadata (e.g. `rosec:provider`, `rosec:type`,
        // `rosec:gnome-keyring:item-id`).  The `xdg:schema` attr records which
        // libsecret schema created the item — it is not application-facing
        // identity and may differ across providers.  Two items from different
        // providers that share the same label and the same client-visible
        // attributes should be considered duplicates.
        let mut attrs: Vec<(String, String)> = item
            .attributes
            .iter()
            .filter(|(k, _)| !k.starts_with("rosec:") && !k.starts_with("xdg:"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        attrs.sort();
        let key = (item.label.clone(), attrs);
        by_key.entry(key).or_default().push(item);
    }

    let mut result = Vec::new();
    for (_key, candidates) in by_key {
        let winner = match config.strategy {
            DedupStrategy::Priority => select_by_priority(&candidates, provider_priority),
            DedupStrategy::Newest => {
                select_by_newest(&candidates, config.time_fallback, provider_priority)
            }
        };
        result.push(winner);
    }

    DedupResult { items: result }
}

fn select_by_priority(
    candidates: &[ItemMeta],
    provider_priority: &HashMap<String, usize>,
) -> ItemMeta {
    // Callers always pass non-empty slices (grouped from a non-empty HashMap entry).
    // We use `unwrap_or_else` with the first element as a safe fallback rather than
    // panicking, since `min_by_key` only returns None on an empty iterator and we
    // have a debug_assert guarding that invariant.
    debug_assert!(!candidates.is_empty(), "candidates must be non-empty");
    candidates
        .iter()
        .min_by_key(|item| {
            provider_priority
                .get(&item.provider_id)
                .copied()
                .unwrap_or(usize::MAX)
        })
        .cloned()
        .unwrap_or_else(|| candidates[0].clone())
}

fn select_by_newest(
    candidates: &[ItemMeta],
    fallback: DedupTimeFallback,
    provider_priority: &HashMap<String, usize>,
) -> ItemMeta {
    // Callers always pass non-empty slices (grouped from a non-empty HashMap entry).
    debug_assert!(!candidates.is_empty(), "candidates must be non-empty");
    let (first, rest) = match candidates.split_first() {
        Some(pair) => pair,
        // Empty slice: debug_assert above catches this in test builds;
        // in release builds return a zero-value item rather than panic.
        None => {
            return ItemMeta {
                id: String::new(),
                provider_id: String::new(),
                label: String::new(),
                attributes: crate::Attributes::new(),
                created: None,
                modified: None,
                locked: true,
                attribute_hashes: None,
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
            let candidate_priority = provider_priority
                .get(&candidate.provider_id)
                .copied()
                .unwrap_or(usize::MAX);
            let winner_priority = provider_priority
                .get(&winner.provider_id)
                .copied()
                .unwrap_or(usize::MAX);
            if candidate_priority < winner_priority {
                winner = candidate.clone();
            }
        }
    }
    winner
}

fn timestamp(item: &ItemMeta, fallback: DedupTimeFallback) -> SystemTime {
    if let Some(modified) = item.modified {
        return modified;
    }
    match fallback {
        DedupTimeFallback::Created => item.created.unwrap_or(SystemTime::UNIX_EPOCH),
        DedupTimeFallback::None => SystemTime::UNIX_EPOCH,
    }
}

pub fn provider_priority_map<I>(ids: I) -> HashMap<String, usize>
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
    use crate::{Attributes, ItemMeta};

    fn meta(id: &str, provider_id: &str, label: &str, modified: Option<SystemTime>) -> ItemMeta {
        ItemMeta {
            id: id.to_string(),
            provider_id: provider_id.to_string(),
            label: label.to_string(),
            attributes: Attributes::new(),
            created: None,
            modified,
            locked: false,
            attribute_hashes: None,
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
        let map = provider_priority_map(vec!["a".to_string(), "b".to_string()]);
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
        let map = provider_priority_map(vec!["b".to_string(), "a".to_string()]);
        let result = dedup(vec![a, b], config, &map);
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].provider_id, "b");
    }

    /// Items from different providers that share the same label and
    /// client-visible attributes must be grouped together, even when
    /// rosec-internal attributes (`rosec:*`) differ.  This mirrors the
    /// Chrome/Vivaldi scenario where a "Chrome Safe Storage" item with
    /// `application=chrome` exists in both a local vault and gnome-keyring,
    /// with gnome-keyring items carrying extra `rosec:gnome-keyring:*`
    /// metadata.
    #[test]
    fn dedup_ignores_rosec_internal_attributes() {
        let mut local_attrs = Attributes::new();
        local_attrs.insert("application".into(), "chrome".into());
        local_attrs.insert(
            "xdg:schema".into(),
            "chrome_libsecret_os_crypt_password_v2".into(),
        );
        local_attrs.insert("rosec:provider".into(), "local".into());
        local_attrs.insert("rosec:type".into(), "generic".into());

        let mut gk_attrs = Attributes::new();
        gk_attrs.insert("application".into(), "chrome".into());
        gk_attrs.insert(
            "xdg:schema".into(),
            "chrome_libsecret_os_crypt_password_v2".into(),
        );
        gk_attrs.insert("rosec:provider".into(), "gnome-keyring".into());
        gk_attrs.insert("rosec:type".into(), "generic".into());
        gk_attrs.insert("rosec:gnome-keyring:item-id".into(), "3".into());
        gk_attrs.insert("rosec:gnome-keyring:keyring".into(), "Login".into());

        let local_item = ItemMeta {
            id: "local-1".into(),
            provider_id: "local".into(),
            label: "Chrome Safe Storage".into(),
            attributes: local_attrs,
            created: None,
            modified: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(120)),
            locked: false,
            attribute_hashes: None,
        };

        let gk_item = ItemMeta {
            id: "gk-3".into(),
            provider_id: "gnome-keyring".into(),
            label: "Chrome Safe Storage".into(),
            attributes: gk_attrs,
            created: None,
            modified: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(60)),
            locked: false,
            attribute_hashes: None,
        };

        let config = DedupConfig {
            strategy: DedupStrategy::Priority,
            time_fallback: DedupTimeFallback::Created,
        };
        // gnome-keyring has higher priority (lower index) than local
        let map = provider_priority_map(vec!["gnome-keyring".into(), "local".into()]);
        let result = dedup(vec![local_item, gk_item], config, &map);

        assert_eq!(result.items.len(), 1, "should collapse into a single item");
        assert_eq!(
            result.items[0].provider_id, "gnome-keyring",
            "gnome-keyring has higher priority"
        );
    }

    /// Items from different providers may differ on `xdg:schema` (or lack it
    /// entirely).  The dedup key should ignore `xdg:*` attributes so these
    /// are still recognised as duplicates.
    #[test]
    fn dedup_ignores_xdg_schema_mismatch() {
        let mut gk_attrs = Attributes::new();
        gk_attrs.insert("application".into(), "chrome".into());
        gk_attrs.insert(
            "xdg:schema".into(),
            "chrome_libsecret_os_crypt_password_v2".into(),
        );
        gk_attrs.insert("rosec:provider".into(), "gnome-keyring".into());

        // Local item created via import — no xdg:schema at all.
        let mut local_attrs = Attributes::new();
        local_attrs.insert("application".into(), "chrome".into());
        local_attrs.insert("rosec:provider".into(), "local".into());

        let gk_item = ItemMeta {
            id: "gk-3".into(),
            provider_id: "gnome-keyring".into(),
            label: "Chrome Safe Storage".into(),
            attributes: gk_attrs,
            created: None,
            modified: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(60)),
            locked: false,
            attribute_hashes: None,
        };

        let local_item = ItemMeta {
            id: "local-imported".into(),
            provider_id: "local".into(),
            label: "Chrome Safe Storage".into(),
            attributes: local_attrs,
            created: None,
            modified: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(200)),
            locked: false,
            attribute_hashes: None,
        };

        let config = DedupConfig {
            strategy: DedupStrategy::Newest,
            time_fallback: DedupTimeFallback::Created,
        };
        let map = provider_priority_map(vec!["local".into(), "gnome-keyring".into()]);
        let result = dedup(vec![gk_item, local_item], config, &map);

        assert_eq!(
            result.items.len(),
            1,
            "xdg:schema mismatch should not prevent dedup"
        );
        assert_eq!(
            result.items[0].provider_id, "local",
            "local item is newer and should win"
        );
    }
}
