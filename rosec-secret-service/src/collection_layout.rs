use std::collections::BTreeMap;
use std::sync::Arc;

use rosec_core::config::{CollectionConfig, resolve_collections};
use rosec_core::{Capability, Provider};

use crate::server::DEFAULT_COLLECTION_PATH;

pub(crate) const COLLECTION_ROOT: &str = "/org/freedesktop/secrets/collection";
const ALIAS_ROOT: &str = "/org/freedesktop/secrets/aliases";

pub(crate) struct CollectionView {
    pub label: String,
    pub providers: Vec<String>,
    pub writer: Option<String>,
    pub legacy: bool,
}

impl CollectionView {
    pub fn legacy() -> Self {
        Self {
            label: "default".into(),
            providers: vec![],
            writer: None,
            legacy: true,
        }
    }

    pub fn includes(&self, provider: &str) -> bool {
        self.legacy || self.providers.iter().any(|id| id == provider)
    }
}

pub(crate) struct CollectionLayout {
    pub canonical: BTreeMap<String, Arc<CollectionView>>,
    aliases: BTreeMap<String, String>,
    item_parents: BTreeMap<String, String>,
    pub legacy: bool,
}

impl CollectionLayout {
    pub fn new(
        config: &[CollectionConfig],
        providers: &[Arc<dyn Provider>],
    ) -> anyhow::Result<Self> {
        let legacy = config.is_empty();
        let mut canonical = BTreeMap::new();
        let mut aliases = BTreeMap::new();
        let mut item_parents = BTreeMap::new();
        if legacy {
            canonical.insert(
                DEFAULT_COLLECTION_PATH.to_owned(),
                Arc::new(CollectionView::legacy()),
            );
            aliases.insert("default".to_owned(), DEFAULT_COLLECTION_PATH.to_owned());
        }
        let writers = resolve_collections(config, |id| {
            providers
                .iter()
                .find(|p| p.id() == id)
                .map(|p| p.capabilities().contains(&Capability::Write))
        })?;
        for (entry, writer) in config.iter().zip(writers) {
            let path = format!("{COLLECTION_ROOT}/{}", entry.id);
            for provider in &entry.providers {
                item_parents
                    .entry(provider.clone())
                    .or_insert_with(|| path.clone());
            }
            for alias in &entry.aliases {
                aliases.insert(alias.clone(), path.clone());
            }
            canonical.insert(
                path,
                Arc::new(CollectionView {
                    label: entry.id.clone(),
                    providers: entry.providers.clone(),
                    writer,
                    legacy,
                }),
            );
        }
        if let Some(default) = aliases.get("default").cloned() {
            aliases.entry("login".into()).or_insert(default);
        }
        Ok(Self {
            canonical,
            aliases,
            item_parents,
            legacy,
        })
    }

    pub fn alias(&self, name: &str) -> &str {
        self.aliases.get(name).map_or("/", String::as_str)
    }

    pub fn at(&self, path: &str) -> Option<&Arc<CollectionView>> {
        let canonical = path
            .strip_prefix(ALIAS_ROOT)
            .and_then(|rest| rest.strip_prefix('/'))
            .map_or(path, |alias| self.alias(alias));
        self.canonical.get(canonical)
    }

    pub fn objects(&self) -> impl Iterator<Item = (String, &Arc<CollectionView>)> {
        self.canonical
            .iter()
            .map(|(path, view)| (path.clone(), view))
            .chain(
                self.aliases
                    .iter()
                    .map(|(alias, path)| (format!("{ALIAS_ROOT}/{alias}"), &self.canonical[path])),
            )
    }

    // A provider can appear in several views. Keep a single item object,
    // underneath the first collection that includes the provider.
    pub fn item_parent(&self, provider: &str) -> &str {
        self.item_parents
            .get(provider)
            .map_or(DEFAULT_COLLECTION_PATH, String::as_str)
    }

    pub fn includes(&self, provider: &str) -> bool {
        self.legacy || self.item_parents.contains_key(provider)
    }
}
