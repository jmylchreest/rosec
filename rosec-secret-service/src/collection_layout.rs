use std::collections::BTreeMap;
use std::sync::Arc;

use rosec_core::config::{ALL_COLLECTION_ID, Config, resolve_collections};
use rosec_core::{Capability, Provider};

use crate::server::DEFAULT_COLLECTION_PATH;

pub(crate) const COLLECTION_ROOT: &str = "/org/freedesktop/secrets/collection";
const ALIAS_ROOT: &str = "/org/freedesktop/secrets/aliases";

#[derive(PartialEq, Eq)]
pub(crate) struct CollectionView {
    pub id: String,
    pub label: String,
    pub times: crate::collection_metadata::Times,
    pub providers: Vec<String>,
    pub writer: Option<String>,
    pub legacy: bool,
}

impl CollectionView {
    pub fn legacy() -> Self {
        Self {
            id: ALL_COLLECTION_ID.into(),
            label: "default".into(),
            times: Default::default(),
            providers: vec![],
            writer: None,
            legacy: true,
        }
    }

    pub fn includes(&self, provider: &str) -> bool {
        self.legacy || self.providers.iter().any(|id| id == provider)
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct CollectionLayout {
    pub canonical: BTreeMap<String, Arc<CollectionView>>,
    aliases: BTreeMap<String, String>,
    pub legacy: bool,
}

impl CollectionLayout {
    pub fn new(config: &Config, providers: &[Arc<dyn Provider>]) -> anyhow::Result<Self> {
        let legacy = config.collection.is_empty();
        let all_path = if legacy {
            DEFAULT_COLLECTION_PATH.to_owned()
        } else {
            format!("{COLLECTION_ROOT}/{ALL_COLLECTION_ID}")
        };
        let mut canonical = BTreeMap::new();
        let mut aliases: BTreeMap<_, _> = config
            .all_collection_aliases
            .iter()
            .map(|alias| (alias.clone(), all_path.clone()))
            .collect();
        let mut all = CollectionView::legacy();
        if !legacy {
            all.label = ALL_COLLECTION_ID.into();
        }
        if let Some(label) = &config.all_collection_label {
            all.label = label.clone();
        }
        all.providers = providers
            .iter()
            .map(|provider| provider.id().to_owned())
            .collect();
        let writable = |id: &str| {
            providers
                .iter()
                .any(|p| p.id() == id && p.capabilities().contains(&Capability::Write))
        };
        all.writer = config
            .service
            .write_provider
            .as_deref()
            .filter(|id| writable(id))
            .or_else(|| {
                config
                    .provider
                    .iter()
                    .map(|entry| entry.id.as_str())
                    .find(|id| writable(id))
            })
            .or_else(|| {
                all.providers
                    .iter()
                    .map(String::as_str)
                    .find(|id| writable(id))
            })
            .map(str::to_owned);
        canonical.insert(all_path.clone(), Arc::new(all));
        let writers =
            resolve_collections(&config.collection, &config.all_collection_aliases, |id| {
                providers
                    .iter()
                    .find(|p| p.id() == id)
                    .map(|p| p.capabilities().contains(&Capability::Write))
            })?;
        for (entry, writer) in config.collection.iter().zip(writers) {
            let path = format!("{COLLECTION_ROOT}/{}", entry.id);
            for alias in &entry.aliases {
                aliases.insert(alias.clone(), path.clone());
            }
            canonical.insert(
                path,
                Arc::new(CollectionView {
                    id: entry.id.clone(),
                    label: entry.label.as_ref().unwrap_or(&entry.id).clone(),
                    times: Default::default(),
                    providers: entry.providers.clone(),
                    writer,
                    legacy: false,
                }),
            );
        }
        let default = aliases
            .entry("default".into())
            .or_insert_with(|| all_path.clone())
            .clone();
        aliases.entry("login".into()).or_insert(default);
        Ok(Self {
            canonical,
            aliases,
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
}
