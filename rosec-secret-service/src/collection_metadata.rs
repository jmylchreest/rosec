use std::{collections::BTreeMap, io::Write, path::Path, sync::Arc};

use serde::{Deserialize, Serialize};

use crate::collection_layout::{CollectionLayout, CollectionView};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Times {
    pub created: u64,
    pub modified: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct Record {
    label: String,
    providers: Vec<String>,
    writer: Option<String>,
    times: Times,
}

impl Record {
    fn from_view(view: &CollectionView) -> Self {
        let mut providers = view.providers.clone();
        providers.sort_unstable();
        Self {
            label: view.label.clone(),
            providers,
            writer: view.writer.clone(),
            times: view.times,
        }
    }
}

pub(crate) fn apply(
    path: Option<&Path>,
    previous: &CollectionLayout,
    next: &mut CollectionLayout,
    now: u64,
) -> anyhow::Result<()> {
    let mut old: BTreeMap<String, Record> = previous
        .canonical
        .values()
        .filter(|view| view.times.created != 0)
        .map(|view| (view.id.clone(), Record::from_view(view)))
        .collect();
    if let Some(path) = path {
        match std::fs::read(path) {
            Ok(bytes) => old = serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut records = BTreeMap::new();
    for view in next.canonical.values_mut() {
        let view = Arc::get_mut(view).expect("new layout owns each collection");
        let mut record = Record::from_view(view);
        record.times = match old.get(&view.id) {
            Some(prior) => Times {
                created: prior.times.created,
                modified: if prior.label == record.label
                    && prior.providers == record.providers
                    && prior.writer == record.writer
                {
                    prior.times.modified
                } else {
                    now.max(prior.times.modified)
                },
            },
            None => Times {
                created: now,
                modified: now,
            },
        };
        view.times = record.times;
        records.insert(view.id.clone(), record);
    }
    if let Some(path) = path
        && records != old
    {
        let parent = path.parent().expect("metadata path has a parent");
        std::fs::create_dir_all(parent)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer(&mut temporary, &records)?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary.persist(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosec_core::config::Config;

    #[test]
    fn timestamps_follow_definition_changes_and_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("collections.json");
        let config = Config::default();
        let mut previous = CollectionLayout::new(&config, &[]).unwrap();
        for (now, writer, alias, modified) in [
            (10, Some("one"), false, 10),
            (20, Some("two"), false, 20),
            (30, Some("two"), true, 20),
        ] {
            let mut config = config.clone();
            if alias {
                config.all_collection_aliases.push("example".into());
            }
            let mut next = CollectionLayout::new(&config, &[]).unwrap();
            let view = Arc::get_mut(next.canonical.values_mut().next().unwrap()).unwrap();
            view.writer = writer.map(str::to_owned);
            apply(Some(&path), &previous, &mut next, now).unwrap();
            assert_eq!(
                next.canonical.values().next().unwrap().times,
                Times {
                    created: 10,
                    modified
                }
            );
            previous = next;
        }
        let mut restarted = CollectionLayout::new(&config, &[]).unwrap();
        Arc::get_mut(restarted.canonical.values_mut().next().unwrap())
            .unwrap()
            .writer = Some("two".into());
        apply(
            Some(&path),
            &CollectionLayout::new(&config, &[]).unwrap(),
            &mut restarted,
            40,
        )
        .unwrap();
        assert_eq!(
            restarted.canonical.values().next().unwrap().times,
            Times {
                created: 10,
                modified: 20
            }
        );
    }
}
