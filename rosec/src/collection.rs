use std::collections::HashMap;

use anyhow::{Context, Result, ensure};
use rosec_core::config::{
    ALL_COLLECTION_ID, CollectionConfig, resolve_collections, valid_collection_component,
};

use crate::cli::CollectionCommands;

pub async fn dispatch(action: CollectionCommands) -> Result<()> {
    let path = crate::config_path();
    let config = rosec_core::config_load::load(&path)?.config;
    let mut collections = config.collection;

    match action {
        CollectionCommands::List => {
            let all_aliases = collections
                .iter()
                .find(|entry| entry.id == ALL_COLLECTION_ID)
                .map_or(&[][..], |entry| entry.aliases.as_slice());
            println!(
                "all: all providers (write preference: {}; configured aliases: {})",
                config
                    .service
                    .write_provider
                    .as_deref()
                    .unwrap_or("automatic"),
                all_aliases.join(", ")
            );
            for collection in collections
                .iter()
                .filter(|entry| entry.id != ALL_COLLECTION_ID)
            {
                println!(
                    "{}: {} (write: {}; aliases: {})",
                    collection.id,
                    collection.providers.join(", "),
                    collection.write_provider.as_deref().unwrap_or("automatic"),
                    collection.aliases.join(", ")
                );
            }
            let target = |name: &str| {
                collections
                    .iter()
                    .find(|entry| entry.aliases.iter().any(|alias| alias == name))
                    .map(|entry| entry.id.as_str())
            };
            let default = target("default").unwrap_or(ALL_COLLECTION_ID);
            println!("default -> {default}");
            println!("login -> {}", target("login").unwrap_or(default));
            return Ok(());
        }
        CollectionCommands::Set {
            id,
            providers,
            write_provider,
        } => {
            ensure!(id != ALL_COLLECTION_ID, "'all' is a built-in collection");
            let connection = crate::conn().await?;
            let proxy = zbus::Proxy::new(
                &connection,
                "org.freedesktop.secrets",
                "/org/rosec/Daemon",
                "org.rosec.Daemon",
            )
            .await?;
            let entries: Vec<crate::ProviderEntry> = proxy
                .call("ProviderList", &())
                .await
                .context("could not read provider capabilities from the running daemon")?;
            let capabilities: HashMap<_, _> = entries
                .into_iter()
                .map(|(id, _, _, _, _, _, _, _, caps)| (id, caps.iter().any(|cap| cap == "Write")))
                .collect();
            if let Some(entry) = collections.iter_mut().find(|entry| entry.id == id) {
                entry.providers = providers;
                entry.write_provider = write_provider;
            } else {
                collections.push(CollectionConfig {
                    id,
                    providers,
                    write_provider,
                    aliases: vec![],
                });
            }
            resolve_collections(&collections, |id| capabilities.get(id).copied())?;
        }
        CollectionCommands::Remove { id } => {
            ensure!(id != ALL_COLLECTION_ID, "'all' is a built-in collection");
            let index = collections
                .iter()
                .position(|entry| entry.id == id)
                .with_context(|| format!("unknown collection '{id}'"))?;
            collections.remove(index);
        }
        CollectionCommands::Alias { name, collection } => {
            ensure!(
                valid_collection_component(&name),
                "invalid collection alias '{name}'"
            );
            if collection.as_deref() == Some(ALL_COLLECTION_ID)
                && !collections
                    .iter()
                    .any(|entry| entry.id == ALL_COLLECTION_ID)
            {
                collections.push(CollectionConfig {
                    id: ALL_COLLECTION_ID.into(),
                    providers: vec![],
                    write_provider: None,
                    aliases: vec![],
                });
            }
            if let Some(id) = &collection {
                ensure!(
                    collections.iter().any(|entry| &entry.id == id),
                    "unknown collection '{id}'"
                );
            }
            let mut removed = false;
            for entry in &mut collections {
                if let Some(index) = entry.aliases.iter().position(|alias| alias == &name) {
                    entry.aliases.remove(index);
                    removed = true;
                }
                if collection.as_ref() == Some(&entry.id) {
                    entry.aliases.push(name.clone());
                }
            }
            ensure!(
                collection.is_some() || removed || matches!(name.as_str(), "default" | "login"),
                "no configured alias '{name}'"
            );
        }
    }

    collections.retain(|entry| entry.id != ALL_COLLECTION_ID || !entry.aliases.is_empty());
    rosec_core::config_edit::set_collections(&path, &collections)?;
    println!(
        "Updated {}. Restart rosecd to apply collection changes.",
        path.display()
    );
    Ok(())
}
