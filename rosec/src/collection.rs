use std::collections::HashMap;

use anyhow::{Context, Result, ensure};
use rosec_core::config::{ALL_COLLECTION_ID, CollectionConfig, resolve_collections};

use crate::cli::CollectionCommands;

pub async fn dispatch(action: CollectionCommands) -> Result<()> {
    let path = crate::config_path();
    let _edit_lock = if matches!(action, CollectionCommands::List) {
        None
    } else {
        Some(rosec_core::config_edit::lock_collection_config(&path)?)
    };
    let config = rosec_core::config_load::load(&path)?.config;
    let mut collections = config.collection;
    let mut all_aliases = config.all_collection_aliases;

    match action {
        CollectionCommands::List => {
            println!(
                "all: all providers (write preference: {}; configured aliases: {})",
                config
                    .service
                    .write_provider
                    .as_deref()
                    .unwrap_or("automatic"),
                all_aliases.join(", ")
            );
            for collection in &collections {
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
                    .or_else(|| {
                        all_aliases
                            .iter()
                            .any(|alias| alias == name)
                            .then_some(ALL_COLLECTION_ID)
                    })
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
            resolve_collections(&collections, &all_aliases, |id| {
                capabilities.get(id).copied()
            })?;
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
            let removed = rosec_core::config_edit::assign_collection_alias(
                &mut collections,
                &mut all_aliases,
                &name,
                collection.as_deref(),
            )?;
            ensure!(
                collection.is_some() || removed || matches!(name.as_str(), "default" | "login"),
                "no configured alias '{name}'"
            );
        }
    }

    rosec_core::config_edit::set_collections(&path, &collections, &all_aliases)?;
    println!(
        "Updated {}. rosecd reloads collection changes automatically.",
        path.display()
    );
    Ok(())
}
