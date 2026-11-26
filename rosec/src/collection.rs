use std::collections::HashMap;

use anyhow::{Context, Result, ensure};
use rosec_core::config::{CollectionConfig, resolve_collections, valid_collection_component};

use crate::cli::CollectionCommands;

pub async fn dispatch(action: CollectionCommands) -> Result<()> {
    let path = crate::config_path();
    let mut collections = rosec_core::config_load::load(&path)?.config.collection;

    match action {
        CollectionCommands::List => {
            if collections.is_empty() {
                println!("default: all providers (aliases: default, login)");
            }
            for collection in &collections {
                println!(
                    "{}: {} (write: {}; aliases: {})",
                    collection.id,
                    collection.providers.join(", "),
                    collection.write_provider.as_deref().unwrap_or("automatic"),
                    collection.aliases.join(", ")
                );
            }
            return Ok(());
        }
        CollectionCommands::Set {
            id,
            providers,
            write_provider,
        } => {
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
                collection.is_some() || removed,
                "no configured alias '{name}'"
            );
        }
    }

    rosec_core::config_edit::set_collections(&path, &collections)?;
    println!(
        "Updated {}. Restart rosecd to apply collection changes.",
        path.display()
    );
    Ok(())
}
