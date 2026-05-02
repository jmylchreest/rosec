//! `rosec provider attach --path <file> [--id <id>] [--collection <c>]`
//!
//! Adds an existing vault file to the config without creating it.

use anyhow::Result;

use rosec_core::config_edit;

use crate::cli::ProviderAttachArgs;
use crate::config_path;

use super::derive_vault_id_from_path;

pub async fn run(args: ProviderAttachArgs) -> Result<()> {
    let vault_path = args.path;
    let collection = args.collection;

    // Derive ID from filename if not specified.
    let id = match args.id {
        Some(id) => id,
        None => derive_vault_id_from_path(&vault_path),
    };

    let cfg = config_path();
    config_edit::add_local_provider(&cfg, &id, &vault_path, collection.as_deref())?;

    println!("Attached vault '{id}' ({vault_path}) to {}", cfg.display());
    println!("rosecd will hot-reload the config automatically if it is running.");
    println!("Run `rosec provider auth {id}` to authenticate.");
    Ok(())
}
