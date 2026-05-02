//! `rosec provider remove <id>`
//!
//! For external providers, removes the config entry.
//! For local vaults, also offers to delete the vault file from disk.

use anyhow::Result;

use rosec_core::config_edit;

use crate::{config_path, load_config, prompt_field};

use super::expand_tilde;

pub async fn run(id: &str) -> Result<()> {
    let cfg = config_path();

    // Check if this is a local vault with a path — if so, offer to delete the file.
    let cfg_data = load_config();
    let vault_path = cfg_data
        .provider
        .iter()
        .find(|p| p.id == *id && p.kind == "local")
        .and_then(|p| p.path.as_deref())
        .map(expand_tilde);

    config_edit::remove_provider(&cfg, id)?;
    println!("Removed provider '{id}' from {}", cfg.display());

    if let Some(ref path) = vault_path
        && std::path::Path::new(path).exists()
    {
        let confirm = prompt_field(
            &format!("Also delete the vault file at {path}? (yes/no)"),
            "no",
            "text",
        )
        .await?;
        if confirm.as_str() == "yes" {
            match std::fs::remove_file(path) {
                Ok(()) => println!("Deleted vault file: {path}"),
                Err(e) => eprintln!("warning: could not delete vault file {path}: {e}"),
            }
        } else {
            println!("Vault file kept at {path}.");
            println!("Use `rosec provider attach --path {path}` to re-attach later.");
        }
    }

    println!("rosecd will hot-reload the config automatically if it is running.");
    Ok(())
}
