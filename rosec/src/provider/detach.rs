//! `rosec provider detach <id>`
//!
//! Removes the vault from the config file but leaves the vault file on disk.

use anyhow::Result;

use rosec_core::config_edit;

use crate::config_path;

pub async fn run(id: &str) -> Result<()> {
    let cfg = config_path();
    config_edit::remove_provider(&cfg, id)?;
    println!("Detached vault '{id}' from {}", cfg.display());
    println!(
        "The vault file was NOT deleted. Use `rosec provider remove` to also delete the file."
    );
    println!("rosecd will hot-reload the config automatically if it is running.");
    Ok(())
}
