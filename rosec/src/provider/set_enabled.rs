//! `rosec provider enable <id>` / `rosec provider disable <id>`

use anyhow::Result;

use rosec_core::config_edit;

use crate::config_path;

pub async fn run(id: &str, enabled: bool) -> Result<()> {
    let cfg = config_path();
    config_edit::set_provider_enabled(&cfg, id, enabled)?;

    if enabled {
        println!("Provider '{id}' enabled.");
    } else {
        println!("Provider '{id}' disabled.");
    }
    println!("rosecd will hot-reload the config automatically if it is running.");
    Ok(())
}
