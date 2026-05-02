//! `rosec config show` — print the current config.toml or compiled-in defaults.

use anyhow::Result;

use rosec_core::config::Config;

use crate::{config_path, load_config};

pub fn run(show_defaults: bool) -> Result<()> {
    let path = config_path();
    if !path.exists() {
        println!("# No config file found at {}", path.display());
        println!("# Showing compiled-in defaults:\n");
        let default_toml = toml::to_string_pretty(&Config::default())
            .unwrap_or_else(|_| "# (serialization error)".to_string());
        println!("{default_toml}");
        return Ok(());
    }

    if show_defaults {
        let mut cfg = load_config();
        for entry in &mut cfg.provider {
            if entry.tls_mode_probe.is_none() {
                entry.tls_mode_probe = Some(entry.tls_mode.clone());
            }
        }
        let effective_toml =
            toml::to_string_pretty(&cfg).unwrap_or_else(|_| "# (serialization error)".to_string());
        print!("{effective_toml}");
    } else {
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
        print!("{raw}");
    }
    Ok(())
}
