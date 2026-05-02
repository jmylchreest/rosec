//! `rosec config set <key> <value>` — write a single config value.

use anyhow::{Result, bail};

use rosec_core::config_edit;

use crate::config_path;

use super::{CONFIG_KEYS, validate_config_value};

pub fn run(key: &str, value: &str) -> Result<()> {
    if !CONFIG_KEYS.iter().any(|(k, _)| *k == key) {
        bail!("unknown config key: {key}\nrun `rosec config --help` to see supported keys");
    }

    validate_config_value(key, value)?;

    let path = config_path();
    config_edit::set_value(&path, key, value)?;

    println!("{key} = {value}");
    Ok(())
}
