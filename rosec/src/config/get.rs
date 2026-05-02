//! `rosec config get <key>` — read a single config value.

use anyhow::{Result, bail};

use crate::load_config;

use super::{CONFIG_KEYS, config_get_value};

pub fn run(key: &str) -> Result<()> {
    if !CONFIG_KEYS.iter().any(|(k, _)| *k == key) {
        bail!("unknown config key: {key}\nrun `rosec config --help` to see supported keys");
    }

    let cfg = load_config();
    let value = config_get_value(&cfg, key)?;
    println!("{value}");
    Ok(())
}
