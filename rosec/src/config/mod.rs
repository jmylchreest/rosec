//! `rosec config` — read/write config.toml.

use anyhow::Result;

use rosec_core::config::Config;

use crate::cli::ConfigCommands;

pub mod get;
pub mod set;
pub mod show;

/// Supported dotted-path config keys and their human description.
///
/// Only settings that are safe to change at runtime (the daemon hot-reloads
/// config.toml) and genuinely useful from the CLI are listed here.
/// Theme colours and prompt binary paths are intentionally excluded —
/// hand-editing TOML is cleaner for those.
pub(super) static CONFIG_KEYS: &[(&str, &str)] = &[
    (
        "service.refresh_interval_secs",
        "Vault re-sync interval in seconds (0 = disabled)",
    ),
    (
        "service.dedup_strategy",
        "Deduplication strategy: newest | priority",
    ),
    (
        "service.dedup_time_fallback",
        "Tie-break field when strategy=newest: created | none",
    ),
    (
        "autolock.on_logout",
        "Lock vault when the session ends (true | false)",
    ),
    (
        "autolock.on_session_lock",
        "Lock vault when the screen locks (true | false)",
    ),
    (
        "autolock.idle_timeout_minutes",
        "Lock after N minutes of inactivity (0 or omit = disabled)",
    ),
    (
        "autolock.max_unlocked_minutes",
        "Hard cap: lock after N minutes unlocked (0 or omit = disabled)",
    ),
];

pub fn dispatch(action: Option<ConfigCommands>) -> Result<()> {
    match action {
        None => show::run(false),
        Some(ConfigCommands::Show { show_defaults }) => show::run(show_defaults),
        Some(ConfigCommands::Get { key }) => get::run(&key),
        Some(ConfigCommands::Set { key, value }) => set::run(&key, &value),
    }
}

/// Read a single dotted-path value from a loaded `Config` as a display string.
pub(super) fn config_get_value(cfg: &Config, key: &str) -> Result<String> {
    Ok(match key {
        "service.refresh_interval_secs" => cfg
            .service
            .refresh_interval_secs
            .map(|v| v.to_string())
            .unwrap_or_else(|| "60".to_string()),
        "service.dedup_strategy" => format!("{:?}", cfg.service.dedup_strategy).to_lowercase(),
        "service.dedup_time_fallback" => {
            format!("{:?}", cfg.service.dedup_time_fallback).to_lowercase()
        }
        "autolock.on_logout" => cfg.autolock.on_logout.to_string(),
        "autolock.on_session_lock" => cfg.autolock.on_session_lock.to_string(),
        "autolock.idle_timeout_minutes" => cfg
            .autolock
            .idle_timeout_minutes
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".to_string()),
        "autolock.max_unlocked_minutes" => cfg
            .autolock
            .max_unlocked_minutes
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".to_string()),
        other => anyhow::bail!("unhandled key: {other}"),
    })
}

/// Validate a config value before writing it, giving the user a clear error
/// rather than silently writing a value the daemon will reject on reload.
pub(super) fn validate_config_value(key: &str, value: &str) -> Result<()> {
    match key {
        "service.dedup_strategy" if !matches!(value, "newest" | "priority") => {
            anyhow::bail!("invalid value '{value}': must be 'newest' or 'priority'");
        }
        "service.dedup_time_fallback" if !matches!(value, "created" | "none") => {
            anyhow::bail!("invalid value '{value}': must be 'created' or 'none'");
        }
        "autolock.on_logout" | "autolock.on_session_lock" if !matches!(value, "true" | "false") => {
            anyhow::bail!("invalid value '{value}': must be 'true' or 'false'");
        }
        "service.refresh_interval_secs"
        | "autolock.idle_timeout_minutes"
        | "autolock.max_unlocked_minutes" => {
            value.parse::<u64>().map_err(|_| {
                anyhow::anyhow!("invalid value '{value}': must be a non-negative integer")
            })?;
        }
        _ => {}
    }
    Ok(())
}
