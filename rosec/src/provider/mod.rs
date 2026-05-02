//! `rosec provider` subcommand group.
//!
//! Each subcommand has its own module — the dispatcher matches on
//! [`ProviderCommands`] and delegates.

use std::path::PathBuf;

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

use rosec_core::config_edit;

use crate::cli::ProviderCommands;

pub mod add;
pub mod add_password;
pub mod attach;
pub mod auth;
pub mod change_password;
pub mod detach;
pub mod kinds;
pub mod list;
pub mod list_passwords;
pub mod remove;
pub mod remove_password;
pub mod set_enabled;

pub async fn dispatch(action: Option<ProviderCommands>) -> Result<()> {
    let action = action.unwrap_or(ProviderCommands::List);
    match action {
        ProviderCommands::List => list::run().await,
        ProviderCommands::Kinds => {
            kinds::run();
            Ok(())
        }
        ProviderCommands::Auth(args) => auth::run(&args).await,
        ProviderCommands::Add(args) => add::run(args).await,
        ProviderCommands::Remove(args) => remove::run(&args.id).await,
        ProviderCommands::Enable(args) => set_enabled::run(&args.id, true).await,
        ProviderCommands::Disable(args) => set_enabled::run(&args.id, false).await,
        ProviderCommands::Attach(args) => attach::run(args).await,
        ProviderCommands::Detach(args) => detach::run(&args.id).await,
        ProviderCommands::AddPassword(args) => add_password::run(args).await,
        ProviderCommands::RemovePassword(args) => remove_password::run(&args).await,
        ProviderCommands::ListPasswords(args) => list_passwords::run(&args.id).await,
        ProviderCommands::ChangePassword(args) => change_password::run(&args.id).await,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Shared helpers
// ───────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub(super) enum OptionScope {
    Required,
    Optional,
}

pub(super) struct OptionPrompt {
    pub(super) key: String,
    pub(super) description: String,
    pub(super) field_kind: String,
}

pub(super) fn known_kinds_display(registry: &rosec_wasm::PluginRegistry) -> String {
    let mut v: Vec<String> = config_edit::KNOWN_KINDS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    for kind in registry.kinds() {
        if !v.iter().any(|k| k == kind) {
            v.push(kind.to_string());
        }
    }
    v.join(", ")
}

pub(super) fn parse_option_args(
    raw: &[String],
    initial_path: Option<String>,
    initial_collection: Option<String>,
) -> (Vec<(String, String)>, Option<String>, Option<String>) {
    let mut options = Vec::new();
    let mut path = initial_path;
    let mut collection = initial_collection;
    for opt in raw {
        if let Some((k, v)) = opt.split_once('=') {
            match k {
                "path" => path = Some(v.to_string()),
                "collection" => collection = Some(v.to_string()),
                _ => options.push((k.to_string(), v.to_string())),
            }
        }
    }
    (options, path, collection)
}

pub(super) fn collect_option_prompts(
    kind: &str,
    registry: &rosec_wasm::PluginRegistry,
    is_discovered: bool,
    scope: OptionScope,
) -> Vec<OptionPrompt> {
    let suffix = match scope {
        OptionScope::Required => "",
        OptionScope::Optional => " (optional, Enter to skip)",
    };

    if is_discovered {
        let opts = match scope {
            OptionScope::Required => rosec_wasm::discovery::required_options(registry, kind),
            OptionScope::Optional => rosec_wasm::discovery::optional_options(registry, kind),
        };
        return opts
            .unwrap_or_default()
            .into_iter()
            .map(|opt| OptionPrompt {
                description: format!("{}{suffix}", opt.description),
                key: opt.key,
                field_kind: opt.kind,
            })
            .collect();
    }

    let builtin = match scope {
        OptionScope::Required => config_edit::required_options_for_kind(kind),
        OptionScope::Optional => config_edit::optional_options_for_kind(kind),
    };
    builtin
        .iter()
        .map(|(key, description)| OptionPrompt {
            key: (*key).to_string(),
            description: format!("{description}{suffix}"),
            field_kind: builtin_field_kind(key, scope).to_string(),
        })
        .collect()
}

fn builtin_field_kind(key: &str, scope: OptionScope) -> &'static str {
    match scope {
        OptionScope::Required if key.contains("secret") || key.contains("password") => "secret",
        _ => "text",
    }
}

pub(super) async fn prompt_and_collect(
    prompts: &[OptionPrompt],
    supplied: &std::collections::HashSet<String>,
    out: &mut Vec<(String, String)>,
) -> Result<()> {
    for p in prompts {
        if supplied.contains(&p.key) {
            continue;
        }
        let v = crate::prompt_field(&p.description, "", &p.field_kind).await?;
        let s = v.as_str().to_string();
        if !s.is_empty() {
            out.push((p.key.clone(), s));
        }
    }
    Ok(())
}

pub(super) fn ensure_local_vault_path(
    id: &str,
    options: &mut Vec<(String, String)>,
    derive_default: bool,
) -> Result<()> {
    if derive_default {
        options.push(("path".to_string(), default_vault_path(id)));
    }
    let path_value = options
        .iter()
        .find(|(k, _)| k == "path")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let resolved = expand_tilde(path_value);
    if std::path::Path::new(&resolved).exists() {
        bail!(
            "a vault file already exists at {resolved}\n\
             Use `rosec provider attach --path {resolved}` to attach an existing vault."
        );
    }
    Ok(())
}

/// Derive a short, stable provider ID from the credential that identifies the account.
///
/// Format: `{kind}-{first8hexchars of sha256(credential)}`
///
/// - `bitwarden-sm`: hashes the organization_id
/// - anything else: falls back to the kind string itself
pub(super) fn derive_provider_id(
    kind: &str,
    options: &[(String, String)],
    registry: &rosec_wasm::PluginRegistry,
) -> String {
    let discovered_key = rosec_wasm::discovery::id_derivation_key(registry, kind);

    let credential_key = match kind {
        "bitwarden-sm" => "organization_id",
        _ => match discovered_key.as_deref() {
            Some(k) => k,
            None => return kind.to_string(),
        },
    };

    let value = options
        .iter()
        .find(|(k, _)| k == credential_key)
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    if value.is_empty() {
        return kind.to_string();
    }

    let hash = Sha256::digest(value.as_bytes());
    let short = format!(
        "{:08x}",
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
    );
    format!("{kind}-{short}")
}

/// Default vault file path: `$XDG_DATA_HOME/rosec/vaults/<id>.vault`.
pub(super) fn default_vault_path(id: &str) -> String {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("rosec")
        .join("vaults")
        .join(format!("{id}.vault"))
        .to_string_lossy()
        .into_owned()
}

/// Derive a vault ID from a file path.
///
/// Takes the filename stem (e.g. `/mnt/shared/team.vault` → `team`).
pub(super) fn derive_vault_id_from_path(path: &str) -> String {
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("vault")
        .to_string()
}

/// Expand `~` to `$HOME` in a path string.
pub(super) fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return format!("{}/{rest}", home.to_string_lossy());
    }
    path.to_string()
}

/// Generate a default password label: `user@hostname`.
pub(super) fn default_password_label() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".into());

    let host = {
        let mut buf = [0u8; 256];
        // SAFETY: gethostname writes into a fixed-size buffer we own.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        if rc == 0 {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..len]).into_owned()
        } else {
            "localhost".into()
        }
    };

    format!("{user}@{host}")
}

/// Poll rosecd's `ProviderList` until `id` appears (max 3 s, 200 ms intervals).
///
/// Returns `Some(proxy)` if the daemon is running and the provider appeared,
/// `None` if the daemon isn't running or the provider didn't appear in time.
pub(super) async fn wait_for_daemon_reload(id: &str) -> Option<zbus::Proxy<'static>> {
    let conn = crate::conn().await.ok()?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await
    .ok()?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if let Ok(entries) = proxy
            .call::<_, _, Vec<crate::ProviderEntry>>("ProviderList", &())
            .await
            && entries.iter().any(|(bid, ..)| bid == id)
        {
            return Some(proxy);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}
