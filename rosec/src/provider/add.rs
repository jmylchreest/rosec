//! `rosec provider add <kind> [--id <id>] [key=value ...]`

use anyhow::{Result, bail};

use rosec_core::{WasmPreference, config_edit};

use crate::cli::ProviderAddArgs;
use crate::{config_path, load_config, open_tty_owned_fd};

use super::{
    OptionScope, collect_option_prompts, derive_provider_id, ensure_local_vault_path,
    known_kinds_display, parse_option_args, prompt_and_collect, wait_for_daemon_reload,
};

pub async fn run(args: ProviderAddArgs) -> Result<()> {
    let trusted_keys = crate::load_config().service.wasm_trusted_key;
    let registry = rosec_wasm::discovery::scan_plugins(
        WasmPreference::default(),
        rosec_core::WasmVerify::default(),
        &trusted_keys,
    );

    let kind = &args.kind;
    let is_builtin = config_edit::KNOWN_KINDS.contains(&kind.as_str());
    let is_discovered = registry.contains_kind(kind);
    if !is_builtin && !is_discovered {
        let known = known_kinds_display(&registry);
        bail!("unknown provider kind '{kind}'. Known kinds: {known}");
    }

    if is_discovered
        && let Some(plugin) = registry.get(kind)
        && plugin.manifest.experimental
    {
        eprintln!(
            "warning: provider kind '{kind}' is EXPERIMENTAL — interfaces, \
             on-disk format, and behaviour may change without notice."
        );
        if args.yes {
            eprintln!("(--yes given, continuing without confirmation)");
        } else {
            let confirm = crate::prompt_field("Continue? (yes/no)", "no", "text").await?;
            if confirm.as_str() != "yes" {
                bail!("cancelled");
            }
        }
    }

    let (mut options, custom_path, collection) =
        parse_option_args(&args.options, args.path, args.collection);

    let mut supplied: std::collections::HashSet<String> =
        options.iter().map(|(k, _)| k.clone()).collect();
    // `parse_option_args` extracts `path` and `collection` into separate
    // variables (legacy of the local-vault add flow) — so they don't appear
    // in `options` at this point, which means a manifest that declares
    // `path` as required (e.g. keepassxc-file) would re-prompt the user
    // even when `path=...` was given.  Mark them as supplied here so the
    // prompt-and-collect loop skips them.
    if custom_path.is_some() {
        supplied.insert("path".to_string());
    }
    if collection.is_some() {
        supplied.insert("collection".to_string());
    }
    let required = collect_option_prompts(kind, &registry, is_discovered, OptionScope::Required);
    if args.yes {
        // Non-interactive: required options must already be supplied, else
        // bail with a clear list rather than prompting.
        let missing: Vec<&str> = required
            .iter()
            .filter(|p| !supplied.contains(&p.key))
            .map(|p| p.key.as_str())
            .collect();
        if !missing.is_empty() {
            bail!(
                "missing required options for kind '{kind}': {}\n\
                 pass them as `key=value` arguments",
                missing.join(", ")
            );
        }
    } else {
        prompt_and_collect(&required, &supplied, &mut options).await?;
    }

    // Build a temporary view of options for ID derivation that includes the
    // extracted `path`/`collection` (parse_option_args pulls them out into
    // separate vars; without re-merging here, manifests whose
    // id_derivation_key is "path" would fall through to the bare kind name).
    let id = match args.id {
        Some(id) => id,
        None => {
            let mut for_derivation = options.clone();
            if let Some(p) = &custom_path {
                for_derivation.push(("path".to_string(), p.clone()));
            }
            if let Some(c) = &collection {
                for_derivation.push(("collection".to_string(), c.clone()));
            }
            derive_provider_id(kind, &for_derivation, &registry)
        }
    };

    supplied.extend(options.iter().map(|(k, _)| k.clone()));
    let optional = collect_option_prompts(kind, &registry, is_discovered, OptionScope::Optional);
    if !args.yes {
        prompt_and_collect(&optional, &supplied, &mut options).await?;
    }
    // With --yes, optional fields not supplied on the CLI are simply omitted.

    if let Some(p) = &custom_path {
        options.push(("path".to_string(), p.clone()));
    }
    if let Some(c) = &collection {
        options.push(("collection".to_string(), c.clone()));
    }

    if kind == "local" {
        ensure_local_vault_path(&id, &mut options, custom_path.is_none())?;
    }

    let cfg_data = load_config();
    if cfg_data.provider.iter().any(|p| p.id == id) {
        bail!("provider '{id}' already exists. Use --id to choose a different name.");
    }
    if kind == "local" {
        let path_value = options
            .iter()
            .find(|(k, _)| k == "path")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if let Some(other) = super::find_local_path_conflict(&cfg_data, path_value) {
            let state = if other.enabled { "" } else { " (disabled)" };
            bail!(
                "vault file {path_value} is already used by provider '{}'{state}.\n\
                 Two providers on one vault file would overwrite each other's writes.",
                other.id
            );
        }
    }

    let cfg = config_path();
    config_edit::add_provider(&cfg, &id, kind, &options)?;
    println!("Added provider '{id}' (kind: {kind}) to {}", cfg.display());

    if let Some(proxy) = wait_for_daemon_reload(&id).await {
        println!("rosecd picked up the new provider — starting authentication.");
        let tty_fd = open_tty_owned_fd()?;
        let _: () = proxy
            .call("AuthProviderWithTty", &(id.as_str(), tty_fd, false))
            .await?;
        println!("Provider '{id}' authenticated.");
    } else {
        println!("rosecd will hot-reload the config automatically if it is running.");
        println!("Run `rosec provider auth {id}` to authenticate.");
    }

    Ok(())
}
