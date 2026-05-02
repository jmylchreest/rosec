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
    let registry = rosec_wasm::discovery::scan_plugins(
        WasmPreference::default(),
        rosec_core::WasmVerify::default(),
    );

    let kind = &args.kind;
    let is_builtin = config_edit::KNOWN_KINDS.contains(&kind.as_str());
    let is_discovered = registry.contains_kind(kind);
    if !is_builtin && !is_discovered {
        let known = known_kinds_display(&registry);
        bail!("unknown provider kind '{kind}'. Known kinds: {known}");
    }

    let (mut options, custom_path, collection) =
        parse_option_args(&args.options, args.path, args.collection);

    let mut supplied: std::collections::HashSet<String> =
        options.iter().map(|(k, _)| k.clone()).collect();
    let required = collect_option_prompts(kind, &registry, is_discovered, OptionScope::Required);
    prompt_and_collect(&required, &supplied, &mut options).await?;

    let id = match args.id {
        Some(id) => id,
        None => derive_provider_id(kind, &options, &registry),
    };

    supplied.extend(options.iter().map(|(k, _)| k.clone()));
    let optional = collect_option_prompts(kind, &registry, is_discovered, OptionScope::Optional);
    prompt_and_collect(&optional, &supplied, &mut options).await?;

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
