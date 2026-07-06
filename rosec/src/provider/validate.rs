//! `rosec provider validate` — verify a WASM plugin bundle and show the
//! sandbox it will get.
//!
//! Three answers in one command, without starting the daemon:
//!
//! 1. Is the combined `(wasm || policy)` signature good against the public
//!    key embedded in this build?
//! 2. What does the plugin *claim* to need (the policy sidecar)?
//! 3. What will the sandbox actually be for each configured provider of
//!    this kind — after user overrides (`allowed_hosts` replacing,
//!    `additional_hosts` extending) and template resolution against the
//!    options in `rosec.toml`?
//!
//! The override/resolution logic is shared with rosecd
//! ([`rosec_wasm::policy::effective_allowed_hosts`], [`PluginPolicy::resolve`]),
//! so the dry-run shows exactly what the daemon will enforce at startup.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use rosec_core::WasmVerify;
use rosec_core::config::ProviderEntry;
use rosec_wasm::discovery::PluginBundle;
use rosec_wasm::policy::{self, AccessMode, PluginPolicy};

use crate::cli::ProviderValidateArgs;
use crate::load_config;

pub fn run(args: &ProviderValidateArgs) -> Result<()> {
    let cfg = load_config();

    let wasm_paths: Vec<PathBuf> = if let Some(path) = &args.wasm {
        vec![path.clone()]
    } else {
        // Disabled here means "discover regardless of signature state" — this
        // command reports signature status itself instead of silently
        // skipping unsigned plugins the way the daemon's Required scan does.
        let registry =
            rosec_wasm::discovery::scan_plugins(cfg.service.wasm_prefer, WasmVerify::Disabled);
        match &args.kind {
            Some(kind) => match registry.get(kind) {
                Some(plugin) => vec![plugin.wasm_path.clone()],
                None => bail!(
                    "no WASM plugin of kind '{kind}' found in the provider directories \
                     (discovered: {})",
                    if registry.is_empty() {
                        "none".to_string()
                    } else {
                        registry.kinds().join(", ")
                    },
                ),
            },
            None => {
                if registry.is_empty() {
                    bail!(
                        "no WASM plugins found in /usr/lib/rosec/providers or \
                         $XDG_DATA_HOME/rosec/providers"
                    );
                }
                registry
                    .kinds()
                    .iter()
                    .filter_map(|k| registry.get(k).map(|p| p.wasm_path.clone()))
                    .collect()
            }
        }
    };

    let mut problems = 0usize;
    for (i, wasm_path) in wasm_paths.iter().enumerate() {
        if i > 0 {
            println!();
        }
        problems += validate_bundle(wasm_path, &cfg.provider, cfg.service.wasm_verify);
    }

    if problems > 0 {
        bail!("{problems} problem(s) found");
    }
    Ok(())
}

/// Validate one bundle and print the report. Returns the number of problems
/// (signature failures, unresolvable policies, missing required options).
fn validate_bundle(wasm_path: &Path, entries: &[ProviderEntry], verify: WasmVerify) -> usize {
    let mut problems = 0usize;

    let bundle = match PluginBundle::load(wasm_path) {
        Ok(b) => b,
        Err(reason) => {
            println!("✗ {}", wasm_path.display());
            println!("    {reason}");
            return 1;
        }
    };

    let policy = &bundle.policy;
    println!(
        "{} ({}){}",
        policy.kind,
        policy.name,
        policy
            .version
            .as_deref()
            .map(|v| format!("  v{v}"))
            .unwrap_or_default(),
    );
    println!("  wasm:    {}", bundle.wasm_path.display());
    println!("  policy:  {}", bundle.policy_path.display());

    match bundle.verify_signature() {
        Ok(()) => {
            println!("  signature: ✓ valid (embedded rosec release key)");
        }
        Err(reason) => {
            problems += 1;
            println!("  signature: ✗ {reason}");
            if verify == WasmVerify::Disabled {
                println!(
                    "    note: wasm_verify = \"disabled\" in your config — the daemon \
                     will load this plugin anyway (development mode)"
                );
            }
        }
    }

    print_policy_claim(policy);

    let matching: Vec<&ProviderEntry> = entries.iter().filter(|e| e.kind == policy.kind).collect();
    if matching.is_empty() {
        println!();
        println!(
            "  No providers of kind '{}' in your config — dry-run with policy defaults only:",
            policy.kind
        );
        problems += print_dry_run(policy, None);
    } else {
        for entry in matching {
            println!();
            println!(
                "  Provider '{}' (rosec.toml){}:",
                entry.id,
                if entry.enabled { "" } else { "  [disabled]" },
            );
            problems += print_dry_run(policy, Some(entry));
        }
    }

    problems
}

/// The plugin author's claim, straight from the signed policy sidecar.
fn print_policy_claim(policy: &PluginPolicy) {
    println!();
    println!("  Policy (plugin author's claim):");

    if policy.network.allowed_hosts.is_empty() {
        println!("    network: no hosts (network access denied)");
    } else {
        println!("    network.allowed_hosts:");
        for h in &policy.network.allowed_hosts {
            println!("      {h}");
        }
    }

    if !policy.filesystem.preopens.is_empty() {
        println!("    filesystem.preopens:");
        for p in &policy.filesystem.preopens {
            println!(
                "      {} -> {}  ({})",
                p.host_template,
                p.guest_path,
                mode_str(p.mode)
            );
        }
    }
    if !policy.filesystem.allowed_files.is_empty() {
        println!("    filesystem.allowed_files:");
        for f in &policy.filesystem.allowed_files {
            println!(
                "      {}  ({}{})",
                f.host_template,
                mode_str(f.mode),
                if f.optional { ", optional" } else { "" },
            );
        }
    }
    if policy.filesystem.preopens.is_empty() && policy.filesystem.allowed_files.is_empty() {
        println!("    filesystem: no access");
    }

    if !policy.options.required.is_empty() {
        println!(
            "    options.required: {}",
            policy.options.required.join(", ")
        );
    }
    if !policy.options.optional.is_empty() {
        println!(
            "    options.optional: {}",
            policy.options.optional.join(", ")
        );
    }
    for (k, v) in {
        let mut d: Vec<_> = policy.options.defaults.iter().collect();
        d.sort_by_key(|(k, _)| k.as_str());
        d
    } {
        println!("    options.defaults: {k} = {v}");
    }
}

/// Dry-run the daemon's provider-construction pipeline for one config entry
/// (or the policy defaults when `entry` is `None`) and print the effective
/// sandbox. Returns the number of problems found.
fn print_dry_run(policy: &PluginPolicy, entry: Option<&ProviderEntry>) -> usize {
    let mut problems = 0usize;

    // Mirror rosecd's option pipeline: drop the host-side shorthands, expand
    // `~`/`$home`-style variables once at the boundary, then merge the
    // top-level `path`/`collection` fields plugins may declare as options.
    let mut options: HashMap<String, serde_json::Value> = entry
        .map(|e| {
            e.options
                .iter()
                .filter(|(k, _)| !matches!(k.as_str(), "name" | "allowed_hosts"))
                .map(|(k, v)| (k.clone(), expand_tilde_in_value(v)))
                .collect()
        })
        .unwrap_or_default();
    if let Some(e) = entry {
        if let Some(p) = e.path.as_ref() {
            options
                .entry("path".to_string())
                .or_insert_with(|| expand_tilde_in_value(&serde_json::Value::String(p.clone())));
        }
        if let Some(c) = e.collection.as_ref() {
            options
                .entry("collection".to_string())
                .or_insert_with(|| serde_json::Value::String(c.clone()));
        }
    }

    // Effective network allow-list — same computation as rosecd startup.
    let empty_options = HashMap::new();
    let effective = policy::effective_allowed_hosts(
        policy,
        entry.and_then(|e| e.allowed_hosts.as_deref()),
        entry.map_or(&[][..], |e| e.additional_hosts.as_slice()),
        entry.map_or(&empty_options, |e| &e.options),
    );
    if effective.hosts.is_empty() {
        println!("    network: no hosts (network access denied)");
    } else {
        println!("    effective allowed_hosts:");
        for h in &effective.hosts {
            let origin = if effective.added.contains(h) {
                "  (user additional_hosts)"
            } else if effective.derived.contains(h) {
                "  (derived from URL option)"
            } else if effective.replaced {
                "  (user allowed_hosts)"
            } else {
                "  (policy)"
            };
            println!("      {h}{origin}");
        }
    }
    if effective.replaced {
        println!(
            "    warning: user config replaced policy network.allowed_hosts via allowed_hosts"
        );
    }
    if !effective.added.is_empty() {
        println!(
            "    info: extending allowed_hosts with user additional_hosts ({})",
            effective.added.join(", ")
        );
    }

    // Filesystem dry-run: defaults + template resolution, exactly as the
    // daemon does before constructing the provider.
    if let Err(e) = policy.apply_defaults(&mut options) {
        println!("    error: policy defaults: {e}");
        return problems + 1;
    }
    match policy.resolve(&options) {
        Ok(resolved) => {
            if resolved.allowed_paths.is_empty() && resolved.allowed_files.is_empty() {
                println!("    filesystem: no access");
            } else {
                println!("    resolved filesystem sandbox:");
                for (host, guest) in &resolved.allowed_paths {
                    let (mode, host) = match host.strip_prefix("ro:") {
                        Some(h) => ("ro", h),
                        None => ("rw", host.as_str()),
                    };
                    println!("      preopen  {host} -> {}  ({mode})", guest.display());
                }
                for f in &resolved.allowed_files {
                    println!("      file     {}", f.display());
                }
            }
        }
        Err(e) => {
            problems += 1;
            println!("    error: policy resolve: {e}");
            if entry.is_none() {
                println!(
                    "      (expected without a configured provider when the policy has \
                     required options — add one with `rosec provider add {}`)",
                    policy.kind
                );
                problems -= 1; // not a real problem, just nothing to resolve against
            }
        }
    }

    // Same lenient unknown-option warning the daemon logs at startup.
    for key in policy.unknown_options(&options) {
        println!(
            "    warning: unknown option '{key}' for plugin kind, ignored \
             (not declared in policy)"
        );
    }

    problems
}

fn mode_str(mode: AccessMode) -> &'static str {
    match mode {
        AccessMode::Ro => "ro",
        AccessMode::Rw => "rw",
    }
}

/// Daemon-boundary variable expansion for string option values (`~/`,
/// `$home`, `$xdg_*`); non-strings pass through. Matches rosecd's
/// `expand_tilde_in_value`.
fn expand_tilde_in_value(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::String(s) => serde_json::Value::String(policy::expand_env_vars(s)),
        other => other.clone(),
    }
}
