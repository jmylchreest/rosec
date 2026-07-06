//! `rosec status` — show daemon, providers, and component versions.

use std::path::PathBuf;

use anyhow::Result;

use crate::{
    ColSpec, ProviderEntry, capability_codes, config_path, conn, epoch_now, fit_columns,
    format_relative_time, load_config, terminal_width, trunc,
};

pub async fn run() -> Result<()> {
    let ver = format!("{} ({})", env!("ROSEC_VERSION"), env!("ROSEC_GIT_SHA"));
    let cfg_path = config_path();
    let cfg_display = cfg_path
        .strip_prefix(
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default(),
        )
        .map(|rel| format!("~/{}", rel.display()))
        .unwrap_or_else(|_| cfg_path.display().to_string());

    let socket_display = if std::env::var_os("ROSEC_SOCKET").is_some() {
        "private socket"
    } else {
        "session bus"
    };

    println!("  {:<14}{ver}", "Daemon");
    println!("  {:<14}{cfg_display}", "Config");
    println!("  {:<14}{socket_display}", "Socket");
    println!();

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let (cache_size,): (u32,) = proxy.call("Status", &()).await?;

    let cfg = load_config();
    let disabled: Vec<&rosec_core::config::ProviderEntry> =
        cfg.provider.iter().filter(|p| !p.enabled).collect();
    let providers: Vec<ProviderEntry> = proxy.call("ProviderList", &()).await?;

    println!("Providers");

    if providers.is_empty() && disabled.is_empty() {
        println!("  (none configured)");
    } else {
        struct RowData {
            id: String,
            name: String,
            kind: String,
            caps: String,
            state: String,
            sync: String,
        }

        let now_epoch = epoch_now();

        let registry = rosec_wasm::discovery::scan_plugins(
            rosec_core::WasmPreference::default(),
            rosec_core::WasmVerify::default(),
            &cfg.service.wasm_trusted_key,
        );
        let is_experimental_kind = |k: &str| -> bool {
            registry
                .get(k)
                .map(|p| p.manifest.experimental)
                .unwrap_or(false)
        };
        let mut any_experimental = false;

        let mut rows: Vec<RowData> = providers
            .iter()
            .map(
                |(
                    id,
                    name,
                    kind,
                    locked,
                    cached,
                    _offline_cache,
                    _last_cache_write,
                    last_sync,
                    capabilities,
                )| {
                    let state = match (*locked, *cached) {
                        (true, _) => "locked".to_string(),
                        (false, true) => "unlocked (cached)".to_string(),
                        (false, false) => "unlocked".to_string(),
                    };
                    let sync = if *locked {
                        String::new()
                    } else {
                        format_relative_time(*last_sync, now_epoch)
                    };
                    let caps = capability_codes(capabilities);
                    let kind_display = if is_experimental_kind(kind) {
                        any_experimental = true;
                        format!("{kind}*")
                    } else {
                        kind.clone()
                    };
                    RowData {
                        id: id.clone(),
                        name: name.clone(),
                        kind: kind_display,
                        caps,
                        state,
                        sync,
                    }
                },
            )
            .collect();

        for entry in &disabled {
            let kind_display = if is_experimental_kind(&entry.kind) {
                any_experimental = true;
                format!("{}*", entry.kind)
            } else {
                entry.kind.clone()
            };
            rows.push(RowData {
                id: entry.id.clone(),
                name: entry.id.clone(),
                kind: kind_display,
                caps: String::new(),
                state: "disabled".to_string(),
                sync: String::new(),
            });
        }

        let id_w = rows.iter().map(|r| r.id.len()).max().unwrap_or(2).max(2);
        let name_w = rows.iter().map(|r| r.name.len()).max().unwrap_or(4).max(4);
        let kind_w = rows.iter().map(|r| r.kind.len()).max().unwrap_or(4).max(4);
        let caps_w = rows
            .iter()
            .map(|r| r.caps.len())
            .max()
            .unwrap_or(0)
            .max("CAPS".len());
        let state_w = rows.iter().map(|r| r.state.len()).max().unwrap_or(5).max(5);
        let sync_w = rows.iter().map(|r| r.sync.len()).max().unwrap_or(0).max(
            if rows.iter().any(|r| !r.sync.is_empty()) {
                "LAST SYNC".len()
            } else {
                0
            },
        );

        let has_sync_col = sync_w > 0;

        // Priority ordering: ID > NAME > KIND > CAPS > STATE > SYNC
        let mut cols = vec![
            ColSpec {
                natural: id_w,
                min: 2,
                allocated: 0,
            },
            ColSpec {
                natural: name_w,
                min: 4,
                allocated: 0,
            },
            ColSpec {
                natural: kind_w,
                min: 4,
                allocated: 0,
            },
            ColSpec {
                natural: caps_w,
                min: "CAPS".len(),
                allocated: 0,
            },
            ColSpec {
                natural: state_w,
                min: 5,
                allocated: 0,
            },
        ];
        if has_sync_col {
            cols.push(ColSpec {
                natural: sync_w,
                min: "SYNC".len(),
                allocated: 0,
            });
        }

        fit_columns(&mut cols, 2, terminal_width().saturating_sub(2)); // 2-char indent
        let id_w = cols[0].allocated;
        let name_w = cols[1].allocated;
        let kind_w = cols[2].allocated;
        let caps_w = cols[3].allocated;
        let state_w = cols[4].allocated;
        let sync_w = if has_sync_col { cols[5].allocated } else { 0 };

        if has_sync_col {
            println!(
                "  {:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  {:<state_w$}  LAST SYNC",
                "ID", "NAME", "KIND", "CAPS", "STATE",
            );
        } else {
            println!(
                "  {:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  STATE",
                "ID", "NAME", "KIND", "CAPS",
            );
        }
        let sep_w = id_w
            + 2
            + name_w
            + 2
            + kind_w
            + 2
            + caps_w
            + 2
            + state_w
            + if has_sync_col { 2 + sync_w } else { 0 };
        println!("  {}", "\u{2500}".repeat(sep_w));

        for row in &rows {
            if has_sync_col {
                println!(
                    "  {:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  {:<state_w$}  {}",
                    trunc(&row.id, id_w),
                    trunc(&row.name, name_w),
                    trunc(&row.kind, kind_w),
                    trunc(&row.caps, caps_w),
                    trunc(&row.state, state_w),
                    trunc(&row.sync, sync_w),
                );
            } else {
                println!(
                    "  {:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  {}",
                    trunc(&row.id, id_w),
                    trunc(&row.name, name_w),
                    trunc(&row.kind, kind_w),
                    trunc(&row.caps, caps_w),
                    trunc(&row.state, state_w),
                );
            }
        }
        if any_experimental {
            println!("  *: experimental provider — interfaces and behaviour may change");
        }
    }
    println!();

    println!("Daemon");
    println!("  {:<14}{cache_size} items", "Items");
    println!();

    println!("Components");
    println!("  {:<22}{ver}", "rosec");

    for bin in &["rosecd", "rosec-prompt"] {
        let bin_ver = probe_binary_version(bin).unwrap_or_else(|| "not found".to_string());
        println!("  {:<22}{bin_ver}", bin);
    }

    let pam_unlock_ver = probe_binary_version("rosec-pam-unlock")
        .or_else(|| probe_binary_version_at("/usr/lib/rosec/rosec-pam-unlock"));
    println!(
        "  {:<22}{}",
        "rosec-pam-unlock",
        pam_unlock_ver.unwrap_or_else(|| "not found".to_string())
    );

    let pam_so = std::path::Path::new("/usr/lib/security/pam_rosec.so");
    println!(
        "  {:<22}{}",
        "pam_rosec.so",
        if pam_so.exists() {
            "installed"
        } else {
            "not found"
        }
    );

    Ok(())
}

/// Run `<binary> --version` and return the first line of output, or `None`.
fn probe_binary_version(name: &str) -> Option<String> {
    let output = std::process::Command::new(name)
        .arg("--version")
        .output()
        .ok()?;
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        String::from_utf8_lossy(&output.stdout).to_string()
    };
    let line = text.lines().next()?.trim().to_string();
    let ver = line
        .strip_prefix(name)
        .map(|s| s.trim().to_string())
        .unwrap_or(line);
    if ver.is_empty() { None } else { Some(ver) }
}

/// Run a binary at an absolute path with `--version`.
fn probe_binary_version_at(path: &str) -> Option<String> {
    if !std::path::Path::new(path).exists() {
        return None;
    }
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()?;
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        String::from_utf8_lossy(&output.stdout).to_string()
    };
    let line = text.lines().next()?.trim().to_string();
    let bin_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let ver = line
        .strip_prefix(bin_name)
        .map(|s| s.trim().to_string())
        .unwrap_or(line);
    if ver.is_empty() { None } else { Some(ver) }
}
