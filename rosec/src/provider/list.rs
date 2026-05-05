//! `rosec provider list` — show all configured providers with lock state.

use anyhow::Result;

use crate::{
    ColSpec, ProviderEntry, capability_codes, conn, fit_columns, format_relative_time, load_config,
    terminal_width, trunc,
};

pub async fn run() -> Result<()> {
    let cfg = load_config();
    if cfg.provider.is_empty() {
        println!("No providers configured. Run `rosec provider add <kind>` to add one.");
        return Ok(());
    }

    // Collect disabled entries from config (they won't appear in D-Bus).
    let disabled: Vec<&rosec_core::config::ProviderEntry> =
        cfg.provider.iter().filter(|p| !p.enabled).collect();

    // Try D-Bus first for live state.
    if let Ok(conn) = conn().await
        && let Ok(proxy) = zbus::Proxy::new(
            &conn,
            "org.freedesktop.secrets",
            "/org/rosec/Daemon",
            "org.rosec.Daemon",
        )
        .await
        && let Ok(entries) = proxy
            .call::<_, _, Vec<ProviderEntry>>("ProviderList", &())
            .await
    {
        if entries.is_empty() && disabled.is_empty() {
            println!("No providers configured. Run `rosec provider add <kind>` to add one.");
            return Ok(());
        }

        let registry = rosec_wasm::discovery::scan_plugins(
            rosec_core::WasmPreference::default(),
            rosec_core::WasmVerify::default(),
        );
        let is_experimental_kind = |k: &str| -> bool {
            registry
                .get(k)
                .map(|p| p.manifest.experimental)
                .unwrap_or(false)
        };

        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        struct RowData {
            id: String,
            name: String,
            kind: String,
            state: String,
            caps: String,
            sync: String,
        }

        let mut any_experimental = false;
        let mut rows: Vec<RowData> = entries
            .iter()
            .map(
                |(id, name, kind, locked, cached, _, _, last_sync, capabilities)| {
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
                        state,
                        caps,
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
                state: "disabled".to_string(),
                caps: String::new(),
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

        // Priority: ID > NAME > KIND > CAPS > STATE > SYNC (fit to terminal).
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

        fit_columns(&mut cols, 2, terminal_width());
        let id_w = cols[0].allocated;
        let name_w = cols[1].allocated;
        let kind_w = cols[2].allocated;
        let caps_w = cols[3].allocated;
        let state_w = cols[4].allocated;
        let sync_w = if has_sync_col { cols[5].allocated } else { 0 };

        if has_sync_col {
            println!(
                "{:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  {:<state_w$}  LAST SYNC",
                "ID", "NAME", "KIND", "CAPS", "STATE",
            );
        } else {
            println!(
                "{:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  STATE",
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
        println!("{}", "\u{2500}".repeat(sep_w));

        for row in &rows {
            if has_sync_col {
                println!(
                    "{:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  {:<state_w$}  {}",
                    trunc(&row.id, id_w),
                    trunc(&row.name, name_w),
                    trunc(&row.kind, kind_w),
                    trunc(&row.caps, caps_w),
                    trunc(&row.state, state_w),
                    trunc(&row.sync, sync_w),
                );
            } else {
                println!(
                    "{:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  {}",
                    trunc(&row.id, id_w),
                    trunc(&row.name, name_w),
                    trunc(&row.kind, kind_w),
                    trunc(&row.caps, caps_w),
                    trunc(&row.state, state_w),
                );
            }
        }
        println!(
            "\nCAPS: S=Sync W=Write s=Ssh K=KeyWrapping P=PasswordChange C=Cache N=Notifications"
        );
        if any_experimental {
            println!("*: experimental provider — interfaces and behaviour may change");
        }
        return Ok(());
    }

    // Fallback: read config directly (daemon not running).
    let nat_id = cfg
        .provider
        .iter()
        .map(|p| p.id.len())
        .max()
        .unwrap_or(2)
        .max(2);
    let nat_kind = cfg
        .provider
        .iter()
        .map(|p| p.kind.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let state_w = "(daemon not running)".len().max("STATE".len());

    let mut cols = [
        ColSpec {
            natural: nat_id,
            min: 2,
            allocated: 0,
        },
        ColSpec {
            natural: nat_kind,
            min: 4,
            allocated: 0,
        },
        ColSpec {
            natural: state_w,
            min: "STATE".len(),
            allocated: 0,
        },
    ];
    fit_columns(&mut cols, 2, terminal_width());
    let id_w = cols[0].allocated;
    let kind_w = cols[1].allocated;

    println!("{:<id_w$}  {:<kind_w$}  STATE", "ID", "KIND");
    let sep_w = id_w + 2 + kind_w + 2 + state_w;
    println!("{}", "\u{2500}".repeat(sep_w));
    for entry in &cfg.provider {
        let state = if entry.enabled {
            "(daemon not running)"
        } else {
            "disabled"
        };
        println!(
            "{:<id_w$}  {:<kind_w$}  {state}",
            trunc(&entry.id, id_w),
            trunc(&entry.kind, kind_w),
        );
    }
    Ok(())
}
