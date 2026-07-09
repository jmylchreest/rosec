//! `rosec provider list` — show all configured providers with lock state.

use anyhow::Result;

use crate::{
    ColSpec, ProviderEntry, conn, fit_columns, load_config, render_provider_table, terminal_width,
    trunc,
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
            &cfg.service.wasm_trusted_key,
        );
        let is_experimental_kind = |k: &str| -> bool {
            registry
                .get(k)
                .map(|p| p.manifest.experimental)
                .unwrap_or(false)
        };

        let any_experimental =
            render_provider_table(&entries, &disabled, &is_experimental_kind, "");
        println!(
            "\nCAPS: S=Sync W=Write s=Ssh K=KeyWrapping P=PasswordChange C=Cache N=Notifications F=Fido2"
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
