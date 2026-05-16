//! `rosec search` — query items via the Secret Service `SearchItems` API.

use std::collections::HashMap;

use anyhow::{Result, bail};
use zbus::Connection;

use crate::cli::SearchArgs;
use crate::{
    ItemSummary, OutputFormat, any_syncable_providers_locked, cli_format_to_output, conn,
    fetch_item_data, is_glob, is_rosecd, preemptive_sync, print_search_json, print_search_kv,
    print_search_table, search_exact, search_with_glob_fallback, trigger_unlock,
    warn_if_no_providers,
};

pub async fn run(args: SearchArgs) -> Result<()> {
    let format = cli_format_to_output(args.format);
    let show_path = args.show_path;
    let sync = args.sync;
    let no_unlock = args.no_unlock;
    let no_dedup = args.no_dedup;
    let provider_id = args.provider.clone();
    let mut all_attrs: HashMap<String, String> = HashMap::new();

    for filter in &args.filters {
        if let Some((key, value)) = filter.split_once('=') {
            all_attrs.insert(key.to_string(), value.to_string());
        } else {
            bail!("invalid filter: {filter} (expected key=value)");
        }
    }

    if sync && no_unlock {
        bail!("--sync and --no-unlock are mutually exclusive");
    }

    if no_dedup && provider_id.is_none() {
        bail!("--no-dedup requires --provider <id>");
    }

    let conn = conn().await?;
    let rosecd = is_rosecd(&conn).await;
    if rosecd {
        warn_if_no_providers(&conn).await;
    }

    if no_dedup {
        return run_no_dedup(&conn, provider_id.as_deref().unwrap(), &all_attrs, format).await;
    }

    if sync {
        preemptive_sync(&conn).await?;
    }

    let has_globs = all_attrs.values().any(|v| is_glob(v)) || all_attrs.contains_key("name");

    // Strategy:
    //   - Any glob pattern or "name" filter → use org.rosec.Search.SearchItemsGlob
    //     when rosecd is running; otherwise fall back to spec-compliant
    //     SearchItems({}) + client-side glob (works against GNOME Keyring, KWallet, etc.)
    //   - All-exact attrs → always use spec-compliant SearchItems directly.
    let do_search = |conn: &Connection| {
        let conn = conn.clone();
        let all_attrs = all_attrs.clone();
        async move {
            if has_globs {
                search_with_glob_fallback(&conn, &all_attrs, rosecd, no_unlock).await
            } else {
                search_exact(&conn, &all_attrs, no_unlock).await
            }
        }
    };

    let (unlocked, locked) = match do_search(&conn).await {
        Ok(result) => result,
        Err(e) if sync => {
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            do_search(&conn).await.map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    let needs_unlock = !no_unlock && sync && any_syncable_providers_locked(&conn).await?;
    let (unlocked, locked) = if needs_unlock {
        trigger_unlock(&conn).await?;
        preemptive_sync(&conn).await?;
        do_search(&conn).await?
    } else {
        (unlocked, locked)
    };

    if unlocked.is_empty() && locked.is_empty() {
        if format != OutputFormat::Json {
            println!("No items found.");
        } else {
            println!("[]");
        }
        return Ok(());
    }

    let mut items: Vec<ItemSummary> = Vec::new();
    for path in &unlocked {
        let summary = fetch_item_data(&conn, path, false)
            .await
            .unwrap_or_else(|_| ItemSummary {
                label: path.clone(),
                attrs: HashMap::new(),
                path: path.clone(),
                locked: false,
            });
        items.push(summary);
    }
    for path in &locked {
        let summary = fetch_item_data(&conn, path, true)
            .await
            .unwrap_or_else(|_| ItemSummary {
                label: path.clone(),
                attrs: HashMap::new(),
                path: path.clone(),
                locked: true,
            });
        items.push(summary);
    }

    match format {
        OutputFormat::Human | OutputFormat::Table => print_search_table(&items, show_path),
        OutputFormat::Kv => print_search_kv(&items, show_path),
        OutputFormat::Json => print_search_json(&items)?,
    }

    Ok(())
}

/// `--no-dedup` path: call `org.rosec.Items.ReadItemsFromProvider` directly so
/// items that the cache's dedup layer would hide (cross-provider duplicates,
/// where another provider won by priority) are returned with their primary
/// secret bytes attached.  Useful for diagnostics and cross-provider migration
/// — the surfaced bytes can be copied into another provider via
/// `rosec item edit` / `rosec item import`.
async fn run_no_dedup(
    conn: &Connection,
    provider_id: &str,
    attrs: &HashMap<String, String>,
    format: OutputFormat,
) -> Result<()> {
    type RawItem = (String, String, HashMap<String, String>, Vec<u8>);

    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Items",
        "org.rosec.Items",
    )
    .await?;
    let items: Vec<RawItem> = proxy
        .call("ReadItemsFromProvider", &(provider_id, attrs))
        .await?;

    if items.is_empty() {
        if format == OutputFormat::Json {
            println!("[]");
        } else {
            println!("No items found.");
        }
        return Ok(());
    }

    match format {
        OutputFormat::Json => {
            use base64::Engine;
            let json: Vec<serde_json::Value> = items
                .iter()
                .map(|(id, label, attrs, secret)| {
                    serde_json::json!({
                        "provider": provider_id,
                        "id": id,
                        "label": label,
                        "attributes": attrs,
                        "secret_base64": base64::engine::general_purpose::STANDARD.encode(secret),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        _ => {
            for (id, label, attrs_map, secret) in &items {
                println!("Provider:   {provider_id}");
                println!("ID:         {id}");
                println!("Label:      {label}");
                if !attrs_map.is_empty() {
                    println!("Attributes:");
                    let mut sorted: Vec<_> = attrs_map.iter().collect();
                    sorted.sort_by_key(|(k, _)| *k);
                    for (k, v) in sorted {
                        println!("  {k}: {v}");
                    }
                }
                if secret.is_empty() {
                    println!("Secret:     <empty / not readable>");
                } else {
                    let text = String::from_utf8_lossy(secret);
                    println!("Secret:     {text}");
                }
                println!();
            }
        }
    }

    Ok(())
}
