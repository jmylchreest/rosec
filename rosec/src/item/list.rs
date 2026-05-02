//! `rosec item list` — delegates to the search infrastructure with convenience
//! `--provider` and `--type` filters that get merged into the attribute query.

use std::collections::HashMap;

use anyhow::{Result, bail};
use zbus::Connection;

use crate::cli::ItemListArgs;
use crate::{
    ItemSummary, OutputFormat, any_syncable_providers_locked, cli_format_to_output, conn,
    fetch_item_data, is_glob, is_rosecd, preemptive_sync, print_search_json, print_search_kv,
    print_search_table, search_exact, search_with_glob_fallback, trigger_unlock,
    warn_if_no_providers,
};

pub async fn run(args: ItemListArgs) -> Result<()> {
    let format = cli_format_to_output(args.format);
    let show_path = args.show_path;
    let sync = args.sync;
    let no_unlock = args.no_unlock;
    let mut all_attrs: HashMap<String, String> = HashMap::new();

    if let Some(ref prov) = args.provider {
        all_attrs.insert(rosec_core::ATTR_PROVIDER.to_string(), prov.clone());
    }
    if let Some(ref typ) = args.item_type {
        all_attrs.insert(rosec_core::ATTR_TYPE.to_string(), typ.clone());
    }
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

    let conn = conn().await?;
    let rosecd = is_rosecd(&conn).await;
    if rosecd {
        warn_if_no_providers(&conn).await;
    }

    if sync {
        preemptive_sync(&conn).await?;
    }

    let has_globs = all_attrs.values().any(|v| is_glob(v)) || all_attrs.contains_key("name");

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
