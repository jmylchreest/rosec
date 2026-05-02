//! `rosec item delete` — delete an item with confirmation.
//!
//! 1. Resolve the item path
//! 2. Fetch label for the confirmation prompt
//! 3. Prompt for confirmation (unless `--yes` / `-y`)
//! 4. Call DeleteItem via D-Bus

use std::io::{self, BufRead};

use anyhow::{Result, bail};

use crate::cli::ItemDeleteArgs;
use crate::{conn, is_rosecd, preemptive_sync, resolve_item_path, trigger_unlock};

pub async fn run(args: ItemDeleteArgs) -> Result<()> {
    let sync = args.sync;
    let yes = args.yes;
    let raw = args.item.as_str();

    let conn = conn().await?;
    if !is_rosecd(&conn).await {
        bail!("rosec item delete requires rosecd (the rosec daemon) to be running");
    }

    if sync {
        preemptive_sync(&conn).await?;
    }

    let (path, is_locked) = match resolve_item_path(&conn, raw).await {
        Ok(result) => result,
        Err(e) if sync => {
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            resolve_item_path(&conn, raw).await.map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    if is_locked {
        trigger_unlock(&conn).await?;
        if sync {
            preemptive_sync(&conn).await?;
        }
    }

    let item_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        path.as_str(),
        "org.freedesktop.Secret.Item",
    )
    .await?;

    let label: String = item_proxy
        .get_property("Label")
        .await
        .unwrap_or_else(|_| "<unknown>".to_string());

    let display_id = path
        .rsplit('/')
        .next()
        .and_then(|seg| seg.rsplit('_').next())
        .unwrap_or(&path);

    if !yes {
        eprint!("Delete item '{}' ({})? [y/N] ", label, display_id);
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        let answer = line.trim().to_lowercase();
        if answer != "y" && answer != "yes" {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let items_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Items",
        "org.rosec.Items",
    )
    .await?;

    let _: () = items_proxy.call("DeleteItem", &(path.as_str(),)).await?;

    println!("Deleted item: {} ({})", label, display_id);
    Ok(())
}
