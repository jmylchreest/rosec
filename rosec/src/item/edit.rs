//! `rosec item edit` — edit an existing item via $EDITOR.
//!
//! 1. Resolve the item path
//! 2. Fetch label, public attributes, secret attribute names + values
//! 3. Build a TOML document
//! 4. Open $EDITOR
//! 5. Parse the edited TOML
//! 6. Call UpdateItem via D-Bus

use anyhow::{Result, bail};

use crate::cli::ItemEditArgs;
use crate::{conn, is_rosecd, preemptive_sync, resolve_item_path, trigger_unlock};

use super::{build_item_toml, fetch_full_item, open_editor, parse_item_toml};

pub async fn run(args: ItemEditArgs) -> Result<()> {
    let sync = args.sync;
    let raw = args.item.as_str();

    let conn = conn().await?;
    if !is_rosecd(&conn).await {
        bail!("rosec item edit requires rosecd (the rosec daemon) to be running");
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

    let fetched = fetch_full_item(&conn, &path).await?;

    let toml_content = build_item_toml(
        &fetched.label,
        &fetched.item_type,
        &fetched.pub_attrs,
        &fetched.secrets,
    );

    let edited = open_editor(&toml_content)?;
    let content = match edited {
        Some(c) => c,
        None => {
            println!("No changes — item not updated.");
            return Ok(());
        }
    };

    let parsed = parse_item_toml(&content)?;

    let items_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Items",
        "org.rosec.Items",
    )
    .await?;

    let _: () = items_proxy
        .call(
            "UpdateItem",
            &(
                path.as_str(),
                parsed.label.as_str(),
                parsed.item_type.as_str(),
                &parsed.attributes,
                &parsed.secrets,
            ),
        )
        .await?;

    let display_id = path
        .rsplit('/')
        .next()
        .and_then(|seg| seg.rsplit('_').next())
        .unwrap_or(&path);

    println!("Updated item: {} ({})", parsed.label, display_id);
    Ok(())
}
