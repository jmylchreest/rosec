//! `rosec item export` — export an item as TOML to stdout.
//!
//! The output uses the same `[item]`/`[attributes]`/`[secrets]` format as
//! the editor workflow, so it can be piped into `rosec item import` or
//! redirected to a file for backup.

use anyhow::{Result, bail};

use crate::cli::ItemExportArgs;
use crate::{conn, is_rosecd, preemptive_sync, resolve_item_path, trigger_unlock};

use super::{build_item_toml, fetch_full_item};

pub async fn run(args: ItemExportArgs) -> Result<()> {
    let sync = args.sync;
    let raw = args.item.as_str();

    let conn = conn().await?;
    if !is_rosecd(&conn).await {
        bail!("rosec item export requires rosecd (the rosec daemon) to be running");
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
    print!("{toml_content}");

    Ok(())
}
