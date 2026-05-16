//! `rosec item import` — import an item from TOML on stdin.
//!
//! Reads the same `[item]`/`[attributes]`/`[secrets]` TOML format produced
//! by `rosec item export`.  Creates the item via `CreateItemExtended` on
//! the specified (or default write-capable) provider.

use std::io::{self, Read};

use anyhow::{Result, bail};

use crate::cli::ItemImportArgs;
use crate::{conn, is_rosecd};

use super::parse_item_toml;

pub async fn run(args: ItemImportArgs) -> Result<()> {
    let provider_id = args.provider.unwrap_or_default();
    let force = args.force;

    let mut content = String::new();
    io::stdin().lock().read_to_string(&mut content)?;

    if content.trim().is_empty() {
        bail!("no input on stdin — pipe a TOML document or redirect a file");
    }

    let parsed = parse_item_toml(&content)?;

    if parsed.secrets.is_empty() && parsed.attributes.is_empty() {
        bail!("item has no attributes or secrets — nothing to store");
    }

    let conn = conn().await?;
    if !is_rosecd(&conn).await {
        bail!("rosec item import requires rosecd (the rosec daemon) to be running");
    }

    let items_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Items",
        "org.rosec.Items",
    )
    .await?;

    let caps: Vec<String> = items_proxy
        .call("GetCapabilities", &(&provider_id,))
        .await?;
    if !caps.iter().any(|c| c == "Write") {
        if provider_id.is_empty() {
            bail!("no write-capable provider available — add a local vault first");
        } else {
            bail!("provider '{provider_id}' does not support writes");
        }
    }

    let supported_types: Vec<String> = items_proxy
        .call("GetSupportedItemTypes", &(&provider_id,))
        .await?;
    if !supported_types.is_empty() && !supported_types.contains(&parsed.item_type) {
        bail!(
            "provider does not support item type '{}'\nsupported: {}",
            parsed.item_type,
            supported_types.join(", ")
        );
    }

    let item_path: String = items_proxy
        .call(
            "CreateItemExtended",
            &(
                &parsed.label,
                &parsed.item_type,
                &parsed.attributes,
                &parsed.secrets,
                force, // replace if --force was passed
            ),
        )
        .await?;

    let display_id = item_path
        .rsplit('/')
        .next()
        .and_then(|seg| seg.rsplit('_').next())
        .unwrap_or(&item_path);

    eprintln!("Imported item: {} ({})", parsed.label, display_id);
    Ok(())
}
