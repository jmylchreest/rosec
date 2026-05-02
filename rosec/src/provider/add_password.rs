//! `rosec provider add-password <id> [--label <label>]`
//!
//! Add a new unlock password to a vault. The vault must be unlocked (running in
//! rosecd).

use anyhow::{Result, bail};

use crate::cli::ProviderAddPasswordArgs;
use crate::{conn, prompt_field};

use super::default_password_label;

pub async fn run(args: ProviderAddPasswordArgs) -> Result<()> {
    let vault_id = args.id.as_str();

    // Default label: user@hostname
    let label = args.label.unwrap_or_else(default_password_label);

    let pw = prompt_field("New password", "", "password").await?;
    if pw.is_empty() {
        bail!("password cannot be empty");
    }
    let pw_confirm = prompt_field("Confirm password", "", "password").await?;
    if pw.as_str() != pw_confirm.as_str() {
        bail!("passwords do not match");
    }

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let entry_id: String = proxy
        .call("AddPassword", &(vault_id, pw.as_bytes().to_vec(), &label))
        .await?;

    println!("Added password entry {entry_id} (label: {label}) to vault '{vault_id}'.");
    Ok(())
}
