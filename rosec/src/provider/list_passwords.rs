//! `rosec provider list-passwords <vault-id>`
//!
//! List the wrapping entries (unlock passwords) for a vault. The vault must be
//! unlocked. Shows the entry ID and label for each password.

use anyhow::Result;

use crate::conn;

pub async fn run(vault_id: &str) -> Result<()> {
    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let entries: Vec<(String, String)> = proxy.call("ListPasswords", &(vault_id,)).await?;

    if entries.is_empty() {
        println!("No password entries found for vault '{vault_id}'.");
        return Ok(());
    }

    println!("Password entries for vault '{vault_id}':\n");
    println!("  {:<40} LABEL", "ENTRY ID");
    println!("  {:<40} -----", "--------");
    for (id, label) in &entries {
        let display_label = if label.is_empty() { "(none)" } else { label };
        println!("  {:<40} {}", id, display_label);
    }

    Ok(())
}
