//! `rosec provider remove-password <vault-id> <entry-id>`
//!
//! Remove an unlock password from a vault. The vault must be unlocked and must
//! have at least 2 passwords.

use anyhow::Result;

use crate::cli::ProviderRemovePasswordArgs;
use crate::conn;

pub async fn run(args: &ProviderRemovePasswordArgs) -> Result<()> {
    let vault_id = args.id.as_str();
    let entry_id = args.entry_id.as_str();

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    // First list passwords to show the user what they're removing.
    let entries: Vec<(String, String)> = proxy.call("ListPasswords", &(vault_id,)).await?;

    let target = entries
        .iter()
        .find(|(id, _)| id == entry_id)
        .ok_or_else(|| {
            anyhow::anyhow!("password entry '{entry_id}' not found in vault '{vault_id}'")
        })?;

    let label_display = if target.1.is_empty() {
        "(no label)".to_string()
    } else {
        target.1.clone()
    };

    println!("Removing password entry: {entry_id} {label_display}");

    let _: () = proxy.call("RemovePassword", &(vault_id, entry_id)).await?;

    println!("Removed password entry '{entry_id}' from vault '{vault_id}'.");
    Ok(())
}
