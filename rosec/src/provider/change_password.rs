//! `rosec provider change-password <vault-id>`
//!
//! Change the unlock password for a vault.  Prompts for the current password,
//! new password, and confirmation.  The wrapping entry matched by the old
//! password is atomically replaced with a new one for the new password.

use anyhow::{Result, bail};

use crate::{conn, password_to_pipe_fd, prompt_field};

pub async fn run(vault_id: &str) -> Result<()> {
    let old_pw = prompt_field("Current password", "", "password").await?;
    if old_pw.is_empty() {
        bail!("current password cannot be empty");
    }

    let new_pw = prompt_field("New password", "", "password").await?;
    if new_pw.is_empty() {
        bail!("new password cannot be empty");
    }

    let confirm_pw = prompt_field("Confirm new password", "", "password").await?;
    if new_pw.as_str() != confirm_pw.as_str() {
        bail!("passwords do not match");
    }

    let old_fd = password_to_pipe_fd(old_pw.as_bytes())?;
    let new_fd = password_to_pipe_fd(new_pw.as_bytes())?;

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let _: () = proxy
        .call("ChangeProviderPassword", &(vault_id, old_fd, new_fd))
        .await?;

    println!("Password changed for vault '{vault_id}'.");
    Ok(())
}
