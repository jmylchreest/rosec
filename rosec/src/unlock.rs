//! `rosec unlock` — unlock all syncable providers via TTY fd-passing.

use anyhow::Result;

use crate::{ProviderEntry, conn, open_tty_owned_fd};

pub async fn run() -> Result<()> {
    let conn = conn().await?;

    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let providers: Vec<ProviderEntry> = proxy.call("ProviderList", &()).await?;

    if providers.is_empty() {
        println!("No providers configured. Run `rosec provider add <kind>` to add one.");
        return Ok(());
    }

    let any_locked = providers.iter().any(|(_, _, _, locked, ..)| *locked);
    if !any_locked {
        for (id, ..) in &providers {
            println!("  {id}: already unlocked");
        }
        return Ok(());
    }

    // Pass the caller's TTY fd to the daemon via D-Bus fd-passing.
    // All credential prompting happens inside rosecd — credentials never
    // appear in any D-Bus message payload.
    let tty_fd = open_tty_owned_fd()?;
    eprintln!("Unlocking…");
    type ResultEntry = (String, bool, String); // (provider_id, success, message)
    let results: Vec<ResultEntry> = proxy.call("UnlockWithTty", &(tty_fd,)).await?;

    for (id, success, message) in &results {
        if *success {
            println!("  {id}: {message}");
        }
        // Failures are already printed inline on the TTY by the daemon.
    }

    Ok(())
}
