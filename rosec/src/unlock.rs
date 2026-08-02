//! `rosec unlock` — unlock all syncable providers via TTY fd-passing, or via
//! the graphical prompt with `--gui`.

use anyhow::Result;

use crate::{ProviderEntry, conn, open_tty_owned_fd};

pub async fn run(gui: bool) -> Result<()> {
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

    type ResultEntry = (String, bool, String); // (provider_id, success, message)

    // Both methods run the same walk inside rosecd and return the same tuples;
    // they differ only in where the daemon renders its prompts.
    let results: Vec<ResultEntry> = if gui {
        proxy.call("UnlockWithPrompt", &()).await?
    } else {
        // Pass the caller's TTY fd to the daemon via D-Bus fd-passing.
        // All credential prompting happens inside rosecd — credentials never
        // appear in any D-Bus message payload.
        let tty_fd = open_tty_owned_fd()?;
        eprintln!("Unlocking…");
        proxy.call("UnlockWithTty", &(tty_fd,)).await?
    };

    for (id, success, message) in &results {
        if *success {
            println!("  {id}: {message}");
        } else if gui {
            // The TTY path already printed failures inline on the terminal;
            // a dialog leaves no such trace, so surface them here.
            println!("  {id}: {message}");
        }
    }

    Ok(())
}
