//! `rosec sync` — manually trigger a sync on all syncable providers.

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

    for (id, _name, _kind, _locked, _, _, _, _, capabilities) in &providers {
        if !capabilities.iter().any(|c| c == "Sync") {
            continue;
        }
        eprint!("Syncing '{id}'...");
        match proxy.call::<_, _, u32>("SyncProvider", &(id,)).await {
            Ok(count) => {
                println!(" {count} items");
            }
            Err(zbus::Error::MethodError(_, Some(detail), _))
                if detail.as_str().starts_with("locked::") =>
            {
                // Daemon says this provider needs credentials first.
                let provider_id = detail.as_str().strip_prefix("locked::").unwrap_or("");
                eprintln!(" locked");
                let tty_fd = open_tty_owned_fd()?;
                // force=false: don't re-register if creds already stored;
                // sync's lazy unlock just wants normal auth.
                let _: () = proxy
                    .call("AuthProviderWithTty", &(provider_id, tty_fd, false))
                    .await?;
                eprint!("Syncing '{id}' (retrying)...");
                match proxy.call::<_, _, u32>("SyncProvider", &(id,)).await {
                    Ok(count) => println!(" {count} items"),
                    Err(e) => eprintln!(" failed: {e}"),
                }
            }
            Err(e) => eprintln!(" failed: {e}"),
        }
    }

    Ok(())
}
