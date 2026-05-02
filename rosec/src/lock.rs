//! `rosec lock` — lock the default collection (and report how many providers were locked).

use anyhow::Result;
use zvariant::OwnedObjectPath;

use crate::{ProviderEntry, conn};

pub async fn run() -> Result<()> {
    let conn = conn().await?;

    let mgmt_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;
    let providers: Vec<ProviderEntry> = mgmt_proxy.call("ProviderList", &()).await?;
    let unlocked_count = providers
        .iter()
        .filter(|(_, _, _, locked, ..)| !locked)
        .count();

    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;
    let _: (Vec<OwnedObjectPath>, OwnedObjectPath) = proxy
        .call(
            "Lock",
            &(vec![
                OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default")
                    .expect("static path"),
            ],),
        )
        .await?;

    match unlocked_count {
        0 => println!("Nothing to lock — all providers already locked."),
        n => println!(
            "Locked: 1 collection, {} provider{}.",
            n,
            if n == 1 { "" } else { "s" }
        ),
    }
    Ok(())
}
