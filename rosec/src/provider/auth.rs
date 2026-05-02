//! `rosec provider auth <id>` — interactively authenticate a provider.
//!
//! Opens `/dev/tty` and passes the fd to `rosecd` via D-Bus fd-passing.
//! All credential prompting happens inside the daemon — credentials never
//! appear in any D-Bus message payload.

use anyhow::Result;

use crate::cli::ProviderAuthArgs;
use crate::{conn, open_tty_owned_fd};

pub async fn run(args: &ProviderAuthArgs) -> Result<()> {
    let provider_id = args.id.as_str();
    let force = args.force;

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let tty_fd = open_tty_owned_fd()?;
    let _: () = proxy
        .call("AuthProviderWithTty", &(provider_id, tty_fd, force))
        .await?;

    println!("Provider '{provider_id}' authenticated.");
    Ok(())
}
