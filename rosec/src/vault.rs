//! Native-file operations; these do not pretend to be generic provider recovery.
use crate::cli::{SnapshotRestoreArgs, VaultCommands, VaultSnapshotCommands};
use anyhow::{Result, bail};
pub async fn dispatch(action: VaultCommands) -> Result<()> {
    match action {
        VaultCommands::Snapshot {
            action: VaultSnapshotCommands::Restore(args),
        } => restore(args).await,
    }
}
async fn restore(args: SnapshotRestoreArgs) -> Result<()> {
    let SnapshotRestoreArgs {
        path,
        snapshot,
        yes: _,
    } = args;
    // Do not activate a service. Refuse restoration while rosec is serving
    // cached metadata, even if its native vault happens to be locked.
    if let Ok(conn) = zbus::Connection::session().await {
        let bus = zbus::Proxy::new(
            &conn,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .await?;
        let owned: bool = bus
            .call("NameHasOwner", &("org.freedesktop.secrets",))
            .await?;
        if owned {
            let proxy = zbus::Proxy::new(
                &conn,
                "org.freedesktop.secrets",
                "/org/rosec/Daemon",
                "org.freedesktop.DBus.Introspectable",
            )
            .await?;
            if proxy.call::<_, _, String>("Introspect", &()).await.is_ok() {
                bail!("stop rosecd before restoring a vault snapshot");
            }
        }
    }
    let password = crate::prompt_field("Snapshot password", "", "password").await?;
    rosec_vault::LocalVault::new("recovery", &path)
        .restore_snapshot(&snapshot, password.as_bytes())
        .await?;
    println!(
        "Restored {}. The previous encrypted vault was kept beside it as a recovery snapshot.",
        path.display()
    );
    Ok(())
}
