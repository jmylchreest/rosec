//! One dispatch path for both modern and deprecated instance commands.
use crate::cli::{
    PasswordOperation, ProviderAddPasswordArgs, ProviderAuthArgs, ProviderOperation,
    ProviderRemovePasswordArgs, ProviderRequest,
};
use anyhow::{Result, bail};
pub async fn run(request: ProviderRequest) -> Result<()> {
    let id = request.id;
    match request.operation {
        ProviderOperation::Unlock { force } => {
            super::auth::run(&ProviderAuthArgs { id, force }).await
        }
        ProviderOperation::Password { action } => match action {
            PasswordOperation::Add { label } => {
                super::add_password::run(ProviderAddPasswordArgs { id, label }).await
            }
            PasswordOperation::Remove { entry_id } => {
                super::remove_password::run(&ProviderRemovePasswordArgs { id, entry_id }).await
            }
            PasswordOperation::List => super::list_passwords::run(&id).await,
            PasswordOperation::Change => super::change_password::run(&id).await,
        },
        operation => {
            let conn = crate::conn().await?;
            let proxy = zbus::Proxy::new(
                &conn,
                "org.freedesktop.secrets",
                "/org/rosec/Daemon",
                "org.rosec.Daemon",
            )
            .await?;
            let entries: Vec<crate::ProviderEntry> = proxy.call("ProviderList", &()).await?;
            let entry = entries
                .into_iter()
                .find(|entry| entry.0 == id)
                .ok_or_else(|| anyhow::anyhow!("provider '{id}' is not active"))?;
            match operation {
                ProviderOperation::Status => {
                    crate::render_provider_table(&[entry], &[], &|_| false, "");
                    Ok(())
                }
                ProviderOperation::Sync => {
                    if !entry.8.iter().any(|c| c == "Sync") {
                        bail!("provider '{id}' does not support sync");
                    }
                    let count: u32 = proxy.call("SyncProvider", &(id.as_str(),)).await?;
                    println!("Synced '{id}': {count} items");
                    Ok(())
                }
                _ => unreachable!(),
            }
        }
    }
}
