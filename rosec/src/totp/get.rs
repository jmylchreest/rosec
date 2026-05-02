//! `rosec totp get <item>` — fetch and display a TOTP code.

use anyhow::{Result, bail};
use zbus::Connection;

use crate::cli::TotpGetArgs;
use crate::{conn, preemptive_sync, resolve_item_path, trigger_unlock, try_lazy_unlock};

use super::{has_display, resolve_prompt_binary_cli};

pub async fn run(args: TotpGetArgs) -> Result<()> {
    if args.sync && args.no_unlock {
        bail!("--sync and --no-unlock are mutually exclusive");
    }

    let conn = conn().await?;

    if args.sync {
        preemptive_sync(&conn).await?;
    }

    let resolve_result = resolve_item_path(&conn, args.item.as_str()).await;

    let (path, is_locked) = match resolve_result {
        Ok(result) => result,
        Err(e) if args.sync && !args.no_unlock => {
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            resolve_item_path(&conn, args.item.as_str())
                .await
                .map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    if is_locked {
        if args.no_unlock {
            bail!("item is locked — use --sync to unlock the provider first");
        }
        trigger_unlock(&conn).await?;
        if args.sync {
            preemptive_sync(&conn).await?;
        }
    }

    match totp_inner(&conn, &path, args.stdout).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let zbus_err = e.downcast_ref::<zbus::Error>();
            if !args.no_unlock
                && let Some(ze) = zbus_err
                && try_lazy_unlock(&conn, ze).await?
            {
                totp_inner(&conn, &path, args.stdout).await
            } else {
                Err(e)
            }
        }
    }
}

async fn totp_inner(conn: &Connection, path: &str, use_stdout: bool) -> Result<()> {
    let secrets_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Secrets",
        "org.rosec.Secrets",
    )
    .await?;

    let item_obj_path = zvariant::ObjectPath::try_from(path)
        .map_err(|e| anyhow::anyhow!("invalid item path: {e}"))?;
    let (code, remaining): (String, u32) = secrets_proxy
        .call("GetTotpCode", &(&item_obj_path,))
        .await
        .map_err(|e| anyhow::anyhow!("GetTotpCode failed: {e}"))?;

    if use_stdout || !has_display() {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        out.write_all(code.as_bytes())?;
        if std::io::IsTerminal::is_terminal(&out) && !code.ends_with('\n') {
            out.write_all(b"\n")?;
        }
        out.flush()?;
        return Ok(());
    }

    let prompt_bin = resolve_prompt_binary_cli();

    let item_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        path,
        "org.freedesktop.Secret.Item",
    )
    .await?;
    let label: String = item_proxy
        .get_property("Label")
        .await
        .unwrap_or_else(|_| "TOTP".to_string());

    // Fetch the raw TOTP seed so the prompter can regenerate codes on expiry.
    let seed: Option<zeroize::Zeroizing<String>> = secrets_proxy
        .call("GetSecretAttribute", &(&item_obj_path, "totp"))
        .await
        .ok()
        .map(|bytes: Vec<u8>| {
            zeroize::Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned())
        });

    let json = serde_json::json!({
        "title": format!("TOTP — {label}"),
        "totp_display": {
            "code": code,
            "remaining": remaining,
            "period": seed.as_deref()
                .and_then(|s| rosec_core::totp::parse_totp_input(s.as_bytes()).ok())
                .map(|p| p.period)
                .unwrap_or(30),
            "seed": seed.as_deref(),
        }
    });

    let mut cmd = std::process::Command::new(&prompt_bin);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to launch rosec-prompt: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(json.to_string().as_bytes());
    }

    let _ = child.wait();

    Ok(())
}
