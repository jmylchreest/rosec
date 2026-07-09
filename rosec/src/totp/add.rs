//! `rosec totp add <item>` — add a TOTP seed to an existing item or create a new one.

use std::collections::HashMap;

use anyhow::{Result, bail};

use crate::cli::TotpAddArgs;
use crate::{conn, resolve_item_path, trigger_unlock};

use super::{
    collect_totp_seed_prompt, collect_totp_seed_qr, has_display, resolve_prompt_binary_cli,
};

pub async fn run(args: TotpAddArgs) -> Result<()> {
    let conn = conn().await?;

    // Try to find the item. Use key=value search or hex ID to locate an
    // existing item. Plain names (no '=', not hex ID, not a path) are treated
    // as labels for a new item.
    let is_search = args.item.contains('=')
        || args.item.starts_with('/')
        || (args.item.len() == 16 && args.item.chars().all(|c| c.is_ascii_hexdigit()));
    let (path, is_new) = if is_search {
        match resolve_item_path(&conn, args.item.as_str()).await {
            Ok((path, is_locked)) => {
                if is_locked {
                    trigger_unlock(&conn).await?;
                }
                (path, false)
            }
            Err(e) => return Err(e),
        }
    } else {
        (String::new(), true)
    };

    let seed: zeroize::Zeroizing<String> = if args.qr {
        collect_totp_seed_qr()?
    } else {
        collect_totp_seed_prompt()?
    };

    if seed.is_empty() {
        bail!("no TOTP seed provided");
    }

    let params = rosec_core::totp::parse_totp_input(seed.as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid TOTP seed: {e}"))?;

    // Show the test code and ask for confirmation via the prompter.
    let now = std::time::SystemTime::now();
    let test_code = rosec_core::totp::generate_code(&params, now)
        .map_err(|e| anyhow::anyhow!("TOTP generation failed: {e}"))?;
    let remaining = rosec_core::totp::time_remaining_at(&params, now);
    if has_display() {
        let prompt_bin = resolve_prompt_binary_cli();
        let json = serde_json::json!({
            "title": "Confirm TOTP",
            "totp_display": {
                "code": &*test_code,
                "remaining": remaining,
                "period": params.period,
                "confirm": "Save",
            },
        });
        let mut cmd = std::process::Command::new(&prompt_bin);
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit());
        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to launch rosec-prompt: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(json.to_string().as_bytes());
        }
        let status = child.wait()?;
        if !status.success() {
            bail!("cancelled");
        }
    } else {
        eprintln!("Current code: {}", test_code.as_str());
        eprint!("Does this match? [y/N] ");
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf)?;
        if !buf.trim().eq_ignore_ascii_case("y") {
            bail!("cancelled");
        }
    }

    let items_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Items",
        "org.rosec.Items",
    )
    .await?;

    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();
    let seed_bytes = zeroize::Zeroizing::new(seed.as_bytes().to_vec());
    secrets.insert("totp".to_string(), seed_bytes.to_vec());

    if is_new {
        let label = args.item.as_str();
        let empty_attrs: HashMap<String, String> = HashMap::new();
        let item_path: String = items_proxy
            .call(
                "CreateItemExtended",
                &(label, "login", &empty_attrs, &secrets, false),
            )
            .await
            .map_err(|e| anyhow::anyhow!("CreateItemExtended failed: {e}"))?;
        let display_id = item_path.rsplit('/').next().unwrap_or(&item_path);
        eprintln!("Created item \"{label}\" with TOTP seed ({display_id})");
    } else {
        let empty_attrs: HashMap<String, String> = HashMap::new();
        let _: () = items_proxy
            .call(
                "UpdateItem",
                &(path.as_str(), "", "", &empty_attrs, &secrets),
            )
            .await
            .map_err(|e| anyhow::anyhow!("UpdateItem failed: {e}"))?;
        let display_id = path.rsplit('/').next().unwrap_or(&path);
        eprintln!("TOTP seed saved for item {display_id}");
    }
    Ok(())
}
