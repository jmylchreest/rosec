//! `rosec totp` subcommand group.
//!
//! Each subcommand has its own module — the dispatcher matches on
//! [`TotpCommand`] and delegates.

use std::collections::HashMap;

use anyhow::{Result, bail};

use crate::cli::{TotpCommand, TotpGetArgs, TotpSubcommands};

pub mod add;
pub mod get;

pub async fn dispatch(cmd: TotpCommand) -> Result<()> {
    match cmd.action {
        Some(TotpSubcommands::Get(args)) => get::run(args).await,
        Some(TotpSubcommands::Add(args)) => add::run(args).await,
        None => {
            // Default: treat trailing args as `totp get <item>`
            let mut sync = false;
            let mut no_unlock = false;
            let mut stdout = false;
            let mut item = None;
            for arg in &cmd.default_args {
                match arg.as_str() {
                    "-s" | "--sync" => sync = true,
                    "--no-unlock" => no_unlock = true,
                    "--stdout" => stdout = true,
                    other => {
                        if item.is_none() {
                            item = Some(other.to_string());
                        }
                    }
                }
            }
            let item = item.ok_or_else(|| anyhow::anyhow!("missing item identifier"))?;
            get::run(TotpGetArgs {
                sync,
                no_unlock,
                stdout,
                item,
            })
            .await
        }
    }
}
// Shared helpers (display detection, prompter binary resolution, seed input)
pub(super) fn has_display() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some()
}

/// Resolve the `rosec-prompt` binary: sibling of this executable, or PATH.
pub(super) fn resolve_prompt_binary_cli() -> String {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("rosec-prompt");
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    "rosec-prompt".to_string()
}

/// Collect a TOTP seed via the prompter (hidden input).
pub(super) fn collect_totp_seed_prompt() -> Result<zeroize::Zeroizing<String>> {
    let prompt_bin = resolve_prompt_binary_cli();
    let display = has_display();

    let json = serde_json::json!({
        "title": "Add TOTP",
        "message": "Enter the TOTP seed or otpauth:// URI",
        "fields": [{
            "id": "seed",
            "label": "TOTP seed",
            "kind": "secret",
            "placeholder": "otpauth://totp/... or base32 secret"
        }],
        "confirm_label": "Add",
    });

    if display {
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

        let output = child.wait_with_output()?;
        if !output.status.success() {
            bail!("cancelled");
        }
        let mut response: HashMap<String, String> = serde_json::from_slice(&output.stdout)?;
        let seed = response
            .remove("seed")
            .ok_or_else(|| anyhow::anyhow!("no seed in response"))?;
        for v in response.values_mut() {
            zeroize::Zeroize::zeroize(v);
        }
        Ok(zeroize::Zeroizing::new(seed))
    } else {
        // TTY fallback: use rpassword for hidden input.
        eprint!("TOTP seed or otpauth:// URI: ");
        let seed = rpassword::read_password()?;
        Ok(zeroize::Zeroizing::new(seed))
    }
}

/// Collect a TOTP seed via QR scanner overlay.
pub(super) fn collect_totp_seed_qr() -> Result<zeroize::Zeroizing<String>> {
    let prompt_bin = resolve_prompt_binary_cli();

    if !has_display() {
        bail!("--qr requires a display server (WAYLAND_DISPLAY or DISPLAY)");
    }

    let json = serde_json::json!({
        "title": "Scan TOTP QR Code",
        "qr_scan": true,
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

    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!("QR scan cancelled");
    }
    let mut response: HashMap<String, String> = serde_json::from_slice(&output.stdout)?;
    let uri = response
        .remove("otpauth_uri")
        .ok_or_else(|| anyhow::anyhow!("no otpauth URI from QR scanner"))?;
    for v in response.values_mut() {
        zeroize::Zeroize::zeroize(v);
    }
    Ok(zeroize::Zeroizing::new(uri))
}
