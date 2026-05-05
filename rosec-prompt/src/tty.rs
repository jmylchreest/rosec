//! TTY mode — used when no Wayland/X compositor is reachable.

use std::collections::HashMap;
use std::io;

use anyhow::Result;
use zeroize::Zeroizing;

use crate::output::{emit_empty_and_exit, emit_secret_json};
use crate::request::{FieldKind, PromptRequest};

/// Collect credentials from a TTY using rpassword (hidden) or plain readline (text).
///
/// In confirm mode (zero fields), prints the title/message and asks for y/N
/// confirmation.  Exit 0 = confirmed, exit 1 = cancelled.
///
/// In TOTP display mode, prints the code and expiry to stderr, emits `{}`
/// to stdout, and exits immediately (no clipboard in TTY mode).
pub(crate) fn run(request: PromptRequest) -> Result<()> {
    if request.qr_scan {
        eprintln!("QR scanning requires a display server");
        std::process::exit(1);
    }

    if let Some(totp) = &request.totp_display {
        if !request.title.is_empty() {
            eprintln!("{}", request.title);
        }
        eprintln!("{}", totp.code);
        eprintln!("Expires in {}s", totp.remaining);
        emit_empty_and_exit();
    }

    let fields = request.effective_fields();

    if !request.title.is_empty() {
        eprintln!("{}", request.title);
    }
    if !request.message.is_empty() {
        eprintln!("{}", request.message);
    }
    if !request.hint.is_empty() {
        eprintln!("({})", request.hint);
    }
    eprintln!();

    if fields.is_empty() {
        let confirm_label = if request.confirm_label.is_empty() {
            "OK"
        } else {
            &request.confirm_label
        };
        let cancel_label = if request.cancel_label.is_empty() {
            "Cancel"
        } else {
            &request.cancel_label
        };
        eprint!("{confirm_label} / {cancel_label} [y/N]: ");
        let mut buf = String::new();
        io::stdin()
            .read_line(&mut buf)
            .map_err(|e| anyhow::anyhow!("failed to read confirmation: {e}"))?;
        let answer = buf.trim().to_lowercase();
        if answer == "y" || answer == "yes" {
            emit_empty_and_exit();
        }
        std::process::exit(1);
    }

    let mut values: HashMap<String, Zeroizing<String>> = HashMap::new();

    for field in &fields {
        let label = if field.label.is_empty() {
            field.id.as_str()
        } else {
            field.label.as_str()
        };
        let value: Zeroizing<String> = match field.kind {
            FieldKind::Password | FieldKind::Secret => {
                let prompt = format!("{label}: ");
                Zeroizing::new(
                    rpassword::prompt_password(&prompt)
                        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", field.id))?,
                )
            }
            FieldKind::Text => {
                eprint!("{label}: ");
                let mut buf = String::new();
                io::stdin()
                    .read_line(&mut buf)
                    .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", field.id))?;
                Zeroizing::new(buf.trim_end_matches(['\n', '\r']).to_string())
            }
        };
        values.insert(field.id.clone(), value);
    }

    // Borrow as &str so the JSON shares the Zeroizing buffers — no plaintext copy.
    let out: HashMap<&str, &str> = values
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    emit_secret_json(&out)?;
    Ok(())
}
