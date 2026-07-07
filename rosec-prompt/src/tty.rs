//! TTY mode — used when no Wayland/X compositor is reachable.

use std::collections::HashMap;
use std::io;

use anyhow::Result;
use zeroize::Zeroizing;

use crate::output::{emit_empty_and_exit, emit_secret_json};
use crate::request::{FieldKind, PromptRequest, SelectRequest};

/// Numbered-menu fallback for selection prompts when no display server is
/// reachable. Prints the options, reads a 1-based index, and emits
/// `{"selected": "<id>"}`. Empty input or `q` cancels (exit 1).
fn run_select(request: &PromptRequest, select: &SelectRequest) -> Result<()> {
    use std::collections::HashMap;

    if select.options.is_empty() {
        return Err(anyhow::anyhow!("select request has no options"));
    }

    if !request.title.is_empty() {
        eprintln!("{}", request.title);
    }
    if !request.message.is_empty() {
        eprintln!("{}", request.message);
    }
    eprintln!();
    for (i, opt) in select.options.iter().enumerate() {
        if opt.secondary.is_empty() {
            eprintln!("  {}) {}", i + 1, opt.primary);
        } else {
            eprintln!("  {}) {}  ({})", i + 1, opt.primary, opt.secondary);
        }
    }
    eprintln!();

    // The request occupies stdin (main reads it to EOF), so read the choice
    // from the controlling terminal directly — the same reason password
    // fields go through rpassword rather than stdin.
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| anyhow::anyhow!("selection prompt needs a terminal: {e}"))?;

    loop {
        {
            use std::io::Write as _;
            write!(tty, "Select [1-{}, q to cancel]: ", select.options.len())?;
            tty.flush()?;
        }
        let mut buf = String::new();
        {
            use std::io::{BufRead as _, BufReader};
            BufReader::new(&tty)
                .read_line(&mut buf)
                .map_err(|e| anyhow::anyhow!("failed to read selection: {e}"))?;
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("q") {
            std::process::exit(1);
        }
        match trimmed.parse::<usize>() {
            Ok(n) if n >= 1 && n <= select.options.len() => {
                let id = select.options[n - 1].id.as_str();
                let out: HashMap<&str, &str> = HashMap::from([("selected", id)]);
                emit_secret_json(&out)?;
                return Ok(());
            }
            _ => eprintln!("Invalid selection."),
        }
    }
}

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

    if let Some(select) = &request.select {
        return run_select(&request, select);
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
