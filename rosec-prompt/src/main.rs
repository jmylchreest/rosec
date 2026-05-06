//! rosec-prompt — credential prompt subprocess.
//!
//! # Protocol
//!
//! **stdin**: a single JSON object:
//! ```json
//! {
//!   "t": "Unlock provider",
//!   "m": "Enter credentials",
//!   "h": "Backend: my-vault",
//!   "backend": "my-vault",
//!   "fields": [
//!     {"id": "password", "label": "Master Password", "kind": "password", "placeholder": "…"},
//!     {"id": "email",    "label": "Email",           "kind": "text",     "placeholder": "…"}
//!   ],
//!   "info": "Requested by **firefox** (PID 1234)",
//!   "theme": { … }
//! }
//! ```
//! `fields` is optional — if absent a single hidden `password` field is implied.
//!
//! ## Rich text
//!
//! The `info`, `message`, and `hint` fields support inline markup:
//! `**bold**` and `_italic_` (word-boundary delimited).
//!
//! ## Confirmation mode
//!
//! Set `"confirm_mode": true` for a zero-field confirmation dialog.  Stdout is
//! `{}` on confirmation.
//!
//! **stdout**: a single JSON object mapping field IDs to values:
//! ```json
//! {"password": "hunter2"}
//! ```
//!
//! **Exit codes**: 0 = confirmed, 1 = cancelled, 2 = bad input.
//!
//! # Display mode
//!
//! If `WAYLAND_DISPLAY` or `DISPLAY` is set, the iced Wayland GUI is used.
//! Otherwise (SSH session, TTY, headless) credentials are collected via
//! `rpassword` (hidden) or plain readline (visible text).

mod gui;
mod helpers;
mod output;
mod request;
mod tty;

use std::io::{self, Read};

use anyhow::Result;

use crate::request::PromptRequest;

fn main() -> Result<()> {
    // Detect the screenshot-helper subprocess BEFORE harden(): xdg-desktop-portal
    // needs to read /proc/<our-pid>/root for sandbox identification, and
    // PR_SET_DUMPABLE=0 re-owns that to root. The helper applies its own staged
    // hardening around the portal call.
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() == 2 && args[1] == "--screenshot-helper" {
            gui::run_screenshot_helper();
        }
    }

    rosec_core::sandbox::harden();

    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!(
            "rosec-prompt {} ({})",
            env!("ROSEC_VERSION"),
            env!("ROSEC_GIT_SHA")
        );
        return Ok(());
    }

    tracing_subscriber::fmt().with_env_filter("warn").init();

    use rosec_core::limits::MAX_PROMPT_REQUEST_BYTES;
    let mut raw = String::new();
    io::stdin()
        .lock()
        .take(MAX_PROMPT_REQUEST_BYTES + 1)
        .read_to_string(&mut raw)?;
    if raw.len() as u64 > MAX_PROMPT_REQUEST_BYTES {
        eprintln!("prompt request exceeds {MAX_PROMPT_REQUEST_BYTES} bytes");
        std::process::exit(2);
    }

    let request: PromptRequest = if raw.trim().is_empty() {
        PromptRequest {
            title: "Unlock provider".to_string(),
            message: "Enter your credentials".to_string(),
            ..Default::default()
        }
    } else {
        match serde_json::from_str(&raw) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("invalid prompt request: {e}");
                std::process::exit(2);
            }
        }
    };

    let has_display =
        std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();

    if has_display {
        gui::run(request)
    } else {
        tty::run(request)
    }
}
