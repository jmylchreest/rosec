//! Resolution of the prompt subprocess environment.
//!
//! This module owns the logic for deciding **how** the daemon will collect a
//! password from the user (which binary to spawn, whether a display server
//! is reachable, whether `/dev/tty` is available, and which environment
//! variables to propagate to the child).  It does **not** spawn the prompt
//! itself — that responsibility still lives in
//! [`crate::state::ServiceState::spawn_prompt`].
//!
//! Extracted from `state.rs` as the first step of an incremental
//! decomposition: keep `state.rs` as the orchestrator, push leaf logic
//! (env discovery, JSON building, child-process I/O) into focused modules
//! that can be unit-tested without standing up a full `ServiceState`.

use crate::prompt_manager::PromptManager;
use rosec_core::config::PromptConfig;

/// Resolved prompt environment: config snapshot, binary path, display state.
#[derive(Debug, Clone)]
pub struct PromptEnv {
    pub cfg: PromptConfig,
    pub program: String,
    pub has_display: bool,
    pub has_tty: bool,
    /// Display environment variables discovered from the systemd user manager
    /// when they are absent from the daemon's own process environment.
    /// Must be injected into child processes that need a display server.
    pub display_env: Vec<(String, String)>,
}

/// Resolve `rosec-prompt` next to the daemon binary. Returns `None` if no
/// sibling exists; the daemon refuses to fall back to a `$PATH` lookup
/// because `$PATH` can be attacker-influenced at spawn time.
fn resolve_prompt_binary() -> Option<String> {
    rosec_core::prompt::resolve_sibling_binary("rosec-prompt")
        .map(|p| p.to_string_lossy().into_owned())
}

/// Discover `WAYLAND_DISPLAY` / `DISPLAY` from the systemd user manager's
/// environment via the session D-Bus bus.
///
/// The compositor (sway, Hyprland, GNOME Shell, …) typically calls
/// `systemctl --user import-environment WAYLAND_DISPLAY DISPLAY` during
/// startup.  When rosecd is D-Bus-activated before those vars are in its
/// own process environment, this function retrieves them so they can be
/// injected into child processes (e.g. `rosec-prompt`).
///
/// Returns an empty vec on any error (not on the session bus, systemd not
/// reachable, vars not present).  This is intentionally best-effort.
fn discover_display_env_from_systemd(
    handle: &tokio::runtime::Handle,
    conn: &zbus::Connection,
) -> Vec<(String, String)> {
    /// Display-related variable names to look for.
    const DISPLAY_VARS: &[&str] = &["WAYLAND_DISPLAY", "DISPLAY"];

    let conn = conn.clone();
    let result = handle.block_on(async {
        let reply = conn
            .call_method(
                Some("org.freedesktop.systemd1"),
                "/org/freedesktop/systemd1",
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.freedesktop.systemd1.Manager", "Environment"),
            )
            .await?;
        // The reply body is a VARIANT wrapping an array of strings (as).
        let body = reply.body();
        let variant: zbus::zvariant::OwnedValue = body.deserialize()?;
        let env_strings: Vec<String> = variant.try_into().unwrap_or_default();
        Ok::<Vec<String>, zbus::Error>(env_strings)
    });

    let env_strings = match result {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("failed to query systemd user manager environment: {e}");
            return Vec::new();
        }
    };

    env_strings
        .iter()
        .filter_map(|entry| {
            let (key, value) = entry.split_once('=')?;
            if DISPLAY_VARS.contains(&key) {
                Some((key.to_string(), value.to_string()))
            } else {
                None
            }
        })
        .collect()
}

/// Resolve the prompt subprocess environment for the current request.
///
/// Reads the live prompt config, picks the prompt binary (sibling of the
/// daemon, or whatever the operator configured), and probes for a usable
/// display/TTY.  Falls back to systemd-user-manager environment lookup
/// when the daemon's own process env lacks `WAYLAND_DISPLAY` /
/// `DISPLAY` (common when rosecd is D-Bus-activated before the
/// compositor imports those vars).
pub fn resolve_prompt_env(
    prompts: &PromptManager,
    tokio_handle: &tokio::runtime::Handle,
    conn: &zbus::Connection,
) -> PromptEnv {
    let cfg = prompts.config();
    let (program, builtin_missing) = match cfg.backend.as_str() {
        "builtin" | "" => match resolve_prompt_binary() {
            Some(p) => (p, false),
            None => {
                tracing::error!(
                    "rosec-prompt not found alongside daemon binary; \
                     refusing $PATH fallback. Prompt-based unlock is unavailable."
                );
                (String::new(), true)
            }
        },
        custom => (custom.to_string(), false),
    };

    let mut has_display =
        std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();

    // If the daemon's own environment lacks display vars (e.g. started by
    // systemd before the compositor imported them), try to discover them
    // from the systemd user manager's environment over D-Bus.
    //
    // Log at info the first time we fail to find display vars (so the
    // admin sees it at startup), but only at debug on subsequent calls
    // (to avoid spamming when clients repeatedly trigger prompts).
    static LOGGED_NO_DISPLAY: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    let mut display_env: Vec<(String, String)> = Vec::new();
    if !has_display {
        display_env = discover_display_env_from_systemd(tokio_handle, conn);
        if !display_env.is_empty() {
            tracing::debug!(
                vars = ?display_env,
                "discovered display environment from systemd user manager"
            );
            has_display = true;
        } else if !LOGGED_NO_DISPLAY.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::info!(
                "no display environment found (process env or systemd user manager) — \
                 GUI prompts will not be available until a compositor imports \
                 WAYLAND_DISPLAY or DISPLAY"
            );
        }
    }

    // Actually try to open /dev/tty — the path exists even inside
    // systemd services, but open() fails with ENXIO when there is no
    // controlling terminal.
    let has_tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok();
    let (has_display, has_tty) = if builtin_missing {
        (false, false)
    } else {
        (has_display, has_tty)
    };
    PromptEnv {
        cfg,
        program,
        has_display,
        has_tty,
        display_env,
    }
}
