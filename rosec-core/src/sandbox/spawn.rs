//! Helpers for the daemon to propagate sandbox decisions into spawned
//! subprocesses (rosec-prompt, the screenshot helper, etc.) via env vars.
//!
//! The daemon reads its `[sandbox]` config at startup; subprocess Landlock
//! is short-lived and reads its inputs from env vars so we don't have to
//! teach every spawned binary how to find and parse the daemon config.

use crate::config::SandboxConfig;
use crate::sandbox::landlock::{ENV_DISABLE, ENV_EXTRA_RO_PATHS};

/// Env pairs the daemon should set on every spawned subprocess to
/// propagate its sandbox decisions. Empty when the config matches the
/// (default) "Landlock on, no extra paths" shape.
///
/// Callers iterate the returned slice and call `cmd.env(k, v)` on
/// whatever Command type they have (std or tokio).
pub fn sandbox_env_for_subprocess(cfg: &SandboxConfig) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if !cfg.landlock_enabled {
        out.push((ENV_DISABLE, "1".to_string()));
    }
    if !cfg.extra_ro_paths.is_empty() {
        out.push((ENV_EXTRA_RO_PATHS, cfg.extra_ro_paths.join(":")));
    }
    out
}
