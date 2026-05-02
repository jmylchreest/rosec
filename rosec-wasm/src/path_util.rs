//! Path helpers shared by host imports.
//!
//! Currently just `expand_tilde` — used by `host_file::check_allowed`,
//! `host_file::build_file_host_functions`, and `host_watch::register_watch_impl`.
//! Lifted into a single module so the three call sites can't drift.

use std::path::{Path, PathBuf};

/// Expand a leading `~/` against `$HOME`.  Other paths pass through unchanged.
///
/// Mirrors the daemon-side `expand_tilde_in_value` in `rosecd/src/main.rs`,
/// but operates on `Path` rather than `serde_json::Value`.  Both layers run
/// the expansion: the daemon canonicalises config paths once at provider
/// construction, and these host imports re-expand at call time as a
/// defence-in-depth check before canonicalisation.
pub(crate) fn expand_tilde(path: &Path) -> PathBuf {
    let s = match path.to_str() {
        Some(s) => s,
        None => return path.to_path_buf(),
    };
    if let Some(rest) = s.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        let mut p = PathBuf::from(home);
        p.push(rest);
        return p;
    }
    path.to_path_buf()
}
