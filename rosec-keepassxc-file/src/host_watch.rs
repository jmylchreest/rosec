//! Guest-side bindings for the `host_watch` host imports.
//!
//! See `rosec-wasm/src/host_watch.rs` for the host implementation.

use extism_pdk::*;

#[host_fn]
unsafe extern "ExtismHost" {
    fn register_watch(path: String);
}

/// Ask the host to call `on_path_changed` whenever `path` is modified on
/// disk.  The path must already be in the host's `host_file` allow-list.
///
/// Idempotent — calling twice for the same path is a no-op host-side.
pub fn watch(path: &str) -> Result<(), Error> {
    unsafe { register_watch(path.to_string()) }
}
