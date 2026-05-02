//! Guest-side bindings for the `host_file` host imports.
//!
//! These wrap the raw `extism_pdk::host_fn!` declarations in safe Rust
//! helpers.  See `rosec-wasm/src/host_file.rs` for the host implementation
//! and security model.

use extism_pdk::*;
use serde::Deserialize;

#[host_fn]
unsafe extern "ExtismHost" {
    fn file_read(path: String) -> Vec<u8>;
    fn file_stat(path: String) -> Json<StatResponse>;
}

#[derive(Debug, Deserialize)]
pub struct StatResponse {
    /// Modification time, seconds since UNIX epoch.  0 if unavailable.
    pub mtime_secs: u64,
    /// File size in bytes.
    #[allow(dead_code)]
    pub size: u64,
}

/// Read the entire contents of a host-side file.
///
/// The path must be in the host's `allowed_files` list (configured by the
/// daemon based on the provider's `path` option).  Returns an error from the
/// host if the path isn't allowed or the read fails.
pub fn read(path: &str) -> Result<Vec<u8>, Error> {
    unsafe { file_read(path.to_string()) }
}

/// Stat a host-side file — returns modification time and size.
pub fn stat(path: &str) -> Result<StatResponse, Error> {
    let Json(resp) = unsafe { file_stat(path.to_string())? };
    Ok(resp)
}
