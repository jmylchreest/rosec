//! Host-side file access for WASM guests.
//!
//! Some providers (notably `keepassxc-file`) need to read a single
//! user-configured file — the encrypted database.  WASI's pre-open mechanism
//! is directory-scoped, which would expose every sibling file in that
//! directory to the guest.  This module provides per-file scoping instead:
//!
//! - The host pre-canonicalises the configured paths.
//! - At request time, the host canonicalises the requested path and rejects
//!   anything not in the exact allow-list.
//! - Symlinks and `..` traversal can't escape because both sides go through
//!   `std::fs::canonicalize`.
//!
//! Two host functions are exposed (registered in `extism:host/user`, not the
//! `env` namespace, so they don't shadow built-ins):
//!
//! | Function     | Input (offset → string) | Output (offset → bytes) |
//! |--------------|-------------------------|-------------------------|
//! | `file_read`  | UTF-8 path              | raw file contents       |
//! | `file_stat`  | UTF-8 path              | JSON `{mtime_secs,size}`|

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use extism::{CurrentPlugin, Function, UserData, Val, ValType};
use serde::Serialize;

use crate::path_util::expand_tilde;

/// Namespace where the guest-side `#[host_fn] extern "ExtismHost"` import
/// declarations are looked up.  Matches the default used by `extism-pdk`
/// when no explicit namespace is given on the `extern` block.
pub(crate) const HOST_USER_MODULE: &str = "extism:host/user";

/// State shared by `file_read` and `file_stat` — the canonicalised allow-list.
///
/// `allowed` holds canonicalised paths.  Paths that fail canonicalisation
/// (e.g. the file doesn't exist yet at host startup) fall through to the
/// raw path as a best-effort match — `file_read` will still re-canonicalise
/// at call time.
struct FileState {
    allowed: HashSet<PathBuf>,
}

/// Build the file host functions.
///
/// `allowed_files` is the list of host paths the guest is allowed to read.
/// Empty list = no file access.
pub(crate) fn build_file_host_functions(allowed_files: &[PathBuf]) -> Vec<Function> {
    let allowed: HashSet<PathBuf> = allowed_files
        .iter()
        .map(|p| {
            let expanded = expand_tilde(p);
            std::fs::canonicalize(&expanded).unwrap_or(expanded)
        })
        .collect();

    let user_data: UserData<FileState> = UserData::new(FileState { allowed });

    vec![
        Function::new(
            "file_read",
            [ValType::I64],
            [ValType::I64],
            user_data.clone(),
            file_read_impl,
        )
        .with_namespace(HOST_USER_MODULE),
        Function::new(
            "file_stat",
            [ValType::I64],
            [ValType::I64],
            user_data,
            file_stat_impl,
        )
        .with_namespace(HOST_USER_MODULE),
    ]
}

fn lock_state(user_data: &UserData<FileState>) -> Result<Arc<Mutex<FileState>>, extism::Error> {
    user_data
        .get()
        .map_err(|e| extism::Error::msg(format!("file state error: {e}")))
}

/// Read a UTF-8 string from WASM memory at `offset`, then free the handle.
fn read_path_arg(data: &mut CurrentPlugin, offset: u64) -> Result<String, extism::Error> {
    let handle = data
        .memory_handle(offset)
        .ok_or_else(|| extism::Error::msg(format!("invalid memory offset: {offset}")))?;
    let bytes = data.memory_bytes(handle)?.to_vec();
    data.memory_free(handle)?;
    String::from_utf8(bytes).map_err(|e| extism::Error::msg(format!("path is not UTF-8: {e}")))
}

/// Allocate `bytes` in WASM memory and return its offset.
fn write_output_bytes(data: &mut CurrentPlugin, bytes: &[u8]) -> Result<u64, extism::Error> {
    let handle = data.memory_new(bytes)?;
    Ok(handle.offset())
}

/// Validate a path against the allow-list.  Expands a leading `~/` against
/// `$HOME`, then canonicalises so symlinks and `..` traversal can't escape.
fn check_allowed(state: &FileState, path: &Path) -> Result<PathBuf, extism::Error> {
    let expanded = expand_tilde(path);
    let canon = std::fs::canonicalize(&expanded).map_err(|e| {
        extism::Error::msg(format!(
            "file_read: cannot canonicalise '{}': {e}",
            path.display()
        ))
    })?;
    if !state.allowed.contains(&canon) {
        return Err(extism::Error::msg(format!(
            "file_read: '{}' is not in the allow-list",
            path.display()
        )));
    }
    Ok(canon)
}

/// `file_read(path: string) -> bytes`
fn file_read_impl(
    data: &mut CurrentPlugin,
    input: &[Val],
    output: &mut [Val],
    user_data: UserData<FileState>,
) -> Result<(), extism::Error> {
    let path_offset = input[0].unwrap_i64() as u64;
    let raw_path = read_path_arg(data, path_offset)?;

    let state_arc = lock_state(&user_data)?;
    let state = state_arc
        .lock()
        .map_err(|e| extism::Error::msg(format!("file state lock poisoned: {e}")))?;

    let canon = check_allowed(&state, Path::new(&raw_path))?;
    drop(state);

    let bytes = std::fs::read(&canon)
        .map_err(|e| extism::Error::msg(format!("file_read: '{}': {e}", canon.display())))?;

    let out = write_output_bytes(data, &bytes)?;
    output[0] = Val::I64(out as i64);
    Ok(())
}

#[derive(Serialize)]
struct StatResponse {
    /// Modification time, seconds since UNIX epoch.  0 if unavailable.
    mtime_secs: u64,
    /// File size in bytes.
    size: u64,
}

/// `file_stat(path: string) -> json` — returns `{mtime_secs, size}`.
fn file_stat_impl(
    data: &mut CurrentPlugin,
    input: &[Val],
    output: &mut [Val],
    user_data: UserData<FileState>,
) -> Result<(), extism::Error> {
    let path_offset = input[0].unwrap_i64() as u64;
    let raw_path = read_path_arg(data, path_offset)?;

    let state_arc = lock_state(&user_data)?;
    let state = state_arc
        .lock()
        .map_err(|e| extism::Error::msg(format!("file state lock poisoned: {e}")))?;

    let canon = check_allowed(&state, Path::new(&raw_path))?;
    drop(state);

    let meta = std::fs::metadata(&canon)
        .map_err(|e| extism::Error::msg(format!("file_stat: '{}': {e}", canon.display())))?;

    let mtime_secs = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let response = StatResponse {
        mtime_secs,
        size: meta.len(),
    };
    let json = serde_json::to_vec(&response)
        .map_err(|e| extism::Error::msg(format!("file_stat: serialize: {e}")))?;

    let out = write_output_bytes(data, &json)?;
    output[0] = Val::I64(out as i64);
    Ok(())
}
