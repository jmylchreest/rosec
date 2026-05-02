//! Host-side filesystem-event subscription for WASM guests.
//!
//! Some providers — `keepassxc-file` in particular — read a single
//! user-configured file on the host.  When that file changes (e.g. KeePassXC
//! saves a new entry) the guest needs to invalidate its in-memory cache and
//! re-decrypt.  Without a host-side watcher the guest has to poll on every
//! `sync()` call, which defers the change until the next external sync
//! trigger.
//!
//! This module exposes one host import to guests:
//!
//! | Function          | Input (offset → string) | Output |
//! |-------------------|-------------------------|--------|
//! | `register_watch`  | UTF-8 path              | empty  |
//!
//! Registration is gated by the same canonicalised allow-list used by
//! `host_file` — guests cannot watch paths they couldn't already read.
//! Each registration adds the path to a `notify::RecommendedWatcher`; the
//! resulting events are forwarded over an mpsc channel to a dispatcher task
//! the host owns (see `WasmProvider::new`), which then calls the guest's
//! `on_path_changed` export with `{ path, kind }` JSON.
//!
//! Events are debounced in the dispatcher (not here), so a single save that
//! triggers `Modify` + `Create` + `Chmod` collapses to one guest call.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use extism::{CurrentPlugin, Function, UserData, Val, ValType};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::host_file::HOST_USER_MODULE;
use crate::path_util::expand_tilde;

/// A filesystem event delivered to the guest's `on_path_changed` export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchEvent {
    /// The watched path the event fired on.  Always one of the paths the
    /// guest passed to `register_watch` (canonicalised).
    pub path: String,
    /// One of: `"modify"`, `"create"`, `"remove"`, `"rename"`, `"other"`.
    pub kind: String,
}

/// Shared state between the `register_watch` host function and the watcher.
struct WatchState {
    /// Canonicalised paths the guest is allowed to watch (== the host_file
    /// allow-list).  We don't share `host_file::FileState` directly because
    /// it's a different `UserData` and Extism keeps them isolated.
    allowed: HashSet<PathBuf>,
    /// Paths the guest has actually subscribed to.
    watched: HashSet<PathBuf>,
    /// The recommendation: one watcher per provider.  `None` if no
    /// `register_watch` call has happened yet (so we don't pay the cost
    /// of spawning the inotify thread for providers that don't use it).
    watcher: Option<RecommendedWatcher>,
    /// Where to deliver events.  The receiver lives in `WasmProvider`'s
    /// dispatcher task.
    tx: mpsc::UnboundedSender<WatchEvent>,
}

/// Build the watch host functions and return them alongside the receiver
/// half of the event channel.  The caller (`WasmProvider::new`) spawns a
/// task that drains the receiver and dispatches into the guest.
///
/// `allowed_files` is the same canonicalised allow-list used by
/// `host_file::build_file_host_functions`.
pub(crate) fn build_watch_host_functions(
    allowed_files: &[PathBuf],
) -> (Vec<Function>, mpsc::UnboundedReceiver<WatchEvent>) {
    let allowed: HashSet<PathBuf> = allowed_files
        .iter()
        .map(|p| {
            let expanded = expand_tilde(p);
            std::fs::canonicalize(&expanded).unwrap_or(expanded)
        })
        .collect();

    let (tx, rx) = mpsc::unbounded_channel();

    let user_data: UserData<WatchState> = UserData::new(WatchState {
        allowed,
        watched: HashSet::new(),
        watcher: None,
        tx,
    });

    let fns = vec![
        Function::new(
            "register_watch",
            [ValType::I64],
            [],
            user_data,
            register_watch_impl,
        )
        .with_namespace(HOST_USER_MODULE),
    ];

    (fns, rx)
}

fn lock_state(user_data: &UserData<WatchState>) -> Result<Arc<Mutex<WatchState>>, extism::Error> {
    user_data
        .get()
        .map_err(|e| extism::Error::msg(format!("watch state error: {e}")))
}

fn read_path_arg(data: &mut CurrentPlugin, offset: u64) -> Result<String, extism::Error> {
    let handle = data
        .memory_handle(offset)
        .ok_or_else(|| extism::Error::msg(format!("invalid memory offset: {offset}")))?;
    let bytes = data.memory_bytes(handle)?.to_vec();
    data.memory_free(handle)?;
    String::from_utf8(bytes).map_err(|e| extism::Error::msg(format!("path is not UTF-8: {e}")))
}

/// `register_watch(path: string)` — guest tells the host "notify me when this
/// file changes".  The path must be in the allow-list.  Subsequent calls
/// for the same path are no-ops.
fn register_watch_impl(
    data: &mut CurrentPlugin,
    input: &[Val],
    _output: &mut [Val],
    user_data: UserData<WatchState>,
) -> Result<(), extism::Error> {
    let raw_path = read_path_arg(data, input[0].unwrap_i64() as u64)?;
    let expanded = expand_tilde(Path::new(&raw_path));
    let canon = std::fs::canonicalize(&expanded).map_err(|e| {
        extism::Error::msg(format!(
            "register_watch: cannot canonicalise '{raw_path}': {e}"
        ))
    })?;

    let state_arc = lock_state(&user_data)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| extism::Error::msg(format!("watch state lock poisoned: {e}")))?;

    if !state.allowed.contains(&canon) {
        return Err(extism::Error::msg(format!(
            "register_watch: '{raw_path}' is not in the host_file allow-list"
        )));
    }
    if state.watched.contains(&canon) {
        return Ok(());
    }

    // Lazily spawn the watcher on first use.
    if state.watcher.is_none() {
        let tx = state.tx.clone();
        let watcher_result = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                let evt = match res {
                    Ok(e) => e,
                    Err(err) => {
                        debug!(error = %err, "host_watch: notify error");
                        return;
                    }
                };
                let kind_str = match evt.kind {
                    EventKind::Modify(_) => "modify",
                    EventKind::Create(_) => "create",
                    EventKind::Remove(_) => "remove",
                    EventKind::Access(_) => return, // noisy, ignore reads
                    EventKind::Other => "other",
                    EventKind::Any => "other",
                };
                for path in evt.paths {
                    let payload = WatchEvent {
                        path: path.to_string_lossy().into_owned(),
                        kind: kind_str.to_string(),
                    };
                    debug!(path = %payload.path, kind = %payload.kind, "host_watch: event");
                    if tx.send(payload).is_err() {
                        break;
                    }
                }
            },
            notify::Config::default(),
        );
        match watcher_result {
            Ok(w) => state.watcher = Some(w),
            Err(e) => {
                return Err(extism::Error::msg(format!(
                    "register_watch: failed to create watcher: {e}"
                )));
            }
        }
    }

    let watcher = state.watcher.as_mut().expect("just assigned above");
    if let Err(e) = watcher.watch(&canon, RecursiveMode::NonRecursive) {
        warn!(path = %canon.display(), error = %e, "host_watch: failed to watch path");
        return Err(extism::Error::msg(format!(
            "register_watch: watch '{}' failed: {e}",
            canon.display()
        )));
    }
    state.watched.insert(canon.clone());
    debug!(path = %canon.display(), "host_watch: registered");
    Ok(())
}
