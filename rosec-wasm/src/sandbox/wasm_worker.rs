//! Specialised actor for owning an extism `Plugin` on a dedicated thread.
//!
//! Differs from the generic `Worker<R>` in two ways: it multiplexes
//! filesystem watch events alongside async caller requests on the same
//! thread (avoiding a separate dispatcher with its own Plugin lock), and
//! it handles wasmtime trap recovery transparently — the caller sees the
//! ordinary `Err` from the failed call but the next request lands on a
//! freshly-rebuilt Plugin instance.
//!
//! This is also the natural site to apply per-provider Landlock: the
//! `restrict_self()` syscall affects only the calling thread, so applying
//! it once at worker-thread start gives a kernel-enforced sandbox around
//! every guest call without disturbing the rest of the daemon.

use std::panic::AssertUnwindSafe;
use std::thread;
use std::time::Duration;

use anyhow::anyhow;
use crossbeam_channel as cb;
use extism::{Manifest, Plugin, Wasm};
use rosec_core::ProviderError;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

use crate::host_watch::WatchEvent;
use crate::protocol::ReadinessProbe;
use crate::provider::{
    CallOutcome, GUEST_CALL_TIMEOUT, call_guest_json, call_guest_json_no_input, init_guest,
    query_attribute_descriptors, query_auth_fields, query_capabilities, query_readiness_probes,
    query_registration_info,
};

/// Host-side ceiling on how long any caller will wait for a wasm worker
/// to reply.  Tighter than extism's [`GUEST_CALL_TIMEOUT`] (180s) so the
/// host releases the await well before extism's trap, freeing downstream
/// rebuilds / searches for other providers.
const HOST_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Capacity of the call-request channel between async callers and the
/// worker thread. Per-provider activity is sequential (one user, one
/// vault) so 16 in-flight is plenty; the bound prevents a misbehaving
/// caller from queueing unbounded work.
const CALL_CHANNEL_CAPACITY: usize = 16;

/// Quiet window inside which contiguous watch events for the same path
/// collapse into a single `on_path_changed` dispatch. A typical editor save
/// fires 3-5 inotify events within tens of ms; we want one guest call.
const WATCH_DEBOUNCE: Duration = Duration::from_millis(500);

/// A boxed unit of work the worker executes against `&mut Plugin`.
/// The `&mut bool` is the closure's signal back to the worker that the
/// Plugin needs recreation after this call (set when a wasmtime trap
/// corrupts the instance). The worker rebuilds the Plugin between
/// requests; subsequent calls land on a fresh instance.
type CallFn = Box<dyn FnOnce(&mut Plugin, &mut bool) + Send + 'static>;

/// One-time outputs the worker emits after init: the eagerly-queried
/// guest metadata plus a flag indicating whether `on_path_changed` is
/// available. The async caller (WasmProvider::new) waits for these on
/// the init oneshot before returning to its caller.
pub(crate) struct WasmInitOutputs {
    pub capabilities: &'static [rosec_core::Capability],
    pub attribute_descriptors: &'static [rosec_core::AttributeDescriptor],
    pub auth_fields: &'static [rosec_core::AuthField],
    pub registration_info: Option<rosec_core::RegistrationInfo>,
    pub readiness_probes: Vec<ReadinessProbe>,
}

pub(crate) struct WasmWorker {
    tx: cb::Sender<CallFn>,
    label: String,
    /// Held so callers can identify the thread in panics / debuggers.
    /// Not joined on Drop because pending guest calls (e.g. an in-flight
    /// 60-second Argon2 unlock) could pin shutdown.
    _handle: thread::JoinHandle<()>,
}

impl WasmWorker {
    /// Spawn a dedicated worker thread, build the Plugin under its
    /// Landlock domain (when enabled), eagerly query metadata, and return
    /// the worker handle alongside those metadata outputs.
    ///
    /// Blocks until the worker reports init completion (success or failure)
    /// via an internal oneshot — the caller (WasmProvider::new) is therefore
    /// guaranteed that any subsequent `call()` lands on a live Plugin.
    pub(crate) fn spawn(
        config: crate::WasmProviderConfig,
    ) -> Result<(Self, WasmInitOutputs), ProviderError> {
        let (call_tx, call_rx) = cb::bounded::<CallFn>(CALL_CHANNEL_CAPACITY);
        let (init_tx, init_rx) =
            std::sync::mpsc::sync_channel::<Result<WasmInitOutputs, String>>(0);
        let label = format!("wasm-{}", config.id);
        let label_for_thread = label.clone();
        let config_for_thread = config.clone();

        let handle = thread::Builder::new()
            .name(label.clone())
            .spawn(move || {
                worker_thread_main(config_for_thread, call_rx, init_tx, label_for_thread)
            })
            .map_err(|e| {
                ProviderError::Other(anyhow!("failed to spawn wasm worker thread: {e}"))
            })?;

        match init_rx.recv() {
            Ok(Ok(outputs)) => Ok((
                Self {
                    tx: call_tx,
                    label,
                    _handle: handle,
                },
                outputs,
            )),
            Ok(Err(msg)) => Err(ProviderError::Other(anyhow!(
                "wasm worker '{label}' init failed: {msg}"
            ))),
            Err(_) => Err(ProviderError::Other(anyhow!(
                "wasm worker '{label}' panicked during init"
            ))),
        }
    }

    /// Dispatch a closure to the worker thread; await its result.
    ///
    /// The closure runs with exclusive `&mut Plugin` on the worker's
    /// dedicated thread, returning a tuple of `(result, CallOutcome)`. The
    /// outcome tells the worker whether a wasmtime trap occurred — on
    /// `PluginCallFailed` the worker rebuilds the Plugin between requests
    /// so subsequent calls land on a fresh instance.
    ///
    /// Long-running guest work (Argon2, network calls) no longer pins a
    /// tokio worker — the daemon's runtime stays responsive.
    pub(crate) async fn call<T, F>(&self, f: F) -> Result<T, ProviderError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Plugin) -> (Result<T, ProviderError>, CallOutcome) + Send + 'static,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(Box::new(move |plugin, needs_recreate| {
                let (result, outcome) = f(plugin);
                if outcome == CallOutcome::PluginCallFailed {
                    *needs_recreate = true;
                }
                let _ = reply_tx.send(result);
            }))
            .map_err(|_| {
                ProviderError::Unavailable(format!("wasm worker '{}' has stopped", self.label))
            })?;
        // Host-side ceiling: bounds how long any caller waits for the worker
        // to reply, independent of extism's in-guest timeout (which only
        // covers wasm execution, not host functions like network I/O).  If
        // this fires the worker thread keeps running its call until either
        // it finishes or extism's `GUEST_CALL_TIMEOUT` cuts it short, but
        // the caller stops blocking and downstream code (cache rebuild,
        // SearchItems) keeps going for the other providers.
        let awaited = tokio::time::timeout(HOST_CALL_TIMEOUT, reply_rx).await;
        match awaited {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ProviderError::Unavailable(format!(
                "wasm worker '{}' dropped reply (panic during call)",
                self.label
            ))),
            Err(_) => Err(ProviderError::Unavailable(format!(
                "wasm worker '{}' did not reply within {}s",
                self.label,
                HOST_CALL_TIMEOUT.as_secs()
            ))),
        }
    }

    /// Convenience wrapper around [`Self::call`] for the canonical pattern:
    /// serialize JSON input, dispatch via `plugin.call`, deserialize JSON
    /// output. Used by most Provider trait methods.
    pub(crate) async fn call_json<I, O>(
        &self,
        func: &'static str,
        input: I,
    ) -> Result<O, ProviderError>
    where
        I: Serialize + Send + 'static,
        O: DeserializeOwned + Send + 'static,
    {
        self.call(move |plugin| call_guest_json::<I, O>(plugin, func, &input))
            .await
    }

    /// Convenience for guest calls that take no JSON input.
    pub(crate) async fn call_json_no_input<O>(&self, func: &'static str) -> Result<O, ProviderError>
    where
        O: DeserializeOwned + Send + 'static,
    {
        self.call(move |plugin| call_guest_json_no_input::<O>(plugin, func))
            .await
    }
}

/// Build the Manifest + host functions + Plugin once. Returns the new
/// Plugin and the receiver for filesystem watch events the worker drains.
fn build_plugin(
    config: &crate::WasmProviderConfig,
) -> Result<(Plugin, cb::Receiver<WatchEvent>), ProviderError> {
    let wasm = Wasm::data((*config.wasm_bytes).clone());
    let mut manifest = Manifest::new([wasm])
        .with_allowed_hosts(config.allowed_hosts.iter().cloned())
        .with_timeout(GUEST_CALL_TIMEOUT)
        .with_memory_max(4096);
    for (src, dest) in &config.allowed_paths {
        manifest = manifest.with_allowed_path(src.clone(), dest);
    }

    let mut host_fns = crate::host_http::build_http_host_functions(&config.tls_mode);
    host_fns.extend(crate::host_file::build_file_host_functions(
        &config.allowed_files,
    ));
    let (watch_fns, watch_rx) =
        crate::host_watch::build_watch_host_functions(&config.allowed_files);
    host_fns.extend(watch_fns);

    let plugin = Plugin::new(&manifest, host_fns, true).map_err(|e| {
        ProviderError::Other(anyhow!(
            "failed to load WASM plugin '{}': {e}",
            config.wasm_path
        ))
    })?;
    Ok((plugin, watch_rx))
}

/// Body of the worker thread. Owns the Plugin from construction through
/// shutdown; never returns it to another thread.
fn worker_thread_main(
    config: crate::WasmProviderConfig,
    call_rx: cb::Receiver<CallFn>,
    init_tx: std::sync::mpsc::SyncSender<Result<WasmInitOutputs, String>>,
    label: String,
) {
    // 1. Apply per-provider Landlock under BestEffort. Failure logs but
    // does not abort init — Landlock is defence-in-depth, not the primary
    // gate (wasmtime sandboxing + userspace policy enforcement remain).
    if let Err(e) = apply_landlock(&config) {
        warn!(provider = %config.id, error = %e, "wasm worker: Landlock apply failed (continuing)");
    }

    // 2. Build the Plugin and run guest init.
    let (mut plugin, watch_rx) = match build_plugin(&config) {
        Ok(p) => p,
        Err(e) => {
            let _ = init_tx.send(Err(format!("plugin build: {e}")));
            return;
        }
    };
    if let Err(e) = init_guest(&mut plugin, &config, "init") {
        let _ = init_tx.send(Err(format!("init: {e}")));
        return;
    }

    // 3. Eager metadata queries — once at startup, results outlive the
    // Plugin via Box::leak in the query helpers.
    let outputs = WasmInitOutputs {
        capabilities: query_capabilities(&mut plugin, &config.id),
        attribute_descriptors: query_attribute_descriptors(&mut plugin, &config.id),
        auth_fields: query_auth_fields(&mut plugin, &config.id),
        registration_info: query_registration_info(&mut plugin, &config.id),
        readiness_probes: query_readiness_probes(&mut plugin, &config.id),
    };

    debug!(
        provider = %config.id,
        caps = ?outputs.capabilities,
        attrs = outputs.attribute_descriptors.len(),
        auth = outputs.auth_fields.len(),
        reg = outputs.registration_info.is_some(),
        probes = outputs.readiness_probes.len(),
        "WASM provider initialised on worker thread",
    );
    let _ = init_tx.send(Ok(outputs));
    drop(init_tx);

    // 4. Service requests until the call channel closes (Drop of WasmWorker).
    main_loop(plugin, watch_rx, &call_rx, &config, &label);
}

/// Resolve the directory wasmtime uses for its module cache. Mirrors
/// wasmtime's own logic: `$XDG_CACHE_HOME/wasmtime` if set, else
/// `$HOME/.cache/wasmtime`. Returns `None` when neither is available
/// (e.g. very stripped systemd unit) — the worker proceeds without
/// granting the path, accepting the recompile-each-time cost.
fn wasmtime_cache_dir() -> Option<std::path::PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").filter(|s| !s.is_empty()) {
        return Some(std::path::PathBuf::from(xdg).join("wasmtime"));
    }
    let home = std::env::var_os("HOME").filter(|s| !s.is_empty())?;
    Some(std::path::PathBuf::from(home).join(".cache/wasmtime"))
}

/// Apply the per-provider Landlock ruleset to the calling thread.
fn apply_landlock(config: &crate::WasmProviderConfig) -> Result<(), anyhow::Error> {
    // The translator needs PluginPolicy + ResolvedPolicy. The daemon
    // already resolved both before constructing the WasmProviderConfig
    // and stashed them inside; for now we'll compute a minimal ruleset
    // from the config's allowed_hosts/allowed_paths/allowed_files since
    // the WasmProviderConfig is the single source of truth here.
    use rosec_core::sandbox::landlock::{ConnectPort, FsMode, PathRule};
    use std::path::PathBuf;

    let mut paths: Vec<PathRule> = Vec::new();
    // Base provider needs: libs / certs / DNS / proc-self.
    for p in [
        "/usr/lib",
        "/lib",
        "/usr/lib64",
        "/lib64",
        "/etc/ld.so.cache",
        "/etc/ld.so.preload",
        "/etc/ssl",
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/etc/hosts",
        "/proc/self",
        "/sys/devices/system/cpu",
    ] {
        paths.push(PathRule::ro(p));
    }

    for (src, _) in &config.allowed_paths {
        let raw = src.strip_prefix("ro:").unwrap_or(src.as_str());
        paths.push(PathRule {
            path: PathBuf::from(raw),
            mode: if src.starts_with("ro:") {
                FsMode::Ro
            } else {
                FsMode::Rw
            },
        });
    }
    for f in &config.allowed_files {
        paths.push(PathRule::ro(f.clone()));
    }

    // wasmtime's module cache lives under $XDG_CACHE_HOME (or ~/.cache).
    // JIT compilation persists artefacts there; without RW access wasmtime
    // logs a warning and recompiles on every load. Best-effort: skip if
    // neither variable resolves to a path we can use.
    if let Some(cache_dir) = wasmtime_cache_dir() {
        paths.push(PathRule {
            path: cache_dir,
            mode: FsMode::Rw,
        });
    }

    let ports: Vec<ConnectPort> = if config.allowed_hosts.is_empty() {
        Vec::new()
    } else {
        vec![ConnectPort(443), ConnectPort(80)]
    };

    rosec_core::sandbox::landlock::apply_paths_and_ports(&paths, &ports)
        .map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

/// Multiplex caller requests and watch events on the same thread.
///
/// `select!` blocks until either channel has data. Watch events get
/// debounced and dispatched via `on_path_changed` to the same Plugin
/// the caller closures see — no cross-thread synchronisation needed.
fn main_loop(
    mut plugin: Plugin,
    mut watch_rx: cb::Receiver<WatchEvent>,
    call_rx: &cb::Receiver<CallFn>,
    config: &crate::WasmProviderConfig,
    label: &str,
) {
    loop {
        // Two-step: select! borrows the receivers, the match arm has owned
        // access. Action carries the work out so we can mutate plugin /
        // watch_rx freely below.
        enum Action {
            Call(CallFn),
            Watch(WatchEvent),
            CallClosed,
            WatchClosed,
        }
        let action = cb::select! {
            recv(call_rx) -> msg => match msg {
                Ok(c) => Action::Call(c),
                Err(_) => Action::CallClosed,
            },
            recv(&watch_rx) -> msg => match msg {
                Ok(e) => Action::Watch(e),
                Err(_) => Action::WatchClosed,
            },
        };

        match action {
            Action::Call(call) => {
                let mut needs_recreate = false;
                run_call(&mut plugin, call, &mut needs_recreate, label);
                if needs_recreate {
                    recreate_in_place(&mut plugin, &mut watch_rx, config, label);
                }
            }
            Action::Watch(first) => {
                let _ = process_watch_burst(&mut plugin, first, &watch_rx, &config.id);
            }
            Action::CallClosed => {
                debug!(worker = %label, "call channel closed, exiting");
                return;
            }
            Action::WatchClosed => {
                // Watch sender dropped — plugin doesn't use watches, or
                // the host fns were rebuilt. Keep serving calls.
                let (drained_tx, drained_rx) = cb::bounded::<WatchEvent>(0);
                drop(drained_tx);
                watch_rx = drained_rx;
            }
        }
    }
}

/// Run a single dispatched closure under `catch_unwind` so a panicking
/// call does not take the worker thread down. The closure signals trap
/// detection by setting `*needs_recreate = true`.
fn run_call(plugin: &mut Plugin, call: CallFn, needs_recreate: &mut bool, label: &str) {
    let plugin_ptr = plugin as *mut Plugin;
    let recreate_ptr = needs_recreate as *mut bool;
    if let Err(panic) = std::panic::catch_unwind(AssertUnwindSafe(move || {
        // SAFETY: pointers are valid for the duration of catch_unwind; we
        // own &mut Plugin and &mut bool from the caller's stack frame.
        unsafe { call(&mut *plugin_ptr, &mut *recreate_ptr) }
    })) {
        let msg = panic
            .downcast_ref::<&'static str>()
            .map(|s| s.to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "(non-string panic)".into());
        error!(worker = %label, panic = %msg, "wasm worker call panicked");
    }
}

/// Rebuild the Plugin in place after a wasmtime trap. Replaces both the
/// Plugin and the watch receiver (a fresh Plugin owns a fresh watch
/// channel — the old one's sender is dropped when the old host fns drop).
///
/// On rebuild failure the worker keeps the old (corrupted) Plugin and logs.
/// The next call will fail again, the daemon's hot-reload path can rotate
/// the provider if it cares to.
fn recreate_in_place(
    plugin: &mut Plugin,
    watch_rx: &mut cb::Receiver<WatchEvent>,
    config: &crate::WasmProviderConfig,
    label: &str,
) {
    info!(worker = %label, "recreating plugin after wasmtime trap");
    match build_plugin(config) {
        Ok((new_plugin, new_watch_rx)) => {
            *plugin = new_plugin;
            *watch_rx = new_watch_rx;
            if let Err(e) = init_guest(plugin, config, "re-init") {
                warn!(worker = %label, error = %e, "re-init after recreate failed");
            }
        }
        Err(e) => {
            warn!(worker = %label, error = %e, "plugin recreate failed");
        }
    }
}

/// Drain consecutive watch events for the same paths within a 500ms
/// quiet window, then dispatch one `on_path_changed` per unique path
/// to the guest. Mirrors the old async dispatcher's coalescing.
fn process_watch_burst(
    plugin: &mut Plugin,
    first: WatchEvent,
    watch_rx: &cb::Receiver<WatchEvent>,
    provider_id: &str,
) -> Result<(), ()> {
    use std::collections::HashMap;

    let mut pending: HashMap<String, String> = HashMap::new();
    pending.insert(first.path, first.kind);

    let deadline = std::time::Instant::now() + WATCH_DEBOUNCE;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match watch_rx.recv_timeout(remaining) {
            Ok(evt) => {
                pending.insert(evt.path, evt.kind);
            }
            Err(cb::RecvTimeoutError::Timeout) => break,
            Err(cb::RecvTimeoutError::Disconnected) => break,
        }
    }

    if !plugin.function_exists("on_path_changed") {
        return Ok(());
    }

    for (path, kind) in pending {
        let payload = WatchEvent { path, kind };
        let json = match serde_json::to_vec(&payload) {
            Ok(v) => v,
            Err(e) => {
                warn!(provider = %provider_id, error = %e, "host_watch: serialize failed");
                continue;
            }
        };
        debug!(
            provider = %provider_id,
            path = %payload.path,
            kind = %payload.kind,
            "host_watch: dispatching on_path_changed",
        );
        if let Err(e) = plugin.call::<&[u8], &[u8]>("on_path_changed", &json) {
            debug!(
                provider = %provider_id,
                path = %payload.path,
                error = %e,
                "on_path_changed call failed",
            );
        }
    }
    Ok(())
}
