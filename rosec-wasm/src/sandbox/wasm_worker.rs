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
use std::sync::{Arc, Mutex};
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

// The guest and HTTP execution deadline expires before the caller deadline.
const HOST_CALL_TIMEOUT: Duration = Duration::from_secs(185);

#[derive(Default)]
struct Control {
    generation: u64,
    preserve_for_lock: bool,
    next_id: u64,
    active: Option<(u64, extism::CancelHandle)>,
}

// A cancelled future must invalidate the instance even if its reply was already
// queued. The worker checks generation again before servicing any later call.
struct CallGuard {
    control: Arc<Mutex<Control>>,
    id: u64,
    armed: bool,
    wake: cb::Sender<()>,
}
impl Drop for CallGuard {
    fn drop(&mut self) {
        if self.armed {
            let mut c = self.control.lock().unwrap_or_else(|e| e.into_inner());
            c.generation = c.generation.wrapping_add(1);
            c.preserve_for_lock = false;
            let _ = self.wake.try_send(());
            if let Some((id, handle)) = &c.active
                && *id == self.id
            {
                let _ = handle.cancel();
            }
        }
    }
}

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
    call_timeout: Duration,
    control: Arc<Mutex<Control>>,
    wake: cb::Sender<()>,
    /// Held so callers can identify the thread in panics / debuggers.
    /// Not joined on Drop because pending guest calls (e.g. an in-flight
    /// 60-second Argon2 unlock) could pin shutdown.
    _handle: thread::JoinHandle<()>,
}

impl Drop for WasmWorker {
    fn drop(&mut self) {
        self.invalidate();
    }
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
        let call_timeout = if config.kind == "protonpass" {
            Duration::from_secs(65)
        } else {
            HOST_CALL_TIMEOUT
        };
        let config_for_thread = config.clone();
        let control = Arc::new(Mutex::new(Control::default()));
        let thread_control = Arc::clone(&control);
        let (wake, wake_rx) = cb::bounded(1);

        let handle = thread::Builder::new()
            .name(label.clone())
            .spawn(move || {
                worker_thread_main(
                    config_for_thread,
                    call_rx,
                    init_tx,
                    label_for_thread,
                    thread_control,
                    wake_rx,
                )
            })
            .map_err(|e| {
                ProviderError::Other(anyhow!("failed to spawn wasm worker thread: {e}"))
            })?;

        match init_rx.recv() {
            Ok(Ok(outputs)) => Ok((
                Self {
                    tx: call_tx,
                    label,
                    call_timeout,
                    control,
                    wake,
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
        self.call_with_timeout(self.call_timeout, f).await
    }

    async fn call_with_timeout<T, F>(&self, timeout: Duration, f: F) -> Result<T, ProviderError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Plugin) -> (Result<T, ProviderError>, CallOutcome) + Send + 'static,
    {
        self.call_in_generation(None, timeout, f).await
    }

    pub(crate) fn generation(&self) -> u64 {
        self.control
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .generation
    }

    pub(crate) fn check_generation(&self, generation: u64) -> Result<(), ProviderError> {
        if self.generation() == generation {
            Ok(())
        } else {
            Err(ProviderError::Locked)
        }
    }

    pub(crate) async fn call_for_generation<T, F>(
        &self,
        generation: u64,
        f: F,
    ) -> Result<T, ProviderError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Plugin) -> (Result<T, ProviderError>, CallOutcome) + Send + 'static,
    {
        self.call_in_generation(Some(generation), self.call_timeout, f)
            .await
    }

    async fn call_in_generation<T, F>(
        &self,
        expected: Option<u64>,
        timeout: Duration,
        f: F,
    ) -> Result<T, ProviderError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Plugin) -> (Result<T, ProviderError>, CallOutcome) + Send + 'static,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        let (id, generation) = {
            let mut c = self.control.lock().unwrap_or_else(|e| e.into_inner());
            if expected.is_some_and(|generation| generation != c.generation) {
                return Err(ProviderError::Locked);
            }
            c.next_id = c.next_id.wrapping_add(1);
            (c.next_id, c.generation)
        };
        let control = Arc::clone(&self.control);
        let mut guard = CallGuard {
            control: Arc::clone(&control),
            id,
            armed: false,
            wake: self.wake.clone(),
        };
        self.tx
            .try_send(Box::new(move |plugin, needs_recreate| {
                {
                    let mut c = control.lock().unwrap_or_else(|e| e.into_inner());
                    if reply_tx.is_closed() || generation != c.generation {
                        let _ = reply_tx.send(Err(ProviderError::Locked));
                        return;
                    }
                    c.active = Some((id, plugin.cancel_handle()));
                }
                let (mut result, outcome) = f(plugin);
                let mut c = control.lock().unwrap_or_else(|e| e.into_inner());
                c.active = None;
                if generation != c.generation || reply_tx.is_closed() {
                    *needs_recreate = true;
                    result = Err(ProviderError::Locked);
                }
                if outcome == CallOutcome::PluginCallFailed {
                    *needs_recreate = true;
                }
                let _ = reply_tx.send(result);
            }))
            .map_err(|e| {
                ProviderError::Unavailable(match e {
                    cb::TrySendError::Full(_) => format!("wasm worker '{}' is busy", self.label),
                    cb::TrySendError::Disconnected(_) => {
                        format!("wasm worker '{}' has stopped", self.label)
                    }
                })
            })?;
        guard.armed = true;
        match tokio::time::timeout(timeout, reply_rx).await {
            Ok(Ok(result)) => {
                guard.armed = false;
                result
            }
            Ok(Err(_)) => Err(ProviderError::Unavailable(format!(
                "wasm worker '{}' dropped reply",
                self.label
            ))),
            Err(_) => Err(ProviderError::Unavailable(format!(
                "wasm worker '{}' did not reply within {}s",
                self.label,
                timeout.as_secs()
            ))),
        }
    }

    /// Invalidate queued calls and cancel active execution before locking. Even
    /// if the queue is full, the next request must use a fresh locked instance.
    pub(crate) fn invalidate(&self) {
        let mut c = self.control.lock().unwrap_or_else(|e| e.into_inner());
        c.generation = c.generation.wrapping_add(1);
        c.preserve_for_lock = false;
        let _ = self.wake.try_send(());
        if let Some((_, handle)) = &c.active {
            let _ = handle.cancel();
        }
    }

    /// Fence queued operations, let an idle guest revoke its session, then
    /// discard the instance regardless of cleanup success. Active execution is
    /// cancelled and discarded first; remote cleanup is best effort in that case.
    pub(crate) async fn lock(&self) -> Result<crate::protocol::SimpleResponse, ProviderError> {
        struct LockGuard<'a>(&'a WasmWorker);
        impl Drop for LockGuard<'_> {
            fn drop(&mut self) {
                self.0.invalidate();
            }
        }
        let _guard = LockGuard(self);
        {
            let mut c = self.control.lock().unwrap_or_else(|e| e.into_inner());
            c.generation = c.generation.wrapping_add(1);
            c.preserve_for_lock = c.active.is_none();
            if let Some((_, handle)) = &c.active {
                let _ = handle.cancel();
            }
            let _ = self.wake.try_send(());
        }
        self.call(move |p| {
            let (result, _) = call_guest_json_no_input(p, "lock");
            (result, CallOutcome::PluginCallFailed)
        })
        .await
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
    if config.kind == "protonpass" {
        manifest = manifest.with_timeout(Duration::from_secs(60));
        manifest.memory.max_http_response_bytes = Some(8 * 1024 * 1024);
    }
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
    control: Arc<Mutex<Control>>,
    wake_rx: cb::Receiver<()>,
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
    main_loop(
        plugin, watch_rx, &call_rx, &config, &label, &control, &wake_rx,
    );
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
    use rosec_core::sandbox::landlock::{FsMode, PathRule};
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

    let ports = super::policy_to_ruleset::ports_for_hosts(&config.allowed_hosts);

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
    control: &Mutex<Control>,
    wake_rx: &cb::Receiver<()>,
) {
    let mut generation = 0;
    loop {
        // Two-step: select! borrows the receivers, the match arm has owned
        // access. Action carries the work out so we can mutate plugin /
        // watch_rx freely below.
        enum Action {
            Call(CallFn),
            Watch(WatchEvent),
            CallClosed,
            WatchClosed,
            Invalidate,
        }
        let action = cb::select_biased! {
            recv(wake_rx) -> msg => if msg.is_ok() { Action::Invalidate } else { Action::CallClosed },
            recv(call_rx) -> msg => match msg {
                Ok(c) => Action::Call(c),
                Err(_) => Action::CallClosed,
            },
            recv(&watch_rx) -> msg => match msg {
                Ok(e) => Action::Watch(e),
                Err(_) => Action::WatchClosed,
            },
        };

        let (current, preserve) = {
            let mut c = control.lock().unwrap_or_else(|e| e.into_inner());
            let preserve = c.preserve_for_lock;
            c.preserve_for_lock = false;
            (c.generation, preserve)
        };
        if current != generation {
            if !preserve && recreate_in_place(&mut plugin, &mut watch_rx, config, label).is_err() {
                return;
            }
            generation = current;
        }
        match action {
            Action::Invalidate => {}
            Action::Call(call) => {
                let mut needs_recreate = false;
                run_call(&mut plugin, call, &mut needs_recreate, label);
                if needs_recreate
                    && recreate_in_place(&mut plugin, &mut watch_rx, config, label).is_err()
                {
                    return;
                }
            }
            Action::Watch(first) => {
                if process_watch_burst(&mut plugin, first, &watch_rx, &config.id).is_err()
                    && recreate_in_place(&mut plugin, &mut watch_rx, config, label).is_err()
                {
                    return;
                }
            }
            Action::CallClosed => {
                debug!(worker = %label, "call channel closed, exiting");
                return;
            }
            Action::WatchClosed => {
                // Watch sender dropped — plugin doesn't use watches, or
                // the host fns were rebuilt. Keep serving calls.
                watch_rx = cb::never();
            }
        }
    }
}

/// Run a single dispatched closure under `catch_unwind` so a panicking
/// call does not take the worker thread down. The closure signals trap
/// detection by setting `*needs_recreate = true`.
fn run_call(plugin: &mut Plugin, call: CallFn, needs_recreate: &mut bool, label: &str) {
    if std::panic::catch_unwind(AssertUnwindSafe(|| call(plugin, needs_recreate))).is_err() {
        *needs_recreate = true;
        error!(worker = %label, "wasm worker call panicked; discarding instance");
    }
}

/// Rebuild the Plugin in place after a wasmtime trap. Replaces both the
/// Plugin and the watch receiver (a fresh Plugin owns a fresh watch
/// channel — the old one's sender is dropped when the old host fns drop).
///
/// A failed rebuild stops the worker. Never reuse a damaged instance.
fn recreate_in_place(
    plugin: &mut Plugin,
    watch_rx: &mut cb::Receiver<WatchEvent>,
    config: &crate::WasmProviderConfig,
    label: &str,
) -> Result<(), ()> {
    info!(worker = %label, "recreating plugin after invalidation");
    let (mut new_plugin, new_watch_rx) = build_plugin(config).map_err(|_| {
        warn!(worker = %label, "plugin recreate failed; stopping worker");
    })?;
    init_guest(&mut new_plugin, config, "re-init").map_err(|_| {
        warn!(worker = %label, "plugin re-init failed; stopping worker");
    })?;
    *plugin = new_plugin;
    *watch_rx = new_watch_rx;
    Ok(())
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
        if plugin
            .call::<&[u8], &[u8]>("on_path_changed", &json)
            .is_err()
        {
            debug!(
                provider = %provider_id,
                path = %payload.path,
                "on_path_changed call failed",
            );
            return Err(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SimpleResponse;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn config() -> crate::WasmProviderConfig {
        // State lives inside actual WASM memory; recreation must clear it.
        let bytes = br#"(module
            (import "extism:host/env" "alloc" (func $alloc (param i64) (result i64)))
            (import "extism:host/env" "store_u8" (func $store (param i64 i32)))
            (import "extism:host/env" "output_set" (func $output (param i64 i64)))
            (global $secret (mut i32) (i32.const 0))
            (func $reply (param $value i32) (local $p i64)
                i64.const 1 call $alloc local.set $p
                local.get $p local.get $value call $store
                local.get $p i64.const 1 call $output)
            (func (export "init") (result i32) (local $p i64)
                i64.const 11 call $alloc local.set $p
                local.get $p i32.const 123 call $store
                local.get $p i64.const 1 i64.add i32.const 34 call $store
                local.get $p i64.const 2 i64.add i32.const 111 call $store
                local.get $p i64.const 3 i64.add i32.const 107 call $store
                local.get $p i64.const 4 i64.add i32.const 34 call $store
                local.get $p i64.const 5 i64.add i32.const 58 call $store
                local.get $p i64.const 6 i64.add i32.const 116 call $store
                local.get $p i64.const 7 i64.add i32.const 114 call $store
                local.get $p i64.const 8 i64.add i32.const 117 call $store
                local.get $p i64.const 9 i64.add i32.const 101 call $store
                local.get $p i64.const 10 i64.add i32.const 125 call $store
                local.get $p i64.const 11 call $output i32.const 0)
            (func (export "set") (result i32)
                i32.const 1 global.set $secret i32.const 0)
            (func (export "read") (result i32)
                global.get $secret call $reply i32.const 0)
            (func (export "spin") (result i32)
                i32.const 1 global.set $secret (loop $forever br $forever) i32.const 0)
            (func (export "trap") (result i32)
                i32.const 1 global.set $secret unreachable)
        )"#
        .to_vec();
        crate::WasmProviderConfig {
            id: "worker-security-test".into(),
            name: "test".into(),
            kind: "test".into(),
            wasm_path: "synthetic.wat".into(),
            wasm_bytes: Arc::new(bytes),
            allowed_hosts: vec![],
            allowed_paths: vec![],
            allowed_files: vec![],
            options: Default::default(),
            offline_cache: false,
            tls_mode: rosec_core::config::TlsMode::Bundled,
            tls_mode_probe: rosec_core::config::TlsMode::Bundled,
            unlock_timeout_secs: 30,
        }
    }
    async fn invoke(worker: &WasmWorker, name: &'static str) -> Result<Vec<u8>, ProviderError> {
        worker
            .call(move |p| match p.call::<(), Vec<u8>>(name, ()) {
                Ok(v) => (Ok(v), CallOutcome::Clean),
                Err(_) => (Err(ProviderError::Locked), CallOutcome::PluginCallFailed),
            })
            .await
    }
    async fn locked(worker: &WasmWorker) {
        assert_eq!(invoke(worker, "read").await.unwrap(), vec![0]);
    }

    #[test]
    fn provider_registration_survives_restart_and_rejects_wrong_password() {
        use rosec_core::{Provider, UnlockInput};
        use zeroize::Zeroizing;
        fn reply(name: &str, json: &str) -> String {
            let mut wat = format!(
                "(func ${name} (local $p i64) i64.const {} call $alloc local.set $p ",
                json.len()
            );
            for (i, byte) in json.bytes().enumerate() {
                wat.push_str(&format!(
                    "local.get $p i64.const {i} i64.add i32.const {byte} call $store "
                ));
            }
            wat.push_str(&format!(
                "local.get $p i64.const {} call $output)",
                json.len()
            ));
            wat
        }
        let mut cfg = config();
        let mut wat = String::from_utf8((*cfg.wasm_bytes).clone()).unwrap();
        wat = wat.replacen(
            "(module",
            "(module (import \"extism:host/env\" \"input_length\" (func $length (result i64)))",
            1,
        );
        wat.pop();
        wat.push_str(&reply("yes", r#"{"ok":true}"#));
        wat.push_str(&reply(
            "registration",
            r#"{"ok":false,"error_kind":"registration_required"}"#,
        ));
        wat.push_str(&reply(
            "locked",
            r#"{"locked":true,"last_sync_epoch_secs":null}"#,
        ));
        wat.push_str(&reply(
            "unlocked",
            r#"{"locked":false,"last_sync_epoch_secs":null}"#,
        ));
        wat.push_str(
            r#"
            (func (export "unlock") (result i32)
                call $length i64.const 100 i64.gt_u
                if i32.const 1 global.set $secret call $yes
                else i32.const 0 global.set $secret call $registration end i32.const 0)
            (func (export "lock") (result i32)
                i32.const 0 global.set $secret call $yes i32.const 0)
            (func (export "status") (result i32)
                global.get $secret if call $unlocked else call $locked end i32.const 0)
        )"#,
        );
        cfg.wasm_bytes = Arc::new(wat.into_bytes());
        let _env_guard = crate::TEST_ENV_MUTEX.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("XDG_DATA_HOME");
        unsafe {
            std::env::set_var("XDG_DATA_HOME", temp.path());
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let provider = crate::WasmProvider::new(cfg.clone()).unwrap();
            provider
                .unlock(UnlockInput::WithRegistration {
                    password: Zeroizing::new("local-passphrase".into()),
                    registration_fields: [(
                        "personal_access_token".into(),
                        Zeroizing::new("synthetic-personal-access-token".into()),
                    )]
                    .into(),
                })
                .await
                .unwrap();
            assert!(!provider.status().await.unwrap().locked);
            provider.lock().await.unwrap();
            assert!(provider.status().await.unwrap().locked);
            drop(provider);
            let restarted = crate::WasmProvider::new(cfg).unwrap();
            assert!(
                restarted
                    .unlock(UnlockInput::Password(Zeroizing::new("wrong".into())))
                    .await
                    .is_err()
            );
            assert!(restarted.status().await.unwrap().locked);
            restarted
                .unlock(UnlockInput::Password(Zeroizing::new(
                    "local-passphrase".into(),
                )))
                .await
                .unwrap();
            assert!(!restarted.status().await.unwrap().locked);
            restarted.lock().await.unwrap();
        });
        match previous {
            Some(value) => unsafe {
                std::env::set_var("XDG_DATA_HOME", value);
            },
            None => unsafe {
                std::env::remove_var("XDG_DATA_HOME");
            },
        }
    }

    #[tokio::test]
    async fn caller_timeout_discards_active_guest() {
        let (worker, _) = WasmWorker::spawn(config()).unwrap();
        let result = worker
            .call_with_timeout(Duration::from_millis(50), |p| {
                let result = p.call::<(), Vec<u8>>("spin", ());
                (
                    result.map_err(|_| ProviderError::Locked),
                    CallOutcome::PluginCallFailed,
                )
            })
            .await;
        assert!(result.is_err());
        tokio::time::timeout(Duration::from_secs(5), locked(&worker))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn idle_lock_runs_guest_cleanup_before_discarding_instance() {
        let mut cfg = config();
        let mut wat = String::from_utf8((*cfg.wasm_bytes).clone())
            .unwrap()
            .replace("(func (export \"init\")", "(func $ok (export \"init\")");
        wat.pop();
        wat.push_str(
            r#"(func (export "lock") (result i32)
            global.get $secret i32.eqz if unreachable end call $ok) )"#,
        );
        cfg.wasm_bytes = Arc::new(wat.into_bytes());
        let (worker, _) = WasmWorker::spawn(cfg).unwrap();
        invoke(&worker, "set").await.unwrap();
        assert!(worker.lock().await.unwrap().ok);
        locked(&worker).await;
    }

    #[tokio::test]
    async fn traps_and_panics_discard_guest_state() {
        let (worker, _) = WasmWorker::spawn(config()).unwrap();
        assert!(invoke(&worker, "trap").await.is_err());
        locked(&worker).await;
        let result: Result<(), _> = worker
            .call(|p| {
                p.call::<(), Vec<u8>>("set", ()).unwrap();
                panic!("synthetic panic");
            })
            .await;
        assert!(result.is_err());
        locked(&worker).await;
        // Deserialization failure also resets the instance.
        invoke(&worker, "set").await.unwrap();
        assert!(
            worker
                .call_json_no_input::<SimpleResponse>("read")
                .await
                .is_err()
        );
        locked(&worker).await;
    }

    #[tokio::test]
    async fn cancelled_unlock_and_explicit_invalidation_cannot_leave_secrets() {
        let (worker, _) = WasmWorker::spawn(config()).unwrap();
        let worker = Arc::new(worker);
        let started = Arc::new(AtomicBool::new(false));
        let run = Arc::clone(&worker);
        let signal = Arc::clone(&started);
        let task = tokio::spawn(async move {
            run.call(move |p| {
                signal.store(true, Ordering::SeqCst);
                let result = p.call::<(), Vec<u8>>("spin", ());
                (
                    result.map_err(|_| ProviderError::Locked),
                    CallOutcome::PluginCallFailed,
                )
            })
            .await
        });
        while !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        // Let execution enter the guest before dropping the waiting future.
        tokio::time::sleep(Duration::from_millis(20)).await;
        task.abort();
        let _ = task.await;
        tokio::time::timeout(Duration::from_secs(5), locked(&worker))
            .await
            .unwrap();
        invoke(&worker, "set").await.unwrap();
        let old_generation = worker.generation();
        worker.invalidate();
        let stale: Result<(), _> = worker
            .call_for_generation(old_generation, |_| {
                panic!("a pre-lock authentication retry must not execute");
            })
            .await;
        assert!(matches!(stale, Err(ProviderError::Locked)));
        locked(&worker).await;
    }

    #[tokio::test]
    async fn bounded_queue_is_nonblocking_and_abandoned_work_is_skipped() {
        let (worker, _) = WasmWorker::spawn(config()).unwrap();
        let worker = Arc::new(worker);
        let (release_tx, release_rx) = cb::bounded(0);
        let (started_tx, started_rx) = oneshot::channel();
        let run = Arc::clone(&worker);
        let active = tokio::spawn(async move {
            run.call(move |_| {
                let _ = started_tx.send(());
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                (Ok(()), CallOutcome::Clean)
            })
            .await
        });
        started_rx.await.unwrap();
        let executed = Arc::new(AtomicBool::new(false));
        let mut queued = Vec::new();
        for _ in 0..CALL_CHANNEL_CAPACITY {
            let run = Arc::clone(&worker);
            let executed = Arc::clone(&executed);
            queued.push(tokio::spawn(async move {
                run.call(move |_| {
                    executed.store(true, Ordering::SeqCst);
                    (Ok(()), CallOutcome::Clean)
                })
                .await
            }));
        }
        tokio::task::yield_now().await;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                worker.call(|_| (Ok(()), CallOutcome::Clean))
            )
            .await
            .unwrap()
            .is_err()
        );
        for task in queued {
            task.abort();
            let _ = task.await;
        }
        release_tx.send(()).unwrap();
        let _ = active.await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !worker.tx.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        locked(&worker).await;
        assert!(!executed.load(Ordering::SeqCst));
    }
}
