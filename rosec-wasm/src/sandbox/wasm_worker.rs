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

// Wired into WasmProvider in a follow-up commit. Public surface and
// internal plumbing both compile; see #[allow(dead_code)] on the items
// that the upcoming refactor will reference.
#![allow(dead_code)]

use std::panic::AssertUnwindSafe;
use std::thread;
use std::time::Duration;

use anyhow::anyhow;
use crossbeam_channel as cb;
use extism::{Manifest, Plugin, Wasm};
use rosec_core::ProviderError;
use tokio::sync::oneshot;
use tracing::{debug, error, warn};

use crate::host_watch::WatchEvent;
use crate::protocol::ReadinessProbe;
use crate::provider::{
    GUEST_CALL_TIMEOUT, init_guest, query_attribute_descriptors, query_auth_fields,
    query_capabilities, query_readiness_probes, query_registration_info,
};

/// Capacity of the call-request channel between async callers and the
/// worker thread. Per-provider activity is sequential (one user, one
/// vault) so 16 in-flight is plenty; the bound prevents a misbehaving
/// caller from queueing unbounded work.
const CALL_CHANNEL_CAPACITY: usize = 16;

/// Quiet window inside which contiguous watch events for the same path
/// collapse into a single `on_path_changed` dispatch. Mirrors what the
/// previous `spawn_watch_dispatcher` did in tokio land.
const WATCH_DEBOUNCE: Duration = Duration::from_millis(500);

/// A boxed unit of work the worker executes against `&mut Plugin`.
type CallFn = Box<dyn FnOnce(&mut Plugin) + Send + 'static>;

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
    /// dedicated thread. Long-running guest work (Argon2, network calls)
    /// no longer pins a tokio worker — the daemon's runtime stays
    /// responsive.
    pub(crate) async fn call<T, F>(&self, f: F) -> Result<T, ProviderError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Plugin) -> T + Send + 'static,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(Box::new(move |p| {
                let _ = reply_tx.send(f(p));
            }))
            .map_err(|_| {
                ProviderError::Unavailable(format!("wasm worker '{}' has stopped", self.label))
            })?;
        reply_rx.await.map_err(|_| {
            ProviderError::Unavailable(format!(
                "wasm worker '{}' dropped reply (panic during call)",
                self.label
            ))
        })
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
    let (mut plugin, mut watch_rx) = match build_plugin(&config) {
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
    main_loop(plugin, &mut watch_rx, &call_rx, &config, &label);
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
    watch_rx: &mut cb::Receiver<WatchEvent>,
    call_rx: &cb::Receiver<CallFn>,
    config: &crate::WasmProviderConfig,
    label: &str,
) {
    loop {
        cb::select! {
            recv(call_rx) -> msg => {
                match msg {
                    Ok(call) => {
                        run_call(&mut plugin, call, label);
                    }
                    Err(_) => {
                        debug!(worker = %label, "call channel closed, exiting");
                        return;
                    }
                }
            }
            recv(watch_rx) -> msg => {
                match msg {
                    Ok(first) => {
                        let _ = process_watch_burst(&mut plugin, first, watch_rx, &config.id);
                    }
                    Err(_) => {
                        // watch_rx closed — keep serving call_rx, the
                        // plugin may not use the watch channel at all.
                    }
                }
            }
        }
    }
}

/// Run a single dispatched closure under `catch_unwind` so a panicking
/// call does not take the worker thread down.
fn run_call(plugin: &mut Plugin, call: CallFn, label: &str) {
    if let Err(panic) = std::panic::catch_unwind(AssertUnwindSafe(|| call(plugin))) {
        let msg = panic
            .downcast_ref::<&'static str>()
            .map(|s| s.to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "(non-string panic)".into());
        error!(worker = %label, panic = %msg, "wasm worker call panicked");
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
