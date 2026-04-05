//! `WasmProvider` — wraps an Extism WASM plugin as a `rosec_core::Provider`.

use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use extism::{Manifest, Plugin, Wasm};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, Zeroizing};

use rosec_core::{
    AttributeDescriptor, Attributes, AuthField, AuthFieldKind, Capability, ItemAttributes,
    ItemMeta, Provider, ProviderCallbacks, ProviderError, ProviderStatus, RegistrationInfo,
    SecretBytes, SshKeyMeta, SshPrivateKeyMaterial, UnlockInput,
};

use crate::protocol::{
    AuthFieldsResponse, CapabilitiesResponse, ErrorKind, InitRequest, InitResponse,
    ItemAttributesResponse, ItemIdRequest, ItemListResponse, RegistrationInfoResponse,
    SearchRequest, SecretAttrRequest, SecretAttrResponse, SimpleResponse, SshKeyListResponse,
    SshPrivateKeyRequest, SshPrivateKeyResponse, StatusResponse, UnlockRequest,
    WasmAttributeDescriptor, WasmSshKeyMeta,
};

// ── Configuration ────────────────────────────────────────────────

/// Default timeout for guest function calls (60 seconds).
///
/// This covers the worst-case network latency for operations like
/// `unlock` and `sync` that hit Bitwarden's API.  If a guest call
/// exceeds this duration the WASM execution is interrupted via
/// wasmtime epoch interruption, and the provider returns an error
/// instead of blocking indefinitely.
const GUEST_CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// Configuration for constructing a `WasmProvider`.
#[derive(Debug, Clone)]
pub struct WasmProviderConfig {
    /// Unique provider ID (from config file).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Provider kind string (e.g. `"bitwarden-wasm"`).
    pub kind: String,
    /// Path to the `.wasm` file.
    pub wasm_path: String,
    /// Allowed HTTP hosts the plugin may contact (e.g. `["*.bitwarden.com"]`).
    pub allowed_hosts: Vec<String>,
    /// Filesystem paths the WASI sandbox may access.
    ///
    /// Each entry maps a host path to the guest-visible path.
    /// Prefix the host path with `ro:` for read-only access (recommended).
    /// Example: `("ro:/home/user/.local/share/keyrings", "/home/user/.local/share/keyrings")`
    pub allowed_paths: Vec<(String, std::path::PathBuf)>,
    /// Opaque key-value options forwarded to the guest `init` function.
    pub options: HashMap<String, serde_json::Value>,
    /// Host-side gate for offline caching.  When `false`, cache export and
    /// offline unlock are suppressed even if the guest declares
    /// `Capability::OfflineCache`.  Defaults to `true`.
    pub offline_cache: bool,
    /// TLS certificate verification mode for guest HTTP requests.
    pub tls_mode: rosec_core::config::TlsMode,
    /// TLS certificate verification mode for readiness probes.
    pub tls_mode_probe: rosec_core::config::TlsMode,
}

// ── WasmProvider ─────────────────────────────────────────────────

/// A `Provider` backed by an Extism WASM plugin.
///
/// All plugin calls go through a `Mutex<Plugin>` because `extism::Plugin`
/// is `Send + Sync` but `call` takes `&mut self`.
pub struct WasmProvider {
    config: WasmProviderConfig,
    plugin: Arc<Mutex<Plugin>>,
    /// Stored manifest for plugin recreation after a WASM trap.
    manifest: Manifest,
    /// Capabilities queried once from the guest at construction time.
    /// Leaked so we can return `&'static [Capability]` from the trait.
    capabilities: &'static [Capability],
    /// Attribute descriptors queried once from the guest at construction time.
    /// Leaked so we can return `&'static [AttributeDescriptor]` from the trait.
    attribute_descriptors: &'static [AttributeDescriptor],
    /// Auth fields queried once from the guest at construction time.
    auth_fields: &'static [AuthField],
    /// Registration info queried once from the guest at construction time.
    registration_info: Option<RegistrationInfo>,
    /// Readiness probes queried once from the guest after init.
    readiness_probes: Vec<crate::protocol::ReadinessProbe>,
    /// Callbacks registered by the daemon
    callbacks: std::sync::RwLock<ProviderCallbacks>,
    /// Cached timestamp of the last successful sync.
    last_sync_time: std::sync::Mutex<Option<chrono::DateTime<chrono::Utc>>>,
    /// Set `true` after a failed plugin recreation.  Prevents an infinite
    /// trap → recreate → trap loop.  While poisoned, all plugin calls
    /// immediately return `ProviderError::Unavailable` without touching
    /// the WASM instance.  Cleared on next successful `unlock` (which
    /// recreates the plugin from scratch anyway).
    poisoned: std::sync::atomic::AtomicBool,
    /// Cache encryption key — derived from password + machine_key + provider_id
    /// during unlock.  Held in memory while unlocked so that sync() can update
    /// the cache without needing the password again.  Zeroized on lock().
    cache_key: std::sync::Mutex<Option<crate::cache::CacheKey>>,
    /// Data-quality flag: true when in-memory data has not been confirmed
    /// against the remote.  See [`ProviderStatus::cached`] for semantics.
    cached: std::sync::atomic::AtomicBool,
    /// Timestamp of the last successful cache write-back to disk.
    last_cache_write: std::sync::Mutex<Option<std::time::SystemTime>>,
    /// SHA-256 hash of the last blob written to the cache file.
    /// Used to skip redundant writes when the guest state hasn't changed.
    last_cache_blob_hash: std::sync::Mutex<Option<[u8; 32]>>,
    /// Handle to the real-time notifications background task.
    /// Present when the provider is unlocked and declares `Capability::Notifications`.
    /// Dropped on lock (cancels the WebSocket connection).
    notifications_handle: std::sync::Mutex<Option<crate::notifications::NotificationsHandle>>,
}

impl std::fmt::Debug for WasmProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmProvider")
            .field("id", &self.config.id)
            .field("name", &self.config.name)
            .field("wasm_path", &self.config.wasm_path)
            .finish()
    }
}

impl WasmProvider {
    /// Create a new `WasmProvider` from config.
    ///
    /// Loads the WASM module, creates the Extism plugin, calls the guest
    /// `init` function, and eagerly queries `capabilities`,
    /// `attribute_descriptors`, `auth_fields`, and `registration_info`.
    ///
    /// The static-lifetime slices are created via `Box::leak`; this is
    /// acceptable because providers live for the process lifetime.
    pub fn new(config: WasmProviderConfig) -> Result<Self, ProviderError> {
        // Warn if the allowed-hosts list grants unrestricted network access.
        for host in &config.allowed_hosts {
            if host.trim() == "*" {
                warn!(
                    provider = %config.id,
                    wasm = %config.wasm_path,
                    "WASM plugin has unrestricted network access (allowed_hosts contains '*'). \
                     Consider restricting to specific hosts for security.",
                );
                break;
            }
        }

        let wasm = Wasm::file(&config.wasm_path);
        let mut manifest = Manifest::new([wasm])
            .with_allowed_hosts(config.allowed_hosts.iter().cloned())
            .with_timeout(GUEST_CALL_TIMEOUT)
            // Limit WASM linear memory to 256 MiB (4096 pages × 64 KiB/page).
            // Prevents a misbehaving plugin from consuming unbounded host memory.
            .with_memory_max(4096);

        // Pre-open filesystem paths so the WASI sandbox can access them.
        if config.allowed_paths.is_empty() {
            debug!(provider = %config.id, "no WASI allowed_paths configured");
        }
        for (src, dest) in &config.allowed_paths {
            debug!(
                provider = %config.id,
                src = %src,
                dest = %dest.display(),
                "pre-opening WASI path",
            );
            manifest = manifest.with_allowed_path(src.clone(), dest);
        }

        debug!(
            provider = %config.id,
            allowed_hosts = ?config.allowed_hosts,
            allowed_paths = config.allowed_paths.len(),
            "WASM manifest configured",
        );

        // Clone the manifest before consuming it so we can recreate the
        // plugin after a WASM trap (which corrupts the instance).
        let manifest = manifest;
        let host_fns = crate::host_http::build_http_host_functions(&config.tls_mode);
        let mut plugin = Plugin::new(&manifest, host_fns, true).map_err(|e| {
            ProviderError::Other(anyhow::anyhow!(
                "failed to load WASM plugin '{}': {e}",
                config.wasm_path,
            ))
        })?;

        // Call init to let the guest set up its internal state.
        init_guest(&mut plugin, &config, "init")?;

        // ── Eagerly query static metadata from the guest ─────────

        let capabilities = query_capabilities(&mut plugin, &config.id);
        let attribute_descriptors = query_attribute_descriptors(&mut plugin, &config.id);
        let auth_fields = query_auth_fields(&mut plugin, &config.id);
        let registration_info = query_registration_info(&mut plugin, &config.id);
        let readiness_probes = query_readiness_probes(&mut plugin, &config.id);

        debug!(
            provider = %config.id,
            caps = ?capabilities,
            attrs = attribute_descriptors.len(),
            auth = auth_fields.len(),
            reg = registration_info.is_some(),
            probes = readiness_probes.len(),
            "WASM provider initialised",
        );

        Ok(Self {
            config,
            plugin: Arc::new(Mutex::new(plugin)),
            manifest,
            capabilities,
            attribute_descriptors,
            auth_fields,
            registration_info,
            readiness_probes,
            callbacks: std::sync::RwLock::new(ProviderCallbacks::default()),
            last_sync_time: std::sync::Mutex::new(None),
            poisoned: std::sync::atomic::AtomicBool::new(false),
            cache_key: std::sync::Mutex::new(None),
            cached: std::sync::atomic::AtomicBool::new(false),
            last_cache_write: std::sync::Mutex::new(None),
            last_cache_blob_hash: std::sync::Mutex::new(None),
            notifications_handle: std::sync::Mutex::new(None),
        })
    }

    /// Recreate the WASM plugin from the stored manifest after a trap.
    ///
    /// After a WASM trap (timeout, OOM, host function error, guest panic),
    /// the plugin's linear memory and globals are left in a corrupted state.
    /// Extism's `Plugin::reset()` only clears allocation metadata, not the
    /// actual WASM memory.  The only reliable recovery is to create a fresh
    /// Plugin instance and re-run `init`.
    ///
    /// The recreated plugin starts in a locked state (no auth).
    fn recreate_plugin(
        manifest: &Manifest,
        config: &WasmProviderConfig,
    ) -> Result<Plugin, ProviderError> {
        let host_fns = crate::host_http::build_http_host_functions(&config.tls_mode);
        let mut plugin = Plugin::new(manifest, host_fns, true).map_err(|e| {
            ProviderError::Other(anyhow::anyhow!(
                "failed to recreate WASM plugin '{}': {e}",
                config.wasm_path,
            ))
        })?;

        // Re-run init with the same config.
        init_guest(&mut plugin, config, "re-init")?;

        Ok(plugin)
    }

    /// Recreate the plugin after a failed `plugin.call()`.
    ///
    /// In the Extism protocol, guest application errors (wrong password,
    /// not found, etc.) are returned as `Ok` responses with `resp.ok == false`
    /// in the JSON body.  An `Err` from `plugin.call()` only occurs when
    /// something went wrong at the WASM execution level: a trap (timeout,
    /// OOM, host function error, guest panic), a serialization failure, or
    /// a missing function.
    ///
    /// In all of these cases the plugin's linear memory and globals may be
    /// in an undefined state.  Rather than trying to classify which errors
    /// are "real" traps via brittle string matching on wasmtime internals,
    /// we unconditionally recreate the plugin after any `plugin.call()`
    /// failure.  This is safe because:
    ///
    /// - The plugin restarts in a clean locked state (same as fresh boot)
    /// - Serialization / missing-function errors won't be fixed by retrying
    ///   with the same plugin anyway
    /// - The cost (~50-100ms) is acceptable for an error path
    fn recreate_after_call_error(&self, plugin: &mut Plugin, err: &ProviderError) {
        warn!(
            provider = %self.config.id,
            error = %err,
            "WASM plugin call failed, recreating instance",
        );
        match Self::recreate_plugin(&self.manifest, &self.config) {
            Ok(new_plugin) => {
                *plugin = new_plugin;
                self.poisoned
                    .store(false, std::sync::atomic::Ordering::Release);
                debug!(
                    provider = %self.config.id,
                    "plugin instance recreated successfully (now locked)",
                );
            }
            Err(recreate_err) => {
                self.poisoned
                    .store(true, std::sync::atomic::Ordering::Release);
                error!(
                    provider = %self.config.id,
                    "failed to recreate plugin, instance is poisoned: {recreate_err}",
                );
            }
        }
    }

    /// Return `Err(Unavailable)` if the plugin is poisoned (recreation
    /// failed after a previous WASM trap).
    fn check_poisoned(&self) -> Result<(), ProviderError> {
        if self.poisoned.load(std::sync::atomic::Ordering::Acquire) {
            Err(ProviderError::Unavailable(
                "WASM plugin is poisoned after failed recreation".into(),
            ))
        } else {
            Ok(())
        }
    }

    /// Call a guest function with JSON input, recreating the plugin if
    /// `plugin.call()` failed (indicating a WASM trap or execution error).
    fn call_json<I: Serialize, O: serde::de::DeserializeOwned>(
        &self,
        plugin: &mut Plugin,
        func: &str,
        input: &I,
    ) -> Result<O, ProviderError> {
        self.check_poisoned()?;
        let (result, outcome) = call_guest_json(plugin, func, input);
        if outcome == CallOutcome::PluginCallFailed
            && let Err(ref e) = result
        {
            self.recreate_after_call_error(plugin, e);
        }
        result
    }

    /// Call a guest function with sensitive JSON input, recreating the
    /// plugin if `plugin.call()` failed.  Zeroizes the serialized input
    /// regardless of success or failure.
    fn call_json_sensitive<I: Serialize, O: serde::de::DeserializeOwned>(
        &self,
        plugin: &mut Plugin,
        func: &str,
        input: &I,
    ) -> Result<O, ProviderError> {
        self.check_poisoned()?;
        let (result, outcome) = call_guest_json_sensitive(plugin, func, input);
        if outcome == CallOutcome::PluginCallFailed
            && let Err(ref e) = result
        {
            self.recreate_after_call_error(plugin, e);
        }
        result
    }

    /// Call a guest function with no input, recreating the plugin if
    /// `plugin.call()` failed.
    fn call_json_no_input<O: serde::de::DeserializeOwned>(
        &self,
        plugin: &mut Plugin,
        func: &str,
    ) -> Result<O, ProviderError> {
        self.check_poisoned()?;
        let (result, outcome) = call_guest_json_no_input(plugin, func);
        if outcome == CallOutcome::PluginCallFailed
            && let Err(ref e) = result
        {
            self.recreate_after_call_error(plugin, e);
        }
        result
    }

    /// Evaluate all readiness probes before attempting unlock.
    ///
    /// Each probe is checked against the manifest's `allowed_hosts` and
    /// executed natively (no WASM involvement).  Uses exponential backoff
    /// if any probe fails (unless `quick` mode is requested).
    ///
    /// When `quick` is `true`, a single probe attempt is made with a
    /// reduced timeout (2 s).  This is used for providers with an offline
    /// cache — there is no point retrying for ~100 s when we will fall
    /// back to cached data anyway — and for background sync operations.
    ///
    /// **Timeout enforcement:** `ureq`'s `timeout_global` does not
    /// reliably interrupt a hung TCP connect (it depends on OS-level
    /// socket timeouts, which can be 60-120 s on Linux).  To guarantee
    /// the timeout, each probe is run inside `spawn_blocking` wrapped
    /// with `tokio::time::timeout`.
    ///
    /// Returns `Ok(())` when all probes pass, or `Err` if attempts are
    /// exhausted.
    async fn wait_for_readiness(&self, quick: bool) -> Result<(), ProviderError> {
        if self.readiness_probes.is_empty() {
            return Ok(());
        }

        let max_attempts: u32 = if quick { 1 } else { 8 };
        // In quick mode, enforce a hard 3 s wall-clock ceiling per probe.
        // In normal mode, let the guest-declared timeout (clamped to 30 s
        // by MAX_PROBE_TIMEOUT_SECS) govern.
        let hard_timeout: Duration = if quick {
            Duration::from_secs(3)
        } else {
            Duration::from_secs(MAX_PROBE_TIMEOUT_SECS + 1)
        };
        let probe_timeout_override: Option<Duration> = if quick {
            Some(Duration::from_secs(2))
        } else {
            None
        };
        let initial_delay = Duration::from_millis(500);
        let max_delay = Duration::from_secs(30);
        let mut delay = initial_delay;

        let allowed_hosts: Vec<String> = self
            .manifest
            .allowed_hosts
            .as_deref()
            .unwrap_or_default()
            .to_vec();

        for attempt in 1..=max_attempts {
            let mut all_ready = true;
            let mut last_failure = String::new();

            for probe in &self.readiness_probes {
                let probe = probe.clone();
                let hosts = allowed_hosts.clone();
                let tls_mode = self.config.tls_mode_probe.clone();
                let result = tokio::time::timeout(
                    hard_timeout,
                    tokio::task::spawn_blocking(move || {
                        evaluate_probe(&probe, &hosts, probe_timeout_override, &tls_mode)
                    }),
                )
                .await;

                match result {
                    Ok(Ok(Ok(()))) => {}
                    Ok(Ok(Err(reason))) => {
                        all_ready = false;
                        last_failure = reason;
                        break;
                    }
                    Ok(Err(join_err)) => {
                        all_ready = false;
                        last_failure = format!("probe task panicked: {join_err}");
                        break;
                    }
                    Err(_elapsed) => {
                        all_ready = false;
                        last_failure = format!("probe timed out after {}s", hard_timeout.as_secs());
                        break;
                    }
                }
            }

            if all_ready {
                if attempt > 1 {
                    debug!(
                        provider = %self.config.id,
                        attempt,
                        "all readiness probes passed",
                    );
                }
                return Ok(());
            }

            if attempt == max_attempts {
                break;
            }

            debug!(
                provider = %self.config.id,
                attempt,
                delay_ms = delay.as_millis() as u64,
                reason = %last_failure,
                "readiness probe failed, backing off",
            );

            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(max_delay);
        }

        Err(ProviderError::Unavailable(format!(
            "readiness probes not satisfied after {max_attempts} attempt{}",
            if max_attempts == 1 { "" } else { "s" },
        )))
    }

    /// Attempt offline unlock by restoring the cache file.
    ///
    /// Called when readiness probes fail and offline caching is enabled
    /// (both `Capability::OfflineCache` and `config.offline_cache`).
    async fn unlock_from_cache(&self) -> Result<(), ProviderError> {
        use crate::protocol::{RestoreCacheRequest, SimpleResponse};

        // Read and decrypt the cache file while holding the cache_key lock.
        // All synchronous work happens in this block; the lock is released
        // before any `.await`.
        let (blob_b64, cache_time) = {
            let guard = self.cache_key.lock().unwrap_or_else(|e| e.into_inner());
            let cache_key = guard.as_ref().ok_or_else(|| {
                ProviderError::Other(anyhow::anyhow!(
                    "cache key not derived — cannot attempt offline unlock"
                ))
            })?;

            let max_age = crate::cache::DEFAULT_MAX_CACHE_AGE;
            let (plaintext, cache_time) =
                crate::cache::read_cache_file(&self.config.id, cache_key, max_age)?.ok_or_else(
                    || ProviderError::Unavailable("no offline cache available".to_string()),
                )?;

            let blob_b64 = String::from_utf8(plaintext.to_vec()).map_err(|e| {
                ProviderError::Other(anyhow::anyhow!("cache blob is not valid UTF-8: {e}"))
            })?;

            (blob_b64, cache_time)
        };
        // guard is dropped here — safe to await.

        // Feed the blob back to the guest.
        let mut plugin = self.plugin.lock().await;
        let restore_req = RestoreCacheRequest { blob_b64 };
        let resp: SimpleResponse = self.call_json(&mut plugin, "restore_cache", &restore_req)?;

        if !resp.ok {
            return Err(map_guest_error(resp.error, resp.error_kind));
        }

        // Offline unlock succeeded — mark as cached (data unconfirmed).
        self.cached
            .store(true, std::sync::atomic::Ordering::Relaxed);

        // Set last_sync to the cache timestamp so consumers can assess staleness.
        if let Ok(mut guard) = self.last_sync_time.lock() {
            *guard = Some(chrono::DateTime::<chrono::Utc>::from(cache_time));
        }

        debug!(
            provider = %self.config.id,
            "offline unlock from cache succeeded"
        );

        self.fire_callback(|cbs| {
            if let Some(ref cb) = cbs.on_unlocked {
                cb();
            }
        });

        Ok(())
    }

    /// Export the guest's cache blob and persist it to disk.
    ///
    /// Best-effort: logs warnings on failure but does not propagate errors
    /// (cache is a nice-to-have, not a hard requirement for the unlock/sync
    /// path to succeed).
    fn try_export_cache(&self, plugin: &mut Plugin) {
        use crate::protocol::ExportCacheResponse;
        use sha2::{Digest, Sha256};

        if !plugin.function_exists("export_cache") {
            return;
        }

        let resp: ExportCacheResponse = match call_guest_json_no_input(plugin, "export_cache").0 {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    provider = %self.config.id,
                    "export_cache call failed: {e}"
                );
                return;
            }
        };

        if !resp.ok {
            warn!(
                provider = %self.config.id,
                error = ?resp.error,
                "guest export_cache returned error"
            );
            return;
        }

        let Some(blob_b64) = resp.blob_b64 else {
            warn!(
                provider = %self.config.id,
                "guest export_cache returned ok but no blob"
            );
            return;
        };

        // Skip the write if the blob hasn't changed since the last write.
        let blob_bytes = blob_b64.as_bytes();
        let blob_hash: [u8; 32] = Sha256::digest(blob_bytes).into();
        {
            let prev_hash = self
                .last_cache_blob_hash
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if prev_hash.as_ref() == Some(&blob_hash) {
                debug!(
                    provider = %self.config.id,
                    "cache blob unchanged — skipping write"
                );
                return;
            }
        }

        let cache_key_guard = self.cache_key.lock().unwrap_or_else(|e| e.into_inner());
        let Some(cache_key) = cache_key_guard.as_ref() else {
            debug!(
                provider = %self.config.id,
                "no cache key — skipping cache write"
            );
            return;
        };

        match crate::cache::write_cache_file(&self.config.id, cache_key, blob_bytes) {
            Ok(write_time) => {
                *self
                    .last_cache_write
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(write_time);
                *self
                    .last_cache_blob_hash
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(blob_hash);
            }
            Err(e) => {
                warn!(
                    provider = %self.config.id,
                    "failed to write cache file: {e}"
                );
            }
        }
    }
}

impl WasmProvider {
    /// Whether offline caching is both supported by the guest and enabled by
    /// the host configuration.
    ///
    /// The guest declares `Capability::OfflineCache` to signal it *supports*
    /// caching.  The host config `offline_cache` field (per-provider, default
    /// `true`) is the user-facing gate.  Both must be true for any cache
    /// operation (export, import, offline unlock fallback) to proceed.
    fn offline_cache_enabled(&self) -> bool {
        self.config.offline_cache && self.capabilities().contains(&Capability::OfflineCache)
    }

    /// Fire a provider callback if one is registered.
    ///
    /// Silently does nothing if the callbacks lock is poisoned or the
    /// specific callback is `None`.
    fn fire_callback(&self, f: impl FnOnce(&ProviderCallbacks)) {
        if let Ok(cbs) = self.callbacks.read() {
            f(&cbs);
        }
    }

    /// Start or restart the notifications background task.
    ///
    /// Drops any existing handle (cancelling the old connection), then spawns
    /// a new task that calls `get_notification_config` on the guest, connects
    /// the WebSocket, and forwards frames via `parse_notification`.
    ///
    /// No-op if the provider doesn't declare `Capability::Notifications`.
    fn start_notifications(&self) {
        if !self.capabilities().contains(&Capability::Notifications) {
            return;
        }

        // Drop existing handle first (cancels old connection).
        *self
            .notifications_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;

        // Clone the callbacks for the notification task.
        let on_sync_nudge = self
            .callbacks
            .read()
            .ok()
            .and_then(|cbs| cbs.on_remote_sync_nudge.clone());
        let on_lock_nudge = self
            .callbacks
            .read()
            .ok()
            .and_then(|cbs| cbs.on_remote_lock_nudge.clone());

        let config = crate::notifications::NotificationsConfig {
            provider_id: self.config.id.clone(),
            plugin: Arc::clone(&self.plugin),
            readiness_probes: self.readiness_probes.clone(),
            allowed_hosts: self.config.allowed_hosts.clone(),
            tls_mode_probe: self.config.tls_mode_probe.clone(),
            on_sync_nudge,
            on_lock_nudge,
        };

        let handle = crate::notifications::start(config);
        *self
            .notifications_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(handle);
    }

    /// Stop the notifications background task (if running).
    fn stop_notifications(&self) {
        *self
            .notifications_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Derive the cache key from `password` + machine key + provider ID and
    /// store it in `self.cache_key`.
    ///
    /// Best-effort: logs a warning on failure (machine key missing, HKDF error)
    /// but does not propagate — callers that need the key (e.g.
    /// `unlock_from_cache`) will detect `None` and return a proper error.
    fn derive_and_store_cache_key(&self, password: &str) {
        let machine_key = match rosec_core::machine_key::load_or_create() {
            Ok(mk) => mk,
            Err(e) => {
                warn!(
                    provider = %self.config.id,
                    "cannot load machine key for cache key derivation: {e}"
                );
                return;
            }
        };

        match crate::cache::derive_cache_key(&machine_key, password, &self.config.id) {
            Ok(key) => {
                *self.cache_key.lock().unwrap_or_else(|e| e.into_inner()) = Some(key);
            }
            Err(e) => {
                warn!(
                    provider = %self.config.id,
                    "cache key derivation failed: {e}"
                );
            }
        }
    }
}

// ── Provider trait impl ──────────────────────────────────────────

#[async_trait]
impl Provider for WasmProvider {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    fn kind(&self) -> &str {
        &self.config.kind
    }

    fn capabilities(&self) -> &'static [Capability] {
        self.capabilities
    }

    fn available_attributes(&self) -> &'static [AttributeDescriptor] {
        self.attribute_descriptors
    }

    fn auth_fields(&self) -> &'static [AuthField] {
        self.auth_fields
    }

    fn registration_info(&self) -> Option<RegistrationInfo> {
        self.registration_info
    }

    fn set_event_callbacks(&self, callbacks: ProviderCallbacks) -> Result<(), ProviderError> {
        let mut cbs = self
            .callbacks
            .write()
            .map_err(|e| ProviderError::Other(anyhow::anyhow!("callback lock poisoned: {e}")))?;
        *cbs = callbacks;
        Ok(())
    }

    fn password_field(&self) -> AuthField {
        // If the guest declared auth fields, use the first password-kind
        // field; otherwise fall back to the default.
        self.auth_fields
            .iter()
            .find(|f| f.kind == AuthFieldKind::Password)
            .copied()
            .unwrap_or(AuthField {
                id: "password",
                label: "Master Password",
                placeholder: "Enter your master password",
                required: true,
                kind: AuthFieldKind::Password,
            })
    }

    async fn status(&self) -> Result<ProviderStatus, ProviderError> {
        let mut plugin = self.plugin.lock().await;
        let resp: StatusResponse = self.call_json_no_input(&mut plugin, "status")?;
        Ok(ProviderStatus {
            locked: resp.locked,
            last_sync: resp
                .last_sync_epoch_secs
                .map(|s| UNIX_EPOCH + Duration::from_secs(s)),
            cached: self.cached.load(std::sync::atomic::Ordering::Relaxed),
            offline_cache: self.offline_cache_enabled(),
            last_cache_write: *self
                .last_cache_write
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        })
    }

    async fn unlock(&self, input: UnlockInput) -> Result<(), ProviderError> {
        // Extract the password (needed for credential persistence key derivation
        // and cache key derivation).
        let password_ref: &Zeroizing<String> = match &input {
            UnlockInput::Password(pw) => pw,
            UnlockInput::WithRegistration { password, .. }
            | UnlockInput::WithAuth { password, .. } => password,
        };

        let has_offline_cache = self.offline_cache_enabled();

        // Try readiness probes.  If they fail and we have a cache, attempt
        // offline unlock instead of propagating the error immediately.
        // Use quick mode for cache-capable providers — no point waiting
        // ~100 s on exponential backoff when we will fall back to cache.
        let readiness_err = match self.wait_for_readiness(has_offline_cache).await {
            Ok(()) => None,
            Err(e) => {
                if has_offline_cache {
                    info!(
                        provider = %self.config.id,
                        "readiness probes failed, attempting offline cache fallback: {e}"
                    );
                    Some(e)
                } else {
                    return Err(e);
                }
            }
        };

        if let Some(probe_err) = readiness_err {
            // Offline unlock path — derive the cache key now so we can
            // decrypt the cache file.  The key is only stored on success
            // (unlock_from_cache will read it from self.cache_key).
            self.derive_and_store_cache_key(password_ref.as_str());
            return self.unlock_from_cache().await.map_err(|cache_err| {
                // Surface both the original probe failure and the cache
                // failure so the user gets actionable diagnostic context.
                ProviderError::Unavailable(format!(
                    "readiness probe failed: {probe_err}; \
                     offline cache also unavailable: {cache_err}"
                ))
            });
        }

        // ── Online unlock path ──────────────────────────────────────

        let mut req = match &input {
            UnlockInput::Password(pw) => UnlockRequest {
                password: pw.as_str().to_owned(),
                registration_fields: None,
                auth_fields: None,
            },
            UnlockInput::WithRegistration {
                password,
                registration_fields,
            } => UnlockRequest {
                password: password.as_str().to_owned(),
                registration_fields: Some(
                    registration_fields
                        .iter()
                        .map(|(k, v)| (k.clone(), v.as_str().to_owned()))
                        .collect(),
                ),
                auth_fields: None,
            },
            UnlockInput::WithAuth {
                password,
                auth_fields,
            } => UnlockRequest {
                password: password.as_str().to_owned(),
                registration_fields: None,
                auth_fields: Some(
                    auth_fields
                        .iter()
                        .map(|(k, v)| (k.clone(), v.as_str().to_owned()))
                        .collect(),
                ),
            },
        };

        let has_registration = req.registration_fields.is_some();
        let mut plugin = self.plugin.lock().await;

        let result: Result<SimpleResponse, ProviderError> =
            self.call_json_sensitive(&mut plugin, "unlock", &req);

        // If the guest requires registration and none was provided, try
        // loading stored credentials from a previous session.
        let result = match result {
            Ok(ref resp) if !resp.ok => {
                let is_reg_required = resp
                    .error_kind
                    .as_ref()
                    .is_some_and(|k| matches!(k, ErrorKind::RegistrationRequired));
                if is_reg_required && !has_registration {
                    match crate::wasm_cred::load(&self.config.id, password_ref.as_str()) {
                        Ok(Some(stored_fields)) => {
                            debug!(
                                provider = %self.config.id,
                                "loaded stored credentials, retrying unlock with registration"
                            );
                            // Pass the stored fields directly to the guest — they use
                            // whatever field names the provider registered with (e.g.
                            // "access_token" for SM, "client_id"/"client_secret" for PM).
                            let reg_fields_plain: HashMap<String, String> = stored_fields
                                .iter()
                                .map(|(k, v)| (k.clone(), v.as_str().to_owned()))
                                .collect();

                            let mut retry_req = UnlockRequest {
                                password: password_ref.as_str().to_owned(),
                                registration_fields: Some(reg_fields_plain),
                                auth_fields: None,
                            };

                            let retry_result: Result<SimpleResponse, ProviderError> =
                                self.call_json_sensitive(&mut plugin, "unlock", &retry_req);

                            retry_req.password.zeroize();
                            if let Some(ref mut fields) = retry_req.registration_fields {
                                for v in fields.values_mut() {
                                    v.zeroize();
                                }
                            }

                            retry_result
                        }
                        Ok(None) => {
                            debug!(
                                provider = %self.config.id,
                                "no stored credentials found"
                            );
                            result
                        }
                        Err(e) => {
                            // Decryption failed — most likely a wrong password.
                            // Do NOT clear stored credentials (the user may just
                            // have mistyped the password).  Return AuthFailed so
                            // the caller reports "wrong password" rather than
                            // entering the registration flow.
                            warn!(
                                provider = %self.config.id,
                                "failed to decrypt stored credentials: {e}"
                            );
                            Ok(SimpleResponse {
                                ok: false,
                                error: Some("wrong password".to_string()),
                                error_kind: Some(ErrorKind::AuthFailed),
                                two_factor_methods: None,
                            })
                        }
                    }
                } else {
                    result
                }
            }
            _ => result,
        };

        // Zeroize the original request fields.
        req.password.zeroize();
        if let Some(ref mut fields) = req.registration_fields {
            for v in fields.values_mut() {
                v.zeroize();
            }
        }
        if let Some(ref mut fields) = req.auth_fields {
            for v in fields.values_mut() {
                v.zeroize();
            }
        }

        let resp = result?;
        if resp.ok {
            // If registration fields were provided, persist them for next time.
            if has_registration
                && let UnlockInput::WithRegistration {
                    registration_fields,
                    ..
                } = &input
            {
                // Save all registration fields so we can restore them on the
                // next unlock without prompting the user again.
                match crate::wasm_cred::save(
                    &self.config.id,
                    password_ref.as_str(),
                    registration_fields,
                ) {
                    Ok(()) => {
                        debug!(
                            provider = %self.config.id,
                            "saved registration credentials"
                        );
                    }
                    Err(e) => {
                        warn!(
                            provider = %self.config.id,
                            "failed to save registration credentials: {e}"
                        );
                    }
                }
            }

            // Online unlock succeeded — data is confirmed live.
            self.cached
                .store(false, std::sync::atomic::Ordering::Relaxed);

            // Update the cached last-sync timestamp (unlock = first sync).
            if let Ok(mut guard) = self.last_sync_time.lock() {
                *guard = Some(chrono::Utc::now());
            }

            // Export and persist cache for offline use.
            if has_offline_cache {
                info!(provider = %self.config.id, "deriving cache key for offline cache");
                self.derive_and_store_cache_key(password_ref.as_str());
                self.try_export_cache(&mut plugin);
            }

            // Start real-time notifications (if the guest supports it).
            // Must be called after unlock so the guest has a valid token.
            self.start_notifications();

            self.fire_callback(|cbs| {
                if let Some(ref cb) = cbs.on_unlocked {
                    cb();
                }
            });
            Ok(())
        } else if resp
            .error_kind
            .as_ref()
            .is_some_and(|k| matches!(k, ErrorKind::TwoFactorRequired))
        {
            Err(map_guest_2fa_error(resp.error, resp.two_factor_methods))
        } else {
            Err(map_guest_error(resp.error, resp.error_kind))
        }
    }

    fn last_synced_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.last_sync_time.lock().ok().and_then(|g| *g)
    }

    async fn lock(&self) -> Result<(), ProviderError> {
        // Stop notifications first (drops WebSocket before clearing auth).
        self.stop_notifications();

        let mut plugin = self.plugin.lock().await;
        let resp: SimpleResponse = self.call_json_no_input(&mut plugin, "lock")?;
        if resp.ok {
            // Zeroize cache key and reset cache state.
            *self.cache_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
            self.cached
                .store(false, std::sync::atomic::Ordering::Relaxed);
            *self
                .last_cache_blob_hash
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
            // Note: last_cache_write is intentionally NOT reset — it reflects
            // when the file was last written, which is useful even after lock.

            self.fire_callback(|cbs| {
                if let Some(ref cb) = cbs.on_locked {
                    cb();
                }
            });
            Ok(())
        } else {
            Err(map_guest_error(resp.error, resp.error_kind))
        }
    }

    async fn sync(&self) -> Result<(), ProviderError> {
        // Background sync — use quick mode so we don't block for ~100 s
        // on exponential backoff when the network is down.
        let readiness_result = self.wait_for_readiness(true).await;
        if let Err(e) = readiness_result {
            // Network unavailable — mark data as unconfirmed.
            self.cached
                .store(true, std::sync::atomic::Ordering::Relaxed);
            self.fire_callback(|cbs| {
                if let Some(ref cb) = cbs.on_sync_failed {
                    cb();
                }
            });
            return Err(e);
        }

        // Snapshot the cached flag before sync — if we were cached and
        // sync succeeds, we need to (re)start notifications because
        // the access token was refreshed during recovery.
        let was_cached = self.cached.load(std::sync::atomic::Ordering::Relaxed);

        let mut plugin = self.plugin.lock().await;
        if !plugin.function_exists("sync") {
            return Err(ProviderError::NotSupported);
        }
        let resp: SimpleResponse = self.call_json_no_input(&mut plugin, "sync")?;
        if resp.ok {
            // Sync succeeded — data confirmed live.
            self.cached
                .store(false, std::sync::atomic::Ordering::Relaxed);

            // Update the cached last-sync timestamp.
            if let Ok(mut guard) = self.last_sync_time.lock() {
                *guard = Some(chrono::Utc::now());
            }

            // Export and persist cache for offline use.
            if self.offline_cache_enabled() {
                self.try_export_cache(&mut plugin);
            }

            // Drop the plugin lock before starting notifications (which
            // needs to acquire it to call get_notification_config).
            drop(plugin);

            // (Re)start notifications if we just recovered from cached mode
            // (token was refreshed) or if no notification task is running.
            if was_cached {
                self.start_notifications();
            }

            self.fire_callback(|cbs| {
                if let Some(ref cb) = cbs.on_sync_succeeded {
                    cb(true);
                }
            });
            Ok(())
        } else {
            // Sync call failed — mark data as unconfirmed.
            self.cached
                .store(true, std::sync::atomic::Ordering::Relaxed);
            self.fire_callback(|cbs| {
                if let Some(ref cb) = cbs.on_sync_failed {
                    cb();
                }
            });
            Err(map_guest_error(resp.error, resp.error_kind))
        }
    }

    async fn list_items(&self) -> Result<Vec<ItemMeta>, ProviderError> {
        let mut plugin = self.plugin.lock().await;
        let resp: ItemListResponse = self.call_json_no_input(&mut plugin, "list_items")?;
        if !resp.ok {
            return Err(map_guest_error(resp.error, resp.error_kind));
        }
        Ok(resp
            .items
            .into_iter()
            .map(|w| to_item_meta(w, &self.config.id))
            .collect())
    }

    async fn search(&self, attrs: &Attributes) -> Result<Vec<ItemMeta>, ProviderError> {
        let req = SearchRequest {
            attributes: attrs.clone(),
        };
        let mut plugin = self.plugin.lock().await;
        let resp: ItemListResponse = self.call_json(&mut plugin, "search", &req)?;
        if !resp.ok {
            return Err(map_guest_error(resp.error, resp.error_kind));
        }
        Ok(resp
            .items
            .into_iter()
            .map(|w| to_item_meta(w, &self.config.id))
            .collect())
    }

    async fn get_item_attributes(&self, id: &str) -> Result<ItemAttributes, ProviderError> {
        let req = ItemIdRequest { id: id.to_owned() };
        let mut plugin = self.plugin.lock().await;
        let resp: ItemAttributesResponse =
            self.call_json(&mut plugin, "get_item_attributes", &req)?;
        if !resp.ok {
            return Err(map_guest_error(resp.error, resp.error_kind));
        }
        Ok(ItemAttributes {
            public: resp.public,
            secret_names: resp.secret_names,
        })
    }

    async fn get_secret_attr(&self, id: &str, attr: &str) -> Result<SecretBytes, ProviderError> {
        let req = SecretAttrRequest {
            id: id.to_owned(),
            attr: attr.to_owned(),
        };
        let mut plugin = self.plugin.lock().await;
        let resp: SecretAttrResponse = self.call_json(&mut plugin, "get_secret_attr", &req)?;
        if !resp.ok {
            return Err(map_guest_error(resp.error, resp.error_kind));
        }
        let mut b64 = resp.value_b64.ok_or(ProviderError::NotFound)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| ProviderError::Other(anyhow::anyhow!("invalid base64 from guest: {e}")));
        // Zeroize the base64 string — it contained the secret in encoded form.
        b64.zeroize();
        Ok(SecretBytes::new(bytes?))
    }

    async fn list_ssh_keys(&self) -> Result<Vec<SshKeyMeta>, ProviderError> {
        let mut plugin = self.plugin.lock().await;
        if !plugin.function_exists("list_ssh_keys") {
            return Ok(Vec::new());
        }
        let resp: SshKeyListResponse = self.call_json_no_input(&mut plugin, "list_ssh_keys")?;
        if !resp.ok {
            return Err(map_guest_error(resp.error, resp.error_kind));
        }
        Ok(resp
            .keys
            .into_iter()
            .map(|w| to_ssh_key_meta(w, &self.config.id))
            .collect())
    }

    async fn get_ssh_private_key(&self, id: &str) -> Result<SshPrivateKeyMaterial, ProviderError> {
        let req = SshPrivateKeyRequest {
            item_id: id.to_owned(),
        };
        let mut plugin = self.plugin.lock().await;
        if !plugin.function_exists("get_ssh_private_key") {
            return Err(ProviderError::NotSupported);
        }
        let resp: SshPrivateKeyResponse =
            self.call_json(&mut plugin, "get_ssh_private_key", &req)?;
        if !resp.ok {
            return Err(map_guest_error(resp.error, resp.error_kind));
        }
        let pem = resp.pem.ok_or(ProviderError::NotFound)?;
        Ok(SshPrivateKeyMaterial {
            pem: Zeroizing::new(pem),
        })
    }

    /// Check whether the remote has changed since the last sync.
    ///
    /// If the guest exports `check_remote_changed`, delegate to it with an
    /// ISO-8601 timestamp derived from `last_synced_at()`.  This allows
    /// SM guests to use the lightweight delta-sync endpoint instead of a
    /// full re-fetch.
    ///
    /// If the guest does not export the function, falls back to the trait
    /// default (`Ok(true)` — assume changed, trigger a full sync).
    async fn check_remote_changed(&self) -> Result<bool, ProviderError> {
        // Check if the guest supports this function (requires plugin lock).
        // Build the ISO-8601 timestamp from the cached last_sync_time before
        // acquiring the plugin lock to avoid holding two locks simultaneously.
        let iso8601 = match self.last_synced_at() {
            Some(dt) => dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            None => {
                // No prior sync — assume changed.
                return Ok(true);
            }
        };

        self.wait_for_readiness(true).await?;

        let mut plugin = self.plugin.lock().await;
        if !plugin.function_exists("check_remote_changed") {
            // No guest support — assume changed (safe default).
            return Ok(true);
        }

        let req = crate::protocol::CheckRemoteChangedRequest {
            last_synced_iso8601: iso8601,
        };

        let resp: crate::protocol::CheckRemoteChangedResponse =
            self.call_json(&mut plugin, "check_remote_changed", &req)?;

        if !resp.ok {
            // On guest error, assume changed so the host falls back to full sync.
            debug!(provider = %self.config.id, error = ?resp.error,
                "check_remote_changed guest error, assuming changed");
            return Ok(true);
        }

        Ok(resp.has_changes)
    }
}

// ── Eager metadata queries (called during new()) ─────────────────

/// Query capabilities from the guest, leak into `&'static [Capability]`.
fn query_capabilities(plugin: &mut Plugin, provider_id: &str) -> &'static [Capability] {
    if !plugin.function_exists("capabilities") {
        return &[];
    }
    match call_guest_json_no_input::<CapabilitiesResponse>(plugin, "capabilities").0 {
        Ok(resp) => {
            let caps: Vec<Capability> = resp
                .capabilities
                .iter()
                .filter_map(|s| parse_capability(s))
                .collect();
            if caps.is_empty() {
                &[]
            } else {
                Box::leak(caps.into_boxed_slice())
            }
        }
        Err(e) => {
            warn!(provider = %provider_id, "capabilities call failed: {e}");
            &[]
        }
    }
}

/// Query attribute descriptors from the guest, leak into `&'static [AttributeDescriptor]`.
fn query_attribute_descriptors(
    plugin: &mut Plugin,
    provider_id: &str,
) -> &'static [AttributeDescriptor] {
    if !plugin.function_exists("attribute_descriptors") {
        return &[];
    }
    match call_guest_json_no_input::<crate::protocol::AttributeDescriptorsResponse>(
        plugin,
        "attribute_descriptors",
    )
    .0
    {
        Ok(resp) => {
            let descs: Vec<AttributeDescriptor> = resp
                .descriptors
                .into_iter()
                .map(leak_attribute_descriptor)
                .collect();
            if descs.is_empty() {
                &[]
            } else {
                Box::leak(descs.into_boxed_slice())
            }
        }
        Err(e) => {
            warn!(provider = %provider_id, "attribute_descriptors call failed: {e}");
            &[]
        }
    }
}

/// Query auth fields from the guest, leak into `&'static [AuthField]`.
fn query_auth_fields(plugin: &mut Plugin, provider_id: &str) -> &'static [AuthField] {
    if !plugin.function_exists("auth_fields") {
        return &[];
    }
    match call_guest_json_no_input::<AuthFieldsResponse>(plugin, "auth_fields").0 {
        Ok(resp) => {
            let fields: Vec<AuthField> = resp.fields.into_iter().map(leak_auth_field).collect();
            if fields.is_empty() {
                &[]
            } else {
                Box::leak(fields.into_boxed_slice())
            }
        }
        Err(e) => {
            warn!(provider = %provider_id, "auth_fields call failed: {e}");
            &[]
        }
    }
}

/// Query registration info from the guest, leak strings into `&'static`.
fn query_registration_info(plugin: &mut Plugin, provider_id: &str) -> Option<RegistrationInfo> {
    if !plugin.function_exists("registration_info") {
        return None;
    }
    match call_guest_json_no_input::<RegistrationInfoResponse>(plugin, "registration_info").0 {
        Ok(resp) if resp.has_registration => {
            let instructions: &'static str = resp
                .instructions
                .map(|s| &*Box::leak(s.into_boxed_str()))
                .unwrap_or("");
            let fields: &'static [AuthField] = if resp.fields.is_empty() {
                &[]
            } else {
                let leaked: Vec<AuthField> = resp.fields.into_iter().map(leak_auth_field).collect();
                Box::leak(leaked.into_boxed_slice())
            };
            Some(RegistrationInfo {
                instructions,
                fields,
            })
        }
        Ok(_) => None,
        Err(e) => {
            warn!(provider = %provider_id, "registration_info call failed: {e}");
            None
        }
    }
}

/// Query readiness probes from the guest (called during `new()`).
fn query_readiness_probes(
    plugin: &mut Plugin,
    provider_id: &str,
) -> Vec<crate::protocol::ReadinessProbe> {
    if !plugin.function_exists("readiness_probes") {
        return Vec::new();
    }
    match call_guest_json_no_input::<crate::protocol::ReadinessProbesResponse>(
        plugin,
        "readiness_probes",
    )
    .0
    {
        Ok(resp) => {
            debug!(
                provider = %provider_id,
                count = resp.probes.len(),
                "queried readiness probes from guest",
            );
            resp.probes
        }
        Err(e) => {
            warn!(provider = %provider_id, "readiness_probes call failed: {e}");
            Vec::new()
        }
    }
}

// ── Readiness probe evaluation ───────────────────────────────────

/// Check whether a probe target's hostname is in the allowed hosts list.
///
/// Uses the same glob matching as Extism's built-in HTTP host function.
fn is_host_allowed(hostname: &str, allowed_hosts: &[String]) -> bool {
    allowed_hosts
        .iter()
        .any(|pattern| match glob::Pattern::new(pattern) {
            Ok(pat) => pat.matches(hostname),
            Err(_) => pattern == hostname,
        })
}

/// Maximum timeout for any single probe, regardless of what the guest
/// declares.  Prevents a malicious guest from setting `timeout_secs` to
/// `u32::MAX` and blocking the host thread for years.
const MAX_PROBE_TIMEOUT_SECS: u64 = 30;

/// Evaluate a single readiness probe natively on the host.
///
/// Returns `Ok(())` if the probe passes, or `Err(reason)` with a
/// human-readable explanation of why it failed.
///
/// When `timeout_override` is `Some(d)`, the probe timeout is clamped to
/// `d` regardless of what the guest declared.  This is used in quick mode
/// to fail fast when the network is down.
pub(crate) fn evaluate_probe(
    probe: &crate::protocol::ReadinessProbe,
    allowed_hosts: &[String],
    timeout_override: Option<Duration>,
    tls_mode: &rosec_core::config::TlsMode,
) -> Result<(), String> {
    match probe {
        crate::protocol::ReadinessProbe::Http {
            url,
            method,
            expected_status,
            timeout_secs,
        } => {
            // Parse URL and enforce allowed_hosts.
            let parsed =
                url::Url::parse(url).map_err(|e| format!("invalid probe URL '{url}': {e}"))?;
            let host = parsed
                .host_str()
                .filter(|h| !h.is_empty())
                .ok_or_else(|| format!("probe URL '{url}' has no valid host"))?;
            if !is_host_allowed(host, allowed_hosts) {
                return Err(format!("probe host '{host}' not in allowed_hosts"));
            }

            let timeout = match timeout_override {
                Some(d) => d,
                None => {
                    let clamped = u64::from(*timeout_secs).min(MAX_PROBE_TIMEOUT_SECS);
                    Duration::from_secs(clamped)
                }
            };

            // Build agent with redirects disabled to prevent SSRF via
            // an allowed host that 302-redirects to internal endpoints.
            // TLS mode is configurable per-provider via `tls_mode_probe`.
            let agent = crate::host_http::build_probe_agent(tls_mode);
            let req = ureq::http::request::Builder::new()
                .method(method.to_uppercase().as_str())
                .uri(url.as_str());
            let config = agent
                .configure_request(req.body(()).map_err(|e| format!("build request: {e}"))?)
                .http_status_as_error(false);
            let result = ureq::run(config.timeout_global(Some(timeout)).build());

            match result {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == *expected_status {
                        Ok(())
                    } else {
                        Err(format!(
                            "HTTP {method} {url}: got status {status}, expected {expected_status}"
                        ))
                    }
                }
                Err(e) => Err(format!("HTTP {method} {url}: {e}")),
            }
        }
        crate::protocol::ReadinessProbe::Tcp {
            host,
            port,
            timeout_secs,
        } => {
            // Enforce allowed_hosts.
            if !is_host_allowed(host, allowed_hosts) {
                return Err(format!("probe host '{host}' not in allowed_hosts"));
            }

            let timeout = match timeout_override {
                Some(d) => d,
                None => {
                    let clamped = u64::from(*timeout_secs).min(MAX_PROBE_TIMEOUT_SECS);
                    Duration::from_secs(clamped)
                }
            };
            let addr = format!("{host}:{port}");
            let socket_addr = addr
                .to_socket_addrs()
                .map_err(|e| format!("DNS resolution failed for {addr}: {e}"))?
                .next()
                .ok_or_else(|| format!("no addresses resolved for {addr}"))?;

            TcpStream::connect_timeout(&socket_addr, timeout)
                .map(|_| ())
                .map_err(|e| format!("TCP connect to {addr}: {e}"))
        }
    }
}

// ── Guest init helper ────────────────────────────────────────────

/// Build init options (injecting `home_dir` if needed), call the guest
/// `init` function, and check the response.
///
/// `context` is used in error messages (e.g. `"init"`, `"re-init"`).
fn init_guest(
    plugin: &mut Plugin,
    config: &WasmProviderConfig,
    context: &str,
) -> Result<(), ProviderError> {
    let mut options = config.options.clone();
    if !options.contains_key("home_dir")
        && let Ok(home) = std::env::var("HOME")
    {
        debug!(provider = %config.id, home = %home, "injecting home_dir into guest options");
        options.insert("home_dir".into(), serde_json::Value::String(home));
    }

    // Log all options being sent to the guest (redact values that may be
    // sensitive — only log the keys and string lengths).
    for (key, val) in &options {
        match val {
            serde_json::Value::String(s) => {
                debug!(
                    provider = %config.id,
                    key = %key,
                    value_len = s.len(),
                    value_preview = %if s.len() <= 60 { s.as_str() } else { &s[..60] },
                    "guest {context} option",
                );
            }
            other => {
                debug!(
                    provider = %config.id,
                    key = %key,
                    value = %other,
                    "guest {context} option",
                );
            }
        }
    }

    let init_req = InitRequest {
        provider_id: config.id.clone(),
        provider_name: config.name.clone(),
        options,
    };
    let init_resp: InitResponse = call_guest_json(plugin, "init", &init_req).0?;
    if !init_resp.ok {
        return Err(ProviderError::Other(anyhow::anyhow!(
            "WASM plugin {context} failed: {}",
            init_resp.error.unwrap_or_else(|| "unknown error".into()),
        )));
    }
    Ok(())
}

// ── Guest call helpers ───────────────────────────────────────────

/// Whether a `plugin.call()` failure occurred (as opposed to a
/// serialization/deserialization error).
///
/// When `plugin.call()` fails, the WASM instance may be in a corrupted
/// state (trap, timeout, OOM, host function error, guest panic).  The
/// plugin should be recreated.  Serialization failures happen before or
/// after the WASM call and do not affect the instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallOutcome {
    /// No WASM call failure — the error (if any) is from serialization.
    Clean,
    /// `plugin.call()` returned an error — the instance may be corrupted.
    PluginCallFailed,
}

/// Result of a guest call: the value or an error, plus whether the WASM
/// call itself failed (requiring plugin recreation).
pub(crate) type GuestCallResult<T> = (Result<T, ProviderError>, CallOutcome);

/// Execute `plugin.call()`, classify errors, and deserialize the JSON
/// output on success.
///
/// This is the shared core of [`call_guest_json`], [`call_guest_json_sensitive`],
/// and [`call_guest_json_no_input`].
fn dispatch_and_deserialize<O: DeserializeOwned>(
    plugin: &mut Plugin,
    func: &str,
    input: &[u8],
) -> GuestCallResult<O> {
    let output_bytes: &[u8] = match plugin.call(func, input) {
        Ok(b) => b,
        Err(e) => {
            return (
                Err(ProviderError::Other(anyhow::anyhow!(
                    "WASM call to {func} failed: {e}"
                ))),
                CallOutcome::PluginCallFailed,
            );
        }
    };

    match serde_json::from_slice(output_bytes) {
        Ok(val) => (Ok(val), CallOutcome::Clean),
        Err(e) => (
            Err(ProviderError::Other(anyhow::anyhow!(
                "failed to deserialize output from {func}: {e}"
            ))),
            CallOutcome::Clean,
        ),
    }
}

/// Call a guest function with JSON input, deserialize JSON output.
pub(crate) fn call_guest_json<I: Serialize, O: DeserializeOwned>(
    plugin: &mut Plugin,
    func: &str,
    input: &I,
) -> GuestCallResult<O> {
    let input_bytes = match serde_json::to_vec(input) {
        Ok(b) => b,
        Err(e) => {
            return (
                Err(ProviderError::Other(anyhow::anyhow!(
                    "failed to serialize input for {func}: {e}"
                ))),
                CallOutcome::Clean,
            );
        }
    };

    dispatch_and_deserialize(plugin, func, &input_bytes)
}

/// Call a guest function with JSON input that may contain secrets.
///
/// Like [`call_guest_json`] but zeroizes the serialized input bytes after
/// the call completes, regardless of success or failure.  Use this for
/// any guest call whose input contains passwords or other sensitive data.
fn call_guest_json_sensitive<I: Serialize, O: DeserializeOwned>(
    plugin: &mut Plugin,
    func: &str,
    input: &I,
) -> GuestCallResult<O> {
    let mut input_bytes: Zeroizing<Vec<u8>> = match serde_json::to_vec(input) {
        Ok(b) => Zeroizing::new(b),
        Err(e) => {
            return (
                Err(ProviderError::Other(anyhow::anyhow!(
                    "failed to serialize input for {func}: {e}"
                ))),
                CallOutcome::Clean,
            );
        }
    };

    let result = dispatch_and_deserialize(plugin, func, &input_bytes);
    // Explicit zeroize before drop — defense-in-depth alongside Zeroizing's
    // Drop impl, which guarantees cleanup even on early-return / panic paths.
    input_bytes.zeroize();
    result
}

/// Call a guest function with no input (empty bytes), deserialize JSON output.
pub(crate) fn call_guest_json_no_input<O: DeserializeOwned>(
    plugin: &mut Plugin,
    func: &str,
) -> GuestCallResult<O> {
    dispatch_and_deserialize(plugin, func, &[])
}

/// Map a guest error response to a `ProviderError`.
///
/// For `TwoFactorRequired`, the caller must pass the methods separately
/// via [`map_guest_error_2fa`] since `SimpleResponse` carries them in a
/// dedicated field.
fn map_guest_error(message: Option<String>, kind: Option<ErrorKind>) -> ProviderError {
    let msg = message.unwrap_or_else(|| "unknown plugin error".into());
    match kind {
        Some(ErrorKind::Locked) => ProviderError::Locked,
        Some(ErrorKind::NotFound) => ProviderError::NotFound,
        Some(ErrorKind::NotSupported) => ProviderError::NotSupported,
        Some(ErrorKind::Unavailable) => ProviderError::Unavailable(msg),
        Some(ErrorKind::AlreadyExists) => ProviderError::AlreadyExists,
        Some(ErrorKind::InvalidInput) => ProviderError::InvalidInput(msg.into()),
        Some(ErrorKind::RegistrationRequired) => ProviderError::RegistrationRequired,
        Some(ErrorKind::AuthFailed) => ProviderError::AuthFailed,
        Some(ErrorKind::TwoFactorRequired) => {
            // Caller should use map_guest_2fa_error() for TwoFactorRequired
            // with the methods from SimpleResponse.  This fallback creates an
            // empty methods list.
            ProviderError::TwoFactorRequired { methods: vec![] }
        }
        Some(ErrorKind::Other) | None => ProviderError::Other(anyhow::anyhow!("{msg}")),
    }
}

/// Map a guest `TwoFactorRequired` response to a `ProviderError`, converting
/// the protocol `TwoFactorMethod` types to core types.
fn map_guest_2fa_error(
    message: Option<String>,
    methods: Option<Vec<crate::protocol::TwoFactorMethod>>,
) -> ProviderError {
    let core_methods: Vec<rosec_core::TwoFactorMethod> = methods
        .unwrap_or_default()
        .into_iter()
        .map(|m| rosec_core::TwoFactorMethod {
            id: m.id,
            label: m.label,
            prompt_kind: m.prompt_kind,
            challenge: m.challenge,
        })
        .collect();

    if core_methods.is_empty() {
        warn!("guest returned TwoFactorRequired but no methods");
    }

    let _msg = message.unwrap_or_else(|| "two-factor authentication required".into());
    ProviderError::TwoFactorRequired {
        methods: core_methods,
    }
}

// ── Conversion helpers ───────────────────────────────────────────

/// Convert a `WasmItemMeta` to a core `ItemMeta`.
fn to_item_meta(w: crate::protocol::WasmItemMeta, provider_id: &str) -> ItemMeta {
    ItemMeta {
        id: w.id,
        provider_id: provider_id.to_owned(),
        label: w.label,
        attributes: w.attributes,
        created: w
            .created_epoch_secs
            .map(|s| UNIX_EPOCH + Duration::from_secs(s)),
        modified: w
            .modified_epoch_secs
            .map(|s| UNIX_EPOCH + Duration::from_secs(s)),
        locked: false,
    }
}

/// Convert a `WasmSshKeyMeta` to a core `SshKeyMeta`.
fn to_ssh_key_meta(w: WasmSshKeyMeta, provider_id: &str) -> SshKeyMeta {
    SshKeyMeta {
        item_id: w.item_id,
        item_name: w.item_name,
        provider_id: provider_id.to_owned(),
        public_key_openssh: w.public_key_openssh,
        fingerprint: w.fingerprint,
        ssh_hosts: w.ssh_hosts,
        ssh_user: w.ssh_user,
        require_confirm: w.require_confirm,
        revision_date: w
            .revision_date_epoch_secs
            .map(|s| UNIX_EPOCH + Duration::from_secs(s)),
    }
}

/// Parse a capability string from the guest.
fn parse_capability(s: &str) -> Option<Capability> {
    match s {
        "sync" | "Sync" => Some(Capability::Sync),
        "write" | "Write" => Some(Capability::Write),
        "ssh" | "Ssh" => Some(Capability::Ssh),
        "key_wrapping" | "KeyWrapping" => Some(Capability::KeyWrapping),
        "password_change" | "PasswordChange" => Some(Capability::PasswordChange),
        "offline_cache" | "OfflineCache" => Some(Capability::OfflineCache),
        "notifications" | "Notifications" => Some(Capability::Notifications),
        _ => None,
    }
}

/// Convert a `WasmAttributeDescriptor` (owned strings) to a core
/// `AttributeDescriptor` (`&'static` strings) by leaking the allocations.
fn leak_attribute_descriptor(w: WasmAttributeDescriptor) -> AttributeDescriptor {
    let name: &'static str = Box::leak(w.name.into_boxed_str());
    let description: &'static str = Box::leak(w.description.into_boxed_str());
    let item_types: &'static [&'static str] = if w.item_types.is_empty() {
        &[]
    } else {
        let leaked: Vec<&'static str> = w
            .item_types
            .into_iter()
            .map(|s| &*Box::leak(s.into_boxed_str()))
            .collect();
        Box::leak(leaked.into_boxed_slice())
    };
    AttributeDescriptor {
        name,
        sensitive: w.sensitive,
        item_types,
        description,
    }
}

/// Convert a `WasmAuthField` (owned strings) to a core `AuthField`
/// (`&'static` strings) by leaking the allocations.
fn leak_auth_field(w: crate::protocol::WasmAuthField) -> AuthField {
    let id: &'static str = Box::leak(w.id.into_boxed_str());
    let label: &'static str = Box::leak(w.label.into_boxed_str());
    let placeholder: &'static str = Box::leak(w.placeholder.into_boxed_str());
    let kind = match w.kind.as_str() {
        "password" => AuthFieldKind::Password,
        "secret" => AuthFieldKind::Secret,
        _ => AuthFieldKind::Text,
    };
    AuthField {
        id,
        label,
        placeholder,
        required: w.required,
        kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ErrorKind, TwoFactorMethod as ProtoTwoFactorMethod};

    // ── map_guest_2fa_error: happy paths ──────────────────────────

    #[test]
    fn map_2fa_totp_method() {
        let methods = vec![ProtoTwoFactorMethod {
            id: "0".into(),
            label: "Authenticator app (TOTP)".into(),
            prompt_kind: "text".into(),
            challenge: None,
        }];
        let err = map_guest_2fa_error(Some("two-factor required".into()), Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].id, "0");
        assert_eq!(methods[0].label, "Authenticator app (TOTP)");
        assert_eq!(methods[0].prompt_kind, "text");
        assert!(methods[0].challenge.is_none());
    }

    #[test]
    fn map_2fa_email_method_with_hint() {
        let methods = vec![ProtoTwoFactorMethod {
            id: "1".into(),
            label: "Email code (j***@example.com)".into(),
            prompt_kind: "text".into(),
            challenge: None,
        }];
        let err = map_guest_2fa_error(None, Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods[0].id, "1");
        assert!(methods[0].label.contains("j***@example.com"));
    }

    #[test]
    fn map_2fa_duo_method() {
        let methods = vec![ProtoTwoFactorMethod {
            id: "2".into(),
            label: "Duo (passcode)".into(),
            prompt_kind: "text".into(),
            challenge: None,
        }];
        let err = map_guest_2fa_error(None, Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods[0].id, "2");
        assert_eq!(methods[0].prompt_kind, "text");
    }

    #[test]
    fn map_2fa_yubikey_method() {
        let methods = vec![ProtoTwoFactorMethod {
            id: "3".into(),
            label: "YubiKey OTP (touch your key)".into(),
            prompt_kind: "text".into(),
            challenge: None,
        }];
        let err = map_guest_2fa_error(None, Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods[0].id, "3");
        assert_eq!(methods[0].prompt_kind, "text");
    }

    #[test]
    fn map_2fa_fido2_method() {
        let methods = vec![ProtoTwoFactorMethod {
            id: "4".into(),
            label: "FIDO2 / WebAuthn security key".into(),
            prompt_kind: "fido2".into(),
            challenge: Some(r#"{"publicKey":{}}"#.into()),
        }];
        let err = map_guest_2fa_error(None, Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods[0].id, "4");
        assert_eq!(methods[0].prompt_kind, "fido2");
        assert_eq!(methods[0].challenge.as_deref(), Some(r#"{"publicKey":{}}"#));
    }

    #[test]
    fn map_2fa_org_duo_method() {
        let methods = vec![ProtoTwoFactorMethod {
            id: "6".into(),
            label: "Organization Duo (passcode)".into(),
            prompt_kind: "text".into(),
            challenge: None,
        }];
        let err = map_guest_2fa_error(None, Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods[0].id, "6");
        assert_eq!(methods[0].prompt_kind, "text");
    }

    #[test]
    fn map_2fa_multiple_methods_preserves_order() {
        let methods = vec![
            ProtoTwoFactorMethod {
                id: "0".into(),
                label: "TOTP".into(),
                prompt_kind: "text".into(),
                challenge: None,
            },
            ProtoTwoFactorMethod {
                id: "1".into(),
                label: "Email".into(),
                prompt_kind: "text".into(),
                challenge: None,
            },
            ProtoTwoFactorMethod {
                id: "4".into(),
                label: "FIDO2".into(),
                prompt_kind: "fido2".into(),
                challenge: None,
            },
        ];
        let err = map_guest_2fa_error(None, Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods.len(), 3);
        assert_eq!(methods[0].id, "0");
        assert_eq!(methods[1].id, "1");
        assert_eq!(methods[2].id, "4");
    }

    // ── map_guest_2fa_error: unhappy paths ────────────────────────

    #[test]
    fn map_2fa_empty_methods_list() {
        let err = map_guest_2fa_error(Some("2fa required".into()), Some(vec![]));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert!(methods.is_empty());
    }

    #[test]
    fn map_2fa_none_methods() {
        let err = map_guest_2fa_error(Some("2fa required".into()), None);
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert!(methods.is_empty());
    }

    #[test]
    fn map_2fa_none_message_and_methods() {
        let err = map_guest_2fa_error(None, None);
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert!(methods.is_empty());
    }

    // ── map_guest_error: TwoFactorRequired fallback ───────────────

    #[test]
    fn map_error_twofactor_fallback_has_empty_methods() {
        let err = map_guest_error(
            Some("two-factor required".into()),
            Some(ErrorKind::TwoFactorRequired),
        );
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        // Fallback path produces empty methods — caller should have
        // used map_guest_2fa_error() instead.
        assert!(methods.is_empty());
    }

    // ── map_guest_error: non-2FA variants ─────────────────────────

    #[test]
    fn map_error_auth_failed() {
        let err = map_guest_error(Some("bad creds".into()), Some(ErrorKind::AuthFailed));
        assert!(matches!(err, ProviderError::AuthFailed));
    }

    #[test]
    fn map_error_locked() {
        let err = map_guest_error(None, Some(ErrorKind::Locked));
        assert!(matches!(err, ProviderError::Locked));
    }

    #[test]
    fn map_error_not_found() {
        let err = map_guest_error(None, Some(ErrorKind::NotFound));
        assert!(matches!(err, ProviderError::NotFound));
    }

    #[test]
    fn map_error_not_supported() {
        let err = map_guest_error(None, Some(ErrorKind::NotSupported));
        assert!(matches!(err, ProviderError::NotSupported));
    }

    #[test]
    fn map_error_unavailable_carries_message() {
        let err = map_guest_error(Some("server down".into()), Some(ErrorKind::Unavailable));
        match err {
            ProviderError::Unavailable(msg) => assert_eq!(msg, "server down"),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn map_error_already_exists() {
        let err = map_guest_error(None, Some(ErrorKind::AlreadyExists));
        assert!(matches!(err, ProviderError::AlreadyExists));
    }

    #[test]
    fn map_error_invalid_input() {
        let err = map_guest_error(Some("bad field".into()), Some(ErrorKind::InvalidInput));
        assert!(matches!(err, ProviderError::InvalidInput(_)));
    }

    #[test]
    fn map_error_registration_required() {
        let err = map_guest_error(None, Some(ErrorKind::RegistrationRequired));
        assert!(matches!(err, ProviderError::RegistrationRequired));
    }

    #[test]
    fn map_error_other_with_message() {
        let err = map_guest_error(Some("something broke".into()), Some(ErrorKind::Other));
        match err {
            ProviderError::Other(e) => assert!(e.to_string().contains("something broke")),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn map_error_none_kind_falls_to_other() {
        let err = map_guest_error(Some("mystery".into()), None);
        assert!(matches!(err, ProviderError::Other(_)));
    }

    #[test]
    fn map_error_none_kind_none_message_uses_default() {
        let err = map_guest_error(None, None);
        match err {
            ProviderError::Other(e) => assert_eq!(e.to_string(), "unknown plugin error"),
            other => panic!("expected Other, got {other:?}"),
        }
    }
}
