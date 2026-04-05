use std::collections::HashMap;
use std::collections::HashSet;
use std::os::unix::process::CommandExt as _;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use rosec_core::config::{Config, PromptConfig};
use rosec_core::dedup::is_stale;
use rosec_core::router::Router;
use rosec_core::{
    ATTR_PROVIDER, ATTR_TYPE, Attributes, AutoLockPolicy, Capability, ItemMeta, ItemType, Provider,
    ProviderError, SecretBytes, UnlockInput,
};
use tracing::{debug, info, warn};
use zbus::Connection;
use zbus::fdo::Error as FdoError;
use zeroize::Zeroizing;

use wildmatch::WildMatch;

use crate::item::{ItemState, SecretItem};
use crate::session::SessionManager;

// Thread-local storage for passing 2FA method metadata through `FdoError`
// (which can only carry a string).  Set in `map_provider_error` when the
// error is `TwoFactorRequired`, consumed in `unlock.rs` when the sentinel
// `"two_factor_required"` is detected.
//
/// Default ordered list of attribute name patterns tried when `return_attr` is
/// not configured for a provider.
///
/// The service iterates these patterns in order, calling `get_secret_attr()` for
/// the first sensitive attribute name that matches.  Falls back to
/// `rosec_core::primary_secret()` if no attribute matches.
const DEFAULT_RETURN_ATTR: &[&str] = &["password", "number", "private_key", "notes"];

// TODO(P3-12): Decompose ServiceState into focused sub-structs.
//
// Current state: 15+ fields covering 4 distinct concerns.  Proposed grouping:
//
// 1. **ProviderRegistry** — `providers`, `provider_order`, `return_attr_map`,
//    `collection_map`.  Owns provider lifecycle (add/remove/hot-reload) and
//    per-provider config.  Methods: `get()`, `get_order()`, `add()`, `remove()`,
//    `reload()`, `return_attr_for()`, `collection_for()`.
//
// 2. **ItemCache** — `items`, `registered_items`, `metadata_cache`, `last_sync`.
//    Owns the D-Bus item registration and the persistent metadata cache.
//    Methods: `rebuild()`, `search()`, `search_glob()`, `mark_locked()`,
//    `mark_unlocked()`, `resolve_path()`.
//
// 3. **LockPolicy** — `last_activity`, `unlocked_since`, `unlocked_since_map`,
//    `unlock_in_progress`, `sync_in_progress`.  Owns idle/max-unlocked
//    tracking and sync coalescing.  Methods: `touch_activity()`,
//    `mark_provider_unlocked()`, `clear_provider_unlocked()`,
//    `should_idle_lock()`, `should_max_unlock_lock()`.
//
// 4. **PromptManager** — `prompt_counter`, `active_prompts`, `prompt_config`.
//    Owns prompt subprocess lifecycle.  Methods: `next_path()`,
//    `register()`, `dismiss()`, `update_config()`.
//
// Shared / top-level: `router`, `sessions`, `conn`, `tokio_handle`,
// `live_config` stay on `ServiceState` as injected dependencies.
//
// Migration: introduce sub-structs one at a time behind the same public API.
// Start with PromptManager (smallest, fewest callers), then LockPolicy,
// then ItemCache, then ProviderRegistry.  Each step is independently testable.
pub struct ServiceState {
    /// All registered providers, keyed by provider ID.
    /// Wrapped in `RwLock` to support hot-reload without restarting.
    providers: RwLock<HashMap<String, Arc<dyn Provider>>>,
    /// Provider IDs in the order they were configured (fan-out order).
    provider_order: RwLock<Vec<String>>,
    /// Per-provider ordered list of attribute name glob patterns used to
    /// select which sensitive attribute to return for standard Secret Service
    /// `GetSecret` calls (`return_attr` config field).
    ///
    /// Key: provider ID.  Value: ordered patterns (first match wins).
    /// Falls back to `DEFAULT_RETURN_ATTR` when a provider has no entry.
    return_attr_map: RwLock<HashMap<String, Vec<String>>>,
    /// Optional collection label per provider.  When present, the label is
    /// stamped onto every item from that provider as the `"collection"` attribute
    /// at cache-build time.  Key: provider ID.  Value: collection label string.
    collection_map: RwLock<HashMap<String, String>>,
    pub router: Arc<Router>,
    pub sessions: Arc<SessionManager>,
    pub items: Arc<Mutex<HashMap<String, ItemMeta>>>,
    pub registered_items: Arc<Mutex<HashSet<String>>>,
    pub last_sync: Arc<Mutex<Option<SystemTime>>>,
    /// The active D-Bus connection.  Behind `RwLock` so it can be swapped
    /// from a private bus to the session bus during live migration.
    conn: RwLock<Connection>,
    /// Persistent metadata cache that survives provider lock/unlock cycles.
    ///
    /// Per the Secret Service spec, `SearchItems` is a metadata-only operation
    /// that MUST never error when providers are locked — items from locked
    /// providers go in the `locked` return list.  Attributes are stored
    /// unencrypted per spec, so they are always available.
    ///
    /// This cache is populated during `rebuild_cache_inner()` and **never
    /// cleared** when providers lock.  When a provider locks, items belonging
    /// to it have their `locked` flag flipped to `true` (via `mark_provider_locked_in_cache`).
    /// When a provider unlocks and syncs, `rebuild_cache_inner()` replaces the
    /// entries for that provider with fresh data.
    ///
    /// `SearchItems`, `SearchItemsGlob`, and `resolve_item_path` (hash lookup)
    /// read from this cache, ensuring they always return results regardless of
    /// provider lock state.
    metadata_cache: Arc<Mutex<HashMap<String, ItemMeta>>>,
    /// Prevents multiple simultaneous unlock attempts for the same provider.
    unlock_in_progress: tokio::sync::Mutex<()>,
    /// Per-provider sync coalescing: ensures at most one active sync per provider.
    ///
    /// Keyed by provider ID.  Lazily populated on first sync call.  Callers that
    /// need the result (D-Bus `SyncProvider`) await the lock; background callers
    /// (timer, SignalR nudge) use `try_lock` and skip if already in progress.
    sync_in_progress: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Per-provider prompt serialization: ensures at most one active prompt
    /// subprocess per provider at a time.
    ///
    /// When multiple D-Bus clients race to `Unlock()` the same provider (e.g.
    /// after sleep/resume), each gets its own `SecretPrompt` object and calls
    /// `Prompt()`.  The second `run_prompt_task` awaits this lock, and when it
    /// acquires it, checks whether the provider is still locked.  If the first
    /// prompt already unlocked it, the second emits `Completed(success)`
    /// immediately without showing a GUI dialog.
    ///
    /// This matches gnome-keyring-daemon's `unlock_prompt_queue` serialization
    /// approach — only one password dialog is shown at a time per provider.
    prompt_in_progress: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Timestamp of the last client activity (D-Bus method call).
    last_activity: Mutex<Option<SystemTime>>,
    /// Timestamp when any provider was first unlocked (for max-unlocked policy).
    ///
    /// Legacy global field — kept for the `auto_lock` (lock-all) path.
    /// Per-provider max-unlocked checks use `unlocked_since_map` instead.
    unlocked_since: Mutex<Option<SystemTime>>,
    /// Per-provider unlock timestamps for per-provider max-unlocked checking.
    ///
    /// Key: provider ID.  Value: when that provider was unlocked.
    /// Populated by `mark_provider_unlocked()`, cleared by
    /// `clear_provider_unlocked()` or bulk `mark_locked()`.
    unlocked_since_map: Mutex<HashMap<String, SystemTime>>,
    /// Tokio runtime handle.
    ///
    /// zbus dispatches D-Bus method calls on its own `async-io` executor, which
    /// has no Tokio reactor.  Any provider future that uses `reqwest` (or any
    /// other Tokio-dependent crate) must be spawned onto the Tokio runtime via
    /// this handle; otherwise `tokio::time::sleep` and friends will panic with
    /// "no reactor running".
    tokio_handle: tokio::runtime::Handle,
    /// Monotonically increasing counter for unique prompt object paths.
    prompt_counter: AtomicU32,
    /// Active prompts: maps prompt D-Bus path → (provider_id, child_pid).
    ///
    /// `child_pid` is `Some` while a prompt subprocess is running; `None` for
    /// prompts that have already completed or been dismissed.
    pub active_prompts: Mutex<HashMap<String, (String, Option<u32>)>>,
    /// Deferred operations to execute after a prompt (unlock) succeeds.
    ///
    /// Key: prompt D-Bus path.  Populated by `allocate_prompt_with_operation()`
    /// and consumed by `take_pending_operation()` in `run_prompt_task` after unlock.
    pending_operations: Mutex<HashMap<String, crate::prompt::PendingOperation>>,
    /// Prompt program configuration (binary path, theme, etc.).
    /// Behind a `RwLock` so it can be updated by the config hot-reload watcher
    /// without restarting the daemon.
    prompt_config: RwLock<PromptConfig>,
    /// The full non-provider configuration, kept live so background tasks always
    /// read the latest values rather than a snapshot taken at startup.
    live_config: Arc<RwLock<Config>>,
}

impl std::fmt::Debug for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let order = self
            .provider_order
            .read()
            .map(|g| g.clone())
            .unwrap_or_default();
        f.debug_struct("ServiceState")
            .field("providers", &order)
            .finish()
    }
}

impl ServiceState {
    pub fn new(
        providers: Vec<Arc<dyn Provider>>,
        router: Arc<Router>,
        sessions: Arc<SessionManager>,
        conn: Connection,
        tokio_handle: tokio::runtime::Handle,
    ) -> Self {
        Self::new_with_config(
            providers,
            router,
            sessions,
            conn,
            tokio_handle,
            HashMap::new(),
            HashMap::new(),
            PromptConfig::default(),
            Config::default(),
        )
    }

    /// Like `new`, but accepts per-provider `return_attr` patterns from config.
    ///
    /// `return_attr_map` maps provider ID → ordered glob patterns.  Providers
    /// not present in the map fall back to `DEFAULT_RETURN_ATTR`.
    pub fn new_with_return_attr(
        providers: Vec<Arc<dyn Provider>>,
        router: Arc<Router>,
        sessions: Arc<SessionManager>,
        conn: Connection,
        tokio_handle: tokio::runtime::Handle,
        return_attr_map: HashMap<String, Vec<String>>,
    ) -> Self {
        Self::new_with_config(
            providers,
            router,
            sessions,
            conn,
            tokio_handle,
            return_attr_map,
            HashMap::new(),
            PromptConfig::default(),
            Config::default(),
        )
    }

    /// Full constructor: accepts `return_attr` patterns, collection map, `PromptConfig`,
    /// and the full live `Config` for hot-reload support.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_config(
        providers: Vec<Arc<dyn Provider>>,
        router: Arc<Router>,
        sessions: Arc<SessionManager>,
        conn: Connection,
        tokio_handle: tokio::runtime::Handle,
        return_attr_map: HashMap<String, Vec<String>>,
        collection_map: HashMap<String, String>,
        prompt_config: PromptConfig,
        initial_config: Config,
    ) -> Self {
        let provider_order: Vec<String> = providers.iter().map(|b| b.id().to_string()).collect();
        let providers_map: HashMap<String, Arc<dyn Provider>> = providers
            .into_iter()
            .map(|b| (b.id().to_string(), b))
            .collect();
        Self {
            providers: RwLock::new(providers_map),
            provider_order: RwLock::new(provider_order),
            return_attr_map: RwLock::new(return_attr_map),
            collection_map: RwLock::new(collection_map),
            router,
            sessions,
            items: Arc::new(Mutex::new(HashMap::new())),
            registered_items: Arc::new(Mutex::new(HashSet::new())),
            last_sync: Arc::new(Mutex::new(None)),
            conn: RwLock::new(conn),
            unlock_in_progress: tokio::sync::Mutex::new(()),
            sync_in_progress: std::sync::Mutex::new(HashMap::new()),
            prompt_in_progress: std::sync::Mutex::new(HashMap::new()),
            last_activity: Mutex::new(None),
            unlocked_since: Mutex::new(None),
            unlocked_since_map: Mutex::new(HashMap::new()),
            tokio_handle,
            prompt_counter: AtomicU32::new(0),
            metadata_cache: Arc::new(Mutex::new(HashMap::new())),
            active_prompts: Mutex::new(HashMap::new()),
            pending_operations: Mutex::new(HashMap::new()),
            prompt_config: RwLock::new(prompt_config),
            live_config: Arc::new(RwLock::new(initial_config)),
        }
    }

    /// Return a clone of the active D-Bus connection.
    ///
    /// `Connection` is internally `Arc`-based, so cloning is cheap.
    pub fn conn(&self) -> Connection {
        self.conn.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Replace the active D-Bus connection (used during private→session bus
    /// migration).  Callers must re-register objects on the new connection's
    /// `ObjectServer` after swapping.
    pub fn swap_conn(&self, new_conn: Connection) {
        let mut guard = self.conn.write().unwrap_or_else(|e| e.into_inner());
        *guard = new_conn;
    }

    /// Clear the set of registered D-Bus item paths.
    ///
    /// Used during bus migration so that `register_items()` re-registers
    /// all items on the new connection's `ObjectServer`.
    pub fn clear_registered_items(&self) {
        let mut registered = self
            .registered_items
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        registered.clear();
    }

    /// Atomically replace the live config.
    ///
    /// Called by the config hot-reload watcher whenever the config file changes.
    /// Background tasks reading `live_config()` on their next tick will
    /// automatically pick up the new values without any restart.
    pub fn update_live_config(&self, new_config: Config) {
        if let Ok(mut guard) = self.live_config.write() {
            *guard = new_config.clone();
        }
        if let Ok(mut guard) = self.prompt_config.write() {
            *guard = new_config.prompt;
        }
    }

    /// Return a snapshot of the current live config.
    pub fn live_config(&self) -> Config {
        self.live_config
            .read()
            .map(|c| c.clone())
            .unwrap_or_default()
    }

    /// Return a snapshot of the current prompt configuration.
    ///
    /// Used by the SSH agent to resolve the `rosec-prompt` binary and theme
    /// for per-key signing confirmation dialogs.
    pub fn prompt_config(&self) -> PromptConfig {
        self.prompt_config
            .read()
            .map(|c| c.clone())
            .unwrap_or_default()
    }

    /// Return the `return_attr` patterns for a given provider ID.
    ///
    /// Returns the configured patterns if present, otherwise the default list.
    fn return_attr_patterns(&self, provider_id: &str) -> Vec<String> {
        let map = self
            .return_attr_map
            .read()
            .unwrap_or_else(|e| e.into_inner());
        map.get(provider_id).cloned().unwrap_or_else(|| {
            DEFAULT_RETURN_ATTR
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        })
    }

    /// Resolve the primary secret for an item using `return_attr` patterns.
    ///
    /// Iterates the configured (or default) patterns in order and returns the
    /// first sensitive attribute that the provider can resolve.  Falls back to
    /// `rosec_core::primary_secret()` if no pattern matches.
    pub async fn resolve_primary_secret(
        &self,
        provider: Arc<dyn Provider>,
        item_id: &str,
    ) -> Result<SecretBytes, ProviderError> {
        let patterns = self.return_attr_patterns(provider.id());

        // Ask the provider for the available secret attribute names so we can
        // do pattern matching without calling get_secret_attr for every pattern.
        let attr_names: Vec<String> = match provider.get_item_attributes(item_id).await {
            Ok(ia) => ia.secret_names,
            Err(e) => return Err(e),
        };

        // Find the first secret_name that matches any return_attr pattern.
        for pattern in &patterns {
            let wm = WildMatch::new(pattern);
            if let Some(matched) = attr_names.iter().find(|n| wm.matches(n)) {
                match provider.get_secret_attr(item_id, matched).await {
                    Ok(secret) => return Ok(secret),
                    // Attr exists in the list but couldn't be resolved — skip.
                    Err(ProviderError::NotFound) => continue,
                    Err(e) => return Err(e),
                }
            }
        }

        // No pattern matched — fall back to primary_secret.
        rosec_core::primary_secret(&*provider, item_id).await
    }

    /// Resolve a D-Bus item path to the `(provider, item_id)` pair needed by
    /// the rosec extension D-Bus methods.
    ///
    /// Looks the path up in the item cache to find the provider ID and item
    /// ID, then returns the provider arc.  Returns an `FdoError` if not found.
    pub fn provider_and_id_for_path(
        &self,
        item_path: &str,
    ) -> Result<(Arc<dyn Provider>, String), FdoError> {
        let items = self.items.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable(
                "items lock poisoned".to_string(),
            ))
        })?;
        let meta = items
            .get(item_path)
            .ok_or_else(|| FdoError::Failed(format!("item '{item_path}' not found in cache")))?;
        let item_id = meta.id.clone();
        let provider_id = meta.provider_id.clone();
        drop(items);

        let provider = self
            .provider_by_id(&provider_id)
            .ok_or_else(|| FdoError::Failed(format!("provider '{provider_id}' not found")))?;
        Ok((provider, item_id))
    }

    /// Resolve an item path to its provider and item ID, verifying the
    /// provider supports writes.
    ///
    /// Combines [`provider_and_id_for_path`] with a [`Capability::Write`]
    /// check.
    pub fn writable_provider_for_path(
        &self,
        item_path: &str,
    ) -> Result<(Arc<dyn Provider>, String), FdoError> {
        let (provider, item_id) = self.provider_and_id_for_path(item_path)?;
        if !provider.capabilities().contains(&Capability::Write) {
            return Err(FdoError::NotSupported(
                "provider does not support writes".into(),
            ));
        }
        Ok((provider, item_id))
    }

    /// Return all providers in configured order.
    pub fn providers_ordered(&self) -> Vec<Arc<dyn Provider>> {
        let order = self
            .provider_order
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let map = self.providers.read().unwrap_or_else(|e| e.into_inner());
        order
            .iter()
            .filter_map(|id| map.get(id))
            .map(Arc::clone)
            .collect()
    }

    /// Look up a provider by its ID.
    pub fn provider_by_id(&self, id: &str) -> Option<Arc<dyn Provider>> {
        self.providers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .map(Arc::clone)
    }

    /// Return a snapshot of the current provider ordering (config-driven).
    pub fn provider_order_snapshot(&self) -> Vec<String> {
        self.provider_order
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Return the provider to use for write operations.
    ///
    /// Resolution order:
    /// 1. If `service.write_provider` is configured, return that provider if it supports writes
    /// 2. Otherwise, return the first provider that supports writes
    /// 3. If no write-capable provider exists, return None
    pub fn write_provider(&self) -> Option<Arc<dyn Provider>> {
        let config = self.live_config();

        if let Some(ref provider_id) = config.service.write_provider
            && let Some(provider) = self.provider_by_id(provider_id)
            && provider.capabilities().contains(&Capability::Write)
        {
            return Some(provider);
        }

        if let Some(ref provider_id) = config.service.write_provider {
            warn!(
                provider_id = %provider_id,
                "configured write_provider does not support writes, falling back"
            );
        }

        self.providers_ordered()
            .into_iter()
            .find(|b| b.capabilities().contains(&Capability::Write))
    }

    /// Spawn `fut` on the Tokio runtime and await the result.
    ///
    /// zbus dispatches D-Bus handlers on an `async-io` executor that has no
    /// Tokio reactor.  Any future that internally uses `tokio::time`,
    /// `tokio::net`, or `reqwest` must be driven on the Tokio runtime.
    /// This method bridges the two executors by spawning onto the stored handle
    /// and awaiting the `JoinHandle` from the caller's async context.
    pub async fn run_on_tokio<F, T>(&self, fut: F) -> Result<T, FdoError>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.tokio_handle
            .spawn(fut)
            .await
            .map_err(|e| FdoError::Failed(format!("tokio task panicked: {e}")))
    }

    /// Spawn `fut` on the stored Tokio runtime and return its `JoinHandle`.
    ///
    /// Unlike `run_on_tokio`, this does **not** await the handle — the caller
    /// receives it and can race it against other futures (e.g. a peer-disconnect
    /// signal) before deciding whether to abort it.
    pub fn spawn_on_tokio<F, T>(&self, fut: F) -> tokio::task::JoinHandle<T>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.tokio_handle.spawn(fut)
    }

    /// Return the number of currently registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Hot-add a new provider at runtime.
    ///
    /// No-op if a provider with the same ID is already registered.
    pub fn hotreload_add_provider(&self, provider: Arc<dyn Provider>) {
        let id = provider.id().to_string();
        let mut map = self.providers.write().unwrap_or_else(|e| e.into_inner());
        if map.contains_key(&id) {
            return;
        }
        map.insert(id.clone(), provider);
        drop(map);
        self.provider_order
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(id);
    }

    /// Reorder `provider_order` to match the given config ordering.
    ///
    /// Provider ordering affects the `Priority` dedup strategy and
    /// tie-breaking in `Newest`.  When the user reorders providers in
    /// config without changing their fingerprints, the hot-reload loop
    /// must call this so the new ordering takes effect.
    ///
    /// Returns `true` if the ordering actually changed.
    pub fn reorder_providers(&self, new_order: &[String]) -> bool {
        let mut order = self
            .provider_order
            .write()
            .unwrap_or_else(|e| e.into_inner());
        // Build the desired ordering: keep only IDs that are currently
        // present in provider_order (don't add unknown IDs).
        let current: HashSet<&str> = order.iter().map(String::as_str).collect();
        let reordered: Vec<String> = new_order
            .iter()
            .filter(|id| current.contains(id.as_str()))
            .cloned()
            .collect();
        // Append any IDs that exist in the current order but are missing
        // from new_order (defensive — shouldn't happen in practice).
        let new_set: HashSet<&str> = new_order.iter().map(String::as_str).collect();
        let mut result = reordered;
        for id in order.iter() {
            if !new_set.contains(id.as_str()) {
                result.push(id.clone());
            }
        }
        if *order != result {
            *order = result;
            true
        } else {
            false
        }
    }

    /// Hot-remove a provider at runtime.
    ///
    /// Locks the provider first to zeroize in-memory secrets, then drops it.
    /// Returns `true` if a provider with that ID was found and removed.
    pub async fn hotreload_remove_provider(&self, id: &str) -> bool {
        // Take the provider out of the map under write lock, then lock+drop outside.
        let provider = {
            let mut map = self.providers.write().unwrap_or_else(|e| e.into_inner());
            map.remove(id)
        };
        let found = provider.is_some();
        if let Some(b) = provider
            && let Err(e) = b.lock().await
        {
            warn!(provider_id = id, error = %e, "error locking provider during hot-remove");
        }
        // b is dropped here — Zeroizing<> fields zeroize on drop
        if found {
            self.provider_order
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|existing| existing != id);

            // Purge all items belonging to the removed provider from both caches
            // so they don't appear as ghost entries in SearchItems results.
            if let Ok(mut items) = self.items.lock() {
                items.retain(|_, meta| meta.provider_id != id);
            }
            if let Ok(mut cache) = self.metadata_cache.lock() {
                cache.retain(|_, meta| meta.provider_id != id);
            }
        }
        found
    }

    /// Allocate a unique prompt D-Bus path for the given provider and register
    /// it in `active_prompts` with no child PID yet (filled in by `Prompt()`).
    ///
    /// Returns the path string, e.g. `/org/freedesktop/secrets/prompt/p3`.
    pub fn allocate_prompt(&self, provider_id: &str) -> String {
        let n = self.prompt_counter.fetch_add(1, Ordering::Relaxed);
        let path = format!("/org/freedesktop/secrets/prompt/p{n}");
        if let Ok(mut map) = self.active_prompts.lock() {
            map.insert(path.clone(), (provider_id.to_string(), None));
        }
        path
    }

    /// Like [`allocate_prompt`](Self::allocate_prompt) but also stashes a
    /// [`PendingOperation`](crate::prompt::PendingOperation) to execute after the
    /// prompt (unlock) succeeds.
    ///
    /// Used by `CreateItem` / `Item.Delete` when the write provider is locked:
    /// the D-Bus method returns the prompt path, and after the user completes
    /// the unlock the deferred operation runs automatically.
    pub fn allocate_prompt_with_operation(
        &self,
        provider_id: &str,
        op: crate::prompt::PendingOperation,
    ) -> String {
        let path = self.allocate_prompt(provider_id);
        if let Ok(mut map) = self.pending_operations.lock() {
            map.insert(path.clone(), op);
        }
        path
    }

    /// Retrieve and remove the pending operation for a completed prompt.
    ///
    /// Returns `None` for plain unlock prompts (no deferred work).
    pub fn take_pending_operation(
        &self,
        prompt_path: &str,
    ) -> Option<crate::prompt::PendingOperation> {
        self.pending_operations
            .lock()
            .ok()
            .and_then(|mut map| map.remove(prompt_path))
    }

    /// Store the child PID for an active prompt (called once the subprocess starts).
    pub fn set_prompt_pid(&self, prompt_path: &str, pid: u32) {
        if let Ok(mut map) = self.active_prompts.lock()
            && let Some(entry) = map.get_mut(prompt_path)
        {
            entry.1 = Some(pid);
        }
    }

    /// Kill the active prompt subprocess (if any) and remove it from the registry.
    ///
    /// Sends SIGTERM to the child PID. Safe to call even if the child has already
    /// exited (the signal is silently ignored).  Also deregisters the D-Bus
    /// object so stale prompt objects do not accumulate.
    pub fn cancel_prompt(&self, prompt_path: &str) {
        let pid = self
            .active_prompts
            .lock()
            .ok()
            .and_then(|mut map| map.remove(prompt_path))
            .and_then(|(_, pid)| pid);

        if let Some(pid) = pid {
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            tracing::debug!(prompt = %prompt_path, pid, "prompt child terminated");
        }

        self.deregister_prompt_object(prompt_path);
    }

    /// Remove a completed prompt from the registry without killing the child.
    ///
    /// Also deregisters the D-Bus object so stale prompt objects do not
    /// accumulate on the object server.
    pub fn finish_prompt(&self, prompt_path: &str) {
        if let Ok(mut map) = self.active_prompts.lock() {
            map.remove(prompt_path);
        }
        self.deregister_prompt_object(prompt_path);
    }

    /// Remove a `SecretPrompt` D-Bus object from the object server.
    ///
    /// Safe to call even if no object is registered at the path (returns
    /// silently).  Uses `spawn_on_tokio` because zbus object removal is async.
    fn deregister_prompt_object(&self, prompt_path: &str) {
        let conn = self.conn();
        let path = prompt_path.to_string();
        self.spawn_on_tokio(async move {
            if let Err(e) = conn
                .object_server()
                .remove::<crate::prompt::SecretPrompt, _>(path.as_str())
                .await
            {
                tracing::debug!(
                    prompt = %path,
                    error = %e,
                    "failed to deregister prompt object (may already be removed)"
                );
            }
        });
    }

    /// Get or create a per-provider Tokio mutex for serializing prompt tasks.
    ///
    /// Follows the same lazy-init pattern as `sync_mutex_for`.  When multiple
    /// clients trigger `Unlock()` for the same provider, the second prompt task
    /// awaits this mutex.  After acquiring it, the task checks whether the
    /// provider was already unlocked by the first prompt and skips the GUI
    /// dialog if so.
    pub(crate) fn prompt_mutex_for(&self, provider_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self
            .prompt_in_progress
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.entry(provider_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Record that client activity has occurred (resets idle timer).
    pub fn touch_activity(&self) {
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Some(SystemTime::now());
        }
    }

    /// Record that a provider has been unlocked (starts max-unlocked timer).
    ///
    /// Updates both the global `unlocked_since` (for the lock-all path) and the
    /// per-provider `unlocked_since_map` (for per-provider autolock).
    pub(crate) fn mark_unlocked(&self) {
        let now = SystemTime::now();
        if let Ok(mut guard) = self.unlocked_since.lock() {
            *guard = Some(now);
        }
    }

    /// Record that a specific provider has been unlocked.
    ///
    /// Also updates the global `unlocked_since` timestamp.
    pub(crate) fn mark_provider_unlocked(&self, provider_id: &str) {
        let now = SystemTime::now();
        if let Ok(mut guard) = self.unlocked_since.lock() {
            *guard = Some(now);
        }
        if let Ok(mut guard) = self.unlocked_since_map.lock() {
            guard.insert(provider_id.to_string(), now);
        }
    }

    /// Clear the unlock timestamp for all providers (all locked).
    pub fn mark_locked(&self) {
        if let Ok(mut guard) = self.unlocked_since.lock() {
            *guard = None;
        }
        if let Ok(mut guard) = self.unlocked_since_map.lock() {
            guard.clear();
        }
    }

    /// Clear the unlock timestamp for a specific provider.
    pub(crate) fn clear_provider_unlocked(&self, provider_id: &str) {
        if let Ok(mut guard) = self.unlocked_since_map.lock() {
            guard.remove(provider_id);
        }
    }

    /// Returns `true` if no providers are currently tracked as unlocked.
    pub fn all_providers_locked(&self) -> bool {
        match self.unlocked_since_map.lock() {
            Ok(guard) => guard.is_empty(),
            Err(_) => true,
        }
    }

    /// Check if the provider should be auto-locked based on idle timeout.
    ///
    /// Returns `true` if the provider has been idle longer than `idle_minutes`.
    pub fn is_idle_expired(&self, idle_minutes: u64) -> bool {
        let guard = match self.last_activity.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        match *guard {
            Some(last) => {
                let elapsed = SystemTime::now().duration_since(last).unwrap_or_default();
                elapsed.as_secs() >= idle_minutes * 60
            }
            None => false,
        }
    }

    /// Check if the provider has been unlocked longer than `max_minutes`.
    pub fn is_max_unlocked_expired(&self, max_minutes: u64) -> bool {
        let guard = match self.unlocked_since.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        match *guard {
            Some(since) => {
                let elapsed = SystemTime::now().duration_since(since).unwrap_or_default();
                elapsed.as_secs() >= max_minutes * 60
            }
            None => false,
        }
    }

    /// Check if a specific provider has been unlocked longer than `max_minutes`.
    pub fn is_provider_max_unlocked_expired(&self, provider_id: &str, max_minutes: u64) -> bool {
        let guard = match self.unlocked_since_map.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        match guard.get(provider_id) {
            Some(since) => {
                let elapsed = SystemTime::now().duration_since(*since).unwrap_or_default();
                elapsed.as_secs() >= max_minutes * 60
            }
            None => false,
        }
    }

    /// Resolve the effective autolock policy for a given provider/vault ID.
    ///
    /// Looks up per-provider overrides from the live config and merges
    /// them on top of the global `[autolock]` section.  If no override is
    /// configured for this provider, returns the global policy as-is.
    pub fn effective_autolock_policy(&self, provider_id: &str) -> AutoLockPolicy {
        let config = self.live_config();
        let global = &config.autolock;

        let overrides = config
            .provider
            .iter()
            .find(|p| p.id == provider_id)
            .and_then(|p| p.autolock.as_ref());

        match overrides {
            Some(o) => global.merge(o),
            None => global.clone(),
        }
    }

    /// Lock a single provider by ID and update related state.
    pub async fn auto_lock_provider(&self, provider_id: &str) -> Result<(), FdoError> {
        let provider = self
            .provider_by_id(provider_id)
            .ok_or_else(|| FdoError::Failed(format!("provider '{provider_id}' not found")))?;
        self.run_on_tokio(async move { provider.lock().await })
            .await?
            .map_err(map_provider_error)?;
        self.clear_provider_unlocked(provider_id);
        self.mark_provider_locked_in_cache(provider_id);
        info!(provider = %provider_id, "provider auto-locked");
        Ok(())
    }

    /// Collect a password from the user for the given provider, using whichever
    /// prompt mechanism is appropriate for the current environment:
    ///
    /// 1. `SSH_ASKPASS` env var set → exec that program (stdout is the password)
    /// 2. `WAYLAND_DISPLAY` or `DISPLAY` set → spawn `rosec-prompt` GUI
    /// 3. `/dev/tty` available → spawn `rosec-prompt --tty` (reads /dev/tty)
    /// 4. None of the above → return `Err` (headless; user must run `rosec auth`)
    ///
    /// The `prompt_path` is recorded in `active_prompts` with the child PID so
    /// that `cancel_prompt` can kill it cleanly.
    ///
    /// # Security
    /// - The returned `Zeroizing<String>` scrubs the password on drop.
    /// - GUI/askpass stdout is read via a pipe into a line buffer; the buffer is
    ///   not heap-duplicated into `std::process::Output` (we never call
    ///   `child.wait_with_output()`).
    /// - The pipe read-end is closed immediately after the first line is read.
    pub fn spawn_prompt(
        self: &Arc<Self>,
        prompt_path: &str,
        provider_id: &str,
        label: &str,
    ) -> Result<Zeroizing<String>, FdoError> {
        use std::io::BufRead as _;
        use std::process::Stdio;

        tracing::debug!(%prompt_path, %provider_id, %label, "spawn_prompt called");

        let prompt_path = prompt_path.to_string();
        let provider_id_str = provider_id.to_string();

        // ── 1. SSH_ASKPASS ─────────────────────────────────────────────────
        if let Ok(askpass) = std::env::var("SSH_ASKPASS")
            && !askpass.is_empty()
        {
            tracing::debug!(program = %askpass, "using SSH_ASKPASS for prompt");
            // SAFETY: pre_exec runs after fork() in the child process.
            // setsid() is async-signal-safe and has no preconditions.
            let mut child = unsafe {
                std::process::Command::new(&askpass)
                    .arg(label) // prompt text as argv[1] (standard convention)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    // Detach from the calling terminal so Ctrl+C in the user's
                    // shell does not send SIGINT to this child.
                    .pre_exec(|| {
                        libc::setsid();
                        Ok(())
                    })
                    .spawn()
                    .map_err(|e| {
                        FdoError::Failed(format!("SSH_ASKPASS '{askpass}' failed to launch: {e}"))
                    })?
            };

            let pid = child.id();
            self.set_prompt_pid(&prompt_path, pid);

            // Read exactly one line from stdout into a zeroizing buffer.
            let password = {
                let stdout = child
                    .stdout
                    .take()
                    .ok_or_else(|| FdoError::Failed("SSH_ASKPASS: no stdout pipe".to_string()))?;
                let mut reader = std::io::BufReader::new(stdout);
                let mut line = Zeroizing::new(String::new());
                reader
                    .read_line(&mut line)
                    .map_err(|e| FdoError::Failed(format!("SSH_ASKPASS read error: {e}")))?;
                // Drop the reader (closes pipe read end) before waiting.
                drop(reader);
                // Trim trailing newline in-place without allocating.
                while line.ends_with('\n') || line.ends_with('\r') {
                    let new_len = line.len() - 1;
                    // SAFETY: ASCII control chars are single-byte.
                    unsafe { line.as_mut_vec().truncate(new_len) };
                }
                line
            };

            let status = child
                .wait()
                .map_err(|e| FdoError::Failed(format!("SSH_ASKPASS wait error: {e}")))?;

            if !status.success() || password.is_empty() {
                return Err(FdoError::Failed(
                    "SSH_ASKPASS: cancelled or empty".to_string(),
                ));
            }
            return Ok(password);
        }

        // ── Resolve rosec-prompt binary ────────────────────────────────────
        let PromptEnv {
            cfg: prompt_cfg,
            program,
            has_display,
            has_tty,
        } = self.resolve_prompt_env();

        // ── 2 & 3. GUI or TTY via rosec-prompt ────────────────────────────
        if has_display || has_tty {
            // Build the JSON request that rosec-prompt expects.
            let json = build_prompt_json(provider_id_str, label, &prompt_cfg);

            tracing::debug!(
                %program, has_display, has_tty,
                "launching rosec-prompt"
            );

            let mut cmd = std::process::Command::new(&program);
            // SAFETY: pre_exec runs after fork() in the child process.
            // setsid() is async-signal-safe and has no preconditions.
            // Detach from the calling terminal so Ctrl+C in the user's
            // shell does not send SIGINT to this child.
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());

            if !has_display {
                // No GUI available — request TTY mode.
                cmd.arg("--tty");
            }

            match cmd.spawn() {
                Ok(mut child) => {
                    let pid = child.id();
                    self.set_prompt_pid(&prompt_path, pid);

                    // Send JSON on stdin then close it.
                    if let Some(mut stdin) = child.stdin.take() {
                        use std::io::Write as _;
                        stdin.write_all(json.as_bytes()).map_err(|e| {
                            FdoError::Failed(format!("rosec-prompt stdin write: {e}"))
                        })?;
                        // stdin dropped here → EOF sent to child
                    }

                    // Read one line of JSON from stdout ({"field_id": "value"}).
                    let response_line = {
                        let stdout = child.stdout.take().ok_or_else(|| {
                            FdoError::Failed("rosec-prompt: no stdout pipe".to_string())
                        })?;
                        let mut reader = std::io::BufReader::new(stdout);
                        let mut line = Zeroizing::new(String::new());
                        reader.read_line(&mut line).map_err(|e| {
                            FdoError::Failed(format!("rosec-prompt read error: {e}"))
                        })?;
                        drop(reader);
                        line
                    };

                    let status = child
                        .wait()
                        .map_err(|e| FdoError::Failed(format!("rosec-prompt wait: {e}")))?;

                    if !status.success() {
                        return Err(FdoError::Failed("prompt cancelled".to_string()));
                    }

                    // Parse the JSON map and extract the password field.
                    // Use `take` to move the value out of the map so only one
                    // allocation exists; then zeroize all remaining map values.
                    let mut map: HashMap<String, String> =
                        serde_json::from_str(response_line.trim()).map_err(|e| {
                            FdoError::Failed(format!("rosec-prompt JSON parse: {e}"))
                        })?;

                    // Find the password field ID for this provider.
                    let provider = self.provider_by_id(provider_id).ok_or_else(|| {
                        FdoError::Failed(format!("provider '{provider_id}' not found"))
                    })?;
                    let pw_id = provider.password_field().id.to_string();

                    // Move the password out (avoiding a clone) then immediately
                    // zeroize all remaining map values so no plain-String secrets
                    // linger.
                    let raw_pw = map.remove(&pw_id);
                    for v in map.values_mut() {
                        zeroize::Zeroize::zeroize(v);
                    }
                    let password = raw_pw
                        .filter(|v| !v.is_empty())
                        .map(Zeroizing::new)
                        .ok_or_else(|| {
                            FdoError::Failed("password field empty or missing".to_string())
                        })?;

                    return Ok(password);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && has_tty => {
                    // Binary not found but a TTY is available — fall through
                    // to the embedded TTY prompt below.
                    tracing::info!(
                        program = %program,
                        "rosec-prompt binary not found; using built-in TTY prompt"
                    );
                }
                Err(e) => {
                    return Err(FdoError::Failed(format!(
                        "rosec-prompt failed to launch: {e}"
                    )));
                }
            }
        }

        // ── 3a. Built-in TTY prompt (fallback) ───────────────────────────
        // Reached when either:
        // - rosec-prompt binary was not found but /dev/tty is available, or
        // - there is no display (TTY-only) and the binary is missing.
        //
        // Opens /dev/tty directly and prompts using the daemon's built-in
        // read_hidden() — the same code path used by UnlockWithTty, minus
        // the D-Bus fd-passing overhead.
        if has_tty {
            return self.builtin_tty_prompt(provider_id, label);
        }

        // ── 4. Headless — cannot prompt ────────────────────────────────────
        Err(FdoError::Failed(format!(
            "headless: no display, no TTY, and SSH_ASKPASS is not set — \
             run `rosec auth {provider_id}` to unlock manually"
        )))
    }

    /// Snapshot the prompt configuration and resolve the binary path and
    /// display environment in one place.
    fn resolve_prompt_env(&self) -> PromptEnv {
        let cfg = self
            .prompt_config
            .read()
            .map(|g| g.clone())
            .unwrap_or_default();
        let program = match cfg.backend.as_str() {
            "builtin" | "" => resolve_prompt_binary(),
            custom => custom.to_string(),
        };
        let has_display =
            std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();
        let has_tty = std::path::Path::new("/dev/tty").exists();
        PromptEnv {
            cfg,
            program,
            has_display,
            has_tty,
        }
    }

    /// Launch `rosec-prompt` (or SSH_ASKPASS / built-in TTY) with arbitrary
    /// fields and return the full response map.
    ///
    /// Unlike [`spawn_prompt`], which always sends a single `password` field
    /// and returns just the password, this method accepts a pre-built JSON
    /// `fields` array and returns **all** field values from the prompt response.
    ///
    /// This is used by the GUI prompt 2FA flow: after the initial unlock
    /// returns `TwoFactorRequired`, the caller builds a fields array with
    /// the 2FA method selector and/or token input, launches a second prompt
    /// via this method, and feeds the response into `auth_provider`.
    ///
    /// # Security
    /// - All map values are wrapped in `Zeroizing<String>`.
    /// - Unused response values are zeroized when the map drops.
    pub(crate) fn spawn_prompt_fields(
        self: &Arc<Self>,
        prompt_path: &str,
        title: &str,
        fields_json: &[serde_json::Value],
    ) -> Result<HashMap<String, Zeroizing<String>>, FdoError> {
        use std::io::BufRead as _;
        use std::process::Stdio;

        tracing::debug!(%prompt_path, %title, "spawn_prompt_fields called");

        let PromptEnv {
            cfg: prompt_cfg,
            program,
            has_display,
            has_tty,
        } = self.resolve_prompt_env();

        if !has_display && !has_tty {
            return Err(FdoError::Failed(
                "headless: no display, no TTY — cannot prompt for 2FA".to_string(),
            ));
        }

        let json = build_prompt_fields_json(title, fields_json, &prompt_cfg);

        let mut cmd = std::process::Command::new(&program);
        // SAFETY: pre_exec runs after fork() in the child process.
        // setsid() is async-signal-safe and has no preconditions.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        if !has_display {
            cmd.arg("--tty");
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| FdoError::Failed(format!("rosec-prompt failed to launch: {e}")))?;

        let pid = child.id();
        let prompt_path_owned = prompt_path.to_string();
        self.set_prompt_pid(&prompt_path_owned, pid);

        // Send JSON on stdin then close it.
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write as _;
            stdin
                .write_all(json.as_bytes())
                .map_err(|e| FdoError::Failed(format!("rosec-prompt stdin write: {e}")))?;
        }

        // Read one line of JSON from stdout.
        let response_line = {
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| FdoError::Failed("rosec-prompt: no stdout pipe".to_string()))?;
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = Zeroizing::new(String::new());
            reader
                .read_line(&mut line)
                .map_err(|e| FdoError::Failed(format!("rosec-prompt read error: {e}")))?;
            drop(reader);
            line
        };

        let status = child
            .wait()
            .map_err(|e| FdoError::Failed(format!("rosec-prompt wait: {e}")))?;

        if !status.success() {
            return Err(FdoError::Failed("prompt cancelled".to_string()));
        }

        // Parse the JSON response into a map, wrapping all values in Zeroizing.
        let raw_map: HashMap<String, String> = serde_json::from_str(response_line.trim())
            .map_err(|e| FdoError::Failed(format!("rosec-prompt JSON parse: {e}")))?;

        let mut result = HashMap::with_capacity(raw_map.len());
        for (k, v) in raw_map {
            result.insert(k, Zeroizing::new(v));
        }

        Ok(result)
    }

    /// Built-in TTY prompt: opens `/dev/tty` directly and collects the
    /// password using the daemon's own `read_hidden()`.
    ///
    /// This is the fallback when the external `rosec-prompt` binary is not
    /// installed.  It handles the same password field as the external prompt
    /// but skips the JSON subprocess protocol and GUI path entirely.
    ///
    /// # Security
    /// - The returned `Zeroizing<String>` scrubs the password on drop.
    /// - The TTY fd is opened read/write and closed immediately after use.
    /// - `TermiosGuard` inside `read_hidden` restores terminal echo even on
    ///   error paths.
    fn builtin_tty_prompt(
        &self,
        provider_id: &str,
        label: &str,
    ) -> Result<Zeroizing<String>, FdoError> {
        use std::io::Write as _;
        use std::os::unix::io::AsRawFd as _;

        let provider = self
            .provider_by_id(provider_id)
            .ok_or_else(|| FdoError::Failed(format!("provider '{provider_id}' not found")))?;
        let pw_field = provider.password_field();

        // Open /dev/tty read-write so we can both write the prompt label and
        // read the password with echo disabled.
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|e| FdoError::Failed(format!("cannot open /dev/tty: {e}")))?;
        let fd = tty.as_raw_fd();

        // Print header + prompt label.
        {
            let mut w = &tty;
            let _ = write!(w, "\n{label}\n{}: ", pw_field.label);
            let _ = w.flush();
        }

        let password = crate::tty::read_hidden(fd, None)
            .map_err(|e| FdoError::Failed(format!("built-in TTY prompt read error: {e}")))?;

        if password.is_empty() {
            return Err(FdoError::Failed(
                "password field empty or cancelled".to_string(),
            ));
        }
        Ok(password)
    }

    /// Lock all providers and clear auto-lock state.
    pub async fn auto_lock(&self) -> Result<(), FdoError> {
        for provider in self.providers_ordered() {
            self.run_on_tokio(async move { provider.lock().await })
                .await?
                .map_err(map_provider_error)?;
        }
        self.mark_locked();
        // Mark all items in metadata_cache as locked so SearchItems returns
        // them in the `locked` partition (spec-compliant).
        self.mark_all_locked_in_cache();
        // Clear the activity timestamp so the idle check doesn't keep
        // re-firing every poll interval on an already-locked vault.
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = None;
        }
        info!("all providers auto-locked");
        Ok(())
    }

    /// Check if any provider is locked and, if so, unlock it.
    ///
    /// This is a thin dispatcher: it runs the real work on the Tokio runtime
    /// via `tokio_handle.spawn` so that all `.await` points inside
    /// (tokio mutexes, reqwest calls, spawn_blocking) execute in a Tokio
    /// context, not on the zbus async-io executor thread.
    pub async fn ensure_unlocked(self: &Arc<Self>) -> Result<(), FdoError> {
        let this = Arc::clone(self);
        self.tokio_handle
            .spawn(async move { this.ensure_unlocked_inner().await })
            .await
            .map_err(|e| FdoError::Failed(format!("unlock task panicked: {e}")))?
    }

    /// Real implementation of the unlock flow — must be called only from a
    /// Tokio task context (i.e. via `ensure_unlocked`).
    ///
    /// Iterates all providers in configured order.  All providers require an
    /// interactive password to unlock — there is no silent/auto-unlock path.
    /// Returns a `locked::<id>` sentinel for the first locked provider found so
    /// the client (CLI or D-Bus caller) can prompt the user and call
    /// `AuthProvider` with the collected credentials.
    ///
    /// Uses a tokio mutex to prevent concurrent unlock flows.
    pub(crate) async fn ensure_unlocked_inner(&self) -> Result<(), FdoError> {
        // Quick check — skip the mutex if all providers are already unlocked.
        let mut any_locked = false;
        for provider in self.providers_ordered() {
            let status = provider.status().await.map_err(map_provider_error)?;
            if status.locked {
                any_locked = true;
                break;
            }
        }
        if !any_locked {
            return Ok(());
        }

        // Acquire the unlock mutex to prevent concurrent prompts.
        let _guard = self.unlock_in_progress.lock().await;

        // All providers require interactive unlock — return the sentinel for the
        // first locked one so the client can prompt and call AuthProvider.
        for provider in self.providers_ordered() {
            let status = provider.status().await.map_err(map_provider_error)?;
            if !status.locked {
                continue;
            }
            let provider_id = provider.id().to_string();
            tracing::debug!(provider = %provider_id, "provider is locked; client must call AuthProvider");
            return Err(FdoError::Failed(format!("locked::{provider_id}")));
        }

        self.mark_unlocked();
        self.touch_activity();
        Ok(())
    }

    /// Authenticate/unlock a specific provider using caller-supplied field values.
    ///
    /// Called by the `AuthProvider` D-Bus method (used by `rosec auth`).
    /// Dispatches to Tokio so that the unlock future runs on the Tokio reactor.
    ///
    /// After the target provider is successfully unlocked, an opportunistic
    /// sweep tries the same password against all other locked providers.
    pub async fn auth_provider(
        self: &Arc<Self>,
        provider_id: &str,
        fields: HashMap<String, Zeroizing<String>>,
    ) -> Result<(), FdoError> {
        let this = Arc::clone(self);
        let provider_id = provider_id.to_string();
        self.tokio_handle
            .spawn(async move {
                // Extract the password before auth_provider consumes `fields`,
                // so we can use it for the opportunistic sweep afterwards.
                let password_for_sweep = {
                    let provider = this.provider_by_id(&provider_id).ok_or_else(|| {
                        FdoError::Failed(format!("provider '{provider_id}' not found"))
                    })?;
                    let pw_field_id = provider.password_field().id;
                    fields.get(pw_field_id).cloned()
                };

                this.try_auth_provider(&provider_id, fields)
                    .await
                    .map_err(map_provider_error)?;
                // Trigger a sync so that on_sync_succeeded callbacks (e.g. SSH
                // key rebuild) fire immediately after the vault is unlocked,
                // rather than waiting for the next background-timer tick.
                if let Err(e) = this.try_sync_provider(&provider_id).await {
                    warn!(provider = %provider_id, "post-auth sync failed: {e}");
                }

                // Opportunistically try the same password against other locked
                // providers.  Spawn as a detached task so the caller's D-Bus
                // response returns immediately — the sweep can take seconds
                // when it triggers full Bitwarden syncs.
                if let Some(password) = password_for_sweep {
                    let sweep_state = Arc::clone(&this);
                    let sweep_id = provider_id.clone();
                    tokio::spawn(async move {
                        sweep_state.opportunistic_sweep(&password, &sweep_id).await;
                        debug!("opportunistic sweep complete (from auth_provider)");
                    });
                }

                Ok(())
            })
            .await
            .map_err(|e| FdoError::Failed(format!("auth task panicked: {e}")))?
    }

    /// Authenticate a provider, returning the typed `ProviderError` on failure.
    ///
    /// Callers that need to cross the D-Bus boundary (where only strings are
    /// available) can map the result with `map_provider_error`.  Internal daemon
    /// code should match on the typed variants directly.
    pub(crate) async fn try_auth_provider(
        &self,
        provider_id: &str,
        fields: HashMap<String, Zeroizing<String>>,
    ) -> Result<(), ProviderError> {
        let provider = self.provider_by_id(provider_id).ok_or_else(|| {
            ProviderError::Other(anyhow::anyhow!("provider '{provider_id}' not found"))
        })?;

        let pw_field = provider.password_field();
        let pw_field_id = pw_field.id;

        let password_value = fields.get(pw_field_id).ok_or_else(|| {
            ProviderError::InvalidInput(
                format!("required field '{pw_field_id}' missing for provider '{provider_id}'")
                    .into(),
            )
        })?;

        if pw_field.required && password_value.is_empty() {
            return Err(ProviderError::InvalidInput(
                format!("field '{pw_field_id}' must not be empty").into(),
            ));
        }

        let password = password_value.clone();

        // Check for 2FA auth fields (injected by the TTY unlock flow after a
        // TwoFactorRequired challenge).  These are ephemeral per-unlock and go
        // into UnlockInput::WithAuth, NOT into registration_fields.
        let has_2fa = fields.contains_key("__2fa_method_id")
            && fields.get("__2fa_token").is_some_and(|v| !v.is_empty());

        let two_fa_fields: HashMap<String, Zeroizing<String>> = if has_2fa {
            fields
                .iter()
                .filter(|(k, _)| k.starts_with("__2fa_"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        } else {
            HashMap::new()
        };

        // Collect any non-empty registration/auth fields supplied alongside the password.
        // Sources: registration_info fields (first-time setup) and auth_fields (e.g. token
        // rotation). Empty values are excluded so optional fields left blank don't trigger
        // WithRegistration unnecessarily.
        //
        // The password field and 2FA fields are explicitly excluded — the password
        // is always passed via UnlockInput::password, and 2FA fields go into
        // UnlockInput::WithAuth::auth_fields.
        let reg_field_ids: std::collections::HashSet<&str> = provider
            .registration_info()
            .map(|ri| ri.fields.iter().map(|f| f.id).collect())
            .unwrap_or_default();
        let auth_field_ids: std::collections::HashSet<&str> =
            provider.auth_fields().iter().map(|f| f.id).collect();
        let mut all_extra_ids: std::collections::HashSet<&str> =
            reg_field_ids.union(&auth_field_ids).copied().collect();
        all_extra_ids.remove(pw_field_id);

        let registration_fields: HashMap<String, Zeroizing<String>> = fields
            .iter()
            .filter(|(k, v)| {
                all_extra_ids.contains(k.as_str()) && !v.is_empty() && !k.starts_with("__2fa_")
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let input = if has_2fa {
            UnlockInput::WithAuth {
                password,
                auth_fields: two_fa_fields,
            }
        } else if registration_fields.is_empty() {
            UnlockInput::Password(password)
        } else {
            UnlockInput::WithRegistration {
                password,
                registration_fields,
            }
        };

        provider.unlock(input).await?;

        self.mark_provider_unlocked(provider_id);
        self.touch_activity();
        info!(provider = %provider_id, "provider authenticated via AuthProvider");
        Ok(())
    }

    /// Try the password from a successful auth against all other locked providers.
    ///
    /// This is best-effort: failures are silently logged at `debug` level and
    /// never surface to the caller.  The goal is to reduce the number of
    /// password prompts when multiple providers share the same credentials.
    ///
    /// Only the password field is forwarded — registration fields, 2FA tokens,
    /// etc. are provider-specific and cannot be reused.
    pub(crate) async fn opportunistic_sweep(
        self: &Arc<Self>,
        password: &Zeroizing<String>,
        exclude_id: &str,
    ) {
        let providers = {
            let order = self
                .provider_order
                .read()
                .unwrap_or_else(|e| e.into_inner());
            let map = self.providers.read().unwrap_or_else(|e| e.into_inner());
            order
                .iter()
                .filter(|id| id.as_str() != exclude_id)
                .filter_map(|id| map.get(id).map(|b| (id.clone(), Arc::clone(b))))
                .collect::<Vec<_>>()
        };

        for (id, provider) in &providers {
            // Skip already-unlocked providers.
            let locked = match provider.status().await {
                Ok(s) => s.locked,
                Err(_) => continue,
            };
            if !locked {
                continue;
            }

            // Map the password to this provider's expected field name.
            let pw_field_id = provider.password_field().id.to_string();
            let mut fields = HashMap::new();
            fields.insert(pw_field_id, password.clone());

            match self.try_auth_provider(id, fields).await {
                Ok(()) => {
                    info!(provider = %id, "opportunistic sweep: unlocked");
                    if let Err(e) = self.try_sync_provider(id).await {
                        debug!(provider = %id, "opportunistic sweep: post-unlock sync failed: {e}");
                    }
                }
                Err(e) => {
                    debug!(provider = %id, "opportunistic sweep: unlock failed (expected): {e}");
                }
            }
        }
    }

    /// Search items using glob patterns on their public attributes.
    ///
    /// This is a rosec extension — not part of the Secret Service spec.
    /// Pattern values may contain `*`, `?`, and `[…]` wildcards (wildmatch
    /// semantics).  Exact values (no metacharacters) are matched as-is for
    /// zero overhead.  All patterns must match (AND semantics).
    ///
    /// The special key `"name"` matches against the item label.
    ///
    /// Returns `(unlocked_paths, locked_paths)` — same shape as `SearchItems`.
    pub fn search_items_glob(
        &self,
        attrs: &HashMap<String, String>,
    ) -> Result<(Vec<String>, Vec<String>), FdoError> {
        let items = self.items.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable(
                "items lock poisoned".to_string(),
            ))
        })?;

        Ok(partition_by_glob(items.iter(), attrs))
    }

    /// Search the persistent metadata cache using exact attribute matching.
    ///
    /// This is the method `SearchItems` should use: it reads from `metadata_cache`
    /// which survives lock/unlock cycles, and partitions results into
    /// `(unlocked_paths, locked_paths)`.  Never errors due to locked providers.
    ///
    /// Empty `attrs` returns all cached items.
    pub fn search_metadata_cache(
        &self,
        attrs: &HashMap<String, String>,
    ) -> Result<(Vec<String>, Vec<String>), FdoError> {
        let cache = self.metadata_cache.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable(
                "metadata_cache lock poisoned".to_string(),
            ))
        })?;

        let mut unlocked = Vec::new();
        let mut locked = Vec::new();

        for (path, meta) in cache.iter() {
            if !attributes_match(&meta.attributes, attrs) {
                continue;
            }
            if meta.locked {
                locked.push(path.clone());
            } else {
                unlocked.push(path.clone());
            }
        }

        Ok((unlocked, locked))
    }

    /// Search the persistent metadata cache, returning full `ItemMeta` entries.
    ///
    /// Like [`search_metadata_cache`] but returns `(path, ItemMeta)` pairs so
    /// callers can inspect `provider_id`, `attributes`, etc. for ranking.
    pub fn search_metadata_cache_entries(
        &self,
        attrs: &HashMap<String, String>,
    ) -> Result<Vec<(String, ItemMeta)>, FdoError> {
        let cache = self.metadata_cache.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable(
                "metadata_cache lock poisoned".to_string(),
            ))
        })?;

        let mut results = Vec::new();
        for (path, meta) in cache.iter() {
            if attributes_match(&meta.attributes, attrs) {
                results.push((path.clone(), meta.clone()));
            }
        }
        Ok(results)
    }

    /// Search the persistent metadata cache using glob patterns.
    ///
    /// Like `search_items_glob` but reads from `metadata_cache` (which survives
    /// lock/unlock cycles) instead of `items`.  Never errors due to locked
    /// providers.
    ///
    /// The special key `"name"` matches against the item label.
    pub fn search_metadata_cache_glob(
        &self,
        attrs: &HashMap<String, String>,
    ) -> Result<(Vec<String>, Vec<String>), FdoError> {
        let cache = self.metadata_cache.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable(
                "metadata_cache lock poisoned".to_string(),
            ))
        })?;

        Ok(partition_by_glob(cache.iter(), attrs))
    }

    /// Insert a newly created item into both the `items` and `metadata_cache`
    /// caches, and register the corresponding D-Bus object so that the item
    /// is immediately visible to `SearchItems` / `GetSecret` without waiting
    /// for the next background cache rebuild.
    pub(crate) async fn insert_created_item(
        self: &Arc<Self>,
        path: &str,
        meta: ItemMeta,
    ) -> Result<(), FdoError> {
        // 1. Insert into the items cache (Collection.Items, Collection.SearchItems).
        if let Ok(mut items) = self.items.lock() {
            items.insert(path.to_string(), meta.clone());
        }
        // 2. Insert into the persistent metadata cache (Service.SearchItems).
        if let Ok(mut cache) = self.metadata_cache.lock() {
            cache.insert(path.to_string(), meta.clone());
        }
        // 3. If a D-Bus object already exists at this path (replace/update
        //    path), remove it so register_items will create a fresh one with
        //    updated metadata (label, attributes, etc.).
        let already_registered = self
            .registered_items
            .lock()
            .map(|r| r.contains(path))
            .unwrap_or(false);
        if already_registered {
            let conn = self.conn();
            let server = conn.object_server();
            // Ignore errors — the object might already be gone.
            let _ = server.remove::<SecretItem, _>(path).await;
            if let Ok(mut registered) = self.registered_items.lock() {
                registered.remove(path);
            }
        }
        // 4. Register the D-Bus object so GetSecret works on the new path.
        self.register_items(&[(path.to_string(), meta)]).await?;
        Ok(())
    }

    /// Patch the cached metadata for an existing item after an `UpdateItem`
    /// call so that searches reflect changes immediately.
    ///
    /// Only non-`None` fields are applied.  The `rosec:type` attribute is
    /// stamped when `item_type` is provided, mirroring the provider-level
    /// stamping done inside `LocalVault::update_item`.
    pub(crate) fn patch_cached_item(
        &self,
        path: &str,
        label: Option<&str>,
        item_type: Option<&ItemType>,
        attributes: Option<&HashMap<String, String>>,
    ) {
        let patch = |meta: &mut ItemMeta| {
            if let Some(l) = label {
                meta.label = l.to_string();
            }
            if let Some(attrs) = attributes {
                meta.attributes = attrs.clone();
                // Re-stamp provider since caller-supplied attributes won't
                // include reserved attrs.
                meta.attributes
                    .entry(ATTR_PROVIDER.to_string())
                    .or_insert_with(|| meta.provider_id.clone());
            }
            if let Some(it) = item_type {
                meta.attributes
                    .insert(ATTR_TYPE.to_string(), it.to_string());
            }
            meta.modified = Some(std::time::SystemTime::now());
        };

        if let Ok(mut items) = self.items.lock()
            && let Some(meta) = items.get_mut(path)
        {
            patch(meta);
        }
        if let Ok(mut cache) = self.metadata_cache.lock()
            && let Some(meta) = cache.get_mut(path)
        {
            patch(meta);
        }
    }

    /// Remove a deleted item from both the `items` and `metadata_cache`
    /// caches so it disappears from `SearchItems` immediately.
    pub(crate) fn remove_deleted_item(&self, path: &str) {
        if let Ok(mut items) = self.items.lock() {
            items.remove(path);
        }
        if let Ok(mut cache) = self.metadata_cache.lock() {
            cache.remove(path);
        }
        // Note: we do NOT deregister the D-Bus object here. zbus keeps
        // it registered but it will fail with NotFound on GetSecret
        // because the provider no longer has the item. The next cache
        // rebuild will skip registering it again (already registered).
    }

    /// Mark all items belonging to a specific provider as locked in the
    /// persistent metadata cache.
    ///
    /// Called when a provider transitions to the locked state (auto-lock,
    /// manual lock, etc.).  Does NOT remove items — they remain queryable
    /// via `SearchItems` and friends, just in the `locked` partition.
    pub fn mark_provider_locked_in_cache(&self, provider_id: &str) {
        if let Ok(mut cache) = self.metadata_cache.lock() {
            for meta in cache.values_mut() {
                if meta.provider_id == provider_id {
                    meta.locked = true;
                }
            }
        }
    }

    /// Mark all items in the persistent metadata cache as locked.
    ///
    /// Called during `auto_lock` / `Lock` when all providers are locked at once.
    fn mark_all_locked_in_cache(&self) {
        if let Ok(mut cache) = self.metadata_cache.lock() {
            for meta in cache.values_mut() {
                meta.locked = true;
            }
        }
    }

    /// Resolve item paths or search by attributes.
    /// Dispatches to Tokio so that cache/unlock futures run on the Tokio reactor.
    pub async fn resolve_items(
        self: &Arc<Self>,
        attributes: Option<HashMap<String, String>>,
        item_paths: Option<&[String]>,
    ) -> Result<Vec<(String, ItemMeta)>, FdoError> {
        // Path lookup is synchronous — no Tokio needed.
        if let Some(item_paths) = item_paths {
            let state_items = self.items.lock().map_err(|_| {
                map_provider_error(ProviderError::Unavailable(
                    "items lock poisoned".to_string(),
                ))
            })?;
            return Ok(item_paths
                .iter()
                .filter_map(|path| {
                    let item = state_items.get(path)?;
                    Some((path.clone(), item.clone()))
                })
                .collect());
        }

        // Attribute search or full listing needs cache access — run on Tokio.
        let has_attrs = attributes.is_some();
        let this = Arc::clone(self);
        let entries = self
            .tokio_handle
            .spawn(async move {
                if has_attrs {
                    this.rebuild_cache_inner().await
                } else {
                    this.ensure_cache_inner().await
                }
            })
            .await
            .map_err(|e| FdoError::Failed(format!("resolve task panicked: {e}")))??;

        if let Some(attrs) = attributes {
            let attrs: Attributes = attrs.into_iter().collect();
            Ok(entries
                .into_iter()
                .filter(|(_, item)| attributes_match(&item.attributes, &attrs))
                .collect())
        } else {
            Ok(entries)
        }
    }

    /// Return (or lazily create) the per-provider `tokio::sync::Mutex` used to
    /// coalesce concurrent sync operations.
    ///
    /// Two sync callers for the same provider will share one `Arc<Mutex<()>>`.
    /// An `await` caller serialises behind the in-flight sync; a `try_lock`
    /// caller (background timer, SignalR nudge) skips without redundant work.
    fn sync_mutex_for(&self, provider_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self
            .sync_in_progress
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.entry(provider_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Sync a specific provider against the remote server, then rebuild the cache.
    ///
    /// Uses a per-provider mutex to coalesce concurrent calls:
    /// - The caller **awaits** the lock, so if another sync is already running
    ///   it blocks until that one finishes (and returns immediately after,
    ///   since the cache is now fresh).
    /// - Background callers (timer, SignalR) should use `try_sync_provider`
    ///   instead to skip rather than wait.
    ///
    /// Dispatches to Tokio so that network and cache futures run on the Tokio reactor.
    pub async fn sync_provider(self: &Arc<Self>, provider_id: &str) -> Result<u32, FdoError> {
        let provider = self
            .provider_by_id(provider_id)
            .ok_or_else(|| FdoError::Failed(format!("provider '{provider_id}' not found")))?;

        let sync_mtx = self.sync_mutex_for(provider_id);
        // Await acquisition here, then move the owned guard into the spawned
        // task so it is held for the full sync+rebuild duration.
        let sync_guard = sync_mtx.lock_owned().await;
        let this = Arc::clone(self);
        let provider_id = provider_id.to_string();
        self.tokio_handle
            .spawn(async move {
                let _sync_guard = sync_guard; // held until task completes
                this.ensure_provider_unlocked(&provider_id).await?;
                provider.sync().await.map_err(map_provider_error)?;
                let entries = this.rebuild_cache_inner().await?;
                // Count only items belonging to this provider.
                let count = entries
                    .iter()
                    .filter(|(_, meta)| meta.provider_id == provider_id)
                    .count() as u32;
                Ok(count)
            })
            .await
            .map_err(|e| FdoError::Failed(format!("sync task panicked: {e}")))?
    }

    /// Attempt a background sync for a specific provider, skipping if one is
    /// already in progress.
    ///
    /// Intended for callers that have nothing to gain from waiting — the
    /// background refresh timer and the SignalR notification handler.  If a
    /// sync is already running the in-flight result will be fresh enough; no
    /// duplicate HTTP request is issued.
    ///
    /// Returns `true` if a sync was started, `false` if one was already running.
    pub async fn try_sync_provider(self: &Arc<Self>, provider_id: &str) -> Result<bool, FdoError> {
        let provider = self
            .provider_by_id(provider_id)
            .ok_or_else(|| FdoError::Failed(format!("provider '{provider_id}' not found")))?;

        let sync_mtx = self.sync_mutex_for(provider_id);

        // Non-blocking: attempt to acquire the guard here, then move it into
        // the spawned task.  The guard is held for the full sync+rebuild
        // duration so no concurrent caller can slip in between.
        let sync_guard = match sync_mtx.try_lock_owned() {
            Ok(g) => g,
            Err(_) => {
                tracing::debug!(provider = %provider_id, "sync already in progress, skipping");
                return Ok(false);
            }
        };

        let this = Arc::clone(self);
        let provider_id = provider_id.to_string();
        self.tokio_handle
            .spawn(async move {
                let _sync_guard = sync_guard; // held until task completes
                this.ensure_provider_unlocked(&provider_id).await?;
                provider.sync().await.map_err(map_provider_error)?;
                this.rebuild_cache_inner().await?;
                Ok::<_, FdoError>(())
            })
            .await
            .map_err(|e| FdoError::Failed(format!("sync task panicked: {e}")))?
            .map(|_| true)
    }

    /// Ensure a *single* provider is unlocked.
    ///
    /// All providers require interactive unlock — returns a `locked::<id>`
    /// sentinel if the provider is locked so the CLI can prompt the user and
    /// call `AuthProvider`.
    async fn ensure_provider_unlocked(&self, provider_id: &str) -> Result<(), FdoError> {
        let provider = self
            .provider_by_id(provider_id)
            .ok_or_else(|| FdoError::Failed(format!("provider '{provider_id}' not found")))?;

        let status = provider.status().await.map_err(map_provider_error)?;
        if !status.locked {
            return Ok(());
        }

        tracing::debug!(provider = %provider_id, "provider is locked; client must call AuthProvider");
        Err(FdoError::Failed(format!("locked::{provider_id}")))
    }

    /// Rebuild the item cache from in-memory provider state.
    /// Dispatches to Tokio so that unlock and list futures run on the Tokio reactor.
    pub async fn rebuild_cache(self: &Arc<Self>) -> Result<Vec<(String, ItemMeta)>, FdoError> {
        let this = Arc::clone(self);
        self.tokio_handle
            .spawn(async move { this.rebuild_cache_inner().await })
            .await
            .map_err(|e| FdoError::Failed(format!("cache rebuild task panicked: {e}")))?
    }

    pub(crate) async fn ensure_cache_inner(
        self: &Arc<Self>,
    ) -> Result<Vec<(String, ItemMeta)>, FdoError> {
        let has_items = self
            .items
            .lock()
            .map_err(|_| {
                map_provider_error(ProviderError::Unavailable(
                    "items lock poisoned".to_string(),
                ))
            })
            .map(|g| !g.is_empty())?;

        if has_items {
            if self.should_rebuild_cache().unwrap_or(false) {
                return self.rebuild_cache_inner().await;
            }
            let state_items = self.items.lock().map_err(|_| {
                map_provider_error(ProviderError::Unavailable(
                    "items lock poisoned".to_string(),
                ))
            })?;
            return Ok(state_items
                .iter()
                .map(|(path, item)| (path.clone(), item.clone()))
                .collect());
        }

        // First-time population: attempt to unlock interactive providers so the
        // initial cache contains as many items as possible.
        self.ensure_unlocked_inner().await?;
        let entries = self.fetch_entries().await?;
        self.register_items(&entries).await?;
        let mut state_items = self.items.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable(
                "items lock poisoned".to_string(),
            ))
        })?;
        state_items.clear();
        for (path, item) in entries.iter() {
            state_items.insert(path.clone(), item.clone());
        }
        Ok(entries)
    }

    pub(crate) async fn rebuild_cache_inner(
        self: &Arc<Self>,
    ) -> Result<Vec<(String, ItemMeta)>, FdoError> {
        let entries = self.fetch_entries().await?;
        self.register_items(&entries).await?;

        // Determine which providers contributed fresh entries so we can
        // selectively replace only those providers' items, preserving
        // cached items from providers that were skipped (still locked).
        let fresh_providers: HashSet<String> = entries
            .iter()
            .map(|(_, meta)| meta.provider_id.clone())
            .collect();

        {
            let mut state_items = self.items.lock().map_err(|_| {
                map_provider_error(ProviderError::Unavailable(
                    "items lock poisoned".to_string(),
                ))
            })?;
            // Remove old entries only for providers that were refreshed.
            state_items.retain(|_, meta| !fresh_providers.contains(&meta.provider_id));
            // Insert fresh entries.
            for (path, item) in entries.iter() {
                state_items.insert(path.clone(), item.clone());
            }
        }

        // Also populate the persistent metadata cache with the same
        // selective-replace strategy.  Items from providers that were
        // skipped during fetch_entries (still locked) retain their
        // previous metadata_cache entries with `locked: true`.
        {
            let mut cache = self.metadata_cache.lock().map_err(|_| {
                map_provider_error(ProviderError::Unavailable(
                    "metadata_cache lock poisoned".to_string(),
                ))
            })?;
            // Remove old entries for providers that were refreshed.
            cache.retain(|_, meta| !fresh_providers.contains(&meta.provider_id));
            // Insert fresh entries.
            for (path, meta) in entries.iter() {
                cache.insert(path.clone(), meta.clone());
            }
        }

        self.update_cache_time()?;
        Ok(entries)
    }

    async fn fetch_entries(&self) -> Result<Vec<(String, ItemMeta)>, FdoError> {
        let mut all_items: Vec<ItemMeta> = Vec::new();
        let mut provider_ids: Vec<String> = Vec::new();
        for provider in self.providers_ordered() {
            let bid = provider.id().to_string();
            let result = self
                .run_on_tokio(async move { provider.list_items().await })
                .await?;
            let fetched = match result {
                Ok(items) => items,
                Err(ProviderError::Locked) => {
                    // Provider is locked — skip it so the remaining providers
                    // still populate the cache.  The user must unlock it first.
                    debug!(provider = %bid, "skipping locked provider during cache fetch");
                    provider_ids.push(bid);
                    continue;
                }
                Err(e) => return Err(map_provider_error(e)),
            };
            // Tag each item with its provider_id and optional collection label.
            let collection_label: Option<String> = self
                .collection_map
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&bid)
                .cloned();
            let tagged: Vec<ItemMeta> = fetched
                .into_iter()
                .map(|mut item| {
                    if item.provider_id.is_empty() {
                        item.provider_id = bid.clone();
                    }
                    // Stamp provider identity so clients can see where items
                    // came from and filter by provider in searches.
                    item.attributes
                        .entry(ATTR_PROVIDER.to_string())
                        .or_insert_with(|| item.provider_id.clone());
                    // Stamp collection label if configured and not already set
                    // by the provider itself.
                    if let Some(col) = &collection_label {
                        item.attributes
                            .entry("collection".to_string())
                            .or_insert_with(|| col.clone());
                    }
                    item
                })
                .collect();
            all_items.extend(tagged);
            provider_ids.push(bid);
        }
        let deduped = self.router.dedup(all_items, &provider_ids);
        let fallback_bid = provider_ids
            .first()
            .map(String::as_str)
            .unwrap_or("unknown")
            .to_string();
        let mut entries = Vec::with_capacity(deduped.len());
        for (idx, mut item) in deduped.into_iter().enumerate() {
            if item.provider_id.is_empty() {
                item.provider_id = fallback_bid.clone();
            }
            if item.id.is_empty() {
                item.id = format!("auto-{idx}");
            }
            let path = make_item_path(&item.provider_id, &item.id);
            entries.push((path, item));
        }
        Ok(entries)
    }

    fn should_rebuild_cache(&self) -> Result<bool, FdoError> {
        let last_sync = self.last_sync.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable("sync lock poisoned".to_string()))
        })?;
        if let Some(last_sync) = *last_sync {
            Ok(is_stale(last_sync, 1))
        } else {
            Ok(true)
        }
    }

    fn update_cache_time(&self) -> Result<(), FdoError> {
        let mut last_sync = self.last_sync.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable("sync lock poisoned".to_string()))
        })?;
        *last_sync = Some(SystemTime::now());
        Ok(())
    }

    pub(crate) async fn register_items(
        self: &Arc<Self>,
        entries: &[(String, ItemMeta)],
    ) -> Result<(), FdoError> {
        let conn = self.conn();
        let server = conn.object_server();
        let mut pending = Vec::new();
        {
            let registered = self.registered_items.lock().map_err(|_| {
                map_provider_error(ProviderError::Unavailable(
                    "registered lock poisoned".to_string(),
                ))
            })?;
            for (path, item) in entries {
                if registered.contains(path) {
                    continue;
                }
                pending.push((path.clone(), item.clone()));
            }
        }

        if pending.is_empty() {
            return Ok(());
        }

        for (path, item) in &pending {
            // Look up the correct provider for this item
            let provider = self
                .provider_by_id(&item.provider_id)
                .or_else(|| self.providers_ordered().into_iter().next())
                .ok_or_else(|| {
                    map_provider_error(ProviderError::Unavailable(format!(
                        "no provider found for item provider_id '{}'",
                        item.provider_id
                    )))
                })?;
            let return_attr_patterns = self.return_attr_patterns(&item.provider_id);
            let state = ItemState {
                meta: item.clone(),
                path: path.clone(),
                provider,
                sessions: self.sessions.clone(),
                return_attr_patterns,
                tokio_handle: self.tokio_handle.clone(),
                items_cache: Arc::clone(&self.items),
                service_state: Arc::clone(self),
            };
            server
                .at(path.clone(), SecretItem::new(state))
                .await
                .map_err(map_zbus_error)?;
        }

        let mut registered = self.registered_items.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable(
                "registered lock poisoned".to_string(),
            ))
        })?;
        for (path, _) in pending {
            registered.insert(path);
        }
        Ok(())
    }

    pub(crate) fn ensure_session(&self, session: &str) -> Result<(), FdoError> {
        self.sessions.validate(session).map_err(map_provider_error)
    }
}

// ---------------------------------------------------------------------------
// Prompt helpers (module-private)
// ---------------------------------------------------------------------------

/// Resolved prompt environment: config snapshot, binary path, display state.
struct PromptEnv {
    cfg: PromptConfig,
    program: String,
    has_display: bool,
    has_tty: bool,
}

/// Find the `rosec-prompt` binary next to the current executable or on PATH.
fn resolve_prompt_binary() -> String {
    // Prefer a sibling binary in the same directory (installed layout).
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("rosec-prompt");
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    "rosec-prompt".to_string() // fall back to PATH lookup
}

/// Build the JSON request payload that `rosec-prompt` expects on stdin.
///
/// Includes enough context for the prompt to display a useful title and
/// theme, but deliberately excludes the field values (those come back).
fn build_prompt_json(provider_id: String, label: &str, cfg: &PromptConfig) -> String {
    use serde_json::{Value, json};
    let theme = serde_json::to_value(&cfg.theme).unwrap_or_default();
    let req: Value = json!({
        "title": label,
        "message": "",
        "hint": "",
        "provider": provider_id,
        "confirm_label": "Unlock",
        "cancel_label": "Cancel",
        "fields": [
            {
                "id": "password",
                "label": "Master Password",
                "kind": "password",
                "placeholder": "",
            }
        ],
        "theme": theme,
    });
    req.to_string()
}

/// Build a JSON request payload for `rosec-prompt` with caller-specified fields.
///
/// This is used by the 2FA prompt flow where the fields are dynamic (method
/// selector, TOTP code) rather than the fixed single password field.
fn build_prompt_fields_json(
    title: &str,
    fields: &[serde_json::Value],
    cfg: &PromptConfig,
) -> String {
    use serde_json::{Value, json};
    let theme = serde_json::to_value(&cfg.theme).unwrap_or_default();
    let req: Value = json!({
        "title": title,
        "message": "",
        "hint": "",
        "provider": "",
        "confirm_label": "Submit",
        "cancel_label": "Cancel",
        "fields": fields,
        "theme": theme,
    });
    req.to_string()
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(crate) fn map_provider_error(err: ProviderError) -> FdoError {
    match err {
        ProviderError::Locked => FdoError::Failed("locked".to_string()),
        ProviderError::NotFound => FdoError::Failed("not found".to_string()),
        ProviderError::NotSupported => FdoError::NotSupported("not supported".to_string()),
        // Unavailable carries a reason string already intended for callers
        // (e.g. "provider locked", "network unreachable") — pass it through.
        ProviderError::Unavailable(reason) => FdoError::Failed(reason),
        // Sentinel string detected by the CLI to trigger the registration retry flow.
        ProviderError::RegistrationRequired => {
            FdoError::Failed("registration_required".to_string())
        }
        // Wrong password/passphrase — the provider has stored credentials but
        // the provided password produced a wrong decryption key.  The unlock
        // sweep should re-prompt individually rather than entering registration.
        ProviderError::AuthFailed => FdoError::Failed("auth_failed".to_string()),
        // Two-factor authentication required.  The D-Bus wire only carries a
        // sentinel string; callers that need the methods list should use
        // `try_auth_provider` which returns the typed `ProviderError`.
        ProviderError::TwoFactorRequired { .. } => {
            FdoError::Failed("two_factor_required".to_string())
        }
        // Item already exists (for create with replace=false).
        ProviderError::AlreadyExists => FdoError::Failed("already exists".to_string()),
        // Invalid input (validation failed).
        ProviderError::InvalidInput(reason) => FdoError::Failed(reason.to_string()),
        // Other/internal errors: log the full chain server-side.  Extract a
        // user-facing hint for common failure classes (TLS, DNS, connection)
        // while keeping internal details (cipher UUIDs, HTTP bodies, paths)
        // off the D-Bus wire.
        ProviderError::Other(err) => {
            warn!(error = %err, "internal provider error");
            FdoError::Failed(user_facing_hint(&err))
        }
    }
}

/// Extract a user-facing hint from an `anyhow::Error` for common failure
/// classes (TLS, DNS, connection).  Internal details (cipher UUIDs, HTTP
/// bodies, stack traces) are kept out; the full chain is already logged
/// server-side.
pub(crate) fn user_facing_hint(err: &anyhow::Error) -> String {
    let msg = err.to_string();
    if msg.contains("invalid peer certificate") || msg.contains("certificate") {
        let reason = extract_cert_reason(&msg);
        if let Some(r) = reason {
            format!(
                "TLS certificate rejected ({r}). \
                 Check tls_mode and that your CA is in the system trust store."
            )
        } else {
            "TLS certificate rejected. \
             Check tls_mode and that your CA is in the system trust store."
                .to_string()
        }
    } else if msg.contains("dns") || msg.contains("resolve") {
        "DNS resolution failed — is the server hostname correct?".to_string()
    } else if msg.contains("connection refused") || msg.contains("Connection refused") {
        "connection refused — is the server running?".to_string()
    } else {
        "provider error — see journal for details".to_string()
    }
}

/// Extract the specific certificate rejection reason from an error message.
///
/// Looks for patterns like `invalid peer certificate: UnknownIssuer` or
/// `CaUsedAsEndEntity` in the (possibly nested) error chain.
fn extract_cert_reason(msg: &str) -> Option<&str> {
    // rustls error patterns: "invalid peer certificate: <Reason>"
    if let Some(idx) = msg.find("invalid peer certificate: ") {
        let start = idx + "invalid peer certificate: ".len();
        // Take until end of line, next whitespace-heavy boundary, or end of string.
        let rest = &msg[start..];
        let end = rest.find(['\n', ')', ';']).unwrap_or(rest.len());
        let reason = rest[..end].trim();
        if !reason.is_empty() {
            return Some(reason);
        }
    }
    // rustls_platform_verifier pattern
    if msg.contains("CaUsedAsEndEntity") {
        return Some("CaUsedAsEndEntity — a CA certificate cannot be used as a server certificate");
    }
    None
}

/// Map `ProviderError` to `SecretServiceError` with spec-correct `IsLocked`.
///
/// Use this instead of [`map_provider_error`] in D-Bus interface methods on
/// `Item` and `Collection` where the Secret Service spec requires the
/// `org.freedesktop.Secret.Error.IsLocked` error type.
pub(crate) fn map_provider_error_ss(err: ProviderError) -> crate::error::SecretServiceError {
    use crate::error::SecretServiceError;
    match err {
        ProviderError::Locked => SecretServiceError::IsLocked("item is locked".to_string()),
        ProviderError::NotSupported => {
            SecretServiceError::NotSupported("not supported".to_string())
        }
        other => SecretServiceError::from(map_provider_error(other)),
    }
}

pub(crate) fn map_zbus_error(err: zbus::Error) -> FdoError {
    FdoError::Failed(format!("dbus error: {err}"))
}

fn attributes_match(item: &Attributes, query: &Attributes) -> bool {
    query
        .iter()
        .all(|(key, value)| item.get(key) == Some(value))
}

/// Partition `(path, meta)` entries into `(unlocked, locked)` by glob matching.
///
/// Each attribute pattern in `attrs` is matched using wildmatch semantics.
/// The special key `"name"` matches against the item label.  All patterns must
/// match (AND semantics) for an item to be included.
fn partition_by_glob<'a>(
    entries: impl Iterator<Item = (&'a String, &'a ItemMeta)>,
    attrs: &HashMap<String, String>,
) -> (Vec<String>, Vec<String>) {
    let mut unlocked = Vec::new();
    let mut locked = Vec::new();

    'item: for (path, meta) in entries {
        for (key, pattern) in attrs {
            let value = if key == "name" {
                meta.label.as_str()
            } else {
                meta.attributes
                    .get(key.as_str())
                    .map(String::as_str)
                    .unwrap_or("")
            };
            if !WildMatch::new(pattern).matches(value) {
                continue 'item;
            }
        }
        if meta.locked {
            locked.push(path.clone());
        } else {
            unlocked.push(path.clone());
        }
    }

    (unlocked, locked)
}

pub(crate) fn make_item_path(provider: &str, item_id: &str) -> String {
    let provider_part = sanitize_component(provider);
    let item_part = sanitize_component(item_id);
    let hash = hash_id(&format!("{provider}:{item_id}"));
    format!("/org/freedesktop/secrets/collection/default/{provider_part}_{item_part}_{hash:016x}")
}

fn sanitize_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

/// Compute a stable, deterministic u64 identifier for an item path component.
///
/// Uses SHA-256 (first 8 bytes as big-endian u64) instead of `DefaultHasher`,
/// which is explicitly non-deterministic across Rust versions and process restarts.
/// This ensures D-Bus object paths are stable across toolchain upgrades.
fn hash_id(input: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(input.as_bytes());
    // SHA-256 always produces 32 bytes; slicing [..8] and converting to [u8; 8]
    // cannot fail.  Use unreachable! to make the invariant explicit without
    // disguising it as a handled error.
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .unwrap_or_else(|_| unreachable!("SHA-256 output is always 32 bytes")),
    )
}

// ── Test-only helpers ────────────────────────────────────────────────────────
#[cfg(test)]
impl ServiceState {
    /// Insert an entry directly into the metadata cache (test helper).
    ///
    /// Used to simulate items from providers that are currently locked
    /// (whose cache entries persisted from a prior unlock cycle).
    pub fn seed_metadata_cache(&self, path: &str, meta: ItemMeta) {
        self.metadata_cache
            .lock()
            .unwrap()
            .insert(path.to_string(), meta);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use rosec_core::router::RouterConfig;
    use rosec_core::{ProviderStatus, SecretBytes, UnlockInput};

    #[derive(Debug)]
    struct MockProvider {
        items: Vec<ItemMeta>,
    }

    impl MockProvider {
        fn new(items: Vec<ItemMeta>) -> Self {
            Self { items }
        }
    }

    #[async_trait::async_trait]
    impl Provider for MockProvider {
        fn id(&self) -> &str {
            "mock"
        }

        fn name(&self) -> &str {
            "Mock"
        }

        fn kind(&self) -> &str {
            "mock"
        }

        async fn status(&self) -> Result<ProviderStatus, ProviderError> {
            Ok(ProviderStatus {
                locked: false,
                last_sync: None,
                cached: false,
                offline_cache: false,
                last_cache_write: None,
            })
        }

        async fn unlock(&self, _input: UnlockInput) -> Result<(), ProviderError> {
            Ok(())
        }

        async fn lock(&self) -> Result<(), ProviderError> {
            Ok(())
        }

        async fn list_items(&self) -> Result<Vec<ItemMeta>, ProviderError> {
            Ok(self.items.clone())
        }

        async fn search(&self, attrs: &Attributes) -> Result<Vec<ItemMeta>, ProviderError> {
            let results = self
                .items
                .iter()
                .filter(|item| attrs.iter().all(|(k, v)| item.attributes.get(k) == Some(v)))
                .cloned()
                .collect();
            Ok(results)
        }

        /// Return a simple set of item attributes for testing the attribute model.
        ///
        /// Items with id "rich-item" expose `password` and `totp` as secret attrs.
        /// All others return `NotSupported` so the fallback to `primary_secret` is tested.
        async fn get_item_attributes(
            &self,
            id: &str,
        ) -> Result<rosec_core::ItemAttributes, ProviderError> {
            if id == "rich-item" {
                Ok(rosec_core::ItemAttributes {
                    public: Attributes::new(),
                    secret_names: vec!["password".to_string(), "totp".to_string()],
                })
            } else {
                // Return empty attributes so primary_secret can try the default attr
                Ok(rosec_core::ItemAttributes {
                    public: Attributes::new(),
                    secret_names: vec!["secret".to_string()],
                })
            }
        }

        async fn get_secret_attr(
            &self,
            id: &str,
            attr: &str,
        ) -> Result<SecretBytes, ProviderError> {
            if id == "rich-item" && attr == "password" {
                Ok(SecretBytes::new(b"rich-password".to_vec()))
            } else if id == "rich-item" && attr == "totp" {
                Ok(SecretBytes::new(b"JBSWY3DPEHPK3PXP".to_vec()))
            } else if attr == "secret" {
                Ok(SecretBytes::new(format!("secret-{id}").into_bytes()))
            } else {
                Err(ProviderError::NotFound)
            }
        }
    }

    async fn new_state(items: Vec<ItemMeta>) -> Arc<ServiceState> {
        let provider = Arc::new(MockProvider::new(items));
        let router = Arc::new(Router::new(RouterConfig {
            dedup_strategy: rosec_core::DedupStrategy::Newest,
            dedup_time_fallback: rosec_core::DedupTimeFallback::Created,
        }));
        let sessions = Arc::new(SessionManager::new());
        let conn = match Connection::session().await {
            Ok(conn) => conn,
            Err(err) => panic!("session bus failed: {err}"),
        };
        Arc::new(ServiceState::new(
            vec![provider],
            router,
            sessions,
            conn,
            tokio::runtime::Handle::current(),
        ))
    }

    fn meta(id: &str, label: &str, locked: bool) -> ItemMeta {
        ItemMeta {
            id: id.to_string(),
            provider_id: "mock".to_string(),
            label: label.to_string(),
            attributes: Attributes::new(),
            created: None,
            modified: None,
            locked,
        }
    }

    #[tokio::test]
    async fn search_partitions_locked() {
        let items = vec![meta("item-1", "one", false), meta("item-2", "two", true)];
        let state = new_state(items).await;
        let resolved = match state.resolve_items(Some(HashMap::new()), None).await {
            Ok(result) => result,
            Err(err) => panic!("resolve_items failed: {err}"),
        };
        let mut unlocked = Vec::new();
        let mut locked = Vec::new();
        for (path, item) in resolved {
            if item.locked {
                locked.push(path);
            } else {
                unlocked.push(path);
            }
        }
        assert_eq!(unlocked.len(), 1);
        assert_eq!(locked.len(), 1);
        assert!(unlocked[0].starts_with("/org/freedesktop/secrets/collection/default/"));
        assert!(locked[0].starts_with("/org/freedesktop/secrets/collection/default/"));
    }

    #[tokio::test]
    async fn get_secrets_requires_valid_session() {
        let items = vec![meta("item-1", "one", false)];
        let state = new_state(items).await;
        let resolved = match state.resolve_items(Some(HashMap::new()), None).await {
            Ok(result) => result,
            Err(err) => panic!("resolve_items failed: {err}"),
        };
        let path = resolved.first().map(|(p, _)| p.clone()).expect("item path");

        // Invalid session should error
        let invalid = state.ensure_session("invalid");
        assert!(invalid.is_err());

        // Open session via SessionManager directly
        let session = match state
            .sessions
            .open_session("plain", &zvariant::Value::from(""))
        {
            Ok((_, path)) => path,
            Err(err) => panic!("open_session failed: {err}"),
        };
        state.ensure_session(&session).expect("valid session");

        // Retrieve the secret for the resolved item
        let aes_key = state
            .sessions
            .get_session_key(&session)
            .expect("session key lookup");
        let item_meta = &resolved[0].1;
        let provider = state
            .provider_by_id(&item_meta.provider_id)
            .expect("provider");
        let secret = rosec_core::primary_secret(&*provider, &item_meta.id)
            .await
            .expect("primary_secret");
        let value = crate::service::build_secret_value(&session, &secret, aes_key.as_deref())
            .expect("build_secret_value");

        // Verify we got a valid secret tuple (session, params, value, content_type)
        let _path_str = path; // just ensure the path was resolved
        // The value should be a tuple with 4 fields
        assert!(
            !value.2.is_empty(),
            "secret value bytes should not be empty"
        );
    }

    // -----------------------------------------------------------------------
    // resolve_primary_secret tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn resolve_primary_secret_uses_return_attr_pattern() {
        // rich-item has password + totp; default patterns match "password" first.
        let state = new_state(vec![meta("rich-item", "rich", false)]).await;
        let provider = state.provider_by_id("mock").expect("mock provider");
        let secret = state
            .resolve_primary_secret(provider, "rich-item")
            .await
            .expect("resolve should succeed");
        assert_eq!(secret.as_slice(), b"rich-password");
    }

    #[tokio::test]
    async fn resolve_primary_secret_falls_back_to_primary_secret() {
        // plain-item has no return_attr match → falls back to primary_secret().
        let state = new_state(vec![meta("plain-item", "plain", false)]).await;
        let provider = state.provider_by_id("mock").expect("mock provider");
        let secret = state
            .resolve_primary_secret(provider, "plain-item")
            .await
            .expect("resolve should succeed via fallback");
        assert_eq!(secret.as_slice(), b"secret-plain-item");
    }

    #[tokio::test]
    async fn resolve_primary_secret_custom_pattern_selects_totp() {
        // Configure the state with totp as the first return_attr for "mock".
        let provider = Arc::new(MockProvider::new(vec![meta("rich-item", "rich", false)]));
        let router = Arc::new(Router::new(RouterConfig {
            dedup_strategy: rosec_core::DedupStrategy::Newest,
            dedup_time_fallback: rosec_core::DedupTimeFallback::Created,
        }));
        let sessions = Arc::new(SessionManager::new());
        let conn = match Connection::session().await {
            Ok(conn) => conn,
            Err(err) => panic!("session bus failed: {err}"),
        };
        let mut map = HashMap::new();
        map.insert("mock".to_string(), vec!["totp".to_string()]);
        let state = Arc::new(ServiceState::new_with_return_attr(
            vec![provider],
            router,
            sessions,
            conn,
            tokio::runtime::Handle::current(),
            map,
        ));
        let provider = state.provider_by_id("mock").expect("mock provider");
        let secret = state
            .resolve_primary_secret(provider, "rich-item")
            .await
            .expect("resolve should return totp");
        assert_eq!(secret.as_slice(), b"JBSWY3DPEHPK3PXP");
    }

    // -----------------------------------------------------------------------
    // provider_and_id_for_path tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn provider_and_id_for_path_resolves_cached_item() {
        let items = vec![meta("item-1", "one", false)];
        let state = new_state(items).await;
        // Populate the cache.
        state
            .resolve_items(Some(HashMap::new()), None)
            .await
            .expect("cache");
        // Find the path we assigned.
        let path = {
            let guard = state.items.lock().expect("items lock");
            guard.keys().next().cloned().expect("at least one item")
        };
        let (provider, item_id) = state
            .provider_and_id_for_path(&path)
            .expect("should resolve");
        assert_eq!(provider.id(), "mock");
        assert_eq!(item_id, "item-1");
    }

    #[tokio::test]
    async fn provider_and_id_for_path_errors_on_unknown_path() {
        let state = new_state(vec![]).await;
        let result = state.provider_and_id_for_path("/nonexistent/path");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // search_items_glob tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn search_items_glob_matches_name() {
        let items = vec![
            meta("a", "Alpha Item", false),
            meta("b", "Beta Thing", false),
        ];
        let state = new_state(items).await;
        state
            .resolve_items(Some(HashMap::new()), None)
            .await
            .expect("cache");

        let mut attrs = HashMap::new();
        attrs.insert("name".to_string(), "Alpha*".to_string());
        let (unlocked, locked) = state.search_items_glob(&attrs).expect("glob search");
        assert_eq!(unlocked.len(), 1);
        assert!(locked.is_empty());
    }

    #[tokio::test]
    async fn search_items_glob_empty_returns_all() {
        let items = vec![meta("a", "Alpha", false), meta("b", "Beta", true)];
        let state = new_state(items).await;
        state
            .resolve_items(Some(HashMap::new()), None)
            .await
            .expect("cache");

        let (unlocked, locked) = state
            .search_items_glob(&HashMap::new())
            .expect("glob search");
        assert_eq!(unlocked.len(), 1);
        assert_eq!(locked.len(), 1);
    }
}
