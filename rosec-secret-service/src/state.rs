use std::collections::HashMap;
use std::collections::HashSet;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, ExitStatus};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

/// Cap how long we'll wait for a prompt subprocess. 120 s is comfortably past
/// any human interaction window; beyond that the prompt is hung and we kill
/// it rather than leaking a child + tying up the prompt mutex forever.
const PROMPT_WAIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Wait for `child` to exit, capped at [`PROMPT_WAIT_TIMEOUT`]. On timeout,
/// SIGKILL the child and return an error.
fn wait_with_timeout(child: &mut Child) -> std::io::Result<ExitStatus> {
    use wait_timeout::ChildExt as _;
    match child.wait_timeout(PROMPT_WAIT_TIMEOUT)? {
        Some(status) => Ok(status),
        None => {
            let _ = child.kill();
            let _ = child.wait();
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("prompt did not exit within {PROMPT_WAIT_TIMEOUT:?}"),
            ))
        }
    }
}

use rosec_core::config::{Config, PromptConfig};

use crate::item_cache::ItemCache;
use crate::lock_policy::LockPolicy;
use crate::prompt_manager::PromptManager;
use crate::provider_registry::ProviderRegistry;
use rosec_core::dedup::is_stale;
use rosec_core::router::Router;
use rosec_core::{
    ATTR_PROVIDER, ATTR_TYPE, Attributes, AutoLockPolicy, Capability, ItemMeta, ItemType, Provider,
    ProviderError, SecretBytes, UnlockInput, meta_matches_query,
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
// State is decomposed into four focused sub-structs (P3-12 complete):
// `registry` (providers + per-provider config), `cache` (item registry +
// metadata cache), `locks` (idle/max-unlocked + unlock/sync mutexes), and
// `prompts` (prompt registry + serialization mutex).  Methods on
// `ServiceState` that need cross-cutting access (prompt deregistration uses
// `conn`, hotreload_remove_provider purges `cache`) stay here as orchestration
// wrappers; the sub-structs only own data.
/// Per-provider failure tracking for circuit-breaker quarantine.
///
/// A provider with `failures >= QUARANTINE_THRESHOLD` is considered
/// unhealthy and `quarantine_until` is set into the future.  While
/// quarantined, the cache rebuild skips it without calling `list_items`.
/// Any success resets the counter and clears the quarantine.
#[derive(Debug, Default)]
struct ProviderHealth {
    failures: u32,
    quarantine_until: Option<std::time::Instant>,
}

/// Consecutive `list_items` errors needed to trigger a quarantine.
const QUARANTINE_THRESHOLD: u32 = 3;
/// Cap for the exponential backoff window (10 minutes).
const QUARANTINE_MAX_SECS: u64 = 600;

pub struct ServiceState {
    /// Registered providers, ordering, and per-provider config (return-attr
    /// patterns and optional collection label).  See [`ProviderRegistry`].
    pub registry: ProviderRegistry,
    pub router: Arc<Router>,
    pub sessions: Arc<SessionManager>,
    /// Item registry (mounted items, registered D-Bus paths, last-sync
    /// timestamp, persistent metadata cache).  See [`ItemCache`].
    pub cache: ItemCache,
    /// Per-provider health for circuit-breaker quarantine.
    provider_health: std::sync::Mutex<HashMap<String, ProviderHealth>>,
    /// The active D-Bus connection.  Behind `RwLock` so it can be swapped
    /// from a private bus to the session bus during live migration.
    conn: RwLock<Connection>,
    /// Idle/max-unlocked tracking and unlock/sync mutex registry.  See
    /// [`LockPolicy`].
    pub locks: LockPolicy,
    /// Tokio runtime handle.
    ///
    /// zbus dispatches D-Bus method calls on its own `async-io` executor, which
    /// has no Tokio reactor.  Any provider future that uses `reqwest` (or any
    /// other Tokio-dependent crate) must be spawned onto the Tokio runtime via
    /// this handle; otherwise `tokio::time::sleep` and friends will panic with
    /// "no reactor running".
    tokio_handle: tokio::runtime::Handle,
    /// Prompt registry, deferred ops, per-provider serialization mutex,
    /// and live `PromptConfig`.  See [`PromptManager`].
    pub prompts: PromptManager,
    /// The full non-provider configuration, kept live so background tasks always
    /// read the latest values rather than a snapshot taken at startup.
    live_config: Arc<RwLock<Config>>,
}

impl std::fmt::Debug for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceState")
            .field("providers", &self.registry.order_snapshot())
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
        Self {
            registry: ProviderRegistry::new(providers, return_attr_map, collection_map),
            router,
            sessions,
            cache: ItemCache::new(),
            provider_health: std::sync::Mutex::new(HashMap::new()),
            conn: RwLock::new(conn),
            locks: LockPolicy::new(),
            tokio_handle,
            prompts: PromptManager::new(prompt_config),
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
        self.cache.clear_registered();
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
        self.prompts.update_config(new_config.prompt);
    }

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
        self.prompts.config()
    }

    fn return_attr_patterns(&self, provider_id: &str) -> Vec<String> {
        self.registry.return_attr_patterns(provider_id)
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
        let items = self.cache.items.lock().map_err(|_| {
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

    pub fn providers_ordered(&self) -> Vec<Arc<dyn Provider>> {
        self.registry.ordered()
    }

    pub fn provider_by_id(&self, id: &str) -> Option<Arc<dyn Provider>> {
        self.registry.by_id(id)
    }

    pub fn provider_order_snapshot(&self) -> Vec<String> {
        self.registry.order_snapshot()
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

    /// Resolve which writable provider should receive a `CreateItem` whose
    /// client attributes match `attrs`.
    ///
    /// Walks `metadata_cache` (the same source `SearchItems` reads from) and
    /// applies the canonical [`attributes_match`] predicate so the two
    /// operations agree on what "matching" means.  Returns the writable
    /// provider that owns the best matching item, so the caller can route the
    /// write there and update the item in place instead of creating a
    /// duplicate.  A match owned by a read-only provider does not block the
    /// operation — the caller is expected to fall back to the configured
    /// write provider and shadow the read-only copy; the dedup layer surfaces
    /// the priority winner to clients.
    ///
    /// When several writable providers own a match, prefer higher-priority
    /// providers (lower [`providers_ordered`] index); within a provider,
    /// prefer the most recently modified item, then `id` ASC for a stable
    /// tiebreak across runs.  Returns `Ok(None)` when no writable match
    /// exists.
    pub fn find_writable_match(
        &self,
        attrs: &Attributes,
    ) -> Result<Option<Arc<dyn Provider>>, FdoError> {
        let mut order: HashMap<String, usize> = HashMap::new();
        let mut writable: HashSet<String> = HashSet::new();
        for (idx, p) in self.providers_ordered().iter().enumerate() {
            let pid = p.id().to_string();
            if p.capabilities().contains(&Capability::Write) {
                writable.insert(pid.clone());
            }
            order.insert(pid, idx);
        }

        let mut candidates = self.search_items_entries(attrs)?;
        candidates.retain(|(_, m)| writable.contains(&m.provider_id));
        candidates.sort_by(|(_, a), (_, b)| {
            let ai = order.get(&a.provider_id).copied().unwrap_or(usize::MAX);
            let bi = order.get(&b.provider_id).copied().unwrap_or(usize::MAX);
            ai.cmp(&bi)
                .then_with(|| b.modified.cmp(&a.modified))
                .then_with(|| a.id.cmp(&b.id))
        });

        Ok(candidates
            .into_iter()
            .next()
            .and_then(|(_, m)| self.provider_by_id(&m.provider_id)))
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

    pub fn provider_count(&self) -> usize {
        self.registry.count()
    }

    /// Hot-add a new provider at runtime.  No-op if the ID is already registered.
    pub fn hotreload_add_provider(&self, provider: Arc<dyn Provider>) {
        self.registry.add(provider);
    }

    /// Reorder providers to match the given config ordering.
    ///
    /// Returns `true` if the ordering actually changed.
    pub fn reorder_providers(&self, new_order: &[String]) -> bool {
        self.registry.reorder(new_order)
    }

    /// Hot-remove a provider at runtime.
    ///
    /// Locks the provider first to zeroize in-memory secrets, then drops it,
    /// and purges its items from both caches.
    /// Returns `true` if a provider with that ID was found and removed.
    pub async fn hotreload_remove_provider(&self, id: &str) -> bool {
        let Some(provider) = self.registry.remove(id) else {
            return false;
        };
        if let Err(e) = provider.lock().await {
            warn!(provider_id = id, error = %e, "error locking provider during hot-remove");
        }
        // provider is dropped here — Zeroizing<> fields zeroize on drop
        drop(provider);

        // Purge all items belonging to the removed provider so they don't
        // appear as ghost entries in SearchItems results.
        if let Ok(mut items) = self.cache.items.lock() {
            items.retain(|_, meta| meta.provider_id != id);
        }
        true
    }

    /// Allocate a unique prompt D-Bus path for the given provider.
    pub fn allocate_prompt(&self, provider_id: &str) -> String {
        self.prompts.allocate(provider_id)
    }

    /// Like [`allocate_prompt`](Self::allocate_prompt) but also stashes a
    /// [`PendingOperation`](crate::prompt::PendingOperation) to execute after the
    /// prompt (unlock) succeeds.
    pub fn allocate_prompt_with_operation(
        &self,
        provider_id: &str,
        op: crate::prompt::PendingOperation,
    ) -> String {
        self.prompts.allocate_with_operation(provider_id, op)
    }

    /// Retrieve and remove the pending operation for a completed prompt.
    pub fn take_pending_operation(
        &self,
        prompt_path: &str,
    ) -> Option<crate::prompt::PendingOperation> {
        self.prompts.take_pending_operation(prompt_path)
    }

    pub fn set_prompt_pid(&self, prompt_path: &str, pid: u32) {
        self.prompts.set_pid(prompt_path, pid);
    }

    /// Kill the active prompt subprocess (if any) and deregister the D-Bus
    /// object.  Safe to call after the child has exited.
    pub fn cancel_prompt(&self, prompt_path: &str) {
        if let Some(pid) = self.prompts.remove_and_get_pid(prompt_path) {
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            tracing::debug!(prompt = %prompt_path, pid, "prompt child terminated");
        }
        self.deregister_prompt_object(prompt_path);
    }

    /// Remove a completed prompt from the registry without killing the child.
    pub fn finish_prompt(&self, prompt_path: &str) {
        self.prompts.remove(prompt_path);
        self.deregister_prompt_object(prompt_path);
    }

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
    pub(crate) fn prompt_mutex_for(&self, provider_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.prompts.mutex_for(provider_id)
    }

    /// Record that client activity has occurred (resets idle timer).
    pub fn touch_activity(&self) {
        self.locks.touch_activity();
    }

    /// Record that a provider has been unlocked (starts max-unlocked timer).
    pub(crate) fn mark_unlocked(&self) {
        self.locks.mark_unlocked();
    }

    pub(crate) fn mark_provider_unlocked(&self, provider_id: &str) {
        self.locks.mark_provider_unlocked(provider_id);
        self.mark_provider_unlocked_in_cache(provider_id);
    }

    /// Clear the unlock timestamp for all providers (all locked).
    pub fn mark_locked(&self) {
        self.locks.mark_all_locked();
    }

    pub(crate) fn clear_provider_unlocked(&self, provider_id: &str) {
        self.locks.clear_provider_unlocked(provider_id);
    }

    /// Returns `true` if no providers are currently tracked as unlocked.
    pub fn all_providers_locked(&self) -> bool {
        self.locks.all_providers_locked()
    }

    /// Returns `true` if the provider has been idle longer than `idle_minutes`.
    pub fn is_idle_expired(&self, idle_minutes: u64) -> bool {
        self.locks.is_idle_expired(idle_minutes)
    }

    /// Returns `true` if the provider has been unlocked longer than `max_minutes`.
    pub fn is_max_unlocked_expired(&self, max_minutes: u64) -> bool {
        self.locks.is_max_unlocked_expired(max_minutes)
    }

    pub fn is_provider_max_unlocked_expired(&self, provider_id: &str, max_minutes: u64) -> bool {
        self.locks
            .is_provider_max_unlocked_expired(provider_id, max_minutes)
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
        caller: Option<CallerInfo>,
    ) -> Result<Zeroizing<String>, FdoError> {
        use std::io::BufRead as _;
        use std::process::Stdio;

        tracing::debug!(%prompt_path, %provider_id, %label, "spawn_prompt called");

        let prompt_path = prompt_path.to_string();
        let provider_id_str = provider_id.to_string();
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

            let status = wait_with_timeout(&mut child)
                .map_err(|e| FdoError::Failed(format!("SSH_ASKPASS wait error: {e}")))?;

            if !status.success() || password.is_empty() {
                return Err(FdoError::Failed(
                    "SSH_ASKPASS: cancelled or empty".to_string(),
                ));
            }
            return Ok(password);
        }
        let PromptEnv {
            cfg: prompt_cfg,
            program,
            has_display,
            has_tty,
            display_env,
        } = self.resolve_prompt_env();
        if has_display || has_tty {
            let json = build_prompt_json(provider_id_str, label, &prompt_cfg, caller);

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

            // Inject display vars discovered from the systemd user manager
            // so the child can connect to the compositor.
            for (key, value) in &display_env {
                cmd.env(key, value);
            }

            // Propagate the daemon's sandbox decisions into the child's env
            // so rosec-prompt's per-binary Landlock honours the operator's
            // config without rosec-prompt needing to read rosec.toml.
            for (k, v) in
                rosec_core::sandbox::spawn::sandbox_env_for_subprocess(&self.live_config().sandbox)
            {
                cmd.env(k, v);
            }

            if !has_display {
                cmd.arg("--tty");
            }

            match cmd.spawn() {
                Ok(mut child) => {
                    let pid = child.id();
                    self.set_prompt_pid(&prompt_path, pid);

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

                    let status = wait_with_timeout(&mut child)
                        .map_err(|e| FdoError::Failed(format!("rosec-prompt wait: {e}")))?;

                    if !status.success() {
                        return Err(FdoError::Failed("prompt cancelled".to_string()));
                    }

                    let mut map: HashMap<String, String> =
                        serde_json::from_str(response_line.trim()).map_err(|e| {
                            FdoError::Failed(format!("rosec-prompt JSON parse: {e}"))
                        })?;

                    // Each provider declares its own password field id; look
                    // it up on the provider so we know which key to extract.
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
        tracing::debug!(
            %provider_id,
            "prompt dismissed: no display server, no controlling TTY, \
             and SSH_ASKPASS is not set — cannot prompt interactively"
        );
        Err(FdoError::Failed(format!(
            "headless: no display, no TTY, and SSH_ASKPASS is not set — \
             run `rosec auth {provider_id}` to unlock manually"
        )))
    }

    /// Snapshot the prompt configuration and resolve the binary path and
    /// display environment in one place.
    ///
    /// Thin wrapper around [`crate::prompt_env::resolve_prompt_env`]; kept
    /// as a method so that future seams (mock dispatcher in tests, alternate
    /// resolver per-collection, etc.) only need to override one entrypoint.
    fn resolve_prompt_env(&self) -> PromptEnv {
        crate::prompt_env::resolve_prompt_env(&self.prompts, &self.tokio_handle, &self.conn())
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
            display_env,
        } = self.resolve_prompt_env();

        if !has_display && !has_tty {
            tracing::debug!(
                %title,
                "prompt dismissed: no display server and no controlling TTY — \
                 cannot prompt interactively"
            );
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

        // Inject display vars discovered from the systemd user manager.
        for (key, value) in &display_env {
            cmd.env(key, value);
        }

        // Propagate sandbox decisions to the child (see spawn_prompt above).
        for (k, v) in
            rosec_core::sandbox::spawn::sandbox_env_for_subprocess(&self.live_config().sandbox)
        {
            cmd.env(k, v);
        }

        if !has_display {
            cmd.arg("--tty");
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| FdoError::Failed(format!("rosec-prompt failed to launch: {e}")))?;

        let pid = child.id();
        let prompt_path_owned = prompt_path.to_string();
        self.set_prompt_pid(&prompt_path_owned, pid);

        // Write the request; stdin drops at scope end → EOF to the child.
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write as _;
            stdin
                .write_all(json.as_bytes())
                .map_err(|e| FdoError::Failed(format!("rosec-prompt stdin write: {e}")))?;
        }

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

        let status = wait_with_timeout(&mut child)
            .map_err(|e| FdoError::Failed(format!("rosec-prompt wait: {e}")))?;

        if !status.success() {
            return Err(FdoError::Failed("prompt cancelled".to_string()));
        }

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
        self.locks.clear_activity();
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
        let _guard = self.locks.unlock_guard().await;

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
        let providers: Vec<(String, Arc<dyn Provider>)> = self
            .registry
            .ordered()
            .into_iter()
            .filter(|p| p.id() != exclude_id)
            .map(|p| (p.id().to_string(), p))
            .collect();

        for (id, provider) in &providers {
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
        let items = self.cache.items.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable(
                "items lock poisoned".to_string(),
            ))
        })?;

        Ok(partition_by_glob(items.iter(), attrs))
    }

    /// Partition cached items by whether their owning provider is currently
    /// unlocked, filtering by exact attribute match.
    ///
    /// This is what spec-level `Service::SearchItems` consumes: each cached
    /// `ItemMeta` carries a live `locked` flag (kept current by
    /// [`mark_provider_locked_in_cache`] / cache rebuild), so the partition
    /// is correct even when the owning provider is locked — the entry stays
    /// in the cache so its path can be returned in the `locked` list rather
    /// than erroring.
    ///
    /// Empty `attrs` returns every cached item.
    pub fn search_items_partition(
        &self,
        attrs: &HashMap<String, String>,
    ) -> Result<(Vec<String>, Vec<String>), FdoError> {
        let cache = self.cache.items.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable(
                "items lock poisoned".to_string(),
            ))
        })?;

        let mut unlocked = Vec::new();
        let mut locked = Vec::new();

        for (path, meta) in cache.iter() {
            if !meta_matches_query(meta, attrs) {
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

    /// Like [`search_items_partition`] but returns `(path, ItemMeta)` pairs
    /// so callers can inspect `provider_id`, `attributes`, `locked`, etc. for
    /// routing or ranking.
    pub fn search_items_entries(
        &self,
        attrs: &HashMap<String, String>,
    ) -> Result<Vec<(String, ItemMeta)>, FdoError> {
        let cache = self.cache.items.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable(
                "items lock poisoned".to_string(),
            ))
        })?;

        let mut results = Vec::new();
        for (path, meta) in cache.iter() {
            if meta_matches_query(meta, attrs) {
                results.push((path.clone(), meta.clone()));
            }
        }
        Ok(results)
    }

    /// Glob-pattern variant of [`search_items_partition`].
    ///
    /// The special key `"name"` matches against the item label; every other
    /// key is matched against the corresponding attribute value using
    /// [`wildmatch`] semantics.  All patterns must match (AND).
    pub fn search_items_glob_partition(
        &self,
        attrs: &HashMap<String, String>,
    ) -> Result<(Vec<String>, Vec<String>), FdoError> {
        let cache = self.cache.items.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable(
                "items lock poisoned".to_string(),
            ))
        })?;

        Ok(partition_by_glob(cache.iter(), attrs))
    }

    /// Insert a newly created item into the cache and register the
    /// corresponding D-Bus object so the item is immediately visible to
    /// `SearchItems` / `GetSecret` without waiting for the next background
    /// rebuild.
    pub(crate) async fn insert_created_item(
        self: &Arc<Self>,
        path: &str,
        meta: ItemMeta,
    ) -> Result<(), FdoError> {
        // 1. Insert into the items cache.
        if let Ok(mut items) = self.cache.items.lock() {
            items.insert(path.to_string(), meta.clone());
        }
        // 2. If a D-Bus object already exists at this path (replace/update
        //    path), remove it so register_items will create a fresh one with
        //    updated metadata (label, attributes, etc.).
        let already_registered = self
            .cache
            .registered_items
            .lock()
            .map(|r| r.contains(path))
            .unwrap_or(false);
        if already_registered {
            let conn = self.conn();
            let server = conn.object_server();
            // Ignore errors — the object might already be gone.
            let _ = server.remove::<SecretItem, _>(path).await;
            if let Ok(mut registered) = self.cache.registered_items.lock() {
                registered.remove(path);
            }
        }
        // 3. Register the D-Bus object so GetSecret works on the new path.
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

        if let Ok(mut items) = self.cache.items.lock()
            && let Some(meta) = items.get_mut(path)
        {
            patch(meta);
        }
    }

    /// Remove a deleted item from the cache so it disappears from
    /// `SearchItems` immediately.
    pub(crate) fn remove_deleted_item(&self, path: &str) {
        if let Ok(mut items) = self.cache.items.lock() {
            items.remove(path);
        }
        // Note: we do NOT deregister the D-Bus object here. zbus keeps
        // it registered but it will fail with NotFound on GetSecret
        // because the provider no longer has the item. The next cache
        // rebuild will skip registering it again (already registered).
    }

    /// Mark all items belonging to a specific provider as locked.
    ///
    /// Called when a provider transitions to the locked state (auto-lock,
    /// manual lock, etc.).  Does NOT remove items — they remain queryable
    /// via `SearchItems` and friends, just in the `locked` partition.
    pub fn mark_provider_locked_in_cache(&self, provider_id: &str) {
        if let Ok(mut cache) = self.cache.items.lock() {
            for meta in cache.values_mut() {
                if meta.provider_id == provider_id {
                    meta.locked = true;
                }
            }
        }
    }

    /// Mark every cached item as locked.
    ///
    /// Called during `auto_lock` / `Lock` when all providers are locked at once.
    fn mark_all_locked_in_cache(&self) {
        if let Ok(mut cache) = self.cache.items.lock() {
            for meta in cache.values_mut() {
                meta.locked = true;
            }
        }
    }

    /// Returns true if the provider is currently within its quarantine window.
    pub fn is_provider_quarantined(&self, provider_id: &str) -> bool {
        let Ok(map) = self.provider_health.lock() else {
            return false;
        };
        match map.get(provider_id).and_then(|h| h.quarantine_until) {
            Some(until) => std::time::Instant::now() < until,
            None => false,
        }
    }

    /// Reset failure count and clear any quarantine for the given provider.
    pub fn record_provider_success(&self, provider_id: &str) {
        if let Ok(mut map) = self.provider_health.lock()
            && let Some(h) = map.get_mut(provider_id)
            && (h.failures > 0 || h.quarantine_until.is_some())
        {
            h.failures = 0;
            h.quarantine_until = None;
            debug!(provider = %provider_id, "circuit-breaker: provider healthy again");
        }
    }

    /// Increment failure count for the provider.  Once the count reaches
    /// [`QUARANTINE_THRESHOLD`], set a quarantine window with exponential
    /// backoff capped at [`QUARANTINE_MAX_SECS`].
    pub fn record_provider_failure(&self, provider_id: &str) {
        let Ok(mut map) = self.provider_health.lock() else {
            return;
        };
        let h = map.entry(provider_id.to_string()).or_default();
        h.failures = h.failures.saturating_add(1);
        if h.failures >= QUARANTINE_THRESHOLD {
            let shift = (h.failures - QUARANTINE_THRESHOLD).min(5);
            let secs = (30u64 << shift).min(QUARANTINE_MAX_SECS);
            let until = std::time::Instant::now() + std::time::Duration::from_secs(secs);
            h.quarantine_until = Some(until);
            warn!(
                provider = %provider_id,
                failures = h.failures,
                quarantine_secs = secs,
                "circuit-breaker: provider quarantined",
            );
        }
    }

    /// Flip every cached item belonging to `provider_id` to `locked = false`.
    ///
    /// Mirror of [`mark_provider_locked_in_cache`].  Called from
    /// [`mark_provider_unlocked`] so the cache stops reporting items as
    /// locked the instant their provider unlocks — otherwise `Item.GetSecret`
    /// keeps returning `IsLocked` until the next periodic cache rebuild,
    /// which libsecret clients (e.g. Chromium safe storage) interpret as
    /// "secret not loadable" and react to by regenerating and overwriting.
    pub fn mark_provider_unlocked_in_cache(&self, provider_id: &str) {
        if let Ok(mut cache) = self.cache.items.lock() {
            for meta in cache.values_mut() {
                if meta.provider_id == provider_id {
                    meta.locked = false;
                }
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
            let state_items = self.cache.items.lock().map_err(|_| {
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
                .filter(|(_, item)| meta_matches_query(item, &attrs))
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
        self.locks.sync_mutex_for(provider_id)
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
            .cache
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
            let state_items = self.cache.items.lock().map_err(|_| {
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
        let mut state_items = self.cache.items.lock().map_err(|_| {
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
            let mut state_items = self.cache.items.lock().map_err(|_| {
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

        self.update_cache_time()?;
        Ok(entries)
    }

    async fn fetch_entries(&self) -> Result<Vec<(String, ItemMeta)>, FdoError> {
        let mut all_items: Vec<ItemMeta> = Vec::new();
        let mut provider_ids: Vec<String> = Vec::new();
        for provider in self.providers_ordered() {
            let bid = provider.id().to_string();
            // Honour the circuit breaker: a provider with repeated failures
            // is skipped until its quarantine window elapses, sparing the
            // rebuild loop from spamming the same dead plugin.
            if self.is_provider_quarantined(&bid) {
                debug!(provider = %bid, "skipping quarantined provider during cache fetch");
                provider_ids.push(bid);
                continue;
            }
            let result = self
                .run_on_tokio(async move { provider.list_items().await })
                .await?;
            let fetched = match result {
                Ok(items) => {
                    self.record_provider_success(&bid);
                    items
                }
                Err(ProviderError::Locked) => {
                    // Locked is a normal state, not a fault — reset the
                    // health counter so a previously-failing provider that
                    // is now just locked doesn't stay quarantined.
                    self.record_provider_success(&bid);
                    debug!(provider = %bid, "skipping locked provider during cache fetch");
                    provider_ids.push(bid);
                    continue;
                }
                // Any other per-provider failure (e.g. wasm guest returning
                // Unavailable when its backing file is missing/locked) must
                // not kill the whole rebuild — otherwise one misbehaving
                // provider blocks every other provider's items from reaching
                // the cache, and clients see empty SearchItems and react by
                // regenerating their own keys.
                Err(e) => {
                    warn!(provider = %bid, error = %e, "provider failed during cache fetch — skipping");
                    self.record_provider_failure(&bid);
                    provider_ids.push(bid);
                    continue;
                }
            };
            // Tag each item with its provider_id and optional collection label.
            let collection_label = self.registry.collection_label(&bid);
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
        let last_sync = self.cache.last_sync.lock().map_err(|_| {
            map_provider_error(ProviderError::Unavailable("sync lock poisoned".to_string()))
        })?;
        if let Some(last_sync) = *last_sync {
            Ok(is_stale(last_sync, 1))
        } else {
            Ok(true)
        }
    }

    fn update_cache_time(&self) -> Result<(), FdoError> {
        let mut last_sync = self.cache.last_sync.lock().map_err(|_| {
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
            let registered = self.cache.registered_items.lock().map_err(|_| {
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
                items_cache: Arc::clone(&self.cache.items),
                service_state: Arc::clone(self),
            };
            server
                .at(path.clone(), SecretItem::new(state))
                .await
                .map_err(map_zbus_error)?;
        }

        let mut registered = self.cache.registered_items.lock().map_err(|_| {
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

/// Information about the D-Bus caller that triggered a prompt.
///
/// Resolved from the caller's unique bus name via the D-Bus daemon's
/// `GetConnectionUnixProcessID` and `/proc/<pid>/comm` + `/proc/<pid>/exe`.
#[derive(Debug, Clone)]
pub struct CallerInfo {
    /// Short process name (from `/proc/<pid>/comm`).
    pub name: String,
    /// Process ID.
    pub pid: u32,
    /// Full executable path (from `/proc/<pid>/exe` readlink).
    pub path: String,
}

// PromptEnv, resolve_prompt_binary, and discover_display_env_from_systemd
// have been extracted into `crate::prompt_env`. The method
// `ServiceState::resolve_prompt_env` is the only remaining caller of any
// of them and now delegates to the new module.
use crate::prompt_env::PromptEnv;

/// Build the JSON request payload that `rosec-prompt` expects on stdin.
///
/// Includes enough context for the prompt to display a useful title and
/// theme, but deliberately excludes the field values (those come back).
fn build_prompt_json(
    provider_id: String,
    label: &str,
    cfg: &PromptConfig,
    caller: Option<CallerInfo>,
) -> String {
    use serde_json::{Value, json};
    let theme = serde_json::to_value(&cfg.theme).unwrap_or_default();
    let info = caller
        .map(|c| format_caller_info(&cfg.info_format, &c))
        .unwrap_or_default();
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
        "info": info,
        "theme": theme,
    });
    req.to_string()
}

/// Expand `{name}`, `{pid}`, `{path}` placeholders in the caller format string.
fn format_caller_info(fmt: &str, caller: &CallerInfo) -> String {
    if fmt.is_empty() {
        return String::new();
    }
    fmt.replace("{name}", &caller.name)
        .replace("{pid}", &caller.pid.to_string())
        .replace("{path}", &caller.path)
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
#[cfg(test)]
impl ServiceState {
    /// Insert an entry directly into the item cache (test helper).
    ///
    /// Used to simulate items from providers that are currently locked
    /// (whose cache entries persisted from a prior unlock cycle).
    pub fn seed_item_cache(&self, path: &str, meta: ItemMeta) {
        self.cache
            .items
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
            attribute_hashes: None,
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
    async fn circuit_breaker_quarantines_after_threshold_failures() {
        let state = new_state(vec![]).await;
        // Below threshold: never quarantined.
        for _ in 0..(QUARANTINE_THRESHOLD - 1) {
            state.record_provider_failure("mock");
            assert!(!state.is_provider_quarantined("mock"));
        }
        // Hitting the threshold puts the provider in quarantine.
        state.record_provider_failure("mock");
        assert!(state.is_provider_quarantined("mock"));
    }

    #[tokio::test]
    async fn circuit_breaker_success_clears_quarantine() {
        let state = new_state(vec![]).await;
        for _ in 0..QUARANTINE_THRESHOLD {
            state.record_provider_failure("mock");
        }
        assert!(state.is_provider_quarantined("mock"));
        state.record_provider_success("mock");
        assert!(!state.is_provider_quarantined("mock"));
    }

    #[tokio::test]
    async fn circuit_breaker_isolates_providers() {
        let state = new_state(vec![]).await;
        for _ in 0..QUARANTINE_THRESHOLD {
            state.record_provider_failure("misbehaving");
        }
        assert!(state.is_provider_quarantined("misbehaving"));
        assert!(!state.is_provider_quarantined("healthy"));
    }

    /// Regression: after `auto_lock` flips cache items to `locked=true`, a
    /// subsequent `mark_provider_unlocked` must flip them back.  Without this,
    /// `Item.is_locked()` keeps reading stale `locked=true` from the cache
    /// after the provider has actually unlocked, and `GetSecret` returns
    /// `IsLocked` until the next periodic rebuild — which libsecret clients
    /// (e.g. Chromium safe storage) interpret as "secret missing" and react
    /// to by regenerating and overwriting.
    #[tokio::test]
    async fn unlock_clears_cache_locked_flags() {
        let items = vec![meta("item-1", "one", false)];
        let state = new_state(items).await;

        // Populate the cache via the normal rebuild path.
        state.rebuild_cache().await.expect("initial rebuild");
        {
            let cache = state.cache.items.lock().unwrap();
            assert!(
                cache.values().any(|m| m.provider_id == "mock" && !m.locked),
                "after rebuild cache should hold the mock item as unlocked"
            );
        }

        // Simulate auto-lock: items get flipped to locked=true in the cache.
        state.mark_provider_locked_in_cache("mock");
        {
            let cache = state.cache.items.lock().unwrap();
            assert!(
                cache.values().all(|m| m.provider_id != "mock" || m.locked),
                "after mark_provider_locked_in_cache all mock items must be locked"
            );
        }

        // The fix under test: mark_provider_unlocked must flip them back.
        state.mark_provider_unlocked("mock");
        {
            let cache = state.cache.items.lock().unwrap();
            assert!(
                cache.values().all(|m| m.provider_id != "mock" || !m.locked),
                "after mark_provider_unlocked all mock items must be unlocked"
            );
        }
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
            let guard = state.cache.items.lock().expect("items lock");
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
