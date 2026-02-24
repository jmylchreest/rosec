use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use rosec_core::config::PromptConfig;
use rosec_core::dedup::is_stale;
use rosec_core::router::Router;
use rosec_core::{
    Attributes, BackendError, RecoveryOutcome, SecretBytes, UnlockInput, VaultBackend,
    VaultItemMeta,
};
use tracing::{info, warn};
use zbus::Connection;
use zbus::fdo::Error as FdoError;
use zeroize::Zeroizing;

use wildmatch::WildMatch;

use crate::item::{ItemState, SecretItem};
use crate::session::SessionManager;

/// Default ordered list of attribute name patterns tried when `return_attr` is
/// not configured for a backend.
///
/// The service iterates these patterns in order, calling `get_secret_attr()` for
/// the first sensitive attribute name that matches.  Falls back to the legacy
/// `backend.get_secret()` only if no attribute matches (backward compatibility).
const DEFAULT_RETURN_ATTR: &[&str] = &["password", "number", "private_key", "notes"];

pub struct ServiceState {
    /// All registered backends, keyed by backend ID.
    /// Wrapped in `RwLock` to support hot-reload without restarting.
    backends: RwLock<HashMap<String, Arc<dyn VaultBackend>>>,
    /// Backend IDs in the order they were configured (fan-out order).
    backend_order: RwLock<Vec<String>>,
    /// Per-backend ordered list of attribute name glob patterns used to
    /// select which sensitive attribute to return for standard Secret Service
    /// `GetSecret` calls (`return_attr` config field).
    ///
    /// Key: backend ID.  Value: ordered patterns (first match wins).
    /// Falls back to `DEFAULT_RETURN_ATTR` when a backend has no entry.
    return_attr_map: RwLock<HashMap<String, Vec<String>>>,
    /// Optional collection label per backend.  When present, the label is
    /// stamped onto every item from that backend as the `"collection"` attribute
    /// at cache-build time.  Key: backend ID.  Value: collection label string.
    collection_map: RwLock<HashMap<String, String>>,
    pub router: Arc<Router>,
    pub sessions: Arc<SessionManager>,
    pub items: Arc<Mutex<HashMap<String, VaultItemMeta>>>,
    pub registered_items: Arc<Mutex<HashSet<String>>>,
    pub last_sync: Arc<Mutex<Option<SystemTime>>>,
    pub conn: Connection,
    /// Persistent metadata cache that survives backend lock/unlock cycles.
    ///
    /// Per the Secret Service spec, `SearchItems` is a metadata-only operation
    /// that MUST never error when backends are locked — items from locked
    /// backends go in the `locked` return list.  Attributes are stored
    /// unencrypted per spec, so they are always available.
    ///
    /// This cache is populated during `rebuild_cache_inner()` and **never
    /// cleared** when backends lock.  When a backend locks, items belonging
    /// to it have their `locked` flag flipped to `true` (via `mark_backend_locked_in_cache`).
    /// When a backend unlocks and syncs, `rebuild_cache_inner()` replaces the
    /// entries for that backend with fresh data.
    ///
    /// `SearchItems`, `SearchItemsGlob`, and `resolve_item_path` (hash lookup)
    /// read from this cache, ensuring they always return results regardless of
    /// backend lock state.
    metadata_cache: Arc<Mutex<HashMap<String, VaultItemMeta>>>,
    /// Prevents multiple simultaneous unlock attempts for the same backend.
    unlock_in_progress: tokio::sync::Mutex<()>,
    /// Per-backend sync coalescing: ensures at most one active sync per backend.
    ///
    /// Keyed by backend ID.  Lazily populated on first sync call.  Callers that
    /// need the result (D-Bus `SyncBackend`) await the lock; background callers
    /// (timer, SignalR nudge) use `try_lock` and skip if already in progress.
    sync_in_progress: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Timestamp of the last client activity (D-Bus method call).
    last_activity: Mutex<Option<SystemTime>>,
    /// Timestamp when any backend was first unlocked (for max-unlocked policy).
    unlocked_since: Mutex<Option<SystemTime>>,
    /// Tokio runtime handle.
    ///
    /// zbus dispatches D-Bus method calls on its own `async-io` executor, which
    /// has no Tokio reactor.  Any backend future that uses `reqwest` (or any
    /// other Tokio-dependent crate) must be spawned onto the Tokio runtime via
    /// this handle; otherwise `tokio::time::sleep` and friends will panic with
    /// "no reactor running".
    tokio_handle: tokio::runtime::Handle,
    /// Monotonically increasing counter for unique prompt object paths.
    prompt_counter: AtomicU32,
    /// Active prompts: maps prompt D-Bus path → (backend_id, child_pid).
    ///
    /// `child_pid` is `Some` while a prompt subprocess is running; `None` for
    /// prompts that have already completed or been dismissed.
    pub active_prompts: Mutex<HashMap<String, (String, Option<u32>)>>,
    /// Prompt program configuration (binary path, theme, etc.).
    pub prompt_config: PromptConfig,
}

impl std::fmt::Debug for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let order = self
            .backend_order
            .read()
            .map(|g| g.clone())
            .unwrap_or_default();
        f.debug_struct("ServiceState")
            .field("backends", &order)
            .finish()
    }
}

impl ServiceState {
    pub fn new(
        backends: Vec<Arc<dyn VaultBackend>>,
        router: Arc<Router>,
        sessions: Arc<SessionManager>,
        conn: Connection,
        tokio_handle: tokio::runtime::Handle,
    ) -> Self {
        Self::new_with_config(
            backends,
            router,
            sessions,
            conn,
            tokio_handle,
            HashMap::new(),
            HashMap::new(),
            PromptConfig::default(),
        )
    }

    /// Like `new`, but accepts per-backend `return_attr` patterns from config.
    ///
    /// `return_attr_map` maps backend ID → ordered glob patterns.  Backends
    /// not present in the map fall back to `DEFAULT_RETURN_ATTR`.
    pub fn new_with_return_attr(
        backends: Vec<Arc<dyn VaultBackend>>,
        router: Arc<Router>,
        sessions: Arc<SessionManager>,
        conn: Connection,
        tokio_handle: tokio::runtime::Handle,
        return_attr_map: HashMap<String, Vec<String>>,
    ) -> Self {
        Self::new_with_config(
            backends,
            router,
            sessions,
            conn,
            tokio_handle,
            return_attr_map,
            HashMap::new(),
            PromptConfig::default(),
        )
    }

    /// Full constructor: accepts `return_attr` patterns, collection map, and `PromptConfig`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_config(
        backends: Vec<Arc<dyn VaultBackend>>,
        router: Arc<Router>,
        sessions: Arc<SessionManager>,
        conn: Connection,
        tokio_handle: tokio::runtime::Handle,
        return_attr_map: HashMap<String, Vec<String>>,
        collection_map: HashMap<String, String>,
        prompt_config: PromptConfig,
    ) -> Self {
        let backend_order: Vec<String> = backends.iter().map(|b| b.id().to_string()).collect();
        let backends_map: HashMap<String, Arc<dyn VaultBackend>> = backends
            .into_iter()
            .map(|b| (b.id().to_string(), b))
            .collect();
        Self {
            backends: RwLock::new(backends_map),
            backend_order: RwLock::new(backend_order),
            return_attr_map: RwLock::new(return_attr_map),
            collection_map: RwLock::new(collection_map),
            router,
            sessions,
            items: Arc::new(Mutex::new(HashMap::new())),
            registered_items: Arc::new(Mutex::new(HashSet::new())),
            last_sync: Arc::new(Mutex::new(None)),
            conn,
            unlock_in_progress: tokio::sync::Mutex::new(()),
            sync_in_progress: std::sync::Mutex::new(HashMap::new()),
            last_activity: Mutex::new(None),
            unlocked_since: Mutex::new(None),
            tokio_handle,
            prompt_counter: AtomicU32::new(0),
            metadata_cache: Arc::new(Mutex::new(HashMap::new())),
            active_prompts: Mutex::new(HashMap::new()),
            prompt_config,
        }
    }

    /// Return the `return_attr` patterns for a given backend ID.
    ///
    /// Returns the configured patterns if present, otherwise the default list.
    fn return_attr_patterns(&self, backend_id: &str) -> Vec<String> {
        let map = self
            .return_attr_map
            .read()
            .unwrap_or_else(|e| e.into_inner());
        map.get(backend_id).cloned().unwrap_or_else(|| {
            DEFAULT_RETURN_ATTR
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        })
    }

    /// Resolve the primary secret for an item using `return_attr` patterns.
    ///
    /// Iterates the configured (or default) patterns in order and returns the
    /// first sensitive attribute that the backend can resolve.  Falls back to
    /// `backend.get_secret()` only when the backend does not support
    /// `get_secret_attr()` (i.e. returns `BackendError::NotSupported`).
    pub async fn resolve_primary_secret(
        &self,
        backend: Arc<dyn VaultBackend>,
        item_id: &str,
    ) -> Result<SecretBytes, BackendError> {
        let patterns = self.return_attr_patterns(backend.id());

        // Ask the backend for the available secret attribute names so we can
        // do pattern matching without calling get_secret_attr for every pattern.
        let attr_names: Vec<String> = match backend.get_item_attributes(item_id).await {
            Ok(ia) => ia.secret_names,
            // Backend doesn't support attribute model — fall back to legacy.
            Err(BackendError::NotSupported) => {
                return backend.get_secret(item_id).await;
            }
            Err(e) => return Err(e),
        };

        // Find the first secret_name that matches any return_attr pattern.
        for pattern in &patterns {
            let wm = WildMatch::new(pattern);
            if let Some(matched) = attr_names.iter().find(|n| wm.matches(n)) {
                match backend.get_secret_attr(item_id, matched).await {
                    Ok(secret) => return Ok(secret),
                    // Attr exists in the list but couldn't be resolved — skip.
                    Err(BackendError::NotFound) => continue,
                    Err(e) => return Err(e),
                }
            }
        }

        // No pattern matched — fall back to legacy get_secret.
        backend.get_secret(item_id).await
    }

    /// Resolve a D-Bus item path to the `(backend, item_id)` pair needed by
    /// the rosec extension D-Bus methods.
    ///
    /// Looks the path up in the item cache to find the backend ID and vault item
    /// ID, then returns the backend arc.  Returns an `FdoError` if not found.
    pub fn backend_and_id_for_path(
        &self,
        item_path: &str,
    ) -> Result<(Arc<dyn VaultBackend>, String), FdoError> {
        let items = self.items.lock().map_err(|_| {
            map_backend_error(BackendError::Unavailable("items lock poisoned".to_string()))
        })?;
        let meta = items
            .get(item_path)
            .ok_or_else(|| FdoError::Failed(format!("item '{item_path}' not found in cache")))?;
        let item_id = meta.id.clone();
        let backend_id = meta.backend_id.clone();
        drop(items);

        let backend = self
            .backend_by_id(&backend_id)
            .ok_or_else(|| FdoError::Failed(format!("backend '{backend_id}' not found")))?;
        Ok((backend, item_id))
    }

    /// Return all backends in configured order.
    pub fn backends_ordered(&self) -> Vec<Arc<dyn VaultBackend>> {
        let order = self.backend_order.read().unwrap_or_else(|e| e.into_inner());
        let map = self.backends.read().unwrap_or_else(|e| e.into_inner());
        order
            .iter()
            .filter_map(|id| map.get(id))
            .map(Arc::clone)
            .collect()
    }

    /// Look up a backend by its ID.
    pub fn backend_by_id(&self, id: &str) -> Option<Arc<dyn VaultBackend>> {
        self.backends
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .map(Arc::clone)
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

    /// Return the number of currently registered backends.
    pub fn backend_count(&self) -> usize {
        self.backends
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Hot-add a new backend at runtime.
    ///
    /// No-op if a backend with the same ID is already registered.
    pub fn hotreload_add_backend(&self, backend: Arc<dyn VaultBackend>) {
        let id = backend.id().to_string();
        let mut map = self.backends.write().unwrap_or_else(|e| e.into_inner());
        if map.contains_key(&id) {
            return;
        }
        map.insert(id.clone(), backend);
        drop(map);
        self.backend_order
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(id);
    }

    /// Hot-remove a backend at runtime.
    ///
    /// Locks the backend first to zeroize in-memory secrets, then drops it.
    /// Returns `true` if a backend with that ID was found and removed.
    pub async fn hotreload_remove_backend(&self, id: &str) -> bool {
        // Take the backend out of the map under write lock, then lock+drop outside.
        let backend = {
            let mut map = self.backends.write().unwrap_or_else(|e| e.into_inner());
            map.remove(id)
        };
        let found = backend.is_some();
        if let Some(b) = backend
            && let Err(e) = b.lock().await
        {
            warn!(backend_id = id, error = %e, "error locking backend during hot-remove");
        }
        // b is dropped here — Zeroizing<> fields zeroize on drop
        if found {
            self.backend_order
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|existing| existing != id);

            // Purge all items belonging to the removed backend from both caches
            // so they don't appear as ghost entries in SearchItems results.
            if let Ok(mut items) = self.items.lock() {
                items.retain(|_, meta| meta.backend_id != id);
            }
            if let Ok(mut cache) = self.metadata_cache.lock() {
                cache.retain(|_, meta| meta.backend_id != id);
            }
        }
        found
    }

    /// Allocate a unique prompt D-Bus path for the given backend and register
    /// it in `active_prompts` with no child PID yet (filled in by `Prompt()`).
    ///
    /// Returns the path string, e.g. `/org/freedesktop/secrets/prompt/p3`.
    pub fn allocate_prompt(&self, backend_id: &str) -> String {
        let n = self.prompt_counter.fetch_add(1, Ordering::Relaxed);
        let path = format!("/org/freedesktop/secrets/prompt/p{n}");
        if let Ok(mut map) = self.active_prompts.lock() {
            map.insert(path.clone(), (backend_id.to_string(), None));
        }
        path
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
    /// exited (the signal is silently ignored).
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
    }

    /// Remove a completed prompt from the registry without killing the child.
    pub fn finish_prompt(&self, prompt_path: &str) {
        if let Ok(mut map) = self.active_prompts.lock() {
            map.remove(prompt_path);
        }
    }

    /// Record that client activity has occurred (resets idle timer).
    pub fn touch_activity(&self) {
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Some(SystemTime::now());
        }
    }

    /// Record that the backend has been unlocked (starts max-unlocked timer).
    pub(crate) fn mark_unlocked(&self) {
        if let Ok(mut guard) = self.unlocked_since.lock() {
            *guard = Some(SystemTime::now());
        }
    }

    /// Clear the unlock timestamp (backend was locked).
    pub(crate) fn mark_locked(&self) {
        if let Ok(mut guard) = self.unlocked_since.lock() {
            *guard = None;
        }
    }

    /// Check if the backend should be auto-locked based on idle timeout.
    ///
    /// Returns `true` if the backend has been idle longer than `idle_minutes`.
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

    /// Check if the backend has been unlocked longer than `max_minutes`.
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

    /// Collect a password from the user for the given backend, using whichever
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
        backend_id: &str,
        label: &str,
    ) -> Result<Zeroizing<String>, FdoError> {
        use std::io::BufRead as _;
        use std::process::Stdio;

        let prompt_path = prompt_path.to_string();
        let backend_id_str = backend_id.to_string();

        // ── 1. SSH_ASKPASS ─────────────────────────────────────────────────
        if let Ok(askpass) = std::env::var("SSH_ASKPASS")
            && !askpass.is_empty()
        {
            tracing::debug!(program = %askpass, "using SSH_ASKPASS for prompt");
            let mut child = std::process::Command::new(&askpass)
                .arg(label) // prompt text as argv[1] (standard convention)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| {
                    FdoError::Failed(format!("SSH_ASKPASS '{askpass}' failed to launch: {e}"))
                })?;

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
            self.finish_prompt(&prompt_path);

            if !status.success() || password.is_empty() {
                return Err(FdoError::Failed(
                    "SSH_ASKPASS: cancelled or empty".to_string(),
                ));
            }
            return Ok(password);
        }

        // ── Resolve rosec-prompt binary ────────────────────────────────────
        let program = match self.prompt_config.backend.as_str() {
            "builtin" | "" => resolve_prompt_binary(),
            custom => custom.to_string(),
        };

        let has_display =
            std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();
        let has_tty = std::path::Path::new("/dev/tty").exists();

        // ── 2 & 3. GUI or TTY via rosec-prompt ────────────────────────────
        if has_display || has_tty {
            // Build the JSON request that rosec-prompt expects.
            let json = build_prompt_json(backend_id_str, label, &self.prompt_config);

            let mut cmd = std::process::Command::new(&program);
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());

            if !has_display {
                // No GUI available — request TTY mode.
                cmd.arg("--tty");
            }

            let mut child = cmd
                .spawn()
                .map_err(|e| FdoError::Failed(format!("rosec-prompt failed to launch: {e}")))?;

            let pid = child.id();
            self.set_prompt_pid(&prompt_path, pid);

            // Send JSON on stdin then close it.
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write as _;
                stdin
                    .write_all(json.as_bytes())
                    .map_err(|e| FdoError::Failed(format!("rosec-prompt stdin write: {e}")))?;
                // stdin dropped here → EOF sent to child
            }

            // Read one line of JSON from stdout ({"field_id": "value"}).
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
            self.finish_prompt(&prompt_path);

            if !status.success() {
                return Err(FdoError::Failed("prompt cancelled".to_string()));
            }

            // Parse the JSON map and extract the password field.
            // Use `take` to move the value out of the map so only one
            // allocation exists; then zeroize all remaining map values.
            let mut map: HashMap<String, String> = serde_json::from_str(response_line.trim())
                .map_err(|e| FdoError::Failed(format!("rosec-prompt JSON parse: {e}")))?;

            // Find the password field ID for this backend.
            let backend = self
                .backend_by_id(backend_id)
                .ok_or_else(|| FdoError::Failed(format!("backend '{backend_id}' not found")))?;
            let pw_id = backend.password_field().id.to_string();

            // Move the password out (avoiding a clone) then immediately zeroize
            // all remaining map values so no plain-String secrets linger.
            let raw_pw = map.remove(&pw_id);
            for v in map.values_mut() {
                zeroize::Zeroize::zeroize(v);
            }
            let password = raw_pw
                .filter(|v| !v.is_empty())
                .map(Zeroizing::new)
                .ok_or_else(|| FdoError::Failed("password field empty or missing".to_string()))?;

            return Ok(password);
        }

        // ── 4. Headless — cannot prompt ────────────────────────────────────
        self.finish_prompt(&prompt_path);
        Err(FdoError::Failed(format!(
            "headless: no display, no TTY, and SSH_ASKPASS is not set — \
             run `rosec auth {backend_id}` to unlock manually"
        )))
    }

    /// Lock all backends and clear auto-lock state.
    pub async fn auto_lock(&self) -> Result<(), FdoError> {
        for backend in self.backends_ordered() {
            self.run_on_tokio(async move { backend.lock().await })
                .await?
                .map_err(map_backend_error)?;
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
        info!("all backends auto-locked");
        Ok(())
    }

    /// Check if any backend is locked and, if so, unlock it.
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
    /// Iterates all backends in configured order.  For each locked backend:
    /// - If `backend.can_auto_unlock()` is `true` (e.g. SM token-based backends),
    ///   calls `backend.recover()` silently — no prompt is launched.
    /// - Otherwise, launches an interactive password prompt (PM backends).
    ///
    /// Uses a tokio mutex to prevent concurrent unlock flows.
    /// Returns an error if an interactive backend is locked and no prompt launcher
    /// is configured.
    pub(crate) async fn ensure_unlocked_inner(&self) -> Result<(), FdoError> {
        // Quick check — skip the mutex if all backends are already unlocked
        let mut any_locked = false;
        for backend in self.backends_ordered() {
            let status = backend.status().await.map_err(map_backend_error)?;
            if status.locked {
                any_locked = true;
                break;
            }
        }
        if !any_locked {
            return Ok(());
        }

        // Acquire the unlock mutex to prevent concurrent prompts
        let _guard = self.unlock_in_progress.lock().await;

        // Unlock each locked backend in order
        for backend in self.backends_ordered() {
            let status = backend.status().await.map_err(map_backend_error)?;
            if !status.locked {
                continue;
            }

            let backend_id = backend.id().to_string();

            if backend.can_auto_unlock() {
                // SM / token-based backends: silently re-authenticate.
                // A failure here is non-fatal for the overall unlock — it means
                // the stored credential is stale or missing for this backend, but
                // other backends should still be unlocked normally.
                tracing::debug!(backend = %backend_id, "attempting silent re-auth (auto-unlock)");
                match backend.recover().await.map_err(map_backend_error)? {
                    RecoveryOutcome::Recovered => {
                        tracing::debug!(backend = %backend_id, "silent re-auth succeeded");
                    }
                    RecoveryOutcome::Failed(reason) => {
                        warn!(backend = %backend_id, %reason,
                            "silent re-auth failed — backend will remain locked until re-authenticated");
                        // Continue to the next backend rather than aborting the whole unlock.
                        continue;
                    }
                }
            } else {
                // Interactive backend is locked — tell the client to authenticate.
                // The client (rosec CLI or any other caller) must call AuthBackend
                // with credentials collected on its side, then retry the operation.
                // This is the normal pre-unlock state; debug level to avoid log noise.
                tracing::debug!(backend = %backend_id, "backend is locked; client must call AuthBackend");
                return Err(FdoError::Failed(format!("locked::{backend_id}")));
            }
        }

        self.mark_unlocked();
        self.touch_activity();
        Ok(())
    }

    /// Authenticate/unlock a specific backend using caller-supplied field values.
    ///
    /// Called by the `AuthBackend` D-Bus method (used by `rosec auth`).
    /// Dispatches to Tokio so that the unlock future runs on the Tokio reactor.
    pub async fn auth_backend(
        self: &Arc<Self>,
        backend_id: &str,
        fields: HashMap<String, String>,
    ) -> Result<(), FdoError> {
        let this = Arc::clone(self);
        let backend_id = backend_id.to_string();
        self.tokio_handle
            .spawn(async move { this.auth_backend_inner(&backend_id, fields).await })
            .await
            .map_err(|e| FdoError::Failed(format!("auth task panicked: {e}")))?
    }

    async fn auth_backend_inner(
        &self,
        backend_id: &str,
        fields: HashMap<String, String>,
    ) -> Result<(), FdoError> {
        let backend = self
            .backend_by_id(backend_id)
            .ok_or_else(|| FdoError::Failed(format!("backend '{backend_id}' not found")))?;

        let pw_field = backend.password_field();
        let pw_field_id = pw_field.id;

        let password_value = fields.get(pw_field_id).ok_or_else(|| {
            FdoError::Failed(format!(
                "required field '{pw_field_id}' missing for backend '{backend_id}'"
            ))
        })?;

        if pw_field.required && password_value.is_empty() {
            return Err(FdoError::Failed(format!(
                "field '{pw_field_id}' must not be empty"
            )));
        }

        let password = Zeroizing::new(password_value.clone());

        // Collect any non-empty registration/auth fields supplied alongside the password.
        // Sources: registration_info fields (first-time setup) and auth_fields (e.g. token
        // rotation). Empty values are excluded so optional fields left blank don't trigger
        // WithRegistration unnecessarily.
        let reg_field_ids: std::collections::HashSet<&str> = backend
            .registration_info()
            .map(|ri| ri.fields.iter().map(|f| f.id).collect())
            .unwrap_or_default();
        let auth_field_ids: std::collections::HashSet<&str> =
            backend.auth_fields().iter().map(|f| f.id).collect();
        let all_extra_ids: std::collections::HashSet<&str> =
            reg_field_ids.union(&auth_field_ids).copied().collect();

        let registration_fields: HashMap<String, Zeroizing<String>> = fields
            .iter()
            .filter(|(k, v)| all_extra_ids.contains(k.as_str()) && !v.is_empty())
            .map(|(k, v)| (k.clone(), Zeroizing::new(v.clone())))
            .collect();

        let input = if registration_fields.is_empty() {
            UnlockInput::Password(password)
        } else {
            UnlockInput::WithRegistration {
                password,
                registration_fields,
            }
        };

        backend.unlock(input).await.map_err(map_backend_error)?;

        self.mark_unlocked();
        self.touch_activity();
        info!(backend = %backend_id, "backend authenticated via AuthBackend");
        Ok(())
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
            map_backend_error(BackendError::Unavailable("items lock poisoned".to_string()))
        })?;

        let mut unlocked = Vec::new();
        let mut locked = Vec::new();

        'item: for (path, meta) in items.iter() {
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

        Ok((unlocked, locked))
    }

    /// Search the persistent metadata cache using exact attribute matching.
    ///
    /// This is the method `SearchItems` should use: it reads from `metadata_cache`
    /// which survives lock/unlock cycles, and partitions results into
    /// `(unlocked_paths, locked_paths)`.  Never errors due to locked backends.
    ///
    /// Empty `attrs` returns all cached items.
    pub fn search_metadata_cache(
        &self,
        attrs: &HashMap<String, String>,
    ) -> Result<(Vec<String>, Vec<String>), FdoError> {
        let cache = self.metadata_cache.lock().map_err(|_| {
            map_backend_error(BackendError::Unavailable(
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

    /// Search the persistent metadata cache using glob patterns.
    ///
    /// Like `search_items_glob` but reads from `metadata_cache` (which survives
    /// lock/unlock cycles) instead of `items`.  Never errors due to locked
    /// backends.
    ///
    /// The special key `"name"` matches against the item label.
    pub fn search_metadata_cache_glob(
        &self,
        attrs: &HashMap<String, String>,
    ) -> Result<(Vec<String>, Vec<String>), FdoError> {
        let cache = self.metadata_cache.lock().map_err(|_| {
            map_backend_error(BackendError::Unavailable(
                "metadata_cache lock poisoned".to_string(),
            ))
        })?;

        let mut unlocked = Vec::new();
        let mut locked = Vec::new();

        'item: for (path, meta) in cache.iter() {
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

        Ok((unlocked, locked))
    }

    /// Mark all items belonging to a specific backend as locked in the
    /// persistent metadata cache.
    ///
    /// Called when a backend transitions to the locked state (auto-lock,
    /// manual lock, etc.).  Does NOT remove items — they remain queryable
    /// via `SearchItems` and friends, just in the `locked` partition.
    pub fn mark_backend_locked_in_cache(&self, backend_id: &str) {
        if let Ok(mut cache) = self.metadata_cache.lock() {
            for meta in cache.values_mut() {
                if meta.backend_id == backend_id {
                    meta.locked = true;
                }
            }
        }
    }

    /// Mark all items in the persistent metadata cache as locked.
    ///
    /// Called during `auto_lock` / `Lock` when all backends are locked at once.
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
    ) -> Result<Vec<(String, VaultItemMeta)>, FdoError> {
        // Path lookup is synchronous — no Tokio needed.
        if let Some(item_paths) = item_paths {
            let state_items = self.items.lock().map_err(|_| {
                map_backend_error(BackendError::Unavailable("items lock poisoned".to_string()))
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

    /// Return (or lazily create) the per-backend `tokio::sync::Mutex` used to
    /// coalesce concurrent sync operations.
    ///
    /// Two sync callers for the same backend will share one `Arc<Mutex<()>>`.
    /// An `await` caller serialises behind the in-flight sync; a `try_lock`
    /// caller (background timer, SignalR nudge) skips without redundant work.
    fn sync_mutex_for(&self, backend_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self
            .sync_in_progress
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.entry(backend_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Sync a specific backend against the remote server, then rebuild the cache.
    ///
    /// Uses a per-backend mutex to coalesce concurrent calls:
    /// - The caller **awaits** the lock, so if another sync is already running
    ///   it blocks until that one finishes (and returns immediately after,
    ///   since the cache is now fresh).
    /// - Background callers (timer, SignalR) should use `try_sync_backend`
    ///   instead to skip rather than wait.
    ///
    /// Dispatches to Tokio so that network and cache futures run on the Tokio reactor.
    pub async fn sync_backend(self: &Arc<Self>, backend_id: &str) -> Result<u32, FdoError> {
        let backend = self
            .backend_by_id(backend_id)
            .ok_or_else(|| FdoError::Failed(format!("backend '{backend_id}' not found")))?;

        let sync_mtx = self.sync_mutex_for(backend_id);
        // Await acquisition here, then move the owned guard into the spawned
        // task so it is held for the full sync+rebuild duration.
        let sync_guard = sync_mtx.lock_owned().await;
        let this = Arc::clone(self);
        let backend_id = backend_id.to_string();
        self.tokio_handle
            .spawn(async move {
                let _sync_guard = sync_guard; // held until task completes

                // For auto-unlock backends (e.g. SM), sync() handles its own
                // token loading — calling ensure_backend_unlocked first would
                // trigger recover() (a full fetch) immediately before sync()
                // does another full fetch.  Skip the pre-unlock step for those.
                // For interactive backends, we still need to ensure they are
                // unlocked before calling sync(), which just hits the API.
                if !backend.can_auto_unlock() {
                    this.ensure_backend_unlocked(&backend_id).await?;
                }
                backend.sync().await.map_err(map_backend_error)?;
                let entries = this.rebuild_cache_inner().await?;
                // Count only items belonging to this backend.
                let count = entries
                    .iter()
                    .filter(|(_, meta)| meta.backend_id == backend_id)
                    .count() as u32;
                Ok(count)
            })
            .await
            .map_err(|e| FdoError::Failed(format!("sync task panicked: {e}")))?
    }

    /// Attempt a background sync for a specific backend, skipping if one is
    /// already in progress.
    ///
    /// Intended for callers that have nothing to gain from waiting — the
    /// background refresh timer and the SignalR notification handler.  If a
    /// sync is already running the in-flight result will be fresh enough; no
    /// duplicate HTTP request is issued.
    ///
    /// Returns `true` if a sync was started, `false` if one was already running.
    pub async fn try_sync_backend(self: &Arc<Self>, backend_id: &str) -> Result<bool, FdoError> {
        let backend = self
            .backend_by_id(backend_id)
            .ok_or_else(|| FdoError::Failed(format!("backend '{backend_id}' not found")))?;

        let sync_mtx = self.sync_mutex_for(backend_id);

        // Non-blocking: attempt to acquire the guard here, then move it into
        // the spawned task.  The guard is held for the full sync+rebuild
        // duration so no concurrent caller can slip in between.
        let sync_guard = match sync_mtx.try_lock_owned() {
            Ok(g) => g,
            Err(_) => {
                tracing::debug!(backend = %backend_id, "sync already in progress, skipping");
                return Ok(false);
            }
        };

        let this = Arc::clone(self);
        let backend_id = backend_id.to_string();
        self.tokio_handle
            .spawn(async move {
                let _sync_guard = sync_guard; // held until task completes
                if !backend.can_auto_unlock() {
                    this.ensure_backend_unlocked(&backend_id).await?;
                }
                backend.sync().await.map_err(map_backend_error)?;
                this.rebuild_cache_inner().await?;
                Ok::<_, FdoError>(())
            })
            .await
            .map_err(|e| FdoError::Failed(format!("sync task panicked: {e}")))?
            .map(|_| true)
    }

    /// Ensure a *single* backend is unlocked.
    ///
    /// Mirrors the logic in `ensure_unlocked_inner` but scoped to one backend.
    /// Auto-unlock backends call `recover()`; interactive backends return a
    /// `locked::<id>` sentinel so the CLI can prompt the user.
    async fn ensure_backend_unlocked(&self, backend_id: &str) -> Result<(), FdoError> {
        let backend = self
            .backend_by_id(backend_id)
            .ok_or_else(|| FdoError::Failed(format!("backend '{backend_id}' not found")))?;

        let status = backend.status().await.map_err(map_backend_error)?;
        if !status.locked {
            return Ok(());
        }

        if backend.can_auto_unlock() {
            tracing::debug!(backend = %backend_id, "attempting silent re-auth (auto-unlock)");
            match backend.recover().await.map_err(map_backend_error)? {
                RecoveryOutcome::Recovered => {
                    tracing::debug!(backend = %backend_id, "silent re-auth succeeded");
                }
                RecoveryOutcome::Failed(reason) => {
                    warn!(backend = %backend_id, %reason, "silent re-auth failed");
                    return Err(FdoError::Failed(format!(
                        "auto-unlock failed for backend '{backend_id}': {reason}"
                    )));
                }
            }
        } else {
            tracing::debug!(backend = %backend_id, "backend is locked; client must call AuthBackend");
            return Err(FdoError::Failed(format!("locked::{backend_id}")));
        }

        self.mark_unlocked();
        self.touch_activity();
        Ok(())
    }

    /// Rebuild the item cache from in-memory backend state.
    /// Dispatches to Tokio so that unlock and list futures run on the Tokio reactor.
    pub async fn rebuild_cache(self: &Arc<Self>) -> Result<Vec<(String, VaultItemMeta)>, FdoError> {
        let this = Arc::clone(self);
        self.tokio_handle
            .spawn(async move { this.rebuild_cache_inner().await })
            .await
            .map_err(|e| FdoError::Failed(format!("cache rebuild task panicked: {e}")))?
    }

    pub(crate) async fn ensure_cache_inner(
        &self,
    ) -> Result<Vec<(String, VaultItemMeta)>, FdoError> {
        let has_items = self
            .items
            .lock()
            .map_err(|_| {
                map_backend_error(BackendError::Unavailable("items lock poisoned".to_string()))
            })
            .map(|g| !g.is_empty())?;

        if has_items {
            if self.should_rebuild_cache().unwrap_or(false) {
                return self.rebuild_cache_inner().await;
            }
            let state_items = self.items.lock().map_err(|_| {
                map_backend_error(BackendError::Unavailable("items lock poisoned".to_string()))
            })?;
            return Ok(state_items
                .iter()
                .map(|(path, item)| (path.clone(), item.clone()))
                .collect());
        }

        // First-time population: attempt to unlock interactive backends so the
        // initial cache contains as many items as possible.
        self.ensure_unlocked_inner().await?;
        let entries = self.fetch_entries().await?;
        self.register_items(&entries).await?;
        let mut state_items = self.items.lock().map_err(|_| {
            map_backend_error(BackendError::Unavailable("items lock poisoned".to_string()))
        })?;
        state_items.clear();
        for (path, item) in entries.iter() {
            state_items.insert(path.clone(), item.clone());
        }
        Ok(entries)
    }

    pub(crate) async fn rebuild_cache_inner(
        &self,
    ) -> Result<Vec<(String, VaultItemMeta)>, FdoError> {
        let entries = self.fetch_entries().await?;
        self.register_items(&entries).await?;

        // Determine which backends contributed fresh entries so we can
        // selectively replace only those backends' items, preserving
        // cached items from backends that were skipped (still locked).
        let fresh_backends: HashSet<String> = entries
            .iter()
            .map(|(_, meta)| meta.backend_id.clone())
            .collect();

        {
            let mut state_items = self.items.lock().map_err(|_| {
                map_backend_error(BackendError::Unavailable("items lock poisoned".to_string()))
            })?;
            // Remove old entries only for backends that were refreshed.
            state_items.retain(|_, meta| !fresh_backends.contains(&meta.backend_id));
            // Insert fresh entries.
            for (path, item) in entries.iter() {
                state_items.insert(path.clone(), item.clone());
            }
        }

        // Also populate the persistent metadata cache with the same
        // selective-replace strategy.  Items from backends that were
        // skipped during fetch_entries (still locked) retain their
        // previous metadata_cache entries with `locked: true`.
        {
            let mut cache = self.metadata_cache.lock().map_err(|_| {
                map_backend_error(BackendError::Unavailable(
                    "metadata_cache lock poisoned".to_string(),
                ))
            })?;
            // Remove old entries for backends that were refreshed.
            cache.retain(|_, meta| !fresh_backends.contains(&meta.backend_id));
            // Insert fresh entries.
            for (path, meta) in entries.iter() {
                cache.insert(path.clone(), meta.clone());
            }
        }

        self.update_cache_time()?;
        Ok(entries)
    }

    async fn fetch_entries(&self) -> Result<Vec<(String, VaultItemMeta)>, FdoError> {
        let mut all_items: Vec<VaultItemMeta> = Vec::new();
        let mut backend_ids: Vec<String> = Vec::new();
        for backend in self.backends_ordered() {
            let bid = backend.id().to_string();
            let result = self
                .run_on_tokio(async move { backend.list_items().await })
                .await?;
            let fetched = match result {
                Ok(items) => items,
                Err(BackendError::Locked) => {
                    // Auto-unlock backend (e.g. SM) whose recover() failed —
                    // skip it and continue with the remaining backends so the
                    // other backends' items still populate the cache.
                    warn!(backend = %bid, "skipping locked backend during cache fetch");
                    backend_ids.push(bid);
                    continue;
                }
                Err(e) => return Err(map_backend_error(e)),
            };
            // Tag each item with its backend_id and optional collection label.
            let collection_label: Option<String> = self
                .collection_map
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&bid)
                .cloned();
            let tagged: Vec<VaultItemMeta> = fetched
                .into_iter()
                .map(|mut item| {
                    if item.backend_id.is_empty() {
                        item.backend_id = bid.clone();
                    }
                    // Stamp collection label if configured and not already set
                    // by the backend itself.
                    if let Some(col) = &collection_label {
                        item.attributes
                            .entry("collection".to_string())
                            .or_insert_with(|| col.clone());
                    }
                    item
                })
                .collect();
            all_items.extend(tagged);
            backend_ids.push(bid);
        }
        let deduped = self.router.dedup(all_items, &backend_ids);
        let fallback_bid = backend_ids
            .first()
            .map(String::as_str)
            .unwrap_or("unknown")
            .to_string();
        let mut entries = Vec::with_capacity(deduped.len());
        for (idx, mut item) in deduped.into_iter().enumerate() {
            if item.backend_id.is_empty() {
                item.backend_id = fallback_bid.clone();
            }
            if item.id.is_empty() {
                item.id = format!("auto-{idx}");
            }
            let path = make_item_path(&item.backend_id, &item.id);
            entries.push((path, item));
        }
        Ok(entries)
    }

    fn should_rebuild_cache(&self) -> Result<bool, FdoError> {
        let last_sync = self.last_sync.lock().map_err(|_| {
            map_backend_error(BackendError::Unavailable("sync lock poisoned".to_string()))
        })?;
        if let Some(last_sync) = *last_sync {
            Ok(is_stale(last_sync, 1))
        } else {
            Ok(true)
        }
    }

    fn update_cache_time(&self) -> Result<(), FdoError> {
        let mut last_sync = self.last_sync.lock().map_err(|_| {
            map_backend_error(BackendError::Unavailable("sync lock poisoned".to_string()))
        })?;
        *last_sync = Some(SystemTime::now());
        Ok(())
    }

    pub(crate) async fn register_items(
        &self,
        entries: &[(String, VaultItemMeta)],
    ) -> Result<(), FdoError> {
        let server = self.conn.object_server();
        let mut pending = Vec::new();
        {
            let registered = self.registered_items.lock().map_err(|_| {
                map_backend_error(BackendError::Unavailable(
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
            // Look up the correct backend for this item
            let backend = self
                .backend_by_id(&item.backend_id)
                .or_else(|| self.backends_ordered().into_iter().next())
                .ok_or_else(|| {
                    map_backend_error(BackendError::Unavailable(format!(
                        "no backend found for item backend_id '{}'",
                        item.backend_id
                    )))
                })?;
            let return_attr_patterns = self.return_attr_patterns(&item.backend_id);
            let state = ItemState {
                meta: item.clone(),
                path: path.clone(),
                backend,
                sessions: self.sessions.clone(),
                return_attr_patterns,
                tokio_handle: self.tokio_handle.clone(),
            };
            server
                .at(path.clone(), SecretItem::new(state))
                .await
                .map_err(map_zbus_error)?;
        }

        let mut registered = self.registered_items.lock().map_err(|_| {
            map_backend_error(BackendError::Unavailable(
                "registered lock poisoned".to_string(),
            ))
        })?;
        for (path, _) in pending {
            registered.insert(path);
        }
        Ok(())
    }

    pub(crate) fn ensure_session(&self, session: &str) -> Result<(), FdoError> {
        self.sessions.validate(session).map_err(map_backend_error)
    }
}

// ---------------------------------------------------------------------------
// Prompt helpers (module-private)
// ---------------------------------------------------------------------------

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
fn build_prompt_json(backend_id: String, label: &str, cfg: &PromptConfig) -> String {
    use serde_json::{Value, json};
    let theme = &cfg.theme;
    let req: Value = json!({
        "title": label,
        "message": "",
        "hint": "",
        "backend": backend_id,
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
        "theme": {
            "background":         theme.background,
            "foreground":         theme.foreground,
            "border_color":       theme.border_color,
            "border_width":       theme.border_width,
            "font_family":        theme.font_family,
            "label_color":        theme.label_color,
            "accent_color":       theme.accent_color,
            "confirm_background": theme.confirm_background,
            "confirm_text":       theme.confirm_text,
            "cancel_background":  theme.cancel_background,
            "cancel_text":        theme.cancel_text,
            "input_background":   theme.input_background,
            "input_text":         theme.input_text,
            "font_size":          theme.font_size,
        }
    });
    req.to_string()
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(crate) fn map_backend_error(err: BackendError) -> FdoError {
    match err {
        BackendError::Locked => FdoError::Failed("locked".to_string()),
        BackendError::NotFound => FdoError::Failed("not found".to_string()),
        BackendError::NotSupported => FdoError::NotSupported("not supported".to_string()),
        // Unavailable carries a reason string already intended for callers
        // (e.g. "backend locked", "network unreachable") — pass it through.
        BackendError::Unavailable(reason) => FdoError::Failed(reason),
        // Sentinel string detected by the CLI to trigger the registration retry flow.
        BackendError::RegistrationRequired => FdoError::Failed("registration_required".to_string()),
        // Other/internal errors: log the full chain server-side, return an
        // opaque message to the D-Bus caller to avoid leaking internal detail
        // (cipher UUIDs, server HTTP bodies, file paths, etc.).
        BackendError::Other(err) => {
            warn!(error = %err, "internal backend error");
            FdoError::Failed("backend error".to_string())
        }
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

pub(crate) fn make_item_path(backend: &str, item_id: &str) -> String {
    let backend_part = sanitize_component(backend);
    let item_part = sanitize_component(item_id);
    let hash = hash_id(&format!("{backend}:{item_id}"));
    format!("/org/freedesktop/secrets/collection/default/{backend_part}_{item_part}_{hash:016x}")
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
mod tests {
    use super::*;
    use std::sync::Arc;

    use rosec_core::router::RouterConfig;
    use rosec_core::{BackendStatus, RecoveryOutcome, SecretBytes, UnlockInput, VaultItem};

    #[derive(Debug)]
    struct MockBackend {
        items: Vec<VaultItemMeta>,
    }

    impl MockBackend {
        fn new(items: Vec<VaultItemMeta>) -> Self {
            Self { items }
        }
    }

    #[async_trait::async_trait]
    impl VaultBackend for MockBackend {
        fn id(&self) -> &str {
            "mock"
        }

        fn name(&self) -> &str {
            "Mock"
        }

        fn kind(&self) -> &str {
            "mock"
        }

        async fn status(&self) -> Result<BackendStatus, BackendError> {
            Ok(BackendStatus {
                locked: false,
                last_sync: None,
            })
        }

        async fn unlock(&self, _input: UnlockInput) -> Result<(), BackendError> {
            Ok(())
        }

        async fn lock(&self) -> Result<(), BackendError> {
            Ok(())
        }

        async fn recover(&self) -> Result<RecoveryOutcome, BackendError> {
            Ok(RecoveryOutcome::Recovered)
        }

        async fn list_items(&self) -> Result<Vec<VaultItemMeta>, BackendError> {
            Ok(self.items.clone())
        }

        async fn get_item(&self, id: &str) -> Result<VaultItem, BackendError> {
            let meta = self
                .items
                .iter()
                .find(|item| item.id == id)
                .cloned()
                .ok_or(BackendError::NotFound)?;
            Ok(VaultItem { meta, secret: None })
        }

        async fn get_secret(&self, id: &str) -> Result<SecretBytes, BackendError> {
            Ok(SecretBytes::new(format!("secret-{id}").into_bytes()))
        }

        async fn search(&self, attrs: &Attributes) -> Result<Vec<VaultItemMeta>, BackendError> {
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
        /// All others return `NotSupported` so the fallback to `get_secret` is tested.
        async fn get_item_attributes(
            &self,
            id: &str,
        ) -> Result<rosec_core::ItemAttributes, BackendError> {
            if id == "rich-item" {
                Ok(rosec_core::ItemAttributes {
                    public: Attributes::new(),
                    secret_names: vec!["password".to_string(), "totp".to_string()],
                })
            } else {
                Err(BackendError::NotSupported)
            }
        }

        async fn get_secret_attr(&self, id: &str, attr: &str) -> Result<SecretBytes, BackendError> {
            if id == "rich-item" && attr == "password" {
                Ok(SecretBytes::new(b"rich-password".to_vec()))
            } else if id == "rich-item" && attr == "totp" {
                Ok(SecretBytes::new(b"JBSWY3DPEHPK3PXP".to_vec()))
            } else {
                Err(BackendError::NotFound)
            }
        }
    }

    async fn new_state(items: Vec<VaultItemMeta>) -> Arc<ServiceState> {
        let backend = Arc::new(MockBackend::new(items));
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
            vec![backend],
            router,
            sessions,
            conn,
            tokio::runtime::Handle::current(),
        ))
    }

    fn meta(id: &str, label: &str, locked: bool) -> VaultItemMeta {
        VaultItemMeta {
            id: id.to_string(),
            backend_id: "mock".to_string(),
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
        let backend = state.backend_by_id(&item_meta.backend_id).expect("backend");
        let secret = backend.get_secret(&item_meta.id).await.expect("get_secret");
        let value = crate::service::build_secret_value(&session, &secret, aes_key.as_deref())
            .expect("build_secret_value");

        // Verify we got a valid secret tuple (session, params, value, content_type)
        let _path_str = path; // just ensure the path was resolved
        // The value should be a struct with 4 fields
        assert!(!format!("{value:?}").is_empty());
    }

    // -----------------------------------------------------------------------
    // resolve_primary_secret tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn resolve_primary_secret_uses_return_attr_pattern() {
        // rich-item has password + totp; default patterns match "password" first.
        let state = new_state(vec![meta("rich-item", "rich", false)]).await;
        let backend = state.backend_by_id("mock").expect("mock backend");
        let secret = state
            .resolve_primary_secret(backend, "rich-item")
            .await
            .expect("resolve should succeed");
        assert_eq!(secret.as_slice(), b"rich-password");
    }

    #[tokio::test]
    async fn resolve_primary_secret_falls_back_to_get_secret_when_not_supported() {
        // plain-item triggers NotSupported from get_item_attributes → falls back.
        let state = new_state(vec![meta("plain-item", "plain", false)]).await;
        let backend = state.backend_by_id("mock").expect("mock backend");
        let secret = state
            .resolve_primary_secret(backend, "plain-item")
            .await
            .expect("resolve should succeed via fallback");
        assert_eq!(secret.as_slice(), b"secret-plain-item");
    }

    #[tokio::test]
    async fn resolve_primary_secret_custom_pattern_selects_totp() {
        // Configure the state with totp as the first return_attr for "mock".
        let backend = Arc::new(MockBackend::new(vec![meta("rich-item", "rich", false)]));
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
            vec![backend],
            router,
            sessions,
            conn,
            tokio::runtime::Handle::current(),
            map,
        ));
        let backend = state.backend_by_id("mock").expect("mock backend");
        let secret = state
            .resolve_primary_secret(backend, "rich-item")
            .await
            .expect("resolve should return totp");
        assert_eq!(secret.as_slice(), b"JBSWY3DPEHPK3PXP");
    }

    // -----------------------------------------------------------------------
    // backend_and_id_for_path tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn backend_and_id_for_path_resolves_cached_item() {
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
        let (backend, item_id) = state
            .backend_and_id_for_path(&path)
            .expect("should resolve");
        assert_eq!(backend.id(), "mock");
        assert_eq!(item_id, "item-1");
    }

    #[tokio::test]
    async fn backend_and_id_for_path_errors_on_unknown_path() {
        let state = new_state(vec![]).await;
        let result = state.backend_and_id_for_path("/nonexistent/path");
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
