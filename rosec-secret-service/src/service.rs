use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rosec_core::prompt::PromptContext;
use rosec_core::router::Router;
use rosec_core::dedup::is_stale;
use rosec_core::{Attributes, BackendError, UnlockInput, VaultBackend, VaultItemMeta};
use tracing::{info, warn};
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::Connection;

use crate::PromptLauncher;
use crate::session::SessionManager;
use crate::item::{ItemState, SecretItem};

pub struct ServiceState {
    pub backend: Arc<dyn VaultBackend>,
    pub router: Arc<Router>,
    pub sessions: Arc<SessionManager>,
    pub items: Arc<Mutex<HashMap<String, VaultItemMeta>>>,
    pub registered_items: Arc<Mutex<HashSet<String>>>,
    pub last_refresh: Arc<Mutex<Option<SystemTime>>>,
    pub conn: Connection,
    /// Prompt launcher for requesting master password from user.
    prompt_launcher: Mutex<Option<Arc<PromptLauncher>>>,
    /// Prevents multiple simultaneous unlock prompts.
    unlock_in_progress: tokio::sync::Mutex<()>,
    /// Timestamp of the last client activity (D-Bus method call).
    last_activity: Mutex<Option<SystemTime>>,
    /// Timestamp when the backend was unlocked (for max-unlocked policy).
    unlocked_since: Mutex<Option<SystemTime>>,
}

impl std::fmt::Debug for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceState")
            .field("backend", &self.backend.id())
            .finish()
    }
}

impl ServiceState {
    pub fn new(
        backend: Arc<dyn VaultBackend>,
        router: Arc<Router>,
        sessions: Arc<SessionManager>,
        conn: Connection,
    ) -> Self {
        Self {
            backend,
            router,
            sessions,
            items: Arc::new(Mutex::new(HashMap::new())),
            registered_items: Arc::new(Mutex::new(HashSet::new())),
            last_refresh: Arc::new(Mutex::new(None)),
            conn,
            prompt_launcher: Mutex::new(None),
            unlock_in_progress: tokio::sync::Mutex::new(()),
            last_activity: Mutex::new(None),
            unlocked_since: Mutex::new(None),
        }
    }

    /// Set the prompt launcher for unlock prompts.
    ///
    /// Can be called after the `ServiceState` is wrapped in `Arc`.
    pub fn set_prompt_launcher(&self, launcher: PromptLauncher) {
        if let Ok(mut guard) = self.prompt_launcher.lock() {
            *guard = Some(Arc::new(launcher));
        }
    }

    /// Record that client activity has occurred (resets idle timer).
    pub fn touch_activity(&self) {
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Some(SystemTime::now());
        }
    }

    /// Record that the backend has been unlocked (starts max-unlocked timer).
    fn mark_unlocked(&self) {
        if let Ok(mut guard) = self.unlocked_since.lock() {
            *guard = Some(SystemTime::now());
        }
    }

    /// Clear the unlock timestamp (backend was locked).
    fn mark_locked(&self) {
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
                let elapsed = SystemTime::now()
                    .duration_since(last)
                    .unwrap_or_default();
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
                let elapsed = SystemTime::now()
                    .duration_since(since)
                    .unwrap_or_default();
                elapsed.as_secs() >= max_minutes * 60
            }
            None => false,
        }
    }

    /// Lock the backend and clear auto-lock state.
    pub async fn auto_lock(&self) -> Result<(), FdoError> {
        self.backend.lock().await.map_err(map_backend_error)?;
        self.mark_locked();
        info!("backend auto-locked");
        Ok(())
    }
}

pub struct SecretService {
    state: Arc<ServiceState>,
}

impl SecretService {
    pub fn new(state: Arc<ServiceState>) -> Self {
        Self { state }
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl SecretService {
    #[zbus(property)]
    fn collections(&self) -> Vec<String> {
        vec!["/org/freedesktop/secrets/collection/default".to_string()]
    }

    async fn open_session(
        &self,
        algorithm: &str,
        _input: zvariant::Value<'_>,
    ) -> Result<(zvariant::Value<'_>, String), FdoError> {
        let (output, path) = self
            .state
            .sessions
            .open_session(algorithm)
            .map_err(map_backend_error)?;

        // Register the org.freedesktop.Secret.Session object at the session path
        let session_obj = crate::session_iface::SecretSession::new(
            path.clone(),
            Arc::clone(&self.state.sessions),
        );
        let server = self.state.conn.object_server();
        server
            .at(path.clone(), session_obj)
            .await
            .map_err(map_zbus_error)?;

        Ok((output, path))
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(Vec<String>, Vec<String>), FdoError> {
        self.state.touch_activity();
        let items = self.state.resolve_items(Some(attributes), None).await?;
        let mut unlocked_paths = Vec::new();
        let mut locked_paths = Vec::new();
        for (path, item) in items {
            if item.locked {
                locked_paths.push(path);
            } else {
                unlocked_paths.push(path);
            }
        }
        Ok((unlocked_paths, locked_paths))
    }

    async fn get_secrets(
        &self,
        items: Vec<String>,
        session: &str,
    ) -> Result<HashMap<String, zvariant::Value<'_>>, FdoError> {
        self.state.touch_activity();
        self.state.ensure_session(session)?;
        let resolved = self.state.resolve_items(None, Some(&items)).await?;
        let mut secrets = HashMap::new();
        for (path, item) in resolved {
            if item.locked {
                continue;
            }
            let secret = self
                .state
                .backend
                .get_secret(&item.id)
                .await
                .map_err(map_backend_error)?;
            let value = build_secret_value(session, &secret)?;
            secrets.insert(path, value);
        }
        Ok(secrets)
    }

    fn close_session(&self, session: &str) -> Result<(), FdoError> {
        self.state
            .sessions
            .close_session(session)
            .map_err(map_backend_error)
    }

    fn read_alias(&self, name: &str) -> Result<String, FdoError> {
        if name == "default" {
            Ok("/org/freedesktop/secrets/collection/default".to_string())
        } else {
            Ok("/".to_string())
        }
    }

    fn set_alias(&self, _name: &str, _collection: &str) -> Result<(), FdoError> {
        Err(FdoError::NotSupported("read-only".to_string()))
    }

    async fn lock(&self, objects: Vec<String>) -> Result<(Vec<String>, String), FdoError> {
        self.state.backend.lock().await.map_err(map_backend_error)?;
        self.state.mark_locked();
        // Return the requested objects as "locked" and no prompt needed
        Ok((objects, "/".to_string()))
    }

    async fn unlock(&self, objects: Vec<String>) -> Result<(Vec<String>, String), FdoError> {
        self.state.ensure_unlocked().await?;
        // After unlock, return the requested objects as "immediately unlocked"
        Ok((objects, "/".to_string()))
    }

    fn create_collection(
        &self,
        _properties: HashMap<String, zvariant::Value<'_>>,
        _alias: String,
    ) -> Result<(String, String), FdoError> {
        Err(FdoError::NotSupported("read-only".to_string()))
    }
}

impl ServiceState {
    /// Check if the backend is locked and, if so, prompt the user for a password.
    ///
    /// Uses a tokio mutex to prevent multiple simultaneous prompts.
    /// If no prompt launcher is configured and the backend is locked,
    /// returns a "locked" error.
    pub async fn ensure_unlocked(&self) -> Result<(), FdoError> {
        // Quick check — avoid the lock if already unlocked
        let status = self
            .backend
            .status()
            .await
            .map_err(map_backend_error)?;

        if !status.locked {
            return Ok(());
        }

        // Acquire the unlock mutex to prevent concurrent prompts
        let _guard = self.unlock_in_progress.lock().await;

        // Re-check after acquiring the lock — another caller may have unlocked
        let status = self
            .backend
            .status()
            .await
            .map_err(map_backend_error)?;

        if !status.locked {
            return Ok(());
        }

        let launcher = {
            let guard = self.prompt_launcher.lock().map_err(|_| {
                FdoError::Failed("prompt_launcher lock poisoned".to_string())
            })?;
            match guard.as_ref() {
                Some(l) => Arc::clone(l),
                None => {
                    warn!("backend is locked and no prompt launcher configured");
                    return Err(FdoError::Failed(
                        "vault is locked (no prompt configured)".to_string(),
                    ));
                }
            }
        };

        let backend_name = self.backend.name().to_string();
        let backend_id = self.backend.id().to_string();

        info!(backend = %backend_id, "launching unlock prompt");

        // Run the prompt on a blocking thread (it spawns a subprocess)
        let context = PromptContext {
            title: "Unlock Vault".to_string(),
            message: format!("Enter master password for {backend_name}"),
            hint: format!("Backend: {backend_id}"),
            backend: backend_id.clone(),
        };

        let password = tokio::task::spawn_blocking(move || launcher.prompt(context))
            .await
            .map_err(|e| FdoError::Failed(format!("prompt task panicked: {e}")))?
            .map_err(map_backend_error)?;

        if password.is_empty() {
            return Err(FdoError::Failed("unlock cancelled (empty password)".to_string()));
        }

        // Unlock the backend
        self.backend
            .unlock(UnlockInput::Password(zeroize::Zeroizing::new(password)))
            .await
            .map_err(map_backend_error)?;

        self.mark_unlocked();
        self.touch_activity();

        info!(backend = %backend_id, "vault unlocked");
        Ok(())
    }

    pub async fn resolve_items(
        &self,
        attributes: Option<HashMap<String, String>>,
        item_paths: Option<&[String]>,
    ) -> Result<Vec<(String, VaultItemMeta)>, FdoError> {
        let items = if let Some(item_paths) = item_paths {
            let state_items = self.items.lock().map_err(|_| {
                map_backend_error(BackendError::Unavailable("items lock poisoned".to_string()))
            })?;
            item_paths
                .iter()
                .filter_map(|path| {
                    let item = state_items.get(path)?;
                    Some((path.clone(), item.clone()))
                })
                .collect::<Vec<_>>()
        } else {
            let entries = if attributes.is_some() {
                self.refresh_items().await?
            } else {
                self.ensure_cache().await?
            };
            if let Some(attrs) = attributes {
                let attrs: Attributes = attrs.into_iter().collect();
                entries
                    .into_iter()
                    .filter(|(_, item)| attributes_match(&item.attributes, &attrs))
                    .collect()
            } else {
                entries
            }
        };
        Ok(items)
    }

    pub async fn ensure_cache(&self) -> Result<Vec<(String, VaultItemMeta)>, FdoError> {
        let mut has_items = false;
        {
            let state_items = self.items.lock().map_err(|_| {
                map_backend_error(BackendError::Unavailable("items lock poisoned".to_string()))
            })?;
            if !state_items.is_empty() {
                has_items = true;
            }
        }
        if has_items {
            if self.should_refresh().unwrap_or(false) {
                return self.refresh_items().await;
            }
            let state_items = self.items.lock().map_err(|_| {
                map_backend_error(BackendError::Unavailable("items lock poisoned".to_string()))
            })?;
            let entries = state_items
                .iter()
                .map(|(path, item)| (path.clone(), item.clone()))
                .collect();
            return Ok(entries);
        }

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

    pub async fn refresh_items(&self) -> Result<Vec<(String, VaultItemMeta)>, FdoError> {
        let entries = self.fetch_entries().await?;

        self.register_items(&entries).await?;

        let mut state_items = self.items.lock().map_err(|_| {
            map_backend_error(BackendError::Unavailable("items lock poisoned".to_string()))
        })?;
        state_items.clear();
        for (path, item) in entries.iter() {
            state_items.insert(path.clone(), item.clone());
        }
        self.update_refresh_time()?;

        Ok(entries)
    }

    async fn fetch_entries(&self) -> Result<Vec<(String, VaultItemMeta)>, FdoError> {
        self.ensure_unlocked().await?;
        let fetched = self.backend.list_items().await.map_err(map_backend_error)?;
        let backend_id = self.backend.id();
        let deduped = self.router.dedup(fetched, &[backend_id.to_string()]);
        Ok(build_state_items(deduped, backend_id))
    }

    fn should_refresh(&self) -> Result<bool, FdoError> {
        let last_refresh = self
            .last_refresh
            .lock()
            .map_err(|_| map_backend_error(BackendError::Unavailable("refresh lock poisoned".to_string())))?;
        if let Some(last_refresh) = *last_refresh {
            Ok(is_stale(last_refresh, 1))
        } else {
            Ok(true)
        }
    }

    fn update_refresh_time(&self) -> Result<(), FdoError> {
        let mut last_refresh = self
            .last_refresh
            .lock()
            .map_err(|_| map_backend_error(BackendError::Unavailable("refresh lock poisoned".to_string())))?;
        *last_refresh = Some(SystemTime::now());
        Ok(())
    }

    async fn register_items(
        &self,
        entries: &[(String, VaultItemMeta)],
    ) -> Result<(), FdoError> {
        let server = self.conn.object_server();
        let mut pending = Vec::new();
        {
            let registered = self
                .registered_items
                .lock()
                .map_err(|_| map_backend_error(BackendError::Unavailable("registered lock poisoned".to_string())))?;
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
            let state = ItemState {
                meta: item.clone(),
                path: path.clone(),
                backend: self.backend.clone(),
                sessions: self.sessions.clone(),
            };
            server
                .at(path.clone(), SecretItem::new(state))
                .await
                .map_err(map_zbus_error)?;
        }

        let mut registered = self
            .registered_items
            .lock()
            .map_err(|_| map_backend_error(BackendError::Unavailable("registered lock poisoned".to_string())))?;
        for (path, _) in pending {
            registered.insert(path);
        }
        Ok(())
    }

    fn ensure_session(&self, session: &str) -> Result<(), FdoError> {
        self.sessions.validate(session).map_err(map_backend_error)
    }
}

fn build_state_items(items: Vec<VaultItemMeta>, backend_id: &str) -> Vec<(String, VaultItemMeta)> {
    let mut entries = Vec::with_capacity(items.len());
    for (idx, mut item) in items.into_iter().enumerate() {
        if item.backend_id.is_empty() {
            item.backend_id = backend_id.to_string();
        }
        if item.id.is_empty() {
            item.id = format!("auto-{idx}");
        }
        let path = make_item_path(&item.backend_id, &item.id);
        entries.push((path, item));
    }
    entries
}

/// Build a Secret struct per the D-Bus Secret Service spec:
/// `(ObjectPath session, Array<Byte> parameters, Array<Byte> value, String content_type)`
///
/// # Security note
///
/// The `value` field is copied into a plain `Vec<u8>` here because `zvariant::Value`
/// requires owned, non-zeroizing types. This means the secret bytes briefly exist as
/// a non-zeroized buffer while in transit over D-Bus. This is an inherent limitation
/// of the zbus/zvariant API — there is no way to use `Zeroizing<Vec<u8>>` inside a
/// `zvariant::Value`. The D-Bus transport itself provides no encryption (use session
/// encryption or a trusted bus for sensitive workloads).
pub(crate) fn build_secret_value(
    session_path: &str,
    secret: &rosec_core::SecretBytes,
) -> Result<zvariant::Value<'static>, FdoError> {
    let session = zvariant::OwnedObjectPath::try_from(session_path.to_string())
        .map_err(|_| FdoError::Failed("invalid session path".to_string()))?;
    let secret_tuple: (zvariant::OwnedObjectPath, Vec<u8>, Vec<u8>, String) = (
        session,
        Vec::new(),
        secret.as_slice().to_vec(),
        "text/plain".to_string(),
    );
    Ok(zvariant::Value::from(secret_tuple))
}

fn attributes_match(item: &Attributes, query: &Attributes) -> bool {
    query
        .iter()
        .all(|(key, value)| item.get(key) == Some(value))
}

fn make_item_path(backend: &str, item_id: &str) -> String {
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

fn hash_id(input: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish()
}

pub(crate) fn map_backend_error(err: BackendError) -> FdoError {
    match err {
        BackendError::Locked => FdoError::Failed("locked".to_string()),
        BackendError::NotFound => FdoError::Failed("not found".to_string()),
        BackendError::NotSupported => FdoError::NotSupported("not supported".to_string()),
        BackendError::Unavailable(reason) => FdoError::Failed(reason),
        BackendError::Other(err) => FdoError::Failed(err.to_string()),
    }
}

fn map_zbus_error(err: zbus::Error) -> FdoError {
    FdoError::Failed(format!("dbus error: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use rosec_core::{BackendStatus, RecoveryOutcome, SecretBytes, UnlockInput, VaultItem};
    use rosec_core::router::RouterConfig;

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
    }

    async fn new_service(items: Vec<VaultItemMeta>) -> (SecretService, Arc<ServiceState>) {
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
        let state = Arc::new(ServiceState::new(backend, router, sessions, conn));
        (SecretService::new(Arc::clone(&state)), state)
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
        let (service, _state) = new_service(items).await;
        let (unlocked, locked) = match service.search_items(HashMap::new()).await {
            Ok(result) => result,
            Err(err) => panic!("search_items failed: {err}"),
        };
        assert_eq!(unlocked.len(), 1);
        assert_eq!(locked.len(), 1);
        assert!(unlocked[0].starts_with("/org/freedesktop/secrets/collection/default/"));
        assert!(locked[0].starts_with("/org/freedesktop/secrets/collection/default/"));
    }

    #[tokio::test]
    async fn get_secrets_requires_valid_session() {
        let items = vec![meta("item-1", "one", false)];
        let (service, state) = new_service(items).await;
        let (unlocked, _) = match service.search_items(HashMap::new()).await {
            Ok(result) => result,
            Err(err) => panic!("search_items failed: {err}"),
        };
        let path = unlocked.first().cloned().expect("item path");
        let invalid = service.get_secrets(vec![path.clone()], "invalid").await;
        assert!(invalid.is_err());

        // Open session via SessionManager directly (open_session D-Bus method is not public)
        let session = match state.sessions.open_session("plain") {
            Ok((_, path)) => path,
            Err(err) => panic!("open_session failed: {err}"),
        };
        let secrets = match service.get_secrets(vec![path], &session).await {
            Ok(result) => result,
            Err(err) => panic!("get_secrets failed: {err}"),
        };
        assert_eq!(secrets.len(), 1);
    }
}
