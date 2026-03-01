use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use rosec_core::{BackendError, VaultBackend, VaultItemMeta};
use tracing::info;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zvariant::{ObjectPath, OwnedObjectPath};

use crate::service::{build_secret_value, to_object_path};
use crate::session::SessionManager;
use crate::state::map_backend_error;

#[derive(Clone)]
pub struct ItemState {
    pub meta: VaultItemMeta,
    pub path: String,
    pub backend: Arc<dyn VaultBackend>,
    pub sessions: Arc<SessionManager>,
    /// Ordered glob patterns for selecting which sensitive attribute to return
    /// from `GetSecret`.  Derived from the backend's `return_attr` config.
    pub return_attr_patterns: Vec<String>,
    /// Tokio runtime handle — required to bridge zbus's async-io executor with
    /// backend futures that depend on the Tokio reactor (e.g. reqwest).
    pub tokio_handle: tokio::runtime::Handle,
    /// Reference to service state for cache updates.
    pub items_cache: Arc<std::sync::Mutex<HashMap<String, VaultItemMeta>>>,
}

pub struct SecretItem {
    state: ItemState,
}

impl SecretItem {
    pub fn new(state: ItemState) -> Self {
        Self { state }
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl SecretItem {
    #[zbus(property)]
    fn label(&self) -> String {
        self.state.meta.label.clone()
    }

    #[zbus(property)]
    fn attributes(&self) -> HashMap<String, String> {
        self.state.meta.attributes.clone()
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        self.state.meta.locked
    }

    /// Unix timestamp when the item was created (0 if unknown).
    #[zbus(property)]
    fn created(&self) -> u64 {
        self.state
            .meta
            .created
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Unix timestamp when the item was last modified (0 if unknown).
    #[zbus(property)]
    fn modified(&self) -> u64 {
        self.state
            .meta
            .modified
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    async fn get_secret(
        &self,
        session: ObjectPath<'_>,
    ) -> Result<zvariant::Value<'static>, FdoError> {
        use wildmatch::WildMatch;

        let session = session.as_str();
        ensure_session(&self.state.sessions, session)?;
        if self.state.meta.locked {
            return Err(FdoError::Failed("locked".to_string()));
        }
        let aes_key = self
            .state
            .sessions
            .get_session_key(session)
            .map_err(map_backend_error)?;

        let backend = Arc::clone(&self.state.backend);
        let item_id = self.state.meta.id.clone();
        let patterns = self.state.return_attr_patterns.clone();

        let secret = self
            .state
            .tokio_handle
            .spawn(async move {
                // Try return_attr resolution first.
                match backend.get_item_attributes(&item_id).await {
                    Ok(ia) => {
                        for pattern in &patterns {
                            let wm = WildMatch::new(pattern);
                            if let Some(matched) = ia.secret_names.iter().find(|n| wm.matches(n)) {
                                match backend.get_secret_attr(&item_id, matched).await {
                                    Ok(s) => return Ok(s),
                                    Err(BackendError::NotFound) => continue,
                                    Err(e) => return Err(e),
                                }
                            }
                        }
                        // No pattern matched — fall back.
                        backend.get_secret(&item_id).await
                    }
                    // Backend doesn't support attribute model — use legacy path.
                    Err(BackendError::NotSupported) => backend.get_secret(&item_id).await,
                    Err(e) => Err(e),
                }
            })
            .await
            .map_err(|e| FdoError::Failed(format!("tokio task panicked: {e}")))?
            .map_err(map_backend_error)?;

        build_secret_value(session, &secret, aes_key.as_deref())
    }

    fn set_secret(&self, _secret: zvariant::Value) -> Result<(), FdoError> {
        Err(FdoError::NotSupported(
            "use CreateItem with replace=true".to_string(),
        ))
    }

    async fn delete(&self) -> Result<OwnedObjectPath, FdoError> {
        if !self.state.backend.supports_writes() {
            return Err(FdoError::NotSupported(
                "backend does not support write operations".to_string(),
            ));
        }

        let item_id = self.state.meta.id.clone();
        let item_path = self.state.path.clone();
        let backend = Arc::clone(&self.state.backend);
        let items_cache = Arc::clone(&self.state.items_cache);
        let backend_id = backend.id().to_string();
        let item_id_for_log = item_id.clone();

        self.state
            .tokio_handle
            .spawn(async move { backend.delete_item(&item_id).await })
            .await
            .map_err(|e| FdoError::Failed(format!("tokio task panicked: {e}")))?
            .map_err(map_backend_error)?;

        info!(item_id = %item_id_for_log, backend = %backend_id, "deleted item via D-Bus");

        if let Ok(mut items) = items_cache.lock() {
            items.remove(&item_path);
        }

        // No prompt needed — return "/" per the spec.
        Ok(to_object_path("/"))
    }
}

fn ensure_session(sessions: &SessionManager, session: &str) -> Result<(), FdoError> {
    sessions.validate(session).map_err(map_backend_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rosec_core::{
        Attributes, BackendError, BackendStatus, SecretBytes, UnlockInput, VaultItem,
    };

    #[derive(Debug)]
    struct MockBackend;

    #[async_trait::async_trait]
    impl VaultBackend for MockBackend {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

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

        async fn list_items(&self) -> Result<Vec<VaultItemMeta>, BackendError> {
            Ok(Vec::new())
        }

        async fn get_item(&self, _id: &str) -> Result<VaultItem, BackendError> {
            Err(BackendError::NotFound)
        }

        async fn get_secret(&self, id: &str) -> Result<SecretBytes, BackendError> {
            Ok(SecretBytes::new(format!("secret-{id}").into_bytes()))
        }

        async fn search(&self, _attrs: &Attributes) -> Result<Vec<VaultItemMeta>, BackendError> {
            Ok(Vec::new())
        }

        // Return NotSupported so the get_secret fallback path is exercised.
        async fn get_item_attributes(
            &self,
            _id: &str,
        ) -> Result<rosec_core::ItemAttributes, BackendError> {
            Err(BackendError::NotSupported)
        }
    }

    fn meta(locked: bool) -> VaultItemMeta {
        VaultItemMeta {
            id: "item-1".to_string(),
            backend_id: "mock".to_string(),
            label: "one".to_string(),
            attributes: Attributes::new(),
            created: None,
            modified: None,
            locked,
        }
    }

    #[tokio::test]
    async fn get_secret_requires_valid_session() {
        let sessions = Arc::new(SessionManager::new());
        let backend = Arc::new(MockBackend);
        let items_cache = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let state = ItemState {
            meta: meta(false),
            path: "/org/freedesktop/secrets/item/mock/one".to_string(),
            backend,
            sessions: sessions.clone(),
            return_attr_patterns: vec![],
            tokio_handle: tokio::runtime::Handle::current(),
            items_cache,
        };
        let item = SecretItem::new(state);

        let invalid = item
            .get_secret(ObjectPath::try_from("/invalid").unwrap())
            .await;
        assert!(invalid.is_err());

        let session = match sessions.open_session("plain", &zvariant::Value::from("")) {
            Ok((_, path)) => path,
            Err(err) => panic!("open_session failed: {err}"),
        };
        let valid = item
            .get_secret(ObjectPath::try_from(session.as_str()).unwrap())
            .await;
        assert!(valid.is_ok());
    }

    #[tokio::test]
    async fn get_secret_fails_when_locked() {
        let sessions = Arc::new(SessionManager::new());
        let backend = Arc::new(MockBackend);
        let items_cache = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let state = ItemState {
            meta: meta(true),
            path: "/org/freedesktop/secrets/item/mock/two".to_string(),
            backend,
            sessions: sessions.clone(),
            return_attr_patterns: vec![],
            tokio_handle: tokio::runtime::Handle::current(),
            items_cache,
        };
        let item = SecretItem::new(state);

        let session = match sessions.open_session("plain", &zvariant::Value::from("")) {
            Ok((_, path)) => path,
            Err(err) => panic!("open_session failed: {err}"),
        };
        let result = item
            .get_secret(ObjectPath::try_from(session.as_str()).unwrap())
            .await;
        assert!(result.is_err());
    }
}
