use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use rosec_core::{Capability, ItemMeta, Provider, ProviderError};
use tracing::info;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zvariant::{ObjectPath, OwnedObjectPath};

use crate::error::SecretServiceError;
use crate::service::{SecretStruct, build_secret_value, to_object_path};
use crate::session::SessionManager;
use crate::state::{map_provider_error, map_provider_error_ss};

#[derive(Clone)]
pub struct ItemState {
    pub meta: ItemMeta,
    pub path: String,
    pub provider: Arc<dyn Provider>,
    pub sessions: Arc<SessionManager>,
    /// Ordered glob patterns for selecting which sensitive attribute to return
    /// from `GetSecret`.  Derived from the provider's `return_attr` config.
    pub return_attr_patterns: Vec<String>,
    /// Tokio runtime handle — required to bridge zbus's async-io executor with
    /// provider futures that depend on the Tokio reactor (e.g. reqwest).
    pub tokio_handle: tokio::runtime::Handle,
    /// Reference to service state for cache updates and prompt allocation.
    pub items_cache: Arc<std::sync::Mutex<HashMap<String, ItemMeta>>>,
    pub service_state: Arc<crate::state::ServiceState>,
}

pub struct SecretItem {
    state: ItemState,
}

impl SecretItem {
    pub fn new(state: ItemState) -> Self {
        Self { state }
    }

    /// Live lock state for this item.
    ///
    /// Reads from the shared `items_cache` which is kept up-to-date by
    /// `rebuild_cache_inner()`.  Falls back to the registration-time
    /// snapshot if the item has been evicted from the cache (shouldn't
    /// happen in practice).
    fn is_locked(&self) -> bool {
        self.state
            .items_cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&self.state.path).map(|m| m.locked))
            .unwrap_or(self.state.meta.locked)
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
        if self.is_locked()
            && self
                .state
                .provider
                .capabilities()
                .contains(&Capability::MetadataCache)
        {
            return self
                .state
                .meta
                .attributes
                .keys()
                .map(|k| (k.clone(), String::new()))
                .collect();
        }
        self.state.meta.attributes.clone()
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        self.is_locked()
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
    ) -> Result<(SecretStruct,), SecretServiceError> {
        use wildmatch::WildMatch;

        let session = session.as_str();
        ensure_session(&self.state.sessions, session)?;
        if self.is_locked() {
            return Err(SecretServiceError::IsLocked("item is locked".to_string()));
        }
        let aes_key = self
            .state
            .sessions
            .get_session_key(session)
            .map_err(map_provider_error)?;

        let provider = Arc::clone(&self.state.provider);
        let item_id = self.state.meta.id.clone();
        let patterns = self.state.return_attr_patterns.clone();

        let secret = self
            .state
            .tokio_handle
            .spawn(async move {
                match provider.get_item_attributes(&item_id).await {
                    Ok(ia) => {
                        for pattern in &patterns {
                            let wm = WildMatch::new(pattern);
                            if let Some(matched) = ia.secret_names.iter().find(|n| wm.matches(n)) {
                                match provider.get_secret_attr(&item_id, matched).await {
                                    Ok(s) => return Ok(s),
                                    Err(ProviderError::NotFound) => continue,
                                    Err(e) => return Err(e),
                                }
                            }
                        }
                        // No pattern matched — fall back to primary_secret.
                        rosec_core::primary_secret(&*provider, &item_id).await
                    }
                    Err(e) => Err(e),
                }
            })
            .await
            .map_err(|e| FdoError::Failed(format!("tokio task panicked: {e}")))?
            .map_err(map_provider_error_ss)?;

        Ok((build_secret_value(session, &secret, aes_key.as_deref())?,))
    }

    fn set_secret(&self, _secret: SecretStruct) -> Result<(), SecretServiceError> {
        if self.is_locked() {
            return Err(SecretServiceError::IsLocked("item is locked".to_string()));
        }
        Err(SecretServiceError::NotSupported(
            "use CreateItem with replace=true".to_string(),
        ))
    }

    async fn delete(&self) -> Result<OwnedObjectPath, SecretServiceError> {
        if !self
            .state
            .provider
            .capabilities()
            .contains(&Capability::Write)
        {
            return Err(SecretServiceError::NotSupported(
                "provider does not support write operations".to_string(),
            ));
        }

        // Check if the provider is locked — if so, return a prompt path so the
        // client can trigger unlock before retrying.
        if self.is_locked() {
            let provider_id = self.state.provider.id().to_string();
            let item_id = self.state.meta.id.clone();
            let item_path = self.state.path.clone();

            let prompt_path = self.state.service_state.allocate_prompt_with_operation(
                &provider_id,
                crate::prompt::PendingOperation::DeleteItem {
                    provider_id: provider_id.clone(),
                    item_id,
                    item_path,
                },
            );
            let prompt_obj = crate::prompt::SecretPrompt::new(
                prompt_path.clone(),
                provider_id,
                Arc::clone(&self.state.service_state),
            );
            let conn = self.state.service_state.conn();
            let _: bool = conn
                .object_server()
                .at(prompt_path.clone(), prompt_obj)
                .await
                .map_err(crate::state::map_zbus_error)?;
            return Ok(to_object_path(&prompt_path));
        }

        let item_id = self.state.meta.id.clone();
        let item_path = self.state.path.clone();
        let provider = Arc::clone(&self.state.provider);
        let provider_id = provider.id().to_string();
        let item_id_for_log = item_id.clone();

        self.state
            .tokio_handle
            .spawn(async move { provider.delete_item(&item_id).await })
            .await
            .map_err(|e| SecretServiceError::Failed(format!("tokio task panicked: {e}")))?
            .map_err(map_provider_error_ss)?;

        info!(item_id = %item_id_for_log, provider = %provider_id, "deleted item via D-Bus");

        self.state.service_state.remove_deleted_item(&item_path);

        // No prompt needed — return "/" per the spec.
        Ok(to_object_path("/"))
    }
}

fn ensure_session(sessions: &SessionManager, session: &str) -> Result<(), FdoError> {
    sessions.validate(session).map_err(map_provider_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rosec_core::{
        Attributes, ItemMeta, Provider, ProviderError, ProviderStatus, SecretBytes, UnlockInput,
    };

    #[derive(Debug)]
    struct MockProvider;

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
            Ok(Vec::new())
        }

        async fn search(&self, _attrs: &Attributes) -> Result<Vec<ItemMeta>, ProviderError> {
            Ok(Vec::new())
        }

        async fn get_item_attributes(
            &self,
            _id: &str,
        ) -> Result<rosec_core::ItemAttributes, ProviderError> {
            // Return a "secret" attr so primary_secret fallback works
            Ok(rosec_core::ItemAttributes {
                public: Attributes::new(),
                secret_names: vec!["secret".to_string()],
            })
        }

        async fn get_secret_attr(
            &self,
            id: &str,
            attr: &str,
        ) -> Result<SecretBytes, ProviderError> {
            if attr == "secret" {
                Ok(SecretBytes::new(format!("secret-{id}").into_bytes()))
            } else {
                Err(ProviderError::NotFound)
            }
        }
    }

    fn meta(locked: bool) -> ItemMeta {
        ItemMeta {
            id: "item-1".to_string(),
            provider_id: "mock".to_string(),
            label: "one".to_string(),
            attributes: Attributes::new(),
            created: None,
            modified: None,
            locked,
        }
    }

    async fn test_service_state(provider: Arc<dyn Provider>) -> Arc<crate::state::ServiceState> {
        let router = Arc::new(rosec_core::router::Router::new(
            rosec_core::router::RouterConfig {
                dedup_strategy: rosec_core::DedupStrategy::Newest,
                dedup_time_fallback: rosec_core::DedupTimeFallback::Created,
            },
        ));
        let sessions = Arc::new(SessionManager::new());
        let conn = zbus::Connection::session()
            .await
            .expect("test requires session bus");
        Arc::new(crate::state::ServiceState::new(
            vec![provider],
            router,
            sessions,
            conn,
            tokio::runtime::Handle::current(),
        ))
    }

    #[tokio::test]
    async fn get_secret_requires_valid_session() {
        let sessions = Arc::new(SessionManager::new());
        let provider: Arc<dyn Provider> = Arc::new(MockProvider);
        let items_cache = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let service_state = test_service_state(Arc::clone(&provider)).await;
        let state = ItemState {
            meta: meta(false),
            path: "/org/freedesktop/secrets/item/mock/one".to_string(),
            provider,
            sessions: sessions.clone(),
            return_attr_patterns: vec![],
            tokio_handle: tokio::runtime::Handle::current(),
            items_cache,
            service_state,
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
        let provider: Arc<dyn Provider> = Arc::new(MockProvider);
        let items_cache = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let service_state = test_service_state(Arc::clone(&provider)).await;
        let state = ItemState {
            meta: meta(true),
            path: "/org/freedesktop/secrets/item/mock/two".to_string(),
            provider,
            sessions: sessions.clone(),
            return_attr_patterns: vec![],
            tokio_handle: tokio::runtime::Handle::current(),
            items_cache,
            service_state,
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

    #[derive(Debug)]
    struct MetaCacheProvider;

    #[async_trait::async_trait]
    impl Provider for MetaCacheProvider {
        fn id(&self) -> &str {
            "meta-mock"
        }
        fn name(&self) -> &str {
            "MetaMock"
        }
        fn kind(&self) -> &str {
            "mock"
        }
        fn capabilities(&self) -> &'static [Capability] {
            &[Capability::MetadataCache]
        }
        async fn status(&self) -> Result<ProviderStatus, ProviderError> {
            Ok(ProviderStatus {
                locked: true,
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
            Ok(Vec::new())
        }
        async fn search(&self, _attrs: &Attributes) -> Result<Vec<ItemMeta>, ProviderError> {
            Ok(Vec::new())
        }
        async fn get_item_attributes(
            &self,
            _id: &str,
        ) -> Result<rosec_core::ItemAttributes, ProviderError> {
            Ok(rosec_core::ItemAttributes {
                public: Attributes::new(),
                secret_names: vec![],
            })
        }
        async fn get_secret_attr(
            &self,
            _id: &str,
            _attr: &str,
        ) -> Result<SecretBytes, ProviderError> {
            Err(ProviderError::Locked)
        }
    }

    fn meta_with_attrs(locked: bool, attrs: &[(&str, &str)]) -> ItemMeta {
        let mut attributes = Attributes::new();
        for (k, v) in attrs {
            attributes.insert((*k).to_string(), (*v).to_string());
        }
        ItemMeta {
            id: "item-1".to_string(),
            provider_id: "meta-mock".to_string(),
            label: "one".to_string(),
            attributes,
            created: None,
            modified: None,
            locked,
        }
    }

    #[tokio::test]
    async fn locked_item_attributes_obfuscated_when_provider_has_metadata_cache() {
        let sessions = Arc::new(SessionManager::new());
        let provider: Arc<dyn Provider> = Arc::new(MetaCacheProvider);
        let items_cache = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let service_state = test_service_state(Arc::clone(&provider)).await;
        let state = ItemState {
            meta: meta_with_attrs(
                true,
                &[
                    ("application", "Signal"),
                    ("xdg:schema", "chrome_libsecret_os_crypt_password_v2"),
                ],
            ),
            path: "/org/freedesktop/secrets/item/meta-mock/locked".to_string(),
            provider,
            sessions,
            return_attr_patterns: vec![],
            tokio_handle: tokio::runtime::Handle::current(),
            items_cache,
            service_state,
        };
        let item = SecretItem::new(state);

        let attrs = item.attributes();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs.get("application"), Some(&String::new()));
        assert_eq!(attrs.get("xdg:schema"), Some(&String::new()));
    }

    #[tokio::test]
    async fn unlocked_item_attributes_intact_with_metadata_cache_provider() {
        let sessions = Arc::new(SessionManager::new());
        let provider: Arc<dyn Provider> = Arc::new(MetaCacheProvider);
        let items_cache = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let service_state = test_service_state(Arc::clone(&provider)).await;
        let state = ItemState {
            meta: meta_with_attrs(false, &[("application", "Signal")]),
            path: "/org/freedesktop/secrets/item/meta-mock/unlocked".to_string(),
            provider,
            sessions,
            return_attr_patterns: vec![],
            tokio_handle: tokio::runtime::Handle::current(),
            items_cache,
            service_state,
        };
        let item = SecretItem::new(state);

        let attrs = item.attributes();
        assert_eq!(attrs.get("application"), Some(&"Signal".to_string()));
    }

    #[tokio::test]
    async fn locked_item_attributes_intact_when_provider_lacks_metadata_cache() {
        let sessions = Arc::new(SessionManager::new());
        let provider: Arc<dyn Provider> = Arc::new(MockProvider);
        let items_cache = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let service_state = test_service_state(Arc::clone(&provider)).await;
        let state = ItemState {
            meta: meta_with_attrs(true, &[("application", "Signal")]),
            path: "/org/freedesktop/secrets/item/mock/locked".to_string(),
            provider,
            sessions,
            return_attr_patterns: vec![],
            tokio_handle: tokio::runtime::Handle::current(),
            items_cache,
            service_state,
        };
        let item = SecretItem::new(state);

        let attrs = item.attributes();
        assert_eq!(attrs.get("application"), Some(&"Signal".to_string()));
    }

    /// An item registered while locked should become accessible after the
    /// cache is updated to reflect the provider being unlocked.
    #[tokio::test]
    async fn get_secret_succeeds_after_cache_unlocks_item() {
        let sessions = Arc::new(SessionManager::new());
        let provider: Arc<dyn Provider> = Arc::new(MockProvider);
        let items_cache = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let service_state = test_service_state(Arc::clone(&provider)).await;
        let path = "/org/freedesktop/secrets/item/mock/three".to_string();
        let state = ItemState {
            meta: meta(true), // registered as locked
            path: path.clone(),
            provider,
            sessions: sessions.clone(),
            return_attr_patterns: vec!["secret".to_string()],
            tokio_handle: tokio::runtime::Handle::current(),
            items_cache: Arc::clone(&items_cache),
            service_state,
        };
        let item = SecretItem::new(state);

        assert!(item.locked());

        // Simulate cache rebuild after provider unlocks.
        {
            let mut cache = items_cache.lock().expect("test lock");
            cache.insert(path, meta(false));
        }

        assert!(!item.locked());

        let session = match sessions.open_session("plain", &zvariant::Value::from("")) {
            Ok((_, path)) => path,
            Err(err) => panic!("open_session failed: {err}"),
        };
        let result = item
            .get_secret(ObjectPath::try_from(session.as_str()).unwrap())
            .await;
        assert!(result.is_ok());
    }
}
