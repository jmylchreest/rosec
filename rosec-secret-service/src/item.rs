use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use rosec_core::{VaultBackend, VaultItemMeta};
use zbus::fdo::Error as FdoError;
use zbus::interface;

use crate::service::{build_secret_value, map_backend_error};
use crate::session::SessionManager;

#[derive(Clone)]
pub struct ItemState {
    pub meta: VaultItemMeta,
    pub path: String,
    pub backend: Arc<dyn VaultBackend>,
    pub sessions: Arc<SessionManager>,
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

    async fn get_secret(&self, session: &str) -> Result<zvariant::Value<'_>, FdoError> {
        ensure_session(&self.state.sessions, session)?;
        if self.state.meta.locked {
            return Err(FdoError::Failed("locked".to_string()));
        }
        let secret = self
            .state
            .backend
            .get_secret(&self.state.meta.id)
            .await
            .map_err(map_backend_error)?;
        build_secret_value(session, &secret)
    }

    fn set_secret(&self, _secret: zvariant::Value) -> Result<(), FdoError> {
        Err(FdoError::NotSupported("read-only".to_string()))
    }

    fn delete(&self) -> Result<(), FdoError> {
        Err(FdoError::NotSupported("read-only".to_string()))
    }
}

fn ensure_session(sessions: &SessionManager, session: &str) -> Result<(), FdoError> {
    sessions.validate(session).map_err(map_backend_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rosec_core::{Attributes, BackendError, BackendStatus, RecoveryOutcome, SecretBytes, UnlockInput, VaultItem};

    #[derive(Debug)]
    struct MockBackend;

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
        let state = ItemState {
            meta: meta(false),
            path: "/org/freedesktop/secrets/item/mock/one".to_string(),
            backend,
            sessions: sessions.clone(),
        };
        let item = SecretItem::new(state);

        let invalid = item.get_secret("invalid").await;
        assert!(invalid.is_err());

        let session = match sessions.open_session("plain") {
            Ok((_, path)) => path,
            Err(err) => panic!("open_session failed: {err}"),
        };
        let valid = item.get_secret(&session).await;
        assert!(valid.is_ok());
    }

    #[tokio::test]
    async fn get_secret_fails_when_locked() {
        let sessions = Arc::new(SessionManager::new());
        let backend = Arc::new(MockBackend);
        let state = ItemState {
            meta: meta(true),
            path: "/org/freedesktop/secrets/item/mock/two".to_string(),
            backend,
            sessions: sessions.clone(),
        };
        let item = SecretItem::new(state);

        let session = match sessions.open_session("plain") {
            Ok((_, path)) => path,
            Err(err) => panic!("open_session failed: {err}"),
        };
        let result = item.get_secret(&session).await;
        assert!(result.is_err());
    }
}
