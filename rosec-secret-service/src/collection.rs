use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rosec_core::{VaultBackend, VaultItemMeta};
use zbus::fdo::Error as FdoError;
use zbus::interface;

#[derive(Clone)]
pub struct CollectionState {
    pub label: String,
    pub items: Arc<Mutex<HashMap<String, VaultItemMeta>>>,
    /// All backends backing this collection, in configured order.
    pub backends: Vec<Arc<dyn VaultBackend>>,
}

pub struct SecretCollection {
    state: CollectionState,
}

impl SecretCollection {
    pub fn new(state: CollectionState) -> Self {
        Self { state }
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl SecretCollection {
    #[zbus(property)]
    fn label(&self) -> String {
        self.state.label.clone()
    }

    /// The collection is considered unlocked if *any* backend is unlocked.
    #[zbus(property)]
    async fn locked(&self) -> bool {
        for backend in &self.state.backends {
            match backend.status().await {
                Ok(s) if !s.locked => return false,
                _ => {}
            }
        }
        true
    }

    #[zbus(property)]
    fn items(&self) -> Vec<String> {
        self.state
            .items
            .lock()
            .map(|items| items.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn search_items(&self, attributes: HashMap<String, String>) -> Result<Vec<String>, FdoError> {
        let items = self
            .state
            .items
            .lock()
            .map_err(|_| FdoError::Failed("items lock poisoned".to_string()))?;

        let matched: Vec<String> = items
            .iter()
            .filter(|(_, item)| {
                attributes
                    .iter()
                    .all(|(k, v)| item.attributes.get(k) == Some(v))
            })
            .map(|(path, _)| path.clone())
            .collect();

        Ok(matched)
    }

    fn create_item(
        &self,
        _properties: HashMap<String, zvariant::Value>,
        _secret: zvariant::Value,
        _replace: bool,
    ) -> Result<(String, String), FdoError> {
        Err(FdoError::NotSupported("read-only".to_string()))
    }

    fn delete(&self) -> Result<(), FdoError> {
        Err(FdoError::NotSupported("read-only".to_string()))
    }

    /// Unix timestamp when the collection was created.
    ///
    /// Returns 0 because this is a virtual collection backed by Bitwarden.
    #[zbus(property)]
    fn created(&self) -> u64 {
        0
    }

    /// Unix timestamp when the collection was last modified.
    ///
    /// Returns 0 because this is a virtual collection backed by Bitwarden.
    #[zbus(property)]
    fn modified(&self) -> u64 {
        0
    }
}
