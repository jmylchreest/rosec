use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rosec_core::{NewItem, SecretBytes, VaultBackend, VaultItemMeta};
use tracing::info;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zvariant::OwnedObjectPath;

use crate::crypto::aes128_cbc_decrypt;
use crate::service::to_object_path;
use crate::session::SessionManager;
use crate::state::{ServiceState, map_backend_error};

#[derive(Clone)]
pub struct CollectionState {
    pub label: String,
    pub items: Arc<Mutex<HashMap<String, VaultItemMeta>>>,
    pub backends: Vec<Arc<dyn VaultBackend>>,
    pub service_state: Arc<ServiceState>,
    pub sessions: Arc<SessionManager>,
    pub tokio_handle: tokio::runtime::Handle,
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
    fn items(&self) -> Vec<OwnedObjectPath> {
        self.state
            .items
            .lock()
            .map(|items| items.keys().map(|s| to_object_path(s)).collect())
            .unwrap_or_default()
    }

    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>, FdoError> {
        let items = self
            .state
            .items
            .lock()
            .map_err(|_| FdoError::Failed("items lock poisoned".to_string()))?;

        let matched: Vec<OwnedObjectPath> = items
            .iter()
            .filter(|(_, item)| {
                attributes
                    .iter()
                    .all(|(k, v)| item.attributes.get(k) == Some(v))
            })
            .map(|(path, _)| to_object_path(path))
            .collect();

        Ok(matched)
    }

    async fn create_item(
        &self,
        properties: HashMap<String, zvariant::Value<'_>>,
        secret: zvariant::Value<'_>,
        replace: bool,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), FdoError> {
        let write_backend = self.state.service_state.write_backend().ok_or_else(|| {
            FdoError::NotSupported("no write-capable backend available".to_string())
        })?;

        let label = properties
            .get("org.freedesktop.Secret.Item.Label")
            .and_then(|v| v.downcast_ref::<String>().ok())
            .unwrap_or_else(|| "Untitled".to_string());

        let attributes = properties
            .get("org.freedesktop.Secret.Item.Attributes")
            .and_then(|v| extract_attributes_dict(v))
            .unwrap_or_default();

        let (session_path, parameters, secret_value, _content_type) = parse_secret_struct(&secret)?;

        let aes_key = self
            .state
            .sessions
            .get_session_key(&session_path)
            .map_err(map_backend_error)?;

        let plaintext: Vec<u8> = if let Some(key) = aes_key.as_deref() {
            aes128_cbc_decrypt(key, &parameters, &secret_value)
                .map_err(map_backend_error)?
                .to_vec()
        } else {
            secret_value
        };

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(plaintext));

        let item = NewItem {
            label,
            attributes,
            secrets,
        };

        let backend = Arc::clone(&write_backend);
        let backend_id = backend.id().to_string();
        let item_clone = item.clone();
        let id = self
            .state
            .tokio_handle
            .spawn(async move { backend.create_item(item_clone, replace).await })
            .await
            .map_err(|e| FdoError::Failed(format!("tokio task panicked: {e}")))?
            .map_err(map_backend_error)?;

        info!(item_id = %id, backend = %backend_id, "created item via D-Bus");

        let item_path = format!("/org/freedesktop/secrets/item/{}/{}", backend_id, id);

        let meta = rosec_core::VaultItemMeta {
            id: id.clone(),
            backend_id: backend_id.clone(),
            label: item.label.clone(),
            attributes: item.attributes.clone(),
            created: Some(std::time::SystemTime::now()),
            modified: Some(std::time::SystemTime::now()),
            locked: false,
        };

        if let Ok(mut items) = self.state.items.lock() {
            items.insert(item_path.clone(), meta);
        }

        Ok((to_object_path(&item_path), to_object_path("/")))
    }

    fn delete(&self) -> Result<(), FdoError> {
        Err(FdoError::NotSupported(
            "cannot delete default collection".to_string(),
        ))
    }

    #[zbus(property)]
    fn created(&self) -> u64 {
        0
    }

    #[zbus(property)]
    fn modified(&self) -> u64 {
        0
    }
}

fn extract_attributes_dict(value: &zvariant::Value<'_>) -> Option<HashMap<String, String>> {
    let dict = value.downcast_ref::<zvariant::Dict>().ok()?;
    let mut result = HashMap::new();
    for (k, v) in dict.iter() {
        if let (Some(ks), Some(vs)) = (
            k.downcast_ref::<String>().ok(),
            v.downcast_ref::<String>().ok(),
        ) {
            result.insert(ks.clone(), vs.clone());
        }
    }
    Some(result)
}

fn parse_secret_struct(
    secret: &zvariant::Value<'_>,
) -> Result<(String, Vec<u8>, Vec<u8>, String), FdoError> {
    let structure = secret
        .downcast_ref::<zvariant::Structure>()
        .map_err(|_| FdoError::Failed("secret is not a Structure".to_string()))?;

    let fields = structure.fields();
    if fields.len() != 4 {
        return Err(FdoError::Failed(format!(
            "secret struct has {} fields, expected 4",
            fields.len()
        )));
    }

    let session_path = fields[0]
        .downcast_ref::<zvariant::ObjectPath>()
        .map(|p| p.as_str().to_string())
        .or_else(|_| fields[0].downcast_ref::<String>())
        .map_err(|_| FdoError::Failed("session path is not an ObjectPath or String".to_string()))?;

    let parameters = fields[1]
        .downcast_ref::<zvariant::Array>()
        .and_then(|arr| {
            arr.iter()
                .map(|v| v.downcast_ref::<u8>())
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|_| FdoError::Failed("parameters is not a byte array".to_string()))?;

    let secret_value = fields[2]
        .downcast_ref::<zvariant::Array>()
        .and_then(|arr| {
            arr.iter()
                .map(|v| v.downcast_ref::<u8>())
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|_| FdoError::Failed("secret value is not a byte array".to_string()))?;

    let content_type = fields[3]
        .downcast_ref::<String>()
        .map_err(|_| FdoError::Failed("content_type is not a String".to_string()))?;

    Ok((session_path, parameters, secret_value, content_type))
}
