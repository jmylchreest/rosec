use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rosec_core::{ItemMeta, NewItem, Provider, SecretBytes};
use tracing::{debug, info};
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zvariant::OwnedObjectPath;

use crate::crypto::aes128_cbc_decrypt;
use crate::error::SecretServiceError;
use crate::prompt::{PendingOperation, SecretPrompt};
use crate::service::to_object_path;
use crate::session::SessionManager;
use crate::state::{
    ServiceState, make_item_path, map_provider_error, map_provider_error_ss, map_zbus_error,
};

#[derive(Clone)]
pub struct CollectionState {
    pub label: String,
    pub items: Arc<Mutex<HashMap<String, ItemMeta>>>,
    pub providers: Vec<Arc<dyn Provider>>,
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
        for provider in &self.state.providers {
            match provider.status().await {
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
        secret: (OwnedObjectPath, Vec<u8>, Vec<u8>, String),
        replace: bool,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretServiceError> {
        debug!("CreateItem called (replace={replace})");
        let write_provider = self.state.service_state.write_provider().ok_or_else(|| {
            SecretServiceError::NotSupported("no write-capable provider available".to_string())
        })?;

        let label = properties
            .get("org.freedesktop.Secret.Item.Label")
            .and_then(|v| v.downcast_ref::<String>().ok())
            .unwrap_or_else(|| "Untitled".to_string());

        let attributes = properties
            .get("org.freedesktop.Secret.Item.Attributes")
            .and_then(|v| extract_attributes_dict(v))
            .unwrap_or_default();

        let (session_path, parameters, secret_value, _content_type) = secret;
        let session_path = session_path.as_str().to_string();

        let aes_key = self
            .state
            .sessions
            .get_session_key(&session_path)
            .map_err(map_provider_error)?;

        // Hold plaintext only in zeroizing buffers — no intermediate plain Vec.
        let secret = if let Some(key) = aes_key.as_deref() {
            let plaintext =
                aes128_cbc_decrypt(key, &parameters, &secret_value).map_err(map_provider_error)?;
            SecretBytes::from_zeroizing(plaintext)
        } else {
            SecretBytes::new(secret_value)
        };

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), secret);

        let item = NewItem {
            label,
            item_type: None,
            attributes,
            secrets,
        };

        // Check if the write provider is locked — if so, defer the operation
        // behind a prompt so the client can unlock first.
        let provider_id = write_provider.id().to_string();
        let is_locked = {
            let p = Arc::clone(&write_provider);
            self.state
                .tokio_handle
                .spawn(async move { p.status().await })
                .await
                .map_err(|e| SecretServiceError::Failed(format!("tokio task panicked: {e}")))?
                .map_err(map_provider_error)?
                .locked
        };

        if is_locked {
            debug!(provider = %provider_id, "write provider is locked, deferring CreateItem behind prompt");
            let op = PendingOperation::CreateItem {
                provider_id: provider_id.clone(),
                item,
                replace,
            };
            let prompt_path = self
                .state
                .service_state
                .allocate_prompt_with_operation(&provider_id, op);
            let prompt_obj = SecretPrompt::new(
                prompt_path.clone(),
                provider_id,
                Arc::clone(&self.state.service_state),
            );
            let conn = self.state.service_state.conn();
            conn.object_server()
                .at(prompt_path.clone(), prompt_obj)
                .await
                .map_err(map_zbus_error)?;
            // Return "/" for item path and the prompt path — client must
            // complete the prompt before the item is created.
            return Ok((to_object_path("/"), to_object_path(&prompt_path)));
        }

        let provider = Arc::clone(&write_provider);
        let item_clone = item.clone();
        let id = self
            .state
            .tokio_handle
            .spawn(async move { provider.create_item(item_clone, replace).await })
            .await
            .map_err(|e| SecretServiceError::Failed(format!("tokio task panicked: {e}")))?
            .map_err(map_provider_error_ss)?;

        info!(item_id = %id, provider = %provider_id, "created item via D-Bus");

        let item_path = make_item_path(&provider_id, &id);

        let meta = ItemMeta::from_new_item(id.clone(), provider_id.clone(), &item);

        self.state
            .service_state
            .insert_created_item(&item_path, meta)
            .await
            .map_err(|e| SecretServiceError::Failed(format!("cache update failed: {e}")))?;

        Ok((to_object_path(&item_path), to_object_path("/")))
    }

    fn delete(&self) -> Result<OwnedObjectPath, FdoError> {
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
