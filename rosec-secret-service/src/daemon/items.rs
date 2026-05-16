use std::collections::HashMap;
use std::sync::Arc;

use rosec_core::{ItemMeta, ItemType, ItemUpdate, NewItem, Provider, SecretBytes};
use tracing::info;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::message::Header;

use super::log_dbus_caller;
use crate::state::{ServiceState, make_item_path, map_provider_error};

/// Tuple shape returned by `ReadItemsFromProvider`:
/// `(item_id, label, attributes, secret_bytes)`.  Extracted to satisfy
/// clippy::type_complexity while keeping the D-Bus signature unchanged.
type RawProviderItem = (String, String, HashMap<String, String>, Vec<u8>);

pub struct RosecItems {
    pub(super) state: Arc<ServiceState>,
}

impl RosecItems {
    pub fn new(state: Arc<ServiceState>) -> Self {
        Self { state }
    }

    /// Resolve `provider_id` to a Provider, falling back to the default
    /// write-capable provider when the id is empty.
    fn resolve_provider(&self, provider_id: &str) -> Result<Arc<dyn Provider>, FdoError> {
        if provider_id.is_empty() {
            self.state
                .write_provider()
                .ok_or_else(|| FdoError::Failed("no write-capable provider available".into()))
        } else {
            self.state
                .provider_by_id(provider_id)
                .ok_or_else(|| FdoError::Failed(format!("provider not found: {provider_id}")))
        }
    }
}

#[interface(name = "org.rosec.Items")]
impl RosecItems {
    /// Create an item with full control over type and multiple secrets.
    ///
    /// Unlike the standard `CreateItem` (which only supports a single `"secret"`
    /// key), this method accepts:
    ///
    /// - `label`: human-readable item name
    /// - `item_type`: canonical rosec type string (`"generic"`, `"login"`,
    ///   `"ssh-key"`, `"note"`, `"card"`, `"identity"`)
    /// - `attributes`: public attribute key-value pairs
    /// - `secrets`: map of secret attribute name to raw bytes (e.g.
    ///   `{"password": [...], "totp": [...]}`)
    /// - `replace`: if `true`, overwrite an existing item with matching attributes
    ///
    /// Returns the D-Bus object path of the created item.
    async fn create_item_extended(
        &self,
        label: &str,
        item_type: &str,
        attributes: HashMap<String, String>,
        secrets: HashMap<String, Vec<u8>>,
        replace: bool,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<String, FdoError> {
        log_dbus_caller("items-extension", "CreateItemExtended", &header);
        self.state.touch_activity();

        let parsed_type: ItemType = item_type
            .parse()
            .map_err(|e: String| FdoError::InvalidArgs(e))?;

        let secret_map: HashMap<String, SecretBytes> = secrets
            .into_iter()
            .map(|(k, v)| (k, SecretBytes::new(v)))
            .collect();

        let item = NewItem {
            label: label.to_string(),
            item_type: Some(parsed_type),
            attributes,
            secrets: secret_map,
        };

        // Route to the writable provider that already owns a matching item if
        // one exists; otherwise fall back to the configured / highest-priority
        // writable provider.  Read-only matches do not block the write — they
        // are shadowed by the new item, and the dedup layer presents the
        // priority winner to clients.
        let write_provider = match self
            .state
            .find_writable_match(&item.attributes)
            .map_err(|e| FdoError::Failed(format!("match lookup failed: {e}")))?
        {
            Some(provider) => provider,
            None => self.state.write_provider().ok_or_else(|| {
                FdoError::NotSupported("no write-capable provider available".into())
            })?,
        };

        let supported = write_provider.supported_item_types();
        if !supported.is_empty() && !supported.contains(&parsed_type) {
            return Err(FdoError::NotSupported(format!(
                "provider does not support item type '{item_type}'"
            )));
        }

        let provider_id = write_provider.id().to_string();
        let provider = Arc::clone(&write_provider);
        let item_for_create = item.clone();

        let id = self
            .state
            .run_on_tokio(async move { provider.create_item(item_for_create, replace).await })
            .await?
            .map_err(map_provider_error)?;

        info!(item_id = %id, provider = %provider_id, item_type = %item_type, "created item via D-Bus (extended)");

        let item_path = make_item_path(&provider_id, &id);
        let meta = ItemMeta::from_new_item(id, provider_id, &item);

        self.state
            .insert_created_item(&item_path, meta)
            .await
            .map_err(|e| FdoError::Failed(format!("cache update failed: {e}")))?;

        Ok(item_path)
    }

    /// Update an existing item's label, type, attributes, and/or secrets.
    ///
    /// All fields are optional — only provided fields are updated.
    ///
    /// - `item_path`: D-Bus object path of the item to update
    /// - `label`: new label (empty string = no change)
    /// - `item_type`: new type string (empty string = no change)
    /// - `attributes`: replacement attributes (empty map = no change)
    /// - `secrets`: replacement secrets (empty map = no change)
    async fn update_item(
        &self,
        item_path: &str,
        label: &str,
        item_type: &str,
        attributes: HashMap<String, String>,
        secrets: HashMap<String, Vec<u8>>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FdoError> {
        log_dbus_caller("items-extension", "UpdateItem", &header);
        self.state.touch_activity();

        let (provider, item_id) = self.state.writable_provider_for_path(item_path)?;

        let parsed_type = if item_type.is_empty() {
            None
        } else {
            Some(
                item_type
                    .parse::<ItemType>()
                    .map_err(|e: String| FdoError::InvalidArgs(e))?,
            )
        };

        let update_label = if label.is_empty() {
            None
        } else {
            Some(label.to_string())
        };

        let update_attrs = if attributes.is_empty() {
            None
        } else {
            Some(attributes)
        };

        // Capture values for cache patching before they are moved into
        // `ItemUpdate`.  `label` and `item_path` are borrowed `&str` so
        // they survive the move; `parsed_type` and `update_attrs` are owned
        // and must be cloned.
        let cache_type = parsed_type;
        let cache_attrs = update_attrs.clone();

        let update_secrets = if secrets.is_empty() {
            None
        } else {
            Some(
                secrets
                    .into_iter()
                    .map(|(k, v)| (k, SecretBytes::new(v)))
                    .collect(),
            )
        };

        let update = ItemUpdate {
            label: update_label,
            item_type: parsed_type,
            attributes: update_attrs,
            secrets: update_secrets,
        };

        let provider_id = provider.id().to_string();
        let item_id_for_log = item_id.clone();

        self.state
            .run_on_tokio(async move { provider.update_item(&item_id, update).await })
            .await?
            .map_err(map_provider_error)?;

        info!(item_id = %item_id_for_log, provider = %provider_id, "updated item via D-Bus");

        // Update the in-memory caches so searches reflect the change
        // immediately without waiting for a full cache rebuild.
        let cache_label = if label.is_empty() { None } else { Some(label) };
        self.state.patch_cached_item(
            item_path,
            cache_label,
            cache_type.as_ref(),
            cache_attrs.as_ref(),
        );

        Ok(())
    }

    async fn delete_item(
        &self,
        item_path: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FdoError> {
        log_dbus_caller("items-extension", "DeleteItem", &header);
        self.state.touch_activity();

        let (provider, item_id) = self.state.writable_provider_for_path(item_path)?;

        let provider_id = provider.id().to_string();
        let item_id_for_log = item_id.clone();
        let path_owned = item_path.to_string();

        self.state
            .run_on_tokio(async move { provider.delete_item(&item_id).await })
            .await?
            .map_err(map_provider_error)?;

        self.state.remove_deleted_item(&path_owned);

        info!(item_id = %item_id_for_log, provider = %provider_id, "deleted item via D-Bus");

        Ok(())
    }

    /// Return the capabilities of a provider.
    ///
    /// If `provider_id` is empty, returns capabilities of the default write provider.
    fn get_capabilities(
        &self,
        provider_id: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<String>, FdoError> {
        log_dbus_caller("items-extension", "GetCapabilities", &header);
        let provider = self.resolve_provider(provider_id)?;
        Ok(provider
            .capabilities()
            .iter()
            .map(|c| format!("{c:?}"))
            .collect())
    }

    /// Return the item types supported by a provider for creation.
    ///
    /// If `provider_id` is empty, returns types for the default write provider.
    fn get_supported_item_types(
        &self,
        provider_id: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<String>, FdoError> {
        log_dbus_caller("items-extension", "GetSupportedItemTypes", &header);
        let provider = self.resolve_provider(provider_id)?;
        Ok(provider
            .supported_item_types()
            .iter()
            .map(|t| t.to_string())
            .collect())
    }

    /// Read items from a specific provider, bypassing the deduplication layer.
    ///
    /// `SearchItems` (and the rosec extensions that read from the cache)
    /// surface only the dedup winner per (label, client-attrs) group, so an
    /// item that another writable provider also holds is invisible to
    /// clients.  This method calls `Provider::search` directly on the named
    /// provider and returns every match, paired with its primary secret
    /// bytes, so callers can recover values that the cache hides.
    ///
    /// Each returned tuple is `(item_id, label, attributes, secret_bytes)`.
    /// The secret is read from the first matching `secret_names` entry the
    /// provider exposes (`"secret"` or `"password"` for most provider
    /// kinds).  Items with no readable secret are returned with an empty
    /// byte vector rather than failing the whole call.
    ///
    /// Intended for diagnostic/migration tooling (`rosec search --no-dedup`,
    /// cross-provider copy).  Returns raw bytes — callers must zeroise
    /// whatever they copy.
    async fn read_items_from_provider(
        &self,
        provider_id: &str,
        attributes: HashMap<String, String>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<RawProviderItem>, FdoError> {
        log_dbus_caller("items-extension", "ReadItemsFromProvider", &header);
        self.state.touch_activity();

        let provider = self
            .state
            .provider_by_id(provider_id)
            .ok_or_else(|| FdoError::Failed(format!("provider not found: {provider_id}")))?;

        let metas = self
            .state
            .run_on_tokio({
                let provider = Arc::clone(&provider);
                let attrs = attributes.clone();
                async move { provider.search(&attrs).await }
            })
            .await?
            .map_err(map_provider_error)?;

        let mut out: Vec<RawProviderItem> = Vec::with_capacity(metas.len());

        for meta in metas {
            let item_id = meta.id.clone();
            let label = meta.label.clone();
            let attrs = meta.attributes.clone();
            let provider_for_read = Arc::clone(&provider);
            let id_for_read = item_id.clone();

            let secret_bytes = self
                .state
                .run_on_tokio(async move {
                    let ia = match provider_for_read.get_item_attributes(&id_for_read).await {
                        Ok(ia) => ia,
                        Err(_) => return Vec::new(),
                    };
                    for name in &ia.secret_names {
                        if let Ok(s) = provider_for_read.get_secret_attr(&id_for_read, name).await {
                            return s.as_slice().to_vec();
                        }
                    }
                    Vec::new()
                })
                .await?;

            out.push((item_id, label, attrs, secret_bytes));
        }

        Ok(out)
    }
}
