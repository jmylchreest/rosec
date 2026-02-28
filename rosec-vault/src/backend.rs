use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use async_trait::async_trait;
use base64::prelude::{BASE64_STANDARD, Engine};
use rosec_core::{
    Attributes, BackendCallbacks, BackendError, BackendStatus, ItemAttributes, ItemUpdate, NewItem,
    SecretBytes, SshKeyMeta, UnlockInput, VaultBackend, VaultItem, VaultItemMeta,
};
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{debug, info};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto;
use crate::types::{VaultData, VaultFile, VaultItemData, WrappingEntry};

struct UnlockedState {
    /// The random vault key used to encrypt/decrypt vault data.
    vault_key: Zeroizing<[u8; 32]>,
    /// MAC key derived from the vault key (for HMAC over encrypted data).
    mac_key: Zeroizing<[u8; 32]>,
    /// The current wrapping entries (preserved for re-saving).
    wrapping_entries: Vec<WrappingEntry>,
    /// Decrypted vault data.
    data: VaultData,
    /// Whether in-memory data has been modified since last save.
    dirty: bool,
}

pub struct LocalVault {
    id: String,
    path: PathBuf,
    state: RwLock<Option<UnlockedState>>,
    callbacks: std::sync::RwLock<BackendCallbacks>,
}

impl LocalVault {
    pub fn new(id: impl Into<String>, path: impl AsRef<Path>) -> Self {
        Self {
            id: id.into(),
            path: path.as_ref().to_path_buf(),
            state: RwLock::new(None),
            callbacks: std::sync::RwLock::new(BackendCallbacks::default()),
        }
    }

    /// Load and decrypt a vault file using the given password.
    ///
    /// Tries each wrapping entry to unwrap the vault key. The first entry whose
    /// HMAC verifies is used to recover the vault key, which then decrypts the
    /// vault data.
    async fn load_vault(
        &self,
        password: &[u8],
    ) -> Result<(VaultData, Zeroizing<[u8; 32]>, Vec<WrappingEntry>), BackendError> {
        let content = fs::read(&self.path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BackendError::Unavailable("vault file not found".into())
            } else {
                BackendError::Other(e.into())
            }
        })?;

        let vault_file: VaultFile =
            serde_json::from_slice(&content).map_err(|e| BackendError::Other(e.into()))?;

        if vault_file.version != crate::types::VAULT_FORMAT_VERSION {
            return Err(BackendError::Other(anyhow::anyhow!(
                "unsupported vault version: {}",
                vault_file.version
            )));
        }

        if vault_file.wrapping_entries.is_empty() {
            return Err(BackendError::Other(anyhow::anyhow!(
                "vault has no wrapping entries"
            )));
        }

        // Try each wrapping entry until one succeeds.
        let vault_key = vault_file
            .wrapping_entries
            .iter()
            .find_map(|entry| crypto::unwrap_vault_key(entry, password))
            .ok_or_else(|| BackendError::Other(anyhow::anyhow!("HMAC verification failed")))?;

        let mac_key = crypto::derive_mac_key(&*vault_key);

        let encrypted_data = vault_file.encrypted_data_bytes();
        if !crypto::verify_hmac(&*mac_key, &encrypted_data, &vault_file.hmac_bytes()) {
            return Err(BackendError::Other(anyhow::anyhow!(
                "vault data HMAC verification failed"
            )));
        }

        let decrypted = crypto::decrypt(&encrypted_data, &*vault_key)
            .map_err(|e| BackendError::Other(anyhow::anyhow!("decryption failed: {}", e)))?;

        let data: VaultData =
            serde_json::from_slice(&decrypted).map_err(|e| BackendError::Other(e.into()))?;

        Ok((data, vault_key, vault_file.wrapping_entries))
    }

    /// Create a new vault file with a random vault key wrapped by the password.
    async fn create_vault(
        &self,
        password: &[u8],
    ) -> Result<(VaultData, Zeroizing<[u8; 32]>, Vec<WrappingEntry>), BackendError> {
        let vault_key = crypto::generate_vault_key();
        let mac_key = crypto::derive_mac_key(&*vault_key);
        let data = VaultData::default();

        let entry = crypto::wrap_vault_key(&vault_key, password, Some("master".to_string()));
        let wrapping_entries = vec![entry];

        let plaintext = serde_json::to_vec(&data).map_err(|e| BackendError::Other(e.into()))?;
        let encrypted = crypto::encrypt(&plaintext, &*vault_key);
        let hmac = crypto::compute_hmac(&*mac_key, &encrypted);

        let vault_file = VaultFile::new(wrapping_entries.clone(), &encrypted, &hmac);
        let content =
            serde_json::to_string_pretty(&vault_file).map_err(|e| BackendError::Other(e.into()))?;

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| BackendError::Other(e.into()))?;
        }

        fs::write(&self.path, content)
            .await
            .map_err(|e| BackendError::Other(e.into()))?;

        info!(path = %self.path.display(), "created new vault");

        Ok((data, vault_key, wrapping_entries))
    }

    async fn save(&self) -> Result<(), BackendError> {
        let mut guard = self.state.write().await;

        let state = guard.as_mut().ok_or(BackendError::Locked)?;

        if !state.dirty {
            return Ok(());
        }

        let plaintext =
            serde_json::to_vec(&state.data).map_err(|e| BackendError::Other(e.into()))?;
        let encrypted = crypto::encrypt(&plaintext, &*state.vault_key);
        let hmac = crypto::compute_hmac(&*state.mac_key, &encrypted);

        let vault_file = VaultFile::new(state.wrapping_entries.clone(), &encrypted, &hmac);
        let content =
            serde_json::to_string_pretty(&vault_file).map_err(|e| BackendError::Other(e.into()))?;

        fs::write(&self.path, content)
            .await
            .map_err(|e| BackendError::Other(e.into()))?;

        state.dirty = false;
        debug!(path = %self.path.display(), "saved vault");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Key wrapping management (public API for CLI)
    // -----------------------------------------------------------------------

    /// Add a new password as a wrapping entry for this vault.
    ///
    /// The vault must be unlocked. The new password wraps the same vault key
    /// that the existing entries protect. Labels must be non-empty and unique
    /// within the vault.
    pub async fn add_password(
        &self,
        password: &[u8],
        label: String,
    ) -> Result<String, BackendError> {
        if label.is_empty() {
            return Err(BackendError::InvalidInput(
                "password label cannot be empty".into(),
            ));
        }

        let mut guard = self.state.write().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;

        if state
            .wrapping_entries
            .iter()
            .any(|e| e.label.as_deref() == Some(label.as_str()))
        {
            return Err(BackendError::InvalidInput(
                format!("a password with label '{label}' already exists").into(),
            ));
        }

        let entry = crypto::wrap_vault_key(&state.vault_key, password, Some(label));
        let id = entry.id.clone();
        state.wrapping_entries.push(entry);
        state.dirty = true;

        drop(guard);
        self.save().await?;

        info!(entry_id = %id, "added wrapping entry");
        Ok(id)
    }

    /// Remove a wrapping entry by ID.
    ///
    /// The vault must be unlocked and must have at least 2 wrapping entries
    /// (cannot remove the last one).
    pub async fn remove_password(&self, entry_id: &str) -> Result<(), BackendError> {
        let mut guard = self.state.write().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;

        if state.wrapping_entries.len() <= 1 {
            return Err(BackendError::InvalidInput(
                "cannot remove the last wrapping entry".into(),
            ));
        }

        let initial_len = state.wrapping_entries.len();
        state.wrapping_entries.retain(|e| e.id != entry_id);

        if state.wrapping_entries.len() == initial_len {
            return Err(BackendError::NotFound);
        }

        state.dirty = true;

        drop(guard);
        self.save().await?;

        info!(entry_id = %entry_id, "removed wrapping entry");
        Ok(())
    }

    /// List all wrapping entries (id + label only, no key material).
    pub async fn list_passwords(&self) -> Result<Vec<(String, Option<String>)>, BackendError> {
        let guard = self.state.read().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        Ok(state
            .wrapping_entries
            .iter()
            .map(|e| (e.id.clone(), e.label.clone()))
            .collect())
    }

    /// Return the on-disk path of this vault file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn item_to_meta(&self, item: &VaultItemData, backend_id: &str) -> VaultItemMeta {
        VaultItemMeta {
            id: item.id.clone(),
            backend_id: backend_id.to_string(),
            label: item.label.clone(),
            attributes: item.attributes.clone(),
            created: Some(
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(item.created as u64),
            ),
            modified: Some(
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(item.modified as u64),
            ),
            locked: false,
        }
    }

    fn item_to_vault_item(&self, item: &VaultItemData, backend_id: &str) -> VaultItem {
        let primary_secret = item
            .secrets
            .get("secret")
            .or_else(|| item.secrets.get("password"))
            .and_then(|s| BASE64_STANDARD.decode(s).ok())
            .map(SecretBytes::new);

        VaultItem {
            meta: self.item_to_meta(item, backend_id),
            secret: primary_secret,
        }
    }

    fn matches_attributes(&self, item: &VaultItemData, attrs: &Attributes) -> bool {
        attrs
            .iter()
            .all(|(k, v)| item.attributes.get(k).map(|s| s.as_str()) == Some(v.as_str()))
    }
}

impl std::fmt::Debug for LocalVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalVault")
            .field("id", &self.id)
            .field("path", &self.path)
            .field("unlocked", &self.state.try_read().map(|g| g.is_some()))
            .finish()
    }
}

#[async_trait]
impl VaultBackend for LocalVault {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        "Local Vault"
    }

    fn kind(&self) -> &str {
        "vault"
    }

    fn backend_class(&self) -> rosec_core::BackendClass {
        rosec_core::BackendClass::Vault
    }

    fn supports_writes(&self) -> bool {
        true
    }

    async fn status(&self) -> Result<BackendStatus, BackendError> {
        let guard = self.state.read().await;
        let locked = guard.is_none();

        Ok(BackendStatus {
            locked,
            last_sync: None,
        })
    }

    async fn unlock(&self, input: UnlockInput) -> Result<(), BackendError> {
        let password = match input {
            UnlockInput::Password(pw) => pw,
            _ => return Err(BackendError::NotSupported),
        };

        if password.is_empty() {
            return Err(BackendError::InvalidInput(
                "password cannot be empty".into(),
            ));
        }

        let mut guard = self.state.write().await;

        if guard.is_some() {
            debug!("backend already unlocked");
            return Ok(());
        }

        let password_bytes = password.as_bytes();
        let (data, vault_key, wrapping_entries) = match self.load_vault(password_bytes).await {
            Ok(result) => result,
            Err(BackendError::Unavailable(_)) => {
                info!("vault not found, creating new vault");
                self.create_vault(password_bytes).await?
            }
            Err(e) => return Err(e),
        };

        let mac_key = crypto::derive_mac_key(&*vault_key);

        *guard = Some(UnlockedState {
            vault_key,
            mac_key,
            wrapping_entries,
            data,
            dirty: false,
        });

        info!("backend unlocked");

        let callbacks = self
            .callbacks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(cb) = callbacks.on_unlocked {
            cb();
        }

        Ok(())
    }

    async fn lock(&self) -> Result<(), BackendError> {
        let mut guard = self.state.write().await;

        if guard.is_none() {
            return Ok(());
        }

        *guard = None;
        info!("backend locked");

        let callbacks = self
            .callbacks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(cb) = callbacks.on_locked {
            cb();
        }

        Ok(())
    }

    async fn list_items(&self) -> Result<Vec<VaultItemMeta>, BackendError> {
        let guard = self.state.read().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let items: Vec<VaultItemMeta> = state
            .data
            .items
            .iter()
            .map(|item| self.item_to_meta(item, &self.id))
            .collect();

        Ok(items)
    }

    async fn get_item(&self, id: &str) -> Result<VaultItem, BackendError> {
        let guard = self.state.read().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        state
            .data
            .items
            .iter()
            .find(|item| item.id == id)
            .map(|item| self.item_to_vault_item(item, &self.id))
            .ok_or(BackendError::NotFound)
    }

    async fn get_secret(&self, id: &str) -> Result<SecretBytes, BackendError> {
        self.get_secret_attr(id, "secret").await
    }

    async fn search(&self, attrs: &Attributes) -> Result<Vec<VaultItemMeta>, BackendError> {
        let guard = self.state.read().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let items: Vec<VaultItemMeta> = state
            .data
            .items
            .iter()
            .filter(|item| self.matches_attributes(item, attrs))
            .map(|item| self.item_to_meta(item, &self.id))
            .collect();

        Ok(items)
    }

    async fn get_secret_attr(&self, id: &str, attr: &str) -> Result<SecretBytes, BackendError> {
        let guard = self.state.read().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        state
            .data
            .items
            .iter()
            .find(|item| item.id == id)
            .and_then(|item| item.secrets.get(attr))
            .and_then(|s| BASE64_STANDARD.decode(s).ok())
            .map(SecretBytes::new)
            .ok_or(BackendError::NotFound)
    }

    async fn get_item_attributes(&self, id: &str) -> Result<ItemAttributes, BackendError> {
        let guard = self.state.read().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let item = state
            .data
            .items
            .iter()
            .find(|item| item.id == id)
            .ok_or(BackendError::NotFound)?;

        Ok(ItemAttributes {
            public: item.attributes.clone(),
            secret_names: item.secrets.keys().cloned().collect(),
        })
    }

    async fn create_item(&self, item: NewItem, replace: bool) -> Result<String, BackendError> {
        item.validate()?;

        let mut guard = self.state.write().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;

        if let Some((idx, _)) = state
            .data
            .items
            .iter()
            .enumerate()
            .find(|(_, i)| self.matches_attributes(i, &item.attributes))
        {
            if !replace {
                return Err(BackendError::AlreadyExists);
            }

            let now = chrono::Utc::now().timestamp();
            let mut existing_item = state.data.items[idx].clone();
            existing_item.label = item.label.clone();
            existing_item.attributes = item.attributes.clone();
            existing_item.secrets = item
                .secrets
                .iter()
                .map(|(k, v)| (k.clone(), BASE64_STANDARD.encode(v.as_slice())))
                .collect();
            existing_item.modified = now;

            let id = existing_item.id.clone();
            state.data.items[idx] = existing_item;
            state.dirty = true;

            drop(guard);
            self.save().await?;

            return Ok(id);
        }

        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();

        let secrets: HashMap<String, String> = item
            .secrets
            .iter()
            .map(|(k, v)| (k.clone(), BASE64_STANDARD.encode(v.as_slice())))
            .collect();

        let new_item = VaultItemData {
            id: id.clone(),
            label: item.label,
            attributes: item.attributes,
            secrets,
            created: now,
            modified: now,
        };

        state.data.items.push(new_item);
        state.dirty = true;

        drop(guard);
        self.save().await?;

        info!(item_id = %id, "created item");
        Ok(id)
    }

    async fn update_item(&self, id: &str, update: ItemUpdate) -> Result<(), BackendError> {
        if let Some(ref attrs) = update.attributes {
            for key in rosec_core::RESERVED_ATTRIBUTES {
                if attrs.contains_key(*key) {
                    return Err(BackendError::InvalidInput(
                        format!("reserved attribute name: {}", key).into(),
                    ));
                }
            }
        }

        let mut guard = self.state.write().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;

        let item = state
            .data
            .items
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or(BackendError::NotFound)?;

        let now = chrono::Utc::now().timestamp();

        if let Some(label) = update.label {
            item.label = label;
        }

        if let Some(attrs) = update.attributes {
            item.attributes = attrs;
        }

        if let Some(secrets) = update.secrets {
            for (k, v) in secrets {
                item.secrets.insert(k, BASE64_STANDARD.encode(v.as_slice()));
            }
        }

        item.modified = now;
        state.dirty = true;

        drop(guard);
        self.save().await?;

        info!(item_id = %id, "updated item");
        Ok(())
    }

    async fn delete_item(&self, id: &str) -> Result<(), BackendError> {
        let mut guard = self.state.write().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;

        let initial_len = state.data.items.len();
        state.data.items.retain(|item| item.id != id);

        if state.data.items.len() == initial_len {
            return Err(BackendError::NotFound);
        }

        state.dirty = true;

        drop(guard);
        self.save().await?;

        info!(item_id = %id, "deleted item");
        Ok(())
    }

    async fn list_ssh_keys(&self) -> Result<Vec<SshKeyMeta>, BackendError> {
        Ok(Vec::new())
    }

    /// Local vaults have no remote source — nothing to sync.
    async fn sync(&self) -> Result<(), BackendError> {
        Ok(())
    }

    /// Local vaults have no remote source — never "changed".
    async fn check_remote_changed(&self) -> Result<bool, BackendError> {
        Ok(false)
    }

    fn set_event_callbacks(&self, callbacks: BackendCallbacks) -> Result<(), BackendError> {
        let mut guard = self
            .callbacks
            .write()
            .map_err(|_| BackendError::Other(anyhow::anyhow!("callbacks lock poisoned")))?;
        *guard = callbacks;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_backend() -> (LocalVault, NamedTempFile) {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();
        std::fs::remove_file(&path).unwrap();
        let backend = LocalVault::new("test", path);
        (backend, temp)
    }

    #[tokio::test]
    async fn unlock_creates_vault_if_not_exists() {
        let temp = NamedTempFile::new().unwrap();
        std::fs::remove_file(temp.path()).unwrap();

        let backend = LocalVault::new("test", temp.path());
        let result = backend
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await;

        assert!(result.is_ok());
        assert!(temp.path().exists());
    }

    #[tokio::test]
    async fn unlock_fails_with_empty_password() {
        let (backend, _temp) = create_test_backend();
        let result = backend
            .unlock(UnlockInput::Password(Zeroizing::new(String::new())))
            .await;

        assert!(matches!(result, Err(BackendError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn list_items_returns_empty_when_no_items() {
        let (backend, _temp) = create_test_backend();
        backend
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let items = backend.list_items().await.unwrap();
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn create_and_get_item() {
        let (backend, _temp) = create_test_backend();
        backend
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

        let item = NewItem {
            label: "Test Item".to_string(),
            attributes: HashMap::new(),
            secrets,
        };

        let id = backend.create_item(item, false).await.unwrap();

        let retrieved = backend.get_item(&id).await.unwrap();
        assert_eq!(retrieved.meta.label, "Test Item");
    }

    #[tokio::test]
    async fn create_item_already_exists() {
        let (backend, _temp) = create_test_backend();
        backend
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let mut attrs = HashMap::new();
        attrs.insert("key".to_string(), "value".to_string());

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

        let item = NewItem {
            label: "Test".to_string(),
            attributes: attrs.clone(),
            secrets: secrets.clone(),
        };

        backend.create_item(item, false).await.unwrap();

        let item2 = NewItem {
            label: "Test2".to_string(),
            attributes: attrs,
            secrets,
        };

        let result = backend.create_item(item2, false).await;
        assert!(matches!(result, Err(BackendError::AlreadyExists)));
    }

    #[tokio::test]
    async fn create_item_replace() {
        let (backend, _temp) = create_test_backend();
        backend
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let mut attrs = HashMap::new();
        attrs.insert("key".to_string(), "value".to_string());

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

        let item = NewItem {
            label: "Test".to_string(),
            attributes: attrs.clone(),
            secrets: secrets.clone(),
        };

        let id1 = backend.create_item(item, false).await.unwrap();

        let item2 = NewItem {
            label: "Replaced".to_string(),
            attributes: attrs,
            secrets,
        };

        let id2 = backend.create_item(item2, true).await.unwrap();

        assert_eq!(id1, id2);

        let retrieved = backend.get_item(&id1).await.unwrap();
        assert_eq!(retrieved.meta.label, "Replaced");
    }

    #[tokio::test]
    async fn update_item() {
        let (backend, _temp) = create_test_backend();
        backend
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

        let item = NewItem {
            label: "Original".to_string(),
            attributes: HashMap::new(),
            secrets,
        };

        let id = backend.create_item(item, false).await.unwrap();

        let update = ItemUpdate {
            label: Some("Updated".to_string()),
            attributes: None,
            secrets: None,
        };

        backend.update_item(&id, update).await.unwrap();

        let retrieved = backend.get_item(&id).await.unwrap();
        assert_eq!(retrieved.meta.label, "Updated");
    }

    #[tokio::test]
    async fn update_item_reserved_attribute() {
        let (backend, _temp) = create_test_backend();
        backend
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

        let item = NewItem {
            label: "Test".to_string(),
            attributes: HashMap::new(),
            secrets,
        };

        let id = backend.create_item(item, false).await.unwrap();

        let mut attrs = HashMap::new();
        attrs.insert("id".to_string(), "newid".to_string());

        let update = ItemUpdate {
            label: None,
            attributes: Some(attrs),
            secrets: None,
        };

        let result = backend.update_item(&id, update).await;
        assert!(matches!(result, Err(BackendError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn delete_item() {
        let (backend, _temp) = create_test_backend();
        backend
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

        let item = NewItem {
            label: "Test".to_string(),
            attributes: HashMap::new(),
            secrets,
        };

        let id = backend.create_item(item, false).await.unwrap();

        backend.delete_item(&id).await.unwrap();

        let result = backend.get_item(&id).await;
        assert!(matches!(result, Err(BackendError::NotFound)));
    }

    #[tokio::test]
    async fn search_items() {
        let (backend, _temp) = create_test_backend();
        backend
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let mut attrs1 = HashMap::new();
        attrs1.insert("category".to_string(), "login".to_string());
        attrs1.insert("domain".to_string(), "example.com".to_string());

        let mut attrs2 = HashMap::new();
        attrs2.insert("category".to_string(), "login".to_string());
        attrs2.insert("domain".to_string(), "other.com".to_string());

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

        let item1 = NewItem {
            label: "Item1".to_string(),
            attributes: attrs1.clone(),
            secrets: secrets.clone(),
        };
        let item2 = NewItem {
            label: "Item2".to_string(),
            attributes: attrs2,
            secrets,
        };

        backend.create_item(item1, false).await.unwrap();
        backend.create_item(item2, false).await.unwrap();

        let mut search_attrs = HashMap::new();
        search_attrs.insert("domain".to_string(), "example.com".to_string());

        let results = backend.search(&search_attrs).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].label, "Item1");
    }

    #[tokio::test]
    async fn operations_fail_when_locked() {
        let (backend, _temp) = create_test_backend();

        let result = backend.list_items().await;
        assert!(matches!(result, Err(BackendError::Locked)));

        let result = backend.get_item("id").await;
        assert!(matches!(result, Err(BackendError::Locked)));

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"test".to_vec()));
        let item = NewItem {
            label: "Test".to_string(),
            attributes: HashMap::new(),
            secrets,
        };
        let result = backend.create_item(item, false).await;
        assert!(matches!(result, Err(BackendError::Locked)));
    }

    #[tokio::test]
    async fn unlock_relock_roundtrip() {
        let (backend, _temp) = create_test_backend();

        backend
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

        let item = NewItem {
            label: "Test".to_string(),
            attributes: HashMap::new(),
            secrets,
        };

        let id = backend.create_item(item, false).await.unwrap();

        backend.lock().await.unwrap();

        let result = backend.get_item(&id).await;
        assert!(matches!(result, Err(BackendError::Locked)));

        backend
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let retrieved = backend.get_item(&id).await.unwrap();
        assert_eq!(retrieved.meta.label, "Test");
    }

    #[tokio::test]
    async fn add_password_enables_second_unlock() {
        let (backend, _temp) = create_test_backend();

        // Create vault with master password
        backend
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await
            .unwrap();

        // Add a second password
        let entry_id = backend
            .add_password(b"login-password", "login".to_string())
            .await
            .unwrap();
        assert!(!entry_id.is_empty());

        // Verify we have 2 wrapping entries
        let entries = backend.list_passwords().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].1.as_deref(), Some("master"));
        assert_eq!(entries[1].1.as_deref(), Some("login"));

        // Lock and unlock with the second password
        backend.lock().await.unwrap();
        let result = backend
            .unlock(UnlockInput::Password(Zeroizing::new(
                "login-password".to_string(),
            )))
            .await;
        assert!(result.is_ok());

        // Lock and unlock with the original password still works
        backend.lock().await.unwrap();
        let result = backend
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn remove_password_prevents_unlock() {
        let (backend, _temp) = create_test_backend();

        backend
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await
            .unwrap();

        // Add second password
        let entry_id = backend
            .add_password(b"second", "second".to_string())
            .await
            .unwrap();

        // Remove the second password
        backend.remove_password(&entry_id).await.unwrap();

        let entries = backend.list_passwords().await.unwrap();
        assert_eq!(entries.len(), 1);

        // Lock and try the removed password — should fail
        backend.lock().await.unwrap();
        let result = backend
            .unlock(UnlockInput::Password(Zeroizing::new("second".to_string())))
            .await;
        assert!(result.is_err());

        // Original still works
        let result = backend
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn cannot_remove_last_password() {
        let (backend, _temp) = create_test_backend();

        backend
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await
            .unwrap();

        let entries = backend.list_passwords().await.unwrap();
        assert_eq!(entries.len(), 1);

        let result = backend.remove_password(&entries[0].0).await;
        assert!(matches!(result, Err(BackendError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn add_password_rejects_empty_label() {
        let (backend, _temp) = create_test_backend();

        backend
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await
            .unwrap();

        let result = backend.add_password(b"another", String::new()).await;
        assert!(matches!(result, Err(BackendError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn add_password_rejects_duplicate_label() {
        let (backend, _temp) = create_test_backend();

        backend
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await
            .unwrap();

        // Add a password with label "login"
        backend
            .add_password(b"login-pw", "login".to_string())
            .await
            .unwrap();

        // Try to add another password with the same label — should fail
        let result = backend.add_password(b"other-pw", "login".to_string()).await;
        assert!(matches!(result, Err(BackendError::InvalidInput(_))));

        // Verify only 2 entries exist (master + login), not 3
        let entries = backend.list_passwords().await.unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn wrong_password_fails_to_unlock() {
        let (backend, _temp) = create_test_backend();

        // Create vault
        backend
            .unlock(UnlockInput::Password(Zeroizing::new("correct".to_string())))
            .await
            .unwrap();
        backend.lock().await.unwrap();

        // Try wrong password
        let result = backend
            .unlock(UnlockInput::Password(Zeroizing::new("wrong".to_string())))
            .await;
        assert!(result.is_err());
    }
}
