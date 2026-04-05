use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use async_trait::async_trait;
use base64::prelude::{BASE64_STANDARD, Engine};
use rosec_core::{
    AttributeDescriptor, Attributes, Capability, ItemAttributes, ItemMeta, ItemType, ItemUpdate,
    NewItem, Provider, ProviderCallbacks, ProviderError, ProviderStatus, SecretBytes, SshKeyMeta,
    SshPrivateKeyMaterial, UnlockInput,
};
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{debug, info};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Write `data` to `path` with Unix mode `0600`, replacing any existing file.
///
/// Uses a write-then-rename strategy so the file is never partially written.
fn write_secret_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let tmp_path = path.with_extension("json.tmp");

    {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;

        f.write_all(data)?;
        f.flush()?;
    }

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

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
    callbacks: std::sync::RwLock<ProviderCallbacks>,
}

impl LocalVault {
    pub fn new(id: impl Into<String>, path: impl AsRef<Path>) -> Self {
        Self {
            id: id.into(),
            path: path.as_ref().to_path_buf(),
            state: RwLock::new(None),
            callbacks: std::sync::RwLock::new(ProviderCallbacks::default()),
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
    ) -> Result<(VaultData, Zeroizing<[u8; 32]>, Vec<WrappingEntry>), ProviderError> {
        let content = fs::read(&self.path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ProviderError::Unavailable("vault file not found".into())
            } else {
                ProviderError::Other(e.into())
            }
        })?;

        let vault_file: VaultFile =
            serde_json::from_slice(&content).map_err(|e| ProviderError::Other(e.into()))?;

        if vault_file.version != crate::types::VAULT_FORMAT_VERSION {
            return Err(ProviderError::Other(anyhow::anyhow!(
                "unsupported vault version: {}",
                vault_file.version
            )));
        }

        if vault_file.wrapping_entries.is_empty() {
            return Err(ProviderError::Other(anyhow::anyhow!(
                "vault has no wrapping entries"
            )));
        }

        // Try each wrapping entry until one succeeds.
        let mut vault_key = None;
        for entry in &vault_file.wrapping_entries {
            match crypto::unwrap_vault_key(entry, password) {
                Ok(Some(key)) => {
                    vault_key = Some(key);
                    break;
                }
                Ok(None) => continue,
                Err(e) => return Err(ProviderError::Other(e.into())),
            }
        }
        let vault_key = vault_key.ok_or(ProviderError::AuthFailed)?;

        let mac_key =
            crypto::derive_mac_key(&*vault_key).map_err(|e| ProviderError::Other(e.into()))?;

        let encrypted_data = vault_file.encrypted_data_bytes();
        let hmac_valid = crypto::verify_hmac(&*mac_key, &encrypted_data, &vault_file.hmac_bytes())
            .map_err(|e| ProviderError::Other(e.into()))?;
        if !hmac_valid {
            return Err(ProviderError::AuthFailed);
        }

        let decrypted = crypto::decrypt(&encrypted_data, &*vault_key)
            .map_err(|e| ProviderError::Other(anyhow::anyhow!("decryption failed: {}", e)))?;

        let data: VaultData =
            serde_json::from_slice(&decrypted).map_err(|e| ProviderError::Other(e.into()))?;

        Ok((data, vault_key, vault_file.wrapping_entries))
    }

    /// Create a new vault file with a random vault key wrapped by the password.
    async fn create_vault(
        &self,
        password: &[u8],
    ) -> Result<(VaultData, Zeroizing<[u8; 32]>, Vec<WrappingEntry>), ProviderError> {
        let vault_key = crypto::generate_vault_key();
        let mac_key =
            crypto::derive_mac_key(&*vault_key).map_err(|e| ProviderError::Other(e.into()))?;
        let data = VaultData::default();

        let entry = crypto::wrap_vault_key(&vault_key, password, Some("master".to_string()))
            .map_err(|e| ProviderError::Other(e.into()))?;
        let wrapping_entries = vec![entry];

        let plaintext = serde_json::to_vec(&data).map_err(|e| ProviderError::Other(e.into()))?;
        let encrypted = crypto::encrypt(&plaintext, &*vault_key);
        let hmac = crypto::compute_hmac(&*mac_key, &encrypted)
            .map_err(|e| ProviderError::Other(e.into()))?;

        let vault_file = VaultFile::new(wrapping_entries.clone(), &encrypted, &hmac);
        let content = serde_json::to_string_pretty(&vault_file)
            .map_err(|e| ProviderError::Other(e.into()))?;

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| ProviderError::Other(e.into()))?;
        }

        write_secret_file(&self.path, content.as_bytes())
            .map_err(|e| ProviderError::Other(e.into()))?;

        info!(path = %self.path.display(), "created new vault");

        Ok((data, vault_key, wrapping_entries))
    }

    async fn save(&self) -> Result<(), ProviderError> {
        let mut guard = self.state.write().await;

        let state = guard.as_mut().ok_or(ProviderError::Locked)?;

        if !state.dirty {
            return Ok(());
        }

        let plaintext =
            serde_json::to_vec(&state.data).map_err(|e| ProviderError::Other(e.into()))?;
        let encrypted = crypto::encrypt(&plaintext, &*state.vault_key);
        let hmac = crypto::compute_hmac(&*state.mac_key, &encrypted)
            .map_err(|e| ProviderError::Other(e.into()))?;

        let vault_file = VaultFile::new(state.wrapping_entries.clone(), &encrypted, &hmac);
        let content = serde_json::to_string_pretty(&vault_file)
            .map_err(|e| ProviderError::Other(e.into()))?;

        write_secret_file(&self.path, content.as_bytes())
            .map_err(|e| ProviderError::Other(e.into()))?;

        state.dirty = false;
        debug!(path = %self.path.display(), "saved vault");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Key wrapping management (public API for CLI)
    // -----------------------------------------------------------------------

    /// Return the on-disk path of this vault file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn item_to_meta(&self, item: &VaultItemData, provider_id: &str) -> ItemMeta {
        ItemMeta {
            id: item.id.clone(),
            provider_id: provider_id.to_string(),
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

// ═══════════════════════════════════════════════════════════════════════════
// Static attribute catalogue for LocalVault
// ═══════════════════════════════════════════════════════════════════════════

/// Helper: build an `AttributeDescriptor` with `'static` lifetimes.
const fn desc(
    name: &'static str,
    sensitive: bool,
    item_types: &'static [&'static str],
    description: &'static str,
) -> AttributeDescriptor {
    AttributeDescriptor {
        name,
        sensitive,
        item_types,
        description,
    }
}

/// Catalogue of attributes the local vault can store per item type.
///
/// These mirror the Bitwarden PM descriptors where applicable, so that items
/// created locally and items synced from a remote backend produce a consistent
/// attribute namespace.
static LOCAL_VAULT_ATTRIBUTES: &[AttributeDescriptor] = &[
    // -- Common (all item types) --
    desc("name", false, &[], "Item display name"),
    desc(
        rosec_core::ATTR_TYPE,
        false,
        &[],
        "Item type (generic, login, ssh-key, note, card, identity)",
    ),
    desc("notes", true, &[], "Free-form notes (always sensitive)"),
    // -- Login --
    desc(
        "username",
        false,
        &["login"],
        "Login username (public per attribute-model decision)",
    ),
    desc("password", true, &["login"], "Login password"),
    desc("totp", true, &["login"], "TOTP seed / otpauth URI"),
    desc("uri", false, &["login"], "Primary login URI"),
    // -- SSH Key --
    desc("private_key", true, &["ssh-key"], "SSH private key (PEM)"),
    desc("public_key", false, &["ssh-key"], "SSH public key"),
    desc("fingerprint", false, &["ssh-key"], "SSH key fingerprint"),
    // -- Card --
    desc("cardholder", true, &["card"], "Cardholder name (PII)"),
    desc("number", true, &["card"], "Card number"),
    desc(
        "brand",
        false,
        &["card"],
        "Card brand (Visa, Mastercard, etc.)",
    ),
    desc("exp_month", true, &["card"], "Card expiration month"),
    desc("exp_year", true, &["card"], "Card expiration year"),
    desc("code", true, &["card"], "Card security code (CVV)"),
    // -- Identity (all PII → sensitive) --
    desc(
        "title",
        true,
        &["identity"],
        "Identity title (Mr, Ms, etc.)",
    ),
    desc("first_name", true, &["identity"], "First name"),
    desc("middle_name", true, &["identity"], "Middle name"),
    desc("last_name", true, &["identity"], "Last name"),
    desc("username", true, &["identity"], "Identity username (PII)"),
    desc("company", true, &["identity"], "Company name"),
    desc("ssn", true, &["identity"], "Social Security Number"),
    desc("passport_number", true, &["identity"], "Passport number"),
    desc(
        "license_number",
        true,
        &["identity"],
        "Driver's license number",
    ),
    desc("email", true, &["identity"], "Identity email address (PII)"),
    desc("phone", true, &["identity"], "Identity phone number (PII)"),
    desc("address1", true, &["identity"], "Address line 1"),
    desc("address2", true, &["identity"], "Address line 2"),
    desc("address3", true, &["identity"], "Address line 3"),
    desc("city", true, &["identity"], "City"),
    desc("state", true, &["identity"], "State / province"),
    desc("postal_code", true, &["identity"], "Postal / ZIP code"),
    desc("country", true, &["identity"], "Country"),
    // -- Note --
    // Notes use only the common "notes" attribute (always sensitive).
    // -- Generic --
    // Generic items use only common attributes + a "secret" sensitive attribute.
    desc("secret", true, &["generic"], "Generic secret value"),
];

#[async_trait]
impl Provider for LocalVault {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        "Local Vault"
    }

    fn kind(&self) -> &str {
        "local"
    }

    fn capabilities(&self) -> &'static [Capability] {
        &[
            Capability::Write,
            Capability::Ssh,
            Capability::KeyWrapping,
            Capability::PasswordChange,
        ]
    }

    fn available_attributes(&self) -> &'static [AttributeDescriptor] {
        LOCAL_VAULT_ATTRIBUTES
    }

    fn supported_item_types(&self) -> &'static [ItemType] {
        &[
            ItemType::Generic,
            ItemType::Login,
            ItemType::SshKey,
            ItemType::Note,
            ItemType::Card,
            ItemType::Identity,
        ]
    }

    async fn status(&self) -> Result<ProviderStatus, ProviderError> {
        let guard = self.state.read().await;
        let locked = guard.is_none();

        Ok(ProviderStatus {
            locked,
            last_sync: None,
            cached: false,
            offline_cache: false,
            last_cache_write: None,
        })
    }

    fn needs_new_password_confirmation(&self) -> bool {
        // Confirmation is required when the vault file does not yet exist.
        // The daemon will prompt the user to enter the password twice before
        // calling unlock(), so that a typo cannot silently create a vault
        // with a wrong (unrecoverable) password.
        !self.path.exists()
    }

    async fn unlock(&self, input: UnlockInput) -> Result<(), ProviderError> {
        let password = match input {
            UnlockInput::Password(pw) => pw,
            UnlockInput::WithRegistration { password, .. }
            | UnlockInput::WithAuth { password, .. } => password,
        };

        if password.is_empty() {
            return Err(ProviderError::InvalidInput(
                "password cannot be empty".into(),
            ));
        }

        let mut guard = self.state.write().await;

        if guard.is_some() {
            debug!("provider already unlocked");
            return Ok(());
        }

        let password_bytes = password.as_bytes();
        let (data, vault_key, wrapping_entries) = match self.load_vault(password_bytes).await {
            Ok(result) => result,
            Err(ProviderError::Unavailable(_)) => {
                info!("vault not found, creating new vault");
                self.create_vault(password_bytes).await?
            }
            Err(e) => return Err(e),
        };

        let mac_key =
            crypto::derive_mac_key(&*vault_key).map_err(|e| ProviderError::Other(e.into()))?;

        *guard = Some(UnlockedState {
            vault_key,
            mac_key,
            wrapping_entries,
            data,
            dirty: false,
        });

        info!("provider unlocked");

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

    async fn lock(&self) -> Result<(), ProviderError> {
        let mut guard = self.state.write().await;

        if guard.is_none() {
            return Ok(());
        }

        *guard = None;
        info!("provider locked");

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

    /// Change the unlock password for this vault.
    ///
    /// Finds the wrapping entry that `old_password` successfully unwraps, adds
    /// a new wrapping entry for `new_password` (inheriting the old entry's
    /// label), then removes the old entry.  The vault key itself is unchanged —
    /// only the key-wrapping layer is rotated.
    ///
    /// Returns `ProviderError::AuthFailed` if `old_password` doesn't match any
    /// wrapping entry.  Returns `ProviderError::Locked` if the vault is locked.
    async fn change_password(
        &self,
        old_password: Zeroizing<String>,
        new_password: Zeroizing<String>,
    ) -> Result<(), ProviderError> {
        let mut guard = self.state.write().await;
        let state = guard.as_mut().ok_or(ProviderError::Locked)?;

        // Find the wrapping entry that the old password unlocks.
        let old_entry_idx = state
            .wrapping_entries
            .iter()
            .position(|entry| {
                crypto::unwrap_vault_key(entry, old_password.as_bytes())
                    .ok()
                    .flatten()
                    .is_some()
            })
            .ok_or(ProviderError::AuthFailed)?;

        // Inherit the label from the old entry.
        let label = state.wrapping_entries[old_entry_idx].label.clone();

        // Create a new wrapping entry for the new password with the same vault key.
        let new_entry = crypto::wrap_vault_key(&state.vault_key, new_password.as_bytes(), label)
            .map_err(|e| ProviderError::Other(e.into()))?;

        // Replace atomically: add new entry, then remove old.
        let old_entry_id = state.wrapping_entries[old_entry_idx].id.clone();
        state.wrapping_entries.push(new_entry);
        state.wrapping_entries.retain(|e| e.id != old_entry_id);
        state.dirty = true;

        drop(guard);
        self.save().await?;

        info!("vault password changed");
        Ok(())
    }

    async fn list_items(&self) -> Result<Vec<ItemMeta>, ProviderError> {
        let guard = self.state.read().await;
        let state = guard.as_ref().ok_or(ProviderError::Locked)?;

        let items: Vec<ItemMeta> = state
            .data
            .items
            .iter()
            .map(|item| self.item_to_meta(item, &self.id))
            .collect();

        Ok(items)
    }

    async fn search(&self, attrs: &Attributes) -> Result<Vec<ItemMeta>, ProviderError> {
        let guard = self.state.read().await;
        let state = guard.as_ref().ok_or(ProviderError::Locked)?;

        let items: Vec<ItemMeta> = state
            .data
            .items
            .iter()
            .filter(|item| self.matches_attributes(item, attrs))
            .map(|item| self.item_to_meta(item, &self.id))
            .collect();

        Ok(items)
    }

    async fn get_secret_attr(&self, id: &str, attr: &str) -> Result<SecretBytes, ProviderError> {
        let guard = self.state.read().await;
        let state = guard.as_ref().ok_or(ProviderError::Locked)?;

        state
            .data
            .items
            .iter()
            .find(|item| item.id == id)
            .and_then(|item| item.secrets.get(attr))
            .and_then(|s| BASE64_STANDARD.decode(s).ok())
            .map(SecretBytes::new)
            .ok_or(ProviderError::NotFound)
    }

    async fn get_item_attributes(&self, id: &str) -> Result<ItemAttributes, ProviderError> {
        let guard = self.state.read().await;
        let state = guard.as_ref().ok_or(ProviderError::Locked)?;

        let item = state
            .data
            .items
            .iter()
            .find(|item| item.id == id)
            .ok_or(ProviderError::NotFound)?;

        Ok(ItemAttributes {
            public: item.attributes.clone(),
            secret_names: item.secrets.keys().cloned().collect(),
        })
    }

    async fn create_item(&self, item: NewItem, replace: bool) -> Result<String, ProviderError> {
        item.validate()?;

        let mut guard = self.state.write().await;
        let state = guard.as_mut().ok_or(ProviderError::Locked)?;

        // Stamp rosec:type from the typed item_type field.
        let mut attributes = item.attributes.clone();
        if let Some(ref item_type) = item.item_type {
            attributes.insert(rosec_core::ATTR_TYPE.to_string(), item_type.to_string());
        }

        if let Some((idx, _)) = state
            .data
            .items
            .iter()
            .enumerate()
            .find(|(_, i)| self.matches_attributes(i, &attributes))
        {
            if !replace {
                return Err(ProviderError::AlreadyExists);
            }

            let now = chrono::Utc::now().timestamp();
            let mut existing_item = state.data.items[idx].clone();
            existing_item.label = item.label.clone();
            existing_item.attributes = attributes;
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
            attributes,
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

    async fn update_item(&self, id: &str, update: ItemUpdate) -> Result<(), ProviderError> {
        if let Some(ref attrs) = update.attributes {
            for key in rosec_core::RESERVED_ATTRIBUTES {
                if attrs.contains_key(*key) {
                    return Err(ProviderError::InvalidInput(
                        format!("reserved attribute name: {}", key).into(),
                    ));
                }
            }
        }

        let mut guard = self.state.write().await;
        let state = guard.as_mut().ok_or(ProviderError::Locked)?;

        let item = state
            .data
            .items
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or(ProviderError::NotFound)?;

        let now = chrono::Utc::now().timestamp();

        if let Some(label) = update.label {
            item.label = label;
        }

        if let Some(attrs) = update.attributes {
            item.attributes = attrs;
        }

        // Stamp rosec:type from the typed item_type field.
        // Applied after attribute replacement so the caller-provided type
        // always wins, even if they also replaced all attributes.
        if let Some(item_type) = update.item_type {
            item.attributes
                .insert(rosec_core::ATTR_TYPE.to_string(), item_type.to_string());
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

    async fn delete_item(&self, id: &str) -> Result<(), ProviderError> {
        let mut guard = self.state.write().await;
        let state = guard.as_mut().ok_or(ProviderError::Locked)?;

        let initial_len = state.data.items.len();
        state.data.items.retain(|item| item.id != id);

        if state.data.items.len() == initial_len {
            return Err(ProviderError::NotFound);
        }

        state.dirty = true;

        drop(guard);
        self.save().await?;

        info!(item_id = %id, "deleted item");
        Ok(())
    }

    async fn list_ssh_keys(&self) -> Result<Vec<SshKeyMeta>, ProviderError> {
        let guard = self.state.read().await;
        let state = guard.as_ref().ok_or(ProviderError::Locked)?;

        let provider_id = self.id.clone();
        let keys = state
            .data
            .items
            .iter()
            .filter(|item| {
                // Must have a private_key secret present.
                if !item.secrets.contains_key("private_key") {
                    return false;
                }
                // Prefer explicit type check (handles aliases like "sshkey").
                let typed = rosec_core::ItemType::from_attributes(&item.attributes);
                if typed == rosec_core::ItemType::SshKey {
                    return true;
                }
                // Fallback: items without rosec:type that have SSH key
                // attributes (fingerprint or public_key) are treated as SSH
                // keys.  This covers items created before type stamping.
                !item.attributes.contains_key(rosec_core::ATTR_TYPE)
                    && (item.attributes.contains_key("fingerprint")
                        || item.attributes.contains_key("public_key"))
            })
            .map(|item| {
                let public_key_openssh = item
                    .attributes
                    .get("public_key")
                    .cloned()
                    .filter(|v| !v.is_empty());
                let fingerprint = item
                    .attributes
                    .get("fingerprint")
                    .cloned()
                    .filter(|v| !v.is_empty());

                // SSH host patterns from custom.ssh_host / custom.ssh-host attributes.
                let ssh_hosts: Vec<String> = ["custom.ssh_host", "custom.ssh-host"]
                    .iter()
                    .filter_map(|key| item.attributes.get(*key))
                    .flat_map(|v| v.lines())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect();

                // SSH username from custom.ssh_user / custom.ssh-user.
                let ssh_user = ["custom.ssh_user", "custom.ssh-user"]
                    .iter()
                    .filter_map(|key| item.attributes.get(*key))
                    .map(|v| v.trim().to_string())
                    .find(|s| !s.is_empty());

                // Require confirmation from custom.ssh_confirm / custom.ssh-confirm.
                let require_confirm = ["custom.ssh_confirm", "custom.ssh-confirm"]
                    .iter()
                    .filter_map(|key| item.attributes.get(*key))
                    .any(|v| v == "true");

                let revision_date = SystemTime::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_secs(item.modified as u64));

                SshKeyMeta {
                    item_id: item.id.clone(),
                    item_name: item.label.clone(),
                    provider_id: provider_id.clone(),
                    public_key_openssh,
                    fingerprint,
                    ssh_hosts,
                    ssh_user,
                    require_confirm,
                    revision_date,
                }
            })
            .collect();

        Ok(keys)
    }

    async fn get_ssh_private_key(&self, id: &str) -> Result<SshPrivateKeyMaterial, ProviderError> {
        let guard = self.state.read().await;
        let state = guard.as_ref().ok_or(ProviderError::Locked)?;

        let item = state
            .data
            .items
            .iter()
            .find(|item| item.id == id)
            .ok_or(ProviderError::NotFound)?;

        let encoded = item
            .secrets
            .get("private_key")
            .ok_or(ProviderError::NotFound)?;

        let raw = BASE64_STANDARD
            .decode(encoded)
            .map_err(|e| ProviderError::Other(anyhow::anyhow!("base64 decode failed: {e}")))?;

        let pem = String::from_utf8(raw).map_err(|e| {
            ProviderError::Other(anyhow::anyhow!("private key is not valid UTF-8: {e}"))
        })?;

        Ok(SshPrivateKeyMaterial {
            pem: Zeroizing::new(pem),
        })
    }

    /// Local vaults have no remote source — nothing to sync.
    async fn sync(&self) -> Result<(), ProviderError> {
        Ok(())
    }

    /// Local vaults have no remote source — never "changed".
    async fn check_remote_changed(&self) -> Result<bool, ProviderError> {
        Ok(false)
    }

    fn set_event_callbacks(&self, callbacks: ProviderCallbacks) -> Result<(), ProviderError> {
        let mut guard = self
            .callbacks
            .write()
            .map_err(|_| ProviderError::Other(anyhow::anyhow!("callbacks lock poisoned")))?;
        *guard = callbacks;
        Ok(())
    }

    async fn add_password(&self, password: &[u8], label: String) -> Result<String, ProviderError> {
        if label.is_empty() {
            return Err(ProviderError::InvalidInput(
                "password label cannot be empty".into(),
            ));
        }

        let mut guard = self.state.write().await;
        let state = guard.as_mut().ok_or(ProviderError::Locked)?;

        if state
            .wrapping_entries
            .iter()
            .any(|e| e.label.as_deref() == Some(label.as_str()))
        {
            return Err(ProviderError::InvalidInput(
                format!("a password with label '{label}' already exists").into(),
            ));
        }

        let entry = crypto::wrap_vault_key(&state.vault_key, password, Some(label))
            .map_err(|e| ProviderError::Other(e.into()))?;
        let id = entry.id.clone();
        state.wrapping_entries.push(entry);
        state.dirty = true;

        drop(guard);
        self.save().await?;

        info!(entry_id = %id, "added wrapping entry");
        Ok(id)
    }

    async fn remove_password(&self, entry_id: &str) -> Result<(), ProviderError> {
        let mut guard = self.state.write().await;
        let state = guard.as_mut().ok_or(ProviderError::Locked)?;

        if state.wrapping_entries.len() <= 1 {
            return Err(ProviderError::InvalidInput(
                "cannot remove the last wrapping entry".into(),
            ));
        }

        let initial_len = state.wrapping_entries.len();
        state.wrapping_entries.retain(|e| e.id != entry_id);

        if state.wrapping_entries.len() == initial_len {
            return Err(ProviderError::NotFound);
        }

        state.dirty = true;

        drop(guard);
        self.save().await?;

        info!(entry_id = %entry_id, "removed wrapping entry");
        Ok(())
    }

    async fn list_passwords(&self) -> Result<Vec<(String, Option<String>)>, ProviderError> {
        let guard = self.state.read().await;
        let state = guard.as_ref().ok_or(ProviderError::Locked)?;

        Ok(state
            .wrapping_entries
            .iter()
            .map(|e| (e.id.clone(), e.label.clone()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_provider() -> (LocalVault, NamedTempFile) {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();
        std::fs::remove_file(&path).unwrap();
        let provider = LocalVault::new("test", path);
        (provider, temp)
    }

    #[tokio::test]
    async fn unlock_creates_vault_if_not_exists() {
        let temp = NamedTempFile::new().unwrap();
        std::fs::remove_file(temp.path()).unwrap();

        let provider = LocalVault::new("test", temp.path());
        let result = provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await;

        assert!(result.is_ok());
        assert!(temp.path().exists());
    }

    #[tokio::test]
    async fn unlock_fails_with_empty_password() {
        let (provider, _temp) = create_test_provider();
        let result = provider
            .unlock(UnlockInput::Password(Zeroizing::new(String::new())))
            .await;

        assert!(matches!(result, Err(ProviderError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn list_items_returns_empty_when_no_items() {
        let (provider, _temp) = create_test_provider();
        provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let items = provider.list_items().await.unwrap();
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn create_and_get_item() {
        let (provider, _temp) = create_test_provider();
        provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

        let item = NewItem {
            label: "Test Item".to_string(),
            item_type: None,
            attributes: HashMap::new(),
            secrets,
        };

        let id = provider.create_item(item, false).await.unwrap();

        let attrs = provider.get_item_attributes(&id).await.unwrap();
        let items = provider.list_items().await.unwrap();
        let meta = items.iter().find(|m| m.id == id).unwrap();
        assert_eq!(meta.label, "Test Item");
        assert!(attrs.secret_names.contains(&"secret".to_string()));
    }

    #[tokio::test]
    async fn create_item_already_exists() {
        let (provider, _temp) = create_test_provider();
        provider
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
            item_type: None,
            attributes: attrs.clone(),
            secrets: secrets.clone(),
        };

        provider.create_item(item, false).await.unwrap();

        let item2 = NewItem {
            label: "Test2".to_string(),
            item_type: None,
            attributes: attrs,
            secrets,
        };

        let result = provider.create_item(item2, false).await;
        assert!(matches!(result, Err(ProviderError::AlreadyExists)));
    }

    #[tokio::test]
    async fn create_item_replace() {
        let (provider, _temp) = create_test_provider();
        provider
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
            item_type: None,
            attributes: attrs.clone(),
            secrets: secrets.clone(),
        };

        let id1 = provider.create_item(item, false).await.unwrap();

        let item2 = NewItem {
            label: "Replaced".to_string(),
            item_type: None,
            attributes: attrs,
            secrets,
        };

        let id2 = provider.create_item(item2, true).await.unwrap();

        assert_eq!(id1, id2);

        let items = provider.list_items().await.unwrap();
        let meta = items.iter().find(|m| m.id == id1).unwrap();
        assert_eq!(meta.label, "Replaced");
    }

    #[tokio::test]
    async fn update_item() {
        let (provider, _temp) = create_test_provider();
        provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

        let item = NewItem {
            label: "Original".to_string(),
            item_type: None,
            attributes: HashMap::new(),
            secrets,
        };

        let id = provider.create_item(item, false).await.unwrap();

        let update = ItemUpdate {
            label: Some("Updated".to_string()),
            item_type: None,
            attributes: None,
            secrets: None,
        };

        provider.update_item(&id, update).await.unwrap();

        let items = provider.list_items().await.unwrap();
        let meta = items.iter().find(|m| m.id == id).unwrap();
        assert_eq!(meta.label, "Updated");
    }

    #[tokio::test]
    async fn update_item_reserved_attribute() {
        let (provider, _temp) = create_test_provider();
        provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

        let item = NewItem {
            label: "Test".to_string(),
            item_type: None,
            attributes: HashMap::new(),
            secrets,
        };

        let id = provider.create_item(item, false).await.unwrap();

        let mut attrs = HashMap::new();
        attrs.insert("id".to_string(), "newid".to_string());

        let update = ItemUpdate {
            label: None,
            item_type: None,
            attributes: Some(attrs),
            secrets: None,
        };

        let result = provider.update_item(&id, update).await;
        assert!(matches!(result, Err(ProviderError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn delete_item() {
        let (provider, _temp) = create_test_provider();
        provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

        let item = NewItem {
            label: "Test".to_string(),
            item_type: None,
            attributes: HashMap::new(),
            secrets,
        };

        let id = provider.create_item(item, false).await.unwrap();

        provider.delete_item(&id).await.unwrap();

        let result = provider.get_item_attributes(&id).await;
        assert!(matches!(result, Err(ProviderError::NotFound)));
    }

    #[tokio::test]
    async fn search_items() {
        let (provider, _temp) = create_test_provider();
        provider
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
            item_type: None,
            attributes: attrs1.clone(),
            secrets: secrets.clone(),
        };
        let item2 = NewItem {
            label: "Item2".to_string(),
            item_type: None,
            attributes: attrs2,
            secrets,
        };

        provider.create_item(item1, false).await.unwrap();
        provider.create_item(item2, false).await.unwrap();

        let mut search_attrs = HashMap::new();
        search_attrs.insert("domain".to_string(), "example.com".to_string());

        let results = provider.search(&search_attrs).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].label, "Item1");
    }

    #[tokio::test]
    async fn operations_fail_when_locked() {
        let (provider, _temp) = create_test_provider();

        let result = provider.list_items().await;
        assert!(matches!(result, Err(ProviderError::Locked)));

        let result = provider.get_item_attributes("id").await;
        assert!(matches!(result, Err(ProviderError::Locked)));

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"test".to_vec()));
        let item = NewItem {
            label: "Test".to_string(),
            item_type: None,
            attributes: HashMap::new(),
            secrets,
        };
        let result = provider.create_item(item, false).await;
        assert!(matches!(result, Err(ProviderError::Locked)));
    }

    #[tokio::test]
    async fn unlock_relock_roundtrip() {
        let (provider, _temp) = create_test_provider();

        provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let mut secrets = HashMap::new();
        secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

        let item = NewItem {
            label: "Test".to_string(),
            item_type: None,
            attributes: HashMap::new(),
            secrets,
        };

        let id = provider.create_item(item, false).await.unwrap();

        provider.lock().await.unwrap();

        let result = provider.get_item_attributes(&id).await;
        assert!(matches!(result, Err(ProviderError::Locked)));

        provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "password".to_string(),
            )))
            .await
            .unwrap();

        let items = provider.list_items().await.unwrap();
        let meta = items.iter().find(|m| m.id == id).unwrap();
        assert_eq!(meta.label, "Test");
    }

    #[tokio::test]
    async fn add_password_enables_second_unlock() {
        let (provider, _temp) = create_test_provider();

        // Create vault with master password
        provider
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await
            .unwrap();

        // Add a second password
        let entry_id = provider
            .add_password(b"login-password", "login".to_string())
            .await
            .unwrap();
        assert!(!entry_id.is_empty());

        // Verify we have 2 wrapping entries
        let entries = provider.list_passwords().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].1.as_deref(), Some("master"));
        assert_eq!(entries[1].1.as_deref(), Some("login"));

        // Lock and unlock with the second password
        provider.lock().await.unwrap();
        let result = provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "login-password".to_string(),
            )))
            .await;
        assert!(result.is_ok());

        // Lock and unlock with the original password still works
        provider.lock().await.unwrap();
        let result = provider
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn remove_password_prevents_unlock() {
        let (provider, _temp) = create_test_provider();

        provider
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await
            .unwrap();

        // Add second password
        let entry_id = provider
            .add_password(b"second", "second".to_string())
            .await
            .unwrap();

        // Remove the second password
        provider.remove_password(&entry_id).await.unwrap();

        let entries = provider.list_passwords().await.unwrap();
        assert_eq!(entries.len(), 1);

        // Lock and try the removed password — should fail
        provider.lock().await.unwrap();
        let result = provider
            .unlock(UnlockInput::Password(Zeroizing::new("second".to_string())))
            .await;
        assert!(result.is_err());

        // Original still works
        let result = provider
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn cannot_remove_last_password() {
        let (provider, _temp) = create_test_provider();

        provider
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await
            .unwrap();

        let entries = provider.list_passwords().await.unwrap();
        assert_eq!(entries.len(), 1);

        let result = provider.remove_password(&entries[0].0).await;
        assert!(matches!(result, Err(ProviderError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn add_password_rejects_empty_label() {
        let (provider, _temp) = create_test_provider();

        provider
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await
            .unwrap();

        let result = provider.add_password(b"another", String::new()).await;
        assert!(matches!(result, Err(ProviderError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn add_password_rejects_duplicate_label() {
        let (provider, _temp) = create_test_provider();

        provider
            .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
            .await
            .unwrap();

        // Add a password with label "login"
        provider
            .add_password(b"login-pw", "login".to_string())
            .await
            .unwrap();

        // Try to add another password with the same label — should fail
        let result = provider
            .add_password(b"other-pw", "login".to_string())
            .await;
        assert!(matches!(result, Err(ProviderError::InvalidInput(_))));

        // Verify only 2 entries exist (master + login), not 3
        let entries = provider.list_passwords().await.unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn wrong_password_fails_to_unlock() {
        let (provider, _temp) = create_test_provider();

        // Create vault
        provider
            .unlock(UnlockInput::Password(Zeroizing::new("correct".to_string())))
            .await
            .unwrap();
        provider.lock().await.unwrap();

        // Try wrong password
        let result = provider
            .unlock(UnlockInput::Password(Zeroizing::new("wrong".to_string())))
            .await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // change_password tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn change_password_happy_path() {
        let (provider, _temp) = create_test_provider();
        provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "old-pass".to_string(),
            )))
            .await
            .unwrap();

        provider
            .change_password(
                Zeroizing::new("old-pass".to_string()),
                Zeroizing::new("new-pass".to_string()),
            )
            .await
            .unwrap();

        // Lock and unlock with new password.
        provider.lock().await.unwrap();
        let result = provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "new-pass".to_string(),
            )))
            .await;
        assert!(result.is_ok());

        // Old password should no longer work.
        provider.lock().await.unwrap();
        let result = provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "old-pass".to_string(),
            )))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn change_password_wrong_old_password() {
        let (provider, _temp) = create_test_provider();
        provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "real-pass".to_string(),
            )))
            .await
            .unwrap();

        let result = provider
            .change_password(
                Zeroizing::new("wrong-pass".to_string()),
                Zeroizing::new("new-pass".to_string()),
            )
            .await;
        assert!(matches!(result, Err(ProviderError::AuthFailed)));
    }

    #[tokio::test]
    async fn change_password_when_locked() {
        let (provider, _temp) = create_test_provider();
        let result = provider
            .change_password(
                Zeroizing::new("old".to_string()),
                Zeroizing::new("new".to_string()),
            )
            .await;
        assert!(matches!(result, Err(ProviderError::Locked)));
    }

    #[tokio::test]
    async fn change_password_preserves_label() {
        let (provider, _temp) = create_test_provider();
        provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "master-pw".to_string(),
            )))
            .await
            .unwrap();

        // The first wrapping entry has the label "master" by convention.
        let entries_before = provider.list_passwords().await.unwrap();
        assert_eq!(entries_before.len(), 1);
        assert_eq!(entries_before[0].1, Some("master".to_string()));

        // Change password — the new entry should inherit "master" label.
        provider
            .change_password(
                Zeroizing::new("master-pw".to_string()),
                Zeroizing::new("rotated-pw".to_string()),
            )
            .await
            .unwrap();

        let entries_after = provider.list_passwords().await.unwrap();
        assert_eq!(entries_after.len(), 1);
        assert_eq!(entries_after[0].1, Some("master".to_string()));

        // ID should have changed (new entry, not same entry).
        assert_ne!(entries_before[0].0, entries_after[0].0);
    }

    #[tokio::test]
    async fn change_password_only_affects_matched_entry() {
        let (provider, _temp) = create_test_provider();
        provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "master-pw".to_string(),
            )))
            .await
            .unwrap();

        // Add a second password.
        provider
            .add_password(b"second-pw", "login".to_string())
            .await
            .unwrap();

        // Change only the master password.
        provider
            .change_password(
                Zeroizing::new("master-pw".to_string()),
                Zeroizing::new("rotated-master".to_string()),
            )
            .await
            .unwrap();

        // Should still have 2 entries.
        let entries = provider.list_passwords().await.unwrap();
        assert_eq!(entries.len(), 2);

        // Lock and verify both passwords work.
        provider.lock().await.unwrap();
        let result = provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "rotated-master".to_string(),
            )))
            .await;
        assert!(result.is_ok());

        provider.lock().await.unwrap();
        let result = provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "second-pw".to_string(),
            )))
            .await;
        assert!(result.is_ok());

        // Old master should fail.
        provider.lock().await.unwrap();
        let result = provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "master-pw".to_string(),
            )))
            .await;
        assert!(result.is_err());
    }
}
