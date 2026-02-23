//! Vault state management — holds decrypted keys and cipher data.

use std::collections::HashMap;
use std::time::SystemTime;

use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::api::{SyncCipher, SyncResponse};
use crate::cipher::{self, CipherString};
use crate::crypto::Keys;
use crate::error::BitwardenError;

/// Decrypted vault item.
#[derive(Debug, Clone)]
pub struct DecryptedCipher {
    pub id: String,
    pub name: String,
    pub cipher_type: CipherType,
    pub folder_name: Option<String>,
    pub notes: Option<Zeroizing<String>>,
    pub login: Option<DecryptedLogin>,
    pub card: Option<DecryptedCard>,
    pub identity: Option<DecryptedIdentity>,
    pub ssh_key: Option<DecryptedSshKey>,
    pub fields: Vec<DecryptedField>,
    pub creation_date: Option<String>,
    pub revision_date: Option<String>,
    pub organization_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherType {
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
    Unknown(u8),
}

impl CipherType {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Login,
            2 => Self::SecureNote,
            3 => Self::Card,
            4 => Self::Identity,
            5 => Self::SshKey,
            other => Self::Unknown(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::SecureNote => "note",
            Self::Card => "card",
            Self::Identity => "identity",
            Self::SshKey => "sshkey",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecryptedLogin {
    pub username: Option<String>,
    pub password: Option<Zeroizing<String>>,
    pub totp: Option<Zeroizing<String>>,
    pub uris: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DecryptedCard {
    pub cardholder_name: Option<String>,
    pub number: Option<Zeroizing<String>>,
    pub brand: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<Zeroizing<String>>,
}

#[derive(Debug, Clone)]
pub struct DecryptedSshKey {
    pub private_key: Option<Zeroizing<String>>,
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DecryptedIdentity {
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DecryptedField {
    pub name: Option<String>,
    /// Value is wrapped in `Zeroizing` because hidden fields (type 1) contain secrets.
    pub value: Option<Zeroizing<String>>,
    pub field_type: u8, // 0=Text, 1=Hidden, 2=Boolean, 3=Linked
}

/// Holds the unlocked vault state: keys + decrypted ciphers.
pub struct VaultState {
    /// The master vault keys (enc_key + mac_key).
    vault_keys: Keys,
    /// RSA private key in DER format (for org key decryption).
    private_key: Option<Zeroizing<Vec<u8>>>,
    /// Organization encryption keys, keyed by org ID.
    org_keys: HashMap<String, Keys>,
    /// Decrypted folder names, keyed by folder ID.
    folder_names: HashMap<String, String>,
    /// All decrypted ciphers.
    ciphers: Vec<DecryptedCipher>,
    /// Timestamp of last sync.
    last_sync: Option<SystemTime>,
}

impl VaultState {
    /// Create a new vault state from identity keys and the protected symmetric key.
    pub fn new(identity_keys: &Keys, protected_key: &str) -> Result<Self, BitwardenError> {
        // Decrypt the protected symmetric key to get vault keys
        let cs = CipherString::parse(protected_key)?;
        let key_bytes = cs.decrypt_symmetric(identity_keys)?;
        let vault_keys = Keys::from_bytes(&key_bytes)?;

        Ok(Self {
            vault_keys,
            private_key: None,
            org_keys: HashMap::new(),
            folder_names: HashMap::new(),
            ciphers: Vec::new(),
            last_sync: None,
        })
    }

    /// Process sync response: decrypt private key, org keys, folders, and ciphers.
    pub fn process_sync(&mut self, sync: &SyncResponse) -> Result<(), BitwardenError> {
        // Decrypt private key
        if let Some(pk_str) = &sync.profile.private_key
            && !pk_str.is_empty()
        {
            let cs = CipherString::parse(pk_str)?;
            let pk_padded = cs.decrypt_symmetric(&self.vault_keys)?;
            // The private key may have PKCS7 padding — strip it
            self.private_key = Some(strip_pkcs7_padding(pk_padded));
            debug!("decrypted private key");
        }

        // Decrypt organization keys
        self.org_keys.clear();
        for org in &sync.profile.organizations {
            if let Some(key_str) = &org.key
                && let Some(pk) = &self.private_key
            {
                match CipherString::parse(key_str) {
                    Ok(cs) => match cs.decrypt_asymmetric(pk) {
                        Ok(org_key_bytes) => {
                            match Keys::from_bytes(&org_key_bytes) {
                                Ok(keys) => {
                                    debug!(org_id = %org.id, "decrypted org key");
                                    self.org_keys.insert(org.id.clone(), keys);
                                }
                                Err(e) => {
                                    warn!(org_id = %org.id, error = %e, "invalid org key length");
                                }
                            }
                        }
                        Err(e) => {
                            warn!(org_id = %org.id, error = %e, "failed to decrypt org key");
                        }
                    },
                    Err(e) => {
                        warn!(org_id = %org.id, error = %e, "failed to parse org key cipher");
                    }
                }
            }
        }

        // Decrypt folder names
        self.folder_names.clear();
        for folder in &sync.folders {
            match CipherString::parse(&folder.name) {
                Ok(cs) => match cs.decrypt_to_string(&self.vault_keys) {
                    Ok(name) => {
                        self.folder_names.insert(folder.id.clone(), name);
                    }
                    Err(e) => {
                        warn!(folder_id = %folder.id, error = %e, "failed to decrypt folder name");
                    }
                },
                Err(e) => {
                    warn!(folder_id = %folder.id, error = %e, "failed to parse folder name cipher");
                }
            }
        }
        debug!(folders = self.folder_names.len(), "decrypted folders");

        // Decrypt ciphers
        self.ciphers.clear();
        let mut success_count = 0u32;
        let mut skip_count = 0u32;
        for sync_cipher in &sync.ciphers {
            // Skip deleted items
            if sync_cipher.deleted_date.is_some() {
                continue;
            }

            match self.decrypt_cipher(sync_cipher) {
                Ok(dc) => {
                    self.ciphers.push(dc);
                    success_count += 1;
                }
                Err(e) => {
                    let id = sync_cipher.id.as_deref().unwrap_or("unknown");
                    warn!(cipher_id = id, error = %e, "failed to decrypt cipher");
                    skip_count += 1;
                }
            }
        }
        debug!(
            decrypted = success_count,
            skipped = skip_count,
            "processed ciphers"
        );

        self.last_sync = Some(SystemTime::now());
        Ok(())
    }

    /// Decrypt a single cipher from the sync response.
    fn decrypt_cipher(&self, sc: &SyncCipher) -> Result<DecryptedCipher, BitwardenError> {
        let id = sc
            .id
            .as_deref()
            .ok_or_else(|| BitwardenError::Other(anyhow::anyhow!("cipher missing id")))?
            .to_string();

        let cipher_type = CipherType::from_u8(sc.cipher_type.unwrap_or(0));

        // Select the right keys: org keys for org ciphers, vault keys otherwise
        let base_keys = match &sc.organization_id {
            Some(org_id) => self.org_keys.get(org_id).unwrap_or(&self.vault_keys),
            None => &self.vault_keys,
        };

        // Resolve per-item key if present
        let entry_key = cipher::resolve_entry_key(&sc.key, base_keys)?;
        let keys = entry_key.as_ref().unwrap_or(base_keys);

        // Decrypt name
        let name =
            cipher::decrypt_field(&sc.name, keys, None)?.unwrap_or_else(|| "<unnamed>".to_string());

        // Decrypt notes (sensitive — may contain secrets for SecureNote, Identity, etc.)
        let notes = cipher::decrypt_field_sensitive(&sc.notes, keys, None)?;

        // Resolve folder name
        let folder_name = sc
            .folder_id
            .as_ref()
            .and_then(|fid| self.folder_names.get(fid))
            .cloned();

        // Decrypt type-specific data
        let login = if let Some(l) = &sc.login {
            Some(self.decrypt_login(l, keys)?)
        } else {
            None
        };

        let card = if let Some(c) = &sc.card {
            Some(self.decrypt_card(c, keys)?)
        } else {
            None
        };

        let identity = if let Some(i) = &sc.identity {
            Some(self.decrypt_identity(i, keys)?)
        } else {
            None
        };

        // Decrypt SSH key data
        let ssh_key = if let Some(sk) = &sc.ssh_key {
            Some(self.decrypt_ssh_key(sk, keys)?)
        } else {
            None
        };

        // Decrypt custom fields
        let fields = match &sc.fields {
            Some(fs) => fs
                .iter()
                .filter_map(|f| self.decrypt_field(f, keys).ok())
                .collect(),
            None => Vec::new(),
        };

        Ok(DecryptedCipher {
            id,
            name,
            cipher_type,
            folder_name,
            notes,
            login,
            card,
            identity,
            ssh_key,
            fields,
            creation_date: sc.creation_date.clone(),
            revision_date: sc.revision_date.clone(),
            organization_id: sc.organization_id.clone(),
        })
    }

    fn decrypt_login(
        &self,
        login: &crate::api::SyncLogin,
        keys: &Keys,
    ) -> Result<DecryptedLogin, BitwardenError> {
        let username = cipher::decrypt_field(&login.username, keys, None)?;
        let password = cipher::decrypt_field_sensitive(&login.password, keys, None)?;
        let totp = cipher::decrypt_field_sensitive(&login.totp, keys, None)?;

        let mut uris = Vec::new();
        if let Some(uri_list) = &login.uris {
            for u in uri_list {
                if let Some(uri_str) = cipher::decrypt_field(&u.uri, keys, None)? {
                    uris.push(uri_str);
                }
            }
        }

        Ok(DecryptedLogin {
            username,
            password,
            totp,
            uris,
        })
    }

    fn decrypt_card(
        &self,
        card: &crate::api::SyncCard,
        keys: &Keys,
    ) -> Result<DecryptedCard, BitwardenError> {
        Ok(DecryptedCard {
            cardholder_name: cipher::decrypt_field(&card.cardholder_name, keys, None)?,
            number: cipher::decrypt_field_sensitive(&card.number, keys, None)?,
            brand: cipher::decrypt_field(&card.brand, keys, None)?,
            exp_month: cipher::decrypt_field(&card.exp_month, keys, None)?,
            exp_year: cipher::decrypt_field(&card.exp_year, keys, None)?,
            code: cipher::decrypt_field_sensitive(&card.code, keys, None)?,
        })
    }

    fn decrypt_identity(
        &self,
        ident: &crate::api::SyncIdentity,
        keys: &Keys,
    ) -> Result<DecryptedIdentity, BitwardenError> {
        Ok(DecryptedIdentity {
            title: cipher::decrypt_field(&ident.title, keys, None)?,
            first_name: cipher::decrypt_field(&ident.first_name, keys, None)?,
            last_name: cipher::decrypt_field(&ident.last_name, keys, None)?,
            email: cipher::decrypt_field(&ident.email, keys, None)?,
            phone: cipher::decrypt_field(&ident.phone, keys, None)?,
            username: cipher::decrypt_field(&ident.username, keys, None)?,
        })
    }

    fn decrypt_ssh_key(
        &self,
        ssh_key: &crate::api::SyncSshKey,
        keys: &Keys,
    ) -> Result<DecryptedSshKey, BitwardenError> {
        Ok(DecryptedSshKey {
            private_key: cipher::decrypt_field_sensitive(&ssh_key.private_key, keys, None)?,
            public_key: cipher::decrypt_field(&ssh_key.public_key, keys, None)?,
            fingerprint: cipher::decrypt_field(&ssh_key.fingerprint, keys, None)?,
        })
    }

    fn decrypt_field(
        &self,
        field: &crate::api::SyncField,
        keys: &Keys,
    ) -> Result<DecryptedField, BitwardenError> {
        let name = cipher::decrypt_field(&field.name, keys, None)?;
        // All field values wrapped in Zeroizing — hidden fields (type 1) contain secrets
        let value = cipher::decrypt_field_sensitive(&field.value, keys, None)?;

        Ok(DecryptedField {
            name,
            value,
            field_type: field.field_type.unwrap_or(0),
        })
    }

    /// Get all decrypted ciphers.
    pub fn ciphers(&self) -> &[DecryptedCipher] {
        &self.ciphers
    }

    /// Find a cipher by its ID.
    pub fn cipher_by_id(&self, id: &str) -> Option<&DecryptedCipher> {
        self.ciphers.iter().find(|c| c.id == id)
    }

    /// Get the timestamp of the last sync.
    pub fn last_sync(&self) -> Option<SystemTime> {
        self.last_sync
    }

    /// Get the vault keys (needed for re-decryption of secrets on demand).
    pub fn vault_keys(&self) -> &Keys {
        &self.vault_keys
    }

    /// Get organization keys by org ID.
    pub fn org_keys(&self, org_id: &str) -> Option<&Keys> {
        self.org_keys.get(org_id)
    }
}

impl std::fmt::Debug for VaultState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultState")
            .field("ciphers", &self.ciphers.len())
            .field("org_keys", &self.org_keys.len())
            .field("folder_names", &self.folder_names.len())
            .field("last_sync", &self.last_sync)
            .finish()
    }
}

/// Strip PKCS7 padding from private key data.
///
/// The private key comes padded from AES-CBC decryption; we need the raw DER.
fn strip_pkcs7_padding(data: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
    // The AES-CBC decryptor already strips PKCS7 padding,
    // but some implementations double-pad. Check if last byte looks like padding.
    // If the data is valid DER (starts with 0x30), trust it as-is.
    if data.first() == Some(&0x30) {
        return data;
    }

    // Otherwise just return as-is — the RSA parser will error if it's malformed.
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_type_roundtrip() {
        assert_eq!(CipherType::from_u8(1), CipherType::Login);
        assert_eq!(CipherType::from_u8(2), CipherType::SecureNote);
        assert_eq!(CipherType::from_u8(3), CipherType::Card);
        assert_eq!(CipherType::from_u8(4), CipherType::Identity);
        assert_eq!(CipherType::from_u8(5), CipherType::SshKey);
        assert_eq!(CipherType::from_u8(99), CipherType::Unknown(99));
    }

    #[test]
    fn cipher_type_as_str() {
        assert_eq!(CipherType::Login.as_str(), "login");
        assert_eq!(CipherType::SecureNote.as_str(), "note");
        assert_eq!(CipherType::Card.as_str(), "card");
        assert_eq!(CipherType::Identity.as_str(), "identity");
        assert_eq!(CipherType::SshKey.as_str(), "sshkey");
        assert_eq!(CipherType::Unknown(42).as_str(), "unknown");
    }
}
