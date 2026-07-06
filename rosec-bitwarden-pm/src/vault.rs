//! Vault state management — holds decrypted keys and cipher data.
//!
//! Ported from `rosec-bitwarden/src/vault.rs` for the WASM guest.
//! Changes: tracing → extism_pdk logging, anyhow → BitwardenError, crate::api → guest api types.

use std::collections::HashMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::api::{SyncCipher, SyncResponse};
use crate::cipher::{self, CipherString};
use crate::crypto::Keys;
use crate::error::BitwardenError;

/// Decrypted vault item.
///
/// `Clone` is intentionally not derived — cloning secret material creates
/// untracked copies that may outlive the vault and escape zeroization.
/// Use references (`&DecryptedCipher`) or indices wherever possible.
///
/// `Serialize`/`Deserialize` are used only for the offline cache blob
/// (opaque to the host).  The serialized form lives in encrypted memory
/// or in the host-encrypted cache file — never on disk in plaintext.
#[derive(Serialize, Deserialize)]
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
    /// Human-readable organisation name, resolved from the sync profile.
    pub organization_name: Option<String>,
}

impl std::fmt::Debug for DecryptedCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedCipher")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("cipher_type", &self.cipher_type)
            .field("folder_name", &self.folder_name)
            .field("notes", &self.notes.as_ref().map(|_| "[redacted]"))
            .field("login", &self.login)
            .field("card", &self.card)
            .field("identity", &self.identity)
            .field("ssh_key", &self.ssh_key)
            .field("fields", &self.fields.len())
            .field("creation_date", &self.creation_date)
            .field("revision_date", &self.revision_date)
            .field("organization_id", &self.organization_id)
            .field("organization_name", &self.organization_name)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
            Self::SshKey => "ssh-key",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DecryptedLogin {
    /// Username is PII — zeroized on drop.
    pub username: Option<Zeroizing<String>>,
    pub password: Option<Zeroizing<String>>,
    pub totp: Option<Zeroizing<String>>,
    pub uris: Vec<String>,
    /// FIDO2 credentials (passkeys) attached to this login.
    /// `default` keeps pre-fido2 offline-cache blobs deserialising.
    #[serde(default)]
    pub fido2_credentials: Vec<DecryptedFido2Credential>,
}

impl std::fmt::Debug for DecryptedLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedLogin")
            .field("username", &self.username.as_ref().map(|_| "[redacted]"))
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("totp", &self.totp.as_ref().map(|_| "[redacted]"))
            .field("uris", &self.uris)
            .field("fido2_credentials", &self.fido2_credentials.len())
            .finish()
    }
}

/// A decrypted FIDO2 credential (passkey) from a login cipher.
///
/// `key_value` holds the private key as Bitwarden stores it: base64url
/// (unpadded) PKCS#8 DER. It is zeroized on drop and only leaves the guest
/// through `get_fido2_key`, PEM-wrapped.
#[derive(Serialize, Deserialize)]
pub struct DecryptedFido2Credential {
    /// Bitwarden-native credential ID: a GUID string.
    pub credential_id: Option<String>,
    pub key_algorithm: Option<String>,
    pub key_curve: Option<String>,
    pub key_value: Option<Zeroizing<String>>,
    pub rp_id: Option<String>,
    pub rp_name: Option<String>,
    /// Base64url user handle, as stored.
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub counter: u32,
    pub discoverable: bool,
}

impl std::fmt::Debug for DecryptedFido2Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedFido2Credential")
            .field("credential_id", &self.credential_id)
            .field("rp_id", &self.rp_id)
            .field("key_value", &self.key_value.as_ref().map(|_| "[redacted]"))
            .field("counter", &self.counter)
            .field("discoverable", &self.discoverable)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct DecryptedCard {
    /// Cardholder name is PII — zeroized on drop.
    pub cardholder_name: Option<Zeroizing<String>>,
    pub number: Option<Zeroizing<String>>,
    pub brand: Option<String>,
    /// Expiry month is card metadata — zeroized on drop.
    pub exp_month: Option<Zeroizing<String>>,
    /// Expiry year is card metadata — zeroized on drop.
    pub exp_year: Option<Zeroizing<String>>,
    pub code: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for DecryptedCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedCard")
            .field(
                "cardholder_name",
                &self.cardholder_name.as_ref().map(|_| "[redacted]"),
            )
            .field("number", &self.number.as_ref().map(|_| "[redacted]"))
            .field("brand", &self.brand)
            .field("exp_month", &self.exp_month.as_ref().map(|_| "[redacted]"))
            .field("exp_year", &self.exp_year.as_ref().map(|_| "[redacted]"))
            .field("code", &self.code.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct DecryptedSshKey {
    pub private_key: Option<Zeroizing<String>>,
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
}

impl std::fmt::Debug for DecryptedSshKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedSshKey")
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "[redacted]"),
            )
            .field("public_key", &self.public_key)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct DecryptedIdentity {
    /// All identity fields are PII — zeroized on drop.
    pub title: Option<Zeroizing<String>>,
    pub first_name: Option<Zeroizing<String>>,
    pub middle_name: Option<Zeroizing<String>>,
    pub last_name: Option<Zeroizing<String>>,
    pub username: Option<Zeroizing<String>>,
    pub company: Option<Zeroizing<String>>,
    pub ssn: Option<Zeroizing<String>>,
    pub passport_number: Option<Zeroizing<String>>,
    pub license_number: Option<Zeroizing<String>>,
    pub email: Option<Zeroizing<String>>,
    pub phone: Option<Zeroizing<String>>,
    pub address1: Option<Zeroizing<String>>,
    pub address2: Option<Zeroizing<String>>,
    pub address3: Option<Zeroizing<String>>,
    pub city: Option<Zeroizing<String>>,
    pub state: Option<Zeroizing<String>>,
    pub postal_code: Option<Zeroizing<String>>,
    pub country: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for DecryptedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Helper: redact if Some, show None otherwise.
        fn r(opt: &Option<Zeroizing<String>>) -> &str {
            if opt.is_some() {
                "[redacted]"
            } else {
                "<none>"
            }
        }
        f.debug_struct("DecryptedIdentity")
            .field("title", &r(&self.title))
            .field("first_name", &r(&self.first_name))
            .field("middle_name", &r(&self.middle_name))
            .field("last_name", &r(&self.last_name))
            .field("username", &r(&self.username))
            .field("company", &r(&self.company))
            .field("ssn", &r(&self.ssn))
            .field("passport_number", &r(&self.passport_number))
            .field("license_number", &r(&self.license_number))
            .field("email", &r(&self.email))
            .field("phone", &r(&self.phone))
            .field("address1", &r(&self.address1))
            .field("address2", &r(&self.address2))
            .field("address3", &r(&self.address3))
            .field("city", &r(&self.city))
            .field("state", &r(&self.state))
            .field("postal_code", &r(&self.postal_code))
            .field("country", &r(&self.country))
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct DecryptedField {
    pub name: Option<String>,
    /// Value is wrapped in `Zeroizing` because hidden fields (type 1) contain secrets.
    pub value: Option<Zeroizing<String>>,
    pub field_type: u8, // 0=Text, 1=Hidden, 2=Boolean, 3=Linked
}

impl std::fmt::Debug for DecryptedField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedField")
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "[redacted]"))
            .field("field_type", &self.field_type)
            .finish()
    }
}

/// Holds the unlocked vault state: keys + decrypted ciphers.
#[derive(Serialize, Deserialize)]
pub struct VaultState {
    /// The master vault keys (enc_key + mac_key).
    vault_keys: Keys,
    /// RSA private key in DER format (for org key decryption).
    private_key: Option<Zeroizing<Vec<u8>>>,
    /// Organization encryption keys, keyed by org ID.
    org_keys: HashMap<String, Keys>,
    /// Organisation display names, keyed by org ID.
    org_names: HashMap<String, String>,
    /// Decrypted folder names, keyed by folder ID.
    folder_names: HashMap<String, String>,
    /// All decrypted ciphers.
    ciphers: Vec<DecryptedCipher>,
    /// Timestamp of last sync.  Runtime-only — not included in the cache
    /// blob so that the blob hash stays stable when vault contents haven't
    /// changed (the host tracks `last_sync_time` independently).
    #[serde(skip)]
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
            org_names: HashMap::new(),
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
            extism_pdk::debug!("decrypted private key");
        }

        // Decrypt organization keys and collect org names.
        self.org_keys.clear();
        self.org_names.clear();
        for org in &sync.profile.organizations {
            if let Some(name) = &org.name {
                self.org_names.insert(org.id.clone(), name.clone());
            }
            let Some(key_str) = &org.key else {
                extism_pdk::debug!("org_id={}: org has no key field; skipping", org.id);
                continue;
            };
            let Some(pk) = &self.private_key else {
                extism_pdk::warn!(
                    "org_id={}: cannot decrypt org key: private key was not available",
                    org.id
                );
                continue;
            };
            match CipherString::parse(key_str) {
                Ok(cs) => match cs.decrypt_asymmetric(pk) {
                    Ok(org_key_bytes) => match Keys::from_bytes(&org_key_bytes) {
                        Ok(keys) => {
                            extism_pdk::debug!("org_id={}: decrypted org key", org.id);
                            self.org_keys.insert(org.id.clone(), keys);
                        }
                        Err(e) => {
                            extism_pdk::warn!("org_id={}: invalid org key length: {e}", org.id);
                        }
                    },
                    Err(e) => {
                        extism_pdk::warn!("org_id={}: failed to decrypt org key: {e}", org.id);
                    }
                },
                Err(e) => {
                    extism_pdk::warn!("org_id={}: failed to parse org key cipher: {e}", org.id);
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
                        extism_pdk::warn!(
                            "folder_id={}: failed to decrypt folder name: {e}",
                            folder.id
                        );
                    }
                },
                Err(e) => {
                    extism_pdk::warn!(
                        "folder_id={}: failed to parse folder name cipher: {e}",
                        folder.id
                    );
                }
            }
        }
        extism_pdk::debug!("decrypted folders: {}", self.folder_names.len());

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
                    // org key unavailable is expected (e.g. org key decryption
                    // failed); log at debug so it doesn't pollute normal output.
                    extism_pdk::debug!("cipher_id={id}: skipped cipher: {e}");
                    skip_count += 1;
                }
            }
        }
        extism_pdk::debug!("processed ciphers: decrypted={success_count}, skipped={skip_count}");

        self.last_sync = Some(SystemTime::now());
        Ok(())
    }

    /// Decrypt a single cipher from the sync response.
    fn decrypt_cipher(&self, sc: &SyncCipher) -> Result<DecryptedCipher, BitwardenError> {
        let id = sc
            .id
            .as_deref()
            .ok_or_else(|| BitwardenError::Api("cipher missing id".to_string()))?
            .to_string();

        let cipher_type = CipherType::from_u8(sc.cipher_type.unwrap_or(0));

        extism_pdk::trace!(
            "decrypting cipher: cipher_id={id}, raw_type={}, has_ssh_key={}, cipher_type={}",
            sc.cipher_type.unwrap_or(0),
            sc.ssh_key.is_some(),
            cipher_type.as_str()
        );

        // Select the right keys: org keys for org ciphers, vault keys otherwise.
        let base_keys = match &sc.organization_id {
            Some(org_id) => self.org_keys.get(org_id).ok_or_else(|| {
                BitwardenError::Api(format!("org key unavailable for org {org_id}"))
            })?,
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

        // Resolve organisation name
        let organization_name = sc
            .organization_id
            .as_ref()
            .and_then(|oid| self.org_names.get(oid))
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
                .filter_map(|f| match self.decrypt_field(f, keys) {
                    Ok(field) => Some(field),
                    Err(e) => {
                        extism_pdk::warn!(
                            "cipher_id={id}: failed to decrypt custom field, skipping: {e}"
                        );
                        None
                    }
                })
                .collect(),
            None => Vec::new(),
        };

        if !fields.is_empty() {
            let field_names: Vec<&str> = fields
                .iter()
                .map(|f| f.name.as_deref().unwrap_or("<none>"))
                .collect();
            extism_pdk::trace!(
                "cipher_id={id}: decrypted custom fields: field_count={}, field_names={field_names:?}",
                fields.len()
            );
        }

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
            organization_name,
        })
    }

    fn decrypt_login(
        &self,
        login: &crate::api::SyncLogin,
        keys: &Keys,
    ) -> Result<DecryptedLogin, BitwardenError> {
        // Username is PII — use sensitive variant so it's zeroized on drop
        let username = cipher::decrypt_field_sensitive(&login.username, keys, None)?;
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

        let mut fido2_credentials = Vec::new();
        if let Some(creds) = &login.fido2_credentials {
            for c in creds {
                fido2_credentials.push(DecryptedFido2Credential {
                    credential_id: cipher::decrypt_field(&c.credential_id, keys, None)?,
                    key_algorithm: cipher::decrypt_field(&c.key_algorithm, keys, None)?,
                    key_curve: cipher::decrypt_field(&c.key_curve, keys, None)?,
                    key_value: cipher::decrypt_field_sensitive(&c.key_value, keys, None)?,
                    rp_id: cipher::decrypt_field(&c.rp_id, keys, None)?,
                    rp_name: cipher::decrypt_field(&c.rp_name, keys, None)?,
                    user_handle: cipher::decrypt_field(&c.user_handle, keys, None)?,
                    user_name: cipher::decrypt_field(&c.user_name, keys, None)?,
                    user_display_name: cipher::decrypt_field(&c.user_display_name, keys, None)?,
                    counter: cipher::decrypt_field(&c.counter, keys, None)?
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0),
                    discoverable: cipher::decrypt_field(&c.discoverable, keys, None)?
                        .is_some_and(|s| s == "true"),
                });
            }
        }

        Ok(DecryptedLogin {
            username,
            password,
            totp,
            uris,
            fido2_credentials,
        })
    }

    fn decrypt_card(
        &self,
        card: &crate::api::SyncCard,
        keys: &Keys,
    ) -> Result<DecryptedCard, BitwardenError> {
        Ok(DecryptedCard {
            // Cardholder name, expiry month/year are PII — use sensitive variant
            cardholder_name: cipher::decrypt_field_sensitive(&card.cardholder_name, keys, None)?,
            number: cipher::decrypt_field_sensitive(&card.number, keys, None)?,
            brand: cipher::decrypt_field(&card.brand, keys, None)?,
            exp_month: cipher::decrypt_field_sensitive(&card.exp_month, keys, None)?,
            exp_year: cipher::decrypt_field_sensitive(&card.exp_year, keys, None)?,
            code: cipher::decrypt_field_sensitive(&card.code, keys, None)?,
        })
    }

    fn decrypt_identity(
        &self,
        ident: &crate::api::SyncIdentity,
        keys: &Keys,
    ) -> Result<DecryptedIdentity, BitwardenError> {
        // All identity fields are PII — use sensitive variant so they're zeroized on drop
        Ok(DecryptedIdentity {
            title: cipher::decrypt_field_sensitive(&ident.title, keys, None)?,
            first_name: cipher::decrypt_field_sensitive(&ident.first_name, keys, None)?,
            middle_name: cipher::decrypt_field_sensitive(&ident.middle_name, keys, None)?,
            last_name: cipher::decrypt_field_sensitive(&ident.last_name, keys, None)?,
            username: cipher::decrypt_field_sensitive(&ident.username, keys, None)?,
            company: cipher::decrypt_field_sensitive(&ident.company, keys, None)?,
            ssn: cipher::decrypt_field_sensitive(&ident.ssn, keys, None)?,
            passport_number: cipher::decrypt_field_sensitive(&ident.passport_number, keys, None)?,
            license_number: cipher::decrypt_field_sensitive(&ident.license_number, keys, None)?,
            email: cipher::decrypt_field_sensitive(&ident.email, keys, None)?,
            phone: cipher::decrypt_field_sensitive(&ident.phone, keys, None)?,
            address1: cipher::decrypt_field_sensitive(&ident.address1, keys, None)?,
            address2: cipher::decrypt_field_sensitive(&ident.address2, keys, None)?,
            address3: cipher::decrypt_field_sensitive(&ident.address3, keys, None)?,
            city: cipher::decrypt_field_sensitive(&ident.city, keys, None)?,
            state: cipher::decrypt_field_sensitive(&ident.state, keys, None)?,
            postal_code: cipher::decrypt_field_sensitive(&ident.postal_code, keys, None)?,
            country: cipher::decrypt_field_sensitive(&ident.country, keys, None)?,
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
    #[allow(dead_code)]
    pub fn vault_keys(&self) -> &Keys {
        &self.vault_keys
    }

    /// Get organization keys by org ID.
    #[allow(dead_code)]
    pub fn org_keys(&self, org_id: &str) -> Option<&Keys> {
        self.org_keys.get(org_id)
    }

    /// Deserialize a vault state from a JSON cache blob.
    pub fn from_cache_blob(blob: &[u8]) -> Result<Self, BitwardenError> {
        serde_json::from_slice(blob).map_err(|e| {
            BitwardenError::Crypto(format!("failed to deserialize vault state from cache: {e}"))
        })
    }
}

// ─── Cache blob envelope ────────────────────────────────────────

/// Versioned envelope for the offline cache (deserialization target).
///
/// ## Versions
///
/// - **v1** (implicit): bare `VaultState` JSON — no session tokens.
///   The provider restores in read-only offline mode; a full re-unlock is
///   required when connectivity returns.
/// - **v2**: `CacheBlob` with `vault` + optional session metadata
///   (`refresh_token`, `protected_key`).  When connectivity returns, the
///   guest can refresh the access token and sync automatically.
///
/// ## Refresh token persistence
///
/// The `refresh_token` and `protected_key` are included so that when
/// connectivity returns after an offline unlock, the guest can refresh
/// the access token and sync without requiring a full re-unlock.  If the
/// refresh token has since expired or been revoked, the sync will fail
/// with `AuthFailed` and the host will lock the provider — triggering a
/// normal re-unlock prompt, exactly as if it were a fresh unlock.
///
/// ## Security considerations
///
/// - The refresh token is less sensitive than the vault keys and decrypted
///   passwords already present in the blob — all of which are encrypted by
///   the host's AES-256-CBC + HMAC-SHA256 layer derived from
///   `HKDF(machine_key || password)`.
/// - **The cache blob (and therefore the refresh token) is only ever
///   written to disk when two conditions are met:**
///   1. The provider declares `Capability::OfflineCache` (guest-side
///      feature toggle).
///   2. The host's per-provider `offline_cache` config is `true`
///      (default).
///
///   The host's `try_export_cache()` and `unlock_from_cache()` are both
///   gated on this combined check.  Users who wish to avoid any offline
///   token storage can set `offline_cache = false` in the provider's
///   config section.
#[derive(Deserialize)]
pub struct CacheBlob {
    /// Blob format version — allows future schema evolution.
    /// Currently unused after deserialization (v1 vs v2 is distinguished
    /// by whether the envelope parses at all), but reserved for future
    /// version-gated migration logic.
    #[serde(default = "default_cache_version", rename = "version")]
    pub _version: u32,
    /// The full decrypted vault state.
    pub vault: VaultState,
    /// Refresh token from the last successful authentication.
    /// `None` for v1 blobs or if no refresh token was available.
    #[serde(default)]
    pub refresh_token: Option<Zeroizing<String>>,
    /// Protected symmetric key from the login response.
    /// Needed alongside `refresh_token` to reconstruct vault keys after
    /// a refresh-based re-authentication.
    #[serde(default)]
    pub protected_key: Option<Zeroizing<String>>,
}

fn default_cache_version() -> u32 {
    1
}

impl CacheBlob {
    /// Deserialize from JSON bytes.
    ///
    /// Handles both v2 `CacheBlob` and legacy v1 bare `VaultState` blobs
    /// transparently — if `CacheBlob` deserialization fails, falls back to
    /// parsing as a bare `VaultState` with no session tokens.
    pub fn from_bytes(blob: &[u8]) -> Result<Self, BitwardenError> {
        // Try v2 envelope first.
        if let Ok(cb) = serde_json::from_slice::<CacheBlob>(blob) {
            return Ok(cb);
        }
        // Fall back to bare VaultState (v1).
        let vault = VaultState::from_cache_blob(blob)?;
        Ok(CacheBlob {
            _version: 1,
            vault,
            refresh_token: None,
            protected_key: None,
        })
    }
}

/// Borrowing version of [`CacheBlob`] for serialization without cloning
/// `VaultState` (which intentionally does not implement `Clone` to prevent
/// untracked copies of secret material).
///
/// See [`CacheBlob`] for the full versioning scheme, security
/// considerations, and the guarantee that tokens are never persisted
/// unless the provider declares `Capability::OfflineCache` *and* the
/// host's `offline_cache` config is enabled.
#[derive(Serialize)]
pub struct CacheBlobRef<'a> {
    pub version: u32,
    pub vault: &'a VaultState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<&'a Zeroizing<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_key: Option<&'a Zeroizing<String>>,
}

impl<'a> CacheBlobRef<'a> {
    /// Current cache blob version.
    pub const VERSION: u32 = 2;

    /// Serialize to JSON bytes for the host to encrypt and persist.
    pub fn to_bytes(&self) -> Result<Vec<u8>, BitwardenError> {
        serde_json::to_vec(self)
            .map_err(|e| BitwardenError::Crypto(format!("failed to serialize cache blob: {e}")))
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
