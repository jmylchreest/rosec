use std::collections::HashMap;

use base64::prelude::{BASE64_STANDARD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};

pub const VAULT_FORMAT_VERSION: u32 = 2;
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 200_000;

/// Parameters for PBKDF2 key derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub salt: String,
    pub iterations: u32,
}

impl KdfParams {
    pub fn new_random() -> Self {
        let mut salt = [0u8; 32];
        rand::rng().fill_bytes(&mut salt);
        Self {
            salt: BASE64_STANDARD.encode(salt),
            iterations: DEFAULT_PBKDF2_ITERATIONS,
        }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::new_random()
    }
}

/// A single key-wrapping entry.
///
/// Each entry wraps the same vault key with a different password-derived key.
/// To unlock, the daemon tries each entry: password -> PBKDF2(salt, iterations) ->
/// wrapping key -> AES-unwrap(wrapped_vault_key). If the unwrapped key produces
/// a valid HMAC over the encrypted data, it's the correct vault key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappingEntry {
    /// Unique identifier for this wrapping entry (for add/remove operations).
    pub id: String,
    /// Optional human-readable label (e.g. "master password", "login password").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// KDF parameters (salt + iterations) for this entry's password derivation.
    pub kdf: KdfParams,
    /// The vault key encrypted (wrapped) with the password-derived key.
    /// Format: base64(IV || AES-256-CBC(vault_key)).
    pub wrapped_vault_key: String,
    /// HMAC-SHA256 of the wrapped_vault_key bytes, keyed with a MAC key derived
    /// from the wrapping key. Used to verify correct password before attempting
    /// full vault decryption.
    pub wrapped_key_hmac: String,
}

impl WrappingEntry {
    pub fn wrapped_vault_key_bytes(&self) -> Vec<u8> {
        BASE64_STANDARD
            .decode(&self.wrapped_vault_key)
            .unwrap_or_default()
    }

    pub fn wrapped_key_hmac_bytes(&self) -> Vec<u8> {
        BASE64_STANDARD
            .decode(&self.wrapped_key_hmac)
            .unwrap_or_default()
    }
}

/// Data for a single vault item (decrypted form).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItemData {
    pub id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub secrets: HashMap<String, String>,
    pub created: i64,
    pub modified: i64,
}

/// Container for all vault items (decrypted form).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultData {
    pub items: Vec<VaultItemData>,
}

/// On-disk vault file format (v2 with key wrapping).
///
/// The vault key is a random 32-byte key that encrypts the vault data.
/// Each `WrappingEntry` in `wrapping_entries` wraps this vault key with
/// a different password-derived key, allowing multiple passwords to
/// unlock the same vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    /// One or more key-wrapping entries. Each wraps the same vault key
    /// with a different password.
    pub wrapping_entries: Vec<WrappingEntry>,
    /// The vault data encrypted with the vault key.
    /// Format: base64(IV || AES-256-CBC(json(VaultData))).
    pub encrypted_data: String,
    /// HMAC-SHA256 of the encrypted_data bytes, keyed with a MAC key
    /// derived from the vault key. Used for integrity verification.
    pub hmac: String,
}

impl VaultFile {
    pub fn new(wrapping_entries: Vec<WrappingEntry>, encrypted_data: &[u8], hmac: &[u8]) -> Self {
        Self {
            version: VAULT_FORMAT_VERSION,
            wrapping_entries,
            encrypted_data: BASE64_STANDARD.encode(encrypted_data),
            hmac: BASE64_STANDARD.encode(hmac),
        }
    }

    pub fn encrypted_data_bytes(&self) -> Vec<u8> {
        BASE64_STANDARD
            .decode(&self.encrypted_data)
            .unwrap_or_default()
    }

    pub fn hmac_bytes(&self) -> Vec<u8> {
        BASE64_STANDARD.decode(&self.hmac).unwrap_or_default()
    }
}
