use std::collections::HashMap;

use base64::prelude::{BASE64_STANDARD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};

pub const FILE_FORMAT_VERSION: u32 = 1;
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 200_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub salt: String,
    pub iterations: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        let mut salt = [0u8; 32];
        rand::rng().fill_bytes(&mut salt);
        Self {
            salt: BASE64_STANDARD.encode(salt),
            iterations: DEFAULT_PBKDF2_ITERATIONS,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItemData {
    pub id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub secrets: HashMap<String, String>,
    pub created: i64,
    pub modified: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultData {
    pub items: Vec<VaultItemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    pub kdf: KdfParams,
    pub encrypted_data: String,
    pub hmac: String,
}

impl VaultFile {
    pub fn new(kdf: KdfParams, encrypted_data: &[u8], hmac: &[u8]) -> Self {
        Self {
            version: FILE_FORMAT_VERSION,
            kdf,
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
