//! Bitwarden OAuth credential storage helpers.
//!
//! Owns only the Bitwarden-specific key derivation (HKDF from master key +
//! email). All symmetric crypto and file I/O is delegated to
//! [`rosec_core::credential`], which is backend-agnostic.
//!
//! # Key derivation
//!
//! ```text
//! storage_key = HKDF-SHA256(
//!     prk  = master_key,          // 32 bytes from PBKDF2/Argon2id
//!     info = "rosec-oauth-v1:<email>",
//!     len  = 64,                  // 32-byte enc + 32-byte MAC
//! )
//! ```
//!
//! The email is baked into the info string so that credentials for different
//! Bitwarden accounts cannot be accidentally cross-decrypted even if they share
//! a data directory.
//!
//! # Security
//!
//! - `master_key` must come from the normal prelogin + PBKDF2/Argon2id flow.
//! - All plaintext is zeroized before this module returns.
//! - No plaintext secret ever touches the filesystem.

use hkdf::Hkdf;
use rosec_core::credential::{self, StorageKey};
use rosec_core::oauth::OAuthCredential;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::BitwardenError;

/// Derive the 64-byte storage key for Bitwarden OAuth credential encryption.
///
/// Incorporates `email` into the HKDF info string to scope keys per-account.
pub fn derive_storage_key(master_key: &[u8], email: &str) -> Result<StorageKey, BitwardenError> {
    let info = format!("rosec-oauth-v1:{}", email.trim().to_lowercase());

    let hkdf = Hkdf::<Sha256>::from_prk(master_key)
        .map_err(|e| BitwardenError::Crypto(format!("oauth hkdf from_prk: {e}")))?;

    let mut key_material = Zeroizing::new(vec![0u8; 64]);
    hkdf.expand(info.as_bytes(), &mut key_material)
        .map_err(|e| BitwardenError::Crypto(format!("oauth hkdf expand: {e}")))?;

    StorageKey::from_bytes(&key_material)
        .map_err(|e| BitwardenError::Crypto(format!("storage key: {e}")))
}

/// Encrypt `client_secret` and persist the credential for `backend_id`.
pub fn encrypt_and_save(
    backend_id: &str,
    master_key: &[u8],
    email: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<(), BitwardenError> {
    let key = derive_storage_key(master_key, email)?;
    credential::encrypt_and_save(backend_id, &key, client_id, client_secret)
        .map_err(|e| BitwardenError::Other(anyhow::anyhow!("{e}")))
}

/// Load and decrypt the OAuth credential for `backend_id`.
///
/// Returns `None` if no credential is stored.
/// Returns an error if the MAC fails (wrong master password or tampered file).
pub fn load_and_decrypt(
    backend_id: &str,
    master_key: &[u8],
    email: &str,
) -> Result<Option<OAuthCredential>, BitwardenError> {
    let key = derive_storage_key(master_key, email)?;
    credential::load_and_decrypt(backend_id, &key).map_err(BitwardenError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify HKDF derivation is deterministic and email/key-scoped.
    /// The full encrypt/decrypt/save/load cycle is tested in rosec-core::credential.

    #[test]
    fn storage_key_is_deterministic() {
        let master_key = [0xABu8; 32];
        let k1 = derive_storage_key(&master_key, "test@example.com").unwrap();
        let k2 = derive_storage_key(&master_key, "test@example.com").unwrap();
        // Compare via round-trip through credential::encrypt — if keys are equal,
        // the same plaintext will decrypt correctly across both.
        let fields = rosec_core::credential::encrypt(&k1, b"probe").unwrap();
        rosec_core::credential::decrypt(&k2, &fields)
            .expect("keys derived from same inputs should be equal");
    }

    #[test]
    fn storage_key_differs_by_email() {
        let master_key = [0xABu8; 32];
        let k1 = derive_storage_key(&master_key, "alice@example.com").unwrap();
        let k2 = derive_storage_key(&master_key, "bob@example.com").unwrap();
        let fields = rosec_core::credential::encrypt(&k1, b"probe").unwrap();
        assert!(
            rosec_core::credential::decrypt(&k2, &fields).is_err(),
            "different emails must produce different keys"
        );
    }

    #[test]
    fn storage_key_differs_by_master_key() {
        let k1 = derive_storage_key(&[0xAAu8; 32], "test@example.com").unwrap();
        let k2 = derive_storage_key(&[0xBBu8; 32], "test@example.com").unwrap();
        let fields = rosec_core::credential::encrypt(&k1, b"probe").unwrap();
        assert!(
            rosec_core::credential::decrypt(&k2, &fields).is_err(),
            "different master keys must produce different storage keys"
        );
    }

    #[test]
    fn email_is_normalised() {
        // Uppercase and trailing whitespace should not change the derived key.
        let master_key = [0x42u8; 32];
        let k1 = derive_storage_key(&master_key, "User@Example.COM").unwrap();
        let k2 = derive_storage_key(&master_key, "user@example.com").unwrap();
        let fields = rosec_core::credential::encrypt(&k1, b"probe").unwrap();
        rosec_core::credential::decrypt(&k2, &fields)
            .expect("email normalisation should produce identical keys");
    }
}
