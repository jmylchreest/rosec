use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::prelude::{BASE64_STANDARD, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::types::{KdfParams, WrappingEntry};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const MAC_KEY_LEN: usize = 32;

/// Errors from cryptographic operations within the vault.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid base64 in KDF salt: {0}")]
    InvalidSalt(#[from] base64::DecodeError),
    #[error("HKDF expand failed: {0}")]
    HkdfExpand(hkdf::InvalidLength),
    #[error("HMAC key setup failed")]
    HmacKey,
    #[error("decryption failed")]
    Decryption,
}

/// Derive a 32-byte key from a password using PBKDF2-SHA256.
///
/// Returns `CryptoError::InvalidSalt` if the KDF salt is not valid base64.
pub fn derive_key(
    password: &[u8],
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let salt = BASE64_STANDARD.decode(&kdf.salt)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2_hmac::<Sha256>(password, &salt, kdf.iterations, &mut *key);
    Ok(key)
}

/// Derive a MAC key from an encryption key using HKDF-SHA256.
///
/// Uses a domain-specific salt for strong domain separation between the
/// encryption key and the MAC key.
pub fn derive_mac_key(encryption_key: &[u8]) -> Result<Zeroizing<[u8; MAC_KEY_LEN]>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"rosec-vault-mac-v1"), encryption_key);
    let mut mac_key = Zeroizing::new([0u8; MAC_KEY_LEN]);
    hkdf.expand(b"mac key", &mut *mac_key)
        .map_err(CryptoError::HkdfExpand)?;
    Ok(mac_key)
}

/// Generate a random 32-byte vault key.
pub fn generate_vault_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rand::rng().fill_bytes(&mut *key);
    key
}

/// Create a wrapping entry that protects the vault key with a password.
///
/// 1. Derives a wrapping key from the password via PBKDF2.
/// 2. Encrypts the vault key with AES-256-CBC using the wrapping key.
/// 3. Computes an HMAC over the wrapped bytes for fast password verification.
pub fn wrap_vault_key(
    vault_key: &[u8; KEY_LEN],
    password: &[u8],
    label: Option<String>,
) -> Result<WrappingEntry, CryptoError> {
    let kdf = KdfParams::new_random();
    let wrapping_key = derive_key(password, &kdf)?;
    let wrapping_mac_key = derive_mac_key(&*wrapping_key)?;

    let wrapped = encrypt(vault_key, &*wrapping_key);
    let hmac = compute_hmac(&*wrapping_mac_key, &wrapped)?;

    Ok(WrappingEntry {
        id: Uuid::new_v4().to_string(),
        label,
        kdf,
        wrapped_vault_key: BASE64_STANDARD.encode(&wrapped),
        wrapped_key_hmac: BASE64_STANDARD.encode(hmac),
    })
}

/// Try to unwrap the vault key from a wrapping entry using a password.
///
/// Returns `Ok(Some(vault_key))` if the password is correct (HMAC verifies),
/// `Ok(None)` if the password is wrong, or `Err` on a crypto setup failure.
pub fn unwrap_vault_key(
    entry: &WrappingEntry,
    password: &[u8],
) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, CryptoError> {
    let wrapping_key = derive_key(password, &entry.kdf)?;
    let wrapping_mac_key = derive_mac_key(&*wrapping_key)?;

    let wrapped_bytes = entry.wrapped_vault_key_bytes();
    let expected_hmac = entry.wrapped_key_hmac_bytes();

    // Fast rejection: check HMAC before attempting decryption.
    if !verify_hmac(&*wrapping_mac_key, &wrapped_bytes, &expected_hmac)? {
        return Ok(None);
    }

    let decrypted = match decrypt(&wrapped_bytes, &*wrapping_key) {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };

    if decrypted.len() != KEY_LEN {
        return Ok(None);
    }

    let mut vault_key = Zeroizing::new([0u8; KEY_LEN]);
    vault_key.copy_from_slice(&decrypted);
    Ok(Some(vault_key))
}

/// Encrypt plaintext with AES-256-CBC. Returns IV || ciphertext.
pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = rand::random::<[u8; IV_LEN]>();
    let cipher = Aes256CbcEnc::new(key.into(), (&iv).into());
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let mut result = Vec::with_capacity(IV_LEN + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend(ciphertext);
    result
}

/// Decrypt AES-256-CBC ciphertext. Input is IV || ciphertext.
///
/// Returns the plaintext wrapped in `Zeroizing` so it is scrubbed on drop.
pub fn decrypt(encrypted: &[u8], key: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if encrypted.len() < IV_LEN {
        return Err("encrypted data too short");
    }

    let (iv, ciphertext) = encrypted.split_at(IV_LEN);
    let cipher = Aes256CbcDec::new(key.into(), iv.into());

    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| "decryption failed")
}

/// Compute HMAC-SHA256 over data.
pub fn compute_hmac(mac_key: &[u8], data: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut mac = HmacSha256::new_from_slice(mac_key).map_err(|_| CryptoError::HmacKey)?;
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    Ok(output)
}

/// Verify HMAC-SHA256 over data (constant-time comparison).
pub fn verify_hmac(mac_key: &[u8], data: &[u8], expected: &[u8]) -> Result<bool, CryptoError> {
    if expected.len() != 32 {
        return Ok(false);
    }

    let mut mac = HmacSha256::new_from_slice(mac_key).map_err(|_| CryptoError::HmacKey)?;
    mac.update(data);
    Ok(mac.verify_slice(expected).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let plaintext = b"hello, world!";
        let encrypted = encrypt(plaintext, &key);
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let key = [0u8; 32];
        let wrong_key = [1u8; 32];
        let plaintext = b"hello, world!";
        let encrypted = encrypt(plaintext, &key);
        assert!(decrypt(&encrypted, &wrong_key).is_err());
    }

    #[test]
    fn hmac_verification_succeeds() {
        let mac_key = [0u8; 32];
        let data = b"test data";
        let hmac = compute_hmac(&mac_key, data).unwrap();
        assert!(verify_hmac(&mac_key, data, &hmac).unwrap());
    }

    #[test]
    fn hmac_verification_fails_with_wrong_key() {
        let mac_key = [0u8; 32];
        let wrong_key = [1u8; 32];
        let data = b"test data";
        let hmac = compute_hmac(&mac_key, data).unwrap();
        assert!(!verify_hmac(&wrong_key, data, &hmac).unwrap());
    }

    #[test]
    fn hmac_verification_fails_with_tampered_data() {
        let mac_key = [0u8; 32];
        let data = b"test data";
        let hmac = compute_hmac(&mac_key, data).unwrap();
        assert!(!verify_hmac(&mac_key, b"tampered", &hmac).unwrap());
    }

    #[test]
    fn derive_key_produces_deterministic_result() {
        let kdf = KdfParams {
            salt: BASE64_STANDARD.encode([0u8; 32]),
            iterations: 1000,
        };
        let password = b"password";
        let key1 = derive_key(password, &kdf).unwrap();
        let key2 = derive_key(password, &kdf).unwrap();
        assert_eq!(*key1, *key2);
    }

    #[test]
    fn derive_key_rejects_invalid_salt() {
        let kdf = KdfParams {
            salt: "not-valid-base64!!!".to_string(),
            iterations: 1000,
        };
        assert!(derive_key(b"password", &kdf).is_err());
    }

    #[test]
    fn derive_mac_key_produces_deterministic_result() {
        let enc_key = [0u8; 32];
        let mac1 = derive_mac_key(&enc_key).unwrap();
        let mac2 = derive_mac_key(&enc_key).unwrap();
        assert_eq!(*mac1, *mac2);
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let vault_key = generate_vault_key();
        let password = b"test-password";

        let entry = wrap_vault_key(&vault_key, password, Some("test".to_string())).unwrap();
        let unwrapped = unwrap_vault_key(&entry, password).unwrap();

        assert!(unwrapped.is_some());
        assert_eq!(*unwrapped.unwrap(), *vault_key);
    }

    #[test]
    fn unwrap_fails_with_wrong_password() {
        let vault_key = generate_vault_key();
        let password = b"correct-password";
        let wrong = b"wrong-password";

        let entry = wrap_vault_key(&vault_key, password, None).unwrap();
        let unwrapped = unwrap_vault_key(&entry, wrong).unwrap();

        assert!(unwrapped.is_none());
    }

    #[test]
    fn multiple_wrapping_entries_same_vault_key() {
        let vault_key = generate_vault_key();
        let pw1 = b"password-one";
        let pw2 = b"password-two";

        let entry1 = wrap_vault_key(&vault_key, pw1, Some("master".to_string())).unwrap();
        let entry2 = wrap_vault_key(&vault_key, pw2, Some("login".to_string())).unwrap();

        let unwrapped1 = unwrap_vault_key(&entry1, pw1).unwrap().unwrap();
        let unwrapped2 = unwrap_vault_key(&entry2, pw2).unwrap().unwrap();

        assert_eq!(*unwrapped1, *vault_key);
        assert_eq!(*unwrapped2, *vault_key);

        // Cross-password should fail
        assert!(unwrap_vault_key(&entry1, pw2).unwrap().is_none());
        assert!(unwrap_vault_key(&entry2, pw1).unwrap().is_none());
    }
}
