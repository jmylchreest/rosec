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

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive a 32-byte key from a password using PBKDF2-SHA256.
pub fn derive_key(password: &[u8], kdf: &KdfParams) -> Zeroizing<[u8; KEY_LEN]> {
    let salt = BASE64_STANDARD.decode(&kdf.salt).unwrap_or_default();
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2_hmac::<Sha256>(password, &salt, kdf.iterations, &mut *key);
    key
}

/// Derive a MAC key from an encryption key using HKDF-SHA256.
pub fn derive_mac_key(encryption_key: &[u8]) -> Zeroizing<[u8; MAC_KEY_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(None, encryption_key);
    let mut mac_key = Zeroizing::new([0u8; MAC_KEY_LEN]);
    hkdf.expand(b"mac key", &mut *mac_key)
        .expect("HKDF expand should not fail for 32-byte output");
    mac_key
}

// ---------------------------------------------------------------------------
// Vault key generation
// ---------------------------------------------------------------------------

/// Generate a random 32-byte vault key.
pub fn generate_vault_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rand::rng().fill_bytes(&mut *key);
    key
}

// ---------------------------------------------------------------------------
// Key wrapping (wrap/unwrap the vault key with a password-derived key)
// ---------------------------------------------------------------------------

/// Create a wrapping entry that protects the vault key with a password.
///
/// 1. Derives a wrapping key from the password via PBKDF2.
/// 2. Encrypts the vault key with AES-256-CBC using the wrapping key.
/// 3. Computes an HMAC over the wrapped bytes for fast password verification.
pub fn wrap_vault_key(
    vault_key: &[u8; KEY_LEN],
    password: &[u8],
    label: Option<String>,
) -> WrappingEntry {
    let kdf = KdfParams::new_random();
    let wrapping_key = derive_key(password, &kdf);
    let wrapping_mac_key = derive_mac_key(&*wrapping_key);

    let wrapped = encrypt(vault_key, &*wrapping_key);
    let hmac = compute_hmac(&*wrapping_mac_key, &wrapped);

    WrappingEntry {
        id: Uuid::new_v4().to_string(),
        label,
        kdf,
        wrapped_vault_key: BASE64_STANDARD.encode(&wrapped),
        wrapped_key_hmac: BASE64_STANDARD.encode(hmac),
    }
}

/// Try to unwrap the vault key from a wrapping entry using a password.
///
/// Returns `Some(vault_key)` if the password is correct (HMAC verifies),
/// or `None` if the password is wrong.
pub fn unwrap_vault_key(
    entry: &WrappingEntry,
    password: &[u8],
) -> Option<Zeroizing<[u8; KEY_LEN]>> {
    let wrapping_key = derive_key(password, &entry.kdf);
    let wrapping_mac_key = derive_mac_key(&*wrapping_key);

    let wrapped_bytes = entry.wrapped_vault_key_bytes();
    let expected_hmac = entry.wrapped_key_hmac_bytes();

    // Fast rejection: check HMAC before attempting decryption.
    if !verify_hmac(&*wrapping_mac_key, &wrapped_bytes, &expected_hmac) {
        return None;
    }

    let decrypted = decrypt(&wrapped_bytes, &*wrapping_key).ok()?;

    if decrypted.len() != KEY_LEN {
        return None;
    }

    let mut vault_key = Zeroizing::new([0u8; KEY_LEN]);
    vault_key.copy_from_slice(&decrypted);
    Some(vault_key)
}

// ---------------------------------------------------------------------------
// Data encryption / decryption
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256 over data.
pub fn compute_hmac(mac_key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(mac_key).expect("HMAC key should be valid for any length");
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    output
}

/// Verify HMAC-SHA256 over data (constant-time comparison).
pub fn verify_hmac(mac_key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    if expected.len() != 32 {
        return false;
    }

    let mut mac =
        HmacSha256::new_from_slice(mac_key).expect("HMAC key should be valid for any length");
    mac.update(data);
    mac.verify_slice(expected).is_ok()
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
        let hmac = compute_hmac(&mac_key, data);
        assert!(verify_hmac(&mac_key, data, &hmac));
    }

    #[test]
    fn hmac_verification_fails_with_wrong_key() {
        let mac_key = [0u8; 32];
        let wrong_key = [1u8; 32];
        let data = b"test data";
        let hmac = compute_hmac(&mac_key, data);
        assert!(!verify_hmac(&wrong_key, data, &hmac));
    }

    #[test]
    fn hmac_verification_fails_with_tampered_data() {
        let mac_key = [0u8; 32];
        let data = b"test data";
        let hmac = compute_hmac(&mac_key, data);
        assert!(!verify_hmac(&mac_key, b"tampered", &hmac));
    }

    #[test]
    fn derive_key_produces_deterministic_result() {
        let kdf = KdfParams {
            salt: BASE64_STANDARD.encode([0u8; 32]),
            iterations: 1000,
        };
        let password = b"password";
        let key1 = derive_key(password, &kdf);
        let key2 = derive_key(password, &kdf);
        assert_eq!(*key1, *key2);
    }

    #[test]
    fn derive_mac_key_produces_deterministic_result() {
        let enc_key = [0u8; 32];
        let mac1 = derive_mac_key(&enc_key);
        let mac2 = derive_mac_key(&enc_key);
        assert_eq!(*mac1, *mac2);
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let vault_key = generate_vault_key();
        let password = b"test-password";

        let entry = wrap_vault_key(&*vault_key, password, Some("test".to_string()));
        let unwrapped = unwrap_vault_key(&entry, password);

        assert!(unwrapped.is_some());
        assert_eq!(*unwrapped.unwrap(), *vault_key);
    }

    #[test]
    fn unwrap_fails_with_wrong_password() {
        let vault_key = generate_vault_key();
        let password = b"correct-password";
        let wrong = b"wrong-password";

        let entry = wrap_vault_key(&*vault_key, password, None);
        let unwrapped = unwrap_vault_key(&entry, wrong);

        assert!(unwrapped.is_none());
    }

    #[test]
    fn multiple_wrapping_entries_same_vault_key() {
        let vault_key = generate_vault_key();
        let pw1 = b"password-one";
        let pw2 = b"password-two";

        let entry1 = wrap_vault_key(&*vault_key, pw1, Some("master".to_string()));
        let entry2 = wrap_vault_key(&*vault_key, pw2, Some("login".to_string()));

        let unwrapped1 = unwrap_vault_key(&entry1, pw1).unwrap();
        let unwrapped2 = unwrap_vault_key(&entry2, pw2).unwrap();

        assert_eq!(*unwrapped1, *vault_key);
        assert_eq!(*unwrapped2, *vault_key);

        // Cross-password should fail
        assert!(unwrap_vault_key(&entry1, pw2).is_none());
        assert!(unwrap_vault_key(&entry2, pw1).is_none());
    }
}
