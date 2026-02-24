//! Generic encrypted credential storage.
//!
//! Provides AES-256-CBC + HMAC-SHA256 encrypt/decrypt for any credential that
//! needs to be stored at rest, protected by a caller-supplied key.
//!
//! # Responsibilities
//!
//! This module owns:
//! - Symmetric encryption / decryption (AES-256-CBC + HMAC-SHA256)
//! - Base64 encoding of the encrypted blob
//! - File I/O via [`rosec_core::oauth`] (write-then-rename, mode 0600)
//!
//! It does **not** own:
//! - Key derivation — callers (e.g. `rosec-bitwarden::oauth_cred`) supply a
//!   64-byte key derived via HKDF or similar from their own master secret.
//! - The semantic meaning of `client_id` / `client_secret` — those are opaque
//!   strings from this module's perspective.
//!
//! # Security
//!
//! - The IV is generated fresh on every `encrypt` call.
//! - The MAC covers both IV and ciphertext (encrypt-then-MAC).
//! - Plaintext is held in `Zeroizing<Vec<u8>>` and scrubbed before return.
//! - No plaintext secret ever touches the filesystem.

use aes::Aes256;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::oauth::{self, EncryptedFields, OAuthCredential};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = Decryptor<Aes256>;
type Aes256CbcEnc = Encryptor<Aes256>;

/// A 64-byte symmetric key pair: 32 bytes encryption key + 32 bytes MAC key.
///
/// Callers derive this from their own master secret (e.g. via HKDF) and pass
/// it to [`encrypt`] / [`decrypt`].  The key material is zeroized on drop.
pub struct StorageKey {
    data: Zeroizing<Vec<u8>>,
}

impl StorageKey {
    /// Create from raw 64-byte key material.
    ///
    /// Returns an error string if `bytes` is not exactly 64 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 64 {
            return Err(format!("StorageKey requires 64 bytes, got {}", bytes.len()));
        }
        Ok(Self {
            data: Zeroizing::new(bytes.to_vec()),
        })
    }

    fn enc_key(&self) -> &[u8] {
        &self.data[..32]
    }

    fn mac_key(&self) -> &[u8] {
        &self.data[32..]
    }
}

impl std::fmt::Debug for StorageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StorageKey([redacted])")
    }
}

/// Encrypt `plaintext` with the supplied key.
///
/// Returns `(iv_b64, ciphertext_b64, mac_b64)` — all Base64-encoded.
/// A fresh random IV is generated on every call.
pub fn encrypt(key: &StorageKey, plaintext: &[u8]) -> Result<EncryptedFields, String> {
    use rand::RngCore;

    let mut iv = vec![0u8; 16];
    rand::rng().fill_bytes(&mut iv);

    // Encrypt in-place with PKCS#7 padding.
    let pad_len = 16 - (plaintext.len() % 16);
    let mut buf = vec![0u8; plaintext.len() + pad_len];
    buf[..plaintext.len()].copy_from_slice(plaintext);

    let encryptor =
        Aes256CbcEnc::new_from_slices(key.enc_key(), &iv).map_err(|e| format!("AES init: {e}"))?;
    let ciphertext = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|e| format!("AES encrypt: {e}"))?
        .to_vec();

    // Encrypt-then-MAC: MAC covers IV || ciphertext.
    let mut hmac =
        HmacSha256::new_from_slice(key.mac_key()).map_err(|e| format!("HMAC init: {e}"))?;
    hmac.update(&iv);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes().to_vec();

    Ok(EncryptedFields {
        iv_b64: B64.encode(&iv),
        ciphertext_b64: B64.encode(&ciphertext),
        mac_b64: B64.encode(&mac),
    })
}

/// Decrypt `fields` with the supplied key.
///
/// Verifies the MAC before decrypting.  Returns the plaintext as a
/// `Zeroizing<Vec<u8>>` so it is scrubbed when the caller drops it.
pub fn decrypt(key: &StorageKey, fields: &EncryptedFields) -> Result<Zeroizing<Vec<u8>>, String> {
    let iv = B64
        .decode(&fields.iv_b64)
        .map_err(|e| format!("base64 decode iv: {e}"))?;
    let ciphertext = B64
        .decode(&fields.ciphertext_b64)
        .map_err(|e| format!("base64 decode ciphertext: {e}"))?;
    let mac_bytes = B64
        .decode(&fields.mac_b64)
        .map_err(|e| format!("base64 decode mac: {e}"))?;

    // Verify MAC.
    let mut hmac =
        HmacSha256::new_from_slice(key.mac_key()).map_err(|e| format!("HMAC init: {e}"))?;
    hmac.update(&iv);
    hmac.update(&ciphertext);
    hmac.verify_slice(&mac_bytes)
        .map_err(|_| "MAC verification failed (wrong key or tampered data)".to_string())?;

    // Decrypt in-place.
    let mut buf = Zeroizing::new(ciphertext.clone());
    let decryptor =
        Aes256CbcDec::new_from_slices(key.enc_key(), &iv).map_err(|e| format!("AES init: {e}"))?;
    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| format!("AES decrypt: {e}"))?;

    Ok(Zeroizing::new(plaintext.to_vec()))
}

/// Encrypt `client_secret` and persist the credential for `backend_id`.
///
/// The caller supplies a pre-derived `key` (64 bytes).  This function owns
/// only the encrypt + save steps — key derivation is the caller's concern.
pub fn encrypt_and_save(
    backend_id: &str,
    key: &StorageKey,
    client_id: &str,
    client_secret: &str,
) -> Result<(), String> {
    let plaintext = Zeroizing::new(client_secret.as_bytes().to_vec());
    let fields = encrypt(key, &plaintext)?;
    oauth::save_encrypted(backend_id, client_id, &fields)
}

/// Load and decrypt the OAuth credential for `backend_id`.
///
/// Returns `None` if no credential is stored.
/// Returns an error if the stored data is corrupt or MAC verification fails.
pub fn load_and_decrypt(
    backend_id: &str,
    key: &StorageKey,
) -> Result<Option<OAuthCredential>, String> {
    let Some((client_id, fields)) = oauth::load_encrypted(backend_id) else {
        return Ok(None);
    };

    let plaintext = decrypt(key, &fields)?;

    let secret_str = std::str::from_utf8(&plaintext)
        .map_err(|e| format!("credential is not valid UTF-8: {e}"))?
        .to_string();

    Ok(Some(OAuthCredential {
        client_id,
        client_secret: Zeroizing::new(secret_str),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn with_tmp_home(f: impl FnOnce()) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp =
            std::env::temp_dir().join(format!("rosec-credential-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        // Hold the crate-wide env mutex so oauth tests running in parallel
        // cannot clobber XDG_DATA_HOME at the same time.
        let _guard = crate::TEST_ENV_MUTEX.lock().unwrap();
        unsafe { env::set_var("XDG_DATA_HOME", &tmp) };
        f();
        unsafe { env::remove_var("XDG_DATA_HOME") };
        drop(_guard);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn test_key(byte: u8) -> StorageKey {
        StorageKey::from_bytes(&[byte; 64]).unwrap()
    }

    #[test]
    fn storage_key_rejects_wrong_length() {
        assert!(StorageKey::from_bytes(&[0u8; 32]).is_err());
        assert!(StorageKey::from_bytes(&[0u8; 65]).is_err());
        assert!(StorageKey::from_bytes(&[0u8; 64]).is_ok());
    }

    #[test]
    fn storage_key_debug_redacts() {
        let k = test_key(0x42);
        assert_eq!(format!("{k:?}"), "StorageKey([redacted])");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key(0x55);
        let plaintext = b"super secret credential";
        let fields = encrypt(&key, plaintext).unwrap();
        let recovered = decrypt(&key, &fields).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn encrypt_produces_different_iv_each_time() {
        let key = test_key(0x55);
        let f1 = encrypt(&key, b"same plaintext").unwrap();
        let f2 = encrypt(&key, b"same plaintext").unwrap();
        // IVs should differ (probabilistically); ciphertexts too.
        assert_ne!(f1.iv_b64, f2.iv_b64);
    }

    #[test]
    fn wrong_key_fails_mac() {
        let key_a = test_key(0xAA);
        let key_b = test_key(0xBB);
        let fields = encrypt(&key_a, b"secret").unwrap();
        assert!(decrypt(&key_b, &fields).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_mac() {
        let key = test_key(0x42);
        let mut fields = encrypt(&key, b"hello").unwrap();
        // Flip a byte in the ciphertext base64 — any change should fail MAC.
        let mut ct = B64.decode(&fields.ciphertext_b64).unwrap();
        ct[0] ^= 0xFF;
        fields.ciphertext_b64 = B64.encode(&ct);
        assert!(decrypt(&key, &fields).is_err());
    }

    #[test]
    fn save_and_load_roundtrip() {
        with_tmp_home(|| {
            let key = test_key(0x42);
            encrypt_and_save("my-backend", &key, "user.abc", "s3cr3t").unwrap();
            let cred = load_and_decrypt("my-backend", &key).unwrap().unwrap();
            assert_eq!(cred.client_id, "user.abc");
            assert_eq!(cred.client_secret.as_str(), "s3cr3t");
        });
    }

    #[test]
    fn load_missing_returns_none() {
        with_tmp_home(|| {
            let key = test_key(0x01);
            assert!(load_and_decrypt("no-such-backend", &key).unwrap().is_none());
        });
    }
}
