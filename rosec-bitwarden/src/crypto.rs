//! Bitwarden-compatible cryptographic operations.
//!
//! Implements the key derivation, encryption, and decryption algorithms
//! used by the Bitwarden protocol, compatible with both official servers
//! and Vaultwarden.

use aes::Aes256;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::BitwardenError;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// A 64-byte key pair: 32 bytes encryption key + 32 bytes MAC key.
#[derive(Clone)]
pub struct Keys {
    data: Zeroizing<Vec<u8>>,
}

impl Keys {
    /// Create from raw 64-byte key material.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BitwardenError> {
        if bytes.len() != 64 {
            return Err(BitwardenError::Crypto(format!(
                "expected 64-byte key, got {}",
                bytes.len()
            )));
        }
        Ok(Self {
            data: Zeroizing::new(bytes.to_vec()),
        })
    }

    /// The 32-byte encryption key.
    pub fn enc_key(&self) -> &[u8] {
        &self.data[..32]
    }

    /// The 32-byte MAC key.
    pub fn mac_key(&self) -> &[u8] {
        &self.data[32..]
    }
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys([redacted])")
    }
}

/// KDF parameters returned by the prelogin endpoint.
#[derive(Debug, Clone)]
pub enum KdfParams {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        iterations: u32,
        memory_mb: u32,
        parallelism: u32,
    },
}

/// Derive the 32-byte master key from password + email using the configured KDF.
pub fn derive_master_key(
    password: &[u8],
    email: &str,
    kdf: &KdfParams,
) -> Result<Zeroizing<Vec<u8>>, BitwardenError> {
    let email_lower = email.trim().to_lowercase();
    let mut master_key = Zeroizing::new(vec![0u8; 32]);

    match kdf {
        KdfParams::Pbkdf2 { iterations } => {
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password,
                email_lower.as_bytes(),
                *iterations,
                &mut master_key,
            );
        }
        KdfParams::Argon2id {
            iterations,
            memory_mb,
            parallelism,
        } => {
            use sha2::Digest;
            let salt = Sha256::digest(email_lower.as_bytes());

            let params = argon2::Params::new(
                *memory_mb * 1024, // MB -> KB
                *iterations,
                *parallelism,
                Some(32),
            )
            .map_err(|e| BitwardenError::Crypto(format!("argon2 params: {e}")))?;

            let argon =
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

            argon
                .hash_password_into(password, &salt, &mut master_key)
                .map_err(|e| BitwardenError::Crypto(format!("argon2: {e}")))?;
        }
    }

    Ok(master_key)
}

/// Derive the password hash sent to the server during login.
///
/// `PBKDF2-HMAC-SHA256(password=master_key, salt=raw_password, iterations=1)`
pub fn derive_password_hash(master_key: &[u8], password: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut hash = Zeroizing::new(vec![0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(master_key, password, 1, &mut hash);
    hash
}

/// Expand the 32-byte master key into enc_key + mac_key via HKDF-SHA256.
pub fn expand_master_key(master_key: &[u8]) -> Result<Keys, BitwardenError> {
    use hkdf::Hkdf;

    let hkdf = Hkdf::<Sha256>::from_prk(master_key)
        .map_err(|e| BitwardenError::Crypto(format!("hkdf from_prk: {e}")))?;

    let mut enc_key = Zeroizing::new(vec![0u8; 32]);
    hkdf.expand(b"enc", &mut enc_key)
        .map_err(|e| BitwardenError::Crypto(format!("hkdf expand enc: {e}")))?;

    let mut mac_key = Zeroizing::new(vec![0u8; 32]);
    hkdf.expand(b"mac", &mut mac_key)
        .map_err(|e| BitwardenError::Crypto(format!("hkdf expand mac: {e}")))?;

    let mut combined = Zeroizing::new(vec![0u8; 64]);
    combined[..32].copy_from_slice(&enc_key);
    combined[32..].copy_from_slice(&mac_key);

    Keys::from_bytes(&combined)
}

/// Decrypt data using AES-256-CBC + HMAC-SHA256 verification.
pub fn decrypt_symmetric(
    keys: &Keys,
    iv: &[u8],
    ciphertext: &[u8],
    mac: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, BitwardenError> {
    // Verify MAC if present
    if let Some(mac_bytes) = mac {
        let mut hmac = HmacSha256::new_from_slice(keys.mac_key())
            .map_err(|e| BitwardenError::Crypto(format!("hmac init: {e}")))?;
        hmac.update(iv);
        hmac.update(ciphertext);
        hmac.verify_slice(mac_bytes)
            .map_err(|_| BitwardenError::Crypto("MAC verification failed".to_string()))?;
    }

    // Decrypt
    // buf is wrapped in Zeroizing because it contains plaintext after in-place decryption
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let decryptor = Aes256CbcDec::new_from_slices(keys.enc_key(), iv)
        .map_err(|e| BitwardenError::Crypto(format!("aes init: {e}")))?;
    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| BitwardenError::Crypto(format!("aes decrypt: {e}")))?;

    Ok(Zeroizing::new(plaintext.to_vec()))
}

/// AES-CBC encryption result: (IV, ciphertext, MAC).  Test-only.
#[cfg(test)]
type EncryptResult = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Encrypt data using AES-256-CBC + HMAC-SHA256.
///
/// Only used in tests; production encryption is handled by `rosec-core::credential`.
#[cfg(test)]
pub(crate) fn encrypt_symmetric(
    keys: &Keys,
    plaintext: &[u8],
) -> Result<EncryptResult, BitwardenError> {
    use cbc::cipher::BlockEncryptMut;
    use cbc::Encryptor;
    use rand::RngCore;

    type Aes256CbcEnc = Encryptor<Aes256>;

    let mut iv = vec![0u8; 16];
    rand::rng().fill_bytes(&mut iv);

    let pad_len = 16 - (plaintext.len() % 16);
    let mut buf = vec![0u8; plaintext.len() + pad_len];
    buf[..plaintext.len()].copy_from_slice(plaintext);

    let encryptor = Aes256CbcEnc::new_from_slices(keys.enc_key(), &iv)
        .map_err(|e| BitwardenError::Crypto(format!("aes init: {e}")))?;
    let ciphertext = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|e| BitwardenError::Crypto(format!("aes encrypt: {e}")))?
        .to_vec();

    let mut hmac = HmacSha256::new_from_slice(keys.mac_key())
        .map_err(|e| BitwardenError::Crypto(format!("hmac init: {e}")))?;
    hmac.update(&iv);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes().to_vec();

    Ok((iv, ciphertext, mac))
}

/// Decrypt data using RSA-2048-OAEP-SHA1 (for organization keys).
pub fn decrypt_asymmetric(
    private_key_der: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, BitwardenError> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::{Oaep, RsaPrivateKey};

    let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der)
        .map_err(|e| BitwardenError::Crypto(format!("pkcs8 parse: {e}")))?;

    let padding = Oaep::new::<sha1::Sha1>();
    let plaintext = private_key
        .decrypt(padding, ciphertext)
        .map_err(|e| BitwardenError::Crypto(format!("rsa decrypt: {e}")))?;

    Ok(Zeroizing::new(plaintext))
}

/// Base64-encode using standard encoding.
pub fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Base64-decode using standard encoding.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, BitwardenError> {
    STANDARD
        .decode(s)
        .map_err(|e| BitwardenError::Crypto(format!("base64 decode: {e}")))
}

/// Base64-encode using URL-safe-no-pad encoding (for auth-email header).
pub fn b64_url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_key_derivation() {
        let password = b"master_password";
        let email = "test@example.com";
        let kdf = KdfParams::Pbkdf2 {
            iterations: 100_000,
        };

        let key = derive_master_key(password, email, &kdf).unwrap();
        assert_eq!(key.len(), 32);

        // Same inputs should produce same key
        let key2 = derive_master_key(password, email, &kdf).unwrap();
        assert_eq!(key.as_slice(), key2.as_slice());

        // Different password should produce different key
        let key3 = derive_master_key(b"other", email, &kdf).unwrap();
        assert_ne!(key.as_slice(), key3.as_slice());
    }

    #[test]
    fn email_is_normalized() {
        let password = b"test";
        let kdf = KdfParams::Pbkdf2 { iterations: 1000 };

        let k1 = derive_master_key(password, "Test@Example.COM", &kdf).unwrap();
        let k2 = derive_master_key(password, "test@example.com", &kdf).unwrap();
        let k3 = derive_master_key(password, "  Test@Example.COM  ", &kdf).unwrap();
        assert_eq!(k1.as_slice(), k2.as_slice());
        assert_eq!(k2.as_slice(), k3.as_slice());
    }

    #[test]
    fn password_hash_derivation() {
        let master_key = [0xABu8; 32];
        let password = b"test_password";
        let hash = derive_password_hash(&master_key, password);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn hkdf_expansion() {
        let master_key = [0x42u8; 32];
        let keys = expand_master_key(&master_key).unwrap();
        assert_eq!(keys.enc_key().len(), 32);
        assert_eq!(keys.mac_key().len(), 32);
        // enc and mac keys should differ
        assert_ne!(keys.enc_key(), keys.mac_key());
    }

    #[test]
    fn symmetric_roundtrip() {
        let key_bytes = [0x55u8; 64];
        let keys = Keys::from_bytes(&key_bytes).unwrap();

        let plaintext = b"hello bitwarden world";
        let (iv, ct, mac) = encrypt_symmetric(&keys, plaintext).unwrap();

        let decrypted = decrypt_symmetric(&keys, &iv, &ct, Some(&mac)).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn mac_verification_fails_on_tamper() {
        let key_bytes = [0x55u8; 64];
        let keys = Keys::from_bytes(&key_bytes).unwrap();

        let plaintext = b"sensitive data";
        let (iv, ct, mut mac) = encrypt_symmetric(&keys, plaintext).unwrap();

        // Tamper with MAC
        mac[0] ^= 0xFF;
        let result = decrypt_symmetric(&keys, &iv, &ct, Some(&mac));
        assert!(result.is_err());
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"test data 123";
        let encoded = b64_encode(data);
        let decoded = b64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
