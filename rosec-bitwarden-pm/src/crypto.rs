//! Bitwarden-compatible cryptographic operations.
//!
//! Implements the key derivation, encryption, and decryption algorithms
//! used by the Bitwarden protocol, compatible with both official servers
//! and Vaultwarden.
//!
//! This is a near-direct port of `rosec-bitwarden/src/crypto.rs` for the
//! WASM guest.  Test-only encryption functions are omitted.

use aes::Aes256;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use block_padding::Pkcs7;
use cbc::Decryptor;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
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

// Custom serde for Keys: base64-encode/decode the raw 64-byte key material.
// This is used only for the offline cache blob (host-encrypted, opaque).
impl serde::Serialize for Keys {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&*self.data))
    }
}

impl<'de> serde::Deserialize<'de> for Keys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        let bytes = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64-byte key, got {}",
                bytes.len()
            )));
        }
        Ok(Self {
            data: Zeroizing::new(bytes),
        })
    }
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

    // Decrypt — buf is wrapped in Zeroizing because it contains plaintext after in-place decryption
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let decryptor = Aes256CbcDec::new_from_slices(keys.enc_key(), iv)
        .map_err(|e| BitwardenError::Crypto(format!("aes init: {e}")))?;
    let plaintext = decryptor
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|e| BitwardenError::Crypto(format!("aes decrypt: {e}")))?;

    Ok(Zeroizing::new(plaintext.to_vec()))
}

/// Decrypt data using RSA-2048-OAEP-SHA1 (for organization keys, cipher type 4).
///
/// # Why SHA-1?
///
/// The Bitwarden protocol specifies RSA-OAEP-SHA1 for cipher type 4 (asymmetric
/// organization key encryption) for backwards compatibility with all existing
/// vaults.  This is a **protocol constraint**, not a rosec design choice.
pub fn decrypt_asymmetric(
    private_key_der: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, BitwardenError> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::{Oaep, RsaPrivateKey};

    let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der)
        .map_err(|e| BitwardenError::Crypto(format!("pkcs8 parse: {e}")))?;

    // SHA-1 is required by the Bitwarden wire protocol for cipher type 4.
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
