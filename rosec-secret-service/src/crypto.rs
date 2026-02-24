//! Session encryption for the Secret Service D-Bus protocol.
//!
//! Implements the `dh-ietf1024-sha256-aes128-cbc-pkcs7` algorithm defined by
//! the freedesktop Secret Service specification:
//!
//! 1. Both sides generate a random 1024-bit DH private key using the
//!    RFC 2409 "Second Oakley Group" (MODP-1024) parameters.
//! 2. The client sends its DH public key as raw big-endian bytes in the
//!    `OpenSession` `input` parameter.
//! 3. The server generates its own keypair, computes the shared secret
//!    via modular exponentiation, and returns its public key as `output`.
//! 4. Both sides derive a 16-byte AES-128 key from the shared secret
//!    using HKDF-SHA256 with no salt and no info string.
//! 5. Secrets are encrypted with AES-128-CBC + PKCS7 padding; the random
//!    16-byte IV is returned in the `parameters` field of the Secret struct.

use aes::Aes128;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use num_bigint::BigUint;
use rosec_core::BackendError;
use sha2::Sha256;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// RFC 2409 Second Oakley Group (MODP-1024) parameters
// ---------------------------------------------------------------------------

/// The 1024-bit MODP prime from RFC 2409 §6.2.
///
/// This is the exact byte sequence specified by the freedesktop Secret Service
/// spec for the `dh-ietf1024-sha256-aes128-cbc-pkcs7` algorithm.
const MODP1024_PRIME_BYTES: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Generator for the MODP-1024 group.
const MODP1024_GENERATOR: u64 = 2;

/// Expected byte length of a MODP-1024 public key (1024 bits = 128 bytes).
const DH_KEY_BYTES: usize = 128;

/// AES-128 key length in bytes.
const AES128_KEY_BYTES: usize = 16;

/// AES block/IV size in bytes.
const AES_BLOCK_BYTES: usize = 16;

// ---------------------------------------------------------------------------
// Session algorithm enum
// ---------------------------------------------------------------------------

/// Session encryption algorithms defined by the Secret Service specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAlgorithm {
    /// No encryption — secrets travel as plaintext over the Unix socket.
    /// Adequate when client and daemon share the same user session.
    Plain,
    /// DH-IETF1024-SHA256-AES128-CBC-PKCS7: full session encryption.
    DhIetf1024,
}

impl SessionAlgorithm {
    pub fn parse(name: &str) -> Result<Self, BackendError> {
        match name {
            "plain" => Ok(Self::Plain),
            "dh-ietf1024-sha256-aes128-cbc-pkcs7" => Ok(Self::DhIetf1024),
            _ => Err(BackendError::NotSupported),
        }
    }
}

// ---------------------------------------------------------------------------
// DH key exchange
// ---------------------------------------------------------------------------

/// A server-side DH keypair for one session negotiation.
///
/// The private key bytes are kept in a `Zeroizing` buffer so they are scrubbed
/// on drop.  We store raw bytes rather than a `BigUint` because `BigUint` does
/// not implement `Zeroize`.
pub struct DhKeypair {
    /// Raw big-endian private key bytes (128 bytes), zeroized on drop.
    private_bytes: Zeroizing<[u8; DH_KEY_BYTES]>,
    /// Server public key as raw big-endian bytes (128 bytes, zero-padded).
    pub public_bytes: Vec<u8>,
}

/// Generate a fresh DH keypair using the MODP-1024 group.
///
/// Uses a thread-local CSPRNG (seeded from the OS) for the private key.
/// The private key is 1024 bits; the public key is `g^private mod p`.
pub fn generate_dh_keypair() -> Result<DhKeypair, BackendError> {
    let p = BigUint::from_bytes_be(MODP1024_PRIME_BYTES);
    let g = BigUint::from(MODP1024_GENERATOR);

    // Generate 128 random bytes for the private key
    let mut priv_bytes = Zeroizing::new([0u8; DH_KEY_BYTES]);
    rand::Rng::fill(&mut rand::rng(), priv_bytes.as_mut_slice());
    let private = BigUint::from_bytes_be(priv_bytes.as_ref());

    let public = g.modpow(&private, &p);
    let public_bytes = pad_to_128(public.to_bytes_be());

    Ok(DhKeypair {
        private_bytes: priv_bytes,
        public_bytes,
    })
}

/// Compute the shared secret and derive a 16-byte AES-128 key from it.
///
/// Validates that the client public key is in the range [2, p-2] to prevent
/// small-subgroup attacks before computing the shared secret.
///
/// Key derivation: HKDF-SHA256 with no salt and empty info string, extracting
/// 16 bytes — this matches the freedesktop Secret Service specification.
pub fn derive_session_key(
    keypair: &DhKeypair,
    client_pubkey_bytes: &[u8],
) -> Result<Zeroizing<[u8; AES128_KEY_BYTES]>, BackendError> {
    if client_pubkey_bytes.len() != DH_KEY_BYTES {
        return Err(BackendError::Unavailable(format!(
            "client DH public key must be {DH_KEY_BYTES} bytes, got {}",
            client_pubkey_bytes.len()
        )));
    }

    let p = BigUint::from_bytes_be(MODP1024_PRIME_BYTES);
    let client_pub = BigUint::from_bytes_be(client_pubkey_bytes);

    // Validate client public key is in range [2, p-2] — reject 0, 1, p-1, p
    let two = BigUint::from(2u32);
    let p_minus_two = &p - &two;
    if client_pub < two || client_pub > p_minus_two {
        return Err(BackendError::Unavailable(
            "client DH public key out of valid range".to_string(),
        ));
    }

    // Shared secret: client_pub ^ server_private mod p
    let private = BigUint::from_bytes_be(keypair.private_bytes.as_ref());
    let shared = client_pub.modpow(&private, &p);
    let shared_bytes = Zeroizing::new(pad_to_128(shared.to_bytes_be()));

    // HKDF-SHA256: no salt, no info → 16-byte AES-128 key
    let hkdf = Hkdf::<Sha256>::new(None, shared_bytes.as_ref());
    let mut key = Zeroizing::new([0u8; AES128_KEY_BYTES]);
    hkdf.expand(&[], key.as_mut())
        .map_err(|_| BackendError::Unavailable("HKDF expand failed".to_string()))?;

    Ok(key)
}

// ---------------------------------------------------------------------------
// AES-128-CBC-PKCS7 encrypt / decrypt
// ---------------------------------------------------------------------------

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// Encrypt `plaintext` with AES-128-CBC-PKCS7.
///
/// Returns `(iv, ciphertext)`. The IV is randomly generated from the OS CSPRNG.
pub fn aes128_cbc_encrypt(
    key: &[u8; AES128_KEY_BYTES],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), BackendError> {
    let mut iv = [0u8; AES_BLOCK_BYTES];
    rand::Rng::fill(&mut rand::rng(), &mut iv[..]);

    let encryptor = Aes128CbcEnc::new(key.into(), &iv.into());
    let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    Ok((iv.to_vec(), ciphertext))
}

/// Decrypt `ciphertext` with AES-128-CBC-PKCS7.
///
/// The result is wrapped in `Zeroizing` so the plaintext is scrubbed on drop.
pub fn aes128_cbc_decrypt(
    key: &[u8; AES128_KEY_BYTES],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    if iv.len() != AES_BLOCK_BYTES {
        return Err(BackendError::Unavailable(format!(
            "IV must be {AES_BLOCK_BYTES} bytes, got {}",
            iv.len()
        )));
    }
    let iv_arr: &[u8; AES_BLOCK_BYTES] = iv
        .try_into()
        .map_err(|_| BackendError::Unavailable("invalid IV length".to_string()))?;

    let decryptor = Aes128CbcDec::new(key.into(), iv_arr.into());
    let plaintext = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| BackendError::Unavailable(format!("AES-128-CBC decrypt failed: {e}")))?;

    Ok(Zeroizing::new(plaintext))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Zero-pad a big-endian byte vector to exactly 128 bytes.
///
/// `BigUint::to_bytes_be()` omits leading zeros; the DH public key and shared
/// secret must be exactly 128 bytes for the spec to work correctly.
fn pad_to_128(mut bytes: Vec<u8>) -> Vec<u8> {
    while bytes.len() < DH_KEY_BYTES {
        bytes.insert(0, 0);
    }
    bytes
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_algorithm_accepted() {
        assert_eq!(
            SessionAlgorithm::parse("plain").unwrap(),
            SessionAlgorithm::Plain
        );
    }

    #[test]
    fn dh_algorithm_accepted() {
        assert_eq!(
            SessionAlgorithm::parse("dh-ietf1024-sha256-aes128-cbc-pkcs7").unwrap(),
            SessionAlgorithm::DhIetf1024
        );
    }

    #[test]
    fn unknown_algorithm_rejected() {
        assert!(SessionAlgorithm::parse("bogus").is_err());
    }

    #[test]
    fn generate_keypair_produces_128_byte_public_key() {
        let kp = generate_dh_keypair().unwrap();
        assert_eq!(kp.public_bytes.len(), DH_KEY_BYTES);
    }

    #[test]
    fn dh_key_exchange_produces_same_shared_key() {
        // Simulate a full client-server DH exchange.
        // Both sides must independently compute the same shared secret.
        let server_kp = generate_dh_keypair().unwrap();
        let client_kp = generate_dh_keypair().unwrap();

        let server_key = derive_session_key(&server_kp, &client_kp.public_bytes).unwrap();
        let client_key = derive_session_key(&client_kp, &server_kp.public_bytes).unwrap();

        assert_eq!(
            server_key.as_ref(),
            client_key.as_ref(),
            "both sides must derive the same AES key"
        );
    }

    #[test]
    fn dh_derived_key_is_16_bytes() {
        let server_kp = generate_dh_keypair().unwrap();
        let client_kp = generate_dh_keypair().unwrap();
        let key = derive_session_key(&server_kp, &client_kp.public_bytes).unwrap();
        assert_eq!(key.len(), AES128_KEY_BYTES);
    }

    #[test]
    fn invalid_client_pubkey_zero_rejected() {
        let server_kp = generate_dh_keypair().unwrap();
        let zero = vec![0u8; DH_KEY_BYTES];
        assert!(matches!(
            derive_session_key(&server_kp, &zero),
            Err(BackendError::Unavailable(_))
        ));
    }

    #[test]
    fn invalid_client_pubkey_one_rejected() {
        let server_kp = generate_dh_keypair().unwrap();
        let mut one = vec![0u8; DH_KEY_BYTES];
        *one.last_mut().unwrap() = 1;
        assert!(matches!(
            derive_session_key(&server_kp, &one),
            Err(BackendError::Unavailable(_))
        ));
    }

    #[test]
    fn invalid_client_pubkey_wrong_length_rejected() {
        let server_kp = generate_dh_keypair().unwrap();
        let short = vec![0u8; 64];
        assert!(matches!(
            derive_session_key(&server_kp, &short),
            Err(BackendError::Unavailable(_))
        ));
    }

    #[test]
    fn aes128_cbc_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; AES128_KEY_BYTES];
        let plaintext = b"super secret value";

        let (iv, ciphertext) = aes128_cbc_encrypt(&key, plaintext).unwrap();
        assert_eq!(iv.len(), AES_BLOCK_BYTES);
        assert!(ciphertext.len() >= plaintext.len());
        assert_eq!(ciphertext.len() % AES_BLOCK_BYTES, 0);

        let decrypted = aes128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn aes128_cbc_wrong_key_fails_or_gives_garbage() {
        let key = [0x42u8; AES128_KEY_BYTES];
        let wrong_key = [0x99u8; AES128_KEY_BYTES];
        let (iv, ciphertext) = aes128_cbc_encrypt(&key, b"secret").unwrap();
        match aes128_cbc_decrypt(&wrong_key, &iv, &ciphertext) {
            Err(_) => {} // padding error — expected
            Ok(decrypted) => assert_ne!(decrypted.as_slice(), b"secret"),
        }
    }

    #[test]
    fn aes128_cbc_random_iv_each_time() {
        let key = [0x42u8; AES128_KEY_BYTES];
        let (iv1, _) = aes128_cbc_encrypt(&key, b"msg").unwrap();
        let (iv2, _) = aes128_cbc_encrypt(&key, b"msg").unwrap();
        // IVs should differ (with overwhelming probability from CSPRNG)
        assert_ne!(iv1, iv2);
    }

    #[test]
    fn full_dh_session_encrypt_decrypt() {
        // Full integration: DH exchange → shared key → encrypt → decrypt
        let server_kp = generate_dh_keypair().unwrap();
        let client_kp = generate_dh_keypair().unwrap();

        let server_key = derive_session_key(&server_kp, &client_kp.public_bytes).unwrap();
        let client_key = derive_session_key(&client_kp, &server_kp.public_bytes).unwrap();

        let secret = b"my vault password";
        let (iv, ciphertext) =
            aes128_cbc_encrypt(server_key.as_ref().try_into().unwrap(), secret).unwrap();

        let decrypted =
            aes128_cbc_decrypt(client_key.as_ref().try_into().unwrap(), &iv, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), secret);
    }

    #[test]
    fn pad_to_128_short_input() {
        let short = vec![0x01, 0x02];
        let padded = pad_to_128(short);
        assert_eq!(padded.len(), DH_KEY_BYTES);
        assert_eq!(padded[DH_KEY_BYTES - 2], 0x01);
        assert_eq!(padded[DH_KEY_BYTES - 1], 0x02);
        assert!(padded[..DH_KEY_BYTES - 2].iter().all(|&b| b == 0));
    }

    #[test]
    fn pad_to_128_exact_input_unchanged() {
        let exact = vec![0xABu8; DH_KEY_BYTES];
        let padded = pad_to_128(exact.clone());
        assert_eq!(padded, exact);
    }
}
