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
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use crypto_bigint::{U1024, const_monty_params};
use hkdf::Hkdf;
#[cfg(test)]
use num_bigint::BigUint;
use rosec_core::ProviderError;
use sha2::Sha256;
#[cfg(test)]
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// The 1024-bit MODP prime from RFC 2409 §6.2.
///
/// This is the exact byte sequence specified by the freedesktop Secret Service
/// spec for the `dh-ietf1024-sha256-aes128-cbc-pkcs7` algorithm.
#[cfg(test)]
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
const_monty_params!(
    Modp1024,
    U1024,
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff"
);
type DhMonty = crypto_bigint::modular::ConstMontyForm<Modp1024, { U1024::LIMBS }>;
const MODP1024_PRIME: U1024 = U1024::from_be_hex(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff",
);

// Full-width exponentiation: never derive the loop bound from a secret value.
// These wrappers scrub owned values, not every internal library copy or CPU register.
fn dh_power(base: &U1024, exponent: &[u8]) -> Zeroizing<U1024> {
    let exponent = Zeroizing::new(U1024::from_be_slice(exponent));
    let result = Zeroizing::new(DhMonty::new(base).pow(&exponent));
    Zeroizing::new(result.retrieve())
}

/// Byte width of the MODP-1024 group (1024 bits = 128 bytes).
const DH_KEY_BYTES: usize = 128;

const AES128_KEY_BYTES: usize = 16;

const AES_BLOCK_BYTES: usize = 16;

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
    pub fn parse(name: &str) -> Result<Self, ProviderError> {
        match name {
            "plain" => Ok(Self::Plain),
            "dh-ietf1024-sha256-aes128-cbc-pkcs7" => Ok(Self::DhIetf1024),
            _ => Err(ProviderError::NotSupported),
        }
    }
}

/// A server-side DH keypair for one session negotiation.
///
/// The private key bytes are kept in a `Zeroizing` buffer so they are scrubbed
/// on drop.  Owned arithmetic values are also scrubbed; internal library temporaries
/// are not covered by that guarantee.
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
pub fn generate_dh_keypair() -> Result<DhKeypair, ProviderError> {
    let g = U1024::from(MODP1024_GENERATOR);

    let mut priv_bytes = Zeroizing::new([0u8; DH_KEY_BYTES]);
    rand::RngExt::fill(&mut rand::rng(), priv_bytes.as_mut_slice());
    let public = dh_power(&g, priv_bytes.as_ref());
    let public_bytes = public.to_be_bytes().to_vec();

    Ok(DhKeypair {
        private_bytes: priv_bytes,
        public_bytes,
    })
}

/// Compute the shared secret and derive a 16-byte AES-128 key from it.
///
/// Rejects trivial/out-of-range public values outside [2, p-2] before
/// computing the shared secret. This is not a full subgroup-membership check.
///
/// Key derivation: HKDF-SHA256 with no salt and empty info string, extracting
/// 16 bytes — this matches the freedesktop Secret Service specification.
pub fn derive_session_key(
    keypair: &DhKeypair,
    client_pubkey_bytes: &[u8],
) -> Result<Zeroizing<[u8; AES128_KEY_BYTES]>, ProviderError> {
    // The Secret Service API encodes public keys as unsigned big-endian
    // integers, not fixed-width buffers. libsecret may omit leading zeroes
    // or include a leading zero when the most significant bit is set.
    let first_nonzero = client_pubkey_bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(client_pubkey_bytes.len());
    let client_pubkey_bytes = &client_pubkey_bytes[first_nonzero..];
    if client_pubkey_bytes.len() > DH_KEY_BYTES {
        return Err(ProviderError::InvalidInput(
            format!(
                "client DH public key exceeds {DH_KEY_BYTES} significant bytes, got {}",
                client_pubkey_bytes.len()
            )
            .into(),
        ));
    }

    let mut public_bytes = [0u8; DH_KEY_BYTES];
    public_bytes[DH_KEY_BYTES - client_pubkey_bytes.len()..].copy_from_slice(client_pubkey_bytes);
    let client_pub = U1024::from_be_slice(&public_bytes);
    let two = U1024::from(2u64);
    if client_pub < two || client_pub > MODP1024_PRIME.wrapping_sub(&two) {
        return Err(ProviderError::InvalidInput(
            "client DH public key out of valid range".into(),
        ));
    }
    let shared = dh_power(&client_pub, keypair.private_bytes.as_ref());
    let shared_bytes = Zeroizing::new(shared.to_be_bytes());

    // HKDF-SHA256: no salt, no info → 16-byte AES-128 key
    let hkdf = Hkdf::<Sha256>::new(None, shared_bytes.as_ref());
    let mut key = Zeroizing::new([0u8; AES128_KEY_BYTES]);
    hkdf.expand(&[], key.as_mut())
        .map_err(|_| ProviderError::Unavailable("HKDF expand failed".to_string()))?;

    Ok(key)
}

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// Encrypt `plaintext` with AES-128-CBC-PKCS7.
///
/// Returns `(iv, ciphertext)`. The IV is randomly generated from the OS CSPRNG.
pub fn aes128_cbc_encrypt(
    key: &[u8; AES128_KEY_BYTES],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ProviderError> {
    let mut iv = [0u8; AES_BLOCK_BYTES];
    rand::RngExt::fill(&mut rand::rng(), &mut iv[..]);

    let encryptor = Aes128CbcEnc::new(key.into(), &iv.into());
    let ciphertext = encryptor.encrypt_padded_vec::<Pkcs7>(plaintext);

    Ok((iv.to_vec(), ciphertext))
}

/// Decrypt `ciphertext` with AES-128-CBC-PKCS7.
///
/// The result is wrapped in `Zeroizing` so the plaintext is scrubbed on drop.
pub fn aes128_cbc_decrypt(
    key: &[u8; AES128_KEY_BYTES],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    if iv.len() != AES_BLOCK_BYTES {
        return Err(ProviderError::Unavailable(format!(
            "IV must be {AES_BLOCK_BYTES} bytes, got {}",
            iv.len()
        )));
    }
    let iv_arr: &[u8; AES_BLOCK_BYTES] = iv
        .try_into()
        .map_err(|_| ProviderError::Unavailable("invalid IV length".to_string()))?;

    let decryptor = Aes128CbcDec::new(key.into(), iv_arr.into());
    let plaintext = decryptor
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map_err(|e| ProviderError::Unavailable(format!("AES-128-CBC decrypt failed: {e}")))?;

    Ok(Zeroizing::new(plaintext))
}

/// Zero-pad a big-endian byte vector to exactly 128 bytes.
///
/// `BigUint::to_bytes_be()` omits leading zeros. We emit fixed-width public
/// keys while accepting variable-width unsigned encodings from clients.
/// The shared secret is padded to the group width before key derivation.
#[cfg(test)]
fn pad_to_128(mut bytes: Vec<u8>) -> Vec<u8> {
    // Mod-p values never exceed 128 bytes; nothing to pad.
    if bytes.len() >= DH_KEY_BYTES {
        return bytes;
    }
    // Build the result in a single pre-sized buffer. A growing `insert(0, 0)`
    // loop reallocates and leaves stray copies of the (possibly secret) bytes
    // in freed heap; copy once and scrub the input instead. NOTE: the source
    // `BigUint` itself still holds un-scrubbed limbs — num-bigint has no
    // zeroize support; fully scrubbing needs a bignum migration.
    let mut out = vec![0u8; DH_KEY_BYTES];
    out[DH_KEY_BYTES - bytes.len()..].copy_from_slice(&bytes);
    bytes.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_python_pow_hkdf_vectors() {
        // Generated using Python integer pow and stdlib hmac/SHA256, not this backend.
        // Includes a shared value requiring 127 leading padding bytes.
        for (private_bytes, client_public, expected_key) in [
            (
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                ],
                [
                    253, 237, 46, 221, 193, 89, 123, 12, 152, 210, 19, 117, 28, 174, 242, 157,
                ],
            ),
            (
                [
                    85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
                    85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
                    85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
                    85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
                    85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
                    85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
                    85, 85, 85, 85, 85, 85, 85, 85,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
                ],
                [
                    71, 188, 73, 74, 233, 8, 55, 205, 202, 130, 123, 112, 229, 210, 81, 110,
                ],
            ),
            (
                [
                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                ],
                [
                    255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52,
                    196, 198, 98, 139, 128, 220, 28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2, 11,
                    190, 166, 59, 19, 155, 34, 81, 74, 8, 121, 142, 52, 4, 221, 239, 149, 25, 179,
                    205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225, 53, 109, 109, 81,
                    194, 69, 228, 133, 181, 118, 98, 94, 126, 198, 244, 76, 66, 233, 166, 55, 237,
                    107, 11, 255, 92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90, 137, 159, 165,
                    174, 159, 36, 17, 124, 75, 31, 230, 73, 40, 102, 81, 236, 230, 83, 129, 255,
                    255, 255, 255, 255, 255, 255, 253,
                ],
                [
                    140, 22, 220, 126, 4, 34, 187, 148, 200, 112, 165, 70, 158, 134, 242, 109,
                ],
            ),
        ] {
            let kp = DhKeypair {
                private_bytes: Zeroizing::new(private_bytes),
                public_bytes: vec![],
            };
            assert_eq!(
                *derive_session_key(&kp, &client_public).unwrap(),
                expected_key
            );
        }
    }

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
            Err(ProviderError::InvalidInput(_))
        ));
    }

    #[test]
    fn invalid_client_pubkey_one_rejected() {
        let server_kp = generate_dh_keypair().unwrap();
        let mut one = vec![0u8; DH_KEY_BYTES];
        *one.last_mut().unwrap() = 1;
        assert!(matches!(
            derive_session_key(&server_kp, &one),
            Err(ProviderError::InvalidInput(_))
        ));
    }

    #[test]
    fn client_pubkey_encodings_derive_same_key() {
        let server_kp = generate_dh_keypair().unwrap();
        for width in [1, 127, 128] {
            let mut minimal = vec![0u8; width];
            minimal[0] = 0x80;
            let fixed_width = pad_to_128(minimal.clone());
            let expected = derive_session_key(&server_kp, &fixed_width).unwrap();
            let mut zero_prefixed = vec![0];
            zero_prefixed.extend_from_slice(&minimal);

            for encoding in [&minimal, &zero_prefixed] {
                let actual = derive_session_key(&server_kp, encoding).unwrap();
                assert_eq!(actual.as_ref(), expected.as_ref());
            }
        }
    }

    #[test]
    fn invalid_client_pubkey_range_rejected() {
        let server_kp = generate_dh_keypair().unwrap();
        let p = BigUint::from_bytes_be(MODP1024_PRIME_BYTES);
        for encoding in [
            vec![],
            vec![0],
            vec![1],
            (&p - BigUint::from(1u32)).to_bytes_be(),
            p.to_bytes_be(),
            (&p + BigUint::from(1u32)).to_bytes_be(),
            vec![1; DH_KEY_BYTES + 1],
        ] {
            for prefix_len in [0, 1, 3] {
                let mut prefixed = vec![0; prefix_len];
                prefixed.extend_from_slice(&encoding);
                assert!(matches!(
                    derive_session_key(&server_kp, &prefixed),
                    Err(ProviderError::InvalidInput(_))
                ));
            }
        }
    }

    #[test]
    fn client_pubkey_range_boundaries_accepted_with_zero_prefixes() {
        let server_kp = generate_dh_keypair().unwrap();
        let p = BigUint::from_bytes_be(MODP1024_PRIME_BYTES);
        for value in [BigUint::from(2u32), &p - BigUint::from(2u32)] {
            let minimal = value.to_bytes_be();
            let expected = derive_session_key(&server_kp, &minimal).unwrap();
            for prefix_len in [1, 3, DH_KEY_BYTES] {
                let mut prefixed = vec![0; prefix_len];
                prefixed.extend_from_slice(&minimal);
                let actual = derive_session_key(&server_kp, &prefixed).unwrap();
                assert_eq!(actual.as_ref(), expected.as_ref());
            }
        }
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
