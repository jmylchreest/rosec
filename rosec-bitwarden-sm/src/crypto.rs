//! Cryptographic primitives for the Bitwarden SM WASM guest plugin.
//!
//! Ported from the native `rosec-bitwarden-sm/src/api.rs` crypto section.
//!
//! Operations:
//! - `derive_token_enc_key`: HMAC-SHA256 PRK + HKDF-Expand → 64-byte key
//! - `decrypt_enc_string`: AES-256-CBC-HMAC-SHA256 (EncString type 2)
//! - `decrypt_org_key`: decrypt the org key embedded in the login payload
//! - `decrypt_field_opt`: decrypt an optional EncString field → `String`
//! - `hkdf_expand_sha256`: low-level HKDF-Expand

use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::SmError;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Derive the 64-byte token encryption key from the 16-byte seed.
///
/// Matches the Bitwarden SDK's `derive_shareable_key(seed, "accesstoken", Some("sm-access-token"))`:
/// ```text
/// prk = HMAC-SHA256(key = "bitwarden-accesstoken", data = seed_16_bytes)
/// key = HKDF-Expand(prk, info = "sm-access-token", len = 64)
///     → [enc_key: 32 bytes | mac_key: 32 bytes]
/// ```
pub fn derive_token_enc_key(seed: &[u8; 16]) -> Result<Zeroizing<[u8; 64]>, SmError> {
    let mut mac = HmacSha256::new_from_slice(b"bitwarden-accesstoken")
        .map_err(|e| SmError::Crypto(format!("HMAC key init: {e}")))?;
    mac.update(seed);
    let prk_bytes = mac.finalize().into_bytes();
    let mut prk = Zeroizing::new([0u8; 32]);
    prk.copy_from_slice(&prk_bytes);

    let expanded = hkdf_expand_sha256(&*prk, Some(b"sm-access-token"), 64);
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&expanded);
    Ok(out)
}

/// Decrypt and return the 64-byte organisation encryption key embedded in the
/// `encrypted_payload` field of the login response.
///
/// `encrypted_payload` is an EncString (type 2 = AES-256-CBC-HMAC-SHA256),
/// encrypted with the token encryption key. Once decrypted, it is JSON of the
/// form `{"encryptionKey":"<base64>"}` where the base64 value is the raw 64-byte
/// org key.
pub fn decrypt_org_key(
    encrypted_payload: &str,
    token_enc_key: &[u8; 64],
) -> Result<Zeroizing<[u8; 64]>, SmError> {
    let payload_bytes = decrypt_enc_string(encrypted_payload, token_enc_key)?;

    #[derive(serde::Deserialize)]
    struct Payload {
        #[serde(rename = "encryptionKey")]
        encryption_key: String,
    }

    let mut payload: Payload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| SmError::Crypto(format!("payload JSON parse: {e}")))?;

    let mut key_bytes = B64
        .decode(&payload.encryption_key)
        .map_err(|e| SmError::Crypto(format!("org key base64: {e}")))?;

    payload.encryption_key.zeroize();

    if key_bytes.len() != 64 {
        key_bytes.zeroize();
        return Err(SmError::Crypto(format!(
            "org key must be 64 bytes, got {}",
            key_bytes.len()
        )));
    }

    let mut key = Zeroizing::new([0u8; 64]);
    key.copy_from_slice(&key_bytes);
    key_bytes.zeroize();
    Ok(key)
}

/// Decrypt an EncString field (type 2: `2.{iv_b64}|{data_b64}|{mac_b64}`) using
/// the given 64-byte AES-256-CBC-HMAC-SHA256 key (`[enc_key_32 | mac_key_32]`).
pub fn decrypt_enc_string(enc: &str, key64: &[u8; 64]) -> Result<Zeroizing<Vec<u8>>, SmError> {
    let body = enc.strip_prefix("2.").ok_or_else(|| {
        SmError::Crypto(format!("unsupported EncString type (expected '2.'): {enc}"))
    })?;

    let parts: Vec<&str> = body.split('|').collect();
    if parts.len() != 3 {
        return Err(SmError::Crypto(
            "EncString type 2 must have 3 pipe-separated parts".to_string(),
        ));
    }

    let iv = B64
        .decode(parts[0])
        .map_err(|e| SmError::Crypto(format!("EncString IV base64: {e}")))?;
    let data = B64
        .decode(parts[1])
        .map_err(|e| SmError::Crypto(format!("EncString data base64: {e}")))?;
    let mac = B64
        .decode(parts[2])
        .map_err(|e| SmError::Crypto(format!("EncString MAC base64: {e}")))?;

    if iv.len() != 16 {
        return Err(SmError::Crypto("EncString IV must be 16 bytes".to_string()));
    }
    if mac.len() != 32 {
        return Err(SmError::Crypto(
            "EncString MAC must be 32 bytes".to_string(),
        ));
    }

    let enc_key = &key64[..32];
    let mac_key = &key64[32..];

    // Verify HMAC-SHA256(mac_key, iv || data) == mac before decrypting.
    let mut hmac = HmacSha256::new_from_slice(mac_key)
        .map_err(|e| SmError::Crypto(format!("HMAC key: {e}")))?;
    hmac.update(&iv);
    hmac.update(&data);
    hmac.verify_slice(&mac)
        .map_err(|_| SmError::Crypto("EncString MAC verification failed".to_string()))?;

    // AES-256-CBC decrypt with PKCS7 padding.
    let mut buf = Zeroizing::new(data.clone());
    let plaintext = Aes256CbcDec::new_from_slices(enc_key, &iv)
        .map_err(|e| SmError::Crypto(format!("AES key/IV: {e}")))?
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| SmError::Crypto(format!("AES decrypt: {e}")))?;

    Ok(Zeroizing::new(plaintext.to_vec()))
}

/// Decrypt an optional EncString field, returning an empty string if absent.
pub fn decrypt_field_opt(
    enc: Option<&str>,
    org_key: &[u8; 64],
) -> Result<Zeroizing<String>, SmError> {
    match enc {
        None | Some("") => Ok(Zeroizing::new(String::new())),
        Some(s) => {
            let bytes = decrypt_enc_string(s, org_key)?;
            let text = String::from_utf8(bytes.to_vec())
                .map_err(|e| SmError::Crypto(format!("UTF-8 decode: {e}")))?;
            Ok(Zeroizing::new(text))
        }
    }
}

/// HKDF-Expand (RFC 5869) using HMAC-SHA256.
///
/// `prk` is the pseudo-random key (output of HKDF-Extract or PBKDF).
/// `info` is optional context / application-specific information.
/// `length` is the desired output length in bytes (≤ 255 * 32).
pub fn hkdf_expand_sha256(prk: &[u8], info: Option<&[u8]>, length: usize) -> Zeroizing<Vec<u8>> {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::from_prk(prk)
        .unwrap_or_else(|_| unreachable!("PRK must be a valid HKDF pseudo-random key"));
    let mut okm = Zeroizing::new(vec![0u8; length]);
    hk.expand(info.unwrap_or(b""), &mut okm)
        .unwrap_or_else(|_| unreachable!("HKDF output length must be ≤ 255 * HashLen"));
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector from the Bitwarden SDK access_token.rs test.
    const TEST_SEED_B64: &str = "X8vbvA0bduihIDe/qrzIQQ==";
    const EXPECTED_KEY_B64: &str =
        "H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg==";

    #[test]
    fn derive_token_enc_key_matches_sdk() {
        let seed_bytes = B64.decode(TEST_SEED_B64).unwrap();
        let mut seed = [0u8; 16];
        seed.copy_from_slice(&seed_bytes);
        let key = derive_token_enc_key(&seed).unwrap();
        assert_eq!(B64.encode(*key), EXPECTED_KEY_B64);
    }

    #[test]
    fn decrypt_enc_string_type2() {
        let key_bytes = B64.decode("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==").unwrap();
        let mut key64 = [0u8; 64];
        key64.copy_from_slice(&key_bytes);

        let enc = "2.AQEBAQEBAQEBAQEBAQEBAQ==|kcArgC3nLK58WUYK6yyQ+w==|9HRDjijjSa2tyToYilyG3mvJvHKhw3ZqFE7tFVaQh8Q=";
        let plaintext = decrypt_enc_string(enc, &key64).unwrap();
        assert_eq!(std::str::from_utf8(&plaintext).unwrap(), "EncryptMe!");
    }

    #[test]
    fn decrypt_enc_string_wrong_type() {
        let key = [0u8; 64];
        assert!(decrypt_enc_string("0.iv|data", &key).is_err());
    }

    #[test]
    fn decrypt_enc_string_bad_mac() {
        let key_bytes = B64.decode("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==").unwrap();
        let mut key64 = [0u8; 64];
        key64.copy_from_slice(&key_bytes);
        let bad_mac = B64.encode([0u8; 32]);
        let enc = format!("2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|{bad_mac}");
        assert!(decrypt_enc_string(&enc, &key64).is_err());
    }
}
