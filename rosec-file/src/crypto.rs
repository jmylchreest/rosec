use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::prelude::{BASE64_STANDARD, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::types::KdfParams;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const MAC_KEY_LEN: usize = 32;

pub fn derive_key(password: &[u8], kdf: &KdfParams) -> Zeroizing<[u8; KEY_LEN]> {
    let salt = BASE64_STANDARD.decode(&kdf.salt).unwrap_or_default();
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2_hmac::<Sha256>(password, &salt, kdf.iterations, &mut *key);
    key
}

pub fn derive_mac_key(encryption_key: &[u8]) -> Zeroizing<[u8; MAC_KEY_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(None, encryption_key);
    let mut mac_key = Zeroizing::new([0u8; MAC_KEY_LEN]);
    hkdf.expand(b"mac key", &mut *mac_key)
        .expect("HKDF expand should not fail");
    mac_key
}

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = rand::random::<[u8; IV_LEN]>();
    let cipher = Aes256CbcEnc::new(key.into(), (&iv).into());
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let mut result = Vec::with_capacity(IV_LEN + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend(ciphertext);
    result
}

pub fn decrypt(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, &'static str> {
    if encrypted.len() < IV_LEN {
        return Err("encrypted data too short");
    }

    let (iv, ciphertext) = encrypted.split_at(IV_LEN);
    let cipher = Aes256CbcDec::new(key.into(), iv.into());

    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| "decryption failed")
}

pub fn compute_hmac(mac_key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC key should be valid");
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    output
}

pub fn verify_hmac(mac_key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    if expected.len() != 32 {
        return false;
    }

    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC key should be valid");
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
        assert_eq!(plaintext.to_vec(), decrypted);
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
}
