//! Bitwarden cipher string parsing and decryption.
//!
//! Cipher strings encode encrypted data in the format `{type}.{data}` where
//! type 2 is AES-256-CBC + HMAC-SHA256 (symmetric) and type 4 is RSA-OAEP-SHA1
//! (asymmetric, used for organization keys).

use zeroize::Zeroizing;

use crate::crypto::{self, Keys};
use crate::error::BitwardenError;

/// A parsed Bitwarden cipher string.
#[derive(Debug, Clone)]
pub enum CipherString {
    /// Type 2: AES-256-CBC + HMAC-SHA256
    Symmetric {
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
        mac: Option<Vec<u8>>,
    },
    /// Type 4: RSA-2048-OAEP-SHA1
    Asymmetric { ciphertext: Vec<u8> },
}

impl CipherString {
    /// Parse a cipher string from its string representation.
    ///
    /// Supported formats:
    /// - `2.{iv_b64}|{ct_b64}|{mac_b64}` — symmetric with MAC
    /// - `2.{iv_b64}|{ct_b64}` — symmetric without MAC (legacy)
    /// - `4.{ct_b64}` — asymmetric (RSA-OAEP-SHA1)
    /// - `6.{ct_b64}|{hmac_b64}` — asymmetric with HMAC suffix (stripped)
    pub fn parse(s: &str) -> Result<Self, BitwardenError> {
        let (type_str, data) = s
            .split_once('.')
            .ok_or_else(|| BitwardenError::CipherParse("missing type separator".to_string()))?;

        let cipher_type: u8 = type_str
            .parse()
            .map_err(|_| BitwardenError::CipherParse(format!("invalid type: {type_str}")))?;

        match cipher_type {
            2 => Self::parse_symmetric(data),
            4 => Self::parse_asymmetric(data),
            6 => {
                // Type 6: strip the HMAC suffix, treat as asymmetric
                let ct_part = data.split('|').next().unwrap_or(data);
                Self::parse_asymmetric(ct_part)
            }
            t @ (0 | 1 | 3 | 5) => Err(BitwardenError::CipherParse(format!(
                "unsupported legacy cipher type {t}"
            ))),
            t => Err(BitwardenError::CipherParse(format!(
                "unknown cipher type {t}"
            ))),
        }
    }

    fn parse_symmetric(data: &str) -> Result<Self, BitwardenError> {
        let parts: Vec<&str> = data.split('|').collect();
        match parts.len() {
            2 => {
                let iv = crypto::b64_decode(parts[0])?;
                let ciphertext = crypto::b64_decode(parts[1])?;
                Ok(Self::Symmetric {
                    iv,
                    ciphertext,
                    mac: None,
                })
            }
            3 => {
                let iv = crypto::b64_decode(parts[0])?;
                let ciphertext = crypto::b64_decode(parts[1])?;
                let mac = crypto::b64_decode(parts[2])?;
                Ok(Self::Symmetric {
                    iv,
                    ciphertext,
                    mac: Some(mac),
                })
            }
            n => Err(BitwardenError::CipherParse(format!(
                "symmetric cipher string has {n} parts, expected 2 or 3"
            ))),
        }
    }

    fn parse_asymmetric(data: &str) -> Result<Self, BitwardenError> {
        let ciphertext = crypto::b64_decode(data)?;
        Ok(Self::Asymmetric { ciphertext })
    }

    /// Decrypt this cipher string using symmetric keys.
    ///
    /// Returns the plaintext bytes.
    pub fn decrypt_symmetric(&self, keys: &Keys) -> Result<Zeroizing<Vec<u8>>, BitwardenError> {
        match self {
            Self::Symmetric {
                iv,
                ciphertext,
                mac,
            } => crypto::decrypt_symmetric(keys, iv, ciphertext, mac.as_deref()),
            Self::Asymmetric { .. } => Err(BitwardenError::CipherParse(
                "cannot decrypt asymmetric cipher with symmetric keys".to_string(),
            )),
        }
    }

    /// Decrypt this cipher string using an RSA private key (DER format).
    ///
    /// Used for organization keys.
    pub fn decrypt_asymmetric(
        &self,
        private_key_der: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, BitwardenError> {
        match self {
            Self::Asymmetric { ciphertext } => {
                crypto::decrypt_asymmetric(private_key_der, ciphertext)
            }
            Self::Symmetric { .. } => Err(BitwardenError::CipherParse(
                "cannot decrypt symmetric cipher with asymmetric key".to_string(),
            )),
        }
    }

    /// Decrypt this cipher string to a UTF-8 string.
    pub fn decrypt_to_string(&self, keys: &Keys) -> Result<String, BitwardenError> {
        let bytes = self.decrypt_symmetric(keys)?;
        // `Zeroizing<Vec<u8>>` does not implement `Into<Vec<u8>>` in zeroize 1.x,
        // so we copy the bytes out. The copy is short-lived (dropped with `bytes`
        // before this function returns) and the `Zeroizing` wrapper ensures the
        // decrypted bytes are wiped on drop.
        String::from_utf8(bytes.to_vec())
            .map_err(|e| BitwardenError::CipherParse(format!("invalid UTF-8: {e}")))
    }

    /// Decrypt this cipher string to a zeroizing UTF-8 string (for secrets).
    ///
    /// The resulting `String` is wrapped in `Zeroizing` so it is scrubbed when
    /// dropped. The intermediate byte buffer is also `Zeroizing`, so decrypted
    /// bytes are wiped even if UTF-8 conversion fails.
    pub fn decrypt_to_zeroizing_string(
        &self,
        keys: &Keys,
    ) -> Result<Zeroizing<String>, BitwardenError> {
        let bytes = self.decrypt_symmetric(keys)?;
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|e| BitwardenError::CipherParse(format!("invalid UTF-8: {e}")))?;
        Ok(Zeroizing::new(s))
    }

    /// Decrypt this cipher string to a UTF-8 string, using an optional
    /// per-item key that overrides the provided vault keys.
    pub fn decrypt_with_entry_key(
        &self,
        vault_keys: &Keys,
        entry_key: Option<&Keys>,
    ) -> Result<String, BitwardenError> {
        let keys = entry_key.unwrap_or(vault_keys);
        self.decrypt_to_string(keys)
    }
}

/// Decrypt an optional cipher string field to an optional plain string.
///
/// Returns `Ok(None)` if the input is `None`.
pub fn decrypt_field(
    field: &Option<String>,
    vault_keys: &Keys,
    entry_key: Option<&Keys>,
) -> Result<Option<String>, BitwardenError> {
    match field {
        Some(s) if !s.is_empty() => {
            let cs = CipherString::parse(s)?;
            Ok(Some(cs.decrypt_with_entry_key(vault_keys, entry_key)?))
        }
        _ => Ok(None),
    }
}

/// Decrypt an optional cipher string field to an optional zeroizing string (for secrets).
///
/// Returns `Ok(None)` if the input is `None`.
pub fn decrypt_field_sensitive(
    field: &Option<String>,
    vault_keys: &Keys,
    entry_key: Option<&Keys>,
) -> Result<Option<Zeroizing<String>>, BitwardenError> {
    match field {
        Some(s) if !s.is_empty() => {
            let cs = CipherString::parse(s)?;
            let keys = entry_key.unwrap_or(vault_keys);
            Ok(Some(cs.decrypt_to_zeroizing_string(keys)?))
        }
        _ => Ok(None),
    }
}

/// Resolve the per-item encryption key from a cipher's `Key` field.
///
/// If the cipher has a per-item key, decrypt it with vault keys to get
/// the entry-specific 64-byte key pair.
pub fn resolve_entry_key(
    cipher_key: &Option<String>,
    vault_keys: &Keys,
) -> Result<Option<Keys>, BitwardenError> {
    match cipher_key {
        Some(s) if !s.is_empty() => {
            let cs = CipherString::parse(s)?;
            let key_bytes = cs.decrypt_symmetric(vault_keys)?;
            let keys = Keys::from_bytes(&key_bytes)?;
            Ok(Some(keys))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_symmetric_with_mac() {
        // Create a valid cipher string by encrypting something
        let key_bytes = [0x42u8; 64];
        let keys = Keys::from_bytes(&key_bytes).unwrap();

        let (iv, ct, mac) = crypto::encrypt_symmetric(&keys, b"test").unwrap();
        let cs_str = format!(
            "2.{}|{}|{}",
            crypto::b64_encode(&iv),
            crypto::b64_encode(&ct),
            crypto::b64_encode(&mac),
        );

        let cs = CipherString::parse(&cs_str).unwrap();
        let plaintext = cs.decrypt_symmetric(&keys).unwrap();
        assert_eq!(plaintext.as_slice(), b"test");
    }

    #[test]
    fn parse_symmetric_without_mac() {
        // Legacy format without MAC
        let key_bytes = [0x42u8; 64];
        let keys = Keys::from_bytes(&key_bytes).unwrap();

        let (iv, ct, _mac) = crypto::encrypt_symmetric(&keys, b"no mac").unwrap();
        let cs_str = format!("2.{}|{}", crypto::b64_encode(&iv), crypto::b64_encode(&ct),);

        let cs = CipherString::parse(&cs_str).unwrap();
        let plaintext = cs.decrypt_symmetric(&keys).unwrap();
        assert_eq!(plaintext.as_slice(), b"no mac");
    }

    #[test]
    fn parse_asymmetric_type4() {
        let cs = CipherString::parse("4.AAAA").unwrap();
        assert!(matches!(cs, CipherString::Asymmetric { .. }));
    }

    #[test]
    fn parse_type6_strips_hmac() {
        let cs = CipherString::parse("6.AAAA|BBBB").unwrap();
        match cs {
            CipherString::Asymmetric { ciphertext } => {
                // Should only contain decoded "AAAA", not "BBBB"
                assert_eq!(ciphertext, vec![0x00, 0x00, 0x00]);
            }
            _ => panic!("expected asymmetric"),
        }
    }

    #[test]
    fn rejects_legacy_types() {
        assert!(CipherString::parse("0.data").is_err());
        assert!(CipherString::parse("1.data").is_err());
        assert!(CipherString::parse("3.data").is_err());
    }

    #[test]
    fn rejects_invalid_format() {
        assert!(CipherString::parse("no_dot").is_err());
        assert!(CipherString::parse("99.data").is_err());
    }

    #[test]
    fn decrypt_field_none_returns_none() {
        let keys = Keys::from_bytes(&[0x42u8; 64]).unwrap();
        let result = decrypt_field(&None, &keys, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn decrypt_field_empty_returns_none() {
        let keys = Keys::from_bytes(&[0x42u8; 64]).unwrap();
        let result = decrypt_field(&Some(String::new()), &keys, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn roundtrip_decrypt_field() {
        let key_bytes = [0x42u8; 64];
        let keys = Keys::from_bytes(&key_bytes).unwrap();

        let (iv, ct, mac) = crypto::encrypt_symmetric(&keys, b"field_value").unwrap();
        let cs_str = format!(
            "2.{}|{}|{}",
            crypto::b64_encode(&iv),
            crypto::b64_encode(&ct),
            crypto::b64_encode(&mac),
        );

        let result = decrypt_field(&Some(cs_str), &keys, None).unwrap();
        assert_eq!(result.as_deref(), Some("field_value"));
    }
}
