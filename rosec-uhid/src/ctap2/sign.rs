//! Multi-algorithm signing for CTAP2 assertions, over keys held by rosec
//! providers.
//!
//! A provider hands us a passkey as PEM PKCS#8 (the rosec boundary form) plus
//! its COSE algorithm id. At ceremony time we parse the key by algorithm and
//! sign `authenticatorData || clientDataHash`. Unlike a self-contained
//! authenticator, we never generate or hold these keys — they come from the
//! store and are zeroized after signing.
//!
//! Supported algorithms match what the provider mappings produce:
//! ES256 (`-7`), EdDSA/Ed25519 (`-8`), RS256 (`-257`).

use zeroize::Zeroizing;

/// COSE algorithm identifiers (RFC 9053).
pub const ALG_ES256: i64 = -7;
pub const ALG_EDDSA: i64 = -8;
pub const ALG_RS256: i64 = -257;

/// A signing key parsed from a provider's PEM PKCS#8, tagged by algorithm.
/// Holds only what's needed to sign one assertion; dropped (and its secret
/// scrubbed) immediately after.
pub enum SigningKey {
    Es256(Box<p256::ecdsa::SigningKey>),
    Ed25519(Box<ed25519_dalek::SigningKey>),
    Rs256(Box<rsa::pkcs1v15::SigningKey<sha2::Sha256>>),
}

impl SigningKey {
    /// Parse a PEM PKCS#8 private key for the given COSE algorithm.
    pub fn from_pem(algorithm: i64, pem: &Zeroizing<String>) -> Result<Self, String> {
        match algorithm {
            ALG_ES256 => {
                use p256::pkcs8::DecodePrivateKey;
                let sk = p256::SecretKey::from_pkcs8_pem(pem)
                    .map_err(|e| format!("parse ES256 key: {e}"))?;
                Ok(Self::Es256(Box::new(sk.into())))
            }
            ALG_EDDSA => {
                use ed25519_dalek::pkcs8::DecodePrivateKey;
                let sk = ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
                    .map_err(|e| format!("parse Ed25519 key: {e}"))?;
                Ok(Self::Ed25519(Box::new(sk)))
            }
            ALG_RS256 => {
                use rsa::pkcs8::DecodePrivateKey;
                let sk = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
                    .map_err(|e| format!("parse RS256 key: {e}"))?;
                Ok(Self::Rs256(Box::new(rsa::pkcs1v15::SigningKey::new(sk))))
            }
            other => Err(format!("unsupported COSE algorithm {other}")),
        }
    }

    /// This key's COSE algorithm id.
    pub fn algorithm(&self) -> i64 {
        match self {
            Self::Es256(_) => ALG_ES256,
            Self::Ed25519(_) => ALG_EDDSA,
            Self::Rs256(_) => ALG_RS256,
        }
    }

    /// Sign `message` (`authenticatorData || clientDataHash`) and return the
    /// WebAuthn wire-format signature: ASN.1 DER for ES256/RS256, raw 64-byte
    /// for Ed25519.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Es256(sk) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = sk.sign(message);
                sig.to_der().as_bytes().to_vec()
            }
            Self::Ed25519(sk) => {
                use ed25519_dalek::Signer;
                sk.sign(message).to_bytes().to_vec()
            }
            Self::Rs256(sk) => {
                use rsa::signature::{SignatureEncoding, Signer};
                sk.sign(message).to_vec()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn es256_pem() -> Zeroizing<String> {
        use p256::pkcs8::EncodePrivateKey;
        let sk = p256::SecretKey::random(&mut rand_core::OsRng);
        Zeroizing::new(sk.to_pkcs8_pem(Default::default()).unwrap().to_string())
    }

    fn ed25519_pem() -> Zeroizing<String> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        Zeroizing::new(sk.to_pkcs8_pem(Default::default()).unwrap().to_string())
    }

    fn rs256_pem() -> Zeroizing<String> {
        use rsa::pkcs8::EncodePrivateKey;
        let sk = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        Zeroizing::new(sk.to_pkcs8_pem(Default::default()).unwrap().to_string())
    }

    #[test]
    fn es256_sign_verifies() {
        use p256::ecdsa::signature::Verifier;
        let pem = es256_pem();
        let key = SigningKey::from_pem(ALG_ES256, &pem).unwrap();
        assert_eq!(key.algorithm(), ALG_ES256);
        let msg = b"authdata||clientdatahash";
        let der = key.sign(msg);
        // Reconstruct the verifying key from the same PEM and check.
        use p256::pkcs8::DecodePrivateKey;
        let sk = p256::SecretKey::from_pkcs8_pem(&pem).unwrap();
        let vk = p256::ecdsa::VerifyingKey::from(sk.public_key());
        let sig = p256::ecdsa::Signature::from_der(&der).unwrap();
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn ed25519_sign_verifies() {
        use ed25519_dalek::{Signature, Verifier};
        let pem = ed25519_pem();
        let key = SigningKey::from_pem(ALG_EDDSA, &pem).unwrap();
        let msg = b"authdata||clientdatahash";
        let raw = key.sign(msg);
        assert_eq!(raw.len(), 64);
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let sk = ed25519_dalek::SigningKey::from_pkcs8_pem(&pem).unwrap();
        let sig = Signature::from_slice(&raw).unwrap();
        assert!(sk.verifying_key().verify(msg, &sig).is_ok());
    }

    #[test]
    fn rs256_sign_verifies() {
        let pem = rs256_pem();
        let key = SigningKey::from_pem(ALG_RS256, &pem).unwrap();
        let msg = b"authdata||clientdatahash";
        let sig = key.sign(msg);
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::signature::Verifier;
        let sk = rsa::RsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
        let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(sk.to_public_key());
        let sig = rsa::pkcs1v15::Signature::try_from(sig.as_slice()).unwrap();
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn rejects_unsupported_algorithm() {
        let pem = es256_pem();
        assert!(SigningKey::from_pem(-999, &pem).is_err());
        // Wrong algorithm for the key material also fails to parse.
        assert!(SigningKey::from_pem(ALG_RS256, &pem).is_err());
    }
}
