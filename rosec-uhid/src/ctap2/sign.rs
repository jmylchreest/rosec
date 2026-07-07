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

    // Static throwaway PKCS#8 test keys (openssl-generated), one per
    // algorithm. Fixed vectors test the real production path (from_pem +
    // sign + verify) without depending on the signing crates' in-test
    // key-generation APIs.
    const ES256_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzTa8ki9W2Fr5RXSQ
Uibx++X3ObXxU7hHFQcc2EpjBfShRANCAATnIl1Wh70gWgvnhUdJaxdv59jY2ZSv
Ujz/li9W7GD/hsON2LbfjwOb84yfhDiVAHEDDNbPytYRXp33/HqOjWsu
-----END PRIVATE KEY-----";

    const ED25519_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHlVONoyA7tBX8V9tfyDccKrTIRpd51/IfB3SJCSrRPK
-----END PRIVATE KEY-----";

    const RS256_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDTSFFPHtuz6YHr
EvYhBnJPVOVE5fL0IdjRKFLQfuQGtwDE76ZRPon5R1vN6D6u+b1jvYV00uxNhIL2
Y/gjqZbU5J1EyDNKW0gcpt2EPgm6pTHM+fc3u7aZssdQAw0FWqePmSTqXWdyKNKQ
pgd9s+z92LMDGsFxDvXBao64E57kNzc7Hj8qNENZ+H/YFPvlzSeUqJdErroFVMzR
CZCv4vQe1QysdL4pvRG4wiwLX25im8gKvgGDRzZz9BW/BPTRVucwARjiCKS3IzMN
cOmF0KO0XTJjBbMCut8ZRb0vDOVZGChg9Cpzn5zh5B4fFzSG79Wg4a7LMUA52iSG
WVPp8YG5AgMBAAECggEADBDNyLJSPG4x8IyIdVuN4zPnVLQhCyOnr+h/ZwK031R+
41nTakGJ1ZK0QaHPepfIFgF4gcxnZdUS0yLjkWQzUq/fjB8Dg6DxqrLPMai6G4H1
jxqAE+gdxgQGPjtLK6qBD47gvQJdtvcLCoTaWdzD972MgFMV1IpuXf/jOJkX2NNB
aJ43BYm4a+5tW2vfEuGmGpBMZYvSEWNb83RbgwASPWOfjovilb3CtZB1gcWD9e4M
9tx/ZbWP/DXqvxn1cL0DUbSK9wBQYv4hPUqyg5piCSmusdX3+mAusX00l0ijmHT7
pY8pH62zSn0dHUtaJIlT8qAY704tE6CxGlTzxoiWRQKBgQD0L2LPmPueA8B0QiqK
jAsr9VT6CO7inIBnl/ejM1lGS5JCmDS4qq2vEPM6XEAHjbv2x8WvHP7dKYhB9lXf
HJmBnwMcbJ9TJbTCiJbRaxdJ9fpSV8WKZkoEJ2+nEmV8Qew3EECQ+Ru6eG701rNF
E9YVekUdvrtgCJK8II7yTb61ZwKBgQDdgWGiqqEuFPJdg4cI9ZF8tYeWpm1qn3eQ
mjFlDjGFLUXtBU7sjic6CzK5OSfY2p6HSM6pSGhTsoIBixoAI6EBkZp/fh7Q/jkc
hS9A+W7iyIPow4+1dDIuUkadg4OojAfOSKuzRulMfW49IeOuArK7YSyKheEk+hg6
piOY2G973wKBgDhIm9wCBS1c7AVgIvIgaYrOV7HyUS3GqQo3ywrBETjUvne/IZfX
L4WEwKuZC+Ex2Dt/vJ8qbcyIgDHEF/L/YpqwDkWE/AxsSof0d975cjrICdTlClFm
VnUyqde2s9G6WDow8tD3ul522AxzWIr5kYUN09SRXBs8nqXiU1CifuzNAoGBAKHw
WhoblvTiuYJmi02ggvnimTspd2rxJO+h2yTfaJLN04aCT/4fu0vzLeU+hQREaIvN
TdFzL1qpceSA9sRNSAOmmIZHBW6Tvds8/5wH/+pq4A1HFAR768fzvM6hfJq3rWlB
tc2+tQeH2BV3dkYckODvHSo00LJA6X/PQM0YxwCPAoGBAORwoV3E5gXS6aXMBQgW
0bF2M4rl0zcc3E1yJ36EKHS/4fSJkWBm2Hy9j8ODFhoxWVzsOSEu1d9lrxDCDQ2i
VQ4FO+CFpXPP1PZ+hJBJAEh6x0N3B/LDcclEuY9cYRrMNFql90Hnh6YnWUQGXyDc
iZjQhvXs1XDEnxX1YxWPZa/H
-----END PRIVATE KEY-----";

    fn es256_pem() -> Zeroizing<String> {
        Zeroizing::new(ES256_PEM.to_string())
    }
    fn ed25519_pem() -> Zeroizing<String> {
        Zeroizing::new(ED25519_PEM.to_string())
    }
    fn rs256_pem() -> Zeroizing<String> {
        Zeroizing::new(RS256_PEM.to_string())
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
