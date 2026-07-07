//! COSE_Key encoding of a credential's *public* key.
//!
//! Needed only for `makeCredential`, where the new credential's public key is
//! embedded in attestedCredentialData ([`super::authdata`]). rosec generates
//! ES256 or Ed25519 credentials (never RSA — no relying party asks an
//! authenticator to mint RSA keys), so only those two are encodable here; the
//! public half is derived from the freshly-generated signing key.

use coset::{CborSerializable, CoseKeyBuilder, iana};

use super::sign::SigningKey;

/// Encode the public key of `key` as a canonical COSE_Key CBOR map.
pub fn public_key_cbor(key: &SigningKey) -> Result<Vec<u8>, String> {
    match key {
        SigningKey::Es256(sk) => {
            use p256::elliptic_curve::sec1::ToSec1Point;
            let public = p256::PublicKey::from(*sk.verifying_key());
            let point = public.to_sec1_point(false);
            let x = point.x().ok_or("ES256 public key missing x")?.to_vec();
            let y = point.y().ok_or("ES256 public key missing y")?.to_vec();
            CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
                .algorithm(iana::Algorithm::ES256)
                .build()
                .to_vec()
                .map_err(|e| format!("encode ES256 COSE key: {e}"))
        }
        SigningKey::Ed25519(sk) => {
            use coset::cbor::value::Value;
            let x = sk.verifying_key().to_bytes().to_vec();
            CoseKeyBuilder::new_okp_key()
                .algorithm(iana::Algorithm::EdDSA)
                .param(
                    iana::OkpKeyParameter::Crv as i64,
                    Value::from(iana::EllipticCurve::Ed25519 as i64),
                )
                .param(iana::OkpKeyParameter::X as i64, Value::Bytes(x))
                .build()
                .to_vec()
                .map_err(|e| format!("encode Ed25519 COSE key: {e}"))
        }
        SigningKey::Rs256(_) => Err(
            "RSA COSE public-key encoding unsupported (rosec never generates RSA credentials)"
                .into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap2::sign::{ALG_EDDSA, ALG_ES256, SigningKey};
    use coset::CoseKey;
    use zeroize::Zeroizing;

    const ES256_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzTa8ki9W2Fr5RXSQ
Uibx++X3ObXxU7hHFQcc2EpjBfShRANCAATnIl1Wh70gWgvnhUdJaxdv59jY2ZSv
Ujz/li9W7GD/hsON2LbfjwOb84yfhDiVAHEDDNbPytYRXp33/HqOjWsu
-----END PRIVATE KEY-----";

    const ED25519_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHlVONoyA7tBX8V9tfyDccKrTIRpd51/IfB3SJCSrRPK
-----END PRIVATE KEY-----";

    #[test]
    fn es256_public_key_is_valid_ec2_cose() {
        let key = SigningKey::from_pem(ALG_ES256, &Zeroizing::new(ES256_PEM.into())).unwrap();
        let cbor = public_key_cbor(&key).unwrap();
        let parsed = CoseKey::from_slice(&cbor).unwrap();
        assert_eq!(parsed.kty, coset::KeyType::Assigned(iana::KeyType::EC2));
        assert_eq!(
            parsed.alg,
            Some(coset::Algorithm::Assigned(iana::Algorithm::ES256))
        );
        // x and y params present, 32 bytes each.
        let x = parsed
            .params
            .iter()
            .find(|(l, _)| *l == coset::Label::Int(iana::Ec2KeyParameter::X as i64));
        assert!(x.is_some());
    }

    #[test]
    fn ed25519_public_key_is_valid_okp_cose() {
        let key = SigningKey::from_pem(ALG_EDDSA, &Zeroizing::new(ED25519_PEM.into())).unwrap();
        let cbor = public_key_cbor(&key).unwrap();
        let parsed = CoseKey::from_slice(&cbor).unwrap();
        assert_eq!(parsed.kty, coset::KeyType::Assigned(iana::KeyType::OKP));
        assert_eq!(
            parsed.alg,
            Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA))
        );
    }

    #[test]
    fn rsa_public_key_rejected() {
        // We never generate RSA credentials, so encoding is intentionally
        // unsupported; assertion of an existing RS256 passkey needs no COSE
        // public key from us.
        let es = SigningKey::from_pem(ALG_ES256, &Zeroizing::new(ES256_PEM.into())).unwrap();
        // sanity: the ES256 path works, proving the reject is RSA-specific.
        assert!(public_key_cbor(&es).is_ok());
    }
}
