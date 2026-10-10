// SPDX-License-Identifier: GPL-3.0-or-later
use p256::{
    ecdsa::{
        Signature, SigningKey,
        signature::{Signer, Verifier},
    },
    pkcs8::DecodePrivateKey,
};
use rosec_protonpass::{passkey, upstream::item_v1::Passkey};
use serde_json::{Value, json};

fn fixture() -> (Passkey, Value) {
    let secret = p256::SecretKey::from_slice(&[7; 32]).unwrap();
    let public = secret.public_key().to_sec1_bytes();
    let p = Passkey {
        credential_id: vec![1, 2, 3],
        rp_id: "example.test".into(),
        ..Default::default()
    };
    let inner = json!({"key":{"kty":{"t":"assign","c":"EC2"},"alg":{"t":"assign","c":"ES256"},"par":[
        [{"t":"int","c":-1},{"t":"int","c":{"inner":1i128.to_le_bytes().to_vec()}}],
        [{"t":"int","c":-2},{"t":"bytes","c":public[1..33]}],
        [{"t":"int","c":-3},{"t":"bytes","c":public[33..]}],
        [{"t":"int","c":-4},{"t":"bytes","c":vec![7;32]}]
    ]},"cid":[1,2,3],"rid":"example.test","uhd":[4,5],"cnt":null});
    (p, inner)
}
fn pack(p: &mut Passkey, inner: &Value) {
    p.content =
        rmp_serde::to_vec_named(&json!({"v":1,"c":rmp_serde::to_vec_named(inner).unwrap()}))
            .unwrap();
}
#[test]
fn proton_es256_key_signs_verifiable_assertion() {
    let (mut p, inner) = fixture();
    pack(&mut p, &inner);
    let decoded = passkey::decode(&p).unwrap();
    assert_eq!(decoded.algorithm, -7);
    assert_eq!(decoded.credential_id, "AQID");
    let signing = SigningKey::from_pkcs8_pem(&decoded.pem).unwrap();
    let assertion = [42; 69];
    let signature: Signature = signing.sign(&assertion);
    signing
        .verifying_key()
        .verify(&assertion, &signature)
        .unwrap();
}
#[test]
fn reject_metadata_key_curve_counter_and_version_mismatches() {
    let (mut p, inner) = fixture();
    for (pointer, value) in [
        ("/rid", json!("evil.test")),
        ("/cid", json!([9])),
        ("/cnt", json!(1)),
        ("/cnt", json!(-1)),
        ("/cnt", json!("0")),
        ("/cnt", json!(0.5)),
        ("/key/par/1/1/c", json!(vec![0; 32])),
        ("/key/kty/c", json!("RSA")),
    ] {
        let mut broken = inner.clone();
        *broken.pointer_mut(pointer).unwrap() = value;
        pack(&mut p, &broken);
        assert!(passkey::decode(&p).is_err());
    }
    p.content = rmp_serde::to_vec_named(&json!({"v":2,"c":[]})).unwrap();
    assert!(matches!(
        passkey::decode(&p),
        Err("Unsupported passkey format")
    ));
}

#[test]
fn proton_ed25519_key_signs_verifiable_assertion() {
    use ed25519_dalek::{Signature as EdSignature, SigningKey as EdKey};
    let (mut p, mut inner) = fixture();
    let key = EdKey::from_bytes(&[8; 32]);
    inner["key"] = json!({"kty":{"t":"assign","c":"OKP"},"alg":{"t":"assign","c":"EdDSA"},"par":[
        [{"t":"int","c":-1},{"t":"int","c":{"inner":6i128.to_le_bytes().to_vec()}}],
        [{"t":"int","c":-2},{"t":"bytes","c":key.verifying_key().as_bytes().to_vec()}],
        [{"t":"int","c":-4},{"t":"bytes","c":vec![8;32]}]
    ]});
    pack(&mut p, &inner);
    let decoded = passkey::decode(&p).unwrap();
    assert_eq!(decoded.algorithm, -8);
    let signing = EdKey::from_pkcs8_pem(&decoded.pem).unwrap();
    let signature: EdSignature = signing.sign(b"assertion");
    key.verifying_key()
        .verify(b"assertion", &signature)
        .unwrap();
}
