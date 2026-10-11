// SPDX-License-Identifier: GPL-3.0-or-later
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rosec_protonpass::{crypto, parse_pat};

#[test]
fn authenticates_all_layers_and_rejects_tampering() {
    let key = [7u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let mut bytes = vec![9u8; 12];
    bytes.extend(
        cipher
            .encrypt(
                &Nonce::from([9; 12]),
                Payload {
                    msg: b"synthetic",
                    aad: crypto::ITEM_CONTENT,
                },
            )
            .unwrap(),
    );
    assert_eq!(
        crypto::decrypt(&bytes, &key, crypto::ITEM_CONTENT)
            .unwrap()
            .as_slice(),
        b"synthetic"
    );
    assert!(crypto::decrypt(&bytes, &key, crypto::ITEM_KEY).is_err());
    assert!(crypto::decrypt(&bytes, &[8; 32], crypto::ITEM_CONTENT).is_err());
    assert!(crypto::decrypt(&bytes, &[8; 16], crypto::ITEM_CONTENT).is_err());
    for size in 0..28 {
        assert!(crypto::decrypt(&bytes[..size], &key, crypto::ITEM_CONTENT).is_err());
    }
    bytes[15] ^= 1;
    assert!(crypto::decrypt(&bytes, &key, crypto::ITEM_CONTENT).is_err());
}

#[test]
fn pat_validation_never_echoes_credentials() {
    let pat = format!(
        "pst_{}::{}",
        "x".repeat(64),
        URL_SAFE_NO_PAD.encode([1; 32])
    );
    let (token, key) = parse_pat(&pat).unwrap();
    assert_eq!(token.len(), 68);
    assert_eq!(key.len(), 32);
    for bad in [
        "sensitive".to_owned(),
        format!("pst_{}::bad", "x".repeat(64)),
        format!(
            "pst_{}::{}",
            "x".repeat(64),
            URL_SAFE_NO_PAD.encode([1; 31])
        ),
    ] {
        let error = parse_pat(&bad).err().unwrap();
        assert!(!error.contains(&bad));
    }
}
