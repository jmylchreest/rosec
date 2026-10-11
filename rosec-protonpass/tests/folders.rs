// SPDX-License-Identifier: GPL-3.0-or-later
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use protobuf::Message;
use rosec_protonpass::{
    folders::{self, Revision},
    upstream::folder_v1,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;
fn seal(bytes: &[u8], key: &[u8], aad: &[u8]) -> String {
    let mut out = vec![0; 12];
    out.extend(
        Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt(&Nonce::from([0; 12]), Payload { msg: bytes, aad })
            .unwrap(),
    );
    STANDARD.encode(out)
}
fn revision(id: &str, parent: Option<&str>, key: u8, wrapping: u8) -> Revision {
    let data = folder_v1::Folder {
        name: id.into(),
        ..Default::default()
    }
    .write_to_bytes()
    .unwrap();
    Revision {
        id: id.into(),
        parent: parent.map(str::to_owned),
        key_rotation: 1,
        content_format_version: 1,
        folder_key: seal(&[key; 32], &[wrapping; 32], folders::FOLDER_KEY),
        content: seal(&data, &[key; 32], folders::FOLDER_CONTENT),
    }
}
#[test]
fn nested_out_of_order_folders_resolve_and_validate_aead() {
    let keys = BTreeMap::from([(1, Zeroizing::new(vec![1; 32]))]);
    let folders = folders::open(
        vec![
            revision("child", Some("parent"), 3, 2),
            revision("parent", None, 2, 1),
        ],
        &keys,
    )
    .unwrap();
    assert_eq!(folders["child"].key.as_slice(), &[3; 32]);
    assert_eq!(folders["child"].path, "parent/child");
    assert!(folders::open(vec![revision("bad", None, 2, 9)], &keys).is_err());
}
#[test]
fn cycles_dangling_duplicate_and_wrong_format_fail() {
    let keys = BTreeMap::from([(1, Zeroizing::new(vec![1; 32]))]);
    for rows in [
        vec![
            revision("a", Some("b"), 2, 1),
            revision("b", Some("a"), 3, 2),
        ],
        vec![revision("a", Some("missing"), 2, 1)],
        vec![revision("a", None, 2, 1), revision("a", None, 3, 1)],
    ] {
        assert!(folders::open(rows, &keys).is_err());
    }
    let mut r = revision("a", None, 2, 1);
    r.content_format_version = 2;
    assert!(folders::open(vec![r], &keys).is_err());
}
