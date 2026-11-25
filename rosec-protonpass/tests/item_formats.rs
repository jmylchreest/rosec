// SPDX-License-Identifier: GPL-3.0-or-later
//! Each synthetic item was encoded with the pinned Proton AG schema beside it.
//! The checked-in payloads keep ordinary Cargo tests independent of protoc.
//! Regenerate from the provider directory with:
//!
//! ```sh
//! for fixture in tests/fixtures/item-formats/v?; do
//!   protoc --proto_path="$fixture" --encode=proton_pass_item_v1.Item \
//!     "$fixture/item-v1.proto" < "$fixture/item.textproto" > "$fixture/item.bin"
//! done
//! ```

use protobuf::Message;
use rosec_protonpass::mapping::{Entry, map_item_with_version};
use rosec_protonpass::upstream::item_v1::{Item, ItemLogin, content::Content};

fn map_fixture(version: u8, payload: &[u8]) -> Entry {
    let id = format!("fixture/v{version}");
    let entry = map_item_with_version(id.clone(), payload, u64::from(version))
        .unwrap_or_else(|error| panic!("content format {version} failed to map: {error}"));
    assert_eq!(entry.id, id);
    assert_eq!(entry.label, format!("Format {version}"));
    assert_eq!(entry.secrets["notes"].as_str(), "synthetic note");
    entry
}

fn assert_login(entry: &Entry) {
    assert_eq!(entry.public["rosec:type"], "login");
    assert_eq!(entry.public["uri"], "https://fixture.example");
    assert_eq!(entry.secrets["password"].as_str(), "synthetic password");
}

fn assert_legacy_login(entry: &Entry) {
    assert_login(entry);
    assert_eq!(entry.public["username"], "legacy-user");
    assert_eq!(entry.public["email"], "");
}

fn decode_wire_login(payload: &[u8]) -> ItemLogin {
    let mut item = Item::parse_from_bytes(payload).unwrap();
    let Some(Content::Login(login)) = item.content.take().unwrap().content else {
        panic!("expected a login payload");
    };
    login
}

fn assert_passkey(entry: &Entry) {
    let [passkey] = entry.passkeys.as_slice() else {
        panic!("expected one fixture passkey");
    };
    assert_eq!(passkey.credential_id, "AQID");
    assert_eq!(passkey.rp_id, "fixture.example");
    assert_eq!(passkey.user_handle.as_deref(), Some("BAU"));
    assert_eq!(passkey.algorithm, -8);
}

#[test]
fn item_format_v1() {
    // https://github.com/ProtonMail/WebClients/blob/29b81dab99e3bb2df023e83850f81347f9f5945e/packages/pass/protos/item-v1.proto
    let payload = include_bytes!("fixtures/item-formats/v1/item.bin");
    assert_legacy_login(&map_fixture(1, payload));
}

#[test]
fn item_format_v2() {
    // https://github.com/ProtonMail/WebClients/blob/5ebe554b9a9b3b0612cf1f32c0f0c7d33c4ef61b/packages/pass/types/protobuf/protos/item-v1.proto
    let payload = include_bytes!("fixtures/item-formats/v2/item.bin");
    let entry = map_fixture(2, payload);
    assert_legacy_login(&entry);
    assert_eq!(
        entry.secrets["custom.recovery"].as_str(),
        "synthetic recovery"
    );
}

#[test]
fn item_format_v3() {
    // https://github.com/ProtonMail/WebClients/blob/cb60c1aac840128941eb59913cab1d6693ae5c83/packages/pass/types/protobuf/protos/item-v1.proto
    let payload = include_bytes!("fixtures/item-formats/v3/item.bin");
    let entry = map_fixture(3, payload);
    assert_legacy_login(&entry);
    assert_passkey(&entry);
    let login = decode_wire_login(payload);
    assert_eq!(login.passkeys[0].create_time, 1_700_000_000);
    assert_eq!(login.passkeys[0].credential_id, [1, 2, 3]);
}

#[test]
fn item_format_v4() {
    // https://github.com/ProtonMail/WebClients/blob/e4571b5dc571189e984989a04ddf3b9b7bb728eb/packages/pass/types/protobuf/protos/item-v1.proto
    let payload = include_bytes!("fixtures/item-formats/v4/item.bin");
    let entry = map_fixture(4, payload);
    assert_legacy_login(&entry);
    assert_passkey(&entry);
    let login = decode_wire_login(payload);
    assert_eq!(login.passkeys[0].creation_data.os_name, "Fixture OS");
}

#[test]
fn item_format_v5() {
    // https://github.com/ProtonMail/WebClients/blob/28950603107ee25397c950385869fdc7f8a152fa/packages/pass/types/protobuf/protos/item-v1.proto
    let payload = include_bytes!("fixtures/item-formats/v5/item.bin");
    let entry = map_fixture(5, payload);
    assert_login(&entry);
    assert_eq!(entry.public["email"], "fixture@example.test");
    assert_eq!(entry.public["username"], "fixture-user");
}

#[test]
fn item_format_v6() {
    // https://github.com/ProtonMail/WebClients/blob/4d4049c9b41e503aaf26f8fa4b2d302ab30d0959/packages/pass/types/protobuf/protos/item-v1.proto
    let payload = include_bytes!("fixtures/item-formats/v6/item.bin");
    let entry = map_fixture(6, payload);
    assert_eq!(entry.public["rosec:type"], "identity");
    assert_eq!(entry.secrets["full_name"].as_str(), "Fixture Person");
    assert_eq!(entry.secrets["custom.work.desk"].as_str(), "synthetic desk");
}

#[test]
fn item_format_v7() {
    // https://github.com/ProtonMail/WebClients/blob/61858d08ac1842cdd4eb1e16b7690279a38193cb/packages/pass/types/protobuf/protos/item-v1.proto
    let payload = include_bytes!("fixtures/item-formats/v7/item.bin");
    let entry = map_fixture(7, payload);
    assert_eq!(entry.public["proton_type"], "wifi");
    assert_eq!(entry.public["ssid"], "Fixture Wi-Fi");
    assert_eq!(entry.public["security"], "WPA3");
    assert_eq!(entry.secrets["password"].as_str(), "synthetic password");
    assert_eq!(entry.secrets["custom.created"].as_str(), "1700000000");
}
