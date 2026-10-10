//! Exercises the actual WASM guest, file host functions and shared TOTP engine.
//! Build the guest first, then run `cargo test -p rosec-wasm keepassxc_totp -- --ignored`.

use std::{
    fs::File,
    path::Path,
    time::{Duration, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use extism::{Manifest, Plugin, Wasm};
use serde_json::{Value, json};

fn call(plugin: &mut Plugin, name: &str, input: Value) -> Value {
    let output = plugin.call::<_, Vec<u8>>(name, input.to_string()).unwrap();
    serde_json::from_slice(&output).unwrap()
}

fn save(bytes: &[u8], path: &Path, timestamp: u64) {
    std::fs::write(path, bytes).unwrap();
    let file = File::options().write(true).open(path).unwrap();
    // Deterministic mtime changes without sleeping for the guest's seconds clock.
    file.set_modified(UNIX_EPOCH + Duration::from_secs(timestamp))
        .unwrap();
}

#[test]
#[ignore = "requires the compiled keepassxc-file WASM guest; run in the WASM CI job"]
fn keepassxc_totp_roundtrip() {
    let wasm = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rosec-keepassxc-file/target/wasm32-wasip1/release/rosec_keepassxc_file.wasm");
    assert!(wasm.exists(), "build the keepassxc-file WASM guest first");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("totp.kdbx");
    let uri = "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=8&period=30";
    save(include_bytes!("../tests/fixtures/totp.kdbx"), &path, 100);

    let allowed = [path.clone()];
    let mut functions = crate::host_file::build_file_host_functions(&allowed);
    let (watch_functions, _events) = crate::host_watch::build_watch_host_functions(&allowed);
    functions.extend(watch_functions);
    let mut plugin = Plugin::new(Manifest::new([Wasm::file(wasm)]), functions, true).unwrap();
    let caps = call(&mut plugin, "capabilities", json!(null));
    assert!(
        caps["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "Totp")
    );
    assert_eq!(
        call(
            &mut plugin,
            "init",
            json!({
                "provider_id": "test-kdbx", "provider_name": "Test", "options": {"path": path}
            })
        )["ok"],
        true
    );
    assert_eq!(
        call(&mut plugin, "unlock", json!({"password": "test-password"}))["ok"],
        true
    );
    let found = call(
        &mut plugin,
        "search",
        json!({"attributes": {"rosec:totp": "true"}}),
    );
    assert_eq!(found["items"].as_array().unwrap().len(), 3);
    for item in found["items"].as_array().unwrap() {
        let id = item["id"].as_str().unwrap();
        let attrs = call(&mut plugin, "get_item_attributes", json!({"id": id}));
        assert_eq!(attrs["public"]["rosec:totp"], "true");
        assert!(!attrs["public"].to_string().contains("GEZDGNBV"));
        assert!(!attrs["public"].to_string().contains("63BEDWCQ"));
        assert!(attrs["public"].get("otp").is_none());
        assert!(
            attrs["secret_names"]
                .as_array()
                .unwrap()
                .iter()
                .any(|n| n == "totp")
        );
        let secret = call(
            &mut plugin,
            "get_secret_attr",
            json!({"id": id, "attr": "totp"}),
        );
        let bytes = STANDARD
            .decode(secret["value_b64"].as_str().unwrap())
            .unwrap();
        // Same parser/generator used by GetTotpCode (CLI) and the TOTP FUSE tree.
        let params = rosec_core::totp::parse_totp_input(&bytes).unwrap();
        let (timestamp, expected) = if item["label"] == "Steam" {
            (1511200518, "FR8RV") // KeePassXC Steam Guard vector
        } else {
            assert_eq!(bytes, uri.as_bytes());
            (59, "94287082") // RFC 6238 SHA1 vector
        };
        let code =
            rosec_core::totp::generate_code(&params, UNIX_EPOCH + Duration::from_secs(timestamp))
                .unwrap();
        assert_eq!(code.as_str(), expected);
    }

    // Saving an edited seed must update the value served by the guest.
    let updated = "otpauth://totp/Test:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=60";
    save(
        include_bytes!("../tests/fixtures/totp-updated.kdbx"),
        &path,
        200,
    );
    plugin
        .call::<_, Vec<u8>>(
            "on_path_changed",
            json!({"path": path, "kind": "modify"}).to_string(),
        )
        .unwrap();
    let id = found["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["label"] == "TOTP true")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let secret = call(
        &mut plugin,
        "get_secret_attr",
        json!({"id": id, "attr": "totp"}),
    );
    assert_eq!(
        STANDARD
            .decode(secret["value_b64"].as_str().unwrap())
            .unwrap(),
        updated.as_bytes()
    );
    assert_eq!(call(&mut plugin, "lock", json!(null))["ok"], true);
    assert_eq!(
        call(
            &mut plugin,
            "get_secret_attr",
            json!({"id": id, "attr": "totp"})
        )["ok"],
        false
    );
    assert_eq!(
        call(&mut plugin, "unlock", json!({"password": "wrong-password"}))["ok"],
        false
    );
}
