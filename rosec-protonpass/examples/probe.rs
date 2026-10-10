// SPDX-License-Identifier: GPL-3.0-or-later
//! Run the actual guest with synthetic encrypted API responses, or a PAT on stdin.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use extism::{Manifest, Plugin, Wasm};
use protobuf::{Message, MessageField};
use rosec_protonpass::{crypto, upstream::item_v1};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;

fn call(p: &mut Plugin, name: &str, input: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let input = Zeroizing::new(serde_json::to_vec(&input)?);
    let bytes = Zeroizing::new(p.call::<&[u8], Vec<u8>>(name, &input)?);
    Ok(serde_json::from_slice(&bytes)?)
}
fn seal(plain: &[u8], key: &[u8], aad: &[u8], nonce: u8) -> String {
    // Fixed nonces and keys are synthetic fixtures only.
    let mut data = vec![nonce; 12];
    data.extend(
        Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt(Nonce::from_slice(&[nonce; 12]), Payload { msg: plain, aad })
            .unwrap(),
    );
    STANDARD.encode(data)
}
fn fixture(updated: bool, with_passkey: bool) -> Value {
    let mut item = item_v1::Item::new();
    let mut meta = item_v1::Metadata::new();
    meta.name = "WASM fixture".into();
    meta.note = "synthetic-private-note".into();
    item.metadata = MessageField::some(meta);
    let mut login = item_v1::ItemLogin::new();
    login.password = if updated {
        "synthetic-updated-password"
    } else {
        "synthetic-password"
    }
    .into();
    login.item_username = "fixture-user".into();
    login.totp_uri =
        "otpauth://totp/fixture?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30".into();
    if with_passkey {
        let key = p256::SecretKey::from_slice(&[7; 32]).unwrap();
        let public = key.public_key().to_sec1_bytes();
        let inner = json!({"key":{"kty":{"t":"assign","c":"EC2"},"alg":{"t":"assign","c":"ES256"},"par":[
            [{"t":"int","c":-1},{"t":"int","c":{"inner":1i128.to_le_bytes().to_vec()}}],
            [{"t":"int","c":-2},{"t":"bytes","c":public[1..33]}],
            [{"t":"int","c":-3},{"t":"bytes","c":public[33..]}],
            [{"t":"int","c":-4},{"t":"bytes","c":vec![7;32]}]
        ]},"cid":[1,2,3],"rid":"example.test","uhd":[4,5],"cnt":null});
        login.passkeys.push(item_v1::Passkey {
            credential_id: vec![1, 2, 3],
            rp_id: "example.test".into(),
            content: rmp_serde::to_vec_named(
                &json!({"v":1,"c":rmp_serde::to_vec_named(&inner).unwrap()}),
            )
            .unwrap(),
            ..Default::default()
        });
    }
    let mut content = item_v1::Content::new();
    content.content = Some(item_v1::content::Content::Login(login));
    item.content = MessageField::some(content);
    json!({"ItemID":"item1","State":1,"ContentFormatVersion":rosec_protonpass::ITEM_CONTENT_FORMAT_VERSION,"KeyRotation":1,
        "ItemKey":seal(&[3;32],&[2;32],crypto::ITEM_KEY,2),
        "Content":seal(&item.write_to_bytes().unwrap(),&[3;32],crypto::ITEM_CONTENT,3)})
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|a| a == "--check-production") {
        let wasm = std::env::var("PROTONPASS_WASM")
            .map_err(|_| "PROTONPASS_WASM must point to a build without test-http")?;
        let mut plugin = Plugin::new(
            Manifest::new([Wasm::file(wasm)]).with_timeout(Duration::from_secs(5)),
            [],
            true,
        )?;
        assert!(!plugin.function_exists("test_refresh"));
        for endpoint in [
            "http://127.0.0.1:8080",
            "http://127.0.0.1:80@evil.invalid",
            "https://evil.invalid",
        ] {
            assert_eq!(
                call(&mut plugin, "init", json!({"options":{"api_url":endpoint}}))?["ok"],
                false
            );
            assert_eq!(call(&mut plugin, "status", Value::Null)?["locked"], true);
        }
        assert_eq!(
            call(&mut plugin, "init", json!({"options":{}}))?["ok"],
            true
        );
        println!("PASS: production WASM rejects test/foreign endpoints; no HTTP requests made");
        return Ok(());
    }
    let bench = std::env::args().any(|a| a == "--bench");
    let live = std::env::args().any(|a| a == "--live");
    if bench && live {
        return Err("Benchmarks must use synthetic data".into());
    }
    let check_fixture = std::env::args().any(|a| a == "--check-fixture");
    let mode = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(AtomicUsize::new(0));
    let (api, pat, server) = if live {
        let mut pat = Zeroizing::new(String::new());
        std::io::stdin().take(4096).read_to_string(&mut pat)?;
        ("https://pass-api.proton.me".to_owned(), pat, None)
    } else {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let api = format!("http://{}", listener.local_addr()?);
        let (mode, stop, requests) = (Arc::clone(&mode), Arc::clone(&stop), Arc::clone(&requests));
        let server = std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut data = Vec::new();
                let mut buf = [0; 4096];
                loop {
                    let n = stream.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    data.extend_from_slice(&buf[..n]);
                    if let Some(pos) = data.windows(4).position(|x| x == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&data[..pos]);
                        let len = headers
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|x| x.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if data.len() >= pos + 4 + len {
                            break;
                        }
                    }
                    assert!(data.len() < 65536);
                }
                // TCP readiness probes connect and close without an HTTP request.
                if data.is_empty() {
                    continue;
                }
                let text = String::from_utf8(data).unwrap();
                assert!(
                    !text.contains(&URL_SAFE_NO_PAD.encode([1; 32])),
                    "PAT key must stay local"
                );
                requests.fetch_add(1, Ordering::SeqCst);
                let path = text
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap();
                let current = mode.load(Ordering::SeqCst);
                let (status, body) = if path == "/account/v4/personal-access-token/session" {
                    (
                        200,
                        if current == 8 {
                            json!({"Session":[]})
                        } else {
                            json!({"Session":{"SessionUID":"synthetic-uid","AccessToken":"synthetic-access","RefreshToken":"synthetic-refresh"}})
                        },
                    )
                } else if path == "/core/v4/auth" {
                    assert!(text.starts_with("DELETE "));
                    (200, json!({"Code":1000}))
                } else if current == 2 {
                    (401, json!({"Error":"synthetic revocation"}))
                } else if current == 10 {
                    (403, json!({"Error":"synthetic permission denial"}))
                } else if current == 11 {
                    (503, json!({"Error":"synthetic outage"}))
                } else if path == "/auth/v4/refresh" {
                    assert_eq!(current, 9);
                    assert!(text.contains("synthetic-refresh"));
                    assert!(text.contains("refresh_token"));
                    mode.store(0, Ordering::SeqCst);
                    (
                        200,
                        json!({"UID":"synthetic-uid", "AccessToken":"rotated-access", "RefreshToken":"rotated-refresh"}),
                    )
                } else if current == 9 {
                    (401, json!({"Error":"synthetic expiry"}))
                } else if path == "/pass/v1/share" {
                    (
                        200,
                        json!({"Shares":vec![json!({"ShareID":"share1","TargetType":1,"GroupID":null}); if current==7 {33} else {1}]}),
                    )
                } else if path.starts_with("/pass/v1/share/share1/key?") {
                    (
                        200,
                        json!({"ShareKeys":{"Keys":[{"KeyRotation":1,"Key":seal(&[2;32],&[1;32],crypto::SHARE_KEY,1)}],"Total":1}}),
                    )
                } else if path.starts_with("/pass/v1/share/share1/folder?") {
                    let folder = rosec_protonpass::upstream::folder_v1::Folder {
                        name: "Test folder".into(),
                        ..Default::default()
                    };
                    (
                        200,
                        json!({"Folders":{"Folders":[{"FolderID":"folder1","ParentFolderID":null,"KeyRotation":1,
                        "FolderKey":seal(&[4;32], &[2;32],rosec_protonpass::folders::FOLDER_KEY,4),"ContentFormatVersion":1,
                        "Content":seal(&folder.write_to_bytes().unwrap(), &[4;32],rosec_protonpass::folders::FOLDER_CONTENT,5)}],"LastToken":null}}),
                    )
                } else if path.starts_with("/pass/v1/share/share1/item?") {
                    let mut item = fixture(current == 3, current == 14);
                    if current == 12 {
                        item["FolderID"] = json!("folder1");
                        item["ItemKey"] = json!(seal(&[3; 32], &[4; 32], crypto::ITEM_KEY, 6));
                    }
                    if current == 13 {
                        let mut special = item_v1::Item::new();
                        special.metadata = MessageField::some(item_v1::Metadata {
                            name: "SSH fixture".into(),
                            ..Default::default()
                        });
                        special.content = MessageField::some(item_v1::Content {
                            content: Some(item_v1::content::Content::SshKey(item_v1::ItemSSHKey {
                                public_key: "ssh-ed25519 fixture".into(),
                                private_key: "synthetic-ssh-private".into(),
                                ..Default::default()
                            })),
                            ..Default::default()
                        });
                        item["Content"] = json!(seal(
                            &special.write_to_bytes().unwrap(),
                            &[3; 32],
                            crypto::ITEM_CONTENT,
                            7
                        ));
                    }
                    if current == 1 {
                        item["Content"] = json!(STANDARD.encode([0; 64]));
                    }
                    let start = path
                        .split("Since=")
                        .nth(1)
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(0);
                    let items = if current == 4 {
                        Vec::new()
                    } else if bench {
                        (start..start + 100)
                            .map(|n| {
                                let mut row = item.clone();
                                row["ItemID"] = json!(format!("item{n:05}"));
                                row
                            })
                            .collect()
                    } else if current == 5 {
                        vec![item.clone(), item]
                    } else if current == 6 {
                        vec![item; 101]
                    } else {
                        vec![item]
                    };
                    let next = if bench && start + 100 < 1000 {
                        Some((start + 100).to_string())
                    } else {
                        None
                    };
                    (
                        200,
                        json!({"Items":{"RevisionsData":items,"LastToken":next}}),
                    )
                } else {
                    panic!("Unexpected fixture API path");
                };
                let body = body.to_string();
                write!(stream,"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        (
            api,
            Zeroizing::new(format!(
                "pst_{}::{}",
                "x".repeat(64),
                URL_SAFE_NO_PAD.encode([1; 32])
            )),
            Some(server),
        )
    };
    let wasm = std::env::var_os("PROTONPASS_WASM")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/wasm32-wasip1/release/rosec_protonpass.wasm")
        });
    let host = if live {
        "pass-api.proton.me"
    } else {
        "127.0.0.1"
    };
    let manifest = Manifest::new([Wasm::file(wasm)])
        .with_allowed_host(host)
        .with_timeout(Duration::from_secs(30));
    let mut p = Plugin::new(manifest, [], true)?;
    assert_eq!(
        call(&mut p, "init", json!({"options":{"api_url":api}}))?["ok"],
        true
    );
    let descriptor = call(&mut p, "plugin_manifest", Value::Null)?;
    assert_eq!(descriptor["kind"], "protonpass");
    assert_eq!(descriptor["experimental"], true);
    assert_eq!(
        call(&mut p, "auth_fields", Value::Null)?["fields"],
        json!([])
    );
    let auth = call(&mut p, "registration_info", Value::Null)?;
    assert_eq!(auth["has_registration"], true);
    assert_eq!(
        call(&mut p, "unlock", json!({"password":"test"}))?["error_kind"],
        "registration_required"
    );
    assert_eq!(auth["fields"][0]["id"], "personal_access_token");
    // Password-kind would make the host use the PAT as the local passphrase,
    // removing it from the additional fields passed to the guest.
    assert_eq!(auth["fields"][0]["kind"], "secret");
    let caps = call(&mut p, "capabilities", Value::Null)?;
    assert_eq!(
        caps["capabilities"],
        json!(["Sync", "Totp", "Ssh", "Fido2", "OfflineCache"])
    );
    let unlock = json!({"password":"ephemeral-test-only","auth_fields":{"personal_access_token":pat.trim()}});
    let result = call(&mut p, "unlock", unlock)?;
    if result["ok"] != true {
        // Guest errors are fixed messages, never API response bodies or credentials.
        eprintln!(
            "Guest status: {}",
            result["error"].as_str().unwrap_or("Unknown failure")
        );
        return Err("Guest authentication/sync failed (response withheld)".into());
    }
    let list = call(&mut p, "list_items", Value::Null)?;
    let count = list["items"].as_array().ok_or("Missing items")?.len();
    println!("Guest authenticated; synchronized {count} items");
    if bench {
        assert_eq!(count, 1000);
        let mut samples = Vec::new();
        for _ in 0..50 {
            call(
                &mut p,
                "get_item_attributes",
                json!({"id":"share1/item00999"}),
            )?;
        }
        for _ in 0..1000 {
            let start = std::time::Instant::now();
            let result = call(
                &mut p,
                "get_item_attributes",
                json!({"id":"share1/item00999"}),
            )?;
            assert_eq!(result["ok"], true);
            samples.push(start.elapsed().as_nanos());
        }
        samples.sort();
        println!(
            "BENCH items=1000 lookup_samples=1000 p50_ns={} p95_ns={}",
            samples[500], samples[950]
        );
        let before = requests.load(Ordering::SeqCst);
        let start = std::time::Instant::now();
        assert_eq!(call(&mut p, "sync", Value::Null)?["ok"], true);
        println!(
            "BENCH full_sync_ms={} requests={}",
            start.elapsed().as_millis(),
            requests.load(Ordering::SeqCst) - before
        );
        stop.store(true, Ordering::SeqCst);
        if let Some(server) = server {
            server.join().unwrap();
        }
        return Ok(());
    }
    if live && std::env::var_os("PROTONPASS_TEST_REFRESH").is_some() {
        let refreshed = call(&mut p, "test_refresh", Value::Null)?;
        if refreshed["ok"] != true {
            eprintln!(
                "Guest status: {}",
                refreshed["error"].as_str().unwrap_or("Unknown failure")
            );
            return Err("Live refresh failed".into());
        }
        assert_eq!(
            call(&mut p, "sync", Value::Null)?["ok"],
            true,
            "Live sync after refresh failed"
        );
        println!("PASS: live session refresh and subsequent sync");
    }
    if live && check_fixture {
        if count != 1 || list["items"][0]["label"] != "rosec WASM live fixture" {
            return Err("Dedicated live fixture was not found".into());
        }
        let id = list["items"][0]["id"]
            .as_str()
            .ok_or("Missing fixture ID")?;
        let password = call(
            &mut p,
            "get_secret_attr",
            json!({"id":id,"attr":"password"}),
        )?;
        let password = Zeroizing::new(
            STANDARD.decode(password["value_b64"].as_str().ok_or("Missing password")?)?,
        );
        if password.as_slice() != b"rosec-synthetic-live-password" {
            return Err("Live password mismatch".into());
        }
        let secret = call(&mut p, "get_secret_attr", json!({"id":id,"attr":"totp"}))?;
        let uri =
            Zeroizing::new(STANDARD.decode(secret["value_b64"].as_str().ok_or("Missing TOTP")?)?);
        let params = rosec_core::totp::parse_totp_input(&uri)?;
        if rosec_core::totp::generate_code(
            &params,
            std::time::UNIX_EPOCH + Duration::from_secs(59),
        )?
        .as_str()
            != "94287082"
        {
            return Err("Live TOTP vector mismatch".into());
        }
        let public = list.to_string();
        if public.contains("rosec-synthetic-live-password") || public.contains("GEZDGNBV") {
            return Err("Secret appeared in metadata".into());
        }
        if call(&mut p, "sync", Value::Null)?["ok"] != true {
            return Err("Live resync failed".into());
        }
        println!("PASS: live fixture password, TOTP vector, metadata separation and resync");
    }
    if !live {
        assert_eq!(count, 1);
        let serialized = list.to_string();
        for secret in ["synthetic-password", "synthetic-private-note", "GEZDGNBV"] {
            assert!(!serialized.contains(secret));
        }
        let attrs = call(&mut p, "get_item_attributes", json!({"id":"share1/item1"}))?;
        assert!(
            attrs["secret_names"]
                .as_array()
                .unwrap()
                .contains(&json!("totp"))
        );
        let secret = call(
            &mut p,
            "get_secret_attr",
            json!({"id":"share1/item1","attr":"totp"}),
        )?;
        let uri = STANDARD.decode(secret["value_b64"].as_str().unwrap())?;
        let params = rosec_core::totp::parse_totp_input(&uri)?;
        assert_eq!(
            rosec_core::totp::generate_code(
                &params,
                std::time::UNIX_EPOCH + Duration::from_secs(59)
            )?
            .as_str(),
            "94287082"
        );
        assert_eq!(
            call(
                &mut p,
                "search",
                json!({"attributes":{"rosec:totp":"true"}})
            )?["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        // Round-trip the real WASM snapshot, then reject tampering and lock.
        let cache = call(&mut p, "export_cache", Value::Null)?;
        assert_eq!(cache["ok"], true);
        assert!(
            !String::from_utf8(STANDARD.decode(cache["blob_b64"].as_str().unwrap())?)?
                .contains("synthetic-access")
        );
        assert_eq!(call(&mut p, "lock", Value::Null)?["ok"], true);
        assert_eq!(
            call(
                &mut p,
                "restore_cache",
                json!({"blob_b64":cache["blob_b64"]})
            )?["ok"],
            true
        );
        assert_eq!(
            call(&mut p, "list_items", Value::Null)?["items"],
            list["items"]
        );
        assert_eq!(
            call(&mut p, "sync", Value::Null)?["error_kind"],
            "unavailable"
        );
        assert_eq!(
            call(&mut p, "restore_cache", json!({"blob_b64":"invalid"}))?["ok"],
            false
        );
        assert_eq!(call(&mut p, "status", Value::Null)?["locked"], true);
        assert_eq!(
            call(
                &mut p,
                "unlock",
                json!({"password":"test","auth_fields":{"personal_access_token":pat.as_str()}})
            )?["ok"],
            true
        );
        let before = requests.load(Ordering::SeqCst);
        for operation in [
            "create_item",
            "update_item",
            "delete_item",
            "change_password",
        ] {
            assert_eq!(
                call(&mut p, operation, json!({}))?["error_kind"],
                "not_supported"
            );
        }
        assert_eq!(requests.load(Ordering::SeqCst), before);
        assert_eq!(call(&mut p, "sync", Value::Null)?["ok"], true);
        mode.store(12, Ordering::SeqCst);
        assert_eq!(call(&mut p, "sync", Value::Null)?["ok"], true);
        assert_eq!(
            call(&mut p, "get_item_attributes", json!({"id":"share1/item1"}))?["public"]["folder"],
            "Test folder"
        );
        mode.store(13, Ordering::SeqCst);
        assert_eq!(call(&mut p, "sync", Value::Null)?["ok"], true);
        assert_eq!(
            call(&mut p, "list_ssh_keys", Value::Null)?["keys"][0]["item_id"],
            "share1/item1"
        );
        assert_eq!(
            call(
                &mut p,
                "get_ssh_private_key",
                json!({"item_id":"share1/item1"})
            )?["pem"],
            "synthetic-ssh-private"
        );
        assert_eq!(
            call(&mut p, "get_ssh_private_key", json!({"item_id":"other"}))?["error_kind"],
            "not_found"
        );
        mode.store(14, Ordering::SeqCst);
        assert_eq!(call(&mut p, "sync", Value::Null)?["ok"], true);
        let credentials = call(&mut p, "list_fido2_credentials", Value::Null)?;
        assert_eq!(credentials["credentials"][0]["credential_id"], "AQID");
        assert!(!credentials.to_string().contains("PRIVATE KEY"));
        let material = call(
            &mut p,
            "get_fido2_key",
            json!({"item_id":"share1/item1","credential_id":"AQID"}),
        )?;
        use p256::{
            ecdsa::{
                Signature, SigningKey,
                signature::{Signer, Verifier},
            },
            pkcs8::DecodePrivateKey,
        };
        let signing = SigningKey::from_pkcs8_pem(material["pem"].as_str().unwrap())?;
        let assertion = [42; 69];
        let signature: Signature = signing.sign(&assertion);
        signing.verifying_key().verify(&assertion, &signature)?;
        assert_eq!(
            call(
                &mut p,
                "get_fido2_key",
                json!({"item_id":"other","credential_id":"AQID"})
            )?["error_kind"],
            "not_found"
        );
        mode.store(3, Ordering::SeqCst);
        assert_eq!(call(&mut p, "sync", Value::Null)?["ok"], true);
        let changed = call(
            &mut p,
            "get_secret_attr",
            json!({"id":"share1/item1","attr":"password"}),
        )?;
        assert_eq!(
            STANDARD.decode(changed["value_b64"].as_str().unwrap())?,
            b"synthetic-updated-password"
        );
        mode.store(4, Ordering::SeqCst);
        assert_eq!(call(&mut p, "sync", Value::Null)?["ok"], true);
        assert_eq!(call(&mut p, "list_items", Value::Null)?["items"], json!([]));
        assert_eq!(
            call(
                &mut p,
                "get_secret_attr",
                json!({"id":"share1/item1","attr":"password"})
            )?["error_kind"],
            "not_found"
        );
        mode.store(1, Ordering::SeqCst);
        assert_eq!(call(&mut p, "sync", Value::Null)?["ok"], false);
        assert_eq!(
            call(
                &mut p,
                "get_secret_attr",
                json!({"id":"share1/item1","attr":"totp"})
            )?["error_kind"],
            "locked"
        );
        mode.store(0, Ordering::SeqCst);
        assert_eq!(
            call(
                &mut p,
                "unlock",
                json!({"password":"test","registration_fields":{"personal_access_token":pat.as_str()}})
            )?["ok"],
            true
        );
        mode.store(9, Ordering::SeqCst);
        let before = requests.load(Ordering::SeqCst);
        assert_eq!(call(&mut p, "sync", Value::Null)?["ok"], true);
        assert_eq!(
            requests.load(Ordering::SeqCst) - before,
            5,
            "one refresh and one retried share request"
        );
        for (failure, kind) in [(10, "auth_failed"), (11, "unavailable")] {
            mode.store(failure, Ordering::SeqCst);
            let before = requests.load(Ordering::SeqCst);
            assert_eq!(call(&mut p, "sync", Value::Null)?["error_kind"], kind);
            assert_eq!(
                requests.load(Ordering::SeqCst) - before,
                2,
                "failure plus logout; no refresh retry"
            );
            assert_eq!(call(&mut p, "status", Value::Null)?["locked"], true);
            mode.store(0, Ordering::SeqCst);
            assert_eq!(
                call(
                    &mut p,
                    "unlock",
                    json!({"password":"test", "registration_fields":{"personal_access_token":pat.as_str()}})
                )?["ok"],
                true
            );
        }
        // A rejected re-authentication must not keep the prior session unlocked.
        assert_eq!(call(&mut p, "unlock", json!({"password":""}))?["ok"], false);
        assert_eq!(call(&mut p, "status", Value::Null)?["locked"], true);
        assert_eq!(
            call(
                &mut p,
                "unlock",
                json!({"password":"test","auth_fields":{"personal_access_token":pat.as_str()}})
            )?["ok"],
            true
        );
        for bad in [
            Value::Null,
            json!([]),
            json!({"password":3}),
            json!({"password":"x","registration_fields":[]}),
        ] {
            assert_eq!(call(&mut p, "unlock", bad)?["ok"], false);
            assert_eq!(call(&mut p, "status", Value::Null)?["locked"], true);
        }
        for bad_mode in [5, 6, 7, 8] {
            mode.store(bad_mode, Ordering::SeqCst);
            assert_eq!(
                call(
                    &mut p,
                    "unlock",
                    json!({"password":"test","auth_fields":{"personal_access_token":pat.as_str()}})
                )?["ok"],
                false
            );
            assert_eq!(call(&mut p, "status", Value::Null)?["locked"], true);
        }
        mode.store(0, Ordering::SeqCst);
        assert_eq!(
            call(
                &mut p,
                "unlock",
                json!({"password":"test","auth_fields":{"personal_access_token":pat.as_str()}})
            )?["ok"],
            true
        );
        assert_eq!(
            call(
                &mut p,
                "init",
                json!({"options":{"api_url":"http://127.0.0.1:80@evil.invalid"}})
            )?["ok"],
            false
        );
        assert_eq!(call(&mut p, "status", Value::Null)?["locked"], true);
        assert_eq!(
            call(&mut p, "init", json!({"options":{"api_url":api}}))?["ok"],
            true
        );
        assert_eq!(
            call(
                &mut p,
                "unlock",
                json!({"password":"test","auth_fields":{"personal_access_token":pat.as_str()}})
            )?["ok"],
            true
        );
        mode.store(2, Ordering::SeqCst);
        assert_eq!(call(&mut p, "sync", Value::Null)?["ok"], false);
        assert_eq!(call(&mut p, "status", Value::Null)?["locked"], true);
    }
    call(&mut p, "lock", Value::Null)?;
    assert_eq!(
        call(&mut p, "list_items", Value::Null)?["error_kind"],
        "locked"
    );
    if !live {
        mode.store(0, Ordering::SeqCst);
        host_cache_probe(&api, &pat, &stop)?;
    }
    stop.store(true, Ordering::SeqCst);
    if let Some(server) = server {
        server.join().unwrap();
    }
    if live {
        println!(
            "PASS: live guest authentication, sync and local lock; fixture-only assertions were not run"
        );
    } else {
        println!(
            "PASS: compiled WASM, HTTP, decryption, metadata separation, TOTP, sync changes/deletions, malformed input, limits, lock and read-only boundary"
        );
    }
    Ok(())
}

fn host_cache_probe(
    api: &str,
    pat: &str,
    stop: &AtomicBool,
) -> Result<(), Box<dyn std::error::Error>> {
    use rosec_core::{Provider, UnlockInput};
    use rosec_wasm::{WasmProvider, WasmProviderConfig};
    let directory = tempfile::tempdir()?;
    // This standalone test process has no other environment readers.
    unsafe {
        std::env::set_var("XDG_DATA_HOME", directory.path());
    }
    let wasm_path = std::env::var("PROTONPASS_WASM")?;
    let config = WasmProviderConfig {
        id: "proton-fixture".into(),
        name: "Proton fixture".into(),
        kind: "protonpass".into(),
        wasm_bytes: Arc::new(std::fs::read(&wasm_path)?),
        wasm_path,
        allowed_hosts: vec!["127.0.0.1".into(), api.trim_start_matches("http://").into()],
        allowed_paths: vec![],
        allowed_files: vec![],
        options: std::collections::HashMap::from([("api_url".into(), json!(api))]),
        offline_cache: true,
        tls_mode: rosec_core::config::TlsMode::Bundled,
        tls_mode_probe: rosec_core::config::TlsMode::Bundled,
        unlock_timeout_secs: 60,
    };
    tokio::runtime::Runtime::new()?.block_on(async {
        let provider = WasmProvider::new(config.clone())?;
        provider
            .unlock(UnlockInput::WithRegistration {
                password: Zeroizing::new("fixture-passphrase".into()),
                registration_fields: std::collections::HashMap::from([(
                    "personal_access_token".into(),
                    Zeroizing::new(pat.into()),
                )]),
            })
            .await?;
        let items = provider.list_items().await?;
        assert_eq!(items.len(), 1);
        provider.lock().await?;
        drop(provider);
        let provider = WasmProvider::new(config)?;
        assert!(
            provider
                .unlock(UnlockInput::Password(Zeroizing::new("wrong".into())))
                .await
                .is_err()
        );
        provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "fixture-passphrase".into(),
            )))
            .await?;
        provider.lock().await?;
        // Stop the network source: readiness now fails and the host must decrypt
        // the persisted snapshot, rather than use an in-memory guest session.
        stop.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            provider
                .unlock(UnlockInput::Password(Zeroizing::new("wrong".into())))
                .await
                .is_err()
        );
        provider
            .unlock(UnlockInput::Password(Zeroizing::new(
                "fixture-passphrase".into(),
            )))
            .await?;
        assert!(provider.status().await?.cached);
        let secret = provider.get_secret_attr(&items[0].id, "password").await?;
        assert_eq!(secret.as_slice(), b"synthetic-password");
        provider.lock().await?;
        assert!(
            provider
                .get_secret_attr(&items[0].id, "password")
                .await
                .is_err()
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    println!("PASS: real host registration, restart, wrong password, offline fallback and lock");
    Ok(())
}
