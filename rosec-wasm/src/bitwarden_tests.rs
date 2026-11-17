//! Run with the production Bitwarden guest built first:
//! cargo test -p rosec-wasm bitwarden_sync -- --ignored

use super::*;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use aes::Aes256;
use base64::engine::general_purpose::STANDARD;
use block_padding::Pkcs7;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

const PASSWORD: &str = "fixture-password";
const EMAIL: &str = "sync@example.invalid";

fn encrypt(keys: &[u8; 64], text: &[u8]) -> String {
    let iv = [7; 16];
    let body = cbc::Encryptor::<Aes256>::new_from_slices(&keys[..32], &iv)
        .unwrap()
        .encrypt_padded_vec::<Pkcs7>(text);
    let mut mac = Hmac::<Sha256>::new_from_slice(&keys[32..]).unwrap();
    mac.update(&iv);
    mac.update(&body);
    format!(
        "2.{}|{}|{}",
        STANDARD.encode(iv),
        STANDARD.encode(body),
        STANDARD.encode(mac.finalize().into_bytes())
    )
}

fn fixture() -> (Value, Value) {
    // Cheap, deterministic KDF parameters are confined to this fixture server.
    let mut master = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(PASSWORD.as_bytes(), EMAIL.as_bytes(), 1, &mut master);
    let hkdf = hkdf::Hkdf::<Sha256>::from_prk(&master).unwrap();
    let mut identity = [0; 64];
    hkdf.expand(b"enc", &mut identity[..32]).unwrap();
    hkdf.expand(b"mac", &mut identity[32..]).unwrap();
    let vault = [42; 64];
    let login = json!({
        "access_token": "initial-access", "refresh_token": "initial-refresh",
        "key": encrypt(&identity, &vault)
    });
    let sync = json!({"profile": {}, "ciphers": [{
        "id": "fixture-item", "type": 1,
        "name": encrypt(&vault, b"Fixture login"),
        "login": {"password": encrypt(&vault, b"fixture-secret")}
    }]});
    (login, sync)
}

enum Reply {
    Json(u16, Value),
    Disconnect,
    Partial,
    StallHeaders(Value),
    StallBody(Value),
}

struct Step {
    path: &'static str,
    body_contains: &'static str,
    reply: Reply,
}

fn sync_step(reply: Reply) -> Step {
    Step {
        path: "/api/sync",
        body_contains: "",
        reply,
    }
}

fn refresh_step(reply: Reply) -> Step {
    Step {
        path: "/identity/connect/token",
        body_contains: "refresh_token=initial-refresh",
        reply,
    }
}

fn initial_steps(login: Value, sync: &Value) -> VecDeque<Step> {
    VecDeque::from([
        Step {
            path: "/identity/accounts/prelogin",
            body_contains: EMAIL,
            reply: Reply::Json(200, json!({"kdf": 0, "kdfIterations": 1})),
        },
        Step {
            path: "/identity/connect/token",
            body_contains: "grant_type=password",
            reply: Reply::Json(200, login),
        },
        sync_step(Reply::Json(200, sync.clone())),
    ])
}

struct Server {
    url: String,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn new(mut steps: VecDeque<Step>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let (mut socket, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                    assert!(header.len() < 8192);
                }
                let header = String::from_utf8(header).unwrap();
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(length < 8192);
                let mut body = vec![0; length];
                socket.read_exact(&mut body).unwrap();
                let step = steps.pop_front().expect("unexpected HTTP request");
                assert_eq!(header.split_whitespace().nth(1).unwrap(), step.path);
                assert!(
                    String::from_utf8(body)
                        .unwrap()
                        .contains(step.body_contains)
                );
                match step.reply {
                    Reply::Json(status, body) => {
                        let body = body.to_string();
                        write!(socket, "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                    }
                    Reply::Disconnect => {}
                    Reply::Partial => {
                        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nX-Fixture: partial\r\nConnection: close\r\n\r\n{\"partial\":").unwrap();
                    }
                    Reply::StallHeaders(body) => {
                        // Leave margin for kernel socket-timeout granularity.
                        std::thread::sleep(Duration::from_secs(12));
                        let body = body.to_string();
                        // The response would succeed if the request deadline
                        // were removed. Broken pipes are expected after timeout.
                        let _ = write!(
                            socket,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                    }
                    Reply::StallBody(body) => {
                        let body = body.to_string();
                        write!(
                            socket,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            &body[..1]
                        )
                        .unwrap();
                        std::thread::sleep(Duration::from_secs(12));
                        let _ = socket.write_all(&body.as_bytes()[1..]);
                    }
                }
                if steps.is_empty() {
                    return;
                }
            }
            assert!(steps.is_empty(), "fixture requests were not completed");
        });
        Self {
            url,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let result = self.thread.take().unwrap().join();
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

async fn unlocked(server: &Server) -> WasmProvider {
    let wasm = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rosec-bitwarden-pm/target/wasm32-wasip1/release/rosec_bitwarden_pm.wasm");
    let mut provider = WasmProvider::new(WasmProviderConfig {
        id: "bitwarden-sync-fixture".into(),
        name: "Fixture".into(),
        kind: "bitwarden-pm".into(),
        wasm_path: wasm.display().to_string(),
        wasm_bytes: Arc::new(std::fs::read(wasm).expect("build the Bitwarden PM WASM guest first")),
        // The hostname gates HTTP destinations; the URL also grants the
        // ephemeral fixture port in the worker's Landlock ruleset.
        allowed_hosts: vec!["127.0.0.1".into(), server.url.clone()],
        allowed_paths: vec![],
        allowed_files: vec![],
        options: HashMap::from([
            ("email".into(), json!(EMAIL)),
            ("base_url".into(), json!(server.url)),
            (
                "device_id".into(),
                json!("00000000-0000-0000-0000-000000000001"),
            ),
        ]),
        offline_cache: false,
        tls_mode: rosec_core::config::TlsMode::Bundled,
        tls_mode_probe: rosec_core::config::TlsMode::Bundled,
        unlock_timeout_secs: 30,
    })
    .unwrap();
    // Exercise the production guest's password login while avoiding host-side
    // credential persistence and unrelated readiness/notification requests.
    provider.readiness_probes.clear();
    provider.capabilities = &[Capability::Sync];
    let response: SimpleResponse = provider
        .worker
        .call_json("unlock", json!({"password": PASSWORD}))
        .await
        .unwrap();
    assert!(response.ok, "{response:?}");
    assert_accessible(&provider).await;
    provider
}

async fn assert_accessible(provider: &WasmProvider) {
    assert!(!provider.status().await.unwrap().locked);
    let secret = provider
        .get_secret_attr("fixture-item", "password")
        .await
        .unwrap();
    assert_eq!(secret.as_slice(), b"fixture-secret");
}

#[tokio::test]
#[ignore = "requires the compiled Bitwarden PM WASM guest; run in provider CI"]
async fn bitwarden_sync_transport_recovery() {
    let (login, sync) = fixture();
    let mut steps = initial_steps(login, &sync);
    for fault in [
        Reply::Disconnect,
        Reply::Partial,
        Reply::StallHeaders(sync.clone()),
        Reply::StallBody(sync.clone()),
        Reply::Json(429, json!({})),
        Reply::Json(503, json!({})),
    ] {
        steps.push_back(sync_step(fault));
        steps.push_back(sync_step(Reply::Json(200, sync.clone())));
    }
    let server = Server::new(steps);
    let provider = unlocked(&server).await;
    for fault in 0..6 {
        let result = provider.sync().await;
        assert!(
            matches!(result, Err(ProviderError::Unavailable(_))),
            "fault {fault}: {result:?}"
        );
        assert_accessible(&provider).await;
        assert!(provider.status().await.unwrap().cached);
        provider.sync().await.unwrap();
        assert_accessible(&provider).await;
        assert!(!provider.status().await.unwrap().cached);
    }
    provider.lock().await.unwrap();
    assert!(provider.status().await.unwrap().locked);
    assert!(matches!(
        provider.get_secret_attr("fixture-item", "password").await,
        Err(ProviderError::Locked)
    ));
}

#[tokio::test]
#[ignore = "requires the compiled Bitwarden PM WASM guest; run in provider CI"]
async fn bitwarden_sync_refresh_recovery() {
    let (login, sync) = fixture();
    let mut steps = initial_steps(login, &sync);
    for fault in [
        Reply::Disconnect,
        Reply::Partial,
        Reply::Json(429, json!({"error": "invalid_grant"})),
        Reply::Json(503, json!({"error": "invalid_grant"})),
    ] {
        steps.push_back(sync_step(Reply::Json(401, json!({}))));
        steps.push_back(refresh_step(fault));
    }
    steps.push_back(sync_step(Reply::Json(401, json!({}))));
    // Recover through the same refresh credential without another password login.
    steps.push_back(refresh_step(Reply::Json(
        200,
        json!({"access_token": "new-access"}),
    )));
    steps.push_back(sync_step(Reply::Json(200, sync)));
    let server = Server::new(steps);
    let provider = unlocked(&server).await;
    for _ in 0..4 {
        assert!(matches!(
            provider.sync().await,
            Err(ProviderError::Unavailable(_))
        ));
        assert_accessible(&provider).await;
        assert!(provider.status().await.unwrap().cached);
    }
    provider.sync().await.unwrap();
    assert_accessible(&provider).await;
    assert!(!provider.status().await.unwrap().cached);
}

#[tokio::test]
#[ignore = "requires the compiled Bitwarden PM WASM guest; run in provider CI"]
async fn bitwarden_sync_rejected_refresh_requires_unlock() {
    let (login, sync) = fixture();
    let mut steps = initial_steps(login, &sync);
    steps.push_back(sync_step(Reply::Json(401, json!({}))));
    steps.push_back(refresh_step(Reply::Json(
        400,
        json!({"error": "invalid_grant"}),
    )));
    let server = Server::new(steps);
    let provider = unlocked(&server).await;
    assert!(matches!(
        provider.sync().await,
        Err(ProviderError::AuthFailed)
    ));
    // The daemon locks on AuthFailed; verify that the provider still obeys it.
    provider.lock().await.unwrap();
    assert!(provider.status().await.unwrap().locked);
    assert!(matches!(
        provider.get_secret_attr("fixture-item", "password").await,
        Err(ProviderError::Locked)
    ));
}
