//! Bridges the rosec-uhid CTAP2 engine to the daemon: a [`PasskeyStore`] over
//! the live registry + providers, a [`UserGesture`] over rosec-prompt, and the
//! event loop that drives a virtual authenticator device.

use std::sync::Arc;

use async_trait::async_trait;
use data_encoding::BASE64URL_NOPAD;
use rosec_core::config::{PromptConfig, SandboxConfig};
use rosec_secret_service::ServiceState;
use rosec_uhid::ctap2::command::Ctap2Status;
use rosec_uhid::ctap2::cose;
use rosec_uhid::ctap2::engine::{
    ConfirmAction, CreatedCredential, KeyRef, PasskeyStore, StoredCredential, UserGesture,
};
use rosec_uhid::ctap2::message::MakeCredentialRequest;
use rosec_uhid::ctap2::sign::SigningKey;
use tracing::warn;
use zeroize::Zeroizing;

use crate::fido2::Fido2Registry;

/// [`PasskeyStore`] backed by the live [`Fido2Registry`] and the providers.
/// The registry indexes metadata (base64url ids); the engine speaks raw
/// bytes, so this adapter is where the two representations meet.
pub struct RegistryStore {
    state: Arc<ServiceState>,
    registry: Arc<Fido2Registry>,
}

impl RegistryStore {
    pub fn new(state: Arc<ServiceState>, registry: Arc<Fido2Registry>) -> Self {
        Self { state, registry }
    }
}

#[async_trait]
impl PasskeyStore for RegistryStore {
    async fn find(&self, rp_id: &str, allow_ids: &[Vec<u8>]) -> Vec<StoredCredential> {
        let allow_b64: Vec<String> = allow_ids
            .iter()
            .map(|id| BASE64URL_NOPAD.encode(id))
            .collect();
        self.registry
            .find(rp_id, &allow_b64)
            .into_iter()
            .filter_map(|m| {
                // A credential id that won't decode is unusable; skip it
                // rather than surfacing a broken match.
                let credential_id = BASE64URL_NOPAD.decode(m.credential_id.as_bytes()).ok()?;
                let user_handle = m
                    .user_handle
                    .as_deref()
                    .and_then(|h| BASE64URL_NOPAD.decode(h.as_bytes()).ok());
                Some(StoredCredential {
                    credential_id,
                    rp_id: m.rp_id,
                    user_handle,
                    user_name: m.user_name,
                    algorithm: m.algorithm,
                    counter: m.counter,
                    key_ref: KeyRef {
                        provider_id: m.provider_id,
                        item_id: m.item_id,
                    },
                })
            })
            .collect()
    }

    async fn private_key(&self, cred: &StoredCredential) -> Result<Zeroizing<String>, Ctap2Status> {
        let provider = self
            .state
            .provider_by_id(&cred.key_ref.provider_id)
            .ok_or(Ctap2Status::NoCredentials)?;
        let cred_b64 = BASE64URL_NOPAD.encode(&cred.credential_id);
        let material = provider
            .get_fido2_key(&cred.key_ref.item_id, &cred_b64)
            .await
            .map_err(|e| {
                warn!(error = %e, "fido2: fetching private key failed");
                Ctap2Status::Other
            })?;
        Ok(material.pem)
    }

    async fn create(
        &self,
        req: &MakeCredentialRequest,
        algorithm: i64,
    ) -> Result<CreatedCredential, Ctap2Status> {
        let provider = self
            .state
            .fido2_write_provider()
            .ok_or(Ctap2Status::NotAllowed)?;

        // Provider key custody: mint the keypair here, hand the private key to
        // the provider to persist, keep the public half for the response.
        let (key, pem) =
            SigningKey::generate(algorithm).map_err(|_| Ctap2Status::UnsupportedAlgorithm)?;
        let cose_public_key = cose::public_key_cbor(&key).map_err(|_| Ctap2Status::Other)?;
        let credential_id = random_credential_id();

        let new_cred = rosec_vault::NewFido2Credential {
            rp_id: req.rp_id.clone(),
            rp_name: req.rp_name.clone(),
            credential_id: credential_id.clone(),
            user_handle: req.user_id.clone(),
            user_name: req.user_name.clone(),
            user_display_name: req.user_display_name.clone(),
            algorithm,
            discoverable: req.rk,
            require_uv: req.uv,
            private_key_pem: pem,
        };
        let item = rosec_vault::new_item_for_credential(&new_cred);
        provider.create_item(item, false).await.map_err(|e| {
            warn!(error = %e, "fido2: storing new credential failed");
            Ctap2Status::Other
        })?;

        // Refresh the index so this credential is immediately assertable
        // (create_item does not itself fire the items-changed callback).
        self.registry.rebuild(&self.state.fido2_providers()).await;

        Ok(CreatedCredential {
            credential_id,
            cose_public_key,
        })
    }
}

/// 16 random bytes — an opaque, unguessable credential id (WebAuthn permits
/// up to 1023 bytes; 16 is ample and matches common authenticators).
fn random_credential_id() -> Vec<u8> {
    rand::random::<[u8; 16]>().to_vec()
}

/// [`UserGesture`] over rosec-prompt: confirmation for a single credential,
/// the selection list for several. Both count as user presence + verification.
pub struct PromptGesture {
    prompt: String,
    sandbox: SandboxConfig,
    theme: serde_json::Value,
}

impl PromptGesture {
    /// Build from the live prompt config (resolving the `rosec-prompt` binary
    /// beside the daemon; `None` if it can't be found, which fails gestures
    /// closed).
    pub fn from_config(cfg: &PromptConfig, sandbox: SandboxConfig) -> Option<Self> {
        let prompt = crate::ssh::resolve_prompt_binary_for(cfg)?;
        Some(Self {
            prompt,
            sandbox,
            theme: serde_json::to_value(&cfg.theme).unwrap_or_default(),
        })
    }

    /// Spawn rosec-prompt with `request` JSON, returning its stdout on a
    /// success exit (`0`), or `None` on denial / failure / timeout.
    async fn run(&self, request: serde_json::Value) -> Option<String> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let has_display =
            std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();
        let has_tty = std::path::Path::new("/dev/tty").exists();
        if !has_display && !has_tty {
            warn!("fido2: no display or TTY for the prompt, denying");
            return None;
        }

        let mut cmd = tokio::process::Command::new(&self.prompt);
        // SAFETY: setsid() is async-signal-safe and runs post-fork in the child.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        for (k, v) in rosec_core::sandbox::spawn::sandbox_env_for_subprocess(&self.sandbox) {
            cmd.env(k, v);
        }
        if !has_display {
            cmd.arg("--tty");
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "fido2: failed to spawn rosec-prompt, denying");
                return None;
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(request.to_string().as_bytes()).await;
        }
        let mut stdout = child.stdout.take();

        const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
        let status = match tokio::time::timeout(TIMEOUT, child.wait()).await {
            Ok(Ok(s)) => s,
            _ => {
                let _ = child.kill().await;
                return None;
            }
        };
        if !status.success() {
            return None;
        }
        let mut out = String::new();
        if let Some(ref mut s) = stdout {
            let _ = s.read_to_string(&mut out).await;
        }
        Some(out)
    }
}

#[async_trait]
impl UserGesture for PromptGesture {
    async fn confirm(&self, action: ConfirmAction, rp_id: &str, account: &str) -> bool {
        let message = match action {
            ConfirmAction::Register => format!("Create a passkey for {account} on {rp_id}?"),
            ConfirmAction::Authenticate => format!("Allow {account} to sign in to {rp_id}?"),
            ConfirmAction::Select => "Allow a website to use this authenticator?".to_string(),
        };
        let request = serde_json::json!({
            "title": "Passkey request",
            "message": message,
            "confirm_label": "Allow",
            "cancel_label": "Deny",
            "fields": [],
            "confirm_mode": true,
            "theme": self.theme,
        });
        self.run(request).await.is_some()
    }

    async fn select(&self, rp_id: &str, accounts: &[String]) -> Option<usize> {
        let options: Vec<serde_json::Value> = accounts
            .iter()
            .enumerate()
            .map(|(i, a)| serde_json::json!({ "id": i.to_string(), "primary": a, "secondary": "" }))
            .collect();
        let request = serde_json::json!({
            "title": "Choose a passkey",
            "message": format!("Select an account for {rp_id}"),
            "select": { "options": options },
            "theme": self.theme,
        });
        let out = self.run(request).await?;
        let parsed: serde_json::Value = serde_json::from_str(out.trim()).ok()?;
        let id = parsed.get("selected")?.as_str()?;
        let idx: usize = id.parse().ok()?;
        (idx < accounts.len()).then_some(idx)
    }
}

use rosec_uhid::ctap2::command::{self, Command};
use rosec_uhid::ctap2::engine as ceremony;
use rosec_uhid::ctap2::message::GetAssertionRequest;
use rosec_uhid::ctaphid::{
    self, Assembler, Feed, KEEPALIVE_UPNEEDED, Message, error_report, keepalive_report,
    split_message,
};
use rosec_uhid::uhid::{self, Event};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tracing::info;

/// Largest uhid event (a `UHID_CREATE2`); inbound `UHID_OUTPUT` events are
/// smaller but this bounds a single read.
const UHID_EVENT_SIZE: usize = 4380;

/// Connect to the broker, take the virtual authenticator device, and serve
/// CTAP2 ceremonies until the device closes. Returns on any fatal transport
/// error; the caller decides whether to retry.
pub async fn run_event_loop(state: Arc<ServiceState>, registry: Arc<Fido2Registry>) {
    let device =
        match rosec_uhid::client::connect_and_receive(Path::new(rosec_uhid::BROKER_SOCKET_PATH)) {
            Ok(d) => d,
            Err(e) => {
                // Expected and retried (the broker may not be up yet); debug so
                // an idle retry loop doesn't spam warnings every few seconds.
                tracing::debug!(error = %e, "fido2: broker handshake failed, will retry");
                return;
            }
        };
    if let Err(e) = set_nonblocking(&device) {
        warn!(error = %e, "fido2: could not set device non-blocking");
        return;
    }
    let async_fd = match AsyncFd::new(device) {
        Ok(f) => f,
        Err(e) => {
            warn!(error = %e, "fido2: registering device with the reactor failed");
            return;
        }
    };

    let store = RegistryStore::new(Arc::clone(&state), registry);
    let mut assembler = Assembler::default();
    let mut next_cid: u32 = 1;
    info!("fido2: virtual authenticator ready");

    loop {
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                warn!(error = %e, "fido2: device readable() failed; stopping");
                return;
            }
        };
        let mut buf = [0u8; UHID_EVENT_SIZE];
        let n = match guard.try_io(|inner| {
            let mut dev = inner.get_ref();
            dev.read(&mut buf)
        }) {
            Ok(Ok(0)) => {
                info!("fido2: device closed; stopping");
                return;
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                warn!(error = %e, "fido2: device read error; stopping");
                return;
            }
            Err(_would_block) => continue,
        };

        let report = match uhid::parse_event(&buf[..n]) {
            Some(Event::Output(r)) => r,
            // OPEN/CLOSE are client connect/disconnect notifications — the
            // device persists across them (a browser opens and closes it
            // repeatedly). Keep serving; only a read error/EOF ends the loop.
            _ => continue,
        };

        // uhid prefixes the report with its report-id byte (0 — our FIDO
        // device is unnumbered); strip it to get the raw CTAPHID frame.
        let frame: &[u8] = if report.len() > 64 {
            &report[1..]
        } else {
            &report
        };
        match assembler.push(frame) {
            Feed::Incomplete => {}
            Feed::Error { cid, code } => {
                send_report(&async_fd, &error_report(cid, code)).await;
            }
            Feed::Complete(msg) => {
                dispatch(&async_fd, &state, &store, msg, &mut next_cid).await;
            }
        }
    }
}

/// Route one complete CTAPHID message.
async fn dispatch(
    async_fd: &AsyncFd<File>,
    state: &Arc<ServiceState>,
    store: &RegistryStore,
    msg: Message,
    next_cid: &mut u32,
) {
    match msg.cmd {
        ctaphid::CTAPHID_INIT => {
            let cid = *next_cid;
            *next_cid = next_cid.wrapping_add(1).max(1);
            let resp = ctaphid::init_response(msg.cid, &msg.data, cid);
            write_message(async_fd, &resp).await;
        }
        ctaphid::CTAPHID_PING => {
            write_message(async_fd, &msg).await; // echo payload back
        }
        ctaphid::CTAPHID_CBOR => {
            let data = handle_cbor(async_fd, state, store, msg.cid, &msg.data).await;
            write_message(
                async_fd,
                &Message {
                    cid: msg.cid,
                    cmd: ctaphid::CTAPHID_CBOR,
                    data,
                },
            )
            .await;
        }
        _ => {
            send_report(async_fd, &error_report(msg.cid, ctaphid::ERR_INVALID_CMD)).await;
        }
    }
}

/// Execute one CTAP2 command, returning the response bytes (leading status
/// byte + optional CBOR). The ceremonies run under a keepalive so a browser
/// does not time out while the user is at the prompt.
async fn handle_cbor(
    async_fd: &AsyncFd<File>,
    state: &Arc<ServiceState>,
    store: &RegistryStore,
    cid: u32,
    data: &[u8],
) -> Vec<u8> {
    let Some((&cmd_byte, body)) = data.split_first() else {
        return vec![command::Ctap2Status::InvalidLength as u8];
    };
    match Command::from_byte(cmd_byte) {
        Command::GetInfo => {
            let mut r = vec![command::Ctap2Status::Ok as u8];
            r.extend(command::get_info_response());
            r
        }
        Command::GetAssertion => match GetAssertionRequest::decode(body) {
            Ok(req) => {
                let Some(gesture) = build_gesture(state) else {
                    return vec![command::Ctap2Status::OperationDenied as u8];
                };
                let fut = ceremony::get_assertion(&req, store, &gesture);
                match with_keepalive(async_fd, cid, fut).await {
                    Ok(resp) => {
                        let mut r = vec![command::Ctap2Status::Ok as u8];
                        r.extend(resp.encode());
                        r
                    }
                    Err(status) => vec![status as u8],
                }
            }
            Err(status) => vec![status as u8],
        },
        Command::MakeCredential => match MakeCredentialRequest::decode(body) {
            Ok(req) => {
                let Some(gesture) = build_gesture(state) else {
                    return vec![command::Ctap2Status::OperationDenied as u8];
                };
                let fut = ceremony::make_credential(&req, store, &gesture);
                match with_keepalive(async_fd, cid, fut).await {
                    Ok(resp) => {
                        let mut r = vec![command::Ctap2Status::Ok as u8];
                        r.extend(resp.encode());
                        r
                    }
                    Err(status) => vec![status as u8],
                }
            }
            Err(status) => vec![status as u8],
        },
        _ => vec![command::Ctap2Status::InvalidCommand as u8],
    }
}

/// Build a prompt gesture from the live config (picks up hot-reloaded prompt
/// settings each ceremony); `None` if no prompt binary can be resolved.
fn build_gesture(state: &Arc<ServiceState>) -> Option<PromptGesture> {
    let cfg = state.live_config();
    PromptGesture::from_config(&cfg.prompt, cfg.sandbox.clone())
}

/// Drive `fut` while emitting a CTAPHID keepalive every 100 ms, so the browser
/// keeps waiting through the user's prompt interaction (CTAP requires ~100 ms).
async fn with_keepalive<F: std::future::Future>(
    async_fd: &AsyncFd<File>,
    cid: u32,
    fut: F,
) -> F::Output {
    tokio::pin!(fut);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            out = &mut fut => return out,
            _ = tick.tick() => {
                send_report(async_fd, &keepalive_report(cid, KEEPALIVE_UPNEEDED)).await;
            }
        }
    }
}

/// Write a CTAPHID message as one or more `UHID_INPUT2` reports.
async fn write_message(async_fd: &AsyncFd<File>, msg: &Message) {
    for report in split_message(msg) {
        send_report(async_fd, &report).await;
    }
}

/// Send one 64-byte CTAPHID report as a `UHID_INPUT2` event. The report-id is
/// asymmetric for our unnumbered FIDO device: the host prefixes its writes with
/// a report-id byte (stripped on OUTPUT), but reads raw reports, so INPUT2
/// carries the payload with no prefix.
async fn send_report(async_fd: &AsyncFd<File>, report: &[u8]) {
    write_event(async_fd, &uhid::input2_event(report)).await;
}

/// Write one uhid event to the device fd, awaiting writability.
async fn write_event(async_fd: &AsyncFd<File>, bytes: &[u8]) {
    loop {
        let mut guard = match async_fd.writable().await {
            Ok(g) => g,
            Err(e) => {
                warn!(error = %e, "fido2: device writable() failed");
                return;
            }
        };
        match guard.try_io(|inner| {
            let mut dev = inner.get_ref();
            dev.write_all(bytes)
        }) {
            Ok(Ok(())) => return,
            Ok(Err(e)) => {
                warn!(error = %e, "fido2: device write error");
                return;
            }
            Err(_would_block) => continue,
        }
    }
}

fn set_nonblocking(f: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = f.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
