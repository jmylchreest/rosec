//! Real-time notification support via the Bitwarden SignalR hub.
//!
//! The Bitwarden server pushes cipher-update events to connected clients
//! over a SignalR WebSocket.  This module implements a long-lived background
//! task that listens for those events and triggers incremental cache refreshes
//! rather than waiting for the next periodic poll.
//!
//! # Protocol
//!
//! Bitwarden uses the SignalR JSON hub protocol:
//! - Negotiate: `POST {notifications_url}/hub/negotiate?negotiateVersion=1`
//!   with `Authorization: Bearer <jwt>` header
//! - Connect:   `wss://{notifications_host}/hub?access_token=<jwt>`
//! - After HTTP upgrade: JSON handshake `{"protocol":"json","version":1}\x1e`
//! - Messages are `\x1e`-delimited JSON frames.
//!
//! # Events handled
//!
//! | Target                  | Action                                             |
//! |-------------------------|----------------------------------------------------|
//! | `SyncCipherUpdated`     | Call `on_sync` callback (skips if already syncing) |
//! | `SyncCipherCreated`     | "                                                  |
//! | `SyncCipherDeleted`     | "                                                  |
//! | `SyncCiphers`           | "                                                  |
//! | `SyncVault`             | "                                                  |
//! | `SyncFolderCreated`     | "                                                  |
//! | `SyncFolderUpdated`     | "                                                  |
//! | `SyncFolderDeleted`     | "                                                  |
//! | `SyncSettings`          | "                                                  |
//! | `SyncOrgKeys`           | "                                                  |
//! | `LogOut`                | Call `on_lock` callback — lock the vault           |
//!
//! # Lifecycle
//!
//! The task is started by `BitwardenBackend::unlock` and stopped by `lock`.
//! A `tokio::sync::watch` channel is the cancellation token: the sender is
//! owned by `BitwardenBackend`; when `lock` drops the sender the task exits.
//!
//! # Graceful degradation
//!
//! If the initial connection (negotiate + WebSocket upgrade) fails the task
//! logs a warning and exits without affecting vault state.  The existing poll
//! timer takes over as the only sync trigger.  After a successful connection,
//! disconnects trigger reconnect attempts with exponential backoff (max 5 min).

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::watch;
use tracing::{debug, info, trace, warn};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Configuration for the notifications background task.
///
/// Constructed in `BitwardenBackend::unlock` from config + live auth state.
pub struct NotificationsConfig {
    /// Base URL for the notifications service, e.g.
    /// `https://notifications.bitwarden.com`.
    /// The hub path `/hub` is appended automatically.
    pub notifications_url: String,
    /// Current JWT access token — sent as `Authorization: Bearer <jwt>` on
    /// the negotiate POST and as `?access_token=<jwt>` on the WebSocket URL.
    pub access_token: zeroize::Zeroizing<String>,
    /// Backend instance ID (for log messages only).
    pub backend_id: String,
    /// Invoked (from a Tokio task) when the hub signals a cipher change.
    /// Typically calls `ServiceState::try_sync_backend`.
    /// If `None`, sync nudges are silently ignored.
    pub on_sync_nudge: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
    /// Invoked (from a Tokio task) when the hub sends `LogOut`.
    /// Typically calls `ServiceState::auto_lock` for this backend.
    /// If `None`, logout events are silently ignored.
    pub on_lock_nudge: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
    /// Watch receiver used for cancellation: the task exits when the
    /// corresponding sender is dropped (i.e. when the vault is locked).
    pub cancel_rx: watch::Receiver<()>,
}

/// Spawn the notifications background task and return its join handle.
///
/// Returns immediately.  The spawned task runs until `cancel_rx` fires
/// (sender dropped).
pub fn start(config: NotificationsConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(notifications_loop(config))
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// SignalR record separator — every frame is terminated by this byte.
const RS: char = '\x1e';

/// Bitwarden `PushType` enum values (from `server/src/Core/Enums/PushType.cs`).
///
/// The SignalR hub sends all events via a `ReceiveMessage` target with the
/// actual event type as a numeric value in `arguments[0].type`.
mod push_type {
    // Sync events — trigger a vault re-sync.
    pub const SYNC_CIPHER_UPDATE: u32 = 0;
    pub const SYNC_CIPHER_CREATE: u32 = 1;
    pub const SYNC_LOGIN_DELETE: u32 = 2;
    pub const SYNC_FOLDER_DELETE: u32 = 3;
    pub const SYNC_CIPHERS: u32 = 4;
    pub const SYNC_VAULT: u32 = 5;
    pub const SYNC_ORG_KEYS: u32 = 6;
    pub const SYNC_FOLDER_CREATE: u32 = 7;
    pub const SYNC_FOLDER_UPDATE: u32 = 8;
    pub const SYNC_CIPHER_DELETE: u32 = 9;
    pub const SYNC_SETTINGS: u32 = 10;

    // Lock events — lock the vault.
    pub const LOG_OUT: u32 = 11;

    /// All push types that should trigger a sync.
    pub const SYNC_TYPES: &[u32] = &[
        SYNC_CIPHER_UPDATE,
        SYNC_CIPHER_CREATE,
        SYNC_LOGIN_DELETE,
        SYNC_FOLDER_DELETE,
        SYNC_CIPHERS,
        SYNC_VAULT,
        SYNC_ORG_KEYS,
        SYNC_FOLDER_CREATE,
        SYNC_FOLDER_UPDATE,
        SYNC_CIPHER_DELETE,
        SYNC_SETTINGS,
    ];

    /// Human-readable name for logging.
    pub fn name(t: u32) -> &'static str {
        match t {
            SYNC_CIPHER_UPDATE => "SyncCipherUpdate",
            SYNC_CIPHER_CREATE => "SyncCipherCreate",
            SYNC_LOGIN_DELETE => "SyncLoginDelete",
            SYNC_FOLDER_DELETE => "SyncFolderDelete",
            SYNC_CIPHERS => "SyncCiphers",
            SYNC_VAULT => "SyncVault",
            SYNC_ORG_KEYS => "SyncOrgKeys",
            SYNC_FOLDER_CREATE => "SyncFolderCreate",
            SYNC_FOLDER_UPDATE => "SyncFolderUpdate",
            SYNC_CIPHER_DELETE => "SyncCipherDelete",
            SYNC_SETTINGS => "SyncSettings",
            LOG_OUT => "LogOut",
            _ => "Unknown",
        }
    }
}

/// Initial delay before first reconnect attempt after a disconnect.
const BACKOFF_INITIAL: Duration = Duration::from_secs(5);
/// Maximum delay between reconnect attempts.
const BACKOFF_MAX: Duration = Duration::from_secs(300);

/// Minimal SignalR negotiate response — only the fields we care about.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NegotiateResponse {
    connection_id: String,
}

/// Minimal SignalR invocation message.
///
/// The Bitwarden hub uses a single `"ReceiveMessage"` target for all events.
/// The actual event type is a numeric `PushType` inside the first argument.
#[derive(Debug, Deserialize)]
struct Invocation {
    target: Option<String>,
    #[serde(default)]
    arguments: Vec<InvocationArgument>,
}

/// The first argument of a `ReceiveMessage` invocation.
#[derive(Debug, Deserialize)]
struct InvocationArgument {
    /// `PushType` enum value — determines the event kind.
    #[serde(rename = "type")]
    push_type: Option<u32>,
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

async fn notifications_loop(mut config: NotificationsConfig) {
    let backend_id = config.backend_id.clone();
    let mut backoff = BACKOFF_INITIAL;
    let mut is_first_attempt = true;

    loop {
        // Bail out immediately if the vault was locked while we were sleeping.
        if config.cancel_rx.has_changed().is_err() {
            debug!(backend = %backend_id, "notifications: cancellation received, exiting");
            return;
        }

        if !is_first_attempt {
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = config.cancel_rx.changed() => {
                    debug!(backend = %backend_id, "notifications: cancelled during backoff, exiting");
                    return;
                }
            }
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
        is_first_attempt = false;

        match run_session(&mut config).await {
            SessionResult::Cancelled => {
                debug!(backend = %backend_id, "notifications: vault locked, exiting task");
                return;
            }
            SessionResult::Disconnected => {
                info!(
                    backend = %backend_id,
                    next_retry_secs = backoff.as_secs(),
                    "notifications: hub disconnected, will retry"
                );
                // Loop continues — backoff already updated above.
            }
            SessionResult::ConnectFailed(reason) => {
                // First-connect failure: the server likely doesn't support
                // this hub endpoint (old Vaultwarden, aggressive proxy, …).
                // Degrade to poll-only rather than retrying indefinitely.
                let safe_reason = redact_token(&reason);
                warn!(
                    backend = %backend_id,
                    reason = %safe_reason,
                    "notifications: initial connection failed, falling back to poll-only"
                );
                return;
            }
        }
    }
}

enum SessionResult {
    /// Watch channel closed (vault locked) — caller should exit.
    Cancelled,
    /// Connection was established then dropped — caller should retry.
    Disconnected,
    /// Connection could not be established at all — caller should give up.
    ConnectFailed(String),
}

/// Run one hub session.  Returns when cancelled or when the connection drops.
async fn run_session(config: &mut NotificationsConfig) -> SessionResult {
    let backend_id = &config.backend_id;

    // Build the two URLs:
    //   negotiate_url — clean HTTP URL, auth via Bearer header
    //   ws_url        — WebSocket URL with ?access_token= in query string
    //
    // Bitwarden's server requires Bearer on negotiate and ?access_token= on
    // the WS upgrade.  Using separate URLs is why we implement our own minimal
    // SignalR client rather than using the signalr-client crate (which shares
    // a single hub field for both URLs, making this split impossible).
    let (negotiate_url, ws_url) =
        match build_urls(&config.notifications_url, &config.access_token) {
            Ok(pair) => pair,
            Err(e) => return SessionResult::ConnectFailed(e),
        };

    debug!(backend = %backend_id, "notifications: connecting to hub");

    // ------------------------------------------------------------------
    // Step 1: Negotiate — POST to obtain a connectionId.
    // ------------------------------------------------------------------
    let negotiate_result = reqwest::Client::new()
        .post(&negotiate_url)
        .bearer_auth(config.access_token.as_str())
        .send()
        .await;

    let negotiate_resp = match negotiate_result {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            return SessionResult::ConnectFailed(format!(
                "negotiate returned HTTP {}",
                r.status()
            ));
        }
        Err(e) => return SessionResult::ConnectFailed(format!("negotiate request failed: {e}")),
    };

    let neg: NegotiateResponse = match negotiate_resp.json().await {
        Ok(n) => n,
        Err(e) => {
            return SessionResult::ConnectFailed(format!("negotiate response parse failed: {e}"));
        }
    };

    debug!(
        backend = %backend_id,
        connection_id = %neg.connection_id,
        "notifications: negotiate succeeded"
    );

    // ------------------------------------------------------------------
    // Step 2: WebSocket upgrade.
    // The token must appear as ?access_token= in the WS URL — Bitwarden's
    // server performs a separate auth check on the upgrade request.
    // ------------------------------------------------------------------
    let ws_uri = match ws_url.parse::<http::Uri>() {
        Ok(u) => u,
        Err(e) => return SessionResult::ConnectFailed(format!("invalid WS URI: {e}")),
    };

    let ws_result = tokio_websockets::ClientBuilder::from_uri(ws_uri)
        .connect()
        .await;

    let (mut ws, _) = match ws_result {
        Ok(pair) => pair,
        Err(e) => return SessionResult::ConnectFailed(format!("WebSocket connect failed: {e}")),
    };

    // ------------------------------------------------------------------
    // Step 3: SignalR handshake.
    // ------------------------------------------------------------------
    let handshake = format!("{{\"protocol\":\"json\",\"version\":1}}{RS}");
    if let Err(e) = ws.send(tokio_websockets::Message::text(handshake)).await {
        return SessionResult::ConnectFailed(format!("SignalR handshake send failed: {e}"));
    }

    // Read (and discard) the handshake acknowledgement frame.
    match ws.next().await {
        Some(Ok(_)) => {}
        Some(Err(e)) => {
            return SessionResult::ConnectFailed(format!("SignalR handshake recv failed: {e}"));
        }
        None => {
            return SessionResult::ConnectFailed("WebSocket closed during handshake".to_string());
        }
    }

    debug!(backend = %backend_id, "notifications: connected to hub");

    // ------------------------------------------------------------------
    // Step 4: Event loop — read frames until cancelled or disconnected.
    // ------------------------------------------------------------------
    let on_sync = config.on_sync_nudge.clone();
    let on_lock = config.on_lock_nudge.clone();
    let backend_id_owned = backend_id.to_string();

    loop {
        tokio::select! {
            // Vault locked — sender dropped, `changed()` returns Err.
            result = config.cancel_rx.changed() => {
                if result.is_err() {
                    let _ = ws.send(tokio_websockets::Message::close(None, "")).await;
                    return SessionResult::Cancelled;
                }
                // Spurious wake; keep going.
            }

            msg = ws.next() => {
                match msg {
                    None => return SessionResult::Disconnected,
                    Some(Err(e)) => {
                        debug!(backend = %backend_id_owned, error = %e, "notifications: WS error");
                        return SessionResult::Disconnected;
                    }
                    Some(Ok(m)) if m.is_text() => {
                        if let Some(text) = m.as_text() {
                            trace!(backend = %backend_id_owned, len = text.len(), "notifications: WS text message received");
                            handle_frames(text, &backend_id_owned, &on_sync, &on_lock);
                        }
                    }
                    Some(Ok(_)) => {
                        // Binary or control frames — tokio-websockets handles
                        // ping/pong automatically; close is caught by None above.
                    }
                }
            }
        }
    }
}

/// Parse one or more `\x1e`-delimited SignalR frames from a WebSocket message
/// and dispatch sync/lock callbacks.
fn handle_frames(
    text: &str,
    backend_id: &str,
    on_sync: &Option<Arc<dyn Fn() + Send + Sync + 'static>>,
    on_lock: &Option<Arc<dyn Fn() + Send + Sync + 'static>>,
) {
    for frame in text.split(RS) {
        let frame = frame.trim();
        if frame.is_empty() {
            continue;
        }

        trace!(backend = %backend_id, %frame, "notifications: received frame");

        let inv: Invocation = match serde_json::from_str(frame) {
            Ok(i) => i,
            Err(e) => {
                trace!(backend = %backend_id, error = %e, %frame, "notifications: unparseable frame (ping/ack/unknown)");
                continue;
            }
        };

        let Some(target) = inv.target else {
            trace!(backend = %backend_id, "notifications: frame with no target field");
            continue;
        };

        // The Bitwarden hub sends all events via a `ReceiveMessage` SignalR
        // target.  The actual event kind is a numeric `PushType` in the
        // first argument.
        if target == "ReceiveMessage" {
            let Some(pt) = inv.arguments.first().and_then(|a| a.push_type) else {
                trace!(backend = %backend_id, "notifications: ReceiveMessage with no push type");
                continue;
            };

            let name = push_type::name(pt);

            if push_type::SYNC_TYPES.contains(&pt) {
                debug!(backend = %backend_id, push_type = name, "notifications: sync event");
                if let Some(f) = on_sync {
                    f();
                }
            } else if pt == push_type::LOG_OUT {
                warn!(backend = %backend_id, push_type = name, "notifications: lock event");
                if let Some(f) = on_lock {
                    f();
                }
            } else {
                trace!(backend = %backend_id, push_type = pt, push_name = name, "notifications: unhandled push type");
            }
        } else {
            trace!(backend = %backend_id, %target, "notifications: non-ReceiveMessage target");
        }
    }
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/// Build the negotiate URL and WebSocket URL from a notifications base URL
/// and an access token.
///
/// - negotiate URL: `{https_url}/hub/negotiate?negotiateVersion=1`
///   (no token in URL — Bearer header used instead)
/// - WebSocket URL: `{wss_url}/hub?access_token={token}`
///   (token in query string — required by Bitwarden's WS auth check)
fn build_urls(notifications_url: &str, access_token: &str) -> Result<(String, String), String> {
    let (is_secure, without_schema) = if let Some(s) = notifications_url.strip_prefix("https://") {
        (true, s)
    } else if let Some(s) = notifications_url.strip_prefix("http://") {
        (false, s)
    } else {
        return Err(format!(
            "unsupported schema in notifications URL: {notifications_url}"
        ));
    };

    let (host, base_path) = match without_schema.split_once('/') {
        Some((h, p)) => (h, format!("{p}/hub")),
        None => (without_schema, "hub".to_string()),
    };

    let http_schema = if is_secure { "https" } else { "http" };
    let ws_schema = if is_secure { "wss" } else { "ws" };

    let negotiate_url =
        format!("{http_schema}://{host}/{base_path}/negotiate?negotiateVersion=1");
    let ws_url = format!("{ws_schema}://{host}/{base_path}?access_token={access_token}");

    Ok((negotiate_url, ws_url))
}

/// Replace any `access_token=<value>` occurrence in `s` with a placeholder.
///
/// Used to sanitise error strings that may contain URL fragments before they
/// reach log output.
fn redact_token(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains("access_token=") {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find("access_token=") {
        out.push_str(&rest[..pos]);
        out.push_str("access_token=<redacted>");
        let after = &rest[pos + "access_token=".len()..];
        let skip = after.find('&').unwrap_or(after.len());
        rest = &after[skip..];
    }
    out.push_str(rest);
    std::borrow::Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_urls_official_us() {
        let (neg, ws) = build_urls("https://notifications.bitwarden.com", "TOKEN123").unwrap();
        assert_eq!(
            neg,
            "https://notifications.bitwarden.com/hub/negotiate?negotiateVersion=1"
        );
        assert_eq!(
            ws,
            "wss://notifications.bitwarden.com/hub?access_token=TOKEN123"
        );
    }

    #[test]
    fn build_urls_self_hosted() {
        let (neg, ws) =
            build_urls("https://vault.example.com/notifications", "TOKEN123").unwrap();
        assert_eq!(
            neg,
            "https://vault.example.com/notifications/hub/negotiate?negotiateVersion=1"
        );
        assert_eq!(
            ws,
            "wss://vault.example.com/notifications/hub?access_token=TOKEN123"
        );
    }

    #[test]
    fn build_urls_insecure() {
        let (neg, ws) = build_urls("http://localhost:8080", "TOKEN").unwrap();
        assert_eq!(neg, "http://localhost:8080/hub/negotiate?negotiateVersion=1");
        assert_eq!(ws, "ws://localhost:8080/hub?access_token=TOKEN");
    }

    #[test]
    fn build_urls_invalid_schema() {
        assert!(build_urls("ftp://bad.example.com", "TOKEN").is_err());
    }

    #[test]
    fn redact_token_replaces_value() {
        let input = "failed: https://host/hub?access_token=eyJsecret123 blah";
        let out = redact_token(input);
        assert!(!out.contains("eyJsecret123"));
        assert!(out.contains("access_token=<redacted>"));
    }

    #[test]
    fn redact_token_no_token_unchanged() {
        let input = "some error without any token";
        let out = redact_token(input);
        assert_eq!(out, input);
    }

    #[test]
    fn redact_token_multiple_params() {
        let input = "url?access_token=abc123&other=value&access_token=xyz";
        let out = redact_token(input);
        assert!(!out.contains("abc123"));
        assert!(!out.contains("xyz"));
        assert!(out.contains("other=value"));
    }

    #[test]
    fn parse_receive_message_sync_cipher_update() {
        let frame = r#"{"type":1,"target":"ReceiveMessage","arguments":[{"type":0,"payload":{"id":"abc","userId":"xyz","organizationId":null,"collectionIds":null,"revisionDate":"2026-01-01T00:00:00Z"}}]}"#;
        let inv: Invocation = serde_json::from_str(frame).unwrap();
        assert_eq!(inv.target.as_deref(), Some("ReceiveMessage"));
        assert_eq!(inv.arguments[0].push_type, Some(push_type::SYNC_CIPHER_UPDATE));
    }

    #[test]
    fn parse_receive_message_sync_cipher_create() {
        let frame = r#"{"type":1,"target":"ReceiveMessage","arguments":[{"type":1,"payload":{"id":"abc"}}]}"#;
        let inv: Invocation = serde_json::from_str(frame).unwrap();
        assert_eq!(inv.arguments[0].push_type, Some(push_type::SYNC_CIPHER_CREATE));
    }

    #[test]
    fn parse_receive_message_logout() {
        let frame = r#"{"type":1,"target":"ReceiveMessage","arguments":[{"type":11}]}"#;
        let inv: Invocation = serde_json::from_str(frame).unwrap();
        assert_eq!(inv.arguments[0].push_type, Some(push_type::LOG_OUT));
    }

    #[test]
    fn parse_signalr_ping() {
        // Ping frames have type 6, no target — should parse but have no target.
        let frame = r#"{"type":6}"#;
        let inv: Invocation = serde_json::from_str(frame).unwrap();
        assert!(inv.target.is_none());
        assert!(inv.arguments.is_empty());
    }
}
