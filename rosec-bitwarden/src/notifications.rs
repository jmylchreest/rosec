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
//! - Connect:   `wss://{notifications_host}/hub`
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

use signalr_client::{CallbackHandler, DisconnectionHandler, NoReconnectPolicy, ReconnectionConfig, ReconnectionHandler, SignalRClient};
use tokio::sync::watch;
use tracing::{debug, info, warn};

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
    /// the negotiate POST.  Never embedded in a URL.
    pub access_token: zeroize::Zeroizing<String>,
    /// Backend instance ID (for log messages only).
    pub backend_id: String,
    /// Invoked (from a Tokio task) when the hub signals a cipher change.
    /// Typically calls `ServiceState::try_sync_backend`.
    /// If `None`, sync nudges are silently ignored.
    pub on_sync: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
    /// Invoked (from a Tokio task) when the hub sends `LogOut`.
    /// Typically calls `ServiceState::auto_lock` for this backend.
    /// If `None`, logout events are silently ignored.
    pub on_lock: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
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

/// Sync event target names from the Bitwarden SignalR hub.
const SYNC_TARGETS: &[&str] = &[
    "SyncCipherUpdated",
    "SyncCipherCreated",
    "SyncCipherDeleted",
    "SyncCiphers",
    "SyncVault",
    "SyncFolderCreated",
    "SyncFolderUpdated",
    "SyncFolderDeleted",
    "SyncSettings",
    "SyncOrgKeys",
];

/// Target names that indicate the session should be locked.
const LOCK_TARGETS: &[&str] = &["LogOut"];

/// Initial delay before first reconnect attempt after a disconnect.
const BACKOFF_INITIAL: Duration = Duration::from_secs(5);
/// Maximum delay between reconnect attempts.
const BACKOFF_MAX: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Disconnection handler — signals the session loop when the WS drops
// ---------------------------------------------------------------------------

/// Signals the outer session loop that the WebSocket connection was lost.
struct DropSignaller {
    tx: tokio::sync::mpsc::Sender<()>,
}

impl DisconnectionHandler for DropSignaller {
    fn on_disconnected(&self, _reconnection: ReconnectionHandler) {
        // We manage reconnection ourselves; just wake the select loop.
        let _ = self.tx.try_send(());
    }
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
                //
                // NOTE: `reason` may originate from the signalr-client crate
                // and could theoretically contain URL fragments.  Redact any
                // `access_token=…` query parameter defensively.
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

    // Split the notifications URL into domain + clean hub path (no token).
    // The signalr-client crate builds:
    //   negotiate URL  →  `{schema}://{domain}/{hub}/negotiate?negotiateVersion=1`
    //   WebSocket URL  →  `{ws_schema}://{domain}/{hub}`
    // A `?access_token=…` suffix in `hub` would corrupt the negotiate URL by
    // appending `/negotiate?…` after a query string.  We pass the token as an
    // `Authorization: Bearer` header on the negotiate POST instead.
    let (domain, hub) = match split_for_signalr(&config.notifications_url) {
        Ok(pair) => pair,
        Err(e) => return SessionResult::ConnectFailed(e),
    };

    let is_secure = config.notifications_url.starts_with("https://");

    debug!(
        backend = %backend_id,
        %domain,
        %hub,
        "notifications: connecting to hub"
    );

    // Channel used by DropSignaller to tell us when the WS drops.
    let (drop_tx, mut drop_rx) = tokio::sync::mpsc::channel::<()>(1);

    // Take the token by value so it can be moved into the closure without
    // keeping a borrow on `config`.  We clone only what we need here.
    let bearer_token = config.access_token.as_str().to_owned();

    let connect_result = SignalRClient::connect_with(&domain, &hub, |c| {
        if !is_secure {
            c.unsecure();
        }
        // Pass the JWT as a Bearer header on the negotiate POST.
        // This is the standard SignalR authentication path and avoids
        // embedding the token in the negotiate URL.
        c.authenticate_bearer(bearer_token.clone());
        // Disable automatic reconnection — we manage retries ourselves so we
        // can check cancellation and apply our own backoff.
        c.with_reconnection_policy(ReconnectionConfig {
            policy: std::sync::Arc::new(NoReconnectPolicy),
        });
        c.with_disconnection_handler(DropSignaller { tx: drop_tx.clone() });
    })
    .await;

    let mut client = match connect_result {
        Ok(c) => {
            info!(backend = %backend_id, "notifications: connected to hub");
            c
        }
        Err(e) => {
            return SessionResult::ConnectFailed(e);
        }
    };

    // -----------------------------------------------------------------------
    // Register callbacks for all sync/lock targets.
    // -----------------------------------------------------------------------
    // We keep the handlers in a type-erased vec via a helper closure so we
    // can call unregister() on each regardless of the concrete opaque type.
    // `CallbackHandler::unregister` takes `self`, so we box the call.
    let mut unregisters: Vec<Box<dyn FnOnce() + Send>> = Vec::new();

    macro_rules! register_and_keep {
        ($client:expr, $target:expr, $cb:expr) => {{
            let h = $client.register($target.to_string(), $cb);
            unregisters.push(Box::new(move || h.unregister()));
        }};
    }

    for &target in SYNC_TARGETS {
        let cb_on_sync = config.on_sync.clone();
        let cb_backend_id = backend_id.clone();
        let cb_target = target.to_string();
        register_and_keep!(client, target, move |_ctx| {
            debug!(backend = %cb_backend_id, target = %cb_target, "notifications: sync event");
            if let Some(f) = &cb_on_sync {
                f();
            }
        });
    }

    for &target in LOCK_TARGETS {
        let cb_on_lock = config.on_lock.clone();
        let cb_backend_id = backend_id.clone();
        let cb_target = target.to_string();
        register_and_keep!(client, target, move |_ctx| {
            warn!(backend = %cb_backend_id, target = %cb_target, "notifications: lock event");
            if let Some(f) = &cb_on_lock {
                f();
            }
        });
    }

    // -----------------------------------------------------------------------
    // Wait until cancelled or the WebSocket drops.
    // -----------------------------------------------------------------------
    let outcome = tokio::select! {
        // Vault locked — sender dropped, `changed()` returns Err.
        result = config.cancel_rx.changed() => {
            if result.is_err() {
                SessionResult::Cancelled
            } else {
                // Spurious wake (value changed but sender still alive);
                // treat as a disconnect and let the loop retry.
                SessionResult::Disconnected
            }
        }
        // DropSignaller fired — WebSocket was closed by the server.
        _ = drop_rx.recv() => {
            SessionResult::Disconnected
        }
    };

    // Unregister all callbacks, then drop the client (SignalRClient::drop
    // calls disconnect() internally via block_on).
    for unregister in unregisters {
        unregister();
    }
    drop(client);

    debug!(backend = %backend_id, "notifications: session ended");
    outcome
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/// Replace any `access_token=<value>` occurrence in `s` with a placeholder.
///
/// Used to sanitise error strings that may have been built from URLs by the
/// `signalr-client` crate before they reach log output.
fn redact_token(s: &str) -> std::borrow::Cow<'_, str> {
    // Simple scan: find the key, then replace everything up to the next `&`
    // or end-of-string with a fixed placeholder.
    if !s.contains("access_token=") {
        return std::borrow::Cow::Borrowed(s);
    }
    // Replace all occurrences with a regex-free approach.
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find("access_token=") {
        out.push_str(&rest[..pos]);
        out.push_str("access_token=<redacted>");
        let after = &rest[pos + "access_token=".len()..];
        // Skip to the next `&` (query param separator) or end of string.
        let skip = after.find('&').unwrap_or(after.len());
        rest = &after[skip..];
    }
    out.push_str(rest);
    std::borrow::Cow::Owned(out)
}

/// Split a `https://host/base` notifications URL into the
/// `(domain, hub_path)` pair that `SignalRClient::connect_with` expects.
///
/// The returned hub path is **clean** — no `?access_token=…` suffix.
/// Bearer authentication for the negotiate POST is configured separately
/// via `authenticate_bearer`.  The `signalr-client` crate constructs:
///
/// - negotiate URL: `{schema}://{domain}/{hub}/negotiate?negotiateVersion=1`
/// - WebSocket URL: `{ws_schema}://{domain}/{hub}`
///
/// The hub path must not contain a `?` or the negotiate URL becomes invalid.
///
/// Examples:
/// - `"https://notifications.bitwarden.com"`
///   → `("notifications.bitwarden.com", "hub")`
/// - `"https://vault.example.com/notifications"`
///   → `("vault.example.com", "notifications/hub")`
fn split_for_signalr(notifications_url: &str) -> Result<(String, String), String> {
    // Strip schema prefix.
    let without_schema = notifications_url
        .strip_prefix("https://")
        .or_else(|| notifications_url.strip_prefix("http://"))
        .ok_or_else(|| {
            format!("unsupported schema in notifications URL: {notifications_url}")
        })?;

    // Split on the first `/` to separate `host[:port]` from path.
    let (domain, hub_path) = match without_schema.split_once('/') {
        Some((d, p)) => (d.to_string(), format!("{p}/hub")),
        None => (without_schema.to_string(), "hub".to_string()),
    };

    Ok((domain, hub_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_official_us() {
        let (domain, hub) = split_for_signalr("https://notifications.bitwarden.com").unwrap();
        assert_eq!(domain, "notifications.bitwarden.com");
        assert_eq!(hub, "hub");
    }

    #[test]
    fn split_self_hosted() {
        let (domain, hub) =
            split_for_signalr("https://vault.example.com/notifications").unwrap();
        assert_eq!(domain, "vault.example.com");
        assert_eq!(hub, "notifications/hub");
    }

    #[test]
    fn split_invalid_schema() {
        let result = split_for_signalr("ftp://bad.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn redact_token_replaces_value() {
        let input = "negotiate with https://host/hub?access_token=eyJsecret123 failed";
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
}
