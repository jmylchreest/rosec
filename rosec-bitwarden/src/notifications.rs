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
    /// Current JWT access token — embedded as `?access_token=<jwt>` in
    /// both the negotiate POST and the WebSocket URL.
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
                warn!(
                    backend = %backend_id,
                    %reason,
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

    // Build the hub path including the access token query param.
    // signalr-client constructs the full URL as `{schema}://{domain}/{hub}`,
    // so `hub` must include the path and query string after the domain.
    let (domain, hub_with_token) =
        match split_for_signalr(&config.notifications_url, &config.access_token) {
            Ok(pair) => pair,
            Err(e) => return SessionResult::ConnectFailed(e),
        };

    let is_secure = config.notifications_url.starts_with("https://");

    debug!(
        backend = %backend_id,
        %domain,
        hub = %hub_with_token,
        "notifications: connecting to hub"
    );

    // Channel used by DropSignaller to tell us when the WS drops.
    let (drop_tx, mut drop_rx) = tokio::sync::mpsc::channel::<()>(1);

    let connect_result = SignalRClient::connect_with(&domain, &hub_with_token, |c| {
        if !is_secure {
            c.unsecure();
        }
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

/// Split a `https://host/base` notifications URL into the
/// `(domain, hub_path_with_token)` pair that `SignalRClient::connect_with`
/// expects.
///
/// Examples:
/// - `("https://notifications.bitwarden.com", "TOKEN")`
///   → `("notifications.bitwarden.com", "hub?access_token=TOKEN")`
/// - `("https://vault.example.com/notifications", "TOKEN")`
///   → `("vault.example.com", "notifications/hub?access_token=TOKEN")`
fn split_for_signalr(
    notifications_url: &str,
    access_token: &str,
) -> Result<(String, String), String> {
    // Strip schema prefix.
    let without_schema = notifications_url
        .strip_prefix("https://")
        .or_else(|| notifications_url.strip_prefix("http://"))
        .ok_or_else(|| {
            format!("unsupported schema in notifications URL: {notifications_url}")
        })?;

    // Split on the first `/` to separate `host[:port]` from path.
    let (domain, base_path) = match without_schema.split_once('/') {
        Some((d, p)) => (d.to_string(), format!("{p}/hub")),
        None => (without_schema.to_string(), "hub".to_string()),
    };

    let hub_with_token = format!("{base_path}?access_token={access_token}");
    Ok((domain, hub_with_token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_official_us() {
        let (domain, hub) =
            split_for_signalr("https://notifications.bitwarden.com", "TOKEN123").unwrap();
        assert_eq!(domain, "notifications.bitwarden.com");
        assert_eq!(hub, "hub?access_token=TOKEN123");
    }

    #[test]
    fn split_self_hosted() {
        let (domain, hub) =
            split_for_signalr("https://vault.example.com/notifications", "TOKEN123").unwrap();
        assert_eq!(domain, "vault.example.com");
        assert_eq!(hub, "notifications/hub?access_token=TOKEN123");
    }

    #[test]
    fn split_invalid_schema() {
        let result = split_for_signalr("ftp://bad.example.com", "TOKEN");
        assert!(result.is_err());
    }
}
