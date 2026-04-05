//! Generic WebSocket notification client for WASM providers.
//!
//! The host connects to a WebSocket URL declared by the guest via
//! `get_notification_config`.  Received frames are forwarded to the
//! guest's `parse_notification` function, which classifies each frame
//! as sync, lock, or ignore.  The host fires the appropriate callback.
//!
//! This module is protocol-agnostic — all protocol knowledge (SignalR,
//! plain WebSocket, etc.) lives in the guest.
//!
//! # Lifecycle
//!
//! - **Start**: called after online unlock or successful sync/token refresh.
//! - **Stop**: dropping the [`NotificationsHandle`] cancels the task.
//! - **Reconnect**: on disconnect, calls `get_notification_config` again
//!   (guest re-negotiates, gets fresh token) and reconnects with backoff.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Mutex, watch};
use tracing::{debug, info, trace, warn};

use crate::protocol::{
    NotificationAction, NotificationActionKind, NotificationConfigResponse, NotificationFrame,
    WebSocketSubscription,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Handle to a running notifications background task.
///
/// Dropping this handle cancels the task (the `cancel_tx` sender is dropped,
/// signalling the task to exit).
pub struct NotificationsHandle {
    /// Dropping this sender signals the notifications task to stop.
    _cancel_tx: watch::Sender<()>,
    /// Join handle for the background task (not awaited on drop — the task
    /// exits when it sees the cancellation).
    _task: tokio::task::JoinHandle<()>,
}

/// Configuration for the notifications background task.
pub struct NotificationsConfig {
    /// Provider ID (for log messages).
    pub provider_id: String,
    /// Reference to the WASM plugin (for `get_notification_config` and
    /// `parse_notification` guest calls).
    pub plugin: Arc<Mutex<extism::Plugin>>,
    /// Readiness probes to evaluate before (re)connecting.
    pub readiness_probes: Vec<crate::protocol::ReadinessProbe>,
    /// Allowed hosts for probe evaluation.
    pub allowed_hosts: Vec<String>,
    /// TLS mode for readiness probes.
    pub tls_mode_probe: rosec_core::config::TlsMode,
    /// Invoked when the guest classifies a frame as `Sync`.
    pub on_sync_nudge: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
    /// Invoked when the guest classifies a frame as `Lock`.
    pub on_lock_nudge: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
}

/// Spawn the notifications background task.
///
/// Calls `get_notification_config` on the guest to get the initial
/// subscription, then connects and starts listening.  Dropping the
/// returned handle cancels the task.
pub fn start(config: NotificationsConfig) -> NotificationsHandle {
    let (cancel_tx, cancel_rx) = watch::channel(());
    let task = tokio::spawn(notifications_loop(config, cancel_rx));
    NotificationsHandle {
        _cancel_tx: cancel_tx,
        _task: task,
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Initial delay before first reconnect attempt after a disconnect.
const BACKOFF_INITIAL: Duration = Duration::from_secs(5);
/// Maximum delay between reconnect attempts.
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// Timeout for individual readiness probe checks.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

async fn notifications_loop(config: NotificationsConfig, mut cancel_rx: watch::Receiver<()>) {
    let provider_id = &config.provider_id;
    let mut backoff = BACKOFF_INITIAL;
    let mut is_first_attempt = true;

    loop {
        // Check cancellation before each attempt.
        if cancel_rx.has_changed().is_err() {
            debug!(provider = %provider_id, "notifications: cancellation received, exiting");
            return;
        }

        if !is_first_attempt {
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = cancel_rx.changed() => {
                    debug!(provider = %provider_id, "notifications: cancelled during backoff, exiting");
                    return;
                }
            }
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
        is_first_attempt = false;

        // Check readiness probes before attempting to connect.
        if !config.readiness_probes.is_empty() {
            let probes_ok = config.readiness_probes.iter().all(|probe| {
                crate::provider::evaluate_probe(
                    probe,
                    &config.allowed_hosts,
                    Some(PROBE_TIMEOUT),
                    &config.tls_mode_probe,
                )
                .is_ok()
            });
            if !probes_ok {
                debug!(
                    provider = %provider_id,
                    "notifications: readiness probes failed, will retry"
                );
                continue;
            }
        }

        // Get subscription config from the guest.
        let subscription = {
            let mut plugin = config.plugin.lock().await;
            match get_subscription_from_guest(&mut plugin, provider_id) {
                Some(sub) => sub,
                None => {
                    // Guest returned no subscription — give up entirely
                    // (not a transient failure).
                    info!(
                        provider = %provider_id,
                        "notifications: guest returned no subscription config, disabling"
                    );
                    return;
                }
            }
        };

        match run_session(&config, &subscription, &mut cancel_rx).await {
            SessionResult::Cancelled => {
                debug!(provider = %provider_id, "notifications: cancelled, exiting");
                return;
            }
            SessionResult::Disconnected => {
                info!(
                    provider = %provider_id,
                    next_retry_secs = backoff.as_secs(),
                    "notifications: disconnected, will retry"
                );
            }
            SessionResult::ConnectFailed(reason) => {
                let safe_reason = redact_tokens(&reason);
                if is_first_attempt {
                    // First-connect failure — degrade to poll-only.
                    warn!(
                        provider = %provider_id,
                        reason = %safe_reason,
                        "notifications: initial connection failed, falling back to poll-only"
                    );
                    return;
                }
                info!(
                    provider = %provider_id,
                    reason = %safe_reason,
                    next_retry_secs = backoff.as_secs(),
                    "notifications: connection failed, will retry"
                );
            }
        }
    }
}

enum SessionResult {
    /// Cancellation received — caller should exit.
    Cancelled,
    /// Connection was established then dropped — caller should retry.
    Disconnected,
    /// Connection could not be established — caller may retry or give up.
    ConnectFailed(String),
}

/// Run one WebSocket session.
async fn run_session(
    config: &NotificationsConfig,
    subscription: &WebSocketSubscription,
    cancel_rx: &mut watch::Receiver<()>,
) -> SessionResult {
    let provider_id = &config.provider_id;

    // Parse the URL.
    let ws_uri = match subscription.url.parse::<http::Uri>() {
        Ok(u) => u,
        Err(e) => return SessionResult::ConnectFailed(format!("invalid WebSocket URI: {e}")),
    };

    debug!(provider = %provider_id, "notifications: connecting");

    // Connect WebSocket.
    let ws_result = tokio_websockets::ClientBuilder::from_uri(ws_uri)
        .connect()
        .await;
    let (mut ws, _) = match ws_result {
        Ok(pair) => pair,
        Err(e) => return SessionResult::ConnectFailed(format!("WebSocket connect failed: {e}")),
    };

    // Send handshake message if the guest specified one.
    if let Some(ref handshake) = subscription.handshake_message
        && let Err(e) = ws
            .send(tokio_websockets::Message::text(handshake.to_string()))
            .await
    {
        return SessionResult::ConnectFailed(format!("handshake send failed: {e}"));
    }

    info!(provider = %provider_id, "notifications: connected");

    // Event loop — receive frames, parse via guest, dispatch callbacks.
    let on_sync = &config.on_sync_nudge;
    let on_lock = &config.on_lock_nudge;

    loop {
        tokio::select! {
            result = cancel_rx.changed() => {
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
                        debug!(
                            provider = %provider_id,
                            error = %e,
                            "notifications: WebSocket error"
                        );
                        return SessionResult::Disconnected;
                    }
                    Some(Ok(m)) if m.is_text() => {
                        if let Some(text) = m.as_text() {
                            trace!(
                                provider = %provider_id,
                                len = text.len(),
                                "notifications: received frame"
                            );
                            // Call the guest to parse the frame.
                            let action = {
                                let mut plugin = config.plugin.lock().await;
                                parse_frame_via_guest(
                                    &mut plugin,
                                    provider_id,
                                    text,
                                )
                            };
                            match action {
                                NotificationActionKind::Sync => {
                                    debug!(
                                        provider = %provider_id,
                                        "notifications: sync event"
                                    );
                                    if let Some(f) = on_sync {
                                        f();
                                    }
                                }
                                NotificationActionKind::Lock => {
                                    warn!(
                                        provider = %provider_id,
                                        "notifications: lock event"
                                    );
                                    if let Some(f) = on_lock {
                                        f();
                                    }
                                }
                                NotificationActionKind::Ignore => {}
                            }
                        }
                    }
                    Some(Ok(_)) => {
                        // Binary or control frames — tokio-websockets handles
                        // ping/pong automatically.
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Guest calls
// ---------------------------------------------------------------------------

/// Call the guest's `get_notification_config` function.
fn get_subscription_from_guest(
    plugin: &mut extism::Plugin,
    provider_id: &str,
) -> Option<WebSocketSubscription> {
    if !plugin.function_exists("get_notification_config") {
        debug!(
            provider = %provider_id,
            "notifications: guest does not export get_notification_config"
        );
        return None;
    }

    let (result, _outcome) = crate::provider::call_guest_json_no_input::<NotificationConfigResponse>(
        plugin,
        "get_notification_config",
    );

    match result {
        Ok(resp) if resp.ok => resp.subscription,
        Ok(resp) => {
            warn!(
                provider = %provider_id,
                error = ?resp.error,
                "notifications: guest returned error from get_notification_config"
            );
            None
        }
        Err(e) => {
            warn!(
                provider = %provider_id,
                error = %e,
                "notifications: get_notification_config call failed"
            );
            None
        }
    }
}

/// Call the guest's `parse_notification` function with a raw frame.
fn parse_frame_via_guest(
    plugin: &mut extism::Plugin,
    provider_id: &str,
    text: &str,
) -> NotificationActionKind {
    if !plugin.function_exists("parse_notification") {
        return NotificationActionKind::Ignore;
    }

    let frame = NotificationFrame {
        text: text.to_string(),
    };

    let (result, _outcome) = crate::provider::call_guest_json::<
        NotificationFrame,
        NotificationAction,
    >(plugin, "parse_notification", &frame);

    match result {
        Ok(action) => action.action,
        Err(e) => {
            debug!(
                provider = %provider_id,
                error = %e,
                "notifications: parse_notification call failed, treating as ignore"
            );
            NotificationActionKind::Ignore
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Replace any `access_token=<value>` occurrence with a placeholder.
fn redact_tokens(s: &str) -> std::borrow::Cow<'_, str> {
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
