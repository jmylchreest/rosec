mod bootstrap;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use notify::Watcher;
use rosec_core::VaultBackend;
use rosec_core::config::Config;
use rosec_core::router::{Router, RouterConfig};
use rosec_secret_service::server::register_objects_with_full_config;
use rosec_secret_service::session::SessionManager;
use zbus::fdo::RequestNameFlags;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        // Print the error chain cleanly without a stack backtrace.
        // anyhow chains are displayed as "cause: context" lines; the first
        // line is always the outermost message.
        eprintln!("error: {e}");
        for cause in e.chain().skip(1) {
            eprintln!("  caused by: {cause}");
        }
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    // Security hardening: disable core dumps, lock memory pages.
    // Called immediately after logging is initialised so warnings are visible,
    // but before any backends are constructed or secrets are touched.
    bootstrap::secure_bootstrap();

    let config_path = parse_config_path();
    let config = load_config(&config_path)?;
    tracing::info!("loaded config from {}", config_path.display());
    tracing::info!("backends configured: {}", config.backend.len());

    let router_config = RouterConfig {
        dedup_strategy: config.service.dedup_strategy,
        dedup_time_fallback: config.service.dedup_time_fallback,
    };
    let router = Arc::new(Router::new(router_config));
    let sessions = Arc::new(SessionManager::new());

    let backends: Vec<Arc<dyn VaultBackend>> = build_backends(&config).await?;

    // Build per-backend return_attr and collection maps from config.
    let return_attr_map: std::collections::HashMap<String, Vec<String>> = config
        .backend
        .iter()
        .filter_map(|entry| {
            entry
                .return_attr
                .as_ref()
                .map(|patterns| (entry.id.clone(), patterns.clone()))
        })
        .collect();

    let collection_map: std::collections::HashMap<String, String> = config
        .backend
        .iter()
        .filter_map(|entry| {
            entry
                .collection
                .as_ref()
                .map(|col| (entry.id.clone(), col.clone()))
        })
        .collect();

    let conn = zbus::Connection::session().await?;
    let state = register_objects_with_full_config(
        &conn,
        backends,
        router,
        sessions,
        return_attr_map,
        collection_map,
        config.prompt.clone(),
        config.clone(),
    )
    .await?;

    // Claim the well-known bus name so clients can discover us.
    // Use DoNotQueue so a second instance fails immediately instead of silently
    // waiting in the D-Bus name queue until the first instance exits.
    // If another process already owns it, report who it is before exiting.
    if let Err(e) = conn
        .request_name_with_flags("org.freedesktop.secrets", RequestNameFlags::DoNotQueue.into())
        .await
    {
        // Query the bus for the current owner's PID and comm so the user knows what to kill.
        let owner_info = bus_name_owner_info(&conn, "org.freedesktop.secrets").await;
        anyhow::bail!("cannot claim org.freedesktop.secrets: {e}\n{owner_info}");
    }

    // Start logind watcher unconditionally — it always subscribes to all
    // signals and checks the live config flags on each arrival.  This means
    // enabling on_session_lock or on_logout in the config takes effect
    // immediately without a restart.
    {
        let logind_state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = logind_watcher(logind_state).await {
                tracing::warn!("logind watcher exited: {e}");
            }
        });
    }

    // Wire up real-time notification callbacks for each Bitwarden backend.
    // Must be done after `state` is created because the callbacks need to
    // call back into `ServiceState`.
    for backend in state.backends_ordered() {
        // Downcast to BitwardenBackend — only that type supports set_realtime_callbacks.
        if let Some(bw) = backend
            .as_any()
            .downcast_ref::<rosec_bitwarden::BitwardenBackend>()
        {
            let backend_id = bw.id().to_string();
            let sync_state = Arc::clone(&state);
            let lock_state = Arc::clone(&state);
            let lock_id = backend_id.clone();

            bw.set_realtime_callbacks(
                Arc::new(move || {
                    let s = Arc::clone(&sync_state);
                    let id = backend_id.clone();
                    tokio::spawn(async move {
                        match s.try_sync_backend(&id).await {
                            Ok(true) => tracing::debug!(backend = %id, "notifications: sync triggered"),
                            Ok(false) => tracing::debug!(backend = %id, "notifications: sync already in progress"),
                            Err(e) => tracing::debug!(backend = %id, error = %e, "notifications: sync trigger failed"),
                        }
                    });
                }),
                Arc::new(move || {
                    let s = Arc::clone(&lock_state);
                    let id = lock_id.clone();
                    tokio::spawn(async move {
                        if let Err(e) = s.auto_lock().await {
                            tracing::warn!(backend = %id, error = %e, "notifications: auto-lock failed");
                        }
                    });
                }),
            );
        }
    }

    tracing::info!("rosecd ready on session bus");

    // Config file watcher — hot-reload backends when config.toml changes.
    {
        let watch_state = Arc::clone(&state);
        let watch_path = config_path.clone();
        let initial_config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = config_watcher(watch_state, watch_path, initial_config).await {
                tracing::warn!("config watcher exited: {e}");
            }
        });
    }

    let cache_rebuild_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut consecutive_failures = 0u32;
        loop {
            // Re-read refresh_interval_secs from the live config on every tick
            // so changes to the config file take effect without a restart.
            let interval_secs = cache_rebuild_state
                .live_config()
                .service
                .refresh_interval_secs
                .unwrap_or(60);
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

            // For each backend, decide what to do based on its lock state and
            // whether it supports auto-unlock:
            //
            //  - can_auto_unlock + locked   → sync_backend() (handles token
            //    load + full fetch itself; this keeps SM data fresh even before
            //    the first interactive request arrives)
            //  - any backend + unlocked     → check_remote_changed() first;
            //    only call sync_backend() when the remote reports changes
            //
            // After per-backend work we still call rebuild_cache() as a safety
            // net so the in-process cache always reflects the latest state.

            let mut did_any_work = false;

            for backend in cache_rebuild_state.backends_ordered() {
                let backend_id = backend.id().to_string();
                let locked = match backend.status().await {
                    Ok(s) => s.locked,
                    Err(e) => {
                        tracing::debug!(backend = %backend_id, error = %e, "status check failed, skipping");
                        continue;
                    }
                };

                if locked && backend.can_auto_unlock() {
                    // SM / token backends: silently sync (includes re-auth).
                    // Use try_sync_backend: background caller, skip if a D-Bus
                    // SyncBackend call (or another timer tick) is already running.
                    tracing::debug!(backend = %backend_id, "background: syncing locked auto-unlock backend");
                    match cache_rebuild_state.try_sync_backend(&backend_id).await {
                        Ok(true) => {
                            tracing::debug!(backend = %backend_id, "background: auto-unlock+sync ok");
                            did_any_work = true;
                        }
                        Ok(false) => {
                            tracing::debug!(backend = %backend_id, "background: sync skipped (already in progress)");
                        }
                        Err(e) => {
                            tracing::debug!(backend = %backend_id, error = %e,
                                "background: auto-unlock+sync failed (token missing or API error)");
                        }
                    }
                } else if !locked {
                    // Already unlocked: check for remote changes before syncing.
                    match backend.check_remote_changed().await {
                        Ok(true) => {
                            tracing::debug!(backend = %backend_id, "background: remote changed, syncing");
                            // Use try_sync_backend: skip if a D-Bus caller or
                            // another timer tick already has the sync lock.
                            match cache_rebuild_state.try_sync_backend(&backend_id).await {
                                Ok(true) => {
                                    tracing::debug!(backend = %backend_id, "background: sync ok");
                                    did_any_work = true;
                                }
                                Ok(false) => {
                                    tracing::debug!(backend = %backend_id, "background: sync skipped (already in progress)");
                                }
                                Err(e) => {
                                    let err_str = e.to_string();
                                    if err_str.starts_with("locked::") {
                                        tracing::debug!(backend = %backend_id, "background: sync skipped — backend locked");
                                    } else {
                                        consecutive_failures += 1;
                                        if consecutive_failures <= 3 {
                                            tracing::warn!(backend = %backend_id, attempt = consecutive_failures, "background sync failed: {e}");
                                        } else if consecutive_failures == 4 {
                                            tracing::warn!(backend = %backend_id,
                                                "background sync has failed {} times, suppressing further warnings",
                                                consecutive_failures);
                                        }
                                    }
                                }
                            }
                        }
                        Ok(false) => {
                            tracing::debug!(backend = %backend_id, "background: no remote changes");
                        }
                        Err(e) => {
                            tracing::debug!(backend = %backend_id, error = %e,
                                "background: remote-changed check failed, skipping sync");
                        }
                    }
                }
                // locked && !can_auto_unlock: skip — interactive backends need
                // a user-supplied password; the poller never prompts.
            }

            // Safety-net rebuild: keep the in-process item cache consistent
            // even if no per-backend sync ran (e.g. all unlocked backends had
            // no remote changes).
            if !did_any_work {
                match cache_rebuild_state.rebuild_cache().await {
                    Ok(entries) => {
                        tracing::debug!("background cache rebuild: {} items", entries.len());
                        consecutive_failures = 0;
                    }
                    Err(err) => {
                        let err_str = err.to_string();
                        if err_str.starts_with("locked::") {
                            tracing::debug!(
                                "background cache rebuild skipped: backend not yet unlocked"
                            );
                        } else {
                            consecutive_failures += 1;
                            if consecutive_failures <= 3 {
                                tracing::warn!(
                                    attempt = consecutive_failures,
                                    "background cache rebuild failed: {err}"
                                );
                            } else if consecutive_failures == 4 {
                                tracing::warn!(
                                    "background cache rebuild has failed {} times, suppressing further warnings",
                                    consecutive_failures
                                );
                            }
                        }
                    }
                }
            } else {
                consecutive_failures = 0;
            }
        }
    });

    // Auto-lock policy background task.
    // Reads autolock settings from live_config on every tick so changes to the
    // config file take effect without a restart.
    let autolock_state = Arc::clone(&state);
    tokio::spawn(async move {
        let check_interval = tokio::time::Duration::from_secs(30);
        loop {
            tokio::time::sleep(check_interval).await;

            let autolock = autolock_state.live_config().autolock;

            // Check idle timeout.
            // 0 means disabled (same as omitting the field); skip the check.
            if let Some(idle_min) = autolock.idle_timeout_minutes
                && idle_min != 0
                && autolock_state.is_idle_expired(idle_min)
            {
                tracing::info!(idle_minutes = idle_min, "idle timeout expired, locking");
                if let Err(e) = autolock_state.auto_lock().await {
                    tracing::warn!("auto-lock failed: {e}");
                }
                continue;
            }

            // Check max-unlocked timeout.
            // 0 means disabled (same as omitting the field); skip the check.
            if let Some(max_min) = autolock.max_unlocked_minutes
                && max_min != 0
                && autolock_state.is_max_unlocked_expired(max_min)
            {
                tracing::info!(
                    max_minutes = max_min,
                    "max-unlocked timeout expired, locking"
                );
                if let Err(e) = autolock_state.auto_lock().await {
                    tracing::warn!("auto-lock failed: {e}");
                }
            }
        }
    });

    // Wait for SIGTERM or SIGINT for graceful shutdown.
    shutdown_signal().await;
    tracing::info!("received shutdown signal, locking all backends before exit");
    // Explicitly lock all backends so decrypted state is zeroed before the
    // process exits.  Errors are logged but not fatal — the process is exiting
    // anyway and Zeroizing<> drop impls will still run.
    if let Err(e) = state.auto_lock().await {
        tracing::warn!("lock-on-exit failed: {e}");
    }
    tracing::info!("all backends locked, exiting");
    Ok(())
}

/// Query the D-Bus daemon for who currently owns `name`, returning a
/// human-readable string with the PID and process name if available.
async fn bus_name_owner_info(conn: &zbus::Connection, name: &str) -> String {
    // Ask the bus daemon for the unique name of the current owner.
    let proxy = match zbus::fdo::DBusProxy::new(conn).await {
        Ok(p) => p,
        Err(_) => return "  (could not query bus daemon)".to_string(),
    };

    let bus_name = match zbus::names::BusName::try_from(name) {
        Ok(n) => n,
        Err(_) => return format!("  (invalid bus name: {name})"),
    };
    let unique_name = match proxy.get_name_owner(bus_name).await {
        Ok(n) => n.to_string(),
        Err(_) => return "  (no current owner found — may have just exited)".to_string(),
    };

    let unique_bus_name = match zbus::names::BusName::try_from(unique_name.as_str()) {
        Ok(n) => n,
        Err(_) => return format!("  current owner: {unique_name} (invalid unique name)"),
    };
    let pid = match proxy.get_connection_unix_process_id(unique_bus_name).await {
        Ok(p) => p,
        Err(_) => return format!("  current owner: {unique_name} (PID unknown)"),
    };

    // Read process name from /proc/<pid>/comm (Linux only).
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    format!("  current owner: {comm} (PID {pid}, bus name {unique_name})")
}

/// Wait for ctrl-c (SIGINT) or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!(
                    "failed to register SIGTERM handler: {e}, falling back to SIGINT only"
                );
                ctrl_c.await.ok();
            }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}

/// Subscribe to logind D-Bus signals and enforce on_session_lock / on_logout policies.
///
/// Connects to the **system** bus where `org.freedesktop.login1` lives.
/// Always subscribes to all signals regardless of the current config values;
/// config flags are re-read from `state.live_config()` on each signal arrival
/// so hot-reloading `on_session_lock` or `on_logout` takes effect immediately.
///
/// Signals watched:
/// - `PrepareForSleep(true)` on `org.freedesktop.login1.Manager` → lock (always)
/// - `Lock` on `org.freedesktop.login1.Session` (our own session) → lock if on_session_lock
/// - `SessionRemoved` on `org.freedesktop.login1.Manager` → lock if on_logout
///
/// The function runs until an unrecoverable error occurs (e.g. system bus disconnected).
async fn logind_watcher(
    state: Arc<rosec_secret_service::ServiceState>,
) -> anyhow::Result<()> {
    use futures_util::TryStreamExt;
    use zbus::Connection;

    let system_bus = Connection::system().await?;

    // Determine our own session ID from the environment so we can watch the right
    // Session object.  If XDG_SESSION_ID is not set we skip the per-session lock signal
    // but still watch manager-level signals.
    let session_id = std::env::var("XDG_SESSION_ID").ok();

    // Identify our session path for the per-session Lock signal.
    // logind session paths are /org/freedesktop/login1/session/<id>.
    // Special characters in the ID are escaped as '_XX' (systemd D-Bus path encoding);
    // for typical numeric IDs this is a no-op.
    let session_path: Option<String> = session_id.as_ref().map(|id| {
        let encoded: String = id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c.to_string()
                } else {
                    format!("_{:02x}", c as u32)
                }
            })
            .collect();
        format!("/org/freedesktop/login1/session/{encoded}")
    });

    // -----------------------------------------------------------------------
    // Subscribe to PrepareForSleep — fires before suspend/hibernate
    // -----------------------------------------------------------------------
    let sleep_rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.login1.Manager")?
        .member("PrepareForSleep")?
        .path("/org/freedesktop/login1")?
        .build();
    let mut sleep_stream =
        zbus::MessageStream::for_match_rule(sleep_rule, &system_bus, None).await?;

    // -----------------------------------------------------------------------
    // Subscribe to SessionRemoved — fires when any session is removed (logout)
    // -----------------------------------------------------------------------
    let session_removed_rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.login1.Manager")?
        .member("SessionRemoved")?
        .path("/org/freedesktop/login1")?
        .build();
    let mut session_removed_stream =
        zbus::MessageStream::for_match_rule(session_removed_rule, &system_bus, None).await?;

    // -----------------------------------------------------------------------
    // Always subscribe to the Lock signal on our own session (if we know the
    // path).  Whether to act on it is decided at signal-arrival time by reading
    // the live config, so enabling on_session_lock in the config takes effect
    // without a restart.
    // -----------------------------------------------------------------------
    let mut lock_stream_opt: Option<zbus::MessageStream> = if let Some(ref spath) = session_path {
        let lock_rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface("org.freedesktop.login1.Session")?
            .member("Lock")?
            .path(spath.as_str())?
            .build();
        let stream = zbus::MessageStream::for_match_rule(lock_rule, &system_bus, None).await?;
        Some(stream)
    } else {
        tracing::warn!("XDG_SESSION_ID not set — session Lock signal not subscribed");
        None
    };

    tracing::info!(
        session_id = session_id.as_deref().unwrap_or("unknown"),
        "logind watcher started"
    );

    // Event loop — config flags are read fresh from live_config on each signal.
    loop {
        tokio::select! {
            msg = sleep_stream.try_next() => {
                match msg {
                    Ok(Some(msg)) => {
                        // PrepareForSleep is always honoured regardless of config.
                        if let Ok(going_to_sleep) = msg.body().deserialize::<(bool,)>()
                            && going_to_sleep.0
                        {
                            tracing::info!("logind: PrepareForSleep — locking all backends");
                            if let Err(e) = state.auto_lock().await {
                                tracing::warn!("auto-lock on sleep failed: {e}");
                            }
                        }
                    }
                    Ok(None) => {
                        anyhow::bail!("PrepareForSleep stream ended");
                    }
                    Err(e) => {
                        tracing::debug!("PrepareForSleep stream error (skipping): {e}");
                    }
                }
            }
            msg = session_removed_stream.try_next() => {
                match msg {
                    Ok(Some(msg)) => {
                        // Check live config — on_logout may have changed since startup.
                        if state.live_config().autolock.on_logout {
                            // SessionRemoved(id: &str, path: OwnedObjectPath)
                            // Only lock if the removed session is *our* session.
                            if let Ok(body) = msg.body().deserialize::<(String, zbus::zvariant::OwnedObjectPath)>() {
                                let removed_id = body.0;
                                if session_id.as_deref() == Some(&removed_id) {
                                    tracing::info!(session = %removed_id, "logind: our session removed — locking");
                                    if let Err(e) = state.auto_lock().await {
                                        tracing::warn!("auto-lock on logout failed: {e}");
                                    }
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        anyhow::bail!("SessionRemoved stream ended");
                    }
                    Err(e) => {
                        tracing::debug!("SessionRemoved stream error (skipping): {e}");
                    }
                }
            }
            msg = poll_lock_stream(&mut lock_stream_opt), if lock_stream_opt.is_some() => {
                match msg {
                    Some(Ok(_)) => {
                        // Check live config — on_session_lock may have changed since startup.
                        if state.live_config().autolock.on_session_lock {
                            tracing::info!("logind: session Lock signal — locking all backends");
                            if let Err(e) = state.auto_lock().await {
                                tracing::warn!("auto-lock on session lock failed: {e}");
                            }
                        }
                    }
                    Some(Err(e)) => {
                        tracing::debug!("session Lock stream error (skipping): {e}");
                    }
                    None => {
                        tracing::warn!("session Lock stream ended; no longer watching session Lock");
                        lock_stream_opt = None;
                    }
                }
            }
        }
    }
}

/// Poll the next message from an `Option<MessageStream>`, returning `None` forever
/// if the stream is `None` (so the `select!` branch is disabled).
async fn poll_lock_stream(
    stream: &mut Option<zbus::MessageStream>,
) -> Option<Result<zbus::Message, zbus::Error>> {
    use futures_util::TryStreamExt;
    match stream {
        Some(s) => s.try_next().await.transpose(),
        None => std::future::pending().await,
    }
}

/// Build all configured backends from the config, in order.
///
/// Delegates to `build_single_backend` for each entry so startup and
/// hot-reload share identical construction logic.  Returns an empty vec if no
/// backends are configured — the daemon handles that state gracefully.
async fn build_backends(config: &Config) -> Result<Vec<Arc<dyn VaultBackend>>> {
    if config.backend.is_empty() {
        tracing::warn!("no backends configured");
        return Ok(Vec::new());
    }

    let mut backends: Vec<Arc<dyn VaultBackend>> = Vec::with_capacity(config.backend.len());

    for entry in &config.backend {
        match build_single_backend(entry).await {
            Ok(backend) => {
                tracing::info!(
                    backend_id = %entry.id,
                    backend_kind = %entry.kind,
                    "backend initialized"
                );
                backends.push(backend);
            }
            Err(e) if e.to_string().starts_with("unknown backend kind") => {
                tracing::warn!(
                    backend_id = %entry.id,
                    backend_kind = %entry.kind,
                    "unknown backend type; skipping"
                );
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to initialize backend '{}': {e}",
                    entry.id
                ));
            }
        }
    }

    Ok(backends)
}

/// Compute a stable fingerprint string for a backend config entry.
///
/// The fingerprint covers `kind`, all `options` (sorted), `return_attr`, and
/// `match_attr`.  Two entries are considered identical iff their fingerprints
/// are equal, so hot-reload only removes/re-adds backends that materially changed.
fn backend_fingerprint(entry: &rosec_core::config::BackendEntry) -> String {
    let mut opts: Vec<String> = entry
        .options
        .iter()
        .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
        .collect();
    opts.sort();

    let return_attr = entry
        .return_attr
        .as_deref()
        .map(|v| v.join(","))
        .unwrap_or_default();
    let match_attr = entry
        .match_attr
        .as_deref()
        .map(|v| v.join(","))
        .unwrap_or_default();

    format!(
        "{}:{}:return_attr={}:match_attr={}",
        entry.kind,
        opts.join(","),
        return_attr,
        match_attr,
    )
}

/// Watch the config file and hot-reload backends when it changes.
///
/// Uses `notify` (inotify on Linux) to detect writes/renames, debounces
/// rapid events with a 500 ms quiet period, then diffs the backend list:
/// - New backend IDs → construct and hot-add
/// - Removed backend IDs → lock then hot-remove
/// - Changed options for an existing ID → treat as remove + add
///
/// `initial_config` is the config that was active when the daemon started (or
/// last reloaded).  It is used to seed the fingerprint so the first comparison
/// is against actual config values rather than bare backend IDs.
///
/// Parse errors are logged as warnings; the running config is left intact.
async fn config_watcher(
    state: Arc<rosec_secret_service::ServiceState>,
    config_path: PathBuf,
    initial_config: Config,
) -> anyhow::Result<()> {
    use tokio::sync::mpsc;

    let (tx, mut rx) = mpsc::channel::<()>(1);

    // notify's callback is sync; we send a unit through the channel to wake
    // the async side.  The channel capacity of 1 naturally coalesces bursts.
    let mut watcher = notify::RecommendedWatcher::new(
        move |res: notify::Result<notify::Event>| {
            match res {
                Ok(event) => {
                    use notify::EventKind::*;
                    // React to writes, renames-to (atomic saves), and removes.
                    if matches!(event.kind, Modify(_) | Create(_) | Remove(_)) {
                        let _ = tx.try_send(());
                    }
                }
                Err(e) => tracing::warn!("config watcher notify error: {e}"),
            }
        },
        notify::Config::default(),
    )?;

    // Watch the parent directory so we catch atomic rename-based saves
    // (common with editors like vim/neovim and tools like toml_edit's write).
    let watch_dir = config_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path has no parent directory"))?;

    // Ensure the config directory exists so the watcher can be set up even
    // when rosecd starts before any config file has been written (e.g. on
    // first run before `rosec backend add` has been called).
    std::fs::create_dir_all(watch_dir).map_err(|e| {
        anyhow::anyhow!(
            "cannot create config directory {}: {e}",
            watch_dir.display()
        )
    })?;

    watcher.watch(watch_dir, notify::RecursiveMode::NonRecursive)?;
    tracing::info!(path = %config_path.display(), "config watcher started");

    // Seed `known` from the initial config fingerprints so the first diff
    // compares actual config values — not bare backend IDs.
    let mut known: Vec<(String, String)> = initial_config
        .backend
        .iter()
        .map(|entry| (entry.id.clone(), backend_fingerprint(entry)))
        .collect();

    loop {
        // Wait for a notification.
        if rx.recv().await.is_none() {
            break;
        }

        // Debounce: drain any additional events that arrive within 500 ms.
        while let Ok(Some(())) =
            tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.recv()).await
        {}

        // Only reload if the event is for our config file specifically.
        if !config_path.exists() {
            tracing::debug!("config file removed, skipping reload");
            continue;
        }

        let new_config = match load_config(&config_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    path = %config_path.display(),
                    error = %e,
                    "config hot-reload: parse error — keeping current config"
                );
                continue;
            }
        };

        // Build fingerprints for the new config.
        let new_fingerprints: Vec<(String, String)> = new_config
            .backend
            .iter()
            .map(|entry| (entry.id.clone(), backend_fingerprint(entry)))
            .collect();

        if new_fingerprints == known {
            tracing::debug!("config unchanged, no reload needed");
            continue;
        }

        tracing::info!(path = %config_path.display(), "config changed, hot-reloading backends");

        let known_ids: HashSet<&str> = known.iter().map(|(id, _)| id.as_str()).collect();

        // Remove backends that are gone or changed (changed = remove + re-add).
        let known_map: std::collections::HashMap<&str, &str> = known
            .iter()
            .map(|(id, fp)| (id.as_str(), fp.as_str()))
            .collect();
        let new_map: std::collections::HashMap<&str, &str> = new_fingerprints
            .iter()
            .map(|(id, fp)| (id.as_str(), fp.as_str()))
            .collect();

        for id in &known_ids {
            let changed = new_map
                .get(id)
                .is_none_or(|new_fp| known_map.get(id) != Some(new_fp));
            if changed && state.hotreload_remove_backend(id).await {
                tracing::info!(backend_id = id, "hot-reload: removed backend");
            }
        }

        // Add backends that are new or changed.
        for entry in &new_config.backend {
            let id = entry.id.as_str();
            let is_new = !known_ids.contains(id);
            let is_changed = known_map
                .get(id)
                .is_some_and(|old_fp| new_map.get(id).is_some_and(|new_fp| old_fp != new_fp));
            if is_new || is_changed {
                match build_single_backend(entry).await {
                    Ok(backend) => {
                        state.hotreload_add_backend(backend);
                        tracing::info!(backend_id = id, "hot-reload: added backend");
                    }
                    Err(e) => {
                        tracing::warn!(backend_id = id, error = %e, "hot-reload: failed to construct backend");
                    }
                }
            }
        }

        // ── Hot-reload non-backend config sections ─────────────────────────
        // These are live-updated in ServiceState and the Router so background
        // tasks pick up the new values on their next tick without a restart.
        let old_config = state.live_config();

        if new_config.service.dedup_strategy != old_config.service.dedup_strategy
            || new_config.service.dedup_time_fallback != old_config.service.dedup_time_fallback
        {
            state.router.update_config(rosec_core::router::RouterConfig {
                dedup_strategy: new_config.service.dedup_strategy,
                dedup_time_fallback: new_config.service.dedup_time_fallback,
            });
            tracing::info!(
                dedup_strategy = ?new_config.service.dedup_strategy,
                dedup_time_fallback = ?new_config.service.dedup_time_fallback,
                "hot-reload: service dedup config updated"
            );
        }
        if new_config.service.refresh_interval_secs != old_config.service.refresh_interval_secs {
            tracing::info!(
                refresh_interval_secs = ?new_config.service.refresh_interval_secs,
                "hot-reload: refresh_interval_secs updated (takes effect on next timer tick)"
            );
        }
        if new_config.autolock != old_config.autolock {
            tracing::info!(
                idle_timeout_minutes = ?new_config.autolock.idle_timeout_minutes,
                max_unlocked_minutes = ?new_config.autolock.max_unlocked_minutes,
                on_session_lock = new_config.autolock.on_session_lock,
                on_logout = new_config.autolock.on_logout,
                "hot-reload: autolock policy updated"
            );
        }
        if new_config.prompt.backend != old_config.prompt.backend
            || new_config.prompt.args != old_config.prompt.args
        {
            tracing::info!(
                backend = %new_config.prompt.backend,
                "hot-reload: prompt config updated"
            );
        }

        // Atomically push the new config into ServiceState so all live readers
        // (autolock loop, cache rebuild, logind watcher, prompt) see it.
        state.update_live_config(new_config.clone());

        known = new_fingerprints;
        tracing::info!(
            "hot-reload complete ({} backends active)",
            state.backend_count()
        );
    }

    Ok(())
}

/// Construct a single backend from a config entry.
///
/// Extracted from `build_backends` so the hot-reload watcher can reuse it
/// without re-parsing the whole config.
///
/// All backends are returned locked; the daemon unlocks them via `AuthBackend`
/// D-Bus calls once the user supplies credentials interactively.
async fn build_single_backend(
    entry: &rosec_core::config::BackendEntry,
) -> anyhow::Result<Arc<dyn VaultBackend>> {
    match entry.kind.as_str() {
        "bitwarden" => {
            let email = entry
                .options
                .get("email")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!("bitwarden backend '{}' requires 'email' option", entry.id)
                })?
                .to_string();

            let region = entry
                .options
                .get("region")
                .and_then(|v| v.as_str())
                .and_then(rosec_bitwarden::BitwardenRegion::parse);

            let base_url = entry
                .options
                .get("base_url")
                .and_then(|v| v.as_str())
                .map(String::from);
            let api_url = entry
                .options
                .get("api_url")
                .and_then(|v| v.as_str())
                .map(String::from);
            let identity_url = entry
                .options
                .get("identity_url")
                .and_then(|v| v.as_str())
                .map(String::from);

            let realtime_sync = entry
                .options
                .get("realtime_sync")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let notifications_poll_interval_secs = entry
                .options
                .get("notifications_poll_interval_secs")
                .and_then(|v| v.as_u64())
                .map(|v| v.max(1))
                .unwrap_or(3600);

            let bw_config = rosec_bitwarden::BitwardenConfig {
                id: entry.id.clone(),
                email,
                region,
                base_url,
                api_url,
                identity_url,
                realtime_sync,
                notifications_poll_interval_secs,
            };

            Ok(Arc::new(
                rosec_bitwarden::BitwardenBackend::new(bw_config)
                    .map_err(|e| anyhow::anyhow!("bitwarden backend '{}': {e}", entry.id))?,
            ))
        }
        "bitwarden-sm" => {
            let organization_id = entry
                .options
                .get("organization_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "bitwarden-sm backend '{}' requires 'organization_id' option",
                        entry.id
                    )
                })?
                .to_string();

            let server_url = entry
                .options
                .get("server_url")
                .and_then(|v| v.as_str())
                .map(String::from);

            let region = match entry.options.get("region").and_then(|v| v.as_str()) {
                Some("eu") => rosec_bitwarden_sm::SmRegion::Eu,
                _ => rosec_bitwarden_sm::SmRegion::Us,
            };

            let sm_config = rosec_bitwarden_sm::BitwardenSmConfig {
                id: entry.id.clone(),
                name: Some(entry.id.clone()),
                region,
                server_url,
                organization_id,
            };

            Ok(Arc::new(rosec_bitwarden_sm::BitwardenSmBackend::new(
                sm_config,
            )))
        }
        other => anyhow::bail!("unknown backend kind '{other}'"),
    }
}

/// Parse `--config <path>` from CLI args, falling back to XDG default.
fn parse_config_path() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" || args[i] == "-c" {
            if let Some(path) = args.get(i + 1) {
                return PathBuf::from(path);
            }
            eprintln!("error: --config requires a path argument");
            std::process::exit(1);
        }
        if let Some(path) = args[i].strip_prefix("--config=") {
            return PathBuf::from(path);
        }
        if args[i] == "--help" || args[i] == "-h" {
            eprintln!("Usage: rosecd [--config <path>]");
            eprintln!();
            eprintln!("Options:");
            eprintln!(
                "  -c, --config <path>  Path to config file (default: $XDG_CONFIG_HOME/rosec/config.toml)"
            );
            eprintln!("  -h, --help           Show this help message");
            std::process::exit(0);
        }
        i += 1;
    }
    default_config_path()
}

fn default_config_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| {
            tracing::warn!(
                "neither XDG_CONFIG_HOME nor HOME are set; using current directory for config"
            );
            PathBuf::from(".")
        });
    base.join("rosec").join("config.toml")
}

fn load_config(path: &PathBuf) -> Result<Config> {
    if !path.exists() {
        tracing::warn!(
            "config file not found at {}, using defaults",
            path.display()
        );
        return Ok(Config::default());
    }

    // Warn if the config file is world- or group-readable — it may contain
    // sensitive options (access tokens, etc.) and should be 0600.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.mode();
                // Bits for group-read (040), group-write (020), other-read (004), other-write (002)
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        path = %path.display(),
                        mode = format!("{:o}", mode & 0o777),
                        "config file is readable by group or others — recommend: chmod 600 {}",
                        path.display()
                    );
                }
            }
            Err(e) => {
                tracing::warn!("could not check config file permissions: {e}");
            }
        }
    }

    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}
