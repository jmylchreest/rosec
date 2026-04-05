mod bootstrap;
#[cfg(feature = "private-socket")]
mod bus;
mod ssh;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use notify::Watcher;
use rosec_core::config::Config;
use rosec_core::router::{Router, RouterConfig};
use rosec_core::{Capability, Provider};
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
    // Parse --version / --help before initialising tracing so that `--version`
    // output is not polluted by log lines on stdout.
    let config_path = parse_config_path();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "info,fuser=warn,ssh_agent_lib=warn,extism::plugin=warn".into()
            }),
        )
        .init();

    tracing::info!("rosecd v{}", env!("CARGO_PKG_VERSION"));

    // Security hardening: disable core dumps, lock memory pages.
    // Called immediately after logging is initialised so warnings are visible,
    // but before any providers are constructed or secrets are touched.
    bootstrap::secure_bootstrap();

    let config = load_config(&config_path)?;
    tracing::info!("loaded config from {}", config_path.display());
    tracing::info!(
        "local vaults: {}, external providers: {}",
        config.provider.iter().filter(|e| e.kind == "local").count(),
        config.provider.iter().filter(|e| e.kind != "local").count()
    );

    // Discover WASM plugins from system and user directories.
    let plugin_registry =
        rosec_wasm::discovery::scan_plugins(config.service.wasm_prefer, config.service.wasm_verify);

    let router_config = RouterConfig {
        dedup_strategy: config.service.dedup_strategy,
        dedup_time_fallback: config.service.dedup_time_fallback,
    };
    let router = Arc::new(Router::new(router_config));
    let sessions = Arc::new(SessionManager::new());

    let providers: Vec<Arc<dyn Provider>> = build_providers(&config, &plugin_registry).await?;

    // Build per-provider return_attr and collection maps from config.
    let return_attr_map: std::collections::HashMap<String, Vec<String>> = config
        .provider
        .iter()
        .filter_map(|entry| {
            entry
                .return_attr
                .as_ref()
                .map(|patterns| (entry.id.clone(), patterns.clone()))
        })
        .collect();

    let collection_map: std::collections::HashMap<String, String> = config
        .provider
        .iter()
        .filter_map(|entry| {
            entry
                .collection
                .as_ref()
                .map(|col| (entry.id.clone(), col.clone()))
        })
        .collect();

    // Establish the D-Bus connection.  With the `private-socket` feature,
    // this tries the session bus first and falls back to an embedded private
    // bus broker when the session bus is unavailable (e.g. during initial
    // login).  Without the feature, this is a direct session bus connection.
    #[cfg(feature = "private-socket")]
    let (conn, bus_mode, bus_config) = {
        let bus_config = parse_bus_config();
        let (conn, mode) = bus::establish_connection(&bus_config).await?;
        (conn, mode, bus_config)
    };
    #[cfg(not(feature = "private-socket"))]
    let conn = zbus::Connection::session().await?;

    let state = register_objects_with_full_config(
        &conn,
        providers,
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
        .request_name_with_flags(
            "org.freedesktop.secrets",
            RequestNameFlags::DoNotQueue.into(),
        )
        .await
    {
        let owner_info = bus_name_owner_info(&conn, "org.freedesktop.secrets").await;
        anyhow::bail!("cannot claim org.freedesktop.secrets: {e}\n{owner_info}");
    }

    // Claim the portal bus name so xdg-desktop-portal can discover us.
    // Non-fatal: the portal works without its own name if rosecd already owns
    // org.freedesktop.secrets, but having a dedicated name is cleaner.
    if let Err(e) = conn
        .request_name_with_flags(
            "org.freedesktop.impl.portal.desktop.rosec",
            RequestNameFlags::DoNotQueue.into(),
        )
        .await
    {
        tracing::warn!("could not claim portal bus name: {e}");
    }

    // Start the SSH agent and FUSE filesystem.  Returns None if XDG_RUNTIME_DIR
    // is unset or FUSE is unavailable — the daemon continues without SSH
    // agent support.
    let ssh_manager: Option<Arc<ssh::SshManager>> = {
        let state_for_ssh = Arc::clone(&state);
        let confirm_cb = ssh::build_confirm_callback(move || state_for_ssh.prompt_config());
        ssh::SshManager::start(confirm_cb).await.map(Arc::new)
    };

    if let Some(ref sm) = ssh_manager {
        tracing::info!(sock = %sm.agent_sock().display(), "SSH agent ready");
    }

    // Start logind watcher unconditionally — it always subscribes to all
    // signals and checks the live config flags on each arrival.  This means
    // enabling on_session_lock or on_logout in the config takes effect
    // immediately without a restart.
    {
        let logind_state = Arc::clone(&state);
        let logind_ssh = ssh_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = logind_watcher(logind_state, logind_ssh).await {
                tracing::warn!("logind watcher exited: {e}");
            }
        });
    }

    wire_provider_callbacks(&state, &ssh_manager);

    // When running on a private bus, spawn a watcher that polls for the
    // session bus and migrates to it when available.
    #[cfg(feature = "private-socket")]
    if let bus::BusMode::Private { ref socket_path } = bus_mode {
        if bus_config.no_migrate {
            tracing::info!(
                socket = %socket_path.display(),
                "rosecd ready on private bus (migration disabled)"
            );
        } else {
            tracing::info!(
                socket = %socket_path.display(),
                interval_ms = bus_config.migrate_interval.as_millis() as u64,
                "rosecd ready on private bus, watching for session bus"
            );
            let watcher_state = Arc::clone(&state);
            let interval = bus_config.migrate_interval;
            tokio::spawn(async move {
                bus::session_bus_watcher(watcher_state, interval).await;
            });
        }
    } else {
        tracing::info!("rosecd ready on session bus");
    }

    #[cfg(not(feature = "private-socket"))]
    tracing::info!("rosecd ready on session bus");

    // Config file watcher — hot-reload providers when config.toml changes.
    {
        let watch_state = Arc::clone(&state);
        let watch_path = config_path.clone();
        let initial_config = config.clone();
        let watch_ssh = ssh_manager.clone();
        let watch_registry = plugin_registry;
        tokio::spawn(async move {
            if let Err(e) = config_watcher(
                watch_state,
                watch_path,
                initial_config,
                watch_ssh,
                watch_registry,
            )
            .await
            {
                tracing::warn!("config watcher exited: {e}");
            }
        });
    }

    let cache_rebuild_state = Arc::clone(&state);
    tokio::spawn(background_sync_loop(cache_rebuild_state));

    // Auto-lock policy background task.
    // Reads autolock settings from live_config on every tick so changes to the
    // config file take effect without a restart.  Each provider is evaluated
    // independently against its effective policy (global defaults merged with
    // any per-provider/per-vault overrides).
    let autolock_state = Arc::clone(&state);
    let autolock_ssh = ssh_manager.clone();
    tokio::spawn(autolock_loop(autolock_state, autolock_ssh));

    // Wait for SIGTERM or SIGINT for graceful shutdown.
    shutdown_signal().await;
    tracing::info!("received shutdown signal, locking all providers before exit");
    // Clear SSH keys first so no sign requests can be served during shutdown.
    if let Some(ref sm) = ssh_manager {
        sm.clear();
    }
    // Explicitly lock all providers so decrypted state is zeroed before the
    // process exits.  Errors are logged but not fatal — the process is exiting
    // anyway and Zeroizing<> drop impls will still run.
    if let Err(e) = state.auto_lock().await {
        tracing::warn!("lock-on-exit failed: {e}");
    }
    tracing::info!("all providers locked, exiting");
    Ok(())
}

/// Background sync loop: periodically checks each unlocked provider for remote
/// changes, syncs when needed, and rebuilds the item cache as a safety net.
///
/// **Per-provider scheduling:** Each provider tracks its own last-checked
/// timestamp.  The loop ticks every [`SYNC_TICK_SECS`] seconds and only
/// processes providers whose effective interval has elapsed.
///
/// **Accelerated cached-mode retry:** When a provider is in cached mode
/// (operating from its offline cache), the effective interval is
/// `refresh_interval_secs × cache_sync_modifier` (default 0.2, i.e. 5×
/// more frequent).  Once a sync succeeds and clears the `cached` flag, the
/// provider reverts to its normal interval on the next tick.
///
/// Both `refresh_interval_secs` and `cache_sync_modifier` are read from
/// live config on every tick, so config changes take effect without a restart.
const SYNC_TICK_SECS: u64 = 5;

async fn background_sync_loop(state: Arc<rosec_secret_service::ServiceState>) {
    use std::collections::HashMap;
    use std::time::Instant;

    let mut consecutive_failures = 0u32;
    // Per-provider tracking: last time we checked, and per-provider failure
    // counter for log suppression.
    let mut last_checked: HashMap<String, Instant> = HashMap::new();
    let mut provider_failures: HashMap<String, u32> = HashMap::new();

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(SYNC_TICK_SECS)).await;

        let config = state.live_config();
        let base_interval_secs = config.service.refresh_interval_secs.unwrap_or(60);
        let now = Instant::now();

        let mut did_any_work = false;

        for provider in state.providers_ordered() {
            let provider_id = provider.id().to_string();

            // Skip providers that don't support sync — avoids pointless
            // check_remote_changed / sync cycles for read-only backends
            // like gnome-keyring.
            if !provider.capabilities().contains(&Capability::Sync) {
                continue;
            }

            let status = match provider.status().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(provider = %provider_id, error = %e, "status check failed, skipping");
                    continue;
                }
            };

            if status.locked {
                tracing::debug!(provider = %provider_id, "background: provider locked, skipping sync");
                // Reset last-checked so that when it unlocks, we check
                // immediately rather than waiting a full interval.
                last_checked.remove(&provider_id);
                continue;
            }

            // Compute effective interval: accelerate when cached.
            let fraction = if status.cached {
                config
                    .provider
                    .iter()
                    .find(|e| e.id == provider_id)
                    .map_or(0.2, |e| e.effective_cache_sync_modifier())
            } else {
                1.0
            };
            let effective_secs = (base_interval_secs as f64 * fraction)
                .ceil()
                .max(SYNC_TICK_SECS as f64) as u64;

            // Check whether enough time has elapsed since last check.
            // First iteration or just unlocked → no entry → check immediately.
            if let Some(&last) = last_checked.get(&provider_id)
                && now.duration_since(last).as_secs() < effective_secs
            {
                continue;
            }

            last_checked.insert(provider_id.clone(), now);

            if status.cached {
                tracing::debug!(
                    provider = %provider_id,
                    effective_interval_secs = effective_secs,
                    "background: provider cached, using accelerated sync interval"
                );
            }

            match provider.check_remote_changed().await {
                Ok(true) => {
                    tracing::debug!(provider = %provider_id, "background: remote changed, syncing");
                    match state.try_sync_provider(&provider_id).await {
                        Ok(true) => {
                            tracing::debug!(provider = %provider_id, "background: sync ok");
                            did_any_work = true;
                            provider_failures.remove(&provider_id);

                            if status.cached {
                                tracing::info!(
                                    provider = %provider_id,
                                    "provider recovered from cached mode after successful sync"
                                );
                            }
                        }
                        Ok(false) => {
                            tracing::debug!(provider = %provider_id, "background: sync skipped (already in progress)");
                        }
                        Err(e) => {
                            if handle_sync_auth_failure(&e, &provider, &provider_id).await {
                                last_checked.remove(&provider_id);
                                provider_failures.remove(&provider_id);
                            } else {
                                let pf = provider_failures.entry(provider_id.clone()).or_insert(0);
                                log_background_failure(pf, &provider_id, "sync", &e);
                            }
                        }
                    }
                }
                Ok(false) => {
                    tracing::debug!(provider = %provider_id, "background: no remote changes");
                    provider_failures.remove(&provider_id);

                    // If the provider is cached but probes passed (no remote
                    // changes is still a successful probe), try syncing anyway
                    // to refresh from the server and clear cached state.
                    if status.cached {
                        tracing::info!(
                            provider = %provider_id,
                            "background: provider cached but probes passed, forcing sync to recover"
                        );
                        match state.try_sync_provider(&provider_id).await {
                            Ok(true) => {
                                tracing::info!(
                                    provider = %provider_id,
                                    "provider recovered from cached mode after forced sync"
                                );
                                did_any_work = true;
                                provider_failures.remove(&provider_id);
                            }
                            Ok(false) => {
                                tracing::debug!(
                                    provider = %provider_id,
                                    "background: forced sync skipped (already in progress)"
                                );
                            }
                            Err(e) => {
                                if handle_sync_auth_failure(&e, &provider, &provider_id).await {
                                    last_checked.remove(&provider_id);
                                    provider_failures.remove(&provider_id);
                                } else {
                                    let pf =
                                        provider_failures.entry(provider_id.clone()).or_insert(0);
                                    log_background_failure(
                                        pf,
                                        &provider_id,
                                        "forced sync (cached recovery)",
                                        &e,
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(provider = %provider_id, error = %e,
                        "background: remote-changed check failed, skipping sync");
                }
            }
        }

        // Safety-net rebuild: keep the in-process item cache consistent
        // even if no per-provider sync ran.
        if !did_any_work {
            match state.rebuild_cache().await {
                Ok(entries) => {
                    tracing::debug!("background cache rebuild: {} items", entries.len());
                    consecutive_failures = 0;
                }
                Err(err) => {
                    log_background_failure(&mut consecutive_failures, "", "cache rebuild", &err);
                }
            }
        } else {
            consecutive_failures = 0;
        }
    }
}

/// Handle `auth_failed` errors from background sync.
///
/// When a sync attempt fails with `auth_failed`, the provider's session is
/// unrecoverable in the background (the refresh token has expired or been
/// revoked).  Lock the provider so the next user interaction triggers a
/// normal unlock prompt — exactly as if it were a fresh start.
///
/// Returns `true` if the error was `auth_failed` and the provider was
/// locked, `false` for all other errors (caller should handle normally).
async fn handle_sync_auth_failure(
    error: &zbus::fdo::Error,
    provider: &Arc<dyn Provider>,
    provider_id: &str,
) -> bool {
    let err_str = error.to_string();
    if !err_str.contains("auth_failed") {
        return false;
    }

    tracing::warn!(
        provider = %provider_id,
        "background sync failed with auth_failed — session is unrecoverable, \
         locking provider to trigger re-unlock on next access"
    );

    if let Err(lock_err) = provider.lock().await {
        tracing::error!(
            provider = %provider_id,
            error = %lock_err,
            "failed to lock provider after auth_failed"
        );
    }

    true
}

/// Auto-lock policy loop: evaluates idle-timeout and max-unlocked policies for
/// each provider every 30 seconds.
///
/// Reads autolock settings from live_config on every tick so config file changes
/// take effect without a restart.
async fn autolock_loop(
    state: Arc<rosec_secret_service::ServiceState>,
    ssh_manager: Option<Arc<ssh::SshManager>>,
) {
    let check_interval = tokio::time::Duration::from_secs(30);
    loop {
        tokio::time::sleep(check_interval).await;

        let mut any_locked = false;

        for provider in state.providers_ordered() {
            let provider_id = provider.id().to_string();
            let policy = state.effective_autolock_policy(&provider_id);

            // Check idle timeout (0 means disabled).
            if let Some(idle_min) = policy.idle_timeout_minutes
                && idle_min != 0
                && state.is_idle_expired(idle_min)
            {
                tracing::info!(
                    provider = %provider_id,
                    idle_minutes = idle_min,
                    "idle timeout expired, locking provider"
                );
                if let Err(e) = state.auto_lock_provider(&provider_id).await {
                    tracing::warn!(provider = %provider_id, "auto-lock failed: {e}");
                } else {
                    any_locked = true;
                }
                continue;
            }

            // Check max-unlocked timeout (0 means disabled).
            if let Some(max_min) = policy.max_unlocked_minutes
                && max_min != 0
                && state.is_provider_max_unlocked_expired(&provider_id, max_min)
            {
                tracing::info!(
                    provider = %provider_id,
                    max_minutes = max_min,
                    "max-unlocked timeout expired, locking provider"
                );
                if let Err(e) = state.auto_lock_provider(&provider_id).await {
                    tracing::warn!(provider = %provider_id, "auto-lock failed: {e}");
                } else {
                    any_locked = true;
                }
            }
        }

        if any_locked && state.all_providers_locked() {
            if let Some(ref sm) = ssh_manager {
                sm.clear();
            }
            state.mark_locked();
        }
    }
}

/// Log a background task failure with progressive suppression.
///
/// Logs warnings for the first 3 failures, a suppression notice on the 4th,
/// and silently skips further warnings. Errors starting with `"locked::"` are
/// logged at debug level since they indicate an expected locked-provider state.
fn log_background_failure(
    consecutive: &mut u32,
    provider_id: &str,
    operation: &str,
    error: &dyn std::fmt::Display,
) {
    let err_str = error.to_string();
    if err_str.starts_with("locked::") {
        tracing::debug!(provider = %provider_id, "background {operation} skipped — provider locked");
        return;
    }
    *consecutive += 1;
    if *consecutive <= 3 {
        tracing::warn!(provider = %provider_id, attempt = *consecutive, "background {operation} failed: {error}");
    } else if *consecutive == 4 {
        tracing::warn!(
            provider = %provider_id,
            "background {operation} has failed {} times, suppressing further warnings",
            *consecutive
        );
    }
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

// ---------------------------------------------------------------------------

/// Ask logind for the session that owns our PID via `GetSessionByPID`.
///
/// Returns the session ID string (e.g. "3") on success, or `None` if logind
/// is unavailable or our process has no associated session (e.g. running in a
/// pure TTY without PAM, or inside a container).
async fn resolve_session_id_from_logind(system_bus: &zbus::Connection) -> Option<String> {
    let pid = std::process::id();
    let proxy = zbus::Proxy::new(
        system_bus,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )
    .await
    .ok()?;

    // GetSessionByPID returns the object path of the session, e.g.
    // /org/freedesktop/login1/session/_33  (where _33 is the encoded session ID)
    let session_path: zbus::zvariant::OwnedObjectPath =
        proxy.call("GetSessionByPID", &(pid,)).await.ok()?;

    // The session ID is the last path component, with systemd D-Bus encoding
    // reversed (_XX → char).  For the common numeric case this is a no-op.
    let id_encoded = session_path.as_str().rsplit('/').next()?;
    let id = decode_dbus_path_component(id_encoded);
    tracing::debug!(pid, session_id = %id, "resolved session ID from logind");
    Some(id)
}

/// Reverse systemd's D-Bus object-path encoding: `_XX` → the character with
/// hex code `XX`.  Alphanumeric characters and `_` that are not followed by
/// two hex digits are passed through unchanged.
fn decode_dbus_path_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '_' {
            // Try to consume exactly two hex digits.
            let h1 = chars.next();
            let h2 = chars.next();
            match (h1, h2) {
                (Some(a), Some(b)) if a.is_ascii_hexdigit() && b.is_ascii_hexdigit() => {
                    let byte = u8::from_str_radix(&format!("{a}{b}"), 16).unwrap_or(b'_');
                    out.push(byte as char);
                }
                (Some(a), Some(b)) => {
                    out.push('_');
                    out.push(a);
                    out.push(b);
                }
                (Some(a), None) => {
                    out.push('_');
                    out.push(a);
                }
                (None, _) => out.push('_'),
            }
        } else {
            out.push(c);
        }
    }
    out
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
///
/// Each signal handler iterates providers and checks their effective autolock
/// policies before locking.
async fn logind_watcher(
    state: Arc<rosec_secret_service::ServiceState>,
    ssh_manager: Option<Arc<ssh::SshManager>>,
) -> anyhow::Result<()> {
    use futures_util::TryStreamExt;
    use zbus::Connection;

    let system_bus = Connection::system().await?;

    // Determine our own session ID.  Prefer XDG_SESSION_ID from the environment
    // (set by PAM / login shells), but fall back to asking logind for the session
    // that owns our PID.  This handles the case where rosecd is started as a
    // systemd user service and XDG_SESSION_ID is not propagated into the unit.
    let session_id = match std::env::var("XDG_SESSION_ID").ok() {
        Some(id) => Some(id),
        None => resolve_session_id_from_logind(&system_bus).await,
    };

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
                            tracing::info!("logind: PrepareForSleep — locking all providers");
                            if let Some(ref sm) = ssh_manager {
                                sm.clear();
                            }
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
                        // SessionRemoved(id: &str, path: OwnedObjectPath)
                        // Only lock if the removed session is *our* session.
                        if let Ok(body) = msg.body().deserialize::<(String, zbus::zvariant::OwnedObjectPath)>() {
                            let removed_id = body.0;
                            if session_id.as_deref() == Some(&removed_id) {
                                // Check per-provider on_logout policies.
                                let mut any_locked = false;
                                for provider in state.providers_ordered() {
                                    let pid = provider.id().to_string();
                                    let policy = state.effective_autolock_policy(&pid);
                                    if policy.on_logout {
                                        tracing::info!(
                                            session = %removed_id,
                                            provider = %pid,
                                            "logind: our session removed — locking provider"
                                        );
                                        if let Err(e) = state.auto_lock_provider(&pid).await {
                                            tracing::warn!(provider = %pid, "auto-lock on logout failed: {e}");
                                        } else {
                                            any_locked = true;
                                        }
                                    }
                                }
                                if any_locked && state.all_providers_locked() {
                                    if let Some(ref sm) = ssh_manager {
                                        sm.clear();
                                    }
                                    state.mark_locked();
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
                        // Check per-provider on_session_lock policies.
                        let mut any_locked = false;
                        for provider in state.providers_ordered() {
                            let pid = provider.id().to_string();
                            let policy = state.effective_autolock_policy(&pid);
                            if policy.on_session_lock {
                                tracing::info!(
                                    provider = %pid,
                                    "logind: session Lock signal — locking provider"
                                );
                                if let Err(e) = state.auto_lock_provider(&pid).await {
                                    tracing::warn!(provider = %pid, "auto-lock on session lock failed: {e}");
                                } else {
                                    any_locked = true;
                                }
                            }
                        }
                        if any_locked && state.all_providers_locked() {
                            if let Some(ref sm) = ssh_manager {
                                sm.clear();
                            }
                            state.mark_locked();
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

/// Register lifecycle and nudge event callbacks on every provider.
///
/// Remote nudge callbacks (sync / lock) are set as fields on
/// [`ProviderCallbacks`] before calling `set_event_callbacks()`.  Providers
/// that support remote push notifications (e.g. Bitwarden PM) wire these
/// into their internal SignalR handler.
///
/// Called once after `state` and `ssh_manager` are created, and again after
/// each hot-reload that adds a new provider.
fn wire_provider_callbacks(
    state: &Arc<rosec_secret_service::ServiceState>,
    ssh_manager: &Option<Arc<ssh::SshManager>>,
) {
    use rosec_core::ProviderCallbacks;

    for provider in state.providers_ordered() {
        let provider_id = provider.id().to_string();

        // --- Lifecycle event callbacks (all providers via trait) ---

        let ssh_unlocked = ssh_manager.clone();
        let ssh_synced = ssh_manager.clone();
        let ssh_locked = ssh_manager.clone();
        let providers_for_unlock = Arc::clone(state);
        let providers_for_sync = Arc::clone(state);
        let locked_id = provider_id.clone();
        let synced_id = provider_id.clone();
        let failed_id = provider_id.clone();

        // --- Remote nudge callbacks (e.g. Bitwarden SignalR) ---
        let sync_state = Arc::clone(state);
        let lock_state = Arc::clone(state);
        let nudge_sync_id = provider_id.clone();
        let nudge_lock_id = provider_id.clone();

        let callbacks = ProviderCallbacks {
            on_unlocked: Some(Arc::new(move || {
                // Trigger an immediate SSH key rebuild so keys appear as soon
                // as the provider is unlocked — no need to wait for the next
                // background timer tick.
                let sm = ssh_unlocked.clone();
                let s = Arc::clone(&providers_for_unlock);
                tokio::spawn(async move {
                    if let Some(ref sm) = sm {
                        let providers = s.providers_ordered();
                        sm.rebuild(&providers).await;
                    }
                });
            })),
            on_locked: Some(Arc::new(move || {
                // Evict only this provider's keys; other providers stay available.
                if let Some(ref sm) = ssh_locked {
                    sm.remove_provider(&locked_id);
                }
            })),
            on_sync_succeeded: Some(Arc::new(move |changed| {
                if !changed {
                    return; // Nothing new — skip the rebuild.
                }
                let sm = ssh_synced.clone();
                let s = Arc::clone(&providers_for_sync);
                let id = synced_id.clone();
                tokio::spawn(async move {
                    if let Some(ref sm) = sm {
                        let providers = s.providers_ordered();
                        tracing::debug!(provider = %id, "sync changed vault — rebuilding SSH keys");
                        sm.rebuild(&providers).await;
                    }
                });
            })),
            on_sync_failed: Some(Arc::new(move || {
                tracing::debug!(provider = %failed_id, "sync failed (SSH keys unchanged)");
            })),
            on_remote_sync_nudge: Some(Arc::new(move || {
                let s = Arc::clone(&sync_state);
                let id = nudge_sync_id.clone();
                tokio::spawn(async move {
                    match s.try_sync_provider(&id).await {
                        Ok(true) => tracing::debug!(provider = %id, "remote nudge: sync triggered"),
                        Ok(false) => {
                            tracing::debug!(provider = %id, "remote nudge: sync already in progress")
                        }
                        Err(e) => {
                            tracing::debug!(provider = %id, error = %e, "remote nudge: sync trigger failed")
                        }
                    }
                });
            })),
            on_remote_lock_nudge: Some(Arc::new(move || {
                let s = Arc::clone(&lock_state);
                let id = nudge_lock_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = s.auto_lock().await {
                        tracing::warn!(provider = %id, error = %e, "remote nudge: auto-lock failed");
                    }
                });
            })),
        };

        if let Err(e) = provider.set_event_callbacks(callbacks) {
            tracing::warn!(provider = %provider.id(), error = %e, "failed to set event callbacks (lock poisoned)");
        }
    }
}

/// Build all configured providers, in order.
///
/// Local vaults (`kind = "local"`) and external providers (`kind = "bitwarden-pm"`,
/// `"bitwarden-sm"`, etc.) are built from the unified `[[provider]]` config entries.
/// Both go through the same `Provider` trait.
async fn build_providers(
    config: &Config,
    plugin_registry: &rosec_wasm::PluginRegistry,
) -> Result<Vec<Arc<dyn Provider>>> {
    if config.provider.is_empty() {
        tracing::warn!("no providers configured");
        return Ok(Vec::new());
    }

    let mut providers: Vec<Arc<dyn Provider>> = Vec::with_capacity(config.provider.len());

    for entry in &config.provider {
        if !entry.enabled {
            tracing::info!(
                provider_id = %entry.id,
                provider_kind = %entry.kind,
                "provider disabled, skipping"
            );
            continue;
        }
        match entry.kind.as_str() {
            "local" => {
                let provider = build_vault_provider(entry);
                tracing::info!(
                    vault_id = %entry.id,
                    path = %entry.path.as_deref().unwrap_or(""),
                    "vault initialized"
                );
                providers.push(provider);
            }
            _ => match build_single_provider(entry, plugin_registry).await {
                Ok(provider) => {
                    tracing::info!(
                        provider_id = %entry.id,
                        provider_kind = %entry.kind,
                        "provider initialized"
                    );
                    providers.push(provider);
                }
                Err(e) if e.to_string().starts_with("unknown provider kind") => {
                    tracing::warn!(
                        provider_id = %entry.id,
                        provider_kind = %entry.kind,
                        "unknown provider type; skipping"
                    );
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "failed to initialize provider '{}': {e}",
                        entry.id
                    ));
                }
            },
        }
    }

    Ok(providers)
}

/// Construct a vault provider from a `[[provider]]` config entry with `kind = "local"`.
///
/// The path undergoes `~` expansion and, if relative, is resolved against
/// `$XDG_DATA_HOME/rosec/vaults/`.
fn build_vault_provider(entry: &rosec_core::config::ProviderEntry) -> Arc<dyn Provider> {
    let path = expand_vault_path(entry.path.as_deref().unwrap_or(""));
    Arc::new(rosec_vault::LocalVault::new(&entry.id, path))
}

/// Expand `~` in a vault path and resolve relative paths against the default
/// vault directory.
fn expand_vault_path(raw: &str) -> PathBuf {
    let expanded = if let Some(stripped) = raw.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home).join(stripped)
        } else {
            PathBuf::from(raw)
        }
    } else {
        PathBuf::from(raw)
    };

    if expanded.is_relative() {
        // Default vault directory: $XDG_DATA_HOME/rosec/vaults/
        let data_dir = std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(home).join(".local/share")
            })
            .join("rosec/vaults");
        data_dir.join(expanded)
    } else {
        expanded
    }
}

/// Compute a stable fingerprint string for a provider config entry.
///
/// The fingerprint covers `kind`, `path` (for local vaults), all `options`
/// (sorted), `return_attr`, `match_attr`, and `collection`.  Two entries are
/// considered identical iff their fingerprints are equal, so hot-reload only
/// removes/re-adds providers that materially changed.
fn provider_fingerprint(entry: &rosec_core::config::ProviderEntry) -> String {
    let mut opts: Vec<String> = entry
        .options
        .iter()
        .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
        .collect();
    opts.sort();

    let path = entry.path.as_deref().unwrap_or("");
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
    let collection = entry.collection.as_deref().unwrap_or_default();

    format!(
        "{}:enabled={}:path={}:{}:return_attr={}:match_attr={}:collection={}",
        entry.kind,
        entry.enabled,
        path,
        opts.join(","),
        return_attr,
        match_attr,
        collection,
    )
}

/// Watch the config file and hot-reload providers when it changes.
///
/// Uses `notify` (inotify on Linux) to detect writes/renames, debounces
/// rapid events with a 500 ms quiet period, then diffs the provider list:
/// - New provider IDs → construct and hot-add
/// - Removed provider IDs → lock then hot-remove
/// - Changed options for an existing ID → treat as remove + add
///
/// `initial_config` is the config that was active when the daemon started (or
/// last reloaded).  It is used to seed the fingerprint so the first comparison
/// is against actual config values rather than bare provider IDs.
///
/// Parse errors are logged as warnings; the running config is left intact.
async fn config_watcher(
    state: Arc<rosec_secret_service::ServiceState>,
    config_path: PathBuf,
    initial_config: Config,
    ssh_manager: Option<Arc<ssh::SshManager>>,
    mut plugin_registry: rosec_wasm::PluginRegistry,
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
    // first run before `rosec provider add` has been called).
    std::fs::create_dir_all(watch_dir).map_err(|e| {
        anyhow::anyhow!(
            "cannot create config directory {}: {e}",
            watch_dir.display()
        )
    })?;

    watcher.watch(watch_dir, notify::RecursiveMode::NonRecursive)?;
    tracing::info!(path = %config_path.display(), "config watcher started");

    // Seed `known` from the initial config fingerprints so the first diff
    // compares actual config values — not bare provider IDs.
    let mut known: Vec<(String, String)> = initial_config
        .provider
        .iter()
        .map(|entry| (entry.id.clone(), provider_fingerprint(entry)))
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
            .provider
            .iter()
            .map(|entry| (entry.id.clone(), provider_fingerprint(entry)))
            .collect();

        if new_fingerprints == known {
            tracing::debug!("config unchanged, no reload needed");
            continue;
        }

        tracing::info!(path = %config_path.display(), "config changed, hot-reloading providers");

        let known_ids: HashSet<&str> = known.iter().map(|(id, _)| id.as_str()).collect();

        // Remove providers that are gone or changed (changed = remove + re-add).
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
            if changed && state.hotreload_remove_provider(id).await {
                tracing::info!(provider_id = id, "hot-reload: removed provider");
                // Evict this provider's SSH keys immediately.
                if let Some(ref sm) = ssh_manager {
                    sm.remove_provider(id);
                }
            }
        }

        // Add providers that are new or changed.
        let mut added_any = false;

        // Re-scan WASM plugins if the new config references any provider
        // kinds that the current registry doesn't know about.  This lets
        // users deploy a new `.wasm` plugin and immediately reference it
        // in config without restarting the daemon.
        let needs_rescan = new_config.provider.iter().any(|entry| {
            let id = entry.id.as_str();
            let is_new = !known_ids.contains(id);
            let is_changed = known_map
                .get(id)
                .is_some_and(|old_fp| new_map.get(id).is_some_and(|new_fp| old_fp != new_fp));
            (is_new || is_changed)
                && !matches!(entry.kind.as_str(), "local")
                && !plugin_registry.contains_kind(&entry.kind)
        });
        if needs_rescan {
            tracing::info!("hot-reload: re-scanning WASM plugins for new provider kinds");
            plugin_registry = rosec_wasm::discovery::scan_plugins(
                new_config.service.wasm_prefer,
                new_config.service.wasm_verify,
            );
        }

        for entry in &new_config.provider {
            let id = entry.id.as_str();
            let is_new = !known_ids.contains(id);
            let is_changed = known_map
                .get(id)
                .is_some_and(|old_fp| new_map.get(id).is_some_and(|new_fp| old_fp != new_fp));
            if is_new || is_changed {
                // Skip disabled providers — they were already removed above
                // (the fingerprint changed), so there is nothing to add back.
                if !entry.enabled {
                    tracing::info!(provider_id = id, "hot-reload: provider disabled, skipping");
                    continue;
                }
                match entry.kind.as_str() {
                    "local" => {
                        let provider = build_vault_provider(entry);
                        state.hotreload_add_provider(provider);
                        tracing::info!(vault_id = id, "hot-reload: added vault");
                        added_any = true;
                    }
                    _ => match build_single_provider(entry, &plugin_registry).await {
                        Ok(provider) => {
                            state.hotreload_add_provider(provider);
                            tracing::info!(provider_id = id, "hot-reload: added provider");
                            added_any = true;
                        }
                        Err(e) => {
                            tracing::warn!(provider_id = id, error = %e, "hot-reload: failed to construct provider");
                        }
                    },
                }
            }
        }

        // Re-wire callbacks after hot-reload so new providers get their event
        // callbacks and nudge callbacks registered immediately.
        if added_any {
            wire_provider_callbacks(&state, &ssh_manager);
        }

        // ── Hot-reload non-provider config sections ────────────────────────
        // These are live-updated in ServiceState and the Router so background
        // tasks pick up the new values on their next tick without a restart.
        let old_config = state.live_config();

        // Track whether dedup-relevant state changed so we can rebuild the
        // cache once at the end, ensuring all D-Bus clients see the new
        // dedup results immediately.
        let mut dedup_changed = false;

        if new_config.service.dedup_strategy != old_config.service.dedup_strategy
            || new_config.service.dedup_time_fallback != old_config.service.dedup_time_fallback
        {
            state
                .router
                .update_config(rosec_core::router::RouterConfig {
                    dedup_strategy: new_config.service.dedup_strategy,
                    dedup_time_fallback: new_config.service.dedup_time_fallback,
                });
            tracing::info!(
                dedup_strategy = ?new_config.service.dedup_strategy,
                dedup_time_fallback = ?new_config.service.dedup_time_fallback,
                "hot-reload: service dedup config updated"
            );
            dedup_changed = true;
        }

        // Reorder providers to match the new config ordering.  This affects
        // the Priority dedup strategy and tie-breaking in Newest.
        let config_order: Vec<String> = new_config
            .provider
            .iter()
            .filter(|e| e.enabled)
            .map(|e| e.id.clone())
            .collect();
        if state.reorder_providers(&config_order) {
            tracing::info!("hot-reload: provider order updated");
            dedup_changed = true;
        }

        // If dedup config or provider order changed, force a cache rebuild
        // so D-Bus clients see corrected results immediately.
        if dedup_changed {
            tracing::info!("hot-reload: rebuilding cache for new dedup/ordering config");
            let state2 = Arc::clone(&state);
            if let Err(e) = state2.rebuild_cache().await {
                tracing::warn!(error = %e, "hot-reload: cache rebuild failed after dedup config change");
            }
        }
        if new_config.service.refresh_interval_secs != old_config.service.refresh_interval_secs {
            tracing::info!(
                refresh_interval_secs = ?new_config.service.refresh_interval_secs,
                "hot-reload: refresh_interval_secs updated (takes effect on next timer tick)"
            );
        }
        // Log per-provider cache_sync_modifier changes.
        for new_entry in &new_config.provider {
            let old_fraction = old_config
                .provider
                .iter()
                .find(|e| e.id == new_entry.id)
                .and_then(|e| e.cache_sync_modifier);
            if new_entry.cache_sync_modifier != old_fraction {
                tracing::info!(
                    provider = %new_entry.id,
                    cache_sync_modifier = ?new_entry.cache_sync_modifier,
                    effective = new_entry.effective_cache_sync_modifier(),
                    "hot-reload: cache_sync_modifier updated (takes effect on next sync tick)"
                );
            }
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
            "hot-reload complete ({} providers active)",
            state.provider_count()
        );
    }

    Ok(())
}

/// Construct a single provider from a config entry.
///
/// Extracted from `build_providers` so the hot-reload watcher can reuse it
/// without re-parsing the whole config.
///
/// All providers are returned locked; the daemon unlocks them via `AuthProvider`
/// D-Bus calls once the user supplies credentials interactively.
async fn build_single_provider(
    entry: &rosec_core::config::ProviderEntry,
    plugin_registry: &rosec_wasm::PluginRegistry,
) -> anyhow::Result<Arc<dyn Provider>> {
    match entry.kind.as_str() {
        kind if plugin_registry.contains_kind(kind) => {
            let discovered = plugin_registry.get(kind).expect("contains_kind was true");

            let name = entry
                .options
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(&entry.id)
                .to_string();

            // User-specified allowed_hosts override manifest defaults.
            let explicit_hosts = entry.options.get("allowed_hosts").and_then(|v| v.as_str());
            let mut allowed_hosts: Vec<String> = explicit_hosts
                .map(|s| s.split(',').map(|h| h.trim().to_string()).collect())
                .unwrap_or_else(|| discovered.manifest.default_allowed_hosts.clone());

            // When using defaults (no explicit allowed_hosts), auto-derive
            // hostnames from URL-valued options so self-hosted servers work
            // without requiring a manual allowed_hosts override.
            if explicit_hosts.is_none() {
                let derived: Vec<String> = ["base_url", "api_url", "identity_url"]
                    .iter()
                    .filter_map(|k| entry.options.get(*k).and_then(|v| v.as_str()))
                    .filter_map(extract_host_from_url)
                    .filter(|h| !allowed_hosts.contains(h))
                    .collect();
                allowed_hosts.extend(derived);
            }

            // Forward all options except host-consumed ones to the guest.
            let mut guest_options: std::collections::HashMap<String, serde_json::Value> = entry
                .options
                .iter()
                .filter(|(k, _)| !matches!(k.as_str(), "name" | "allowed_hosts"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            // Inject host-managed device_id if the guest doesn't already have one.
            // Bitwarden APIs require a stable deviceIdentifier; the WASM sandbox
            // cannot access the filesystem, so the host provides it.
            guest_options
                .entry("device_id".to_string())
                .or_insert_with(|| serde_json::Value::String(load_or_create_device_id()));

            // Compute WASI filesystem paths to pre-open for the sandbox.
            let allowed_paths = compute_wasi_allowed_paths(kind, &guest_options);

            let wasm_config = rosec_wasm::WasmProviderConfig {
                id: entry.id.clone(),
                name,
                kind: kind.to_string(),
                wasm_path: discovered.wasm_path.display().to_string(),
                allowed_hosts,
                allowed_paths,
                options: guest_options,
                offline_cache: entry.offline_cache,
                tls_mode: entry.tls_mode.clone(),
                tls_mode_probe: entry.tls_mode_probe.clone(),
            };

            Ok(Arc::new(
                rosec_wasm::WasmProvider::new(wasm_config)
                    .map_err(|e| anyhow::anyhow!("plugin provider '{}': {e}", entry.id))?,
            ))
        }
        other => anyhow::bail!("unknown provider kind '{other}'"),
    }
}

/// Extract the hostname from a URL string.  Returns `None` for malformed input.
fn extract_host_from_url(url_str: &str) -> Option<String> {
    url::Url::parse(url_str)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
}

/// Compute WASI filesystem paths to pre-open for a plugin.
///
/// The WASI sandbox blocks all host filesystem access unless directories are
/// explicitly pre-opened.  This function inspects the plugin kind and options
/// to determine which host paths the guest needs.
///
/// Paths are returned as `(src, dest)` pairs where `src` is the host path
/// (prefixed with `ro:` for read-only) and `dest` is the guest-visible path.
fn compute_wasi_allowed_paths(
    kind: &str,
    options: &std::collections::HashMap<String, serde_json::Value>,
) -> Vec<(String, PathBuf)> {
    let mut paths = Vec::new();

    if kind == "gnome-keyring" {
        // Mirror the guest's default: keyring_dir option, or $HOME/.local/share/keyrings
        let keyring_dir = options
            .get("keyring_dir")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| {
                options
                    .get("home_dir")
                    .and_then(|v| v.as_str())
                    .map(|h| format!("{h}/.local/share/keyrings"))
            })
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|h| format!("{h}/.local/share/keyrings"))
            });

        if let Some(dir) = keyring_dir {
            let dest = PathBuf::from(&dir);
            paths.push((format!("ro:{dir}"), dest));
        }
    }

    paths
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
        if args[i] == "--version" || args[i] == "-V" {
            eprintln!(
                "rosecd {} ({})",
                env!("ROSEC_VERSION"),
                env!("ROSEC_GIT_SHA")
            );
            std::process::exit(0);
        }
        if args[i] == "--help" || args[i] == "-h" {
            eprintln!("Usage: rosecd [OPTIONS]");
            eprintln!();
            eprintln!("Options:");
            eprintln!(
                "  -c, --config <path>          Config file (default: $XDG_CONFIG_HOME/rosec/config.toml)"
            );
            #[cfg(feature = "private-socket")]
            {
                eprintln!(
                    "      --socket <path>          Run on a private bus at <path> (no session bus)"
                );
                eprintln!(
                    "      --no-migrate             Stay on private bus, never migrate to session bus"
                );
                eprintln!(
                    "      --migrate-interval <s>   Session bus poll interval in seconds (default: 1)"
                );
            }
            eprintln!("  -V, --version                Show version");
            eprintln!("  -h, --help                   Show this help message");
            std::process::exit(0);
        }
        i += 1;
    }
    default_config_path()
}

#[cfg(feature = "private-socket")]
fn parse_bus_config() -> bus::BusConfig {
    let args: Vec<String> = std::env::args().collect();
    let mut config = bus::BusConfig::default();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--socket" {
            i += 1;
            config.socket_path = Some(
                args.get(i)
                    .unwrap_or_else(|| {
                        eprintln!("error: --socket requires a path argument");
                        std::process::exit(1);
                    })
                    .into(),
            );
            config.no_migrate = true;
        } else if let Some(path) = args[i].strip_prefix("--socket=") {
            config.socket_path = Some(path.into());
            config.no_migrate = true;
        } else if args[i] == "--no-migrate" {
            config.no_migrate = true;
        } else if args[i] == "--migrate-interval" {
            i += 1;
            let secs: f64 = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                eprintln!("error: --migrate-interval requires a numeric value");
                std::process::exit(1);
            });
            config.migrate_interval = std::time::Duration::from_secs_f64(secs);
        } else if let Some(val) = args[i].strip_prefix("--migrate-interval=") {
            let secs: f64 = val.parse().unwrap_or_else(|_| {
                eprintln!("error: --migrate-interval requires a numeric value");
                std::process::exit(1);
            });
            config.migrate_interval = std::time::Duration::from_secs_f64(secs);
        }
        i += 1;
    }
    config
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

// ── Device ID persistence ────────────────────────────────────────
//
// Bitwarden APIs require a stable `deviceIdentifier`.  The WASM provider
// cannot access the filesystem, so the host injects the device ID
// into its init options.

/// Return `$XDG_DATA_HOME/rosec/device_id` (default
/// `~/.local/share/rosec/device_id`).
fn device_id_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
    Some(base.join("rosec").join("device_id"))
}

/// Load an existing device ID or create and persist a new one.
///
/// Falls back to an ephemeral UUID when the data directory is
/// inaccessible.
fn load_or_create_device_id() -> String {
    let Some(path) = device_id_path() else {
        tracing::warn!("cannot determine data directory; using ephemeral device ID");
        return uuid::Uuid::new_v4().to_string();
    };

    // Try reading an existing device ID.
    if let Ok(contents) = std::fs::read_to_string(&path) {
        let id = contents.trim().to_string();
        if !id.is_empty() {
            tracing::debug!("loaded persistent device ID from {}", path.display());
            return id;
        }
    }

    // Generate and persist a new one.
    let id = uuid::Uuid::new_v4().to_string();
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        tracing::warn!(error = %e, "failed to create data directory; using ephemeral device ID");
        return id;
    }

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(id.as_bytes()))
        {
            Ok(()) => tracing::debug!("persisted new device ID to {}", path.display()),
            Err(e) => {
                tracing::warn!(error = %e, "failed to persist device ID to {}", path.display())
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = std::fs::write(&path, &id) {
            tracing::warn!(error = %e, "failed to persist device ID to {}", path.display());
        } else {
            tracing::debug!("persisted new device ID to {}", path.display());
        }
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_from_base_url() {
        assert_eq!(
            extract_host_from_url("https://vault.example.com/identity"),
            Some("vault.example.com".into()),
        );
    }

    #[test]
    fn extract_host_with_port_strips_port() {
        assert_eq!(
            extract_host_from_url("https://vault.lan:8443/api"),
            Some("vault.lan".into()),
        );
    }

    #[test]
    fn extract_host_garbage_returns_none() {
        assert_eq!(extract_host_from_url("not-a-url"), None);
    }
}
