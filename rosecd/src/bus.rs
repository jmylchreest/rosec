//! Bus management for resilient D-Bus startup.
//!
//! When the session bus is unavailable (e.g. during initial login before the
//! graphical session starts), rosecd spawns an embedded [`busd`] broker on a
//! private Unix socket and connects to it.  A background watcher polls for
//! the session bus and migrates to it when it appears.
//!
//! All code in this module is gated behind `#[cfg(feature = "private-socket")]`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rosec_secret_service::server::re_register_top_level_objects;
use rosec_secret_service::state::ServiceState;
use zbus::Connection;
use zbus::fdo::RequestNameFlags;

/// How the daemon is connected to a D-Bus bus.
pub enum BusMode {
    Session,
    /// Running an embedded private bus broker.
    Private {
        /// Path to the private socket.
        socket_path: PathBuf,
    },
}

/// Parsed CLI flags for bus behaviour.
pub struct BusConfig {
    /// Explicit socket path (`--socket`).  Implies no migration.
    pub socket_path: Option<PathBuf>,
    /// Disable migration even if started on private bus (`--no-migrate`).
    pub no_migrate: bool,
    /// Poll interval for session bus detection (`--migrate-interval`).
    pub migrate_interval: Duration,
}

impl Default for BusConfig {
    fn default() -> Self {
        Self {
            socket_path: None,
            no_migrate: false,
            migrate_interval: Duration::from_secs(1),
        }
    }
}

/// Attempt to establish a D-Bus connection according to the bus configuration.
///
/// Returns the connection and the bus mode.  When `config.socket_path` is set,
/// always starts a private bus.  Otherwise, tries the session bus first and
/// falls back to a private bus if unavailable.
pub async fn establish_connection(config: &BusConfig) -> Result<(Connection, BusMode)> {
    // Explicit --socket: always use private bus.
    if let Some(ref path) = config.socket_path {
        let conn = spawn_private_bus(path).await?;
        return Ok((
            conn,
            BusMode::Private {
                socket_path: path.clone(),
            },
        ));
    }

    // Try session bus first.
    match Connection::session().await {
        Ok(conn) => {
            tracing::info!("connected to session bus");
            Ok((conn, BusMode::Session))
        }
        Err(session_err) => {
            tracing::info!("session bus unavailable ({session_err}), starting private bus");
            let path = default_private_socket_path()?;
            let conn = spawn_private_bus(&path).await?;
            Ok((conn, BusMode::Private { socket_path: path }))
        }
    }
}

/// Spawn an embedded `busd` broker on `socket_path` and return a client
/// connection to it.
///
/// Holds umask 0o077 across the bind so the socket and its parent dir
/// are created at 0o600/0o700 atomically. Scope is deliberately tight:
/// umask is process-global on Linux (not thread-local), so any other
/// tokio task creating files while we hold this picks up the restrictive
/// mode. Don't widen the bracket without auditing concurrent fs work.
async fn spawn_private_bus(socket_path: &Path) -> Result<Connection> {
    // SAFETY: umask(2) takes no pointers and has no preconditions; the
    // hazard is the process-global state noted above, not memory safety.
    let old_umask = unsafe { libc::umask(0o077) };
    let setup_result = spawn_private_bus_inner(socket_path).await;
    // Restore even on error — a stuck 0o077 would silently affect every
    // later fs creation in the daemon (logs, state files, etc.).
    unsafe { libc::umask(old_umask) };
    setup_result
}

async fn spawn_private_bus_inner(socket_path: &Path) -> Result<Connection> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
        // Ensure the directory has 0o700 even if it already existed with
        // weaker permissions from a previous run.
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("set permissions on {}", parent.display()))?;
    }

    if socket_path.exists() {
        std::fs::remove_file(socket_path)
            .with_context(|| format!("remove stale socket {}", socket_path.display()))?;
    }

    let address = format!("unix:path={}", socket_path.display());

    let mut bus = busd::bus::Bus::for_address(Some(&address))
        .await
        .with_context(|| format!("create busd at {address}"))?;

    tokio::spawn(async move {
        if let Err(e) = bus.run().await {
            tracing::error!("private bus broker exited: {e}");
        }
    });

    // Poll for the socket to appear rather than an unconditional sleep.
    // busd binds almost immediately, but we need the spawned task to
    // actually reach its bind() call.
    for attempt in 0..20 {
        if socket_path.exists() {
            break;
        }
        if attempt == 19 {
            anyhow::bail!(
                "private bus socket did not appear at {} within 1s",
                socket_path.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let conn = zbus::connection::Builder::address(&*address)?
        .build()
        .await
        .with_context(|| format!("connect to private bus at {address}"))?;

    tracing::info!(socket = %socket_path.display(), "private bus broker started");

    Ok(conn)
}

/// Default private socket path: `$XDG_RUNTIME_DIR/rosec/bus`.
fn default_private_socket_path() -> Result<PathBuf> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!("XDG_RUNTIME_DIR not set — cannot create private bus socket")
        })?;
    Ok(runtime_dir.join("rosec").join("bus"))
}

/// Background task that polls for the session bus and migrates when it appears.
///
/// When `Connection::session()` succeeds and `org.freedesktop.secrets` can be
/// claimed, re-registers all D-Bus objects on the session bus, swaps the
/// connection in `ServiceState`, and rebuilds the item cache.
///
/// Exits when:
/// - Migration succeeds
/// - Another provider already owns the name (no point retrying)
/// - The task is cancelled
pub async fn session_bus_watcher(state: Arc<ServiceState>, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;

        // Try to connect to the session bus.
        let session_conn = match Connection::session().await {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Try to claim the well-known name.
        match session_conn
            .request_name_with_flags(
                "org.freedesktop.secrets",
                RequestNameFlags::DoNotQueue.into(),
            )
            .await
        {
            Ok(_) => {
                // Also claim the portal bus name on the session bus.
                if let Err(e) = session_conn
                    .request_name_with_flags(
                        "org.freedesktop.impl.portal.desktop.rosec",
                        RequestNameFlags::DoNotQueue.into(),
                    )
                    .await
                {
                    tracing::warn!("could not claim portal bus name on session bus: {e}");
                }

                // Name claimed — proceed with migration.
                match migrate_to_session_bus(&state, &session_conn).await {
                    Ok(()) => {
                        tracing::info!("migrated to session bus");
                        return;
                    }
                    Err(e) => {
                        tracing::warn!("migration to session bus failed: {e}");
                        // Release names since migration failed.
                        let _ = session_conn.release_name("org.freedesktop.secrets").await;
                        let _ = session_conn
                            .release_name("org.freedesktop.impl.portal.desktop.rosec")
                            .await;
                        // Retry on next tick — might be transient.
                        continue;
                    }
                }
            }
            Err(e) => {
                let owner_info = bus_name_owner_info(&session_conn).await;
                tracing::warn!(
                    "cannot claim org.freedesktop.secrets on session bus: {e}\n{owner_info}"
                );
                tracing::info!(
                    "staying on private bus — another Secret Service provider is active"
                );
                return;
            }
        }
    }
}

/// Perform the actual migration: re-register objects, swap connection, rebuild cache.
async fn migrate_to_session_bus(
    state: &Arc<ServiceState>,
    session_conn: &Connection,
) -> Result<()> {
    // Register top-level D-Bus objects on the session bus.
    re_register_top_level_objects(session_conn, state)
        .await
        .context("re-register top-level objects on session bus")?;

    // Swap the connection so dynamic item registration uses the new bus.
    state.swap_conn(session_conn.clone());

    // Clear registered items so rebuild_cache re-registers them all on the
    // new connection's ObjectServer.
    state.clear_registered_items();

    // Rebuild the cache — this re-registers all dynamic SecretItem objects.
    if let Err(e) = state.rebuild_cache().await {
        tracing::warn!("cache rebuild after migration failed: {e}");
        // Non-fatal — items will be registered on the next sync tick.
    }

    Ok(())
}

/// Query the session bus for who currently owns `org.freedesktop.secrets`.
async fn bus_name_owner_info(conn: &Connection) -> String {
    let proxy = match zbus::fdo::DBusProxy::new(conn).await {
        Ok(p) => p,
        Err(_) => return "  (could not query bus daemon)".to_string(),
    };

    let bus_name = match zbus::names::BusName::try_from("org.freedesktop.secrets") {
        Ok(n) => n,
        Err(_) => return "  (invalid bus name)".to_string(),
    };
    let unique_name = match proxy.get_name_owner(bus_name).await {
        Ok(n) => n.to_string(),
        Err(_) => return "  (no current owner)".to_string(),
    };

    let unique_bus_name = match zbus::names::BusName::try_from(unique_name.as_str()) {
        Ok(n) => n,
        Err(_) => return format!("  current owner: {unique_name}"),
    };
    let pid = match proxy.get_connection_unix_process_id(unique_bus_name).await {
        Ok(p) => p,
        Err(_) => return format!("  current owner: {unique_name} (PID unknown)"),
    };

    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    format!("  current owner: {comm} (PID {pid}, bus name {unique_name})")
}
