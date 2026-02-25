//! SSH agent and FUSE filesystem manager for `rosecd`.
//!
//! [`SshManager`] owns the [`KeyStore`], the background SSH agent listener, and
//! the FUSE mount handle.  It is the single point of contact between the
//! `rosecd` main loop and the `rosec-ssh-agent` / `rosec-fuse` crates.
//!
//! ## Lifecycle
//!
//! 1. [`SshManager::start`] — allocates paths, starts the agent socket listener,
//!    mounts the FUSE filesystem, returns the manager handle.
//! 2. [`SshManager::rebuild`] — called after each sync / unlock event; fetches
//!    all SSH keys from all provided backends, repopulates the key store, and
//!    refreshes the FUSE snapshot.
//! 3. [`SshManager::remove_backend`] — called when a backend is locked or
//!    removed; evicts that backend's keys from the store and refreshes FUSE.
//! 4. [`SshManager::clear`] — evicts all keys (called on global lock / shutdown).
//! 5. Drop of [`SshManager`] unmounts the FUSE filesystem and closes the agent
//!    socket (both handled by their respective RAII wrappers).

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, UNIX_EPOCH};

use rosec_core::VaultBackend;
use rosec_fuse::MountHandle;
use rosec_ssh_agent::keystore::{build_entry, KeyStore};
use rosec_ssh_agent::session::SshAgent;
use ssh_key::PrivateKey;
use tracing::{debug, info, warn};

/// Manages the SSH agent and FUSE filesystem on behalf of `rosecd`.
pub struct SshManager {
    store: Arc<RwLock<KeyStore>>,
    fuse_handle: MountHandle,
    /// Absolute path to the Unix socket (`$XDG_RUNTIME_DIR/rosec/agent.sock`).
    agent_sock: PathBuf,
}

impl std::fmt::Debug for SshManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshManager")
            .field("agent_sock", &self.agent_sock)
            .finish_non_exhaustive()
    }
}

impl SshManager {
    /// Start the SSH agent and FUSE filesystem.
    ///
    /// The agent socket is placed at `$XDG_RUNTIME_DIR/rosec/agent.sock`;
    /// the FUSE mount at `$XDG_RUNTIME_DIR/rosec/ssh/`.
    ///
    /// Returns `None` and logs a warning if `XDG_RUNTIME_DIR` is unset or the
    /// FUSE mount / socket creation fails — the daemon continues without SSH
    /// agent support rather than aborting.
    pub async fn start() -> Option<Self> {
        let runtime_dir = match std::env::var("XDG_RUNTIME_DIR") {
            Ok(d) => PathBuf::from(d),
            Err(_) => {
                warn!("XDG_RUNTIME_DIR not set — SSH agent and FUSE filesystem disabled");
                return None;
            }
        };

        let ssh_dir = runtime_dir.join("rosec").join("ssh");
        // Agent socket lives OUTSIDE the FUSE mountpoint (one level up) so it
        // can be bound on the real filesystem, not through FUSE.
        let agent_sock = runtime_dir.join("rosec").join("agent.sock");

        // Remove stale socket from a previous run.
        if agent_sock.exists()
            && let Err(e) = std::fs::remove_file(&agent_sock)
        {
            warn!(path = %agent_sock.display(), "failed to remove stale agent socket: {e}");
        }

        // Mount FUSE first — it creates the directory tree we bind into.
        let fuse_handle = match rosec_fuse::mount(&ssh_dir, agent_sock.clone()) {
            Ok(h) => h,
            Err(e) => {
                warn!("SSH FUSE mount failed (SSH agent disabled): {e:#}");
                return None;
            }
        };

        let store = KeyStore::new();

        // Spawn the agent listener in the background.
        {
            let agent = SshAgent::new(Arc::clone(&store), agent_sock.clone());
            tokio::spawn(async move {
                if let Err(e) = agent.listen().await {
                    warn!("SSH agent listener exited: {e}");
                }
            });
        }

        debug!(
            sock = %agent_sock.display(),
            mount = %ssh_dir.display(),
            "SSH agent started"
        );

        Some(Self { store, fuse_handle, agent_sock })
    }

    /// Rebuild the key store from the given set of backends.
    ///
    /// For each backend that is unlocked:
    /// 1. Call `list_ssh_keys()` to discover available keys.
    /// 2. Call `get_ssh_private_key(item_id)` for each key.
    /// 3. Parse the PEM and build a [`KeyEntry`].
    ///
    /// Keys from backends that are locked or that return errors are skipped
    /// with a debug log.  After all backends are processed the FUSE snapshot
    /// is refreshed atomically.
    pub async fn rebuild(&self, backends: &[Arc<dyn VaultBackend>]) {
        let mut new_entries = Vec::new();

        for backend in backends {
            let backend_id = backend.id().to_string();

            // Skip locked backends — no keys are available while locked.
            let locked = match backend.status().await {
                Ok(s) => s.locked,
                Err(e) => {
                    debug!(backend = %backend_id, error = %e, "ssh rebuild: status check failed, skipping");
                    continue;
                }
            };
            if locked {
                debug!(backend = %backend_id, "ssh rebuild: backend locked, skipping");
                continue;
            }

            // Discover keys.
            let metas = match backend.list_ssh_keys().await {
                Ok(m) => m,
                Err(e) => {
                    debug!(backend = %backend_id, error = %e, "ssh rebuild: list_ssh_keys failed");
                    continue;
                }
            };

            debug!(backend = %backend_id, count = metas.len(), "ssh rebuild: discovered keys");

            for meta in metas {
                // Fetch private key material.
                let material = match backend.get_ssh_private_key(&meta.item_id).await {
                    Ok(m) => m,
                    Err(e) => {
                        debug!(
                            backend = %backend_id,
                            item_id = %meta.item_id,
                            error = %e,
                            "ssh rebuild: get_ssh_private_key failed, skipping"
                        );
                        continue;
                    }
                };

                // Parse PEM.
                let private_key = match PrivateKey::from_openssh(material.pem.as_bytes()) {
                    Ok(k) => k,
                    Err(e) => {
                        debug!(
                            backend = %backend_id,
                            item = %meta.item_name,
                            error = %e,
                            "ssh rebuild: PEM parse failed, skipping"
                        );
                        continue;
                    }
                };

                // Convert revision_date to SystemTime for conflict resolution.
                let revision_date = meta.revision_date;

                // Build the key entry.
                match build_entry(
                    private_key,
                    meta.item_name.clone(),
                    backend_id.clone(),
                    meta.ssh_hosts.clone(),
                    meta.ssh_user.clone(),
                    meta.require_confirm,
                    revision_date,
                ) {
                    Some(entry) => {
                        debug!(
                            fingerprint = %entry.fingerprint,
                            item = %meta.item_name,
                            "ssh rebuild: loaded key"
                        );
                        new_entries.push(entry);
                    }
                    None => {
                        warn!(
                            backend = %backend_id,
                            item = %meta.item_name,
                            "ssh rebuild: failed to build key entry (serialisation error)"
                        );
                    }
                }
            }
        }

        // Atomically replace the store contents.
        match self.store.write() {
            Ok(mut guard) => {
                guard.clear();
                let count = new_entries.len();
                for entry in new_entries {
                    guard.insert(entry);
                }
                info!(count, "SSH key store rebuilt");
            }
            Err(e) => {
                warn!("SSH key store lock poisoned during rebuild: {e}");
                return;
            }
        }

        self.refresh_fuse();
    }

    /// Remove all keys belonging to `backend_id` from the store and refresh FUSE.
    ///
    /// Called when a backend is locked or hot-removed.
    pub fn remove_backend(&self, backend_id: &str) {
        match self.store.write() {
            Ok(mut guard) => guard.remove_backend(backend_id),
            Err(e) => {
                warn!("SSH key store lock poisoned in remove_backend: {e}");
                return;
            }
        }
        self.refresh_fuse();
    }

    /// Clear all keys from the store and refresh FUSE.
    ///
    /// Called on global auto-lock.
    pub fn clear(&self) {
        match self.store.write() {
            Ok(mut guard) => guard.clear(),
            Err(e) => {
                warn!("SSH key store lock poisoned in clear: {e}");
                return;
            }
        }
        info!("SSH key store cleared");
        self.refresh_fuse();
    }

    /// Return the agent socket path for display / env-var injection.
    pub fn agent_sock(&self) -> &std::path::Path {
        &self.agent_sock
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Rebuild the FUSE snapshot from the current store contents.
    fn refresh_fuse(&self) {
        let snap_entries: Vec<rosec_ssh_agent::KeyEntry> = match self.store.read() {
            Ok(guard) => guard.iter().cloned().collect(),
            Err(e) => {
                warn!("SSH key store lock poisoned in refresh_fuse: {e}");
                return;
            }
        };
        let refs: Vec<&rosec_ssh_agent::KeyEntry> = snap_entries.iter().collect();
        self.fuse_handle.fuse.update(&refs);

        // Compute a stable "last modified" time for logging.
        let newest = snap_entries
            .iter()
            .filter_map(|e| e.revision_date)
            .max()
            .unwrap_or(UNIX_EPOCH);
        let age_secs = SystemTime::now()
            .duration_since(newest)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        debug!(
            keys = snap_entries.len(),
            newest_age_secs = age_secs,
            "FUSE snapshot refreshed"
        );
    }
}

use std::time::SystemTime;
