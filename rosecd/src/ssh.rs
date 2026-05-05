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
//!    all SSH keys from all provided providers, repopulates the key store, and
//!    refreshes the FUSE snapshot.
//! 3. [`SshManager::remove_provider`] — called when a provider is locked or
//!    removed; evicts that provider's keys from the store and refreshes FUSE.
//! 4. [`SshManager::clear`] — evicts all keys (called on global lock / shutdown).
//! 5. Drop of [`SshManager`] unmounts the FUSE filesystem and closes the agent
//!    socket (both handled by their respective RAII wrappers).

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, UNIX_EPOCH};

use rosec_core::Provider;
use rosec_core::config::PromptConfig;
use rosec_fuse::MountHandle;
use rosec_ssh_agent::ConfirmCallback;
use rosec_ssh_agent::keystore::{KeyStore, build_entry};
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
    /// `confirm_cb` is called before signing with keys that have
    /// `require_confirm = true` (from `custom.ssh_confirm` / `custom.ssh-confirm`).
    ///
    /// Returns `None` and logs a warning if `XDG_RUNTIME_DIR` is unset or the
    /// FUSE mount / socket creation fails — the daemon continues without SSH
    /// agent support rather than aborting.
    pub async fn start(confirm_cb: ConfirmCallback) -> Option<Self> {
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
                // FUSE mount fails under NoNewPrivileges=yes (systemd hardened unit)
                // because fusermount3's setuid bit is suppressed.  This is expected
                // when running as a systemd user service.  The SSH agent is disabled
                // but the daemon continues normally.
                warn!("SSH FUSE mount failed (SSH agent disabled): {e:#}");
                return None;
            }
        };

        let store = KeyStore::new();

        {
            let agent =
                SshAgent::new(Arc::clone(&store), agent_sock.clone()).with_confirm(confirm_cb);
            tokio::spawn(async move {
                if let Err(e) = agent.listen().await {
                    warn!("SSH agent listener exited: {e}");
                }
            });
        }

        info!(mount = %ssh_dir.display(), "SSH FUSE ready");
        info!(sock = %agent_sock.display(), "SSH agent ready");

        Some(Self {
            store,
            fuse_handle,
            agent_sock,
        })
    }

    /// Rebuild the key store from the given set of providers.
    ///
    /// For each provider that is unlocked:
    /// 1. Call `list_ssh_keys()` to discover available keys.
    /// 2. Call `get_ssh_private_key(item_id)` for each key.
    /// 3. Parse the PEM and build a [`KeyEntry`].
    ///
    /// Keys from providers that are locked or that return errors are skipped
    /// with a debug log.  After all providers are processed the FUSE snapshot
    /// is refreshed atomically.
    pub async fn rebuild(&self, providers: &[Arc<dyn Provider>]) {
        let mut new_entries = Vec::new();

        for provider in providers {
            let provider_id = provider.id().to_string();

            // Skip locked providers — no keys are available while locked.
            let locked = match provider.status().await {
                Ok(s) => s.locked,
                Err(e) => {
                    debug!(provider = %provider_id, error = %e, "ssh rebuild: status check failed, skipping");
                    continue;
                }
            };
            if locked {
                debug!(provider = %provider_id, "ssh rebuild: provider locked, skipping");
                continue;
            }

            let metas = match provider.list_ssh_keys().await {
                Ok(m) => m,
                Err(e) => {
                    debug!(provider = %provider_id, error = %e, "ssh rebuild: list_ssh_keys failed");
                    continue;
                }
            };

            debug!(provider = %provider_id, count = metas.len(), "ssh rebuild: discovered keys");

            for meta in metas {
                let material = match provider.get_ssh_private_key(&meta.item_id).await {
                    Ok(m) => m,
                    Err(e) => {
                        debug!(
                            provider = %provider_id,
                            item_id = %meta.item_id,
                            error = %e,
                            "ssh rebuild: get_ssh_private_key failed, skipping"
                        );
                        continue;
                    }
                };

                let private_key = match PrivateKey::from_openssh(material.pem.as_bytes()) {
                    Ok(k) => k,
                    Err(e) => {
                        debug!(
                            provider = %provider_id,
                            item = %meta.item_name,
                            error = %e,
                            "ssh rebuild: PEM parse failed, skipping"
                        );
                        continue;
                    }
                };

                let revision_date = meta.revision_date;

                match build_entry(
                    private_key,
                    meta.item_id.clone(),
                    meta.item_name.clone(),
                    provider_id.clone(),
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
                            provider = %provider_id,
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
                for entry in new_entries {
                    guard.insert(entry);
                }
                debug!(
                    entries = guard.len(),
                    unique_keys = guard.unique_count(),
                    "SSH key store rebuilt"
                );
            }
            Err(e) => {
                warn!("SSH key store lock poisoned during rebuild: {e}");
                return;
            }
        }

        self.refresh_fuse();
    }

    /// Remove all keys belonging to `provider_id` from the store and refresh FUSE.
    ///
    /// Called when a provider is locked or hot-removed.
    pub fn remove_provider(&self, provider_id: &str) {
        match self.store.write() {
            Ok(mut guard) => guard.remove_provider(provider_id),
            Err(e) => {
                warn!("SSH key store lock poisoned in remove_provider: {e}");
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

/// Find the `rosec-prompt` binary next to the current executable.
///
/// Returns `None` if no sibling exists. The daemon must not fall back to
/// a `$PATH` lookup — `$PATH` is attacker-influenceable in some launch
/// contexts (sysadmin-set environment, broken systemd unit, etc.) and a
/// silent fallback would let an attacker substitute their own `rosec-prompt`.
fn resolve_prompt_binary() -> Option<String> {
    rosec_core::prompt::resolve_sibling_binary("rosec-prompt")
        .map(|p| p.to_string_lossy().into_owned())
}

/// Build a [`ConfirmCallback`] that spawns `rosec-prompt` in confirmation mode.
///
/// `get_config` is called at prompt time (not at construction) so it picks up
/// hot-reloaded prompt config changes.
///
/// Fails closed when ssh_confirm=true but no GUI/TTY is available to ask
/// for confirmation — the whole point of ssh_confirm is to defeat silent
/// abuse, so a headless fallback that signs anyway makes the option a no-op.
pub fn build_confirm_callback(
    get_config: impl Fn() -> PromptConfig + Send + Sync + 'static,
) -> ConfirmCallback {
    Arc::new(move |fingerprint: String, item_name: String| {
        let cfg = get_config();
        Box::pin(async move {
            // Resolve prompt binary and theme from the live config.
            let program = match cfg.backend.as_str() {
                "builtin" | "" => match resolve_prompt_binary() {
                    Some(p) => p,
                    None => {
                        warn!(
                            fingerprint = %fingerprint,
                            item = %item_name,
                            "rosec-prompt not found alongside daemon binary; \
                             denying sign request — refusing PATH fallback as \
                             a defence against $PATH-controlled substitution"
                        );
                        return false;
                    }
                },
                custom => custom.to_string(),
            };
            let theme_json = serde_json::to_value(&cfg.theme).unwrap_or_default();

            let has_display = std::env::var_os("WAYLAND_DISPLAY").is_some()
                || std::env::var_os("DISPLAY").is_some();
            let has_tty = std::path::Path::new("/dev/tty").exists();

            if !has_display && !has_tty {
                warn!(
                    fingerprint = %fingerprint,
                    item = %item_name,
                    "no display or TTY available for sign confirmation, denying"
                );
                return false;
            }

            let request_json = serde_json::json!({
                "title": format!("SSH sign request"),
                "message": format!("Allow key \u{201c}{item_name}\u{201d} ({fingerprint}) to sign?"),
                "hint": "",
                "provider": "",
                "confirm_label": "Allow",
                "cancel_label": "Deny",
                "fields": [],
                "confirm_mode": true,
                "theme": theme_json,
            });

            let mut cmd = tokio::process::Command::new(&program);
            // SAFETY: pre_exec runs after fork() in the child process.
            // setsid() is async-signal-safe and has no preconditions.
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

            if !has_display {
                cmd.arg("--tty");
            }

            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        program = %program,
                        error = %e,
                        "failed to spawn rosec-prompt for sign confirmation, denying"
                    );
                    return false;
                }
            };

            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt as _;
                if let Err(e) = stdin.write_all(request_json.to_string().as_bytes()).await {
                    warn!("rosec-prompt stdin write error: {e}, denying sign");
                    let _ = child.kill().await;
                    return false;
                }
                // stdin dropped here → EOF sent to child
            }

            // Bound the wait so a hung prompt cannot pin the SSH agent
            // forever. 120 s is well past any human interaction window.
            const CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
            match tokio::time::timeout(CONFIRM_TIMEOUT, child.wait()).await {
                Ok(Ok(status)) => {
                    if status.success() {
                        true
                    } else {
                        info!(
                            fingerprint = %fingerprint,
                            item = %item_name,
                            "sign confirmation denied (prompt cancelled)"
                        );
                        false
                    }
                }
                Ok(Err(e)) => {
                    warn!("rosec-prompt wait error: {e}, denying sign");
                    false
                }
                Err(_) => {
                    warn!(
                        fingerprint = %fingerprint,
                        item = %item_name,
                        "rosec-prompt did not exit within {CONFIRM_TIMEOUT:?}, denying sign"
                    );
                    let _ = child.kill().await;
                    false
                }
            }
        })
    })
}
