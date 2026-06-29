//! TOTP FUSE manager — mounts and refreshes the TOTP virtual filesystem.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rosec_core::{Capability, Provider};
use rosec_fuse::{TotpEntry, TotpMountHandle};
use tracing::{debug, info, warn};

/// Throttle for FUSE re-mount retries, so a permanently-unmountable
/// environment (e.g. forced `NoNewPrivileges`) isn't hammered on every event.
const MOUNT_RETRY_COOLDOWN: Duration = Duration::from_secs(10);

struct MountState {
    handle: Option<TotpMountHandle>,
    last_attempt: Option<Instant>,
}

pub struct TotpManager {
    fuse: Mutex<MountState>,
    totp_dir: PathBuf,
}

impl std::fmt::Debug for TotpManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpManager").finish_non_exhaustive()
    }
}

impl TotpManager {
    /// Start the TOTP FUSE filesystem.
    ///
    /// Mounts at `$XDG_RUNTIME_DIR/rosec/totp/`.
    /// Returns `None` if `XDG_RUNTIME_DIR` is unset or the mount fails.
    pub fn start() -> Option<Self> {
        let runtime_dir = match std::env::var("XDG_RUNTIME_DIR") {
            Ok(d) => PathBuf::from(d),
            Err(_) => {
                warn!("XDG_RUNTIME_DIR not set — TOTP FUSE filesystem disabled");
                return None;
            }
        };

        let totp_dir = runtime_dir.join("rosec").join("totp");

        Some(Self {
            fuse: Mutex::new(MountState {
                handle: None,
                last_attempt: None,
            }),
            totp_dir,
        })
    }

    /// Mount the FUSE filesystem if not already mounted, retrying a failed
    /// boot-time mount (throttled by [`MOUNT_RETRY_COOLDOWN`]).  Returns
    /// `true` if mounted.
    fn ensure_mounted(&self) -> bool {
        let mut state = match self.fuse.lock() {
            Ok(g) => g,
            Err(e) => {
                warn!("TOTP FUSE mount lock poisoned: {e}");
                return false;
            }
        };
        if state.handle.is_some() {
            return true;
        }
        if let Some(last) = state.last_attempt
            && last.elapsed() < MOUNT_RETRY_COOLDOWN
        {
            return false;
        }
        state.last_attempt = Some(Instant::now());
        match rosec_fuse::totp_mount(&self.totp_dir) {
            Ok(h) => {
                info!(mount = %self.totp_dir.display(), "TOTP FUSE ready");
                state.handle = Some(h);
                true
            }
            Err(e) => {
                warn!("TOTP FUSE mount failed (will retry on next unlock): {e:#}");
                false
            }
        }
    }

    /// Rebuild the TOTP snapshot from the given providers.
    ///
    /// Iterates all unlocked providers that declare `Totp`, fetches
    /// TOTP seeds, parses them, and updates the FUSE snapshot.
    pub async fn rebuild(&self, providers: &[Arc<dyn Provider>]) {
        // Nothing consumes TOTP entries until the filesystem is mounted.
        if !self.ensure_mounted() {
            return;
        }

        let mut entries = Vec::new();

        for provider in providers {
            if !provider.capabilities().contains(&Capability::Totp) {
                continue;
            }

            let status = match provider.status().await {
                Ok(s) => s,
                Err(e) => {
                    debug!(
                        provider = %provider.id(),
                        error = %e,
                        "TOTP rebuild: status check failed, skipping"
                    );
                    continue;
                }
            };
            if status.locked {
                debug!(provider = %provider.id(), "TOTP rebuild: provider locked, skipping");
                continue;
            }

            let items = match provider.list_items().await {
                Ok(items) => items,
                Err(e) => {
                    debug!(
                        provider = %provider.id(),
                        error = %e,
                        "TOTP rebuild: list_items failed, skipping"
                    );
                    continue;
                }
            };

            for item in &items {
                if item
                    .attributes
                    .get(rosec_core::ATTR_TOTP)
                    .map(|v| v.as_str())
                    != Some("true")
                {
                    continue;
                }

                let seed = match provider.get_secret_attr(&item.id, "totp").await {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                let params = match rosec_core::totp::parse_totp_input(seed.as_slice()) {
                    Ok(p) => p,
                    Err(e) => {
                        debug!(
                            item_id = %item.id,
                            error = %e,
                            "TOTP rebuild: failed to parse seed, skipping"
                        );
                        continue;
                    }
                };

                entries.push(TotpEntry {
                    item_id: item.id.clone(),
                    item_name: item.label.clone(),
                    params,
                });
            }
        }

        let count = entries.len();
        self.update_snapshot(&entries);
        debug!(items = count, "TOTP FUSE snapshot refreshed");
    }

    /// Remove all entries and refresh with an empty snapshot.
    pub fn clear(&self) {
        self.update_snapshot(&[]);
        info!("TOTP FUSE snapshot cleared");
    }

    /// Push a snapshot to the FUSE filesystem if it is currently mounted.
    fn update_snapshot(&self, entries: &[TotpEntry]) {
        match self.fuse.lock() {
            Ok(state) => {
                if let Some(handle) = state.handle.as_ref() {
                    handle.fuse.update(entries);
                }
            }
            Err(e) => warn!("TOTP FUSE mount lock poisoned in update: {e}"),
        }
    }
}
