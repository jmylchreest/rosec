//! TOTP FUSE manager — mounts and refreshes the TOTP virtual filesystem.

use std::path::PathBuf;
use std::sync::Arc;

use rosec_core::{Capability, Provider};
use rosec_fuse::{TotpEntry, TotpMountHandle};
use tracing::{debug, info, warn};

pub struct TotpManager {
    fuse_handle: TotpMountHandle,
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

        let fuse_handle = match rosec_fuse::totp_mount(&totp_dir) {
            Ok(h) => h,
            Err(e) => {
                warn!("TOTP FUSE mount failed: {e:#}");
                return None;
            }
        };

        info!(mount = %totp_dir.display(), "TOTP FUSE ready");

        Some(Self { fuse_handle })
    }

    /// Rebuild the TOTP snapshot from the given providers.
    ///
    /// Iterates all unlocked providers that declare `TotpGenerate`, fetches
    /// TOTP seeds, parses them, and updates the FUSE snapshot.
    pub async fn rebuild(&self, providers: &[Arc<dyn Provider>]) {
        let mut entries = Vec::new();

        for provider in providers {
            if !provider.capabilities().contains(&Capability::TotpGenerate) {
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
                // Fast path: skip items explicitly marked as not having TOTP.
                // If the attribute is absent (e.g. older WASM plugin that hasn't
                // been rebuilt), we still attempt to fetch the seed and silently
                // skip on NotFound.
                if item
                    .attributes
                    .get(rosec_core::ATTR_TOTP)
                    .map(|v| v.as_str())
                    == Some("false")
                {
                    continue;
                }

                let seed = match provider.get_secret_attr(&item.id, "totp").await {
                    Ok(s) => s,
                    Err(_) => continue, // no TOTP seed on this item
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
        self.fuse_handle.fuse.update(&entries);
        debug!(items = count, "TOTP FUSE snapshot refreshed");
    }

    /// Remove all entries and refresh with an empty snapshot.
    pub fn clear(&self) {
        self.fuse_handle.fuse.update(&[]);
        info!("TOTP FUSE snapshot cleared");
    }
}
