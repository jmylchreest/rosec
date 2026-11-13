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
    gate: rosec_events::ConsumerGate,
    fuse: Mutex<MountState>,
    entries: Mutex<Vec<(String, TotpEntry)>>,
    totp_dir: PathBuf,
}

impl std::fmt::Debug for TotpManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpManager").finish_non_exhaustive()
    }
}

impl TotpManager {
    pub fn register_provider(&self, provider: &Arc<dyn Provider>) {
        self.gate.register(provider);
    }
    pub fn activate_provider(&self, provider: &Arc<dyn Provider>) {
        self.gate.activate(provider);
    }

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
            gate: Default::default(),
            entries: Default::default(),
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
    pub async fn rebuild(&self, providers: &[Arc<dyn Provider>]) -> bool {
        // Nothing consumes TOTP entries until the filesystem is mounted.
        if !self.ensure_mounted() {
            return false;
        }

        self.rebuild_entries(providers).await
    }

    async fn rebuild_entries(&self, providers: &[Arc<dyn Provider>]) -> bool {
        let (epoch, providers) = self.gate.begin(providers);
        let mut entries = Vec::new();
        let mut complete = true;

        for provider in &providers {
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
                    complete = false;
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
                    complete = false;
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
                    Err(_) => {
                        complete = false;
                        continue;
                    }
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

                entries.push((
                    provider.id().to_owned(),
                    TotpEntry {
                        item_id: item.id.clone(),
                        item_name: item.label.clone(),
                        params,
                    },
                ));
            }
        }

        let count = entries.len();
        let published = self.gate.publish(epoch, || {
            *self.entries.lock().unwrap_or_else(|e| e.into_inner()) = entries;
            self.refresh_snapshot();
        });
        debug!(items = count, "TOTP FUSE snapshot refreshed");
        published && complete
    }

    /// Remove all entries and refresh with an empty snapshot.
    pub fn remove_provider(&self, id: &str) {
        self.gate.revoke(Some(id), || self.evict_provider(id));
    }
    pub fn remove_provider_instance(&self, provider: &Arc<dyn Provider>) {
        self.gate
            .revoke_source(provider, || self.evict_provider(provider.id()));
    }
    fn evict_provider(&self, id: &str) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(provider, _)| provider != id);
        self.refresh_snapshot();
    }

    pub fn clear(&self) {
        self.gate.revoke(None, || {
            self.entries
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            self.refresh_snapshot();
        });
        info!("TOTP FUSE snapshot cleared");
    }

    /// Push a snapshot to the FUSE filesystem if it is currently mounted.
    fn refresh_snapshot(&self) {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entries: Vec<&TotpEntry> = entries.iter().map(|(_, entry)| entry).collect();
        match self.fuse.lock() {
            Ok(state) => {
                if let Some(handle) = state.handle.as_ref() {
                    handle.fuse.update_refs(&entries);
                }
            }
            Err(e) => warn!("TOTP FUSE mount lock poisoned in update: {e}"),
        }
    }
}

#[cfg(test)]
mod revocation_tests {
    use super::*;
    use crate::fido2::tests::DelayedProvider;
    #[tokio::test]
    async fn revoked_material_cannot_be_restored_by_pending_rebuild() {
        let manager = Arc::new(TotpManager {
            gate: Default::default(),
            entries: Default::default(),
            fuse: Mutex::new(MountState {
                handle: None,
                last_attempt: Some(Instant::now()),
            }),
            totp_dir: PathBuf::new(),
        });
        let provider = Arc::new(DelayedProvider {
            locked: false.into(),
            callbacks: Default::default(),
            entered: Default::default(),
            release: Default::default(),
        });
        let source: Arc<dyn Provider> = provider.clone();
        manager.register_provider(&source);
        let task = {
            let manager = manager.clone();
            let source = source.clone();
            tokio::spawn(async move {
                manager.rebuild_entries(&[source]).await;
            })
        };
        provider.entered.notified().await;
        manager.remove_provider("local");
        provider.release.notify_one();
        task.await.unwrap();
        assert!(manager.entries.lock().unwrap().is_empty());
        // Successful fresh unlock still loads the same data.
        manager.activate_provider(&source);
        provider.release.notify_one();
        manager.rebuild_entries(&[source]).await;
        assert!(!(manager.entries.lock().unwrap().is_empty()));
        manager.clear();
        assert!(manager.entries.lock().unwrap().is_empty());
    }
    /// Opt-in host test: creates and unmounts only its own temporary filesystem.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires host /dev/fuse and fusermount3"]
    async fn mounted_fuse_revocation_survives_pending_rebuild() {
        use std::io::{Read, Seek};
        let temp = tempfile::tempdir().unwrap();
        let mountpoint = temp.path().join("mount");
        let manager = Arc::new(TotpManager {
            gate: Default::default(),
            entries: Default::default(),
            fuse: Mutex::new(MountState {
                handle: Some(rosec_fuse::totp_mount(&mountpoint).unwrap()),
                last_attempt: None,
            }),
            totp_dir: mountpoint.clone(),
        });
        let provider = Arc::new(DelayedProvider {
            locked: false.into(),
            callbacks: Default::default(),
            entered: Default::default(),
            release: Default::default(),
        });
        let source: Arc<dyn Provider> = provider.clone();
        manager.register_provider(&source);
        provider.release.notify_one();
        assert!(manager.rebuild(std::slice::from_ref(&source)).await);
        let file = std::fs::read_dir(mountpoint.join("by-name"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let data = std::fs::read(&file).unwrap();
        assert_eq!(data.len(), 7);
        assert!(data[..6].iter().all(u8::is_ascii_digit));
        assert!(std::fs::write(&file, b"forbidden").is_err());
        let mut held = std::fs::File::open(&file).unwrap();
        provider.entered.notified().await; // consume the initial rebuild notification
        let task = {
            let manager = manager.clone();
            let source = source.clone();
            tokio::spawn(async move { manager.rebuild(&[source]).await })
        };
        tokio::time::timeout(Duration::from_secs(2), provider.entered.notified())
            .await
            .unwrap();
        manager.remove_provider_instance(&source);
        assert!(std::fs::read(&file).is_err());
        held.rewind().unwrap();
        assert!(held.read_to_end(&mut Vec::new()).is_err());
        provider.release.notify_one();
        assert!(!task.await.unwrap());
        assert!(std::fs::read(&file).is_err());
        manager.activate_provider(&source);
        provider.release.notify_one();
        assert!(manager.rebuild(&[source]).await);
        assert!(std::fs::read(&file).is_ok());
        manager.clear();
        assert!(std::fs::read(&file).is_err());
        drop(held);
        drop(manager); // unmount before deleting the temporary directory
    }
}
