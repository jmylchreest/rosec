//! In-memory state for in-flight prompts owned by `ServiceState`.
//!
//! Tracks the prompt path → (provider, child PID) registry, deferred
//! post-prompt operations, the per-provider serialization mutex (so only
//! one GUI dialog runs at a time per provider), and the live `PromptConfig`.
//!
//! Side-effects that need the D-Bus connection (deregistering a
//! `SecretPrompt` object) live on `ServiceState`; this struct only owns
//! the pure data manipulation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use rosec_core::config::PromptConfig;

use crate::prompt::PendingOperation;

/// Prefer a stable process handle so cancellation cannot signal a reused PID.
pub struct PromptChild {
    pub pid: u32,
    #[cfg(target_os = "linux")]
    process_fd: Option<std::os::fd::OwnedFd>,
}

impl PromptChild {
    fn new(pid: u32) -> Self {
        #[cfg(target_os = "linux")]
        let process_fd = {
            use std::os::fd::FromRawFd as _;
            // SAFETY: pidfd_open has no pointer arguments. A successful call
            // returns a new descriptor owned by this entry.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if fd >= 0 {
                Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) })
            } else {
                None
            }
        };
        Self {
            pid,
            #[cfg(target_os = "linux")]
            process_fd,
        }
    }

    pub fn terminate(&self) {
        #[cfg(target_os = "linux")]
        if let Some(fd) = &self.process_fd {
            use std::os::fd::AsRawFd as _;
            // SAFETY: fd is a live pidfd; a null siginfo requests normal SIGTERM.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGTERM,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
            return;
        }
        // Preserve the existing behavior on systems without pidfd support.
        unsafe {
            libc::kill(self.pid as libc::pid_t, libc::SIGTERM);
        }
    }
}

#[derive(Clone)]
pub struct PromptRoute {
    pub owner: crate::session::SessionOwner,
    pub conn: zbus::Connection,
}

struct PromptEntry {
    route: Option<PromptRoute>,
    pid: Option<PromptChild>,
    tty_cancel_writer: Option<std::os::unix::net::UnixStream>,
    pending: Option<PendingOperation>,
    started: bool,
    committing: bool,
    cancelled: Arc<tokio::sync::Notify>,
}

pub struct PromptManager {
    counter: AtomicU32,
    active: Mutex<HashMap<String, PromptEntry>>,
    /// Per-provider mutex to serialize prompt subprocesses.  Mirrors
    /// gnome-keyring's `unlock_prompt_queue` pattern.
    in_progress: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    config: RwLock<PromptConfig>,
}

impl PromptManager {
    pub fn new(config: PromptConfig) -> Self {
        Self {
            counter: AtomicU32::new(0),
            active: Mutex::new(HashMap::new()),
            in_progress: Mutex::new(HashMap::new()),
            config: RwLock::new(config),
        }
    }

    /// Allocate prompt state and its deferred data together so cancellation
    /// cannot leave an operation behind in a separate registry.
    pub fn allocate(&self, provider_id: &str) -> String {
        self.allocate_with_operation(provider_id, PendingOperation::Unlock)
    }

    pub fn allocate_with_operation(&self, _provider_id: &str, op: PendingOperation) -> String {
        self.allocate_inner(op, None)
    }

    pub fn allocate_owned(&self, op: PendingOperation, route: PromptRoute) -> String {
        self.allocate_inner(op, Some(route))
    }

    fn allocate_inner(&self, op: PendingOperation, route: Option<PromptRoute>) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let path = format!("/org/freedesktop/secrets/prompt/p{n}");
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                path.clone(),
                PromptEntry {
                    route,
                    pid: None,
                    tty_cancel_writer: None,
                    pending: Some(op),
                    started: false,
                    committing: false,
                    cancelled: Arc::new(tokio::sync::Notify::new()),
                },
            );
        path
    }

    pub fn route(&self, path: &str) -> Option<PromptRoute> {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(path)?
            .route
            .clone()
    }

    pub fn authorize(
        &self,
        path: &str,
        caller: &crate::session::SessionOwner,
    ) -> zbus::fdo::Result<PromptRoute> {
        self.route(path)
            .filter(|route| route.owner == *caller)
            .ok_or_else(|| {
                zbus::fdo::Error::AccessDenied(
                    "prompt belongs to another caller or has completed".into(),
                )
            })
    }

    pub fn owner_paths(&self, bus: &str, name: Option<&str>) -> Vec<String> {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, entry)| {
                entry.route.as_ref().is_some_and(|route| {
                    route.owner.bus == bus && name.is_none_or(|name| name == route.owner.name)
                })
            })
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// Claim the one permitted execution of this prompt.
    pub fn start(&self, path: &str) -> Option<Arc<tokio::sync::Notify>> {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let entry = active.get_mut(path)?;
        if entry.started {
            return None;
        }
        entry.started = true;
        Some(Arc::clone(&entry.cancelled))
    }

    /// Cancellation and commit contend for the same entry. Once commit wins,
    /// dismissal cannot truthfully promise that the provider mutation stopped.
    pub fn claim_commit(&self, path: &str) -> Option<PendingOperation> {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let entry = active.get_mut(path)?;
        if entry.committing {
            return None;
        }
        entry.committing = true;
        entry.pending.take()
    }

    pub fn take_pending_operation(&self, path: &str) -> Option<PendingOperation> {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(path)?
            .pending
            .take()
    }

    /// Closing the retained peer wakes read_hidden's cancellation poll.
    pub fn tty_cancel_reader(&self, path: &str) -> std::io::Result<std::os::unix::net::UnixStream> {
        let (reader, writer) = std::os::unix::net::UnixStream::pair()?;
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let entry = active.get_mut(path).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Interrupted, "prompt cancelled")
        })?;
        entry.tty_cancel_writer = Some(writer);
        Ok(reader)
    }

    /// Return false if cancellation won before the child could be registered.
    pub fn set_pid(&self, path: &str, pid: u32) -> bool {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = active.get_mut(path) else {
            return false;
        };
        entry.pid = Some(PromptChild::new(pid));
        true
    }

    pub fn clear_pid(&self, path: &str, pid: u32) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = active.get_mut(path)
            && entry.pid.as_ref().is_some_and(|child| child.pid == pid)
        {
            entry.pid = None;
        }
    }

    /// Outer None means completion/commit already won. Removing the entry
    /// drops deferred secrets immediately and wakes a queued worker.
    pub fn remove_and_get_pid(&self, path: &str) -> Option<Option<PromptChild>> {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if active.get(path)?.committing {
            return None;
        }
        let entry = active.remove(path)?;
        entry.cancelled.notify_one();
        Some(entry.pid)
    }

    /// Claim terminal completion once. The caller emits its signal afterwards.
    pub fn remove(&self, path: &str) -> bool {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(path)
            .is_some()
    }

    pub fn contains_path(&self, path: &str) -> bool {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(path)
    }

    /// Get or create the per-provider Tokio mutex for serializing prompt tasks.
    pub fn mutex_for(&self, provider_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.in_progress.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(provider_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Snapshot the current `PromptConfig`.
    pub fn config(&self) -> PromptConfig {
        self.config
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| PromptConfig::default())
    }

    /// Replace the live `PromptConfig` (called by the config hot-reload watcher).
    pub fn update_config(&self, new_config: PromptConfig) {
        if let Ok(mut guard) = self.config.write() {
            *guard = new_config;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_discards_pending_work_and_rejects_late_child() {
        let manager = PromptManager::new(PromptConfig::default());
        let path = manager.allocate_with_operation(
            "probe",
            PendingOperation::DeleteItem {
                provider_id: "probe".into(),
                item_id: "item".into(),
                item_path: "/item".into(),
            },
        );
        assert!(manager.start(&path).is_some());
        assert!(manager.start(&path).is_none());
        assert!(matches!(manager.remove_and_get_pid(&path), Some(None)));
        assert!(!manager.set_pid(&path, 123));
        assert!(manager.claim_commit(&path).is_none());
        assert!(manager.take_pending_operation(&path).is_none());
        assert!(!manager.remove(&path));
    }

    #[test]
    fn cancellation_terminates_registered_child() {
        let manager = PromptManager::new(PromptConfig::default());
        let path = manager.allocate("probe");
        let mut child = std::process::Command::new("sleep")
            .arg("10")
            .spawn()
            .unwrap();
        assert!(manager.set_pid(&path, child.id()));
        let tracked = manager.remove_and_get_pid(&path).unwrap().unwrap();
        tracked.terminate();
        assert!(!child.wait().unwrap().success());
    }

    #[test]
    fn cancelling_wakes_terminal_input() {
        use std::io::Read as _;
        let manager = PromptManager::new(PromptConfig::default());
        let path = manager.allocate("probe");
        let mut reader = manager.tty_cancel_reader(&path).unwrap();
        reader
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        manager.remove_and_get_pid(&path);
        assert_eq!(reader.read(&mut [0u8]).unwrap(), 0);
        assert!(manager.tty_cancel_reader(&path).is_err());
    }

    #[test]
    fn committing_operation_wins_over_late_dismissal() {
        let manager = PromptManager::new(PromptConfig::default());
        let path = manager.allocate("probe");
        assert!(manager.start(&path).is_some());
        assert!(manager.claim_commit(&path).is_some());
        assert!(manager.claim_commit(&path).is_none());
        assert!(manager.remove_and_get_pid(&path).is_none());
        assert!(manager.remove(&path));
        assert!(!manager.remove(&path));
    }
}
