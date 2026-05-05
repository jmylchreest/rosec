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

pub struct PromptManager {
    counter: AtomicU32,
    /// path → (provider_id, child_pid).  `child_pid` is `Some` while a
    /// subprocess is running.
    active: Mutex<HashMap<String, (String, Option<u32>)>>,
    /// Deferred operations queued by `allocate_with_operation`, consumed
    /// after the prompt completes.
    pending_ops: Mutex<HashMap<String, PendingOperation>>,
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
            pending_ops: Mutex::new(HashMap::new()),
            in_progress: Mutex::new(HashMap::new()),
            config: RwLock::new(config),
        }
    }

    /// Allocate a unique prompt D-Bus path for the given provider and
    /// register it with no child PID yet.
    pub fn allocate(&self, provider_id: &str) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let path = format!("/org/freedesktop/secrets/prompt/p{n}");
        if let Ok(mut map) = self.active.lock() {
            map.insert(path.clone(), (provider_id.to_string(), None));
        }
        path
    }

    /// Like [`allocate`](Self::allocate) but stashes a deferred operation
    /// to run after the prompt (unlock) succeeds.
    pub fn allocate_with_operation(&self, provider_id: &str, op: PendingOperation) -> String {
        let path = self.allocate(provider_id);
        if let Ok(mut map) = self.pending_ops.lock() {
            map.insert(path.clone(), op);
        }
        path
    }

    /// Retrieve and remove the pending operation for a completed prompt.
    pub fn take_pending_operation(&self, prompt_path: &str) -> Option<PendingOperation> {
        self.pending_ops
            .lock()
            .ok()
            .and_then(|mut map| map.remove(prompt_path))
    }

    pub fn set_pid(&self, prompt_path: &str, pid: u32) {
        if let Ok(mut map) = self.active.lock()
            && let Some(entry) = map.get_mut(prompt_path)
        {
            entry.1 = Some(pid);
        }
    }

    /// Remove the registry entry and return its child PID (for cancellation).
    pub fn remove_and_get_pid(&self, prompt_path: &str) -> Option<u32> {
        self.active
            .lock()
            .ok()
            .and_then(|mut map| map.remove(prompt_path))
            .and_then(|(_, pid)| pid)
    }

    /// Remove the registry entry without caring about the PID (for completion).
    pub fn remove(&self, prompt_path: &str) {
        if let Ok(mut map) = self.active.lock() {
            map.remove(prompt_path);
        }
    }

    /// Check whether a prompt is currently registered at this path.
    pub fn contains_path(&self, prompt_path: &str) -> bool {
        self.active
            .lock()
            .map(|g| g.contains_key(prompt_path))
            .unwrap_or(false)
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
