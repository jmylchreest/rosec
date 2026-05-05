//! Idle/max-unlocked tracking and per-provider sync-coalescing for
//! `ServiceState`.
//!
//! Tracks last client activity, per-provider unlock timestamps, and the
//! mutexes used to serialize unlock and sync work.  Pure state — the
//! callers that decide what to do based on these signals (autolock loop,
//! sync timer, unlock orchestration) live on `ServiceState`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

pub struct LockPolicy {
    /// Timestamp of the last client activity (D-Bus method call).
    last_activity: Mutex<Option<SystemTime>>,
    /// Timestamp when any provider was first unlocked.  Used by the
    /// global `auto_lock` (lock-all) max-unlocked path.
    unlocked_since: Mutex<Option<SystemTime>>,
    /// Per-provider unlock timestamps for per-provider max-unlocked
    /// checking.
    unlocked_since_map: Mutex<HashMap<String, SystemTime>>,
    /// Held during interactive unlock to prevent concurrent prompts
    /// from racing.
    unlock_in_progress: tokio::sync::Mutex<()>,
    /// Per-provider mutex coalescing concurrent `sync_provider` callers.
    sync_in_progress: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl Default for LockPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl LockPolicy {
    pub fn new() -> Self {
        Self {
            last_activity: Mutex::new(None),
            unlocked_since: Mutex::new(None),
            unlocked_since_map: Mutex::new(HashMap::new()),
            unlock_in_progress: tokio::sync::Mutex::new(()),
            sync_in_progress: Mutex::new(HashMap::new()),
        }
    }

    /// Record that client activity has occurred (resets idle timer).
    pub fn touch_activity(&self) {
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Some(SystemTime::now());
        }
    }

    /// Clear the last-activity timestamp so the idle check stops firing
    /// (used after auto-lock to avoid re-firing on every poll).
    pub fn clear_activity(&self) {
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = None;
        }
    }

    /// Record that a provider has been unlocked (starts max-unlocked timer).
    pub fn mark_unlocked(&self) {
        if let Ok(mut guard) = self.unlocked_since.lock() {
            *guard = Some(SystemTime::now());
        }
    }

    /// Record that a specific provider has been unlocked.  Also bumps the
    /// global `unlocked_since` timestamp.
    pub fn mark_provider_unlocked(&self, provider_id: &str) {
        let now = SystemTime::now();
        if let Ok(mut guard) = self.unlocked_since.lock() {
            *guard = Some(now);
        }
        if let Ok(mut guard) = self.unlocked_since_map.lock() {
            guard.insert(provider_id.to_string(), now);
        }
    }

    /// Clear the unlock timestamp for all providers (all locked).
    pub fn mark_all_locked(&self) {
        if let Ok(mut guard) = self.unlocked_since.lock() {
            *guard = None;
        }
        if let Ok(mut guard) = self.unlocked_since_map.lock() {
            guard.clear();
        }
    }

    pub fn clear_provider_unlocked(&self, provider_id: &str) {
        if let Ok(mut guard) = self.unlocked_since_map.lock() {
            guard.remove(provider_id);
        }
    }

    /// Returns `true` if no providers are currently tracked as unlocked.
    pub fn all_providers_locked(&self) -> bool {
        match self.unlocked_since_map.lock() {
            Ok(guard) => guard.is_empty(),
            Err(_) => true,
        }
    }

    /// Returns `true` if the last activity was longer than `idle_minutes` ago.
    pub fn is_idle_expired(&self, idle_minutes: u64) -> bool {
        let guard = match self.last_activity.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        match *guard {
            Some(last) => {
                let elapsed = SystemTime::now().duration_since(last).unwrap_or_default();
                elapsed.as_secs() >= idle_minutes * 60
            }
            None => false,
        }
    }

    /// Returns `true` if any provider has been unlocked longer than
    /// `max_minutes` (global path used by `auto_lock`).
    pub fn is_max_unlocked_expired(&self, max_minutes: u64) -> bool {
        let guard = match self.unlocked_since.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        match *guard {
            Some(since) => {
                let elapsed = SystemTime::now().duration_since(since).unwrap_or_default();
                elapsed.as_secs() >= max_minutes * 60
            }
            None => false,
        }
    }

    /// Returns `true` if a specific provider has been unlocked longer than
    /// `max_minutes`.
    pub fn is_provider_max_unlocked_expired(&self, provider_id: &str, max_minutes: u64) -> bool {
        let guard = match self.unlocked_since_map.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        match guard.get(provider_id) {
            Some(since) => {
                let elapsed = SystemTime::now().duration_since(*since).unwrap_or_default();
                elapsed.as_secs() >= max_minutes * 60
            }
            None => false,
        }
    }

    /// Acquire the global unlock-in-progress mutex (held during interactive
    /// unlock to serialize prompt orchestration).
    pub async fn unlock_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.unlock_in_progress.lock().await
    }

    /// Get or create a per-provider Tokio mutex for serialising sync calls.
    pub fn sync_mutex_for(&self, provider_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self
            .sync_in_progress
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.entry(provider_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}
