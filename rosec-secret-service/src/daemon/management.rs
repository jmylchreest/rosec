use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use tracing::debug;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::message::Header;
use zvariant::OwnedFd;

use crate::state::ServiceState;
use crate::unlock::{UnlockResult, auth_backend_with_tty, unlock_with_tty};

/// Log the D-Bus caller at debug level for a management method.
fn log_caller(method: &str, header: &Header<'_>) {
    let sender = header.sender().map(|s| s.as_str()).unwrap_or("<unknown>");
    debug!(method, sender, "D-Bus management call");
}

pub struct RosecManagement {
    pub(super) state: Arc<ServiceState>,
}

impl RosecManagement {
    pub fn new(state: Arc<ServiceState>) -> Self {
        Self { state }
    }
}

#[interface(name = "org.rosec.Daemon")]
impl RosecManagement {
    fn status(&self, #[zbus(header)] header: Header<'_>) -> Result<DaemonStatus, FdoError> {
        log_caller("Status", &header);
        let cache_size = self
            .state
            .items
            .lock()
            .map(|items| items.len())
            .unwrap_or(0);

        let last_sync = self
            .state
            .last_sync
            .lock()
            .ok()
            .and_then(|guard| *guard)
            .map(|time| {
                time.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            })
            .unwrap_or(0);

        let sessions_active = self.state.sessions.count().unwrap_or(0);

        // Primary backend is the first in configured order
        let (backend_id, backend_name) = self
            .state
            .backends_ordered()
            .into_iter()
            .next()
            .map(|b| (b.id().to_string(), b.name().to_string()))
            .unwrap_or_else(|| ("none".to_string(), "none".to_string()));

        Ok(DaemonStatus {
            backend_id,
            backend_name,
            backend_count: self.state.backend_count() as u32,
            cache_size: cache_size as u32,
            last_sync_epoch: last_sync,
            sessions_active: sessions_active as u32,
        })
    }

    /// Rebuild the item cache from whatever the backends currently hold in memory.
    ///
    /// Does NOT contact the remote server — use `SyncBackend` for that.
    async fn refresh(&self, #[zbus(header)] header: Header<'_>) -> Result<u32, FdoError> {
        log_caller("Refresh", &header);
        let entries = self.state.rebuild_cache().await?;
        Ok(entries.len() as u32)
    }

    /// Pull fresh data from the remote server for a specific backend, then
    /// rebuild the item cache.
    ///
    /// Returns the number of items visible after the sync.
    /// Returns a D-Bus error if the backend is not found, is locked, or the
    /// network request fails.
    async fn sync_backend(
        &self,
        backend_id: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<u32, FdoError> {
        log_caller("SyncBackend", &header);
        self.state.sync_backend(backend_id).await
    }

    fn backend_info(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<BackendInfo>, FdoError> {
        log_caller("BackendInfo", &header);
        let infos = self
            .state
            .backends_ordered()
            .into_iter()
            .map(|b| BackendInfo {
                id: b.id().to_string(),
                name: b.name().to_string(),
            })
            .collect();
        Ok(infos)
    }

    /// Return the full list of configured backends with kind and lock state.
    ///
    /// Lock state is derived from cached item metadata — an unlocked backend
    /// has at least one item without the locked flag set (or the cache is
    /// non-empty), while a locked backend has no accessible items.
    async fn backend_list(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<BackendListEntry>, FdoError> {
        log_caller("BackendList", &header);
        let backends = self.state.backends_ordered();
        let mut entries = Vec::with_capacity(backends.len());
        for b in backends {
            let id = b.id().to_string();
            let name = b.name().to_string();
            let kind = b.kind().to_string();
            let status = self
                .state
                .run_on_tokio(async move { b.status().await })
                .await?
                .map_err(|e| FdoError::Failed(format!("status error for {id}: {e}")))?;
            entries.push(BackendListEntry {
                id,
                name,
                kind,
                locked: status.locked,
            });
        }
        Ok(entries)
    }

    /// Return the credential fields required by a backend.
    ///
    /// The list always starts with the password field (`backend.password_field()`)
    /// followed by any additional fields declared by `backend.auth_fields()`.
    ///
    /// Each element is a tuple `(id, label, kind, placeholder, required)` where
    /// `kind` is one of `"text"`, `"password"`, or `"secret"`.
    /// Returns at least one element (the password field) if the backend is found.
    fn get_auth_fields(
        &self,
        backend_id: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<AuthFieldInfo>, FdoError> {
        log_caller("GetAuthFields", &header);
        use rosec_core::AuthFieldKind;

        let backend = match self.state.backend_by_id(backend_id) {
            Some(b) => b,
            None => {
                return Err(FdoError::Failed(format!(
                    "backend '{backend_id}' not found"
                )));
            }
        };

        let field_to_info = |f: &rosec_core::AuthField| AuthFieldInfo {
            id: f.id.to_string(),
            label: f.label.to_string(),
            kind: match f.kind {
                AuthFieldKind::Text => "text".to_string(),
                AuthFieldKind::Password => "password".to_string(),
                AuthFieldKind::Secret => "secret".to_string(),
            },
            placeholder: f.placeholder.to_string(),
            required: f.required,
        };

        // Always emit the password field first, then any additional auth fields.
        let pw = backend.password_field();
        let mut fields = vec![field_to_info(&pw)];
        fields.extend(backend.auth_fields().iter().map(field_to_info));

        Ok(fields)
    }

    /// Return registration info for a backend that requires device/API-key registration.
    ///
    /// Returns `(instructions, fields)` where `fields` has the same element layout
    /// as `GetAuthFields`.  Returns a D-Bus error with message `"no_registration_required"`
    /// if the backend does not support registration.
    fn get_registration_info(
        &self,
        backend_id: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(String, Vec<AuthFieldInfo>), FdoError> {
        log_caller("GetRegistrationInfo", &header);
        use rosec_core::AuthFieldKind;

        let backend = match self.state.backend_by_id(backend_id) {
            Some(b) => b,
            None => {
                return Err(FdoError::Failed(format!(
                    "backend '{backend_id}' not found"
                )));
            }
        };

        let info = backend
            .registration_info()
            .ok_or_else(|| FdoError::Failed("no_registration_required".to_string()))?;

        let fields = info
            .fields
            .iter()
            .map(|f| AuthFieldInfo {
                id: f.id.to_string(),
                label: f.label.to_string(),
                kind: match f.kind {
                    AuthFieldKind::Text => "text".to_string(),
                    AuthFieldKind::Password => "password".to_string(),
                    AuthFieldKind::Secret => "secret".to_string(),
                },
                placeholder: f.placeholder.to_string(),
                required: f.required,
            })
            .collect();

        Ok((info.instructions.to_string(), fields))
    }

    /// Authenticate/unlock a backend using a map of field values.
    ///
    /// The `fields` map must contain the keys returned by `GetAuthFields`.
    /// Returns `true` on success, or a D-Bus error on failure.
    async fn auth_backend(
        &self,
        backend_id: &str,
        fields: HashMap<String, String>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<bool, FdoError> {
        log_caller("AuthBackend", &header);
        self.state.auth_backend(backend_id, fields).await?;
        Ok(true)
    }

    /// Unlock all locked backends using credentials prompted on the caller's TTY.
    ///
    /// The caller opens `/dev/tty` and passes the file descriptor via D-Bus
    /// fd-passing (SCM_RIGHTS, type signature `h`).  `dbus-monitor` sees only
    /// the fd number — never any credential.  All prompting happens inside the
    /// daemon process via the received fd.
    ///
    /// Returns a list of `(backend_id, success, message)` tuples — one per
    /// backend that was locked at the time of the call.
    async fn unlock_with_tty(
        &self,
        tty_fd: OwnedFd,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<UnlockResultEntry>, FdoError> {
        log_caller("UnlockWithTty", &header);

        // Duplicate the fd so it survives the move into the Tokio task.
        // SAFETY: as_raw_fd() returns a valid fd owned by tty_fd (which is
        // kept alive until this function returns); dup() produces a new
        // independent fd that we own and close after the task completes.
        use std::os::unix::io::AsRawFd as _;
        let raw: libc::c_int = unsafe { libc::dup(tty_fd.as_raw_fd()) };
        if raw < 0 {
            return Err(FdoError::Failed(format!(
                "dup(tty_fd) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let state = Arc::clone(&self.state);
        let results: Vec<UnlockResult> = self
            .state
            .run_on_tokio(async move {
                let res = unlock_with_tty(state, raw).await;
                // Close our dup'd fd after the unlock completes.
                unsafe { libc::close(raw) };
                res
            })
            .await?
            .map_err(|e| FdoError::Failed(format!("unlock_with_tty error: {e}")))?;

        Ok(results
            .into_iter()
            .map(|r| UnlockResultEntry {
                backend_id: r.backend_id,
                success: r.success,
                message: r.message,
            })
            .collect())
    }

    /// Authenticate a specific backend using credentials prompted on the caller's TTY.
    ///
    /// Like `UnlockWithTty` but targets a single backend by ID.  Used by
    /// `rosec backend auth` and `rosec backend add`.
    ///
    /// Credentials are prompted in-process on the fd received via fd-passing;
    /// they never appear in any D-Bus message payload.
    async fn auth_backend_with_tty(
        &self,
        backend_id: String,
        tty_fd: OwnedFd,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FdoError> {
        log_caller("AuthBackendWithTty", &header);

        use std::os::unix::io::AsRawFd as _;
        let raw: libc::c_int = unsafe { libc::dup(tty_fd.as_raw_fd()) };
        if raw < 0 {
            return Err(FdoError::Failed(format!(
                "dup(tty_fd) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let state = Arc::clone(&self.state);
        self.state
            .run_on_tokio(async move {
                let res = auth_backend_with_tty(state, raw, &backend_id).await;
                unsafe { libc::close(raw) };
                res
            })
            .await?
            .map_err(|e| FdoError::Failed(format!("auth_backend_with_tty error: {e}")))
    }

    /// Cancel an active prompt subprocess by its D-Bus object path.
    ///
    /// Used by the `rosec` CLI (and other clients) to cleanly cancel a running
    /// `rosec-prompt` child when the user presses Ctrl+C.  After killing the
    /// child, the Prompt object is responsible for emitting `Completed(true, "")`.
    ///
    /// Returns `true` if a matching prompt was found and cancelled, `false` if
    /// the path was not in the active-prompt registry (already completed or invalid).
    fn cancel_prompt(
        &self,
        prompt_path: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<bool, FdoError> {
        log_caller("CancelPrompt", &header);
        // cancel_prompt() sends SIGTERM to the child and removes it from the registry.
        // We check whether the path existed before calling it.
        let existed = self
            .state
            .active_prompts
            .lock()
            .map(|g| g.contains_key(prompt_path))
            .unwrap_or(false);
        self.state.cancel_prompt(prompt_path);
        Ok(existed)
    }
}

// ---------------------------------------------------------------------------
// Return types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct DaemonStatus {
    pub backend_id: String,
    pub backend_name: String,
    pub backend_count: u32,
    pub cache_size: u32,
    pub last_sync_epoch: u64,
    pub sessions_active: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct BackendInfo {
    pub id: String,
    pub name: String,
}

/// A backend list entry returned by `BackendList`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct BackendListEntry {
    pub id: String,
    pub name: String,
    /// The backend type string (e.g. `"bitwarden"`, `"bitwarden-sm"`).
    pub kind: String,
    pub locked: bool,
}

/// A single auth-field descriptor returned by `GetAuthFields`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct AuthFieldInfo {
    pub id: String,
    pub label: String,
    /// One of "text", "password", or "secret".
    pub kind: String,
    pub placeholder: String,
    pub required: bool,
}

/// Result entry returned by `UnlockWithTty`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct UnlockResultEntry {
    pub backend_id: String,
    pub success: bool,
    /// Human-readable status message (e.g. "unlocked", "wrong password").
    pub message: String,
}
