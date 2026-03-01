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
    /// Triggers a background sync for every unlocked backend so that
    /// `on_sync_succeeded` callbacks (e.g. SSH key rebuild) fire even when the
    /// caller only asks for a cache refresh.  Uses `try_sync_backend` so
    /// concurrent in-flight syncs are skipped rather than serialised.
    async fn refresh(&self, #[zbus(header)] header: Header<'_>) -> Result<u32, FdoError> {
        log_caller("Refresh", &header);

        // Kick off a sync for every unlocked backend so that lifecycle callbacks
        // (SSH key rebuild, etc.) are triggered.  Errors are logged but do not
        // fail the Refresh call — the cache is still rebuilt from in-memory state.
        for backend in self.state.backends_ordered() {
            let is_locked = backend.status().await.map(|s| s.locked).unwrap_or(true);
            if !is_locked {
                let id = backend.id().to_string();
                if let Err(e) = self.state.try_sync_backend(&id).await {
                    tracing::warn!(backend = %id, "Refresh: background sync failed: {e}");
                }
            }
        }

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
    ///
    /// # Security
    ///
    /// The incoming `HashMap<String, String>` arrives as plain D-Bus `a{ss}` —
    /// passwords are visible to `dbus-monitor`.  Prefer `AuthBackendWithTty`
    /// (fd-passing) for interactive clients.  This method converts values into
    /// `Zeroizing<String>` at the D-Bus boundary and explicitly zeroizes the
    /// original map so plain-text copies are scrubbed as soon as possible.
    async fn auth_backend(
        &self,
        backend_id: &str,
        mut fields: HashMap<String, String>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<bool, FdoError> {
        log_caller("AuthBackend", &header);

        // Convert to Zeroizing at the D-Bus boundary, then zeroize originals.
        let secure_fields: HashMap<String, zeroize::Zeroizing<String>> = fields
            .drain()
            .map(|(k, v)| (k, zeroize::Zeroizing::new(v)))
            .collect();

        self.state.auth_backend(backend_id, secure_fields).await?;
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

    /// Authenticate a backend by reading a password from a pipe fd.
    ///
    /// The caller creates a pipe, writes the password to the write end (then
    /// closes it), and passes the read end via D-Bus fd-passing (SCM_RIGHTS).
    /// The daemon reads the password from the pipe, wraps it in `Zeroizing`,
    /// and calls `auth_backend`.
    ///
    /// This is the preferred method for PAM modules and other non-interactive
    /// callers that already have the password but want to avoid sending it as
    /// a plain D-Bus message payload (visible to `dbus-monitor`).
    ///
    /// **Access restricted**: The daemon resolves the caller's PID via
    /// `GetConnectionCredentials` and verifies that `/proc/<pid>/exe` matches
    /// one of the paths in `[service] pam_helper_paths`.  If the caller is
    /// not the PAM helper binary, the request is rejected.
    ///
    /// Returns `true` on success.  Returns a D-Bus error if the backend is not
    /// found, the password is wrong, or reading from the pipe fails.
    async fn auth_backend_from_pipe(
        &self,
        backend_id: String,
        pipe_fd: OwnedFd,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<bool, FdoError> {
        log_caller("AuthBackendFromPipe", &header);

        // --- Caller verification ---
        let allowed_paths = self.state.live_config().service.pam_helper_paths;
        if !allowed_paths.is_empty() {
            let sender = header.sender().ok_or_else(|| {
                FdoError::AccessDenied("AuthBackendFromPipe: missing D-Bus sender".into())
            })?;
            let dbus_proxy = zbus::fdo::DBusProxy::new(&self.state.conn)
                .await
                .map_err(|e| FdoError::Failed(format!("DBusProxy: {e}")))?;
            let pid = dbus_proxy
                .get_connection_unix_process_id(zbus::names::BusName::from(sender.clone()))
                .await
                .map_err(|e| {
                    FdoError::AccessDenied(format!(
                        "AuthBackendFromPipe: cannot resolve caller PID: {e}"
                    ))
                })?;
            let exe = std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|e| {
                FdoError::AccessDenied(format!(
                    "AuthBackendFromPipe: cannot read /proc/{pid}/exe: {e}"
                ))
            })?;
            if !allowed_paths.iter().any(|p| exe == std::path::Path::new(p)) {
                return Err(FdoError::AccessDenied(format!(
                    "AuthBackendFromPipe: caller exe '{}' not in pam_helper_paths",
                    exe.display(),
                )));
            }
            debug!(
                pid,
                exe = %exe.display(),
                "AuthBackendFromPipe: caller verified"
            );
        }
        // --- End caller verification ---

        use std::os::unix::io::AsRawFd as _;
        let raw: libc::c_int = unsafe { libc::dup(pipe_fd.as_raw_fd()) };
        if raw < 0 {
            return Err(FdoError::Failed(format!(
                "dup(pipe_fd) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let state = Arc::clone(&self.state);
        self.state
            .run_on_tokio(async move {
                // Read password from the pipe into a zeroizing buffer.
                let password = {
                    use std::io::Read as _;
                    // SAFETY: raw is a valid fd from dup() above.
                    let file = unsafe { std::os::unix::io::FromRawFd::from_raw_fd(raw) };
                    let mut file: std::fs::File = file;
                    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(256));
                    file.read_to_end(&mut buf)
                        .map_err(|e| FdoError::Failed(format!("read from pipe failed: {e}")))?;
                    // file is dropped here → fd closed

                    // Strip trailing null byte (pam_exec null-terminates).
                    if buf.last() == Some(&0) {
                        buf.pop();
                    }
                    // Strip trailing newline.
                    if buf.last() == Some(&b'\n') {
                        buf.pop();
                    }

                    if buf.is_empty() {
                        return Err(FdoError::Failed("pipe password is empty".to_string()));
                    }

                    // Convert to Zeroizing<String> for auth_backend.
                    let s = String::from_utf8(std::mem::take(&mut *buf)).map_err(|_| {
                        FdoError::Failed("pipe password is not valid UTF-8".to_string())
                    })?;
                    zeroize::Zeroizing::new(s)
                };

                // Look up the password field ID for this backend.
                let backend = state
                    .backend_by_id(&backend_id)
                    .ok_or_else(|| FdoError::Failed(format!("backend '{backend_id}' not found")))?;
                let pw_field_id = backend.password_field().id.to_string();

                let mut fields = std::collections::HashMap::new();
                fields.insert(pw_field_id, password);

                state.auth_backend(&backend_id, fields).await?;
                Ok(true)
            })
            .await?
    }

    // -----------------------------------------------------------------------
    // Vault password (wrapping entry) management
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Vault password (wrapping entry) management
    // -----------------------------------------------------------------------

    /// Add a password (wrapping entry) to a local vault.
    ///
    /// The vault must be unlocked.  The new password wraps the same vault key
    /// that existing entries protect, enabling multi-password unlock.
    ///
    /// `password` is the raw password bytes (caller collects from the user).
    /// `label` is an optional human-readable name for the entry (e.g. "login",
    /// "pam", "backup").
    ///
    /// Returns the wrapping entry ID on success.
    ///
    /// # Security
    ///
    /// The incoming `Vec<u8>` is wrapped in `Zeroizing` at the D-Bus boundary
    /// so the password bytes are scrubbed on drop.
    async fn vault_add_password(
        &self,
        vault_id: String,
        password: Vec<u8>,
        label: String,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<String, FdoError> {
        log_caller("VaultAddPassword", &header);

        // Wrap in Zeroizing at the D-Bus boundary so the password is scrubbed on drop.
        let password = zeroize::Zeroizing::new(password);

        let backend = self
            .state
            .backend_by_id(&vault_id)
            .ok_or_else(|| FdoError::Failed(format!("vault '{vault_id}' not found")))?;

        // Verify this is a local vault before spawning the tokio task.
        if !backend.as_any().is::<rosec_vault::LocalVault>() {
            return Err(FdoError::Failed(format!(
                "'{vault_id}' is not a local vault"
            )));
        }

        let label = if label.is_empty() {
            return Err(FdoError::Failed("password label cannot be empty".into()));
        } else {
            label
        };

        self.state
            .run_on_tokio(async move {
                let local_vault = backend
                    .as_any()
                    .downcast_ref::<rosec_vault::LocalVault>()
                    .expect("type check passed above");
                local_vault
                    .add_password(&password, label)
                    .await
                    .map_err(|e| FdoError::Failed(format!("add_password failed: {e}")))
            })
            .await?
    }

    /// Remove a password (wrapping entry) from a local vault by entry ID.
    ///
    /// The vault must be unlocked and must have at least 2 wrapping entries
    /// (the last entry cannot be removed).
    async fn vault_remove_password(
        &self,
        vault_id: String,
        entry_id: String,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FdoError> {
        log_caller("VaultRemovePassword", &header);

        let backend = self
            .state
            .backend_by_id(&vault_id)
            .ok_or_else(|| FdoError::Failed(format!("vault '{vault_id}' not found")))?;

        if !backend.as_any().is::<rosec_vault::LocalVault>() {
            return Err(FdoError::Failed(format!(
                "'{vault_id}' is not a local vault"
            )));
        }

        self.state
            .run_on_tokio(async move {
                let local_vault = backend
                    .as_any()
                    .downcast_ref::<rosec_vault::LocalVault>()
                    .expect("type check passed above");
                local_vault
                    .remove_password(&entry_id)
                    .await
                    .map_err(|e| FdoError::Failed(format!("remove_password failed: {e}")))
            })
            .await?
    }

    /// List all wrapping entries (passwords) for a local vault.
    ///
    /// Returns `Vec<(entry_id, label)>` where `label` is empty if none was set.
    /// The vault must be unlocked.
    async fn vault_list_passwords(
        &self,
        vault_id: String,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<VaultPasswordEntry>, FdoError> {
        log_caller("VaultListPasswords", &header);

        let backend = self
            .state
            .backend_by_id(&vault_id)
            .ok_or_else(|| FdoError::Failed(format!("vault '{vault_id}' not found")))?;

        if !backend.as_any().is::<rosec_vault::LocalVault>() {
            return Err(FdoError::Failed(format!(
                "'{vault_id}' is not a local vault"
            )));
        }

        let entries = self
            .state
            .run_on_tokio(async move {
                let local_vault = backend
                    .as_any()
                    .downcast_ref::<rosec_vault::LocalVault>()
                    .expect("type check passed above");
                local_vault
                    .list_passwords()
                    .await
                    .map_err(|e| FdoError::Failed(format!("list_passwords failed: {e}")))
            })
            .await??;

        Ok(entries
            .into_iter()
            .map(|(id, label)| VaultPasswordEntry {
                id,
                label: label.unwrap_or_default(),
            })
            .collect())
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
        prompt_path: zvariant::ObjectPath<'_>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<bool, FdoError> {
        log_caller("CancelPrompt", &header);
        // cancel_prompt() sends SIGTERM to the child and removes it from the registry.
        // We check whether the path existed before calling it.
        let prompt_path = prompt_path.as_str();
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

/// A vault wrapping entry (password) descriptor returned by `VaultListPasswords`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct VaultPasswordEntry {
    /// Unique entry ID (UUID).
    pub id: String,
    /// Human-readable label (empty if none was set).
    pub label: String,
}
