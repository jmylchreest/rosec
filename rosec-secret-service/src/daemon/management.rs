use std::sync::Arc;
use std::time::SystemTime;

use futures_util::StreamExt as _;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::message::Header;
use zvariant::OwnedFd;

use super::log_dbus_caller;
use crate::state::ServiceState;
use crate::unlock::{CredentialSink, auth_provider_with_tty, unlock_all, unlock_with_tty};

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
        log_dbus_caller("management", "Status", &header);
        let cache_size = self
            .state
            .cache
            .items
            .lock()
            .map(|items| items.len())
            .unwrap_or(0);

        Ok(DaemonStatus {
            cache_size: cache_size as u32,
        })
    }

    /// Rebuild the item cache from whatever the providers currently hold in memory.
    ///
    /// Triggers a background sync for every unlocked provider so that
    /// `on_sync_succeeded` callbacks (e.g. SSH key rebuild) fire even when the
    /// caller only asks for a cache refresh.  Uses `try_sync_provider` so
    /// concurrent in-flight syncs are skipped rather than serialised.
    async fn refresh(&self, #[zbus(header)] header: Header<'_>) -> Result<u32, FdoError> {
        log_dbus_caller("management", "Refresh", &header);

        // Kick off a sync for every unlocked provider so that lifecycle callbacks
        // (SSH key rebuild, etc.) are triggered.  Errors are logged but do not
        // fail the Refresh call — the cache is still rebuilt from in-memory state.
        for provider in self.state.providers_ordered() {
            let is_locked = provider.status().await.map(|s| s.locked).unwrap_or(true);
            if !is_locked {
                let id = provider.id().to_string();
                if let Err(e) = self.state.try_sync_provider(&id).await {
                    tracing::warn!(provider = %id, "Refresh: background sync failed: {e}");
                }
            }
        }

        let entries = self.state.rebuild_cache().await?;
        Ok(entries.len() as u32)
    }

    /// Pull fresh data from the remote server for a specific provider, then
    /// rebuild the item cache.
    ///
    /// Returns the number of items visible after the sync.
    /// Returns a D-Bus error if the provider is not found, is locked, or the
    /// network request fails.
    async fn sync_provider(
        &self,
        provider_id: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<u32, FdoError> {
        log_dbus_caller("management", "SyncProvider", &header);
        self.state.sync_provider(provider_id).await
    }

    /// Return the full list of configured providers with kind and lock state.
    ///
    /// Lock state is derived from cached item metadata — an unlocked provider
    /// has at least one item without the locked flag set (or the cache is
    /// non-empty), while a locked provider has no accessible items.
    async fn provider_list(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<ProviderListEntry>, FdoError> {
        log_dbus_caller("management", "ProviderList", &header);
        let providers = self.state.providers_ordered();
        let mut entries = Vec::with_capacity(providers.len());
        for p in providers {
            let id = p.id().to_string();
            let name = p.name().to_string();
            let kind = p.kind().to_string();
            let capabilities: Vec<String> =
                p.capabilities().iter().map(|c| format!("{c:?}")).collect();
            let status = self
                .state
                .run_on_tokio(async move { p.status().await })
                .await?
                .map_err(|e| FdoError::Failed(format!("status error for {id}: {e}")))?;
            let last_cache_write = status
                .last_cache_write
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            let last_sync = status
                .last_sync
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            entries.push(ProviderListEntry {
                id,
                name,
                kind,
                locked: status.locked,
                cached: status.cached,
                offline_cache: status.offline_cache,
                last_cache_write,
                last_sync,
                capabilities,
            });
        }
        Ok(entries)
    }

    /// Return the credential fields required by a provider.
    ///
    /// The list always starts with the password field (`provider.password_field()`)
    /// followed by any additional fields declared by `provider.auth_fields()`.
    ///
    /// Each element is a tuple `(id, label, kind, placeholder, required)` where
    /// `kind` is one of `"text"`, `"password"`, or `"secret"`.
    /// Returns at least one element (the password field) if the provider is found.
    fn get_auth_fields(
        &self,
        provider_id: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<AuthFieldInfo>, FdoError> {
        log_dbus_caller("management", "GetAuthFields", &header);

        let provider = match self.state.provider_by_id(provider_id) {
            Some(b) => b,
            None => {
                return Err(FdoError::Failed(format!(
                    "provider '{provider_id}' not found"
                )));
            }
        };

        let field_to_info = |f: &rosec_core::AuthField| AuthFieldInfo {
            id: f.id.to_string(),
            label: f.label.to_string(),
            kind: f.kind.to_string(),
            placeholder: f.placeholder.to_string(),
            required: f.required,
        };

        // Always emit the password field first, then any additional auth fields.
        let pw = provider.password_field();
        let mut fields = vec![field_to_info(&pw)];
        fields.extend(provider.auth_fields().iter().map(field_to_info));

        Ok(fields)
    }

    /// Return registration info for a provider that requires device/API-key registration.
    ///
    /// Returns `(instructions, fields)` where `fields` has the same element layout
    /// as `GetAuthFields`.  Returns a D-Bus error with message `"no_registration_required"`
    /// if the provider does not support registration.
    fn get_registration_info(
        &self,
        provider_id: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(String, Vec<AuthFieldInfo>), FdoError> {
        log_dbus_caller("management", "GetRegistrationInfo", &header);

        let provider = match self.state.provider_by_id(provider_id) {
            Some(b) => b,
            None => {
                return Err(FdoError::Failed(format!(
                    "provider '{provider_id}' not found"
                )));
            }
        };

        let info = provider
            .registration_info()
            .ok_or_else(|| FdoError::Failed("no_registration_required".to_string()))?;

        let fields = info
            .fields
            .iter()
            .map(|f| AuthFieldInfo {
                id: f.id.to_string(),
                label: f.label.to_string(),
                kind: f.kind.to_string(),
                placeholder: f.placeholder.to_string(),
                required: f.required,
            })
            .collect();

        Ok((info.instructions.to_string(), fields))
    }

    /// Unlock all locked providers using credentials prompted on the caller's TTY.
    ///
    /// The caller opens `/dev/tty` and passes the file descriptor via D-Bus
    /// fd-passing (SCM_RIGHTS, type signature `h`).  `dbus-monitor` sees only
    /// the fd number — never any credential.  All prompting happens inside the
    /// daemon process via the received fd.
    ///
    /// Returns a list of `(provider_id, success, message)` tuples — one per
    /// provider that was locked at the time of the call.
    async fn unlock_with_tty(
        &self,
        tty_fd: OwnedFd,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<UnlockResultEntry>, FdoError> {
        log_dbus_caller("management", "UnlockWithTty", &header);

        // Duplicate the tty fd so it survives the move into the Tokio task.
        use std::os::unix::io::AsRawFd as _;
        let raw: libc::c_int = unsafe { libc::dup(tty_fd.as_raw_fd()) };
        if raw < 0 {
            return Err(FdoError::Failed(format!(
                "dup(tty_fd) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Create a cancellation pipe.  The read end is passed into the auth
        // task; closing the write end from this side triggers poll() in
        // read_hidden() to return POLLHUP and abort the blocking read.
        let (cancel_r, cancel_w) = make_cancel_pipe()?;

        let state = Arc::clone(&self.state);
        let handle = self.state.spawn_on_tokio(async move {
            let res = unlock_with_tty(state, raw, Some(cancel_r)).await;
            // Close our dup'd fds after the unlock completes (whether success
            // or failure) so no fd leaks occur.
            unsafe {
                libc::close(raw);
                libc::close(cancel_r);
            }
            res
        });

        // Race the auth task against peer-disconnect.  If the caller exits
        // before the task finishes, signal the cancel pipe and abort the task
        // so its spawn_blocking thread unblocks via poll().
        let conn = self.state.conn();
        let result = wait_for_task_or_peer_exit(
            handle,
            cancel_w,
            header.sender().map(|s| s.as_str().to_string()),
            &conn,
        )
        .await;

        match result {
            Ok(Ok(results)) => Ok(results
                .into_iter()
                .map(|r| UnlockResultEntry {
                    provider_id: r.provider_id,
                    success: r.success,
                    message: r.message,
                })
                .collect()),
            Ok(Err(e)) => Err(FdoError::Failed(format!("unlock_with_tty error: {e}"))),
            Err(e) => Err(e),
        }
    }

    /// Unlock every locked provider, prompting in `rosec-prompt` dialogs.
    ///
    /// Same walk and same return as `UnlockWithTty`, but needs no controlling
    /// terminal — usable from keybindings and systemd units.
    async fn unlock_with_prompt(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<UnlockResultEntry>, FdoError> {
        log_dbus_caller("management", "UnlockWithPrompt", &header);

        // Anything on the session bus can call this, and a dialog carries no
        // evidence of who asked for it — so name the caller on every prompt.
        let caller = crate::prompt::resolve_caller_info(&header, &self.state.conn()).await;

        // One path for the whole walk, so CancelPrompt works as it does for
        // the spec Prompt flow.
        let prompt_path = self.state.allocate_prompt("");
        let state = Arc::clone(&self.state);
        let path_for_task = prompt_path.clone();
        let handle = self.state.spawn_on_tokio(async move {
            let sink = CredentialSink::prompt(path_for_task, caller);
            unlock_all(state, &sink).await
        });

        let result = handle
            .await
            .map_err(|e| FdoError::Failed(format!("unlock task panicked: {e}")))?;
        self.state.finish_prompt(&prompt_path);

        match result {
            Ok(results) => Ok(results
                .into_iter()
                .map(|r| UnlockResultEntry {
                    provider_id: r.provider_id,
                    success: r.success,
                    message: r.message,
                })
                .collect()),
            Err(e) => Err(FdoError::Failed(format!("unlock_with_prompt error: {e}"))),
        }
    }

    /// Authenticate a specific provider using credentials prompted on the caller's TTY.
    ///
    /// Like `UnlockWithTty` but targets a single provider by ID.  Used by
    /// `rosec provider auth` and `rosec provider add`.
    ///
    /// Credentials are prompted in-process on the fd received via fd-passing;
    /// they never appear in any D-Bus message payload.
    async fn auth_provider_with_tty(
        &self,
        provider_id: String,
        tty_fd: OwnedFd,
        force: bool,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FdoError> {
        log_dbus_caller("management", "AuthProviderWithTty", &header);

        use std::os::unix::io::AsRawFd as _;
        let raw: libc::c_int = unsafe { libc::dup(tty_fd.as_raw_fd()) };
        if raw < 0 {
            return Err(FdoError::Failed(format!(
                "dup(tty_fd) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let (cancel_r, cancel_w) = make_cancel_pipe()?;

        let state = Arc::clone(&self.state);
        let handle = self.state.spawn_on_tokio(async move {
            let res = auth_provider_with_tty(state, raw, Some(cancel_r), &provider_id, force).await;
            unsafe {
                libc::close(raw);
                libc::close(cancel_r);
            }
            res
        });

        let conn = self.state.conn();
        let result = wait_for_task_or_peer_exit(
            handle,
            cancel_w,
            header.sender().map(|s| s.as_str().to_string()),
            &conn,
        )
        .await;

        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(FdoError::Failed(format!(
                "auth_provider_with_tty error: {e}"
            ))),
            Err(e) => Err(e),
        }
    }

    /// Authenticate a provider by reading a password from a pipe fd.
    ///
    /// The caller creates a pipe, writes the password to the write end (then
    /// closes it), and passes the read end via D-Bus fd-passing (SCM_RIGHTS).
    /// The daemon reads the password from the pipe, wraps it in `Zeroizing`,
    /// and calls `auth_provider`.
    ///
    /// This is the preferred method for PAM modules and other non-interactive
    /// callers that already have the password but want to avoid sending it as
    /// a plain D-Bus message payload (visible to `dbus-monitor`).
    ///
    /// **Security model**: The D-Bus session bus is per-user (kernel-enforced
    /// UID check on socket connect), so only processes running as the same
    /// user can call this method.  The password travels through a kernel pipe
    /// (SCM_RIGHTS fd-passing), never as a D-Bus message string payload,
    /// making it invisible to `dbus-monitor`.
    ///
    /// Returns `true` on success.  Returns a D-Bus error if the provider is not
    /// found, the password is wrong, or reading from the pipe fails.
    async fn auth_provider_from_pipe(
        &self,
        provider_id: String,
        pipe_fd: OwnedFd,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<bool, FdoError> {
        log_dbus_caller("management", "AuthProviderFromPipe", &header);

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
                // Read the password off the pipe on a blocking thread bounded
                // by a timeout, so a caller that never writes cannot pin a
                // runtime worker (see read_pipe_password).
                let password = read_pipe_password(raw, "auth").await?;

                // Look up the password field ID for this provider.
                let provider = state.provider_by_id(&provider_id).ok_or_else(|| {
                    FdoError::Failed(format!("provider '{provider_id}' not found"))
                })?;
                let pw_field_id = provider.password_field().id.to_string();

                let mut fields = std::collections::HashMap::new();
                fields.insert(pw_field_id, password);

                state.auth_provider(&provider_id, fields).await?;
                Ok(true)
            })
            .await?
    }

    /// Add a password (wrapping entry) to a local vault provider.
    ///
    /// The provider must be unlocked.  The new password wraps the same vault key
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
    async fn add_password(
        &self,
        provider_id: String,
        password: Vec<u8>,
        label: String,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<String, FdoError> {
        log_dbus_caller("management", "AddPassword", &header);

        // Wrap in Zeroizing at the D-Bus boundary so the password is scrubbed on drop.
        let password = zeroize::Zeroizing::new(password);

        let provider = self
            .state
            .provider_by_id(&provider_id)
            .ok_or_else(|| FdoError::Failed(format!("provider '{provider_id}' not found")))?;

        let label = if label.is_empty() {
            return Err(FdoError::Failed("password label cannot be empty".into()));
        } else {
            label
        };

        self.state
            .run_on_tokio(async move {
                provider
                    .add_password(&password, label)
                    .await
                    .map_err(|e| FdoError::Failed(format!("add_password failed: {e}")))
            })
            .await?
    }

    /// Remove a password (wrapping entry) from a local vault provider by entry ID.
    ///
    /// The provider must be unlocked and must have at least 2 wrapping entries
    /// (the last entry cannot be removed).
    async fn remove_password(
        &self,
        provider_id: String,
        entry_id: String,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FdoError> {
        log_dbus_caller("management", "RemovePassword", &header);

        let provider = self
            .state
            .provider_by_id(&provider_id)
            .ok_or_else(|| FdoError::Failed(format!("provider '{provider_id}' not found")))?;

        self.state
            .run_on_tokio(async move {
                provider
                    .remove_password(&entry_id)
                    .await
                    .map_err(|e| FdoError::Failed(format!("remove_password failed: {e}")))
            })
            .await?
    }

    /// List all wrapping entries (passwords) for a local vault provider.
    ///
    /// Returns `Vec<(entry_id, label)>` where `label` is empty if none was set.
    /// The provider must be unlocked.
    async fn list_passwords(
        &self,
        provider_id: String,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<PasswordEntry>, FdoError> {
        log_dbus_caller("management", "ListPasswords", &header);

        let provider = self
            .state
            .provider_by_id(&provider_id)
            .ok_or_else(|| FdoError::Failed(format!("provider '{provider_id}' not found")))?;

        let entries = self
            .state
            .run_on_tokio(async move {
                provider
                    .list_passwords()
                    .await
                    .map_err(|e| FdoError::Failed(format!("list_passwords failed: {e}")))
            })
            .await??;

        Ok(entries
            .into_iter()
            .map(|(id, label)| PasswordEntry {
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
        log_dbus_caller("management", "CancelPrompt", &header);
        // cancel_prompt() sends SIGTERM to the child and removes it from the registry.
        // We check whether the path existed before calling it.
        let prompt_path = prompt_path.as_str();
        let existed = self.state.prompts.contains_path(prompt_path);
        self.state.cancel_prompt(prompt_path);
        Ok(existed)
    }

    /// Change the unlock password for a provider.
    ///
    /// The caller creates two pipes:
    /// - `old_password_fd`: write end has the current password, read end passed here
    /// - `new_password_fd`: write end has the new password, read end passed here
    ///
    /// Both fds are passed via D-Bus fd-passing (SCM_RIGHTS, type signature `h`).
    /// `dbus-monitor` sees only fd numbers — never any credential.
    ///
    /// Works for any provider that implements `change_password()` (local vaults
    /// and SM providers).  Returns a D-Bus error if the provider doesn't support
    /// password changes, the old password is wrong, or the provider is locked.
    async fn change_provider_password(
        &self,
        provider_id: String,
        old_password_fd: OwnedFd,
        new_password_fd: OwnedFd,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FdoError> {
        log_dbus_caller("management", "ChangeProviderPassword", &header);

        use std::os::unix::io::AsRawFd as _;
        let old_raw: libc::c_int = unsafe { libc::dup(old_password_fd.as_raw_fd()) };
        if old_raw < 0 {
            return Err(FdoError::Failed(format!(
                "dup(old_password_fd) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let new_raw: libc::c_int = unsafe { libc::dup(new_password_fd.as_raw_fd()) };
        if new_raw < 0 {
            unsafe { libc::close(old_raw) };
            return Err(FdoError::Failed(format!(
                "dup(new_password_fd) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let state = Arc::clone(&self.state);
        self.state
            .run_on_tokio(async move {
                // Read both passwords off the pipes on blocking threads bounded
                // by a timeout (see read_pipe_password), so a caller that never
                // writes cannot pin a runtime worker.
                let old_password = read_pipe_password(old_raw, "old").await?;
                let new_password = read_pipe_password(new_raw, "new").await?;

                let provider = state.provider_by_id(&provider_id).ok_or_else(|| {
                    FdoError::Failed(format!("provider '{provider_id}' not found"))
                })?;

                provider
                    .change_password(old_password, new_password)
                    .await
                    .map_err(|e| FdoError::Failed(format!("change_password failed: {e}")))
            })
            .await?
    }
}

/// Give up waiting for a password on a caller-supplied pipe after this long,
/// so a peer that passes a pipe and never writes cannot tie up a thread.
const PIPE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Blocking read of a password from a raw pipe fd into a `Zeroizing<String>`.
/// Takes ownership of `raw` and closes it on return.
fn read_pipe_password_blocking(
    raw: std::os::unix::io::RawFd,
    name: &str,
) -> Result<zeroize::Zeroizing<String>, FdoError> {
    use std::io::Read as _;
    use std::os::unix::io::FromRawFd as _;
    // SAFETY: `raw` is a valid, owned dup'd fd handed to this function.
    let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(256));
    file.read_to_end(&mut buf)
        .map_err(|e| FdoError::Failed(format!("read from {name} pipe failed: {e}")))?;
    // Strip a trailing null (pam_exec null-terminates) then a trailing newline.
    if buf.last() == Some(&0) {
        buf.pop();
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.is_empty() {
        return Err(FdoError::Failed(format!("{name} password is empty")));
    }
    // Validate UTF-8 against the zeroizing buffer and copy into a
    // Zeroizing<String>; a mem::take would move the bytes out of the zeroizing
    // wrapper and drop a plain Vec on the error path.
    let s = std::str::from_utf8(&buf)
        .map_err(|_| FdoError::Failed(format!("{name} password is not valid UTF-8")))?;
    Ok(zeroize::Zeroizing::new(s.to_owned()))
}

/// Read a password from a caller-supplied pipe fd *off* the async runtime: the
/// blocking read runs on a `spawn_blocking` thread and is bounded by
/// [`PIPE_READ_TIMEOUT`]. A caller that passes a pipe read-end and never writes
/// therefore cannot pin a Tokio worker — which would otherwise starve the
/// runtime that every provider/secret operation funnels through.
async fn read_pipe_password(
    raw: std::os::unix::io::RawFd,
    name: &'static str,
) -> Result<zeroize::Zeroizing<String>, FdoError> {
    let handle = tokio::task::spawn_blocking(move || read_pipe_password_blocking(raw, name));
    match tokio::time::timeout(PIPE_READ_TIMEOUT, handle).await {
        Ok(join) => {
            join.map_err(|e| FdoError::Failed(format!("{name} pipe read task failed: {e}")))?
        }
        Err(_) => Err(FdoError::Failed(format!(
            "{name} password pipe read timed out after {}s",
            PIPE_READ_TIMEOUT.as_secs()
        ))),
    }
}

/// Create a `(read_fd, write_fd)` pipe used to signal cancellation.
///
/// The read end is passed into the auth task where `read_hidden()` polls it
/// alongside the tty fd.  Closing (or writing to) the write end causes the
/// `poll()` inside `read_hidden()` to return `POLLHUP`/`POLLIN` and the
/// blocking read is abandoned cleanly.
///
/// Both fds are set close-on-exec to prevent leaking into child processes.
fn make_cancel_pipe() -> Result<(libc::c_int, libc::c_int), FdoError> {
    let mut fds: [libc::c_int; 2] = [-1, -1];
    // SAFETY: fds is a valid two-element array; pipe2 fills [read, write].
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret < 0 {
        return Err(FdoError::Failed(format!(
            "pipe2 failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok((fds[0], fds[1]))
}

/// Race `task_handle` against a D-Bus `NameOwnerChanged` watch for `peer_name`.
///
/// If the task completes first, the cancel write-fd is closed (no-op for the
/// task which already finished) and the task result is returned.
///
/// If the peer disappears (client exited) before the task finishes:
///   1. The cancel write-fd is closed; this causes `POLLHUP` on the read end,
///      unblocking any `poll()` inside `read_hidden()`.
///   2. The task handle is aborted so Tokio drops it promptly.
///   3. An `FdoError::Failed("peer disconnected")` is returned.
///
/// If no `peer_name` is available (e.g. the message had no sender), the task
/// is awaited without any peer-disconnect supervision.
async fn wait_for_task_or_peer_exit<T: Send + 'static>(
    task_handle: tokio::task::JoinHandle<T>,
    cancel_write_fd: libc::c_int,
    peer_name: Option<String>,
    conn: &zbus::Connection,
) -> Result<T, FdoError> {
    // RAII wrapper: close the write end of the cancel pipe when this guard is
    // dropped, regardless of which branch of the select! wins.  Closing the
    // write end is a no-op (EBADF) if the task already finished and we close
    // it normally — libc::close on an already-closed fd returns an error we
    // intentionally ignore.
    struct CancelPipeGuard(libc::c_int);
    impl Drop for CancelPipeGuard {
        fn drop(&mut self) {
            if self.0 >= 0 {
                unsafe { libc::close(self.0) };
            }
        }
    }
    let _guard = CancelPipeGuard(cancel_write_fd);

    let Some(peer) = peer_name else {
        // No peer name — just await the task.
        return task_handle
            .await
            .map_err(|e| FdoError::Failed(format!("tokio task panicked: {e}")));
    };

    // Subscribe to NameOwnerChanged for the caller's unique name.  When the
    // new-owner field is empty the name has been released (process exited).
    let dbus_proxy = match zbus::fdo::DBusProxy::new(conn).await {
        Ok(p) => p,
        Err(_) => {
            // Can't set up the watch — fall back to plain await.
            return task_handle
                .await
                .map_err(|e| FdoError::Failed(format!("tokio task panicked: {e}")));
        }
    };
    let mut noc_stream = match dbus_proxy.receive_name_owner_changed().await {
        Ok(s) => s,
        Err(_) => {
            return task_handle
                .await
                .map_err(|e| FdoError::Failed(format!("tokio task panicked: {e}")));
        }
    };

    // Pin the task handle so we can poll it without consuming it, enabling us
    // to call abort() on the abort handle if the peer disconnects.
    let abort_handle = task_handle.abort_handle();
    tokio::pin!(task_handle);

    tokio::select! {
        // Task finished normally.
        join_result = &mut task_handle => {
            join_result.map_err(|e| FdoError::Failed(format!("tokio task panicked: {e}")))
        }
        // Watch NameOwnerChanged for this peer.
        _ = async {
            loop {
                let Some(signal) = noc_stream.next().await else { break };
                let args = match signal.args() {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                // new_owner is empty when the name is released.
                if args.name.as_str() == peer && args.new_owner.as_deref().unwrap_or("").is_empty() {
                    break;
                }
            }
        } => {
            // Peer disconnected.
            // 1. Abort the Tokio task (drops the async future and its
            //    spawn_blocking continuations as soon as the blocking thread
            //    yields or finishes).
            abort_handle.abort();
            // 2. The _guard Drop (below) will close cancel_write_fd, which
            //    triggers POLLHUP on the read end inside read_hidden() so the
            //    spawn_blocking thread exits without waiting for user input.
            Err(FdoError::Failed("peer disconnected — TTY auth cancelled".to_string()))
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct DaemonStatus {
    pub cache_size: u32,
}

/// A provider list entry returned by `ProviderList`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct ProviderListEntry {
    pub id: String,
    pub name: String,
    /// The provider type string (e.g. `"bitwarden-pm"`, `"bitwarden-sm"`).
    pub kind: String,
    pub locked: bool,
    /// True when in-memory data has not been confirmed against the remote
    /// (offline unlock or failed sync). Data-quality signal.
    pub cached: bool,
    /// Whether offline caching is active for this provider (both
    /// `Capability::OfflineCache` declared and host config enabled).
    pub offline_cache: bool,
    /// When the cache file was last written to disk (epoch seconds, 0 = never).
    pub last_cache_write: u64,
    /// When this provider last synced successfully (epoch seconds, 0 = never).
    pub last_sync: u64,
    /// Capabilities declared by this provider (e.g. `["Sync", "Write", "Ssh"]`).
    pub capabilities: Vec<String>,
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
    pub provider_id: String,
    pub success: bool,
    /// Human-readable status message (e.g. "unlocked", "wrong password").
    pub message: String,
}

/// A wrapping entry (password) descriptor returned by `ListPasswords`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct PasswordEntry {
    /// Unique entry ID (UUID).
    pub id: String,
    /// Human-readable label (empty if none was set).
    pub label: String,
}
