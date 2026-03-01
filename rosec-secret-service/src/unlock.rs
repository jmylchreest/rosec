/// In-process credential collection and unlock logic.
///
/// `rosecd` receives a TTY file descriptor from the CLI client via D-Bus
/// fd-passing (SCM_RIGHTS).  All prompting happens here — inside the daemon
/// process — so credentials never appear in any D-Bus message payload.
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use tracing::{debug, info};
use zbus::fdo::Error as FdoError;
use zeroize::Zeroizing;

use crate::state::ServiceState;
use crate::tty::{TtyField, collect_tty_on_fd, prompt_field_on_fd};

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

/// Result of a single backend unlock attempt inside `unlock_with_tty`.
#[derive(Debug)]
pub struct UnlockResult {
    pub backend_id: String,
    pub success: bool,
    /// Human-readable status message (e.g. "unlocked", "wrong password", etc.).
    pub message: String,
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Unlock all locked backends using credentials prompted on `tty_fd`.
///
/// Implements the opportunistic sweep: if there are multiple locked backends,
/// prompts once and tries the same password against all of them.  Any that
/// fail (wrong password) or require registration are handled individually
/// afterwards.
///
/// This function must be called from a Tokio task context.
pub async fn unlock_with_tty(state: Arc<ServiceState>, tty_fd: RawFd) -> Result<Vec<UnlockResult>> {
    let backends = state.backends_ordered();
    let mut locked: Vec<_> = Vec::new();

    for backend in &backends {
        let status = backend
            .status()
            .await
            .map_err(|e| anyhow!("status error for {}: {e}", backend.id()))?;
        if status.locked {
            locked.push(Arc::clone(backend));
        }
    }

    if locked.is_empty() {
        return Ok(Vec::new());
    }

    let mut results: Vec<UnlockResult> = Vec::new();

    // Single-backend fast path — go straight to targeted auth.
    if locked.len() == 1 {
        let backend = &locked[0];
        let id = backend.id().to_string();
        let fields = backend_auth_fields(backend.as_ref());
        let _password = auth_backend_with_tty_inner(&state, tty_fd, &id, &fields, None).await?;
        results.push(UnlockResult {
            backend_id: id.clone(),
            success: true,
            message: "unlocked".to_string(),
        });
        // auth_backend_with_tty_inner -> auth_backend_inner already called
        // mark_backend_unlocked + touch_activity, so no need to repeat here.
        // Sync immediately so on_sync_succeeded callbacks fire (e.g. SSH rebuild).
        if let Err(e) = state.try_sync_backend(&id).await {
            debug!(backend = %id, "post-unlock sync failed: {e}");
        }
        return Ok(results);
    }

    // Multiple backends — print a header listing them all, then prompt once.
    print_on_fd(tty_fd, "\n");
    print_on_fd(tty_fd, &format!("Unlocking {} backends:\n", locked.len()));
    for b in &locked {
        let id = b.id();
        let name = b.name();
        if name.is_empty() || name == id {
            print_on_fd(tty_fd, &format!("  {id}\n"));
        } else {
            print_on_fd(tty_fd, &format!("  {id:<30}  ({name})\n"));
        }
    }

    // Use the first backend's password field descriptor as representative.
    let first_fields = backend_auth_fields(locked[0].as_ref());
    let pw_field = first_fields
        .first()
        .ok_or_else(|| anyhow!("backend returned no auth fields"))?;

    let collected = collect_tty_on_fd(tty_fd, std::slice::from_ref(pw_field)).await?;

    // Try the collected credentials against every locked backend.
    // We pass the Zeroizing<String> map directly — no plain String copies.

    // Track which backends need a registration flow (password already collected).
    let mut need_registration: Vec<(String, HashMap<String, Zeroizing<String>>)> = Vec::new();
    // Track which backends had a plain failure.
    let mut need_individual: Vec<String> = Vec::new();

    for backend in &locked {
        let id = backend.id().to_string();
        // Clone the Zeroizing<String> values — each clone is itself zeroized on drop.
        let fields_clone: HashMap<String, Zeroizing<String>> = collected
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        match state.auth_backend_inner(&id, fields_clone).await {
            Ok(()) => {
                results.push(UnlockResult {
                    backend_id: id.clone(),
                    success: true,
                    message: "unlocked".to_string(),
                });
                // Sync immediately so on_sync_succeeded callbacks fire.
                if let Err(e) = state.try_sync_backend(&id).await {
                    debug!(backend = %id, "post-unlock sync failed: {e}");
                }
            }
            Err(FdoError::Failed(ref msg)) if msg == "registration_required" => {
                debug!(backend = %id, "registration required after opportunistic unlock");
                let prefill: HashMap<String, Zeroizing<String>> = collected
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                need_registration.push((id, prefill));
            }
            Err(e) => {
                debug!(backend = %id, "opportunistic unlock failed: {e}");
                need_individual.push(id);
            }
        }
    }

    // Handle backends that need registration (password already collected).
    for (id, prefill) in need_registration {
        let fields = {
            let b = state
                .backend_by_id(&id)
                .ok_or_else(|| anyhow!("backend '{id}' not found"))?;
            backend_auth_fields(b.as_ref())
        };
        let _password =
            auth_backend_with_tty_inner(&state, tty_fd, &id, &fields, Some(prefill)).await?;
        results.push(UnlockResult {
            backend_id: id.clone(),
            success: true,
            message: "unlocked (registered)".to_string(),
        });
        if let Err(e) = state.try_sync_backend(&id).await {
            debug!(backend = %id, "post-unlock sync failed: {e}");
        }
    }

    // Handle backends that need a fresh individual prompt.
    for id in need_individual {
        let fields = {
            let b = state
                .backend_by_id(&id)
                .ok_or_else(|| anyhow!("backend '{id}' not found"))?;
            backend_auth_fields(b.as_ref())
        };
        let _password = auth_backend_with_tty_inner(&state, tty_fd, &id, &fields, None).await?;
        results.push(UnlockResult {
            backend_id: id.clone(),
            success: true,
            message: "unlocked".to_string(),
        });
        if let Err(e) = state.try_sync_backend(&id).await {
            debug!(backend = %id, "post-unlock sync failed: {e}");
        }
    }

    // mark_backend_unlocked + touch_activity are already called inside
    // auth_backend_inner for each successful backend unlock, so no need
    // for a separate mark_unlocked() call here.

    Ok(results)
}

/// Authenticate a single backend using credentials prompted on `tty_fd`.
///
/// This is the `AuthBackendWithTty` D-Bus method implementation.
/// Must be called from a Tokio task context.
pub async fn auth_backend_with_tty(
    state: Arc<ServiceState>,
    tty_fd: RawFd,
    backend_id: &str,
) -> Result<()> {
    let fields = {
        let b = state
            .backend_by_id(backend_id)
            .ok_or_else(|| anyhow!("backend '{backend_id}' not found"))?;
        backend_auth_fields(b.as_ref())
    };
    let password = auth_backend_with_tty_inner(&state, tty_fd, backend_id, &fields, None).await?;
    // auth_backend_inner (called by auth_backend_with_tty_inner) already
    // called mark_backend_unlocked + touch_activity.
    // Sync immediately so on_sync_succeeded callbacks fire (e.g. SSH rebuild).
    if let Err(e) = state.try_sync_backend(backend_id).await {
        debug!(backend = %backend_id, "post-unlock sync failed: {e}");
    }
    // Opportunistically try the same password against other locked backends.
    // Spawn as a detached task so the caller returns immediately — the sweep
    // can take seconds when it triggers full Bitwarden syncs.
    if !password.is_empty() {
        let sweep_state = Arc::clone(&state);
        let sweep_id = backend_id.to_string();
        tokio::spawn(async move {
            sweep_state.opportunistic_sweep(&password, &sweep_id).await;
            debug!("opportunistic sweep complete (from auth_backend_with_tty)");
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core implementation
// ---------------------------------------------------------------------------

/// Collect credentials from the TTY and authenticate `backend_id`.
///
/// If `prefill` is `Some`, the credential prompt is skipped (the password was
/// already collected during the opportunistic sweep); only registration-specific
/// fields are prompted for.
///
/// If `prefill` is `None` and `AuthBackend` returns `registration_required`,
/// the user is asked to confirm their password once (to guard against typos on
/// first-time setup), then registration-specific fields are collected.
///
/// On success, returns the password value used for the unlock so the caller
/// can pass it to `opportunistic_sweep` if desired.
async fn auth_backend_with_tty_inner(
    state: &Arc<ServiceState>,
    tty_fd: RawFd,
    backend_id: &str,
    fields: &[TtyField],
    prefill: Option<HashMap<String, Zeroizing<String>>>,
) -> Result<Zeroizing<String>> {
    let is_token_auth = {
        let b = state
            .backend_by_id(backend_id)
            .ok_or_else(|| anyhow!("backend '{backend_id}' not found"))?;
        b.kind().ends_with("-sm")
    };

    let mut cred_map: HashMap<String, Zeroizing<String>> = if let Some(existing) = prefill {
        // Credentials already collected — skip the main prompt and go directly
        // to the first AuthBackend call (which we expect to return
        // registration_required).
        existing
    } else {
        // Print unlock header.
        print_on_fd(tty_fd, "\n");
        let b = state
            .backend_by_id(backend_id)
            .ok_or_else(|| anyhow!("backend '{backend_id}' not found"))?;
        let name = b.name().to_string();
        if name.is_empty() || name == backend_id {
            if is_token_auth {
                print_on_fd(tty_fd, &format!("Authenticating {backend_id}\n"));
            } else {
                print_on_fd(tty_fd, &format!("Unlocking {backend_id}\n"));
            }
        } else if is_token_auth {
            print_on_fd(tty_fd, &format!("Authenticating {backend_id}  ({name})\n"));
        } else {
            print_on_fd(tty_fd, &format!("Unlocking {backend_id}  ({name})\n"));
        }

        collect_tty_on_fd(tty_fd, fields).await?
    };

    // Pass the Zeroizing<String> map directly — no plain String intermediary.
    let result = state.auth_backend_inner(backend_id, cred_map.clone()).await;

    let needs_registration = matches!(
        &result,
        Err(FdoError::Failed(msg)) if msg == "registration_required"
    );

    if needs_registration {
        // Registration required — get the instructions and extra fields.
        let b = state
            .backend_by_id(backend_id)
            .ok_or_else(|| anyhow!("backend '{backend_id}' not found"))?;

        let reg_info = b.registration_info().ok_or_else(|| {
            anyhow!("backend reported registration_required but has no registration_info")
        })?;

        print_on_fd(tty_fd, "\n");
        print_on_fd(tty_fd, &format!("{}\n", reg_info.instructions));
        print_on_fd(tty_fd, "\n");

        // Confirm password only when we are the ones who collected it (not from
        // a prefill path — prefill means the password was already verified by
        // another backend unlocking successfully).
        // We check by seeing whether the pw field is in cred_map at all.
        let pw_field_id = b.password_field().id.to_string();
        if cred_map.contains_key(&pw_field_id) {
            // First-time setup: the password has not been verified against
            // anything stored.  Ask the user to confirm it once per
            // password/secret field to guard against typos.
            print_on_fd(
                tty_fd,
                "Please confirm your password (it has not been verified yet):\n\n",
            );
            for field in fields
                .iter()
                .filter(|f| f.kind == "password" || f.kind == "secret")
            {
                let original = cred_map
                    .get(&field.id)
                    .cloned()
                    .unwrap_or_else(|| Zeroizing::new(String::new()));
                loop {
                    let confirm_label = format!("Confirm {}", field.label);
                    let entry = prompt_field_on_fd(tty_fd, &confirm_label, "", &field.kind).await?;
                    if entry.as_str() == original.as_str() {
                        break;
                    }
                    print_on_fd(tty_fd, "Does not match — please try again.\n\n");
                }
            }
        }

        // Collect registration-specific fields (e.g. the SM access token).
        let reg_fields: Vec<TtyField> = reg_info
            .fields
            .iter()
            .map(|f| TtyField {
                id: f.id.to_string(),
                label: f.label.to_string(),
                kind: auth_field_kind_str(&f.kind),
                placeholder: f.placeholder.to_string(),
            })
            .collect();

        let reg_extra = collect_tty_on_fd(tty_fd, &reg_fields).await?;
        cred_map.extend(reg_extra);

        // Retry with registration fields included.
        // cred_map now contains both the original credentials and registration
        // fields — all as Zeroizing<String> values that zeroize on drop.
        state
            .auth_backend_inner(backend_id, cred_map.clone())
            .await
            .map_err(|e| anyhow!("registration failed for '{backend_id}': {e}"))?;
    } else {
        result.map_err(|e| anyhow!("auth failed for '{backend_id}': {e}"))?;
    }

    // Extract the password value for the caller before dropping cred_map.
    let pw_field_id = {
        let b = state
            .backend_by_id(backend_id)
            .ok_or_else(|| anyhow!("backend '{backend_id}' not found"))?;
        b.password_field().id.to_string()
    };
    let password = cred_map
        .get(&pw_field_id)
        .cloned()
        .unwrap_or_else(|| Zeroizing::new(String::new()));

    // cred_map is dropped here; all Zeroizing<String> values are scrubbed.
    drop(cred_map);

    info!(backend = %backend_id, "backend authenticated via AuthBackendWithTty");
    Ok(password)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Collect auth field descriptors for a backend into `TtyField` structs.
pub(crate) fn backend_auth_fields(backend: &dyn rosec_core::VaultBackend) -> Vec<TtyField> {
    let pw = backend.password_field();
    let mut fields = vec![TtyField {
        id: pw.id.to_string(),
        label: pw.label.to_string(),
        kind: auth_field_kind_str(&pw.kind),
        placeholder: pw.placeholder.to_string(),
    }];
    fields.extend(backend.auth_fields().iter().map(|f| TtyField {
        id: f.id.to_string(),
        label: f.label.to_string(),
        kind: auth_field_kind_str(&f.kind),
        placeholder: f.placeholder.to_string(),
    }));
    fields
}

pub(crate) fn auth_field_kind_str(kind: &rosec_core::AuthFieldKind) -> String {
    match kind {
        rosec_core::AuthFieldKind::Text => "text".to_string(),
        rosec_core::AuthFieldKind::Password => "password".to_string(),
        rosec_core::AuthFieldKind::Secret => "secret".to_string(),
    }
}

/// Write a string to the fd (best-effort; errors are silently ignored since
/// this is informational output, not credential data).
fn print_on_fd(fd: RawFd, s: &str) {
    let bytes = s.as_bytes();
    unsafe {
        libc::write(fd, bytes.as_ptr().cast(), bytes.len());
    }
}
