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

/// Result of a single provider unlock attempt inside `unlock_with_tty`.
#[derive(Debug)]
pub struct UnlockResult {
    pub provider_id: String,
    pub success: bool,
    /// Human-readable status message (e.g. "unlocked", "wrong password", etc.).
    pub message: String,
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Unlock all locked providers using credentials prompted on `tty_fd`.
///
/// Implements the opportunistic sweep: if there are multiple locked providers,
/// prompts once and tries the same password against all of them.  Any that
/// fail (wrong password) or require registration are handled individually
/// afterwards.
///
/// `cancel_fd` is the read end of a pipe; closing the write end from outside
/// this function will abort any in-progress blocking TTY read.  Pass `None`
/// if cancellation is not needed.
///
/// This function must be called from a Tokio task context.
pub async fn unlock_with_tty(
    state: Arc<ServiceState>,
    tty_fd: RawFd,
    cancel_fd: Option<RawFd>,
) -> Result<Vec<UnlockResult>> {
    let providers = state.providers_ordered();
    let mut locked: Vec<_> = Vec::new();

    for provider in &providers {
        let status = provider
            .status()
            .await
            .map_err(|e| anyhow!("status error for {}: {e}", provider.id()))?;
        if status.locked {
            locked.push(Arc::clone(provider));
        }
    }

    if locked.is_empty() {
        return Ok(Vec::new());
    }

    let mut results: Vec<UnlockResult> = Vec::new();

    // Single-provider fast path — go straight to targeted auth.
    if locked.len() == 1 {
        let provider = &locked[0];
        let id = provider.id().to_string();
        let fields = provider_auth_fields(provider.as_ref());
        let _password =
            auth_provider_with_tty_inner(&state, tty_fd, cancel_fd, &id, &fields, None, false)
                .await?;
        results.push(UnlockResult {
            provider_id: id.clone(),
            success: true,
            message: "unlocked".to_string(),
        });
        // auth_provider_with_tty_inner -> auth_provider_inner already called
        // mark_provider_unlocked + touch_activity, so no need to repeat here.
        // Sync immediately so on_sync_succeeded callbacks fire (e.g. SSH rebuild).
        if let Err(e) = state.try_sync_provider(&id).await {
            debug!(provider = %id, "post-unlock sync failed: {e}");
        }
        return Ok(results);
    }

    // Multiple providers — print a header listing them all, then prompt once.
    print_on_fd(tty_fd, "\n");
    print_on_fd(tty_fd, &format!("Unlocking {} providers:\n", locked.len()));
    for b in &locked {
        let id = b.id();
        let name = b.name();
        if name.is_empty() || name == id {
            print_on_fd(tty_fd, &format!("  {id}\n"));
        } else {
            print_on_fd(tty_fd, &format!("  {id:<30}  ({name})\n"));
        }
    }

    // Use the first provider's password field descriptor as representative for
    // the TTY prompt (label, hidden flag, etc.).
    let first_fields = provider_auth_fields(locked[0].as_ref());
    let pw_field = first_fields
        .first()
        .ok_or_else(|| anyhow!("provider returned no auth fields"))?;

    let collected = collect_tty_on_fd(tty_fd, std::slice::from_ref(pw_field), cancel_fd).await?;

    // Extract the raw password value.  The collected map is keyed by the first
    // provider's field ID, but other providers may use a different field name
    // (e.g. "unlock_password" vs "password").  We must re-map the value to each
    // provider's own password_field().id — the same approach opportunistic_sweep() uses.
    let raw_password: Zeroizing<String> = collected
        .values()
        .next()
        .cloned()
        .ok_or_else(|| anyhow!("no password value collected"))?;

    // Track which providers need a registration flow (password already collected).
    let mut need_registration: Vec<(String, Zeroizing<String>)> = Vec::new();
    // Track which providers need 2FA (password already collected).
    let mut need_2fa: Vec<(String, Zeroizing<String>)> = Vec::new();
    // Track which providers had a plain auth failure (wrong password etc).
    let mut need_individual: Vec<String> = Vec::new();

    for provider in &locked {
        let id = provider.id().to_string();
        // Map the password to this provider's expected field name.
        let pw_field_id = provider.password_field().id.to_string();
        let mut fields_for_provider = HashMap::new();
        fields_for_provider.insert(pw_field_id, raw_password.clone());
        match state.auth_provider_inner(&id, fields_for_provider).await {
            Ok(()) => {
                results.push(UnlockResult {
                    provider_id: id.clone(),
                    success: true,
                    message: "unlocked".to_string(),
                });
                // Sync immediately so on_sync_succeeded callbacks fire.
                if let Err(e) = state.try_sync_provider(&id).await {
                    debug!(provider = %id, "post-unlock sync failed: {e}");
                }
            }
            Err(FdoError::Failed(ref msg)) if msg == "registration_required" => {
                debug!(provider = %id, "registration required after opportunistic unlock");
                need_registration.push((id, raw_password.clone()));
            }
            Err(FdoError::Failed(ref msg)) if msg == "two_factor_required" => {
                debug!(provider = %id, "2FA required after opportunistic unlock");
                need_2fa.push((id, raw_password.clone()));
            }
            Err(FdoError::Failed(ref msg))
                if msg.contains("not found") || msg.contains("unavailable") =>
            {
                // Provider is unavailable (e.g. local vault file does not exist
                // yet).  Creating new vaults mid-sweep is not supported — the
                // user should run `rosec provider auth <id>` to initialise it.
                print_on_fd(
                    tty_fd,
                    &format!(
                        "  {id}: not available — run `rosec provider auth {id}` to initialise\n"
                    ),
                );
                results.push(UnlockResult {
                    provider_id: id.clone(),
                    success: false,
                    message: "unavailable".to_string(),
                });
            }
            Err(FdoError::Failed(ref msg)) if msg == "auth_failed" => {
                // Password is wrong for this provider (different master
                // password, or cache HMAC verification failed with wrong key).
                // Skip — re-prompting individually won't help since we'd use
                // the same password.
                print_on_fd(tty_fd, &format!("  {id}: wrong password (skipped)\n"));
                results.push(UnlockResult {
                    provider_id: id.clone(),
                    success: false,
                    message: "auth_failed".to_string(),
                });
            }
            Err(FdoError::Failed(ref msg)) if msg.contains("offline cache") => {
                // Provider is offline and has no cached data.  Nothing we can
                // do — skip it and let the user know.
                print_on_fd(tty_fd, &format!("  {id}: offline, no cache available\n"));
                results.push(UnlockResult {
                    provider_id: id.clone(),
                    success: false,
                    message: "offline, no cache".to_string(),
                });
            }
            Err(FdoError::Failed(ref msg)) if msg == "provider error" => {
                // Internal provider error (WASM trap, infrastructure failure,
                // etc.).  Re-prompting won't help — the problem is not the
                // password.  Skip and report.
                print_on_fd(tty_fd, &format!("  {id}: provider error (skipped)\n"));
                results.push(UnlockResult {
                    provider_id: id.clone(),
                    success: false,
                    message: "provider error".to_string(),
                });
            }
            Err(e) => {
                debug!(provider = %id, "opportunistic unlock failed: {e}");
                need_individual.push(id);
            }
        }
    }

    // Handle providers that need registration (password already collected).
    for (id, password) in need_registration {
        let (fields, pw_field_id) = {
            let b = state
                .provider_by_id(&id)
                .ok_or_else(|| anyhow!("provider '{id}' not found"))?;
            (
                provider_auth_fields(b.as_ref()),
                b.password_field().id.to_string(),
            )
        };
        // Build prefill map using this provider's own password field name.
        let mut prefill = HashMap::new();
        prefill.insert(pw_field_id, password);
        let _password = auth_provider_with_tty_inner(
            &state,
            tty_fd,
            cancel_fd,
            &id,
            &fields,
            Some(prefill),
            false,
        )
        .await?;
        results.push(UnlockResult {
            provider_id: id.clone(),
            success: true,
            message: "unlocked (registered)".to_string(),
        });
        if let Err(e) = state.try_sync_provider(&id).await {
            debug!(provider = %id, "post-unlock sync failed: {e}");
        }
    }

    // Handle providers that need 2FA (password already collected — only prompt
    // for the 2FA code, not the master password again).
    for (id, password) in need_2fa {
        let (pw_field_id, name) = {
            let b = state
                .provider_by_id(&id)
                .ok_or_else(|| anyhow!("provider '{id}' not found"))?;
            (b.password_field().id.to_string(), b.name().to_string())
        };
        // Print a header so the user knows which provider needs 2FA.
        print_on_fd(tty_fd, "\n");
        if name.is_empty() || name == id {
            print_on_fd(tty_fd, &format!("Unlocking {id}\n"));
        } else {
            print_on_fd(tty_fd, &format!("Unlocking {id}  ({name})\n"));
        }
        let mut prefill = HashMap::new();
        prefill.insert(pw_field_id, password);
        let fields = {
            let b = state
                .provider_by_id(&id)
                .ok_or_else(|| anyhow!("provider '{id}' not found"))?;
            provider_auth_fields(b.as_ref())
        };
        let _password = auth_provider_with_tty_inner(
            &state,
            tty_fd,
            cancel_fd,
            &id,
            &fields,
            Some(prefill),
            false,
        )
        .await?;
        results.push(UnlockResult {
            provider_id: id.clone(),
            success: true,
            message: "unlocked (2FA)".to_string(),
        });
        if let Err(e) = state.try_sync_provider(&id).await {
            debug!(provider = %id, "post-unlock sync failed: {e}");
        }
    }

    // Handle providers that need a fresh individual prompt.
    for id in need_individual {
        let fields = {
            let b = state
                .provider_by_id(&id)
                .ok_or_else(|| anyhow!("provider '{id}' not found"))?;
            provider_auth_fields(b.as_ref())
        };
        let _password =
            auth_provider_with_tty_inner(&state, tty_fd, cancel_fd, &id, &fields, None, false)
                .await?;
        results.push(UnlockResult {
            provider_id: id.clone(),
            success: true,
            message: "unlocked".to_string(),
        });
        if let Err(e) = state.try_sync_provider(&id).await {
            debug!(provider = %id, "post-unlock sync failed: {e}");
        }
    }

    // mark_provider_unlocked + touch_activity are already called inside
    // auth_provider_inner for each successful provider unlock, so no need
    // for a separate mark_unlocked() call here.

    Ok(results)
}

/// Authenticate a single provider using credentials prompted on `tty_fd`.
///
/// This is the `AuthProviderWithTty` D-Bus method implementation.
/// Must be called from a Tokio task context.
///
/// `cancel_fd` is the read end of a pipe; closing the write end from outside
/// this function will abort any in-progress blocking TTY read.  Pass `None`
/// if cancellation is not needed.
///
/// When `force` is `true`, the normal unlock attempt is skipped and the
/// registration flow is entered unconditionally.  This allows re-registering
/// provider credentials (e.g. rotating a Bitwarden SM access token or
/// re-registering a Bitwarden PM device) without deleting stored state first.
pub async fn auth_provider_with_tty(
    state: Arc<ServiceState>,
    tty_fd: RawFd,
    cancel_fd: Option<RawFd>,
    provider_id: &str,
    force: bool,
) -> Result<()> {
    let fields = {
        let b = state
            .provider_by_id(provider_id)
            .ok_or_else(|| anyhow!("provider '{provider_id}' not found"))?;
        provider_auth_fields(b.as_ref())
    };
    let password =
        auth_provider_with_tty_inner(&state, tty_fd, cancel_fd, provider_id, &fields, None, force)
            .await?;
    // auth_provider_inner (called by auth_provider_with_tty_inner) already
    // called mark_provider_unlocked + touch_activity.
    // Sync immediately so on_sync_succeeded callbacks fire (e.g. SSH rebuild).
    if let Err(e) = state.try_sync_provider(provider_id).await {
        debug!(provider = %provider_id, "post-unlock sync failed: {e}");
    }
    // Opportunistically try the same password against other locked providers.
    // Spawn as a detached task so the caller returns immediately — the sweep
    // can take seconds when it triggers full Bitwarden syncs.
    if !password.is_empty() {
        let sweep_state = Arc::clone(&state);
        let sweep_id = provider_id.to_string();
        tokio::spawn(async move {
            sweep_state.opportunistic_sweep(&password, &sweep_id).await;
            debug!("opportunistic sweep complete (from auth_provider_with_tty)");
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core implementation
// ---------------------------------------------------------------------------

/// Collect credentials from the TTY and authenticate `provider_id`.
///
/// If `prefill` is `Some`, the credential prompt is skipped (the password was
/// already collected during the opportunistic sweep); only registration-specific
/// fields are prompted for.
///
/// If `prefill` is `None` and `AuthProvider` returns `registration_required`,
/// the user is asked to confirm their password once (to guard against typos on
/// first-time setup), then registration-specific fields are collected.
///
/// When `force` is `true`, the initial `auth_provider_inner()` call is skipped
/// and the function proceeds directly to the registration flow.  This is used
/// by `rosec provider auth --force` to re-register even when stored credentials
/// already exist (e.g. to replace a rotated SM access token).
///
/// On success, returns the password value used for the unlock so the caller
/// can pass it to `opportunistic_sweep` if desired.
async fn auth_provider_with_tty_inner(
    state: &Arc<ServiceState>,
    tty_fd: RawFd,
    cancel_fd: Option<RawFd>,
    provider_id: &str,
    fields: &[TtyField],
    prefill: Option<HashMap<String, Zeroizing<String>>>,
    force: bool,
) -> Result<Zeroizing<String>> {
    let (is_token_auth, needs_confirmation) = {
        let b = state
            .provider_by_id(provider_id)
            .ok_or_else(|| anyhow!("provider '{provider_id}' not found"))?;
        (
            b.kind().ends_with("-sm"),
            // Only check when we're going to collect the password ourselves
            // (prefill = None, not a force-registration path).
            prefill.is_none() && !force && b.needs_new_password_confirmation(),
        )
    };

    // When force is set, verify the provider actually supports registration
    // before we collect any credentials.
    if force {
        let b = state
            .provider_by_id(provider_id)
            .ok_or_else(|| anyhow!("provider '{provider_id}' not found"))?;
        if b.registration_info().is_none() {
            return Err(anyhow!(
                "provider '{provider_id}' does not support registration; --force is not applicable"
            ));
        }
    }

    let mut cred_map: HashMap<String, Zeroizing<String>> = if let Some(existing) = prefill {
        // Credentials already collected by the sweep — skip prompting.
        existing
    } else {
        // Print unlock header.
        print_on_fd(tty_fd, "\n");
        let b = state
            .provider_by_id(provider_id)
            .ok_or_else(|| anyhow!("provider '{provider_id}' not found"))?;
        let name = b.name().to_string();
        if name.is_empty() || name == provider_id {
            if is_token_auth {
                print_on_fd(tty_fd, &format!("Authenticating {provider_id}\n"));
            } else {
                print_on_fd(tty_fd, &format!("Unlocking {provider_id}\n"));
            }
        } else if is_token_auth {
            print_on_fd(tty_fd, &format!("Authenticating {provider_id}  ({name})\n"));
        } else {
            print_on_fd(tty_fd, &format!("Unlocking {provider_id}  ({name})\n"));
        }

        collect_tty_on_fd(tty_fd, fields, cancel_fd).await?
    };

    // If the provider requires new-password confirmation (e.g. creating a new
    // local vault where nothing is stored yet to verify against), prompt the
    // user to type the password a second time before proceeding.
    if needs_confirmation {
        print_on_fd(tty_fd, "\n");
        print_on_fd(
            tty_fd,
            "This vault does not exist yet and will be created with this password.\n",
        );
        print_on_fd(tty_fd, "Please confirm your password:\n\n");
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
                let entry =
                    prompt_field_on_fd(tty_fd, &confirm_label, "", &field.kind, cancel_fd).await?;
                if entry.as_str() == original.as_str() {
                    break;
                }
                print_on_fd(tty_fd, "Does not match — please try again.\n\n");
            }
        }
    }

    // Try to authenticate.  If the provider requires registration (SM token
    // setup, Bitwarden device registration), collect the extra fields and retry.
    // If the provider requires 2FA, collect the token and retry.
    let auth_result = if force {
        None // skip straight to registration
    } else {
        Some(
            state
                .auth_provider_inner(provider_id, cred_map.clone())
                .await,
        )
    };

    let needs_registration = match &auth_result {
        None => true,
        Some(Err(FdoError::Failed(msg))) if msg == "registration_required" => true,
        _ => false,
    };

    let needs_2fa =
        matches!(&auth_result, Some(Err(FdoError::Failed(msg))) if msg == "two_factor_required");

    if needs_2fa {
        // Retrieve the available 2FA methods from the thread-local side channel
        // (set by map_provider_error when TwoFactorRequired was mapped).
        let methods = crate::state::take_two_factor_methods();

        // Filter to methods with prompt_kind == "text" (the only kind we
        // currently support).  FIDO2 / browser_redirect are deferred.
        let text_methods: Vec<_> = methods.iter().filter(|m| m.prompt_kind == "text").collect();

        if text_methods.is_empty() {
            return Err(anyhow!(
                "provider requires 2FA but no supported methods available \
                 (FIDO2/WebAuthn is not yet supported)"
            ));
        }

        // If multiple text methods, let the user choose; if only one, use it.
        let chosen = if text_methods.len() == 1 {
            text_methods[0]
        } else {
            print_on_fd(tty_fd, "\nTwo-factor authentication required.\n");
            print_on_fd(tty_fd, "Available methods:\n");
            for (i, m) in text_methods.iter().enumerate() {
                print_on_fd(tty_fd, &format!("  [{}] {}\n", i + 1, m.label));
            }
            let choice_field = vec![TtyField {
                id: "__2fa_choice".to_string(),
                label: "Choose method".to_string(),
                kind: "text".to_string(),
                placeholder: "1".to_string(),
            }];
            let choice_map = collect_tty_on_fd(tty_fd, &choice_field, cancel_fd).await?;
            let choice_str = choice_map
                .get("__2fa_choice")
                .map(|v| v.as_str())
                .unwrap_or("1");
            let idx: usize = choice_str.parse::<usize>().unwrap_or(1).saturating_sub(1);
            text_methods.get(idx).copied().unwrap_or(text_methods[0])
        };

        print_on_fd(tty_fd, &format!("\n{}\n", chosen.label));

        // Collect the 2FA token from the user.
        let token_field = vec![TtyField {
            id: "__2fa_token".to_string(),
            label: "Code".to_string(),
            kind: "secret".to_string(),
            placeholder: String::new(),
        }];
        let token_map = collect_tty_on_fd(tty_fd, &token_field, cancel_fd).await?;

        // Add the 2FA fields to cred_map and retry.
        cred_map.insert(
            "__2fa_method_id".to_string(),
            Zeroizing::new(chosen.id.clone()),
        );
        if let Some(token_val) = token_map.get("__2fa_token") {
            cred_map.insert("__2fa_token".to_string(), token_val.clone());
        }

        state
            .auth_provider_inner(provider_id, cred_map.clone())
            .await
            .map_err(|e| anyhow!("2FA authentication failed for '{provider_id}': {e}"))?;
    } else if needs_registration {
        let b = state
            .provider_by_id(provider_id)
            .ok_or_else(|| anyhow!("provider '{provider_id}' not found"))?;

        let reg_info = b.registration_info().ok_or_else(|| {
            anyhow!("provider reported registration_required but has no registration_info")
        })?;

        print_on_fd(tty_fd, "\n");
        print_on_fd(tty_fd, &format!("{}\n", reg_info.instructions));
        print_on_fd(tty_fd, "\n");

        // Collect registration-specific fields (e.g. the SM access token).
        let reg_fields: Vec<TtyField> = reg_info
            .fields
            .iter()
            .map(|f| TtyField {
                id: f.id.to_string(),
                label: f.label.to_string(),
                kind: f.kind.to_string(),
                placeholder: f.placeholder.to_string(),
            })
            .collect();

        let reg_extra = collect_tty_on_fd(tty_fd, &reg_fields, cancel_fd).await?;
        cred_map.extend(reg_extra);

        state
            .auth_provider_inner(provider_id, cred_map.clone())
            .await
            .map_err(|e| anyhow!("registration failed for '{provider_id}': {e}"))?;
    } else if let Some(result) = auth_result {
        result.map_err(|e| anyhow!("auth failed for '{provider_id}': {e}"))?;
    }

    // Extract the password value for the caller before dropping cred_map.
    let pw_field_id = {
        let b = state
            .provider_by_id(provider_id)
            .ok_or_else(|| anyhow!("provider '{provider_id}' not found"))?;
        b.password_field().id.to_string()
    };
    let password = cred_map
        .get(&pw_field_id)
        .cloned()
        .unwrap_or_else(|| Zeroizing::new(String::new()));

    // cred_map is dropped here; all Zeroizing<String> values are scrubbed.
    drop(cred_map);

    info!(provider = %provider_id, "provider authenticated via AuthProviderWithTty");
    Ok(password)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Collect auth field descriptors for a provider into `TtyField` structs.
pub(crate) fn provider_auth_fields(provider: &dyn rosec_core::Provider) -> Vec<TtyField> {
    let pw = provider.password_field();
    let pw_id = pw.id;
    let mut fields = vec![TtyField {
        id: pw.id.to_string(),
        label: pw.label.to_string(),
        kind: pw.kind.to_string(),
        placeholder: pw.placeholder.to_string(),
    }];
    // Exclude any auth_fields entry that duplicates the password field
    // (a guest might mistakenly include it).
    fields.extend(
        provider
            .auth_fields()
            .iter()
            .filter(|f| f.id != pw_id)
            .map(|f| TtyField {
                id: f.id.to_string(),
                label: f.label.to_string(),
                kind: f.kind.to_string(),
                placeholder: f.placeholder.to_string(),
            }),
    );
    fields
}

/// Write a string to the fd (best-effort; errors are silently ignored since
/// this is informational output, not credential data).
fn print_on_fd(fd: RawFd, s: &str) {
    let bytes = s.as_bytes();
    unsafe {
        libc::write(fd, bytes.as_ptr().cast(), bytes.len());
    }
}
