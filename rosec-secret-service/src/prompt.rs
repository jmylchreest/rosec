//! `org.freedesktop.Secret.Prompt` implementation.
//!
//! The Secret Service spec requires that interactive operations (e.g. unlocking
//! a collection) return a Prompt object path rather than blocking the method
//! call.  The client then calls `Prompt()` on that object; the *service* is
//! responsible for displaying the password dialog and completing the unlock.
//! The `Completed` signal is emitted when the prompt finishes or is dismissed.
//!
//! This keeps credentials entirely inside rosecd — nothing crosses D-Bus.

use std::sync::Arc;

use rosec_core::{ItemMeta, NewItem};
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zeroize::Zeroizing;

use std::collections::HashMap;

use crate::service::to_object_path;
use crate::state::{ServiceState, make_item_path};

/// A deferred operation to execute after a successful unlock prompt.
///
/// When `CreateItem` or `Delete` is called on a locked collection/item, we
/// cannot execute the operation immediately.  Instead we stash the operation
/// details here, return a Prompt to the client, and execute the operation
/// after the prompt (unlock) succeeds.
#[derive(Debug)]
pub enum PendingOperation {
    /// Standard unlock-only prompt (no deferred operation).
    Unlock,

    /// Deferred `CreateItem`: execute `provider.create_item()` after unlock.
    CreateItem {
        provider_id: String,
        item: NewItem,
        replace: bool,
    },

    /// Deferred `Item.Delete`: execute `provider.delete_item()` after unlock.
    DeleteItem {
        provider_id: String,
        item_id: String,
        item_path: String,
    },
}

pub struct SecretPrompt {
    pub path: String,
    /// The provider that needs to be unlocked when `Prompt()` is called.
    pub provider_id: String,
    pub state: Arc<ServiceState>,
}

impl SecretPrompt {
    pub fn new(path: String, provider_id: String, state: Arc<ServiceState>) -> Self {
        Self {
            path,
            provider_id,
            state,
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl SecretPrompt {
    /// Display the credential prompt, perform the unlock, and emit `Completed`.
    ///
    /// Per the Secret Service spec this method returns immediately — the client
    /// waits for the `Completed` signal rather than blocking on the reply.  The
    /// credential collection and unlock happen on a background Tokio task so the
    /// D-Bus executor is never stalled.
    ///
    /// `window_id` is a hint from the client to parent the dialog to their
    /// window.  We pass it to `rosec-prompt` but otherwise ignore it for
    /// the TTY and SSH_ASKPASS paths.
    ///
    /// On success: emits `Completed(dismissed=false, result=[collection_path])`.
    /// On cancel or error: emits `Completed(dismissed=true, result="")`.
    async fn prompt(
        &mut self,
        _window_id: &str,
        #[zbus(signal_emitter)] ctxt: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        tracing::debug!(
            prompt_path = %self.path,
            provider = %self.provider_id,
            window_id = %_window_id,
            "Prompt() called by client"
        );
        let state = Arc::clone(&self.state);
        let prompt_path = self.path.clone();
        let provider_id = self.provider_id.clone();

        // Determine a human-readable label for the prompt dialog.
        let label = state
            .provider_by_id(&provider_id)
            .map(|b| format!("Unlock {}", b.name()))
            .unwrap_or_else(|| format!("Unlock {provider_id}"));

        // Spawn the entire credential-collection + unlock sequence as a
        // background task.  The method returns immediately; the client waits
        // for the Completed signal.  This also means that if the client
        // disconnects (Ctrl+C, SIGKILL, normal exit) the spawn_blocking task
        // is still running — but cancel_prompt() sends SIGTERM to the child
        // so the window disappears when the client calls CancelPrompt or
        // when the Prompt object is dropped (via Dismiss).
        let ctxt_owned = ctxt.to_owned();
        let state2 = Arc::clone(&state);
        state
            .run_on_tokio(async move {
                tokio::spawn(async move {
                    run_prompt_task(state2, prompt_path, provider_id, label, ctxt_owned).await;
                });
            })
            .await?;

        Ok(())
    }

    /// Dismiss the prompt (cancel).  Kills the child subprocess if still running.
    async fn dismiss(
        &self,
        #[zbus(signal_emitter)] ctxt: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        self.state.cancel_prompt(&self.path);
        // Dismissed result is an empty string per the Secret Service spec.
        Self::completed(&ctxt, true, &zvariant::Value::from(""))
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("signal: {e}")))?;
        Ok(())
    }

    /// Emitted when the prompt completes (dismissed=false) or is cancelled (dismissed=true).
    ///
    /// `result` for a successful collection unlock is the collection object path.
    #[zbus(signal)]
    pub async fn completed(
        ctxt: &SignalEmitter<'_>,
        dismissed: bool,
        result: &zvariant::Value<'_>,
    ) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// Background task: credential collection + unlock + Completed signal
// ---------------------------------------------------------------------------

/// Runs on a Tokio task spawned by `Prompt.prompt()`.  Returns immediately
/// (fire-and-forget) so the D-Bus method reply is sent before any blocking I/O.
async fn run_prompt_task(
    state: Arc<ServiceState>,
    prompt_path: String,
    provider_id: String,
    label: String,
    ctxt: SignalEmitter<'static>,
) {
    /// Maximum number of unlock attempts before giving up.
    const MAX_ATTEMPTS: u32 = 3;

    // Inline helper: emit Completed(dismissed=true) and then clean up the
    // prompt object.  The signal MUST be emitted before the object is
    // deregistered so that D-Bus clients receive it.
    async fn dismiss_and_finish(state: &ServiceState, prompt_path: &str, ctxt: &SignalEmitter<'_>) {
        if let Err(e) = SecretPrompt::completed(ctxt, true, &zvariant::Value::from("")).await {
            tracing::debug!(error = %e, "failed to emit Completed(dismissed)");
        }
        state.finish_prompt(prompt_path);
    }

    // ── Prompt serialization (gnome-keyring unlock_prompt_queue pattern) ──
    //
    // Acquire a per-provider mutex so that only one prompt GUI subprocess runs
    // at a time.  If another client's prompt is already in progress for this
    // provider, we wait for it to finish.  When we acquire the lock, we check
    // whether the provider is still locked — if the first prompt succeeded,
    // we emit Completed(success) immediately without showing a second dialog.
    let prompt_mutex = state.prompt_mutex_for(&provider_id);
    let _prompt_guard = prompt_mutex.lock().await;

    // Check if the provider was unlocked while we waited in the queue.
    let already_unlocked = match state.provider_by_id(&provider_id) {
        Some(p) => p.status().await.map(|s| !s.locked).unwrap_or(false),
        None => false,
    };
    if already_unlocked {
        tracing::debug!(
            provider = %provider_id,
            "provider already unlocked by another prompt — skipping"
        );
        // Delegate to on_unlock_success so that any deferred operation
        // (CreateItem / DeleteItem) stashed by this prompt is still executed,
        // the cache is synced, and the Completed signal is emitted.  The empty
        // password is harmless — opportunistic_sweep with an empty string
        // won't unlock anything.
        on_unlock_success(
            &state,
            &prompt_path,
            &provider_id,
            Zeroizing::new(String::new()),
            &ctxt,
        )
        .await;
        return;
    }

    let mut attempt = 0u32;

    tracing::debug!(provider = %provider_id, %label, "run_prompt_task started");

    loop {
        attempt += 1;

        // Collect credentials via spawn_blocking (blocks on subprocess I/O).
        let state2 = Arc::clone(&state);
        let prompt_path2 = prompt_path.clone();
        let provider_id2 = provider_id.clone();
        let label2 = if attempt == 1 {
            label.clone()
        } else {
            format!("{label} (wrong password, attempt {attempt}/{MAX_ATTEMPTS})")
        };

        let password_result: Result<Zeroizing<String>, zbus::fdo::Error> =
            match tokio::task::spawn_blocking(move || {
                state2.spawn_prompt(&prompt_path2, &provider_id2, &label2)
            })
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "prompt task panicked");
                    dismiss_and_finish(&state, &prompt_path, &ctxt).await;
                    return;
                }
            };

        let password = match password_result {
            Err(e) => {
                // User cancelled or prompt failed — stop immediately, no retry.
                tracing::debug!(provider = %provider_id, error = %e, "prompt dismissed or failed");
                dismiss_and_finish(&state, &prompt_path, &ctxt).await;
                return;
            }
            Ok(pw) => pw,
        };

        // Perform the actual provider unlock — password never leaves this process.
        let Some(provider) = state.provider_by_id(&provider_id) else {
            tracing::warn!(provider = %provider_id, "provider not found after prompt");
            dismiss_and_finish(&state, &prompt_path, &ctxt).await;
            return;
        };

        // Clone the password before the unlock consumes it — we need it for
        // the 2FA retry and the opportunistic sweep.
        let password_for_sweep = password.clone();

        // Use auth_provider so we can match on typed ProviderError
        // variants (especially TwoFactorRequired with its methods list).
        let pw_field_id = provider.password_field().id.to_string();
        let mut fields: HashMap<String, Zeroizing<String>> = HashMap::new();
        fields.insert(pw_field_id.clone(), password);

        let unlock_result = state.try_auth_provider(&provider_id, fields).await;

        match unlock_result {
            Ok(()) => {
                // Unlock succeeded — finish prompt and proceed.
                on_unlock_success(
                    &state,
                    &prompt_path,
                    &provider_id,
                    password_for_sweep,
                    &ctxt,
                )
                .await;
                return;
            }
            Err(rosec_core::ProviderError::TwoFactorRequired { methods }) => {
                // ── 2FA required — launch a second prompt for the token ──
                tracing::debug!(
                    provider = %provider_id,
                    "two-factor authentication required, prompting for 2FA code"
                );
                let text_methods: Vec<_> =
                    methods.iter().filter(|m| m.prompt_kind == "text").collect();

                if text_methods.is_empty() {
                    tracing::warn!(
                        provider = %provider_id,
                        "2FA required but no supported text methods available"
                    );
                    dismiss_and_finish(&state, &prompt_path, &ctxt).await;
                    return;
                }

                // Build fields for the 2FA prompt.
                let mut two_fa_fields: Vec<serde_json::Value> = Vec::new();

                // If multiple methods, add a choice selector.
                let chosen_method_id = if text_methods.len() == 1 {
                    text_methods[0].id.clone()
                } else {
                    // Add a dropdown-style selector (rendered as text input
                    // by rosec-prompt — user types the number).
                    let options_label = text_methods
                        .iter()
                        .enumerate()
                        .map(|(i, m)| format!("[{}] {}", i + 1, m.label))
                        .collect::<Vec<_>>()
                        .join("  ");
                    two_fa_fields.push(serde_json::json!({
                        "id": "__2fa_choice",
                        "label": format!("Choose method: {options_label}"),
                        "kind": "text",
                        "placeholder": "1",
                    }));
                    String::new() // resolved after prompt response
                };

                // Add the token input field.  When there's a single method,
                // use its label (e.g. "Authenticator app (TOTP)") so the user
                // knows what kind of code is expected.
                let token_label = if text_methods.len() == 1 {
                    format!("{} code", text_methods[0].label)
                } else {
                    "Code".to_string()
                };
                two_fa_fields.push(serde_json::json!({
                    "id": "__2fa_token",
                    "label": token_label,
                    "kind": "secret",
                    "placeholder": "",
                }));

                // Launch the 2FA prompt via spawn_prompt_fields.
                let state_2fa = Arc::clone(&state);
                let prompt_path_2fa = prompt_path.clone();
                let provider_name = provider.name().to_string();
                let title_2fa = if provider_name.is_empty() || provider_name == provider_id {
                    format!("{provider_id} — two-factor authentication")
                } else {
                    format!("{provider_name} — two-factor authentication")
                };
                let fields_for_prompt = two_fa_fields.clone();

                let two_fa_result: Result<HashMap<String, Zeroizing<String>>, zbus::fdo::Error> =
                    match tokio::task::spawn_blocking(move || {
                        state_2fa.spawn_prompt_fields(
                            &prompt_path_2fa,
                            &title_2fa,
                            &fields_for_prompt,
                        )
                    })
                    .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!(error = %e, "2FA prompt task panicked");
                            dismiss_and_finish(&state, &prompt_path, &ctxt).await;
                            return;
                        }
                    };

                let two_fa_map = match two_fa_result {
                    Err(e) => {
                        tracing::debug!(
                            provider = %provider_id,
                            error = %e,
                            "2FA prompt dismissed or failed"
                        );
                        dismiss_and_finish(&state, &prompt_path, &ctxt).await;
                        return;
                    }
                    Ok(m) => m,
                };

                // Resolve the chosen 2FA method.
                let final_method_id = if chosen_method_id.is_empty() {
                    // Multiple methods — resolve from the choice field.
                    let choice_str = two_fa_map
                        .get("__2fa_choice")
                        .map(|v| v.as_str())
                        .unwrap_or("1");
                    let idx: usize = choice_str.parse::<usize>().unwrap_or(1).saturating_sub(1);
                    text_methods
                        .get(idx)
                        .map(|m| m.id.clone())
                        .unwrap_or_else(|| text_methods[0].id.clone())
                } else {
                    chosen_method_id
                };

                // Build the credential map with password + 2FA fields.
                let mut cred_map: HashMap<String, Zeroizing<String>> = HashMap::new();
                cred_map.insert(pw_field_id, password_for_sweep.clone());
                cred_map.insert(
                    "__2fa_method_id".to_string(),
                    Zeroizing::new(final_method_id),
                );
                if let Some(token_val) = two_fa_map.get("__2fa_token") {
                    cred_map.insert("__2fa_token".to_string(), token_val.clone());
                }

                // Retry authentication with 2FA.
                match state.try_auth_provider(&provider_id, cred_map).await {
                    Ok(()) => {
                        on_unlock_success(
                            &state,
                            &prompt_path,
                            &provider_id,
                            password_for_sweep,
                            &ctxt,
                        )
                        .await;
                        return;
                    }
                    Err(e) => {
                        tracing::warn!(
                            provider = %provider_id,
                            error = %e,
                            "2FA authentication failed"
                        );
                        dismiss_and_finish(&state, &prompt_path, &ctxt).await;
                        return;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    provider = %provider_id,
                    attempt,
                    max_attempts = MAX_ATTEMPTS,
                    error = %e,
                    "unlock failed after prompt (wrong password?)"
                );

                if attempt >= MAX_ATTEMPTS {
                    tracing::warn!(
                        provider = %provider_id,
                        "max unlock attempts reached, giving up"
                    );
                    dismiss_and_finish(&state, &prompt_path, &ctxt).await;
                    return;
                }

                // Loop around and re-prompt with a "wrong password" hint.
            }
        }
    }
}

/// Handle post-unlock success: sync, sweep, execute deferred operations, emit signal.
///
/// The `Completed` signal MUST be emitted while the prompt object is still
/// registered on the D-Bus object server.  `finish_prompt` (which deregisters
/// the object) is therefore called only *after* the signal has been sent.
async fn on_unlock_success(
    state: &Arc<ServiceState>,
    prompt_path: &str,
    provider_id: &str,
    password_for_sweep: Zeroizing<String>,
    ctxt: &SignalEmitter<'_>,
) {
    state.mark_provider_unlocked(provider_id);
    state.touch_activity();

    // Trigger a cache sync immediately so items are visible.
    {
        let state_sync = Arc::clone(state);
        let bid = provider_id.to_string();
        if let Err(e) = state_sync.sync_provider(&bid).await {
            tracing::debug!(provider = %bid, error = %e,
                "post-unlock sync failed (non-fatal)");
        }
    }

    tracing::debug!(provider = %provider_id, "provider unlocked via Prompt");

    // Opportunistic sweep: try the same password against all other locked
    // providers (detached — does not block the Completed signal).
    {
        let sweep_state = Arc::clone(state);
        let sweep_id = provider_id.to_string();
        tokio::spawn(async move {
            sweep_state
                .opportunistic_sweep(&password_for_sweep, &sweep_id)
                .await;
        });
    }

    // Execute any deferred operation that was stashed when the prompt was
    // created (e.g. CreateItem on a locked collection).
    let pending = state.take_pending_operation(prompt_path);
    let result_value = match pending {
        Some(PendingOperation::CreateItem {
            provider_id: pid,
            item,
            replace,
        }) => execute_deferred_create(state, &pid, item, replace).await,
        Some(PendingOperation::DeleteItem {
            provider_id: pid,
            item_id,
            item_path,
        }) => execute_deferred_delete(state, &pid, &item_id, &item_path).await,
        Some(PendingOperation::Unlock) | None => {
            // Plain unlock — return ao (array of object paths) of the
            // unlocked collection, per the Secret Service spec.
            Some(zvariant::Value::from(vec![to_object_path(
                "/org/freedesktop/secrets/collection/default",
            )]))
        }
    };

    // Emit the Completed signal while the prompt object is still registered.
    match result_value {
        Some(val) => {
            if let Err(e) = SecretPrompt::completed(ctxt, false, &val).await {
                tracing::warn!(error = %e, "failed to emit Completed(success)");
            }
        }
        None => {
            // Deferred operation failed after unlock — dismiss.
            if let Err(e) = SecretPrompt::completed(ctxt, true, &zvariant::Value::from("")).await {
                tracing::debug!(error = %e, "failed to emit Completed(dismissed)");
            }
        }
    }

    // Now that the signal has been sent, clean up the prompt object from the
    // D-Bus object server and internal registry.
    state.finish_prompt(prompt_path);
}

// ---------------------------------------------------------------------------
// Deferred operation executors
// ---------------------------------------------------------------------------

/// Execute a deferred `CreateItem` after successful unlock.
///
/// Returns `Some(item_object_path)` on success or `None` on failure.
/// The spec says the `Completed` signal's result for CreateItem should be the
/// new item's object path.
async fn execute_deferred_create(
    state: &Arc<ServiceState>,
    provider_id: &str,
    item: NewItem,
    replace: bool,
) -> Option<zvariant::Value<'static>> {
    let provider = state.provider_by_id(provider_id)?;
    let provider_for_spawn = Arc::clone(&provider);
    let item_clone = item.clone();
    let id = match state
        .run_on_tokio(async move { provider_for_spawn.create_item(item_clone, replace).await })
        .await
    {
        Ok(Ok(id)) => id,
        Ok(Err(e)) => {
            tracing::warn!(provider = %provider_id, error = %e,
                "deferred CreateItem failed after unlock");
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, "deferred CreateItem tokio task failed");
            return None;
        }
    };

    tracing::info!(item_id = %id, provider = %provider_id,
        "created item via deferred Prompt");

    let item_path = make_item_path(provider_id, &id);

    let meta = ItemMeta::from_new_item(id, provider_id.to_string(), &item);

    if let Err(e) = state.insert_created_item(&item_path, meta).await {
        tracing::warn!(error = %e, "failed to register deferred item in cache");
    }

    Some(zvariant::Value::from(to_object_path(&item_path)))
}

/// Execute a deferred `DeleteItem` after successful unlock.
///
/// Returns `Some(/)` on success or `None` on failure.
async fn execute_deferred_delete(
    state: &Arc<ServiceState>,
    provider_id: &str,
    item_id: &str,
    item_path: &str,
) -> Option<zvariant::Value<'static>> {
    let provider = state.provider_by_id(provider_id)?;
    let id = item_id.to_string();
    let provider_for_spawn = Arc::clone(&provider);
    match state
        .run_on_tokio(async move { provider_for_spawn.delete_item(&id).await })
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::warn!(provider = %provider_id, error = %e,
                "deferred DeleteItem failed after unlock");
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, "deferred DeleteItem tokio task failed");
            return None;
        }
    }

    tracing::info!(item_id = %item_id, provider = %provider_id,
        "deleted item via deferred Prompt");

    state.remove_deleted_item(item_path);

    Some(zvariant::Value::from(to_object_path("/")))
}
