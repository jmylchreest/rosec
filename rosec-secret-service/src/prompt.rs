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

use zbus::interface;
use zbus::object_server::SignalEmitter;
use zeroize::Zeroizing;

use crate::state::{ServiceState, map_backend_error};
use rosec_core::UnlockInput;

pub struct SecretPrompt {
    pub path: String,
    /// The backend that needs to be unlocked when `Prompt()` is called.
    pub backend_id: String,
    pub state: Arc<ServiceState>,
}

impl SecretPrompt {
    pub fn new(path: String, backend_id: String, state: Arc<ServiceState>) -> Self {
        Self {
            path,
            backend_id,
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
        let state = Arc::clone(&self.state);
        let prompt_path = self.path.clone();
        let backend_id = self.backend_id.clone();

        // Determine a human-readable label for the prompt dialog.
        let label = state
            .backend_by_id(&backend_id)
            .map(|b| format!("Unlock {}", b.name()))
            .unwrap_or_else(|| format!("Unlock {backend_id}"));

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
                    run_prompt_task(state2, prompt_path, backend_id, label, ctxt_owned).await;
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
    backend_id: String,
    label: String,
    ctxt: SignalEmitter<'static>,
) {
    // Inline helper: emit Completed(dismissed=true).
    async fn emit_dismissed(ctxt: &SignalEmitter<'_>) {
        if let Err(e) = SecretPrompt::completed(ctxt, true, &zvariant::Value::from("")).await {
            tracing::debug!(error = %e, "failed to emit Completed(dismissed)");
        }
    }

    // Collect credentials via spawn_blocking (blocks on subprocess I/O).
    let state2 = Arc::clone(&state);
    let prompt_path2 = prompt_path.clone();
    let backend_id2 = backend_id.clone();
    let label2 = label.clone();

    let password_result: Result<Zeroizing<String>, zbus::fdo::Error> =
        match tokio::task::spawn_blocking(move || {
            state2.spawn_prompt(&prompt_path2, &backend_id2, &label2)
        })
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "prompt task panicked");
                state.finish_prompt(&prompt_path);
                emit_dismissed(&ctxt).await;
                return;
            }
        };

    match password_result {
        Err(e) => {
            tracing::debug!(backend = %backend_id, error = %e, "prompt dismissed or failed");
            state.finish_prompt(&prompt_path);
            emit_dismissed(&ctxt).await;
        }
        Ok(password) => {
            // Perform the actual backend unlock — password never leaves this process.
            let Some(backend) = state.backend_by_id(&backend_id) else {
                tracing::warn!(backend = %backend_id, "backend not found after prompt");
                state.finish_prompt(&prompt_path);
                emit_dismissed(&ctxt).await;
                return;
            };

            let unlock_result = backend
                .unlock(UnlockInput::Password(password))
                .await
                .map_err(map_backend_error);

            state.finish_prompt(&prompt_path);

            match unlock_result {
                Ok(()) => {
                    state.mark_backend_unlocked(&backend_id);
                    state.touch_activity();

                    // Trigger a cache sync immediately so items are visible
                    // without waiting for the background poller.
                    let state3 = Arc::clone(&state);
                    let bid = backend_id.clone();
                    if let Err(e) = state3.sync_backend(&bid).await {
                        tracing::debug!(backend = %bid, error = %e,
                            "post-unlock sync failed (non-fatal)");
                    }

                    tracing::debug!(backend = %backend_id, "backend unlocked via Prompt");

                    let collection =
                        zvariant::Value::from("/org/freedesktop/secrets/collection/default");
                    if let Err(e) = SecretPrompt::completed(&ctxt, false, &collection).await {
                        tracing::warn!(error = %e, "failed to emit Completed(unlocked)");
                    }
                }
                Err(e) => {
                    tracing::warn!(backend = %backend_id, error = %e,
                        "unlock failed after prompt");
                    emit_dismissed(&ctxt).await;
                }
            }
        }
    }
}
