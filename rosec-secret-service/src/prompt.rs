use zbus::interface;
use zbus::object_server::SignalContext;

pub struct SecretPrompt {
    pub path: String,
}

impl SecretPrompt {
    pub fn new(path: String) -> Self {
        Self { path }
    }
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl SecretPrompt {
    /// Perform the prompt. In rosec, the actual prompting is handled
    /// by `ensure_unlocked()` in the service layer — this stub emits
    /// `Completed` immediately since the unlock has already occurred.
    async fn prompt(
        &mut self,
        _window_id: &str,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
    ) -> zbus::fdo::Result<()> {
        // Emit Completed(dismissed=false, result=empty string)
        Self::completed(&ctxt, false, &zvariant::Value::from("")).await
            .map_err(|e| zbus::fdo::Error::Failed(format!("signal emit: {e}")))?;
        Ok(())
    }

    async fn dismiss(
        &self,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
    ) -> zbus::fdo::Result<()> {
        Self::completed(&ctxt, true, &zvariant::Value::from("")).await
            .map_err(|e| zbus::fdo::Error::Failed(format!("signal emit: {e}")))?;
        Ok(())
    }

    /// Signal emitted when the prompt completes or is dismissed.
    #[zbus(signal)]
    async fn completed(
        ctxt: &SignalContext<'_>,
        dismissed: bool,
        result: &zvariant::Value<'_>,
    ) -> zbus::Result<()>;
}
