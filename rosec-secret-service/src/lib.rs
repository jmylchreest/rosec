use std::io::Write;
use std::process::Stdio;

use rosec_core::BackendError;
use rosec_core::config::PromptTheme;
use rosec_core::prompt::{PromptContext, render_args};
use serde::Serialize;

pub mod collection;
pub mod crypto;
pub mod daemon;
pub mod item;
pub mod prompt;
pub mod server;
pub mod service;
pub mod session;
pub mod session_iface;

pub use service::SecretService;

/// JSON payload piped to the prompt subprocess on stdin.
///
/// Must match the `PromptRequest` struct in `rosec-prompt`.
#[derive(Serialize)]
struct PromptRequest<'a> {
    #[serde(rename = "t")]
    title: &'a str,
    #[serde(rename = "m")]
    message: &'a str,
    #[serde(rename = "h")]
    hint: &'a str,
    backend: &'a str,
    theme: PromptThemePayload<'a>,
}

/// Subset of theme config serialized to the prompt.
#[derive(Serialize)]
struct PromptThemePayload<'a> {
    #[serde(rename = "bg")]
    background: &'a str,
    #[serde(rename = "fg")]
    foreground: &'a str,
    #[serde(rename = "bdr")]
    border_color: &'a str,
    #[serde(rename = "bw")]
    border_width: u16,
    #[serde(rename = "font")]
    font_family: &'a str,
    #[serde(rename = "lc")]
    label_color: &'a str,
    #[serde(rename = "ac")]
    accent_color: &'a str,
    #[serde(rename = "ybg")]
    confirm_background: &'a str,
    #[serde(rename = "yt")]
    confirm_text: &'a str,
    #[serde(rename = "nbg")]
    cancel_background: &'a str,
    #[serde(rename = "nt")]
    cancel_text: &'a str,
    #[serde(rename = "ibg")]
    input_background: &'a str,
    #[serde(rename = "it")]
    input_text: &'a str,
    #[serde(rename = "size")]
    font_size: u16,
}

pub struct PromptLauncher {
    pub program: String,
    pub args: Vec<String>,
    pub theme: PromptTheme,
}

impl PromptLauncher {
    pub fn new(program: String, args: Vec<String>, theme: PromptTheme) -> Self {
        Self { program, args, theme }
    }

    pub fn prompt(&self, context: PromptContext) -> Result<String, BackendError> {
        let rendered = render_args(&self.args, &context);

        let request = PromptRequest {
            title: &context.title,
            message: &context.message,
            hint: &context.hint,
            backend: &context.backend,
            theme: PromptThemePayload {
                background: &self.theme.background,
                foreground: &self.theme.foreground,
                border_color: &self.theme.border_color,
                border_width: self.theme.border_width,
                font_family: &self.theme.font_family,
                label_color: &self.theme.label_color,
                accent_color: &self.theme.accent_color,
                confirm_background: &self.theme.confirm_background,
                confirm_text: &self.theme.confirm_text,
                cancel_background: &self.theme.cancel_background,
                cancel_text: &self.theme.cancel_text,
                input_background: &self.theme.input_background,
                input_text: &self.theme.input_text,
                font_size: self.theme.font_size,
            },
        };

        let json = serde_json::to_string(&request)
            .map_err(|e| BackendError::Unavailable(format!("failed to serialize prompt: {e}")))?;

        let mut child = std::process::Command::new(&self.program)
            .args(rendered)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| BackendError::Unavailable(format!("failed to launch prompt: {err}")))?;

        // Write JSON to stdin then close it
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(json.as_bytes()).map_err(|e| {
                BackendError::Unavailable(format!("failed to write to prompt stdin: {e}"))
            })?;
            // stdin is dropped here, closing the pipe
        }

        let output = child
            .wait_with_output()
            .map_err(|err| BackendError::Unavailable(format!("failed to wait for prompt: {err}")))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return Ok(stdout);
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(BackendError::Unavailable(format!(
            "prompt failed: exit={:?} stderr={stderr}",
            output.status.code()
        )))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn opens_plain_session() {
        let sessions = std::sync::Arc::new(crate::session::SessionManager::new());
        let (output, path) = match sessions.open_session("plain") {
            Ok(result) => result,
            Err(err) => panic!("open session failed: {err}"),
        };
        let _ = output;
        assert!(path.contains("/org/freedesktop/secrets/session/"));
        // Verify the session is tracked
        assert!(sessions.is_valid(&path).unwrap_or(false));
    }
}
