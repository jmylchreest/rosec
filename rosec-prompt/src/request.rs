//! Wire types for the JSON request consumed on stdin.

use rosec_core::config::PromptTheme;
use serde::Deserialize;

/// The kind of a prompt field — mirrors `rosec_core::AuthFieldKind`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum FieldKind {
    Text,
    #[default]
    Password,
    Secret,
}

/// A single field descriptor from the JSON request.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct FieldSpec {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) label: String,
    #[serde(default)]
    pub(crate) kind: FieldKind,
    #[serde(default)]
    pub(crate) placeholder: String,
}

/// When present in a `PromptRequest`, the prompt shows a TOTP code display
/// instead of the normal input fields.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TotpDisplayRequest {
    /// The current TOTP code to display.
    pub(crate) code: String,
    /// Seconds remaining before the code expires.
    pub(crate) remaining: u32,
    /// TOTP period in seconds (kept for protocol compat, not used internally).
    #[allow(dead_code)]
    pub(crate) period: u32,
    /// When set, show a confirm/cancel dialog instead of copy/close.
    /// The value is used as the confirm button label (e.g. "Save").
    /// Disables auto-copy and auto-dismiss.
    #[serde(default)]
    pub(crate) confirm: Option<String>,
    /// Raw TOTP seed (otpauth URI or base32). When present, the prompter
    /// regenerates codes locally when the period expires.
    #[serde(default)]
    pub(crate) seed: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct PromptRequest {
    #[serde(alias = "t", default)]
    pub(crate) title: String,
    #[serde(alias = "m", alias = "msg", default)]
    pub(crate) message: String,
    #[serde(alias = "h", alias = "hint", default)]
    pub(crate) hint: String,
    #[serde(default)]
    pub(crate) backend: String,
    /// Label for the confirm button. Defaults to "Unlock".
    #[serde(default)]
    pub(crate) confirm_label: String,
    /// Label for the cancel button. Defaults to "Cancel".
    #[serde(default)]
    pub(crate) cancel_label: String,
    /// Field list.  When absent a single hidden `password` field is implied
    /// (unless `confirm_mode` is set).
    #[serde(default)]
    pub(crate) fields: Vec<FieldSpec>,
    /// When `true`, this is a zero-field confirmation dialog: the prompt
    /// shows only title + message + confirm/cancel buttons (no input fields).
    /// Exit code 0 = confirmed, 1 = cancelled.  Stdout is `{}`.
    #[serde(default)]
    pub(crate) confirm_mode: bool,
    /// Rich-text info line shown below the title (e.g. caller identification).
    /// Supports `**bold**` and `_italic_` markers for styled rendering.
    #[serde(default)]
    pub(crate) info: String,
    /// When set, display a TOTP code instead of input fields.
    #[serde(default)]
    pub(crate) totp_display: Option<TotpDisplayRequest>,
    /// When `true`, enter QR scan mode: show a compact window with a "Scan"
    /// button that captures the screen and decodes a QR code containing an
    /// `otpauth://` URI.
    #[serde(default)]
    pub(crate) qr_scan: bool,
    #[serde(default)]
    pub(crate) theme: ThemeConfig,
}

impl PromptRequest {
    /// Return the effective field list, inserting the default if none were given.
    ///
    /// In `confirm_mode`, fields are always empty — the dialog is purely
    /// confirm / cancel with no input collection.
    pub(crate) fn effective_fields(&self) -> Vec<FieldSpec> {
        if self.confirm_mode {
            Vec::new()
        } else if self.fields.is_empty() {
            vec![FieldSpec {
                id: "password".to_string(),
                label: "Password".to_string(),
                kind: FieldKind::Password,
                placeholder: String::new(),
            }]
        } else {
            self.fields.clone()
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ThemeConfig {
    #[serde(default = "default_background", alias = "bg")]
    pub(crate) background: String,
    #[serde(default = "default_foreground", alias = "fg")]
    pub(crate) foreground: String,
    #[serde(default = "default_border", alias = "bdr", alias = "bd")]
    pub(crate) border_color: String,
    #[serde(default = "default_border_width", alias = "bw")]
    pub(crate) border_width: f32,
    #[serde(default = "default_font", alias = "font")]
    pub(crate) font_family: String,
    #[serde(default = "default_label_color", alias = "lc")]
    pub(crate) label_color: String,
    #[serde(default = "default_accent_color", alias = "ac")]
    pub(crate) accent_color: String,
    #[serde(default, alias = "ybg")]
    pub(crate) confirm_background: String,
    #[serde(default, alias = "yt")]
    pub(crate) confirm_text: String,
    #[serde(default, alias = "nbg")]
    pub(crate) cancel_background: String,
    #[serde(default, alias = "nt")]
    pub(crate) cancel_text: String,
    #[serde(default = "default_input_bg", alias = "ibg")]
    pub(crate) input_background: String,
    #[serde(default = "default_input_text", alias = "it")]
    pub(crate) input_text: String,
    #[serde(default = "default_font_size", alias = "size")]
    pub(crate) font_size: f32,
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self {
            background: default_background(),
            foreground: default_foreground(),
            border_color: default_border(),
            border_width: default_border_width(),
            font_family: default_font(),
            label_color: default_label_color(),
            accent_color: default_accent_color(),
            confirm_background: String::new(),
            confirm_text: String::new(),
            cancel_background: String::new(),
            cancel_text: String::new(),
            input_background: default_input_bg(),
            input_text: default_input_text(),
            font_size: default_font_size(),
        }
    }
}

// Default helpers — delegate to rosec_core::config::PromptTheme so values
// stay in sync with the daemon's config defaults automatically.
fn default_background() -> String {
    PromptTheme::default().background
}
fn default_foreground() -> String {
    PromptTheme::default().foreground
}
fn default_border() -> String {
    PromptTheme::default().border_color
}
fn default_border_width() -> f32 {
    PromptTheme::default().border_width as f32
}
fn default_font() -> String {
    PromptTheme::default().font_family
}
fn default_label_color() -> String {
    PromptTheme::default().label_color
}
fn default_accent_color() -> String {
    PromptTheme::default().accent_color
}
fn default_input_bg() -> String {
    PromptTheme::default().input_background
}
fn default_input_text() -> String {
    PromptTheme::default().input_text
}
fn default_font_size() -> f32 {
    PromptTheme::default().font_size as f32
}
