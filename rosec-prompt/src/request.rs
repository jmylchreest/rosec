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

/// One selectable row in a selection prompt.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SelectOption {
    /// Opaque handle returned as `{"selected": id}` when this row is chosen.
    pub(crate) id: String,
    /// Primary line (e.g. `alice@github.com`).
    pub(crate) primary: String,
    /// Optional secondary line (e.g. the source provider name).
    #[serde(default)]
    pub(crate) secondary: String,
}

/// When present, the prompt shows a single-select scrollable list instead of
/// input fields. Used to disambiguate multiple matches (e.g. several passkeys
/// for one relying party). Choosing a row is the confirmation gesture.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SelectRequest {
    pub(crate) options: Vec<SelectOption>,
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
    #[serde(default)]
    pub(crate) confirm_label: String,
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
    /// When set, show a single-select scrollable list instead of input
    /// fields. Output is `{"selected": "<option id>"}`; cancel exits 1.
    #[serde(default)]
    pub(crate) select: Option<SelectRequest>,
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
        let t = theme_defaults();
        Self {
            background: t.background.clone(),
            foreground: t.foreground.clone(),
            border_color: t.border_color.clone(),
            border_width: t.border_width as f32,
            font_family: t.font_family.clone(),
            label_color: t.label_color.clone(),
            accent_color: t.accent_color.clone(),
            confirm_background: String::new(),
            confirm_text: String::new(),
            cancel_background: String::new(),
            cancel_text: String::new(),
            input_background: t.input_background.clone(),
            input_text: t.input_text.clone(),
            font_size: t.font_size as f32,
        }
    }
}

// Default helpers — pluck values from a single cached `PromptTheme` so
// the daemon's config defaults flow through and we don't reconstruct the
// theme struct on every field deserialization.
fn theme_defaults() -> &'static PromptTheme {
    static T: std::sync::LazyLock<PromptTheme> = std::sync::LazyLock::new(PromptTheme::default);
    &T
}
fn default_background() -> String {
    theme_defaults().background.clone()
}
fn default_foreground() -> String {
    theme_defaults().foreground.clone()
}
fn default_border() -> String {
    theme_defaults().border_color.clone()
}
fn default_border_width() -> f32 {
    theme_defaults().border_width as f32
}
fn default_font() -> String {
    theme_defaults().font_family.clone()
}
fn default_label_color() -> String {
    theme_defaults().label_color.clone()
}
fn default_accent_color() -> String {
    theme_defaults().accent_color.clone()
}
fn default_input_bg() -> String {
    theme_defaults().input_background.clone()
}
fn default_input_text() -> String {
    theme_defaults().input_text.clone()
}
fn default_font_size() -> f32 {
    theme_defaults().font_size as f32
}

#[cfg(test)]
mod select_tests {
    use super::*;

    #[test]
    fn parses_selection_request() {
        let raw = r#"{
            "title": "Choose a passkey",
            "message": "Sign in to github.com",
            "select": {
                "options": [
                    {"id": "a", "primary": "alice@github.com", "secondary": "bitwarden"},
                    {"id": "b", "primary": "bob@github.com"}
                ]
            }
        }"#;
        let req: PromptRequest = serde_json::from_str(raw).unwrap();
        let select = req.select.expect("select present");
        assert_eq!(select.options.len(), 2);
        assert_eq!(select.options[0].id, "a");
        assert_eq!(select.options[0].secondary, "bitwarden");
        // secondary defaults to empty when omitted
        assert_eq!(select.options[1].secondary, "");
    }

    #[test]
    fn absent_select_is_none() {
        let req: PromptRequest = serde_json::from_str(r#"{"title": "x"}"#).unwrap();
        assert!(req.select.is_none());
    }
}
