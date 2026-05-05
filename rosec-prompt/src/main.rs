//! rosec-prompt — credential prompt subprocess.
//!
//! # Protocol
//!
//! **stdin**: a single JSON object:
//! ```json
//! {
//!   "t": "Unlock provider",
//!   "m": "Enter credentials",
//!   "h": "Backend: my-vault",
//!   "backend": "my-vault",
//!   "fields": [
//!     {"id": "password", "label": "Master Password", "kind": "password", "placeholder": "…"},
//!     {"id": "email",    "label": "Email",           "kind": "text",     "placeholder": "…"}
//!   ],
//!   "info": "Requested by **firefox** (PID 1234)",
//!   "theme": { … }
//! }
//! ```
//! `fields` is optional — if absent a single hidden `password` field is implied.
//!
//! ## Rich text
//!
//! The `info`, `message`, and `hint` fields support inline markup:
//! `**bold**` and `_italic_` (word-boundary delimited).  Useful for
//! highlighting process names or paths in the caller identification line.
//!
//! ## Confirmation mode
//!
//! Set `"confirm_mode": true` for a zero-field confirmation dialog.  The prompt
//! shows only the title, message, and confirm / cancel buttons — no input fields.
//! Stdout is `{}` on confirmation.
//!
//! **stdout**: a single JSON object mapping field IDs to values:
//! ```json
//! {"password": "hunter2"}
//! ```
//!
//! **Exit codes**: 0 = confirmed, 1 = cancelled, 2 = bad input.
//!
//! # Display mode
//!
//! If `WAYLAND_DISPLAY` or `DISPLAY` is set, the iced Wayland GUI is used.
//! Otherwise (SSH session, TTY, headless) each field is collected via
//! `rpassword` (hidden) or a plain `eprint!` + `read_line` (visible text).

mod helpers;

use std::collections::HashMap;
use std::io::{self, Read};
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::Result;
use iced::widget::text_input;
use rosec_core::config::PromptTheme;
use serde::Deserialize;
use zeroize::Zeroizing;

use helpers::*;

/// Stable ID for the first text input field so we can auto-focus it on startup.
static FIRST_FIELD_ID: LazyLock<text_input::Id> = LazyLock::new(text_input::Id::unique);

/// The kind of a prompt field — mirrors `rosec_core::AuthFieldKind`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum FieldKind {
    Text,
    #[default]
    Password,
    Secret,
}

/// A single field descriptor from the JSON request.
#[derive(Debug, Clone, Deserialize)]
struct FieldSpec {
    id: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    kind: FieldKind,
    #[serde(default)]
    placeholder: String,
}

/// When present in a `PromptRequest`, the prompt shows a TOTP code display
/// instead of the normal input fields.
#[derive(Debug, Clone, Deserialize)]
struct TotpDisplayRequest {
    /// The current TOTP code to display.
    code: String,
    /// Seconds remaining before the code expires.
    remaining: u32,
    /// TOTP period in seconds (kept for protocol compat, not used internally).
    #[allow(dead_code)]
    period: u32,
    /// When set, show a confirm/cancel dialog instead of copy/close.
    /// The value is used as the confirm button label (e.g. "Save").
    /// Disables auto-copy and auto-dismiss.
    #[serde(default)]
    confirm: Option<String>,
    /// Raw TOTP seed (otpauth URI or base32). When present, the prompter
    /// regenerates codes locally when the period expires.
    #[serde(default)]
    seed: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PromptRequest {
    #[serde(alias = "t", default)]
    title: String,
    #[serde(alias = "m", alias = "msg", default)]
    message: String,
    #[serde(alias = "h", alias = "hint", default)]
    hint: String,
    #[serde(default)]
    backend: String,
    /// Label for the confirm button. Defaults to "Unlock".
    #[serde(default)]
    confirm_label: String,
    /// Label for the cancel button. Defaults to "Cancel".
    #[serde(default)]
    cancel_label: String,
    /// Field list.  When absent a single hidden `password` field is implied
    /// (unless `confirm_mode` is set).
    #[serde(default)]
    fields: Vec<FieldSpec>,
    /// When `true`, this is a zero-field confirmation dialog: the prompt
    /// shows only title + message + confirm/cancel buttons (no input fields).
    /// Exit code 0 = confirmed, 1 = cancelled.  Stdout is `{}`.
    #[serde(default)]
    confirm_mode: bool,
    /// Rich-text info line shown below the title (e.g. caller identification).
    /// Supports `**bold**` and `_italic_` markers for styled rendering.
    #[serde(default)]
    info: String,
    /// When set, display a TOTP code instead of input fields.
    #[serde(default)]
    totp_display: Option<TotpDisplayRequest>,
    /// When `true`, enter QR scan mode: show a compact window with a "Scan"
    /// button that captures the screen and decodes a QR code containing an
    /// `otpauth://` URI.
    #[serde(default)]
    qr_scan: bool,
    #[serde(default)]
    theme: ThemeConfig,
}

impl PromptRequest {
    /// Return the effective field list, inserting the default if none were given.
    ///
    /// In `confirm_mode`, fields are always empty — the dialog is purely
    /// confirm / cancel with no input collection.
    fn effective_fields(&self) -> Vec<FieldSpec> {
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
struct ThemeConfig {
    #[serde(default = "default_background", alias = "bg")]
    background: String,
    #[serde(default = "default_foreground", alias = "fg")]
    foreground: String,
    #[serde(default = "default_border", alias = "bdr", alias = "bd")]
    border_color: String,
    #[serde(default = "default_border_width", alias = "bw")]
    border_width: f32,
    #[serde(default = "default_font", alias = "font")]
    font_family: String,
    #[serde(default = "default_label_color", alias = "lc")]
    label_color: String,
    #[serde(default = "default_accent_color", alias = "ac")]
    accent_color: String,
    #[serde(default, alias = "ybg")]
    confirm_background: String,
    #[serde(default, alias = "yt")]
    confirm_text: String,
    #[serde(default, alias = "nbg")]
    cancel_background: String,
    #[serde(default, alias = "nt")]
    cancel_text: String,
    #[serde(default = "default_input_bg", alias = "ibg")]
    input_background: String,
    #[serde(default = "default_input_text", alias = "it")]
    input_text: String,
    #[serde(default = "default_font_size", alias = "size")]
    font_size: f32,
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

fn main() -> Result<()> {
    // Internal screenshot helper — runs in a subprocess to avoid portal
    // D-Bus session reuse issues.  Pipes the PNG bytes back via stdout,
    // never lands on a parent-controlled disk path. Not user-facing.
    //
    // Detected BEFORE harden() because xdg-desktop-portal needs to read
    // /proc/<our-pid>/root for sandbox identification, and PR_SET_DUMPABLE=0
    // re-owns that to root. The helper applies its own staged hardening
    // around the portal call.
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() == 2 && args[1] == "--screenshot-helper" {
            run_screenshot_helper();
        }
    }

    // Full hardening for the prompt path. The helper above never reaches
    // here because run_screenshot_helper() returns `!`.
    rosec_core::process::harden();

    // Handle --version before anything else (no stdin read needed).
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!(
            "rosec-prompt {} ({})",
            env!("ROSEC_VERSION"),
            env!("ROSEC_GIT_SHA")
        );
        return Ok(());
    }

    tracing_subscriber::fmt().with_env_filter("warn").init();

    // Cap stdin so a misbehaving caller cannot drive us into unbounded
    // allocation by holding stdin open. 64 KiB covers the largest realistic
    // request (theme + many fields + info text) with comfortable headroom.
    const MAX_REQUEST: u64 = 64 * 1024;
    let mut raw = String::new();
    let stdin = io::stdin();
    stdin
        .lock()
        .take(MAX_REQUEST + 1)
        .read_to_string(&mut raw)?;
    if raw.len() as u64 > MAX_REQUEST {
        eprintln!("prompt request exceeds {MAX_REQUEST} bytes");
        std::process::exit(2);
    }

    let request: PromptRequest = if raw.trim().is_empty() {
        PromptRequest {
            title: "Unlock provider".to_string(),
            message: "Enter your credentials".to_string(),
            hint: String::new(),
            backend: String::new(),
            confirm_label: String::new(),
            cancel_label: String::new(),
            fields: Vec::new(),
            confirm_mode: false,
            info: String::new(),
            totp_display: None,
            qr_scan: false,
            theme: ThemeConfig::default(),
        }
    } else {
        match serde_json::from_str(&raw) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("invalid prompt request: {e}");
                std::process::exit(2);
            }
        }
    };

    // Choose display mode: GUI if a compositor is available, TTY otherwise.
    let has_display =
        std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();

    if has_display {
        run_gui(request)
    } else {
        run_tty(request)
    }
}

/// Collect credentials from a TTY using rpassword (hidden) or plain readline (text).
///
/// In confirm mode (zero fields), prints the title/message and asks for y/N
/// confirmation.  Exit 0 = confirmed, exit 1 = cancelled.
///
/// In TOTP display mode, prints the code and expiry to stderr, emits `{}`
/// to stdout, and exits immediately (no clipboard in TTY mode).
fn run_tty(request: PromptRequest) -> Result<()> {
    if request.qr_scan {
        eprintln!("QR scanning requires a display server");
        std::process::exit(1);
    }

    if let Some(totp) = &request.totp_display {
        if !request.title.is_empty() {
            eprintln!("{}", request.title);
        }
        eprintln!("{}", totp.code);
        eprintln!("Expires in {}s", totp.remaining);
        println!("{{}}");
        return Ok(());
    }

    let fields = request.effective_fields();

    if !request.title.is_empty() {
        eprintln!("{}", request.title);
    }
    if !request.message.is_empty() {
        eprintln!("{}", request.message);
    }
    if !request.hint.is_empty() {
        eprintln!("({})", request.hint);
    }
    eprintln!();

    // Confirm-only mode: no fields to collect.
    if fields.is_empty() {
        let confirm_label = if request.confirm_label.is_empty() {
            "OK"
        } else {
            &request.confirm_label
        };
        let cancel_label = if request.cancel_label.is_empty() {
            "Cancel"
        } else {
            &request.cancel_label
        };
        eprint!("{confirm_label} / {cancel_label} [y/N]: ");
        let mut buf = String::new();
        io::stdin()
            .read_line(&mut buf)
            .map_err(|e| anyhow::anyhow!("failed to read confirmation: {e}"))?;
        let answer = buf.trim().to_lowercase();
        if answer == "y" || answer == "yes" {
            println!("{{}}");
            return Ok(());
        }
        std::process::exit(1);
    }

    let mut values: HashMap<String, Zeroizing<String>> = HashMap::new();

    for field in &fields {
        let label = if field.label.is_empty() {
            field.id.as_str()
        } else {
            field.label.as_str()
        };
        let value: Zeroizing<String> = match field.kind {
            FieldKind::Password | FieldKind::Secret => {
                let prompt = format!("{label}: ");
                Zeroizing::new(
                    rpassword::prompt_password(&prompt)
                        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", field.id))?,
                )
            }
            FieldKind::Text => {
                eprint!("{label}: ");
                let mut buf = String::new();
                io::stdin()
                    .read_line(&mut buf)
                    .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", field.id))?;
                Zeroizing::new(buf.trim_end_matches(['\n', '\r']).to_string())
            }
        };
        values.insert(field.id.clone(), value);
    }

    // Emit JSON via the zeroizing-serialise path so the serialised bytes
    // (which contain password material) never live in a non-zeroizing
    // String allocation.
    let out: HashMap<&str, &str> = values
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    emit_secret_json(&out)?;
    Ok(())
}

/// Serialize `value` to JSON inside a `Zeroizing<Vec<u8>>` and write the
/// bytes directly to fd 1 (stdout) via `libc::write`, bypassing Rust's
/// stdout buffer so password / TOTP-seed material is never copied into a
/// userspace allocation that wouldn't be scrubbed on drop.
fn emit_secret_json<T: serde::Serialize>(value: &T) -> Result<()> {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(256));
    serde_json::to_writer(&mut *buf, value)?;
    buf.push(b'\n');
    let mut written = 0usize;
    while written < buf.len() {
        // SAFETY: fd 1 is always valid; ptr is from a live Vec; len is bounded.
        let n = unsafe {
            libc::write(
                1,
                buf.as_ptr().add(written) as *const _,
                buf.len() - written,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        written += n as usize;
    }
    Ok(())
}

fn run_gui(request: PromptRequest) -> Result<()> {
    use iced::window::settings::PlatformSpecific;

    if request.qr_scan {
        return run_gui_qr(request);
    }

    if request.totp_display.is_some() {
        return run_gui_totp(request);
    }

    use iced::application;

    let fields = request.effective_fields();
    let font_size = request.theme.font_size;

    let input_h = line_height(font_size) + 16.0; // text_input: padding(8) top+bottom + text
    let btn_h = line_height(font_size) + 16.0; // button: padding(8) top+bottom + text
    let content_w = content_width(420.0);

    let mut m = TextMeasurer::new(&request.theme, content_w);

    let title_h = m.title(&request.title);
    // Strip **bold** markers for measurement; leave _ alone since
    // word-boundary italic markers are rare and the width difference
    // between normal and italic glyphs is negligible for sizing.
    let info_h = m.body_small(&request.info.replace("**", ""));
    let msg_h = m.body(&request.message);

    // Sum per-field heights individually to account for label wrapping.
    let fields_total_h: f32 = fields
        .iter()
        .map(|f| {
            let label_text = if f.label.is_empty() { &f.id } else { &f.label };
            m.body_small(label_text) + 3.0 + input_h + 10.0
        })
        .sum();

    // Iced draws borders *inside* the container bounds, overlapping with the
    // padding — the border does not add extra height.  Only the two padding
    // layers contribute to vertical overhead.
    let height = (4.0 + 14.0) * 2.0                         // outer pad + inner pad (top+bottom)
        + title_h                                            // title (exact, may wrap)
        + 10.0                                               // spacing after title
        + info_h                                             // info line (0 if absent)
        + if info_h > 0.0 { 10.0 } else { 0.0 }             // spacing after info (only if present)
        + msg_h                                              // message (exact, 0 if absent)
        + if msg_h > 0.0 { 10.0 } else { 0.0 }              // spacing after message (only if present)
        + fields_total_h                                     // fields (label may wrap)
        + btn_h; // buttons row

    application("rosec prompt", update, view)
        .subscription(|_state| {
            // Use `event::listen_with` so we see *all* keyboard events,
            // including those that a focused text_input would otherwise
            // consume (e.g. Escape to unfocus).  `on_key_press` only
            // receives events with Status::Ignored, which means the
            // first Esc press is swallowed by the text input.
            iced::event::listen_with(|event, _status, _id| {
                if let iced::Event::Keyboard(iced::keyboard::Event::KeyPressed { key, .. }) = event
                {
                    Some(Message::KeyPressed(key))
                } else {
                    None
                }
            })
        })
        .window(iced::window::Settings {
            size: iced::Size::new(420.0, height),
            resizable: false,
            decorations: false,
            transparent: true,
            platform_specific: PlatformSpecific {
                application_id: "rosec.prompt".to_string(),
                override_redirect: false,
            },
            ..Default::default()
        })
        .run_with(|| {
            let has_fields = !fields.is_empty();
            let state = GuiApp::from_request(request, fields);
            // Focus the first text input on startup (no-op when there are no fields).
            let task = if has_fields {
                iced::widget::text_input::focus(FIRST_FIELD_ID.clone())
            } else {
                iced::Task::none()
            };
            (state, task)
        })?;
    Ok(())
}

#[derive(Debug, Clone)]
enum Message {
    FieldChanged(usize, String),
    Confirm,
    Cancel,
    KeyPressed(iced::keyboard::Key),
}

#[derive(Debug, Clone)]
enum TotpMessage {
    Tick,
    CopyToClipboard,
    AutoDismiss,
    KeyPressed(iced::keyboard::Key),
}

/// Per-field runtime state held by the GUI.
#[derive(Debug)]
struct FieldState {
    spec: FieldSpec,
    /// Current value — Zeroizing so it is scrubbed when overwritten or dropped.
    value: Zeroizing<String>,
}

#[derive(Debug)]
struct GuiApp {
    title: String,
    message: String,
    hint: String,
    info: String,
    confirm_label: String,
    cancel_label: String,
    fields: Vec<FieldState>,
    theme: ThemeConfig,
    // Pre-parsed colours (avoid re-parsing every frame)
    fg: iced::Color,
    bg: iced::Color,
    border: iced::Color,
    label_color: iced::Color,
    accent: iced::Color,
    confirm_bg: iced::Color,
    confirm_text: iced::Color,
    cancel_bg: iced::Color,
    cancel_text: iced::Color,
    input_bg: iced::Color,
    input_text: iced::Color,
    font: iced::Font,
}

impl GuiApp {
    fn from_request(req: PromptRequest, fields: Vec<FieldSpec>) -> Self {
        let fg = parse_color(&req.theme.foreground, iced::Color::WHITE);
        let bg = parse_color(&req.theme.background, iced::Color::BLACK);
        let border = parse_color(&req.theme.border_color, iced::Color::WHITE);
        let label_color = parse_color(&req.theme.label_color, fg);
        let accent = parse_color(&req.theme.accent_color, fg);
        let confirm_bg = if req.theme.confirm_background.trim().is_empty() {
            accent
        } else {
            parse_color(&req.theme.confirm_background, accent)
        };
        let confirm_text = if req.theme.confirm_text.trim().is_empty() {
            fg
        } else {
            parse_color(&req.theme.confirm_text, fg)
        };
        let cancel_bg = if req.theme.cancel_background.trim().is_empty() {
            // Default: neutral dark grey — clearly distinct from the accent-coloured confirm button.
            iced::Color::from_rgb(0.25, 0.25, 0.28)
        } else {
            parse_color(
                &req.theme.cancel_background,
                iced::Color::from_rgb(0.25, 0.25, 0.28),
            )
        };
        let cancel_text = if req.theme.cancel_text.trim().is_empty() {
            fg
        } else {
            parse_color(&req.theme.cancel_text, label_color)
        };
        let input_bg = parse_color(&req.theme.input_background, bg);
        let input_text = parse_color(&req.theme.input_text, fg);
        let font = font_from_string(&req.theme.font_family);
        let hint = if req.hint.trim().is_empty() && !req.backend.is_empty() {
            format!("Provider: {}", req.backend)
        } else {
            req.hint
        };
        let field_states = fields
            .into_iter()
            .map(|spec| FieldState {
                spec,
                value: Zeroizing::new(String::new()),
            })
            .collect();
        Self {
            title: req.title,
            message: req.message,
            hint,
            info: req.info,
            confirm_label: if req.confirm_label.is_empty() {
                "OK".to_string()
            } else {
                req.confirm_label
            },
            cancel_label: if req.cancel_label.is_empty() {
                "Cancel".to_string()
            } else {
                req.cancel_label
            },
            fields: field_states,
            theme: req.theme,
            fg,
            bg,
            border,
            label_color,
            accent,
            confirm_bg,
            confirm_text,
            cancel_bg,
            cancel_text,
            input_bg,
            input_text,
            font,
        }
    }
}

fn confirm_and_exit(state: &GuiApp) -> ! {
    let out: HashMap<&str, &str> = state
        .fields
        .iter()
        .map(|f| (f.spec.id.as_str(), f.value.as_str()))
        .collect();
    if let Err(e) = emit_secret_json(&out) {
        eprintln!("output emit error: {e}");
    }
    std::process::exit(0);
}

fn update(state: &mut GuiApp, message: Message) {
    match message {
        Message::FieldChanged(idx, value) => {
            if let Some(f) = state.fields.get_mut(idx) {
                // Old Zeroizing<String> is dropped here → scrubbed.
                f.value = Zeroizing::new(value);
            }
        }
        Message::Confirm => {
            confirm_and_exit(state);
        }
        Message::Cancel => std::process::exit(1),
        Message::KeyPressed(key) => {
            use iced::keyboard::Key;
            use iced::keyboard::key::Named;
            match key {
                Key::Named(Named::Enter) => confirm_and_exit(state),
                Key::Named(Named::Escape) => std::process::exit(1),
                _ => {}
            }
        }
    }
}

fn view(state: &GuiApp) -> iced::Element<'_, Message> {
    use iced::widget::{button, column, container, row, text, text_input};
    use iced::{Alignment, Background, Element, Length};

    let font_size = state.theme.font_size as u16;

    let title_widget: Element<'_, Message> = {
        let bold_font = iced::Font {
            weight: iced::font::Weight::Bold,
            ..state.font
        };
        let t = text(&state.title)
            .size(font_size + 1)
            .color(state.fg)
            .font(bold_font);
        if state.hint.trim().is_empty() {
            t.into()
        } else {
            iced::widget::tooltip(
                t,
                container(iced::widget::rich_text(parse_styled_spans(
                    &state.hint,
                    font_size,
                    state.label_color,
                    state.fg,
                    state.font,
                )))
                .padding(6)
                .style(|_| container::Style {
                    background: Some(Background::Color(state.bg)),
                    border: iced::Border {
                        color: state.border,
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    text_color: None,
                    shadow: iced::Shadow::default(),
                }),
                iced::widget::tooltip::Position::Bottom,
            )
            .into()
        }
    };

    let field_widgets: Vec<Element<'_, Message>> = state
        .fields
        .iter()
        .enumerate()
        .map(|(idx, f)| {
            let is_hidden = matches!(f.spec.kind, FieldKind::Password | FieldKind::Secret);
            let lbl = text(if f.spec.label.is_empty() {
                f.spec.id.as_str()
            } else {
                &f.spec.label
            })
            .size(font_size - 1)
            .color(state.label_color)
            .font(state.font);
            let mut inp = text_input(f.spec.placeholder.as_str(), f.value.as_str())
                .on_input(move |v| Message::FieldChanged(idx, v))
                .on_submit(Message::Confirm)
                .secure(is_hidden)
                .padding(8)
                .size(font_size)
                .font(state.font)
                .style({
                    let (accent, border, ibg, itxt, lc) = (
                        state.accent,
                        state.border,
                        state.input_bg,
                        state.input_text,
                        state.label_color,
                    );
                    move |_, status| iced::widget::text_input::Style {
                        background: Background::Color(ibg),
                        border: iced::Border {
                            color: if status == iced::widget::text_input::Status::Focused {
                                accent
                            } else {
                                border
                            },
                            width: 1.0,
                            radius: 6.0.into(),
                        },
                        icon: lc,
                        placeholder: lc,
                        value: itxt,
                        selection: accent,
                    }
                });
            // Auto-focus: attach the known ID to the first field so the
            // `text_input::focus(FIRST_FIELD_ID)` task issued in `run_with`
            // can locate this widget.
            if idx == 0 {
                inp = inp.id(FIRST_FIELD_ID.clone());
            }
            column![lbl, inp].spacing(3).into()
        })
        .collect();

    let confirm = button(
        text(&state.confirm_label)
            .size(font_size)
            .width(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center)
            .color(state.confirm_text)
            .font(state.font),
    )
    .width(Length::Fill)
    .padding(8)
    .style(move |_, s| button_style(state.confirm_bg, state.confirm_text, s))
    .on_press(Message::Confirm);

    let cancel = button(
        text(&state.cancel_label)
            .size(font_size)
            .width(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center)
            .color(state.cancel_text)
            .font(state.font),
    )
    .width(Length::Fill)
    .padding(8)
    .style(move |_, s| button_style(state.cancel_bg, state.cancel_text, s))
    .on_press(Message::Cancel);

    let actions: Element<'_, Message> = row![confirm, cancel]
        .spacing(10)
        .align_y(Alignment::Center)
        .into();

    let mut items: Vec<Element<'_, Message>> = vec![title_widget];

    // Info line with **bold** and _italic_ markers parsed into rich_text spans.
    if !state.info.trim().is_empty() {
        let spans = parse_styled_spans(
            &state.info,
            font_size - 1,
            state.label_color,
            state.fg,
            state.font,
        );
        let info_widget: Element<'_, Message> = iced::widget::rich_text(spans).into();
        items.push(info_widget);
    }

    if !state.message.is_empty() {
        let spans = parse_styled_spans(
            &state.message,
            font_size,
            state.label_color,
            state.fg,
            state.font,
        );
        let message_widget: Element<'_, Message> = iced::widget::rich_text(spans).into();
        items.push(message_widget);
    }
    items.extend(field_widgets);
    items.push(actions);

    let content = iced::widget::Column::with_children(items)
        .spacing(10)
        .padding(14)
        .align_x(Alignment::Start);

    // The styled container fills the entire window so that any sub-pixel
    // rounding between the calculated height and iced's actual layout is
    // hidden — the background colour covers the full window area.
    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(4)
        .style(move |_| container::Style {
            background: Some(Background::Color(state.bg)),
            border: iced::Border {
                color: state.border,
                width: state.theme.border_width,
                radius: 8.0.into(),
            },
            text_color: None,
            shadow: iced::Shadow::default(),
        })
        .into()
}

#[derive(Debug)]
struct TotpApp {
    title: String,
    code: String,
    remaining: u32,
    /// When Some, this is a confirmation dialog (Save/Cancel) instead of
    /// copy/close. The String is the confirm button label.
    confirm_label: Option<String>,
    /// Parsed TOTP params for code regeneration on period expiry.
    totp_params: Option<rosec_core::totp::TotpParams>,
    theme: ThemeConfig,
    fg: iced::Color,
    bg: iced::Color,
    border: iced::Color,
    label_color: iced::Color,
    accent: iced::Color,
    input_bg: iced::Color,
    confirm_bg: iced::Color,
    confirm_text_color: iced::Color,
    cancel_bg: iced::Color,
    cancel_text_color: iced::Color,
    font: iced::Font,
}

fn run_gui_totp(request: PromptRequest) -> Result<()> {
    use iced::application;
    use iced::window::settings::PlatformSpecific;

    let totp = request
        .totp_display
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("totp_display missing"))?;
    let code = totp.code.clone();

    application("rosec prompt", totp_update, totp_view)
        .subscription(totp_subscription)
        .window(iced::window::Settings {
            size: iced::Size::new(380.0, 190.0),
            resizable: false,
            decorations: false,
            transparent: true,
            platform_specific: PlatformSpecific {
                application_id: "rosec.prompt".to_string(),
                override_redirect: false,
            },
            ..Default::default()
        })
        .run_with(move || {
            let state = TotpApp::from_request(&request);
            if state.confirm_label.is_none() {
                clipboard_write(&code);
            }
            (state, iced::Task::none())
        })?;
    Ok(())
}

impl TotpApp {
    fn from_request(req: &PromptRequest) -> Self {
        let totp = req
            .totp_display
            .as_ref()
            .expect("totp_display must be Some");
        let fg = parse_color(&req.theme.foreground, iced::Color::WHITE);
        let bg = parse_color(&req.theme.background, iced::Color::BLACK);
        let border = parse_color(&req.theme.border_color, iced::Color::WHITE);
        let label_color = parse_color(&req.theme.label_color, fg);
        let accent = parse_color(&req.theme.accent_color, fg);
        let confirm_bg = if req.theme.confirm_background.trim().is_empty() {
            accent
        } else {
            parse_color(&req.theme.confirm_background, accent)
        };
        let confirm_text = if req.theme.confirm_text.trim().is_empty() {
            fg
        } else {
            parse_color(&req.theme.confirm_text, fg)
        };
        let cancel_bg = if req.theme.cancel_background.trim().is_empty() {
            iced::Color::from_rgb(0.25, 0.25, 0.28)
        } else {
            parse_color(
                &req.theme.cancel_background,
                iced::Color::from_rgb(0.25, 0.25, 0.28),
            )
        };
        let cancel_text = if req.theme.cancel_text.trim().is_empty() {
            fg
        } else {
            parse_color(&req.theme.cancel_text, label_color)
        };
        let input_bg = parse_color(&req.theme.input_background, bg);
        let font = font_from_string(&req.theme.font_family);
        let totp_params = totp
            .seed
            .as_deref()
            .and_then(|s| rosec_core::totp::parse_totp_input(s.as_bytes()).ok());
        Self {
            title: req.title.clone(),
            code: totp.code.clone(),
            remaining: totp.remaining,
            confirm_label: totp.confirm.clone(),
            totp_params,
            theme: req.theme.clone(),
            fg,
            bg,
            border,
            label_color,
            accent,
            input_bg,
            confirm_bg,
            confirm_text_color: confirm_text,
            cancel_bg,
            cancel_text_color: cancel_text,
            font,
        }
    }
}

/// Write text to the system clipboard via `wl-copy` (Wayland) or `xclip` (X11).
///
/// `wl-copy` forks a background daemon that owns the clipboard content and
/// serves paste requests until another app copies something.  This is the
/// standard mechanism for short-lived processes on Wayland.
fn clipboard_write(text: &str) {
    use std::process::{Command, Stdio};

    if let Ok(mut child) = Command::new("wl-copy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(text.as_bytes());
        }
        let _ = child.wait();
        return;
    }

    if let Ok(mut child) = Command::new("xclip")
        .args(["-selection", "clipboard"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(text.as_bytes());
        }
        let _ = child.wait();
    }
}

fn totp_emit_stdout() {
    use std::io::Write as _;
    let _ = std::io::stdout().write_all(b"{}\n");
    let _ = std::io::stdout().flush();
}

fn totp_update(state: &mut TotpApp, message: TotpMessage) -> iced::Task<TotpMessage> {
    match message {
        TotpMessage::Tick => {
            if state.confirm_label.is_some() {
                return iced::Task::none();
            }
            if state.remaining > 0 {
                state.remaining -= 1;
            }
            if state.remaining == 0 {
                if let Some(ref params) = state.totp_params {
                    let now = std::time::SystemTime::now();
                    if let Ok(code) = rosec_core::totp::generate_code(params, now) {
                        state.code = code.to_string();
                    }
                    state.remaining = rosec_core::totp::time_remaining_at(params, now) as u32;
                } else {
                    std::process::exit(0);
                }
            }
            iced::Task::none()
        }
        TotpMessage::CopyToClipboard => {
            // iced's clipboard::write requires the window surface to stay
            // alive on Wayland, which is impractical for a short-lived prompt.
            // Use wl-copy (standard on all Wayland desktops) or xclip as a
            // reliable cross-desktop clipboard mechanism.
            clipboard_write(&state.code);
            totp_emit_stdout();
            std::process::exit(0);
        }
        TotpMessage::AutoDismiss => {
            std::process::exit(0);
        }
        TotpMessage::KeyPressed(key) => {
            use iced::keyboard::Key;
            use iced::keyboard::key::Named;
            match key {
                Key::Named(Named::Escape) => std::process::exit(1),
                _ => iced::Task::none(),
            }
        }
    }
}

fn totp_subscription(state: &TotpApp) -> iced::Subscription<TotpMessage> {
    let tick = if state.confirm_label.is_none() {
        iced::time::every(Duration::from_secs(1)).map(|_| TotpMessage::Tick)
    } else {
        iced::Subscription::none()
    };

    let keys = iced::event::listen_with(|event, _status, _id| {
        if let iced::Event::Keyboard(iced::keyboard::Event::KeyPressed { key, .. }) = event {
            Some(TotpMessage::KeyPressed(key))
        } else {
            None
        }
    });

    iced::Subscription::batch([tick, keys])
}

fn totp_view(state: &TotpApp) -> iced::Element<'_, TotpMessage> {
    use iced::widget::{button, column, container, row, text};
    use iced::{Alignment, Background, Element, Length};

    let font_size = state.theme.font_size as u16;

    let bold_font = iced::Font {
        weight: iced::font::Weight::Bold,
        ..state.font
    };

    let title_widget: Element<'_, TotpMessage> = text(&state.title)
        .size(font_size + 1)
        .color(state.fg)
        .font(bold_font)
        .into();

    let expiring = state.remaining <= 8 && state.confirm_label.is_none();
    let digit_color = if expiring {
        iced::Color::from_rgb(0.9, 0.25, 0.25)
    } else {
        state.accent
    };

    let code_widget: Element<'_, TotpMessage> = container(pin_box_row::<TotpMessage>(
        &state.code,
        font_size,
        digit_color,
        state.input_bg,
        state.border,
    ))
    .width(Length::Fill)
    .align_x(iced::alignment::Horizontal::Center)
    .into();

    let is_confirm = state.confirm_label.is_some();

    let subtitle: Element<'_, TotpMessage> = if is_confirm {
        text("Does this match your authenticator?")
            .size(font_size)
            .color(state.label_color)
            .font(state.font)
            .width(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center)
            .into()
    } else {
        text(format!("Expires in {}s", state.remaining))
            .size(font_size)
            .color(state.label_color)
            .font(state.font)
            .width(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center)
            .into()
    };

    let primary_label = state.confirm_label.as_deref().unwrap_or("Copy");
    let primary_btn = button(
        text(primary_label)
            .size(font_size)
            .width(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center)
            .color(state.confirm_text_color)
            .font(state.font),
    )
    .width(Length::Fill)
    .padding(8)
    .style(move |_, s| button_style(state.confirm_bg, state.confirm_text_color, s))
    .on_press(if is_confirm {
        TotpMessage::AutoDismiss
    } else {
        TotpMessage::CopyToClipboard
    });

    let cancel_label = if is_confirm { "Cancel" } else { "Close" };
    let cancel_btn = button(
        text(cancel_label)
            .size(font_size)
            .width(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center)
            .color(state.cancel_text_color)
            .font(state.font),
    )
    .width(Length::Fill)
    .padding(8)
    .style(move |_, s| button_style(state.cancel_bg, state.cancel_text_color, s))
    .on_press(TotpMessage::KeyPressed(iced::keyboard::Key::Named(
        iced::keyboard::key::Named::Escape,
    )));

    let actions: Element<'_, TotpMessage> = row![primary_btn, cancel_btn]
        .spacing(10)
        .align_y(Alignment::Center)
        .into();

    let content = column![title_widget, code_widget, subtitle, actions]
        .spacing(10)
        .padding(14)
        .align_x(Alignment::Center);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(4)
        .style(move |_| container::Style {
            background: Some(Background::Color(state.bg)),
            border: iced::Border {
                color: state.border,
                width: state.theme.border_width,
                radius: 8.0.into(),
            },
            text_color: None,
            shadow: iced::Shadow::default(),
        })
        .into()
}

#[derive(Debug, Clone)]
enum QrMessage {
    Scan,
    Cancel,
    WindowHidden,
    ScanResult(Result<String, String>),
    KeyPressed(iced::keyboard::Key),
}

#[derive(Debug)]
struct QrApp {
    title: String,
    status: String,
    scanning: bool,
    theme: ThemeConfig,
    fg: iced::Color,
    bg: iced::Color,
    border: iced::Color,
    label_color: iced::Color,
    _accent: iced::Color,
    confirm_bg: iced::Color,
    confirm_text: iced::Color,
    cancel_bg: iced::Color,
    cancel_text: iced::Color,
    font: iced::Font,
}

fn run_gui_qr(request: PromptRequest) -> Result<()> {
    use iced::application;
    use iced::window::settings::PlatformSpecific;

    let initial_status = "Position the QR code on your screen, then click Scan";
    let initial_size = derive_qr_window_size(&request.title, initial_status, &request.theme);

    application("rosec prompt", qr_update, qr_view)
        .subscription(qr_subscription)
        .window(iced::window::Settings {
            size: initial_size,
            resizable: false,
            decorations: false,
            transparent: true,
            platform_specific: PlatformSpecific {
                application_id: "rosec.prompt".to_string(),
                override_redirect: false,
            },
            ..Default::default()
        })
        .run_with(move || {
            let state = QrApp::from_request(&request);
            (state, iced::Task::none())
        })?;
    Ok(())
}

/// Compute the QR window size by measuring the rendered text.
///
/// Mirrors the regular prompt's derivation: cosmic-text measures the title
/// (bold, font_size+1) and the status text (normal, font_size) at the actual
/// content width, then we add the layout's fixed padding + spacing + button
/// row to get total height.
fn derive_qr_window_size(title: &str, status: &str, theme: &ThemeConfig) -> iced::Size {
    let width = 380.0_f32;
    let btn_h = line_height(theme.font_size) + 16.0; // padding(8) top+bottom + text
    let mut m = TextMeasurer::new(theme, content_width(width));

    let height = (OUTER_PADDING + INNER_PADDING) * 2.0  // top + bottom padding
        + m.title(title)
        + 10.0                                          // spacing after title
        + m.body(status)
        + 10.0                                          // spacing after status
        + btn_h;

    iced::Size::new(width, height)
}

impl QrApp {
    fn from_request(req: &PromptRequest) -> Self {
        let fg = parse_color(&req.theme.foreground, iced::Color::WHITE);
        let bg = parse_color(&req.theme.background, iced::Color::BLACK);
        let border = parse_color(&req.theme.border_color, iced::Color::WHITE);
        let label_color = parse_color(&req.theme.label_color, fg);
        let accent = parse_color(&req.theme.accent_color, fg);
        let confirm_bg = if req.theme.confirm_background.trim().is_empty() {
            accent
        } else {
            parse_color(&req.theme.confirm_background, accent)
        };
        let confirm_text = if req.theme.confirm_text.trim().is_empty() {
            fg
        } else {
            parse_color(&req.theme.confirm_text, fg)
        };
        let cancel_bg = if req.theme.cancel_background.trim().is_empty() {
            iced::Color::from_rgb(0.25, 0.25, 0.28)
        } else {
            parse_color(
                &req.theme.cancel_background,
                iced::Color::from_rgb(0.25, 0.25, 0.28),
            )
        };
        let cancel_text = if req.theme.cancel_text.trim().is_empty() {
            fg
        } else {
            parse_color(&req.theme.cancel_text, label_color)
        };
        let font = font_from_string(&req.theme.font_family);
        Self {
            title: req.title.clone(),
            status: "Position the QR code on your screen, then click Scan".to_string(),
            scanning: false,
            theme: req.theme.clone(),
            fg,
            bg,
            border,
            label_color,
            _accent: accent,
            confirm_bg,
            confirm_text,
            cancel_bg,
            cancel_text,
            font,
        }
    }
}

fn qr_emit_and_exit(uri: &str) -> ! {
    // The otpauth:// URI contains the TOTP seed — sensitive. Route through
    // emit_secret_json so the serialised bytes live only in a Zeroizing
    // buffer.
    let out = serde_json::json!({ "otpauth_uri": uri });
    if let Err(e) = emit_secret_json(&out) {
        eprintln!("output emit error: {e}");
    }
    std::process::exit(0);
}

/// Capture a full-screen screenshot via the XDG Desktop Portal.
///
/// Spawns a **child process** for each attempt so the portal D-Bus session
/// is fully torn down between retries.  The `ashpd` library caches
/// connections process-globally, which causes the second in-process call
/// to hang on some portal implementations (e.g. xdg-desktop-portal-hyprland).
///
/// The child re-invokes the current binary with `--screenshot-helper`,
/// captures stdout (PNG bytes), and returns the bytes on success.
///
/// Bytes flow parent←child through a kernel pipe; the parent never gives
/// the child a writable filesystem path, so a malicious invocation of
/// the same binary cannot trick it into clobbering a chosen file.
fn capture_screenshot() -> Result<Vec<u8>, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let output = std::process::Command::new(exe)
        .arg("--screenshot-helper")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| format!("spawn screenshot helper: {e}"))?;
    if !output.status.success() {
        return Err("screenshot helper exited non-zero".to_string());
    }
    if output.stdout.is_empty() {
        return Err("screenshot helper produced no output".to_string());
    }
    Ok(output.stdout)
}

/// Entry point for the `--screenshot-helper` subprocess.
///
/// Staged hardening: NO_NEW_PRIVS + mlockall up front, then the portal
/// call (which requires xdg-desktop-portal to read /proc/<our-pid>/root
/// for sandbox identification — PR_SET_DUMPABLE=0 would block this).
/// Once the portal returns and we're about to bring PNG bytes into
/// memory, we set PR_SET_DUMPABLE=0 to close the dumpable window.
fn run_screenshot_helper() -> ! {
    rosec_core::process::harden_introspectable();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("screenshot-helper: tokio init failed: {e}");
            std::process::exit(1);
        });
    let bytes = rt.block_on(async {
        let portal = ashpd::desktop::screenshot::Screenshot::request()
            .interactive(false)
            .modal(false)
            .send()
            .await
            .map_err(|e| format!("portal request failed: {e}"))?;
        let response = portal
            .response()
            .map_err(|e| format!("portal response failed: {e}"))?;
        let uri = response.uri().to_string();
        let file_path = uri.strip_prefix("file://").unwrap_or(&uri);
        // Portal phase done — close /proc/<pid>/* introspection before
        // the PNG (which contains the user's screen) enters our memory.
        rosec_core::process::set_not_dumpable();
        let bytes = std::fs::read(file_path).map_err(|e| format!("read {file_path}: {e}"))?;
        let _ = std::fs::remove_file(file_path);
        Ok::<Vec<u8>, String>(bytes)
    });
    match bytes {
        Ok(bytes) => {
            use std::io::Write as _;
            if let Err(e) = std::io::stdout().write_all(&bytes) {
                eprintln!("screenshot-helper: stdout write failed: {e}");
                std::process::exit(1);
            }
            let _ = std::io::stdout().flush();
            std::process::exit(0);
        }
        Err(msg) => {
            eprintln!("screenshot-helper: {msg}");
            std::process::exit(1);
        }
    }
}

fn decode_qr_from_bytes(bytes: &[u8]) -> Option<String> {
    let img = image::load_from_memory(bytes).ok()?;
    let gray = img.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(gray);
    let grids = prepared.detect_grids();
    for grid in grids {
        if let Ok((_, content)) = grid.decode()
            && content.starts_with("otpauth://")
        {
            return Some(content);
        }
    }
    None
}

fn qr_update(state: &mut QrApp, message: QrMessage) -> iced::Task<QrMessage> {
    match message {
        QrMessage::Scan => {
            state.scanning = true;
            state.status = "Scanning...".to_string();
            iced::window::get_oldest().and_then(|id| {
                iced::window::minimize(id, true).chain(iced::Task::done(QrMessage::WindowHidden))
            })
        }
        QrMessage::WindowHidden => iced::Task::perform(
            async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                // Cap at 10s — some portal impls hang indefinitely.
                let captured = tokio::time::timeout(
                    Duration::from_secs(10),
                    tokio::task::spawn_blocking(capture_screenshot),
                )
                .await;
                let bytes = match captured {
                    Ok(Ok(Ok(b))) => b,
                    Ok(Ok(Err(msg))) => {
                        return Err(format!(
                            "Screenshot failed: {msg}. Ensure xdg-desktop-portal is running."
                        ));
                    }
                    Ok(Err(_)) => {
                        return Err("Screenshot helper panicked.".to_string());
                    }
                    Err(_) => {
                        return Err("Screenshot timed out. Portal may be unresponsive.".to_string());
                    }
                };
                match decode_qr_from_bytes(&bytes) {
                    Some(uri) => Ok(uri),
                    None => Err("No otpauth:// QR code found on screen. Try again.".to_string()),
                }
            },
            QrMessage::ScanResult,
        ),
        QrMessage::ScanResult(Ok(uri)) => qr_emit_and_exit(&uri),
        QrMessage::ScanResult(Err(msg)) => {
            state.scanning = false;
            state.status = msg;
            // Re-measure for the new (typically longer) status text and
            // resize the window to fit, otherwise the wrapped error text
            // overflows beyond the original "Position the QR..." height.
            let new_size = derive_qr_window_size(&state.title, &state.status, &state.theme);
            iced::window::get_oldest().and_then(move |id| {
                iced::window::resize(id, new_size).chain(iced::window::minimize(id, false))
            })
        }
        QrMessage::Cancel => std::process::exit(1),
        QrMessage::KeyPressed(key) => {
            use iced::keyboard::Key;
            use iced::keyboard::key::Named;
            match key {
                Key::Named(Named::Escape) => std::process::exit(1),
                _ => iced::Task::none(),
            }
        }
    }
}

fn qr_subscription(_state: &QrApp) -> iced::Subscription<QrMessage> {
    iced::event::listen_with(|event, _status, _id| {
        if let iced::Event::Keyboard(iced::keyboard::Event::KeyPressed { key, .. }) = event {
            Some(QrMessage::KeyPressed(key))
        } else {
            None
        }
    })
}

fn qr_view(state: &QrApp) -> iced::Element<'_, QrMessage> {
    use iced::widget::{button, column, container, row, text};
    use iced::{Alignment, Background, Element, Length};

    let font_size = state.theme.font_size as u16;

    let bold_font = iced::Font {
        weight: iced::font::Weight::Bold,
        ..state.font
    };

    let title_widget: Element<'_, QrMessage> = text(&state.title)
        .size(font_size + 1)
        .color(state.fg)
        .font(bold_font)
        .into();

    let status_widget: Element<'_, QrMessage> = text(&state.status)
        .size(font_size)
        .color(state.label_color)
        .font(state.font)
        .width(Length::Fill)
        .align_x(iced::alignment::Horizontal::Center)
        .wrapping(iced::widget::text::Wrapping::Word)
        .into();

    let scan_btn = button(
        text("Scan")
            .size(font_size)
            .width(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center)
            .color(state.confirm_text)
            .font(state.font),
    )
    .width(Length::Fill)
    .padding(8)
    .style(move |_, s| button_style(state.confirm_bg, state.confirm_text, s))
    .on_press_maybe(if state.scanning {
        None
    } else {
        Some(QrMessage::Scan)
    });

    let cancel_btn = button(
        text("Cancel")
            .size(font_size)
            .width(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center)
            .color(state.cancel_text)
            .font(state.font),
    )
    .width(Length::Fill)
    .padding(8)
    .style(move |_, s| button_style(state.cancel_bg, state.cancel_text, s))
    .on_press(QrMessage::Cancel);

    let actions: Element<'_, QrMessage> = row![scan_btn, cancel_btn]
        .spacing(10)
        .align_y(Alignment::Center)
        .into();

    let content = column![title_widget, status_widget, actions]
        .spacing(10)
        .padding(14)
        .align_x(Alignment::Center);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(4)
        .style(move |_| container::Style {
            background: Some(Background::Color(state.bg)),
            border: iced::Border {
                color: state.border,
                width: state.theme.border_width,
                radius: 8.0.into(),
            },
            text_color: None,
            shadow: iced::Shadow::default(),
        })
        .into()
}
