//! rosec-prompt — credential prompt subprocess.
//!
//! # Protocol
//!
//! **stdin**: a single JSON object:
//! ```json
//! {
//!   "t": "Unlock backend",
//!   "m": "Enter credentials",
//!   "h": "Backend: my-vault",
//!   "backend": "my-vault",
//!   "fields": [
//!     {"id": "password", "label": "Master Password", "kind": "password", "placeholder": "…"},
//!     {"id": "email",    "label": "Email",           "kind": "text",     "placeholder": "…"}
//!   ],
//!   "theme": { … }
//! }
//! ```
//! `fields` is optional — if absent a single hidden `password` field is implied.
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

use std::collections::HashMap;
use std::io::{self, Read};
use std::sync::LazyLock;

use anyhow::Result;
use iced::widget::text_input;
use rosec_core::config::PromptTheme;
use serde::Deserialize;
use zeroize::Zeroizing;

/// Stable ID for the first text input field so we can auto-focus it on startup.
static FIRST_FIELD_ID: LazyLock<text_input::Id> = LazyLock::new(text_input::Id::unique);

// ---------------------------------------------------------------------------
// Field descriptor
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Request / theme types
// ---------------------------------------------------------------------------

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
    /// Field list.  When absent a single hidden `password` field is implied.
    #[serde(default)]
    fields: Vec<FieldSpec>,
    #[serde(default)]
    theme: ThemeConfig,
}

impl PromptRequest {
    /// Return the effective field list, inserting the default if none were given.
    fn effective_fields(&self) -> Vec<FieldSpec> {
        if self.fields.is_empty() {
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

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();

    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;

    let request: PromptRequest = if raw.trim().is_empty() {
        PromptRequest {
            title: "Unlock backend".to_string(),
            message: "Enter your credentials".to_string(),
            hint: String::new(),
            backend: String::new(),
            confirm_label: String::new(),
            cancel_label: String::new(),
            fields: Vec::new(),
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

// ---------------------------------------------------------------------------
// TTY mode
// ---------------------------------------------------------------------------

/// Collect credentials from a TTY using rpassword (hidden) or plain readline (text).
fn run_tty(request: PromptRequest) -> Result<()> {
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

    // Emit JSON result — field values are temporary &str borrows, not copies.
    let out: HashMap<&str, &str> = values
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// GUI mode
// ---------------------------------------------------------------------------

fn run_gui(request: PromptRequest) -> Result<()> {
    use iced::application;
    use iced::window::settings::PlatformSpecific;

    let fields = request.effective_fields();
    let font_size = request.theme.font_size;

    // Calculate height from actual widget dimensions:
    //   outer padding (4×2) + inner padding (14×2) + title + spacing + message
    //   + spacing + per-field (label + 3 + input) + spacing + buttons
    let line_h = font_size + 6.0; // text line height with a little breathing room
    let input_h = font_size + 16.0; // text_input: padding(8) top+bottom + font
    let field_h = line_h + 3.0 + input_h; // label + spacing(3) + input
    let btn_h = font_size + 16.0; // button: padding(8) top+bottom + font

    // Usable content width after outer padding (4×2) + inner padding (14×2).
    let content_w = 420.0 - (4.0 + 14.0) * 2.0;
    // Approximate characters per line.  Proportional fonts average roughly
    // 0.43× the font pixel size per glyph — deliberately conservative so we
    // overcount wrapped lines rather than clip content.
    let avg_char_w = font_size * 0.43;
    let chars_per_line = (content_w / avg_char_w).floor().max(1.0);

    // Estimate visual line count, accounting for word-wrap on each hard line.
    // Title is rendered at font_size+1 so its glyphs are slightly wider.
    let title_chars_per_line = (content_w / ((font_size + 1.0) * 0.43)).floor().max(1.0);
    let title_lines = estimate_wrapped_lines(&request.title, title_chars_per_line);

    // Only account for message height when one is actually present — an empty
    // message still occupies one line_h in the naive formula, which produces
    // a visible blank gap.
    let msg_lines = if request.message.is_empty() {
        0.0
    } else {
        estimate_wrapped_lines(&request.message, chars_per_line)
    };

    let height = (4.0 + 14.0) * 2.0                        // outer + inner padding (top+bottom)
        + line_h * title_lines                               // title (may wrap)
        + 10.0                                               // spacing after title
        + line_h * msg_lines                                 // message (may wrap, 0 if absent)
        + if msg_lines > 0.0 { 10.0 } else { 0.0 }          // spacing after message (only if present)
        + (field_h + 10.0) * fields.len() as f32            // fields + spacing after each
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
            let state = GuiApp::from_request(request, fields);
            // Focus the first text input on startup.
            let task = iced::widget::text_input::focus(FIRST_FIELD_ID.clone());
            (state, task)
        })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// GUI state & logic
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Message {
    FieldChanged(usize, String),
    Confirm,
    Cancel,
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
            format!("Backend: {}", req.backend)
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

fn confirm_and_exit(state: &GuiApp) {
    use std::io::Write as _;
    let out: HashMap<&str, &str> = state
        .fields
        .iter()
        .map(|f| (f.spec.id.as_str(), f.value.as_str()))
        .collect();
    match serde_json::to_string(&out) {
        Ok(json) => {
            // Must flush stdout explicitly — std::process::exit() bypasses
            // Rust's stdio buffers and the JSON would be lost otherwise.
            let _ = std::io::stdout().write_all(json.as_bytes());
            let _ = std::io::stdout().write_all(b"\n");
            let _ = std::io::stdout().flush();
        }
        Err(e) => eprintln!("output serialization error: {e}"),
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
            use iced::keyboard::key::Named;
            use iced::keyboard::Key;
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

    // Title (with tooltip for hint if present)
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
                container(
                    text(&state.hint)
                        .size(font_size)
                        .color(state.label_color)
                        .font(state.font),
                )
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

    // One label + input_box per field
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
    if !state.message.is_empty() {
        let message_widget: Element<'_, Message> = text(&state.message)
            .size(font_size)
            .color(state.label_color)
            .font(state.font)
            .into();
        items.push(message_widget);
    }
    items.extend(field_widgets);
    items.push(actions);

    let content = iced::widget::Column::with_children(items)
        .spacing(10)
        .padding(14)
        .align_x(Alignment::Start);

    container(content)
        .width(Length::Shrink)
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
        .center_x(Length::Fill)
        .into()
}

// ---------------------------------------------------------------------------
// Colour / font helpers
// ---------------------------------------------------------------------------

/// Estimate the number of visual lines a string occupies given a maximum
/// character width per line.  Each hard newline starts a new line, and long
/// segments are assumed to wrap at `chars_per_line` boundaries.
fn estimate_wrapped_lines(s: &str, chars_per_line: f32) -> f32 {
    if s.is_empty() {
        return 1.0;
    }
    let cpl = chars_per_line.max(1.0);
    s.lines()
        .map(|line| {
            let len = line.len() as f32;
            (len / cpl).ceil().max(1.0)
        })
        .sum::<f32>()
        // If the string ends with a trailing newline, `.lines()` won't emit
        // an extra empty item, but we already handle empty → 1 above.
        .max(1.0)
}

fn parse_color(value: &str, fallback: iced::Color) -> iced::Color {
    iced::Color::parse(value.trim()).unwrap_or(fallback)
}

fn font_from_string(name: &str) -> iced::Font {
    let name = name.trim();
    if name.eq_ignore_ascii_case("monospace") {
        return iced::Font::MONOSPACE;
    }
    if name.eq_ignore_ascii_case("sans") || name.eq_ignore_ascii_case("sans-serif") {
        return iced::Font::DEFAULT;
    }
    if name.eq_ignore_ascii_case("serif") {
        return iced::Font {
            family: iced::font::Family::Serif,
            ..iced::Font::DEFAULT
        };
    }
    if !name.is_empty() {
        return iced::Font::with_name(Box::leak(name.to_string().into_boxed_str()));
    }
    iced::Font::DEFAULT
}

fn darken(c: iced::Color, f: f32) -> iced::Color {
    let f = f.clamp(0.0, 1.0);
    iced::Color {
        r: c.r * f,
        g: c.g * f,
        b: c.b * f,
        a: c.a,
    }
}

fn button_style(
    bg: iced::Color,
    fg: iced::Color,
    status: iced::widget::button::Status,
) -> iced::widget::button::Style {
    let base = iced::widget::button::Style {
        background: Some(iced::Background::Color(bg)),
        text_color: fg,
        border: iced::Border {
            color: bg,
            width: 0.0,
            radius: 6.0.into(),
        },
        shadow: iced::Shadow::default(),
    };
    match status {
        iced::widget::button::Status::Hovered => iced::widget::button::Style {
            background: Some(iced::Background::Color(darken(bg, 0.9))),
            ..base
        },
        iced::widget::button::Status::Pressed => iced::widget::button::Style {
            background: Some(iced::Background::Color(darken(bg, 0.8))),
            ..base
        },
        _ => base,
    }
}
