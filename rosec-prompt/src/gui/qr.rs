//! QR-scan window: captures the screen via the XDG screenshot portal and
//! decodes any `otpauth://` QR code found.

use std::time::Duration;

use anyhow::Result;

use crate::helpers::{
    INNER_PADDING, OUTER_PADDING, TextMeasurer, button_style, content_width, font_from_string,
    line_height, parse_color,
};
use crate::output::emit_secret_json;
use crate::request::{PromptRequest, ThemeConfig};

#[derive(Debug, Clone)]
pub(super) enum QrMessage {
    Scan,
    Cancel,
    WindowHidden,
    ScanResult(Result<String, String>),
    KeyPressed(iced::keyboard::Key),
}

#[derive(Debug)]
pub(super) struct QrApp {
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

pub(super) fn run(request: PromptRequest) -> Result<()> {
    use iced::application;
    use iced::window::settings::PlatformSpecific;

    let initial_status = "Position the QR code on your screen, then click Scan";
    let initial_size = derive_window_size(&request.title, initial_status, &request.theme);

    // iced 0.14: boot fn is the first arg to `application()`; title moved to
    // `.title()`; `.run_with()` → `.run()`.
    application(
        move || {
            let state = QrApp::from_request(&request);
            (state, iced::Task::none())
        },
        update,
        view,
    )
    .title("rosec prompt")
    .subscription(subscription)
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
    .run()?;
    Ok(())
}

/// Mirrors the regular prompt's derivation so error messages (which can wrap
/// onto multiple lines) get a window tall enough to show all the text.
fn derive_window_size(title: &str, status: &str, theme: &ThemeConfig) -> iced::Size {
    let width = 380.0_f32;
    let btn_h = line_height(theme.font_size) + 16.0;
    let mut m = TextMeasurer::new(theme, content_width(width));

    let height = (OUTER_PADDING + INNER_PADDING) * 2.0
        + m.title(title)
        + 10.0
        + m.body(status)
        + 10.0
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

/// The decoded `otpauth://` URI carries the TOTP seed, so route it through
/// `emit_secret_json` to keep the serialised bytes in a `Zeroizing` buffer.
fn emit_and_exit(uri: &str) -> ! {
    let out = serde_json::json!({ "otpauth_uri": uri });
    if let Err(e) = emit_secret_json(&out) {
        eprintln!("output emit error: {e}");
    }
    std::process::exit(0);
}

/// Spawns a child process for each capture so the portal D-Bus session is
/// fully torn down between retries — `ashpd` caches connections process-globally,
/// which causes the second in-process call to hang on some portal implementations
/// (e.g. xdg-desktop-portal-hyprland).
///
/// The child re-invokes the current binary with `--screenshot-helper` and pipes
/// PNG bytes back through stdout — no parent-controlled filesystem path crosses
/// the boundary.
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

/// Staged hardening: NO_NEW_PRIVS + mlockall up front, then the portal call
/// (xdg-desktop-portal needs to read /proc/<our-pid>/root for sandbox
/// identification, so PR_SET_DUMPABLE=0 must be deferred). Once the portal
/// returns, set PR_SET_DUMPABLE=0 before the PNG enters our memory.
pub(crate) fn run_screenshot_helper() -> ! {
    rosec_core::sandbox::harden_introspectable();
    crate::sandbox::restrict(crate::sandbox::Mode::ScreenshotHelper);

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
        rosec_core::sandbox::set_not_dumpable();
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

fn update(state: &mut QrApp, message: QrMessage) -> iced::Task<QrMessage> {
    match message {
        QrMessage::Scan => {
            state.scanning = true;
            state.status = "Scanning...".to_string();
            iced::window::oldest().and_then(|id| {
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
        QrMessage::ScanResult(Ok(uri)) => emit_and_exit(&uri),
        QrMessage::ScanResult(Err(msg)) => {
            state.scanning = false;
            state.status = msg;
            // Re-measure: error text typically wraps and would overflow the
            // initial "Position the QR..." height.
            let new_size = derive_window_size(&state.title, &state.status, &state.theme);
            iced::window::oldest().and_then(move |id| {
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

fn subscription(_state: &QrApp) -> iced::Subscription<QrMessage> {
    iced::event::listen_with(|event, _status, _id| {
        if let iced::Event::Keyboard(iced::keyboard::Event::KeyPressed { key, .. }) = event {
            Some(QrMessage::KeyPressed(key))
        } else {
            None
        }
    })
}

fn view(state: &QrApp) -> iced::Element<'_, QrMessage> {
    use iced::widget::{button, column, container, row, text};
    use iced::{Alignment, Background, Element, Length};

    let font_size = state.theme.font_size;

    let bold_font = iced::Font {
        weight: iced::font::Weight::Bold,
        ..state.font
    };

    let title_widget: Element<'_, QrMessage> = text(&state.title)
        .size(font_size + 1.0)
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
            snap: false,
        })
        .into()
}
