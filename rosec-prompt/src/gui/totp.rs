//! TOTP code display window.

use std::time::Duration;

use anyhow::Result;

use crate::helpers::{button_style, font_from_string, parse_color, pin_box_row};
use crate::output::emit_empty_and_exit;
use crate::request::{PromptRequest, ThemeConfig};

#[derive(Debug, Clone)]
pub(super) enum TotpMessage {
    Tick,
    CopyToClipboard,
    AutoDismiss,
    KeyPressed(iced::keyboard::Key),
}

#[derive(Debug)]
pub(super) struct TotpApp {
    title: String,
    code: String,
    remaining: u32,
    /// When `Some`, this is a confirm dialog (Save/Cancel) instead of copy/close.
    /// The string is the confirm button label.
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

pub(super) fn run(request: PromptRequest) -> Result<()> {
    use iced::application;
    use iced::window::settings::PlatformSpecific;

    // Fail fast on a malformed request (from_request also expects totp_display).
    request
        .totp_display
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("totp_display missing"))?;

    // iced 0.14: boot fn is the first arg to `application()`; title moved to
    // `.title()`; `.run_with()` → `.run()`. The TOTP code is copied only on an
    // explicit Copy-button press — never automatically at open.
    application(
        move || {
            let state = TotpApp::from_request(&request);
            (state, iced::Task::none())
        },
        update,
        view,
    )
    .title("rosec prompt")
    .subscription(subscription)
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
    .run()?;
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

/// Write the TOTP code to the clipboard via `wl-copy` (Wayland) or `xclip`
/// (X11). Both fork a background process that owns the selection and keeps
/// serving it after we exit — iced's own clipboard can't, since it serves the
/// selection through the (about-to-close) window.
///
/// The caller must keep the process alive briefly after this returns (see the
/// settle in the `CopyToClipboard` handler): the copy tool's daemon needs a
/// moment to take ownership of the selection, and exiting instantly races that
/// hand-off and leaves the clipboard empty.
///
/// Note: `--paste-once` (auto-clear after one paste) is intentionally *not*
/// used — with a clipboard manager it's consumed immediately, and it doesn't
/// survive the copy-then-exit hand-off. TOTP codes are short-lived anyway.
fn clipboard_write(text: &str) {
    use std::process::{Command, Stdio};

    // wl-copy (and xclip) create a private temp dir via mkdtemp to serve the
    // selection. Under the Landlock sandbox /tmp isn't writable, so point
    // TMPDIR at XDG_RUNTIME_DIR (which the GUI ruleset already allows) rather
    // than widening the sandbox. /dev/null (for the Stdio redirections) is
    // likewise granted in sandbox.rs.
    let tmpdir = std::env::var_os("XDG_RUNTIME_DIR");

    let mut wl = Command::new("wl-copy");
    wl.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(t) = &tmpdir {
        wl.env("TMPDIR", t);
    }
    match wl.spawn() {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
            return;
        }
        Err(e) => {
            tracing::debug!("wl-copy unavailable ({e}), falling back to xclip");
        }
    }

    // X11 fallback: xclip has no auto-clear flag. Stamp the selection now,
    // then schedule a delayed clear via a detached subprocess. 30 s matches
    // the typical TOTP step.
    let mut xc = Command::new("xclip");
    xc.args(["-selection", "clipboard"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(t) = &tmpdir {
        xc.env("TMPDIR", t);
    }
    match xc.spawn() {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();

            // Detached `sh -c "sleep 30 && xclip -i ..."` — survives our exit.
            let _ = Command::new("sh")
                .arg("-c")
                .arg("sleep 30 && printf '' | xclip -selection clipboard -i 2>/dev/null")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
        }
        Err(e) => {
            tracing::warn!(
                "clipboard copy failed: could not run wl-copy or xclip ({e}); \
                 the TOTP code was not copied to the clipboard"
            );
        }
    }
}

fn update(state: &mut TotpApp, message: TotpMessage) -> iced::Task<TotpMessage> {
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
            clipboard_write(&state.code);
            // Let wl-copy/xclip's background daemon take ownership of the
            // selection before we exit; a bare exit here races the hand-off
            // and leaves the clipboard empty. 400 ms is imperceptible for a
            // click-to-close action but reliably wins the race.
            std::thread::sleep(std::time::Duration::from_millis(400));
            emit_empty_and_exit();
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

fn subscription(state: &TotpApp) -> iced::Subscription<TotpMessage> {
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

fn view(state: &TotpApp) -> iced::Element<'_, TotpMessage> {
    use iced::widget::{button, column, container, row, text};
    use iced::{Alignment, Background, Element, Length};

    let font_size = state.theme.font_size;

    let bold_font = iced::Font {
        weight: iced::font::Weight::Bold,
        ..state.font
    };

    let title_widget: Element<'_, TotpMessage> = text(&state.title)
        .size(font_size + 1.0)
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
            snap: false,
        })
        .into()
}
