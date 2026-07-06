//! Single-select scrollable list window.
//!
//! Shows a title/message and a scrollable list of options; the highlighted
//! row is chosen with Enter or a Select-button press (or a direct click),
//! emitting `{"selected": "<id>"}`. Escape / Cancel exits 1 with no output.
//! Motivating use: disambiguating several WebAuthn credentials that match a
//! relying party, where the act of choosing an account is also the user
//! presence/verification gesture.

use anyhow::Result;

use crate::helpers::{button_style, font_from_string, parse_color};
use crate::output::emit_secret_json;
use crate::request::{PromptRequest, SelectOption, ThemeConfig};

#[derive(Debug, Clone)]
pub(super) enum SelectMessage {
    Choose(usize),
    Confirm,
    Cancel,
    MoveUp,
    MoveDown,
}

#[derive(Debug)]
pub(super) struct SelectApp {
    title: String,
    message: String,
    options: Vec<SelectOption>,
    highlighted: usize,
    theme: ThemeConfig,
    fg: iced::Color,
    bg: iced::Color,
    border: iced::Color,
    label_color: iced::Color,
    accent: iced::Color,
    input_bg: iced::Color,
    cancel_bg: iced::Color,
    cancel_text_color: iced::Color,
    font: iced::Font,
}

/// Cap the window height so a large option list scrolls rather than growing
/// off-screen. Chosen to show ~5 rows before scrolling kicks in.
const MAX_WINDOW_HEIGHT: f32 = 420.0;
const ROW_HEIGHT: f32 = 52.0;
const CHROME_HEIGHT: f32 = 150.0;

pub(super) fn run(request: PromptRequest) -> Result<()> {
    use iced::application;
    use iced::window::settings::PlatformSpecific;

    let select = request
        .select
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("select request missing"))?;
    if select.options.is_empty() {
        return Err(anyhow::anyhow!("select request has no options"));
    }

    let rows = select.options.len() as f32;
    let height = (CHROME_HEIGHT + rows * ROW_HEIGHT).min(MAX_WINDOW_HEIGHT);

    application(
        move || {
            let state = SelectApp::from_request(&request);
            (state, iced::Task::none())
        },
        update,
        view,
    )
    .title("rosec prompt")
    .subscription(subscription)
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
    .run()?;
    Ok(())
}

impl SelectApp {
    fn from_request(req: &PromptRequest) -> Self {
        let select = req.select.as_ref().expect("select must be Some");
        let fg = parse_color(&req.theme.foreground, iced::Color::WHITE);
        let bg = parse_color(&req.theme.background, iced::Color::BLACK);
        let border = parse_color(&req.theme.border_color, iced::Color::WHITE);
        let label_color = parse_color(&req.theme.label_color, fg);
        let accent = parse_color(&req.theme.accent_color, fg);
        let input_bg = parse_color(&req.theme.input_background, bg);
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
            message: req.message.clone(),
            options: select.options.clone(),
            highlighted: 0,
            theme: req.theme.clone(),
            fg,
            bg,
            border,
            label_color,
            accent,
            input_bg,
            cancel_bg,
            cancel_text_color: cancel_text,
            font,
        }
    }

    /// Emit the chosen option id and exit. Routed through the zeroizing
    /// writer for consistency with the rest of the protocol even though a
    /// credential handle is not itself secret.
    fn choose(&self, index: usize) -> ! {
        use std::collections::HashMap;
        let id = self
            .options
            .get(index)
            .map(|o| o.id.as_str())
            .unwrap_or_default();
        let out: HashMap<&str, &str> = HashMap::from([("selected", id)]);
        let _ = emit_secret_json(&out);
        std::process::exit(0);
    }
}

fn update(state: &mut SelectApp, message: SelectMessage) -> iced::Task<SelectMessage> {
    match message {
        SelectMessage::Choose(i) => state.choose(i),
        SelectMessage::Confirm => state.choose(state.highlighted),
        SelectMessage::Cancel => std::process::exit(1),
        SelectMessage::MoveUp => {
            state.highlighted = state.highlighted.saturating_sub(1);
        }
        SelectMessage::MoveDown => {
            state.highlighted = (state.highlighted + 1).min(state.options.len().saturating_sub(1));
        }
    }
    iced::Task::none()
}

fn subscription(_state: &SelectApp) -> iced::Subscription<SelectMessage> {
    use iced::keyboard::Key;
    use iced::keyboard::key::Named;
    iced::event::listen_with(|event, _status, _id| {
        let iced::Event::Keyboard(iced::keyboard::Event::KeyPressed { key, .. }) = event else {
            return None;
        };
        match key {
            Key::Named(Named::Escape) => Some(SelectMessage::Cancel),
            Key::Named(Named::Enter) => Some(SelectMessage::Confirm),
            Key::Named(Named::ArrowUp) => Some(SelectMessage::MoveUp),
            Key::Named(Named::ArrowDown) => Some(SelectMessage::MoveDown),
            _ => None,
        }
    })
}

fn view(state: &SelectApp) -> iced::Element<'_, SelectMessage> {
    use iced::widget::{button, column, container, scrollable, text};
    use iced::{Alignment, Background, Element, Length};

    let font_size = state.theme.font_size;
    let bold_font = iced::Font {
        weight: iced::font::Weight::Bold,
        ..state.font
    };

    let title_widget: Element<'_, SelectMessage> = text(&state.title)
        .size(font_size + 1.0)
        .color(state.fg)
        .font(bold_font)
        .width(Length::Fill)
        .into();

    let mut items = column![].spacing(6).width(Length::Fill);
    for (i, opt) in state.options.iter().enumerate() {
        let selected = i == state.highlighted;
        let row_fg = if selected { state.accent } else { state.fg };
        let primary = text(&opt.primary)
            .size(font_size)
            .color(row_fg)
            .font(bold_font);
        let mut rowcol = column![primary].spacing(2).width(Length::Fill);
        if !opt.secondary.is_empty() {
            rowcol = rowcol.push(
                text(&opt.secondary)
                    .size(font_size - 2.0)
                    .color(state.label_color)
                    .font(state.font),
            );
        }
        let row_bg = if selected {
            state.accent
        } else {
            state.input_bg
        };
        let row_border = if selected { state.accent } else { state.border };
        items = items.push(
            button(rowcol)
                .width(Length::Fill)
                .padding(10)
                .on_press(SelectMessage::Choose(i))
                .style(move |_, s| {
                    let mut st = button_style(row_bg, row_fg, s);
                    // Keep the fill subtle for unselected rows: reuse the
                    // input background rather than the accent.
                    if !selected {
                        st.background = Some(Background::Color(state.input_bg));
                        st.text_color = state.fg;
                        st.border = iced::Border {
                            color: row_border,
                            width: 1.0,
                            radius: 6.0.into(),
                        };
                    }
                    st
                }),
        );
    }

    let list: Element<'_, SelectMessage> = scrollable(items)
        .width(Length::Fill)
        .height(Length::Fill)
        .into();

    let cancel_btn = button(
        text("Cancel")
            .size(font_size)
            .width(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center)
            .color(state.cancel_text_color)
            .font(state.font),
    )
    .width(Length::Fill)
    .padding(8)
    .style(move |_, s| button_style(state.cancel_bg, state.cancel_text_color, s))
    .on_press(SelectMessage::Cancel);

    let mut content = column![title_widget].spacing(10).padding(14);
    if !state.message.is_empty() {
        content = content.push(
            text(&state.message)
                .size(font_size)
                .color(state.label_color)
                .font(state.font)
                .width(Length::Fill),
        );
    }
    content = content
        .push(list)
        .push(cancel_btn)
        .align_x(Alignment::Start);

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
