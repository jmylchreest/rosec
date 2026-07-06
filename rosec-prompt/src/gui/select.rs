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
    /// Text colour for the selected (accent-filled) row.
    selected_text: iced::Color,
    /// Secondary text colour for the selected row (muted `selected_text`).
    selected_text_muted: iced::Color,
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
        // Text on the accent-filled selected row must contrast with the
        // accent regardless of theme: dark ink on a light accent, light ink
        // on a dark one. Relative luminance (Rec. 601) picks the side.
        let accent_luma = 0.299 * accent.r + 0.587 * accent.g + 0.114 * accent.b;
        let (selected_text, selected_text_muted) = if accent_luma > 0.55 {
            (
                iced::Color::from_rgb(0.08, 0.08, 0.10),
                iced::Color::from_rgba(0.08, 0.08, 0.10, 0.75),
            )
        } else {
            (
                iced::Color::WHITE,
                iced::Color::from_rgba(1.0, 1.0, 1.0, 0.8),
            )
        };
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
            selected_text,
            selected_text_muted,
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

/// Stable id for the option scrollable, so `update` can scroll it to follow
/// the keyboard highlight (iced's scrollable does not auto-follow a
/// programmatically-moved selection).
fn list_id() -> iced::advanced::widget::Id {
    iced::advanced::widget::Id::new("rosec-select-list")
}

/// A scroll task that brings the highlighted row into view. Maps the
/// highlighted index to a 0.0–1.0 relative offset; the widget clamps and
/// only scrolls when needed, so short lists are unaffected. `x: None`
/// leaves the horizontal offset untouched.
fn follow_highlight(state: &SelectApp) -> iced::Task<SelectMessage> {
    use iced::advanced::widget::operation::scrollable::{RelativeOffset, snap_to};
    let n = state.options.len();
    if n <= 1 {
        return iced::Task::none();
    }
    let y = state.highlighted as f32 / (n - 1) as f32;
    iced::advanced::widget::operate(snap_to(
        list_id(),
        RelativeOffset {
            x: None,
            y: Some(y),
        },
    ))
}

fn update(state: &mut SelectApp, message: SelectMessage) -> iced::Task<SelectMessage> {
    match message {
        SelectMessage::Choose(i) => state.choose(i),
        SelectMessage::Confirm => state.choose(state.highlighted),
        SelectMessage::Cancel => std::process::exit(1),
        SelectMessage::MoveUp => {
            state.highlighted = state.highlighted.saturating_sub(1);
            follow_highlight(state)
        }
        SelectMessage::MoveDown => {
            state.highlighted = (state.highlighted + 1).min(state.options.len().saturating_sub(1));
            follow_highlight(state)
        }
    }
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
        // On the selected row the fill is the accent colour, so text must
        // contrast with the accent — the window background does, by
        // construction (accent is a highlight chosen against `bg`). On
        // unselected rows keep the normal foreground on the subtle input
        // fill. Using accent as *both* fill and text made the selection
        // unreadable.
        let (primary_fg, secondary_fg) = if selected {
            (state.selected_text, state.selected_text_muted)
        } else {
            (state.fg, state.label_color)
        };
        let primary = text(&opt.primary)
            .size(font_size)
            .color(primary_fg)
            .font(bold_font);
        let mut rowcol = column![primary].spacing(2).width(Length::Fill);
        if !opt.secondary.is_empty() {
            rowcol = rowcol.push(
                text(&opt.secondary)
                    .size(font_size - 2.0)
                    .color(secondary_fg)
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
                    let mut st = button_style(row_bg, primary_fg, s);
                    st.background = Some(Background::Color(row_bg));
                    st.text_color = primary_fg;
                    st.border = iced::Border {
                        color: row_border,
                        width: 1.0,
                        radius: 6.0.into(),
                    };
                    st
                }),
        );
    }

    let list: Element<'_, SelectMessage> = scrollable(items)
        .id(list_id())
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
