//! Standard credential prompt window.

use std::collections::HashMap;
use std::sync::LazyLock;

use anyhow::Result;
use zeroize::Zeroizing;

use crate::helpers::{
    TextMeasurer, button_style, content_width, font_from_string, line_height, parse_color,
    parse_styled_spans,
};
use crate::output::emit_secret_json;
use crate::request::{FieldKind, FieldSpec, PromptRequest, ThemeConfig};

/// Stable ID for the first text input so we can auto-focus it on startup.
static FIRST_FIELD_ID: LazyLock<iced::advanced::widget::Id> =
    LazyLock::new(iced::advanced::widget::Id::unique);

#[derive(Debug, Clone)]
pub(super) enum Message {
    FieldChanged(usize, String),
    Confirm,
    Cancel,
    KeyPressed(iced::keyboard::Key, iced::keyboard::Modifiers),
}

#[derive(Debug)]
struct FieldState {
    spec: FieldSpec,
    /// `Zeroizing` so the value is scrubbed when overwritten or dropped.
    value: Zeroizing<String>,
}

#[derive(Debug)]
pub(super) struct GuiApp {
    title: String,
    message: String,
    hint: String,
    info: String,
    confirm_label: String,
    cancel_label: String,
    fields: Vec<FieldState>,
    theme: ThemeConfig,
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

pub(super) fn run(request: PromptRequest) -> Result<()> {
    use iced::application;
    use iced::window::settings::PlatformSpecific;

    let fields = request.effective_fields();
    let height = derive_window_height(&request, &fields);

    // iced 0.14: the boot function is the first arg to `application()` and must
    // be `Fn` (callable by reference), so it clones the captured request/fields
    // rather than consuming them. Title moved to `.title()`; `.run_with()` →
    // `.run()`.
    application(
        move || {
            let has_fields = !fields.is_empty();
            let state = GuiApp::from_request(request.clone(), fields.clone());
            let task = if has_fields {
                iced::advanced::widget::operate(
                    iced::advanced::widget::operation::focusable::focus(FIRST_FIELD_ID.clone()),
                )
            } else {
                iced::Task::none()
            };
            (state, task)
        },
        update,
        view,
    )
    .title("rosec prompt")
    .subscription(|_state| {
        // `event::listen_with` sees all keyboard events, including those a
        // focused text_input would consume. `on_key_press` only receives
        // `Status::Ignored`, so the first Esc gets swallowed.
        iced::event::listen_with(|event, _status, _id| {
            if let iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                key, modifiers, ..
            }) = event
            {
                Some(Message::KeyPressed(key, modifiers))
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
    .run()?;
    Ok(())
}

fn derive_window_height(request: &PromptRequest, fields: &[FieldSpec]) -> f32 {
    let font_size = request.theme.font_size;

    let input_h = line_height(font_size) + 16.0;
    let btn_h = line_height(font_size) + 16.0;
    let content_w = content_width(420.0);

    let mut m = TextMeasurer::new(&request.theme, content_w);

    let title_h = m.title(&request.title);
    // Strip `**` markers before measuring; italic markers are word-bound and
    // narrow enough that the width difference is negligible for sizing.
    let info_h = m.body_small(&request.info.replace("**", ""));
    let msg_h = m.body(&request.message);

    let fields_total_h: f32 = fields
        .iter()
        .map(|f| {
            let label_text = if f.label.is_empty() { &f.id } else { &f.label };
            m.body_small(label_text) + 3.0 + input_h + 10.0
        })
        .sum();

    // Iced draws borders inside container bounds, so the border does not add
    // height — only the two padding layers contribute vertical overhead.
    (4.0 + 14.0) * 2.0
        + title_h
        + 10.0
        + info_h
        + if info_h > 0.0 { 10.0 } else { 0.0 }
        + msg_h
        + if msg_h > 0.0 { 10.0 } else { 0.0 }
        + fields_total_h
        + btn_h
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
            // Neutral dark grey — clearly distinct from the accent-coloured confirm button.
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

fn update(state: &mut GuiApp, message: Message) -> iced::Task<Message> {
    match message {
        Message::FieldChanged(idx, value) => {
            if let Some(f) = state.fields.get_mut(idx) {
                // Old `Zeroizing<String>` drops here → scrubbed.
                f.value = Zeroizing::new(value);
            }
            iced::Task::none()
        }
        Message::Confirm => confirm_and_exit(state),
        Message::Cancel => std::process::exit(1),
        Message::KeyPressed(key, modifiers) => {
            use iced::keyboard::Key;
            use iced::keyboard::key::Named;
            match key {
                Key::Named(Named::Enter) => confirm_and_exit(state),
                Key::Named(Named::Escape) => std::process::exit(1),
                // iced 0.14 no longer traverses focus on Tab automatically, so
                // dispatch the focus operation ourselves (Shift+Tab = previous).
                Key::Named(Named::Tab) => {
                    use iced::advanced::widget::{operate, operation};
                    if modifiers.shift() {
                        operate(operation::focusable::focus_previous())
                    } else {
                        operate(operation::focusable::focus_next())
                    }
                }
                _ => iced::Task::none(),
            }
        }
    }
}

fn view(state: &GuiApp) -> iced::Element<'_, Message> {
    use iced::widget::{button, column, container, row, text, text_input};
    use iced::{Alignment, Background, Element, Length};

    let font_size = state.theme.font_size;

    let title_widget: Element<'_, Message> = {
        let bold_font = iced::Font {
            weight: iced::font::Weight::Bold,
            ..state.font
        };
        let t = text(&state.title)
            .size(font_size + 1.0)
            .color(state.fg)
            .font(bold_font);
        if state.hint.trim().is_empty() {
            t.into()
        } else {
            iced::widget::tooltip(
                t,
                container(iced::widget::rich_text(parse_styled_spans::<Message>(
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
                    snap: false,
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
            .size(font_size - 1.0)
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
                            color: if matches!(
                                status,
                                iced::widget::text_input::Status::Focused { .. }
                            ) {
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
            // Tag the first field so `text_input::focus(FIRST_FIELD_ID)` in
            // `run` can locate it.
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

    if !state.info.trim().is_empty() {
        let spans = parse_styled_spans::<Message>(
            &state.info,
            font_size - 1.0,
            state.label_color,
            state.fg,
            state.font,
        );
        let info_widget: Element<'_, Message> = iced::widget::rich_text(spans).into();
        items.push(info_widget);
    }

    if !state.message.is_empty() {
        let spans = parse_styled_spans::<Message>(
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

    // Container fills the full window so any sub-pixel rounding between
    // calculated height and iced's actual layout is hidden by the background.
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
