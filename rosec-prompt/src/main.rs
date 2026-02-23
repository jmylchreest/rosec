use std::io::{self, Read};

use anyhow::Result;
use iced::alignment::Horizontal;
use iced::widget::{button, column, container, row, text, text_input};
use iced::window::settings::PlatformSpecific;
use iced::{Alignment, Background, Color, Element, Length, application};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PromptRequest {
    #[serde(alias = "t")]
    title: String,
    #[serde(default, alias = "hint", alias = "h")]
    hint: String,
    #[serde(default, alias = "msg", alias = "m")]
    message: String,
    #[serde(default, alias = "yes_text", alias = "yes_btn_text", alias = "yes")]
    confirm_text: Option<String>,
    #[serde(default, alias = "no_text", alias = "no_btn_text", alias = "no")]
    cancel_text: Option<String>,
    backend: String,
    #[serde(default)]
    theme: ThemeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default = "default_confirm_bg", alias = "ybg")]
    confirm_background: String,
    #[serde(default = "default_confirm_text", alias = "yt")]
    confirm_text: String,
    #[serde(default = "default_cancel_bg", alias = "nbg")]
    cancel_background: String,
    #[serde(default = "default_cancel_text", alias = "nt")]
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
            confirm_background: default_confirm_bg(),
            confirm_text: default_confirm_text(),
            cancel_background: default_cancel_bg(),
            cancel_text: default_cancel_text(),
            input_background: default_input_bg(),
            input_text: default_input_text(),
            font_size: default_font_size(),
        }
    }
}

fn default_background() -> String {
    "#1e1e2eff".to_string()
}

fn default_foreground() -> String {
    "#cdd6f4ff".to_string()
}

fn default_border() -> String {
    "#89b4faff".to_string()
}

fn default_border_width() -> f32 {
    2.0
}

fn default_font() -> String {
    "monospace".to_string()
}

fn default_label_color() -> String {
    "#a6adc8ff".to_string()
}

fn default_accent_color() -> String {
    "#7aa2f7ff".to_string()
}

fn default_confirm_bg() -> String {
    "".to_string()
}

fn default_confirm_text() -> String {
    "".to_string()
}

fn default_cancel_bg() -> String {
    "".to_string()
}

fn default_cancel_text() -> String {
    "".to_string()
}

fn default_input_bg() -> String {
    "#181825ff".to_string()
}

fn default_input_text() -> String {
    "#cdd6f4ff".to_string()
}

fn default_font_size() -> f32 {
    14.0
}

fn parse_color(value: &str, fallback: Color) -> Color {
    let value = value.trim();
    if let Some(color) = parse_hex_color(value) {
        return color;
    }
    fallback
}

fn parse_hex_color(value: &str) -> Option<Color> {
    Color::parse(value)
}

#[derive(Debug, Clone)]
enum Message {
    InputChanged(String),
    Confirm,
    Cancel,
}

#[derive(Debug)]
struct PromptApp {
    title: String,
    message: String,
    hint: String,
    confirm_label: String,
    cancel_label: String,
    input: String,
    theme: ThemeConfig,
    foreground: Color,
    background: Color,
    border: Color,
    label_color: Color,
    accent: Color,
    confirm_bg: Color,
    confirm_text: Color,
    cancel_bg: Color,
    cancel_text: Color,
    input_bg: Color,
    input_text: Color,
    font: iced::Font,
}

impl PromptApp {
    fn from_request(flags: PromptRequest) -> Self {
        let foreground = parse_color(&flags.theme.foreground, Color::WHITE);
        let background = parse_color(&flags.theme.background, Color::BLACK);
        let border = parse_color(&flags.theme.border_color, Color::WHITE);
        let label_color = parse_color(&flags.theme.label_color, foreground);
        let accent = parse_color(&flags.theme.accent_color, foreground);
        let confirm_bg = if flags.theme.confirm_background.trim().is_empty() {
            accent
        } else {
            parse_color(&flags.theme.confirm_background, accent)
        };
        let confirm_text = if flags.theme.confirm_text.trim().is_empty() {
            foreground
        } else {
            parse_color(&flags.theme.confirm_text, foreground)
        };
        let cancel_bg = if flags.theme.cancel_background.trim().is_empty() {
            darken(accent, 0.8)
        } else {
            parse_color(&flags.theme.cancel_background, darken(accent, 0.5))
        };
        let cancel_text = if flags.theme.cancel_text.trim().is_empty() {
            foreground
        } else {
            parse_color(&flags.theme.cancel_text, label_color)
        };
        let input_bg = parse_color(&flags.theme.input_background, background);
        let input_text = parse_color(&flags.theme.input_text, foreground);
        let font = font_from_string(&flags.theme.font_family);
        let hint = if flags.hint.trim().is_empty() {
            format!("Backend: {}", flags.backend)
        } else {
            flags.hint.clone()
        };
        let confirm_label = flags.confirm_text.unwrap_or_else(|| "Unlock".to_string());
        let cancel_label = flags.cancel_text.unwrap_or_else(|| "Cancel".to_string());
        Self {
            title: flags.title,
            message: flags.message,
            hint,
            confirm_label,
            cancel_label,
            input: String::new(),
            theme: flags.theme,
            foreground,
            background,
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

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();

    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: PromptRequest = if input.trim().is_empty() {
        PromptRequest {
            title: "Unlock backend".to_string(),
            hint: "".to_string(),
            message: "Enter your password".to_string(),
            confirm_text: None,
            cancel_text: None,
            backend: "backend".to_string(),
            theme: ThemeConfig::default(),
        }
    } else {
        match serde_json::from_str(&input) {
            Ok(request) => request,
            Err(err) => {
                eprintln!("invalid prompt request: {err}");
                std::process::exit(2);
            }
        }
    };

    application("rosec prompt", update, view)
        .window(iced::window::Settings {
            size: iced::Size::new(420.0, 210.0),
            resizable: false,
            decorations: false,
            transparent: true,
            platform_specific: PlatformSpecific {
                application_id: "rosec.prompt".to_string(),
                override_redirect: true,
            },
            ..Default::default()
        })
        .run_with(|| (PromptApp::from_request(request), iced::Task::none()))?;
    Ok(())
}

fn update(state: &mut PromptApp, message: Message) {
    match message {
        Message::InputChanged(value) => state.input = value,
        Message::Confirm => {
            println!("{}", state.input);
            std::process::exit(0);
        }
        Message::Cancel => std::process::exit(1),
    }
}

fn view(state: &PromptApp) -> Element<'_, Message> {
    let title_text = text(&state.title)
        .size(state.theme.font_size as u16 + 1)
        .color(state.foreground)
        .font(state.font);
    let title: Element<'_, Message> = if state.hint.trim().is_empty() {
        title_text.into()
    } else {
        iced::widget::tooltip(
            title_text,
            container(
                text(&state.hint)
                    .size(state.theme.font_size as u16)
                    .color(state.label_color)
                    .font(state.font),
            )
            .padding(6)
            .style(|_theme| container::Style {
                background: Some(Background::Color(state.background)),
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
    };
    let message = text(&state.message)
        .size(state.theme.font_size as u16)
        .color(state.label_color)
        .font(state.font);

    let input = text_input("Password", &state.input)
        .on_input(Message::InputChanged)
        .secure(true)
        .padding(10)
        .size(state.theme.font_size as u16)
        .font(state.font)
        .style(move |_theme, status| iced::widget::text_input::Style {
            background: Background::Color(state.input_bg),
            border: iced::Border {
                color: if status == iced::widget::text_input::Status::Focused {
                    state.accent
                } else {
                    state.border
                },
                width: 1.0,
                radius: 6.0.into(),
            },
            icon: state.label_color,
            placeholder: state.label_color,
            value: state.input_text,
            selection: state.accent,
        });

    let confirm = button(
        text(&state.confirm_label)
            .align_x(Horizontal::Center)
            .width(Length::Fill)
            .font(state.font),
    )
    .padding(8)
    .style(move |_theme, status| button_style(state.confirm_bg, state.confirm_text, status))
    .on_press(Message::Confirm);
    let cancel = button(
        text(&state.cancel_label)
            .align_x(Horizontal::Center)
            .width(Length::Fill)
            .font(state.font),
    )
    .padding(8)
    .style(move |_theme, status| button_style(state.cancel_bg, state.cancel_text, status))
    .on_press(Message::Cancel);

    let actions = row![confirm, cancel].spacing(10).align_y(Alignment::Center);

    let content = column![title, message, input, actions]
        .spacing(10)
        .padding(14)
        .align_x(Alignment::Start);

    container(content)
        .width(Length::Shrink)
        .padding(4)
        .style(move |_theme| container::Style {
            background: Some(Background::Color(state.background)),
            border: iced::Border {
                color: state.border,
                width: state.theme.border_width,
                radius: 8.0.into(),
            },
            text_color: None,
            shadow: iced::Shadow::default(),
        })
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
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

fn darken(color: Color, factor: f32) -> Color {
    let factor = factor.clamp(0.0, 1.0);
    Color {
        r: color.r * factor,
        g: color.g * factor,
        b: color.b * factor,
        a: color.a,
    }
}

fn button_style(
    bg: Color,
    text: Color,
    status: iced::widget::button::Status,
) -> iced::widget::button::Style {
    let base = iced::widget::button::Style {
        background: Some(Background::Color(bg)),
        text_color: text,
        border: iced::Border {
            color: bg,
            width: 0.0,
            radius: 6.0.into(),
        },
        shadow: iced::Shadow::default(),
    };
    match status {
        iced::widget::button::Status::Hovered => iced::widget::button::Style {
            background: Some(Background::Color(darken(bg, 0.9))),
            ..base
        },
        iced::widget::button::Status::Pressed => iced::widget::button::Style {
            background: Some(Background::Color(darken(bg, 0.8))),
            ..base
        },
        _ => base,
    }
}
