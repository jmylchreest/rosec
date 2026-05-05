//! Layout, measurement, and widget helpers shared across the three Iced apps
//! in this binary (regular prompt, TOTP display, QR scan).

use crate::request::ThemeConfig;

// ── Layout constants ─────────────────────────────────────────────────────

/// Outer/inner padding constants matching the `container().padding(4)` +
/// `column().padding(14)` pattern used by every prompt window.
pub(crate) const OUTER_PADDING: f32 = 4.0;
pub(crate) const INNER_PADDING: f32 = 14.0;

/// Usable content width for a window of `window_width`, after subtracting
/// outer + inner padding from both sides.
pub(crate) fn content_width(window_width: f32) -> f32 {
    window_width - (OUTER_PADDING + INNER_PADDING) * 2.0
}

/// Iced default line-height (`Relative(1.3)`) at the given font size.
pub(crate) fn line_height(font_size: f32) -> f32 {
    (font_size * 1.3).ceil()
}

// ── Text measurement ────────────────────────────────────────────────────

/// Cosmic-text driven exact-pixel text measurement, tied to one window's
/// theme + content width.
///
/// Holds the `FontSystem` and resolved `Family` once so we don't pay the
/// init cost per measurement call. Methods are named by *role* (`title`,
/// `body`, `body_small`) so call sites don't repeat the size/weight rules
/// — there's a single source of truth for "title is bold + 1, label is
/// normal − 1, etc."
pub(crate) struct TextMeasurer<'a> {
    font_system: cosmic_text::FontSystem,
    family: cosmic_text::Family<'a>,
    content_w: f32,
    base_size: f32,
}

impl<'a> TextMeasurer<'a> {
    pub(crate) fn new(theme: &'a ThemeConfig, content_w: f32) -> Self {
        Self {
            font_system: cosmic_text::FontSystem::new(),
            family: cosmic_font_family(&theme.font_family),
            content_w,
            base_size: theme.font_size,
        }
    }

    /// Title text: bold, base_size + 1. Empty string still occupies one line.
    pub(crate) fn title(&mut self, text: &str) -> f32 {
        self.measure(text, self.base_size + 1.0, cosmic_text::Weight::BOLD)
    }

    /// Body text at the base font size, normal weight. Empty input → 0.0.
    pub(crate) fn body(&mut self, text: &str) -> f32 {
        if text.is_empty() {
            return 0.0;
        }
        self.measure(text, self.base_size, cosmic_text::Weight::NORMAL)
    }

    /// Smaller body text (info / labels), normal weight. Empty input → 0.0.
    pub(crate) fn body_small(&mut self, text: &str) -> f32 {
        if text.trim().is_empty() {
            return 0.0;
        }
        self.measure(text, self.base_size - 1.0, cosmic_text::Weight::NORMAL)
    }

    fn measure(&mut self, text: &str, font_size: f32, weight: cosmic_text::Weight) -> f32 {
        let lh = line_height(font_size);
        let metrics = cosmic_text::Metrics::new(font_size, lh);
        let mut buffer = cosmic_text::Buffer::new(&mut self.font_system, metrics);
        buffer.set_size(&mut self.font_system, Some(self.content_w), None);
        let attrs = cosmic_text::Attrs::new().family(self.family).weight(weight);
        buffer.set_text(
            &mut self.font_system,
            text,
            attrs,
            cosmic_text::Shaping::Advanced,
        );
        buffer.shape_until_scroll(&mut self.font_system, false);

        // Sum the line_height of every layout run; one run per wrapped line.
        // Empty text still occupies a single line in iced's layout.
        buffer
            .layout_runs()
            .map(|r| r.line_height)
            .sum::<f32>()
            .max(lh)
    }
}

/// Map the theme's font_family string to a `cosmic_text::Family` value,
/// mirroring the iced `font_from_string` resolver below.
pub(crate) fn cosmic_font_family(name: &str) -> cosmic_text::Family<'_> {
    let name = name.trim();
    if name.eq_ignore_ascii_case("monospace") {
        return cosmic_text::Family::Monospace;
    }
    if name.eq_ignore_ascii_case("sans")
        || name.eq_ignore_ascii_case("sans-serif")
        || name.is_empty()
    {
        return cosmic_text::Family::SansSerif;
    }
    if name.eq_ignore_ascii_case("serif") {
        return cosmic_text::Family::Serif;
    }
    cosmic_text::Family::Name(name)
}

// ── Colour / font ───────────────────────────────────────────────────────

pub(crate) fn parse_color(value: &str, fallback: iced::Color) -> iced::Color {
    iced::Color::parse(value.trim()).unwrap_or(fallback)
}

pub(crate) fn font_from_string(name: &str) -> iced::Font {
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
        // `iced::Font::with_name` requires `&'static str`. Stash the name
        // in a process-wide OnceLock so the single allocation lives for
        // the lifetime of the process. rosec-prompt is short-lived; this
        // runs at most once.
        static FONT_NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let stored = FONT_NAME.get_or_init(|| name.to_string());
        return iced::Font::with_name(stored.as_str());
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

// ── Widget helpers ──────────────────────────────────────────────────────

pub(crate) fn button_style(
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

/// Render a TOTP code as individual digit boxes (pin-entry style).
pub(crate) fn pin_box_row<'a, M: 'a>(
    code: &str,
    font_size: u16,
    digit_color: iced::Color,
    box_bg: iced::Color,
    box_border: iced::Color,
) -> iced::Element<'a, M> {
    use iced::widget::{center, container, text};
    use iced::{Alignment, Background, Length};

    let mono = iced::Font {
        family: iced::font::Family::Name("monospace"),
        weight: iced::font::Weight::Bold,
        ..iced::Font::default()
    };
    let digit_size = font_size + 8;
    let box_size = (digit_size as f32 * 1.8).ceil();

    let digit_boxes: Vec<iced::Element<'_, M>> = code
        .chars()
        .map(|ch| {
            let digit = text(ch.to_string())
                .size(digit_size)
                .color(digit_color)
                .font(mono)
                .align_x(iced::alignment::Horizontal::Center)
                .align_y(iced::alignment::Vertical::Center);

            container(center(digit).width(box_size).height(box_size))
                .width(box_size)
                .height(box_size)
                .style(move |_| container::Style {
                    background: Some(Background::Color(box_bg)),
                    border: iced::Border {
                        color: box_border,
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    text_color: None,
                    shadow: iced::Shadow::default(),
                })
                .into()
        })
        .collect();

    iced::widget::Row::with_children(digit_boxes)
        .spacing(6)
        .align_y(Alignment::Center)
        .width(Length::Shrink)
        .into()
}

// ── Inline rich-text spans ──────────────────────────────────────────────

/// Parse a string with `**bold**` and `_italic_` markers into iced rich_text spans.
///
/// Generic over the message type so the same parser feeds any iced app's
/// `Element<M>`.
///
/// `**` is greedy — first occurrence opens, next occurrence closes.
/// `_` is word-boundary delimited so paths like `/usr/share/signal_desktop`
/// and identifiers like `OAUTH_CLIENT_ID` don't get accidentally italicised.
pub(crate) fn parse_styled_spans<'a, M: 'a>(
    input: &str,
    size: u16,
    normal_color: iced::Color,
    emphasis_color: iced::Color,
    base_font: iced::Font,
) -> Vec<iced::widget::text::Span<'a, M>> {
    let bold_font = iced::Font {
        weight: iced::font::Weight::Bold,
        ..base_font
    };
    let italic_font = iced::Font {
        style: iced::font::Style::Italic,
        ..base_font
    };

    let mut spans = Vec::new();
    let mut rest = input;

    while !rest.is_empty() {
        let bold_pos = rest
            .find("**")
            .and_then(|start| rest[start + 2..].find("**").map(|end| (start, end)));
        let ital_pos = find_italic_pair(rest);

        let next = match (bold_pos, ital_pos) {
            (Some((bs, _)), Some((is, _))) => {
                if bs <= is {
                    Some(("bold", bs))
                } else {
                    Some(("italic", is))
                }
            }
            (Some((bs, _)), None) => Some(("bold", bs)),
            (None, Some((is, _))) => Some(("italic", is)),
            (None, None) => None,
        };

        match next {
            Some(("bold", start)) => {
                let end = rest[start + 2..].find("**").unwrap();
                if start > 0 {
                    spans.push(
                        iced::widget::text::Span::new(rest[..start].to_string())
                            .size(size)
                            .color(normal_color)
                            .font(base_font),
                    );
                }
                let content = &rest[start + 2..start + 2 + end];
                spans.push(
                    iced::widget::text::Span::new(content.to_string())
                        .size(size)
                        .color(emphasis_color)
                        .font(bold_font),
                );
                rest = &rest[start + 2 + end + 2..];
            }
            Some(("italic", start)) => {
                let (_, close) = find_italic_pair(rest).unwrap();
                if start > 0 {
                    spans.push(
                        iced::widget::text::Span::new(rest[..start].to_string())
                            .size(size)
                            .color(normal_color)
                            .font(base_font),
                    );
                }
                let content = &rest[start + 1..close];
                spans.push(
                    iced::widget::text::Span::new(content.to_string())
                        .size(size)
                        .color(normal_color)
                        .font(italic_font),
                );
                rest = &rest[close + 1..];
            }
            _ => {
                spans.push(
                    iced::widget::text::Span::new(rest.to_string())
                        .size(size)
                        .color(normal_color)
                        .font(base_font),
                );
                break;
            }
        }
    }

    spans
}

/// Find a `_` opener that sits at a word boundary (preceded by start-of-string
/// or whitespace, followed by non-whitespace) and a matching closer (preceded
/// by non-whitespace, followed by end-of-string or whitespace). Returns the
/// byte offsets of the pair.
fn find_italic_pair(s: &str) -> Option<(usize, usize)> {
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'_' {
            continue;
        }
        let at_start = i == 0 || bytes[i - 1].is_ascii_whitespace();
        let next_non_ws = i + 1 < bytes.len() && !bytes[i + 1].is_ascii_whitespace();
        if !(at_start && next_non_ws) {
            continue;
        }
        for j in (i + 2)..bytes.len() {
            if bytes[j] != b'_' {
                continue;
            }
            let prev_non_ws = !bytes[j - 1].is_ascii_whitespace();
            let at_end = j + 1 == bytes.len() || bytes[j + 1].is_ascii_whitespace();
            if prev_non_ws && at_end {
                return Some((i, j));
            }
        }
    }
    None
}
