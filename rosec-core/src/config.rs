use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{AutoLockPolicy, DedupStrategy, DedupTimeFallback};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub service: ServiceConfig,
    #[serde(default)]
    pub autolock: AutoLockPolicy,
    #[serde(default)]
    pub prompt: PromptConfig,
    #[serde(default)]
    pub backend: Vec<BackendEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    #[serde(default = "default_dedup_strategy")]
    pub dedup_strategy: DedupStrategy,
    #[serde(default = "default_dedup_time_fallback")]
    pub dedup_time_fallback: DedupTimeFallback,
    #[serde(default)]
    pub refresh_interval_secs: Option<u64>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            dedup_strategy: default_dedup_strategy(),
            dedup_time_fallback: default_dedup_time_fallback(),
            refresh_interval_secs: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptConfig {
    #[serde(default = "default_prompt_backend")]
    pub backend: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub theme: PromptTheme,
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self {
            backend: default_prompt_backend(),
            args: Vec::new(),
            theme: PromptTheme::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptTheme {
    #[serde(default = "default_color_background", alias = "bg")]
    pub background: String,
    #[serde(default = "default_color_foreground", alias = "fg")]
    pub foreground: String,
    #[serde(default = "default_color_border", alias = "bd", alias = "bdr")]
    pub border_color: String,
    #[serde(default = "default_border_width", alias = "bw")]
    pub border_width: u16,
    #[serde(default = "default_font_family", alias = "font")]
    pub font_family: String,
    #[serde(default = "default_label_color", alias = "lc")]
    pub label_color: String,
    #[serde(default = "default_accent_color", alias = "ac")]
    pub accent_color: String,
    #[serde(default = "default_confirm_bg", alias = "ybg")]
    pub confirm_background: String,
    #[serde(default = "default_confirm_text", alias = "yt")]
    pub confirm_text: String,
    #[serde(default = "default_cancel_bg", alias = "nbg")]
    pub cancel_background: String,
    #[serde(default = "default_cancel_text", alias = "nt")]
    pub cancel_text: String,
    #[serde(default = "default_input_bg", alias = "ibg")]
    pub input_background: String,
    #[serde(default = "default_input_text", alias = "it")]
    pub input_text: String,
    #[serde(default = "default_font_size", alias = "size")]
    pub font_size: u16,
}

impl Default for PromptTheme {
    fn default() -> Self {
        Self {
            background: default_color_background(),
            foreground: default_color_foreground(),
            border_color: default_color_border(),
            border_width: default_border_width(),
            font_family: default_font_family(),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendEntry {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub options: HashMap<String, serde_json::Value>,
}

impl Default for AutoLockPolicy {
    fn default() -> Self {
        Self {
            on_logout: true,
            on_session_lock: true,
            idle_timeout_minutes: Some(15),
            max_unlocked_minutes: Some(240),
        }
    }
}

fn default_dedup_strategy() -> DedupStrategy {
    DedupStrategy::Newest
}

fn default_dedup_time_fallback() -> DedupTimeFallback {
    DedupTimeFallback::Created
}

fn default_prompt_backend() -> String {
    "builtin".to_string()
}

fn default_color_background() -> String {
    "#1e1e2eff".to_string()
}

fn default_color_foreground() -> String {
    "#cdd6f4ff".to_string()
}

fn default_color_border() -> String {
    "#89b4faff".to_string()
}

fn default_border_width() -> u16 {
    2
}

fn default_font_family() -> String {
    "monospace".to_string()
}

fn default_font_size() -> u16 {
    14
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_toml_gives_defaults() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.service.dedup_strategy, DedupStrategy::Newest);
        assert_eq!(cfg.service.dedup_time_fallback, DedupTimeFallback::Created);
        assert!(cfg.service.refresh_interval_secs.is_none());
        assert_eq!(cfg.prompt.backend, "builtin");
        assert!(cfg.prompt.args.is_empty());
        assert!(cfg.backend.is_empty());
        assert!(cfg.autolock.on_logout);
        assert!(cfg.autolock.on_session_lock);
        assert_eq!(cfg.autolock.idle_timeout_minutes, Some(15));
        assert_eq!(cfg.autolock.max_unlocked_minutes, Some(240));
    }

    #[test]
    fn parse_service_section() {
        let toml_str = r#"
            [service]
            dedup_strategy = "priority"
            dedup_time_fallback = "none"
            refresh_interval_secs = 120
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.service.dedup_strategy, DedupStrategy::Priority);
        assert_eq!(cfg.service.dedup_time_fallback, DedupTimeFallback::None);
        assert_eq!(cfg.service.refresh_interval_secs, Some(120));
    }

    #[test]
    fn parse_backend_entries() {
        let toml_str = r#"
            [[backend]]
            id = "bw1"
            type = "bitwarden"

            [backend.options]
            email = "test@example.com"
            base_url = "https://vault.example.com"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.backend.len(), 1);
        assert_eq!(cfg.backend[0].id, "bw1");
        assert_eq!(cfg.backend[0].kind, "bitwarden");
        assert_eq!(
            cfg.backend[0].options.get("email").and_then(|v| v.as_str()),
            Some("test@example.com")
        );
        assert_eq!(
            cfg.backend[0]
                .options
                .get("base_url")
                .and_then(|v| v.as_str()),
            Some("https://vault.example.com")
        );
    }

    #[test]
    fn parse_prompt_theme_defaults() {
        let cfg: Config = toml::from_str("").unwrap();
        let theme = &cfg.prompt.theme;
        assert_eq!(theme.background, "#1e1e2eff");
        assert_eq!(theme.foreground, "#cdd6f4ff");
        assert_eq!(theme.border_color, "#89b4faff");
        assert_eq!(theme.border_width, 2);
        assert_eq!(theme.font_family, "monospace");
        assert_eq!(theme.font_size, 14);
        assert_eq!(theme.input_background, "#181825ff");
        assert_eq!(theme.input_text, "#cdd6f4ff");
        // Confirm/cancel default to empty (meaning "use accent/fg")
        assert!(theme.confirm_background.is_empty());
        assert!(theme.confirm_text.is_empty());
        assert!(theme.cancel_background.is_empty());
        assert!(theme.cancel_text.is_empty());
    }

    #[test]
    fn parse_prompt_theme_overrides() {
        let toml_str = r##"
            [prompt.theme]
            background = "#000000ff"
            font_size = 20
            border_width = 4
        "##;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        let theme = &cfg.prompt.theme;
        assert_eq!(theme.background, "#000000ff");
        assert_eq!(theme.font_size, 20);
        assert_eq!(theme.border_width, 4);
        // Other fields keep defaults
        assert_eq!(theme.foreground, "#cdd6f4ff");
    }

    #[test]
    fn parse_prompt_theme_aliases() {
        let toml_str = r##"
            [prompt.theme]
            bg = "#111111ff"
            fg = "#eeeeeeff"
            bw = 5
            size = 18
        "##;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        let theme = &cfg.prompt.theme;
        assert_eq!(theme.background, "#111111ff");
        assert_eq!(theme.foreground, "#eeeeeeff");
        assert_eq!(theme.border_width, 5);
        assert_eq!(theme.font_size, 18);
    }

    #[test]
    fn config_roundtrip_serialize() {
        let cfg = Config::default();
        let serialized = toml::to_string(&cfg).unwrap();
        let deserialized: Config = toml::from_str(&serialized).unwrap();
        assert_eq!(
            deserialized.service.dedup_strategy,
            cfg.service.dedup_strategy
        );
        assert_eq!(deserialized.prompt.backend, cfg.prompt.backend);
        assert_eq!(
            deserialized.prompt.theme.font_size,
            cfg.prompt.theme.font_size
        );
    }

    #[test]
    fn multiple_backends() {
        let toml_str = r#"
            [[backend]]
            id = "bw1"
            type = "bitwarden"

            [[backend]]
            id = "bw2"
            type = "bitwarden"

            [backend.options]
            email = "other@example.com"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.backend.len(), 2);
        assert_eq!(cfg.backend[0].id, "bw1");
        assert_eq!(cfg.backend[1].id, "bw2");
    }

    #[test]
    fn autolock_custom_values() {
        let toml_str = r#"
            [autolock]
            on_logout = false
            on_session_lock = false
            idle_timeout_minutes = 30
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(!cfg.autolock.on_logout);
        assert!(!cfg.autolock.on_session_lock);
        assert_eq!(cfg.autolock.idle_timeout_minutes, Some(30));
        // max_unlocked_minutes not set — depends on Default impl
    }
}
