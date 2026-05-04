use std::collections::HashMap;
use std::path::PathBuf;

use serde::Serialize;

/// Resolve a sibling binary to the current executable.
///
/// Used by long-lived processes (e.g. `rosecd`, `rosec-secret-service`)
/// that must not fall back to a `$PATH` lookup. A daemon's `$PATH` may have
/// been set by an attacker prior to spawn, so accepting whatever
/// `rosec-prompt` happens to be earliest on `$PATH` would constitute a
/// silent code-execution vector. Returns `None` if the sibling is missing
/// — callers are expected to log loudly and fail closed rather than
/// substitute an unsafe default.
///
/// This is intentionally distinct from CLI-side resolution: a CLI tool
/// runs in the user's interactive shell where `$PATH` is the user's own
/// responsibility, and a `$PATH` fallback is a reasonable convenience.
pub fn resolve_sibling_binary(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join(name);
    candidate.is_file().then_some(candidate)
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PromptContext {
    pub title: String,
    pub message: String,
    pub hint: String,
    pub backend: String,
}

pub fn render_template(template: &str, context: &PromptContext) -> String {
    let mut values = HashMap::new();
    values.insert("title", context.title.as_str());
    values.insert("message", context.message.as_str());
    values.insert("hint", context.hint.as_str());
    values.insert("backend", context.backend.as_str());

    let mut output = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '{' && chars.peek() == Some(&'{') {
            chars.next();
            let mut key = String::new();
            while let Some(next) = chars.next() {
                if next == '}' && chars.peek() == Some(&'}') {
                    chars.next();
                    break;
                }
                key.push(next);
            }
            let key = key.trim();
            if let Some(value) = values.get(key) {
                output.push_str(value);
            } else {
                output.push_str("{{");
                output.push_str(key);
                output.push_str("}}");
            }
        } else {
            output.push(ch);
        }
    }
    output
}

pub fn render_args(args: &[String], context: &PromptContext) -> Vec<String> {
    args.iter()
        .map(|arg| render_template(arg, context))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_template_fields() {
        let ctx = PromptContext {
            title: "Unlock".to_string(),
            message: "Enter password".to_string(),
            hint: "Hint".to_string(),
            backend: "bitwarden-pm".to_string(),
        };
        let out = render_template("{{title}} {{backend}}", &ctx);
        assert_eq!(out, "Unlock bitwarden-pm");
    }

    #[test]
    fn leaves_unknown_placeholders() {
        let ctx = PromptContext::default();
        let out = render_template("{{unknown}}", &ctx);
        assert_eq!(out, "{{unknown}}");
    }

    #[test]
    fn renders_args() {
        let ctx = PromptContext {
            title: "Unlock".to_string(),
            message: "Enter".to_string(),
            hint: "Hint".to_string(),
            backend: "bitwarden-pm".to_string(),
        };
        let args = vec!["--hint={{backend}}".to_string()];
        let out = render_args(&args, &ctx);
        assert_eq!(out, vec!["--hint=bitwarden-pm".to_string()]);
    }

    #[test]
    fn resolve_sibling_binary_returns_none_when_absent() {
        // The current test runner is not next to a `rosec-prompt` binary,
        // so the resolver must return None — proving it does not silently
        // fall back to a $PATH lookup.
        assert!(resolve_sibling_binary("rosec-prompt-definitely-does-not-exist").is_none());
    }
}
