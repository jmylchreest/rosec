use std::collections::HashMap;

use serde::Serialize;

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
            backend: "bitwarden".to_string(),
        };
        let out = render_template("{{title}} {{backend}}", &ctx);
        assert_eq!(out, "Unlock bitwarden");
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
            backend: "bitwarden".to_string(),
        };
        let args = vec!["--hint={{backend}}".to_string()];
        let out = render_args(&args, &ctx);
        assert_eq!(out, vec!["--hint=bitwarden".to_string()]);
    }
}
