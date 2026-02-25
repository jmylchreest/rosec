//! Filename normalisation helpers.
//!
//! Converts vault item names and host patterns to safe FUSE filenames.

/// Normalise a vault item name to a safe config filename stem.
///
/// Rules:
/// - Lowercased
/// - Spaces → `_`
/// - Any non-alphanumeric, non-`_`, non-`-`, non-`.` character → `_`
/// - Leading `.` → `_dot` prefix (not `_dot_`)
/// - Consecutive `_` are collapsed to a single `_`
/// - Trailing `_` stripped
///
/// # Examples
/// ```
/// # use rosec_fuse::naming::normalise_item_name;
/// assert_eq!(normalise_item_name("My Server One.two"), "my_server_one_two");
/// assert_eq!(normalise_item_name("GitHub SSH Key"), "github_ssh_key");
/// assert_eq!(normalise_item_name(".hidden"), "_dothidden");
/// assert_eq!(normalise_item_name("key!@#$%"), "key");
/// ```
pub fn normalise_item_name(name: &str) -> String {
    let lower = name.to_lowercase();
    let mut result = String::with_capacity(lower.len());

    for ch in lower.chars() {
        if ch.is_alphanumeric() || ch == '-' {
            result.push(ch);
        } else {
            // Replace any separator/punctuation with underscore
            result.push('_');
        }
    }

    // Handle leading dot: replace leading '_' (from '.') with '_dot'
    let result = if name.starts_with('.') {
        format!("_dot{}", result.trim_start_matches('_'))
    } else {
        result
    };

    // Collapse consecutive underscores
    let mut collapsed = String::with_capacity(result.len());
    let mut last_was_underscore = false;
    for ch in result.chars() {
        if ch == '_' {
            if !last_was_underscore {
                collapsed.push('_');
            }
            last_was_underscore = true;
        } else {
            collapsed.push(ch);
            last_was_underscore = false;
        }
    }

    // Strip trailing underscores only.  Leading underscores are meaningful
    // (e.g. `_dot` prefix for items starting with `.`).
    let trimmed = collapsed.trim_end_matches('_').to_string();

    if trimmed.is_empty() || trimmed == "_" {
        "unnamed".to_string()
    } else {
        trimmed
    }
}

/// Sanitise a string for use as a FUSE filename.
///
/// Replaces characters that are illegal or problematic in filenames:
/// `/` (path separator), `\0` (C string terminator), and `:` (can
/// confuse shell tab-completion and some tools).  Whitespace around
/// the result is trimmed and interior runs of whitespace are collapsed.
///
/// This is a *light* sanitiser — it preserves case, hyphens, dots, and
/// most punctuation.  Use [`normalise_item_name`] when a fully-normalised
/// slug is needed (e.g. `config.d/` snippet filenames).
///
/// # Examples
/// ```
/// # use rosec_fuse::naming::sanitise_filename;
/// assert_eq!(sanitise_filename("home-lab: nuc/proxmox"), "home-lab_ nuc_proxmox");
/// assert_eq!(sanitise_filename("SHA256:/t6lSY/foo"), "SHA256__t6lSY_foo");
/// ```
pub fn sanitise_filename(s: &str) -> String {
    let replaced: String = s
        .chars()
        .map(|c| match c {
            '/' | '\0' | ':' => '_',
            _ => c,
        })
        .collect();
    // Collapse interior whitespace runs and trim.
    replaced.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Normalise an OpenSSH host pattern for use as a filename.
///
/// Substitutions:
/// - `*` → `_star`
/// - `?` → `_qmark`
/// - `/` → `_`
/// - Null bytes → removed
///
/// # Examples
/// ```
/// # use rosec_fuse::naming::normalise_host_pattern;
/// assert_eq!(normalise_host_pattern("github.com"), "github.com");
/// assert_eq!(normalise_host_pattern("*.prod.example.com"), "_star.prod.example.com");
/// assert_eq!(normalise_host_pattern("192.168.?.1"), "192.168._qmark.1");
/// ```
pub fn normalise_host_pattern(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len() + 8);
    for ch in pattern.chars() {
        match ch {
            '*' => result.push_str("_star"),
            '?' => result.push_str("_qmark"),
            '/' => result.push('_'),
            '\0' => {} // drop null bytes
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_item_name_basic() {
        assert_eq!(
            normalise_item_name("My Server One.two"),
            "my_server_one_two"
        );
        assert_eq!(normalise_item_name("GitHub SSH Key"), "github_ssh_key");
        assert_eq!(
            normalise_item_name("Production Server"),
            "production_server"
        );
    }

    #[test]
    fn normalise_item_name_leading_dot() {
        assert_eq!(normalise_item_name(".hidden"), "_dothidden");
    }

    #[test]
    fn normalise_item_name_special_chars() {
        assert_eq!(normalise_item_name("key!@#$%"), "key");
    }

    #[test]
    fn normalise_item_name_empty() {
        assert_eq!(normalise_item_name("!@#"), "unnamed");
    }

    #[test]
    fn normalise_host_pattern_wildcard() {
        assert_eq!(
            normalise_host_pattern("*.prod.example.com"),
            "_star.prod.example.com"
        );
        assert_eq!(normalise_host_pattern("192.168.?.1"), "192.168._qmark.1");
    }

    #[test]
    fn normalise_host_pattern_plain() {
        assert_eq!(normalise_host_pattern("github.com"), "github.com");
    }
}
