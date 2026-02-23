//! Structure-preserving edits to `config.toml`.
//!
//! Uses `toml_edit` so that existing comments, formatting, and unrelated
//! sections are left untouched when adding or removing backend entries.

use std::path::Path;

use anyhow::{bail, Context, Result};
use toml_edit::{value, DocumentMut, Item, Table};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Add a new `[[backend]]` entry to the config file.
///
/// `id` must be unique within the file; returns an error if it is already
/// present.  `kind` is the backend type string (e.g. `"bitwarden"`).
/// `options` is a list of `key=value` pairs stored under `[backend.options]`.
pub fn add_backend(
    config_path: &Path,
    id: &str,
    kind: &str,
    options: &[(String, String)],
) -> Result<()> {
    let raw = read_or_empty(config_path)?;
    let mut doc: DocumentMut = raw.parse().context("failed to parse config as TOML")?;

    // Reject duplicate IDs.
    if backend_ids(&doc).any(|existing| existing == id) {
        bail!("backend '{id}' already exists in {}", config_path.display());
    }

    // Build the new table entry.
    let mut entry = Table::new();
    entry.set_implicit(false);
    entry["id"] = value(id);
    entry["type"] = value(kind);

    if !options.is_empty() {
        let mut opts = Table::new();
        for (k, v) in options {
            opts[k.as_str()] = value(v.as_str());
        }
        entry["options"] = Item::Table(opts);
    }

    // Append to the `backend` array-of-tables.
    let backends = doc
        .entry("backend")
        .or_insert_with(|| Item::ArrayOfTables(toml_edit::ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .context("`backend` key is not an array-of-tables")?;

    backends.push(entry);

    write_doc(config_path, &doc)
}

/// Remove a `[[backend]]` entry by id.
///
/// Returns an error if no entry with that id exists.
pub fn remove_backend(config_path: &Path, id: &str) -> Result<()> {
    let raw = read_or_empty(config_path)?;
    let mut doc: DocumentMut = raw.parse().context("failed to parse config as TOML")?;

    let backends = match doc
        .get_mut("backend")
        .and_then(|item| item.as_array_of_tables_mut())
    {
        Some(b) => b,
        None => bail!("no backends configured in {}", config_path.display()),
    };

    let before = backends.len();
    // toml_edit ArrayOfTables doesn't have retain(); rebuild by index.
    let indices_to_remove: Vec<usize> = (0..backends.len())
        .filter(|&i| {
            backends
                .get(i)
                .and_then(|t| t.get("id"))
                .and_then(|v| v.as_str())
                == Some(id)
        })
        .collect();

    if indices_to_remove.is_empty() {
        bail!("backend '{id}' not found in {}", config_path.display());
    }

    // Remove in reverse order so earlier indices stay valid.
    for i in indices_to_remove.into_iter().rev() {
        backends.remove(i);
    }

    let after = backends.len();

    // If the array is now empty, remove the key entirely so the file stays clean.
    if after == 0 {
        doc.remove("backend");
    }

    tracing::debug!(
        removed = before - after,
        config = %config_path.display(),
        "removed backend '{id}' from config"
    );

    write_doc(config_path, &doc)
}

/// Return the known required option keys for a given backend type.
///
/// Used by `rosec backend add` to prompt for missing options interactively.
pub fn required_options_for_kind(kind: &str) -> &'static [(&'static str, &'static str)] {
    match kind {
        "bitwarden" => &[("email", "Bitwarden account email")],
        "bitwarden-sm" => &[
            ("access_token", "Machine account access token"),
            ("organization_id", "Organization UUID"),
        ],
        _ => &[],
    }
}

/// Return the optional option keys for a given backend type.
pub fn optional_options_for_kind(kind: &str) -> &'static [(&'static str, &'static str)] {
    match kind {
        "bitwarden" => &[
            ("region", "Cloud region: 'us' or 'eu' (default: us)"),
            (
                "base_url",
                "Self-hosted base URL, e.g. https://vault.example.com",
            ),
            (
                "api_url",
                "Explicit API URL override (overrides region/base_url)",
            ),
            (
                "identity_url",
                "Explicit identity URL override (overrides region/base_url)",
            ),
        ],
        "bitwarden-sm" => &[(
            "server_url",
            "Self-hosted server URL (leave blank for official cloud)",
        )],
        _ => &[],
    }
}

/// The list of backend type strings the daemon knows about.
pub const KNOWN_KINDS: &[&str] = &["bitwarden", "bitwarden-sm"];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_or_empty(path: &Path) -> Result<String> {
    if path.exists() {
        std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
    } else {
        Ok(String::new())
    }
}

fn write_doc(path: &Path, doc: &DocumentMut) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    std::fs::write(path, doc.to_string())
        .with_context(|| format!("failed to write {}", path.display()))
}

fn backend_ids(doc: &DocumentMut) -> impl Iterator<Item = &str> {
    doc.get("backend")
        .and_then(|item| item.as_array_of_tables())
        .into_iter()
        .flat_map(|aot| aot.iter())
        .filter_map(|t| t.get("id")?.as_str())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn add_backend_creates_file() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_backend(
            &path,
            "bw1",
            "bitwarden",
            &[("email".into(), "a@b.com".into())],
        )
        .unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("id = \"bw1\""));
        assert!(contents.contains("type = \"bitwarden\""));
        assert!(contents.contains("email = \"a@b.com\""));
    }

    #[test]
    fn add_backend_rejects_duplicate_id() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_backend(&path, "bw1", "bitwarden", &[]).unwrap();
        let err = add_backend(&path, "bw1", "bitwarden", &[]).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn add_multiple_backends_same_kind() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_backend(
            &path,
            "bw1",
            "bitwarden",
            &[("email".into(), "a@b.com".into())],
        )
        .unwrap();
        add_backend(
            &path,
            "bw2",
            "bitwarden",
            &[("email".into(), "b@b.com".into())],
        )
        .unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("id = \"bw1\""));
        assert!(contents.contains("id = \"bw2\""));
    }

    #[test]
    fn remove_backend_by_id() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_backend(&path, "bw1", "bitwarden", &[]).unwrap();
        add_backend(&path, "bw2", "bitwarden", &[]).unwrap();
        remove_backend(&path, "bw1").unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("id = \"bw1\""));
        assert!(contents.contains("id = \"bw2\""));
    }

    #[test]
    fn remove_last_backend_cleans_key() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_backend(&path, "bw1", "bitwarden", &[]).unwrap();
        remove_backend(&path, "bw1").unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("bw1"));
        assert!(!contents.contains("[[backend]]"));
    }

    #[test]
    fn remove_nonexistent_backend_errors() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        let err = remove_backend(&path, "ghost").unwrap_err();
        assert!(err.to_string().contains("not found") || err.to_string().contains("no backends"));
    }

    #[test]
    fn preserves_existing_content() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "# my comment\n[service]\ndedup_strategy = \"priority\"\n",
        )
        .unwrap();
        add_backend(&path, "bw1", "bitwarden", &[]).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("# my comment"));
        assert!(contents.contains("dedup_strategy = \"priority\""));
        assert!(contents.contains("id = \"bw1\""));
    }
}
