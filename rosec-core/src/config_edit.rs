//! Structure-preserving edits to `config.toml`.
//!
//! Uses `toml_edit` so that existing comments, formatting, and unrelated
//! sections are left untouched when adding or removing backend entries.

use std::path::Path;

use anyhow::{Context, Result, bail};
use toml_edit::{DocumentMut, Item, Table, value};

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

    // Separate top-level fields ("collection") from backend options.
    // "collection" is written as a top-level key, not inside [options].
    let collection: Option<&str> = options
        .iter()
        .find(|(k, _)| k == "collection")
        .map(|(_, v)| v.as_str());
    let backend_options: Vec<_> = options.iter().filter(|(k, _)| k != "collection").collect();

    // Build the new table entry.
    let mut entry = Table::new();
    entry.set_implicit(false);
    entry["id"] = value(id);
    entry["type"] = value(kind);

    if let Some(col) = collection {
        entry["collection"] = value(col);
    }

    if !backend_options.is_empty() {
        let mut opts = Table::new();
        for (k, v) in &backend_options {
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
        "bitwarden-sm" => &[("organization_id", "Organization UUID")],
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
            (
                "collection",
                "Label stamped on all items as the 'collection' attribute (e.g. 'work')",
            ),
        ],
        "bitwarden-sm" => &[
            ("region", "Cloud region: 'us' or 'eu' (default: us)"),
            ("server_url", "Self-hosted server URL (overrides region)"),
            (
                "collection",
                "Label stamped on all items as the 'collection' attribute (e.g. 'work')",
            ),
        ],
        _ => &[],
    }
}

/// The list of backend type strings the daemon knows about.
pub const KNOWN_KINDS: &[&str] = &["bitwarden", "bitwarden-sm"];

/// Set a single dotted-path value in the config file.
///
/// The key must be of the form `"section.field"` (exactly one dot).
/// The file is created if it does not exist.  Existing comments and
/// unrelated sections are preserved via `toml_edit`.
///
/// `value_str` is always written as the appropriate TOML type:
/// - `"true"` / `"false"` → boolean
/// - All-digit string → integer
/// - Anything else → string
pub fn set_value(config_path: &Path, key: &str, value_str: &str) -> Result<()> {
    let (section, field) = key
        .split_once('.')
        .with_context(|| format!("key must be 'section.field', got: {key}"))?;

    let raw = read_or_empty(config_path)?;
    let mut doc: DocumentMut = raw.parse().context("failed to parse config as TOML")?;

    // Ensure the section table exists.
    let table = doc
        .entry(section)
        .or_insert_with(|| {
            let mut t = toml_edit::Table::new();
            t.set_implicit(false);
            Item::Table(t)
        })
        .as_table_mut()
        .with_context(|| format!("'{section}' exists but is not a table"))?;

    // Parse the value into the most specific TOML type.
    let item = parse_toml_value(value_str);
    table[field] = item;

    write_doc(config_path, &doc)
}

/// Parse a string into a `toml_edit::Item`, choosing the most specific type.
fn parse_toml_value(s: &str) -> Item {
    match s {
        "true" => value(true),
        "false" => value(false),
        s if s.parse::<i64>().is_ok() => value(s.parse::<i64>().unwrap()),
        s => value(s),
    }
}

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
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    // Write with mode 0o600 on creation so the file is never world- or
    // group-readable regardless of the process umask.  If the file already
    // exists its permissions are left unchanged.
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, doc.to_string().as_bytes()))
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
