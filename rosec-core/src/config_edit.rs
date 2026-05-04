//! Structure-preserving edits to `config.toml`.
//!
//! Uses `toml_edit` so that existing comments, formatting, and unrelated
//! sections are left untouched when adding or removing provider entries.

use std::path::Path;

use anyhow::{Context, Result, bail};
use toml_edit::{DocumentMut, Item, Table, value};

/// Add a new `[[provider]]` entry to the config file.
///
/// `id` must be unique within the file; returns an error if it is already
/// present.  `kind` is the provider type string (e.g. `"bitwarden-pm"`,
/// `"bitwarden-sm"`, `"local"`).
///
/// For `kind = "local"`, `path` should be provided as an option with key
/// `"path"`.  The `"path"` and `"collection"` keys are written as top-level
/// fields on the provider entry; all other options go under `[provider.options]`.
pub fn add_provider(
    config_path: &Path,
    id: &str,
    kind: &str,
    options: &[(String, String)],
) -> Result<()> {
    let raw = read_or_empty(config_path)?;
    let mut doc: DocumentMut = raw.parse().context("failed to parse config as TOML")?;

    if provider_ids(&doc).any(|existing| existing == id) {
        bail!(
            "provider '{id}' already exists in {}",
            config_path.display()
        );
    }

    // Top-level fields that go directly on the provider entry, not in [options].
    const TOP_LEVEL_KEYS: &[&str] = &["collection", "path"];

    let collection: Option<&str> = options
        .iter()
        .find(|(k, _)| k == "collection")
        .map(|(_, v)| v.as_str());
    let path: Option<&str> = options
        .iter()
        .find(|(k, _)| k == "path")
        .map(|(_, v)| v.as_str());
    let provider_options: Vec<_> = options
        .iter()
        .filter(|(k, _)| !TOP_LEVEL_KEYS.contains(&k.as_str()))
        .collect();

    let mut entry = Table::new();
    entry.set_implicit(false);
    entry["id"] = value(id);
    entry["kind"] = value(kind);

    if let Some(p) = path {
        entry["path"] = value(p);
    }

    if let Some(col) = collection {
        entry["collection"] = value(col);
    }

    if !provider_options.is_empty() {
        let mut opts = Table::new();
        for (k, v) in &provider_options {
            opts[k.as_str()] = value(v.as_str());
        }
        entry["options"] = Item::Table(opts);
    }

    let providers = doc
        .entry("provider")
        .or_insert_with(|| Item::ArrayOfTables(toml_edit::ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .context("`provider` key is not an array-of-tables")?;

    providers.push(entry);

    write_doc(config_path, &doc)
}

/// Remove a `[[provider]]` entry by id.
///
/// Returns an error if no entry with that id exists.
pub fn remove_provider(config_path: &Path, id: &str) -> Result<()> {
    let raw = read_or_empty(config_path)?;
    let mut doc: DocumentMut = raw.parse().context("failed to parse config as TOML")?;
    remove_array_entry(&mut doc, "provider", id, config_path)?;
    write_doc(config_path, &doc)
}

/// Enable or disable a `[[provider]]` entry by id.
///
/// When `enabled` is `true` the field is removed from the entry entirely
/// (it defaults to true when absent), keeping the common case clean.
/// When `false`, the field is set explicitly.
pub fn set_provider_enabled(config_path: &Path, id: &str, enabled: bool) -> Result<()> {
    let raw = read_or_empty(config_path)?;
    let mut doc: DocumentMut = raw.parse().context("failed to parse config as TOML")?;

    let array = doc
        .get_mut("provider")
        .and_then(|item| item.as_array_of_tables_mut())
        .with_context(|| format!("no providers configured in {}", config_path.display()))?;

    let idx = (0..array.len()).find(|&i| {
        array
            .get(i)
            .and_then(|t| t.get("id"))
            .and_then(|v| v.as_str())
            == Some(id)
    });

    let Some(idx) = idx else {
        bail!("provider '{id}' not found in {}", config_path.display());
    };

    let table = array
        .get_mut(idx)
        .context("provider entry disappeared unexpectedly")?;
    if enabled {
        table.remove("enabled");
    } else {
        table["enabled"] = value(false);
    }

    write_doc(config_path, &doc)
}

/// Return the known required option keys for a given provider kind.
///
/// Used by `rosec provider add` to prompt for missing options interactively.
/// Only covers built-in kinds; discovered WASM plugin kinds get their
/// requirements from the plugin manifest (see `PluginRegistry`).
pub fn required_options_for_kind(_kind: &str) -> &'static [(&'static str, &'static str)] {
    &[]
}

/// Return the optional option keys for a given provider kind.
///
/// Only covers built-in kinds; discovered WASM plugin kinds get their
/// options from the plugin manifest (see `PluginRegistry`).
pub fn optional_options_for_kind(_kind: &str) -> &'static [(&'static str, &'static str)] {
    &[]
}

/// The list of built-in provider kind strings.
///
/// WASM plugin kinds (e.g. `bitwarden-pm`, `bitwarden-sm`) are discovered
/// dynamically from the plugin registry and are not included here.
pub const KNOWN_KINDS: &[&str] = &["local"];

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

    let table = doc
        .entry(section)
        .or_insert_with(|| {
            let mut t = toml_edit::Table::new();
            t.set_implicit(false);
            Item::Table(t)
        })
        .as_table_mut()
        .with_context(|| format!("'{section}' exists but is not a table"))?;

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

/// Convenience wrapper: add a `kind = "local"` provider entry.
///
/// This is a thin wrapper over [`add_provider`] that constructs the
/// appropriate option list for a local vault.
pub fn add_local_provider(
    config_path: &Path,
    id: &str,
    vault_path: &str,
    collection: Option<&str>,
) -> Result<()> {
    let mut options: Vec<(String, String)> = vec![("path".into(), vault_path.into())];
    if let Some(col) = collection {
        options.push(("collection".into(), col.into()));
    }
    add_provider(config_path, id, "local", &options)
}

/// Remove a `[[key]]` entry whose `id` field matches the given value.
///
/// Finds all matching entries, removes them in reverse index order (to keep
/// earlier indices stable), and removes the top-level key entirely when the
/// array becomes empty.
fn remove_array_entry(
    doc: &mut DocumentMut,
    key: &str,
    id: &str,
    config_path: &Path,
) -> Result<()> {
    let array = match doc
        .get_mut(key)
        .and_then(|item| item.as_array_of_tables_mut())
    {
        Some(a) => a,
        None => bail!("no {key}s configured in {}", config_path.display()),
    };

    let before = array.len();

    // toml_edit ArrayOfTables doesn't have retain(); collect indices to remove.
    let indices_to_remove: Vec<usize> = (0..array.len())
        .filter(|&i| {
            array
                .get(i)
                .and_then(|t| t.get("id"))
                .and_then(|v| v.as_str())
                == Some(id)
        })
        .collect();

    if indices_to_remove.is_empty() {
        bail!("{key} '{id}' not found in {}", config_path.display());
    }

    // Remove in reverse order so earlier indices stay valid.
    for i in indices_to_remove.into_iter().rev() {
        array.remove(i);
    }

    let after = array.len();

    // If the array is now empty, remove the key entirely so the file stays clean.
    if after == 0 {
        doc.remove(key);
    }

    tracing::debug!(
        removed = before - after,
        config = %config_path.display(),
        "removed {key} '{id}' from config"
    );

    Ok(())
}

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

/// Iterate over the provider IDs present in a parsed config document.
pub fn provider_ids(doc: &DocumentMut) -> impl Iterator<Item = &str> {
    doc.get("provider")
        .and_then(|item| item.as_array_of_tables())
        .into_iter()
        .flat_map(|aot| aot.iter())
        .filter_map(|t| t.get("id")?.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn add_provider_creates_file() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_provider(
            &path,
            "bw1",
            "bitwarden-pm",
            &[("email".into(), "a@b.com".into())],
        )
        .unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("id = \"bw1\""));
        assert!(contents.contains("kind = \"bitwarden-pm\""));
        assert!(contents.contains("email = \"a@b.com\""));
    }

    #[test]
    fn add_provider_rejects_duplicate_id() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_provider(&path, "bw1", "bitwarden-pm", &[]).unwrap();
        let err = add_provider(&path, "bw1", "bitwarden-pm", &[]).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn add_multiple_providers_same_kind() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_provider(
            &path,
            "bw1",
            "bitwarden-pm",
            &[("email".into(), "a@b.com".into())],
        )
        .unwrap();
        add_provider(
            &path,
            "bw2",
            "bitwarden-pm",
            &[("email".into(), "b@b.com".into())],
        )
        .unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("id = \"bw1\""));
        assert!(contents.contains("id = \"bw2\""));
    }

    #[test]
    fn remove_provider_by_id() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_provider(&path, "bw1", "bitwarden-pm", &[]).unwrap();
        add_provider(&path, "bw2", "bitwarden-pm", &[]).unwrap();
        remove_provider(&path, "bw1").unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("id = \"bw1\""));
        assert!(contents.contains("id = \"bw2\""));
    }

    #[test]
    fn remove_last_provider_cleans_key() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_provider(&path, "bw1", "bitwarden-pm", &[]).unwrap();
        remove_provider(&path, "bw1").unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("bw1"));
        assert!(!contents.contains("[[provider]]"));
    }

    #[test]
    fn remove_nonexistent_provider_errors() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        let err = remove_provider(&path, "ghost").unwrap_err();
        assert!(err.to_string().contains("not found") || err.to_string().contains("no providers"));
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
        add_provider(&path, "bw1", "bitwarden-pm", &[]).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("# my comment"));
        assert!(contents.contains("dedup_strategy = \"priority\""));
        assert!(contents.contains("id = \"bw1\""));
    }

    // -----------------------------------------------------------------------
    // Local provider (vault) config editing tests
    // -----------------------------------------------------------------------

    #[test]
    fn add_local_provider_creates_file() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_local_provider(
            &path,
            "personal",
            "~/.local/share/rosec/vaults/personal.vault",
            None,
        )
        .unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("[[provider]]"));
        assert!(contents.contains("id = \"personal\""));
        assert!(contents.contains("kind = \"local\""));
        assert!(contents.contains("path = \"~/.local/share/rosec/vaults/personal.vault\""));
    }

    #[test]
    fn add_local_provider_with_collection() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_local_provider(&path, "work", "/mnt/work.vault", Some("work")).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("collection = \"work\""));
    }

    #[test]
    fn add_local_provider_rejects_duplicate_id() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_local_provider(&path, "v1", "/tmp/v1.vault", None).unwrap();
        let err = add_local_provider(&path, "v1", "/tmp/v1b.vault", None).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn add_local_provider_rejects_id_colliding_with_external() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_provider(&path, "shared-id", "bitwarden-pm", &[]).unwrap();
        let err = add_local_provider(&path, "shared-id", "/tmp/v.vault", None).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn remove_local_provider_by_id() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_local_provider(&path, "v1", "/tmp/v1.vault", None).unwrap();
        add_local_provider(&path, "v2", "/tmp/v2.vault", None).unwrap();
        remove_provider(&path, "v1").unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("id = \"v1\""));
        assert!(contents.contains("id = \"v2\""));
    }

    #[test]
    fn remove_last_local_provider_cleans_key() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_local_provider(&path, "v1", "/tmp/v1.vault", None).unwrap();
        remove_provider(&path, "v1").unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("v1"));
        assert!(!contents.contains("[[provider]]"));
    }

    #[test]
    fn remove_nonexistent_local_provider_errors() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        let err = remove_provider(&path, "ghost").unwrap_err();
        assert!(err.to_string().contains("not found") || err.to_string().contains("no providers"));
    }

    #[test]
    fn mixed_local_and_external_providers_preserved() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_local_provider(&path, "local", "/tmp/local.vault", None).unwrap();
        add_provider(
            &path,
            "bw1",
            "bitwarden-pm",
            &[("email".into(), "a@b.com".into())],
        )
        .unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("[[provider]]"));
        assert!(contents.contains("id = \"local\""));
        assert!(contents.contains("id = \"bw1\""));

        // Remove the local provider, external should remain.
        remove_provider(&path, "local").unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("[[provider]]"));
        assert!(contents.contains("id = \"bw1\""));
    }

    // -----------------------------------------------------------------------
    // Enable / disable
    // -----------------------------------------------------------------------

    #[test]
    fn disable_provider_adds_enabled_false() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_provider(&path, "bw1", "bitwarden-pm", &[]).unwrap();
        set_provider_enabled(&path, "bw1", false).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("enabled = false"));
    }

    #[test]
    fn enable_provider_removes_enabled_field() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_provider(&path, "bw1", "bitwarden-pm", &[]).unwrap();
        set_provider_enabled(&path, "bw1", false).unwrap();
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("enabled = false")
        );
        set_provider_enabled(&path, "bw1", true).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("enabled"));
    }

    #[test]
    fn enable_disable_nonexistent_provider_errors() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        add_provider(&path, "bw1", "bitwarden-pm", &[]).unwrap();
        let err = set_provider_enabled(&path, "ghost", false).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
}
