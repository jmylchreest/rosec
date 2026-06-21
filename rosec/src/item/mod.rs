//! `rosec item` subcommand group.
//!
//! Each subcommand has its own module — the dispatcher matches on
//! [`ItemCommands`] and delegates.

use std::collections::HashMap;

use anyhow::{Result, bail};
use zvariant::OwnedObjectPath;

use crate::cli::{Format, ItemCommands, ItemListArgs};

pub mod add;
pub mod delete;
pub mod edit;
pub mod export;
pub mod import;
pub mod list;

pub async fn dispatch(action: Option<ItemCommands>) -> Result<()> {
    let action = action.unwrap_or(ItemCommands::List(ItemListArgs {
        provider: None,
        item_type: None,
        format: Format::Table,
        show_path: false,
        sync: false,
        no_unlock: false,
        filters: Vec::new(),
    }));
    match action {
        ItemCommands::List(args) => list::run(args).await,
        ItemCommands::Add(args) => add::run(args).await,
        ItemCommands::Edit(args) => edit::run(args).await,
        ItemCommands::Delete(args) => delete::run(args).await,
        ItemCommands::Export(args) => export::run(args).await,
        ItemCommands::Import(args) => import::run(args).await,
    }
}
// Shared helpers (TOML round-trip + editor)
/// Parsed result of an item TOML document.
pub(super) struct ParsedItem {
    pub(super) label: String,
    pub(super) item_type: String,
    pub(super) attributes: HashMap<String, String>,
    /// Secret name → raw bytes (UTF-8 encoded).
    pub(super) secrets: HashMap<String, Vec<u8>>,
}

/// Parse a TOML document written by the user in $EDITOR into a `ParsedItem`.
///
/// Expects sections `[item]` (with `label` and `type`), `[attributes]`, and
/// `[secrets]`.  Empty string values in `[secrets]` are silently dropped.
pub(super) fn parse_item_toml(content: &str) -> Result<ParsedItem> {
    let doc: toml::Value = toml::from_str(content)
        .map_err(|e: toml::de::Error| anyhow::anyhow!("failed to parse TOML: {e}"))?;

    let item_table = doc
        .get("item")
        .and_then(|v| v.as_table())
        .ok_or_else(|| anyhow::anyhow!("[item] section is missing or not a table"))?;

    let label = item_table
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if label.is_empty() {
        bail!("item label is required (set label = \"...\" in [item])");
    }

    let raw_type = item_table
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("generic");

    // Validate and normalize the item type (e.g. "sshkey" → "ssh-key").
    let item_type = raw_type
        .parse::<rosec_core::ItemType>()
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .as_str()
        .to_string();

    let mut attributes = HashMap::new();
    if let Some(attrs_table) = doc.get("attributes").and_then(|v| v.as_table()) {
        for (k, v) in attrs_table {
            let val = match v {
                toml::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if !val.is_empty() {
                attributes.insert(k.clone(), val);
            }
        }
    }

    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();
    if let Some(secrets_table) = doc.get("secrets").and_then(|v| v.as_table()) {
        for (k, v) in secrets_table {
            match v {
                toml::Value::String(s) => {
                    if !s.is_empty() {
                        secrets.insert(k.clone(), s.as_bytes().to_vec());
                    }
                }
                // Inline table with `base64` key → decode binary secret.
                toml::Value::Table(tbl) => {
                    if let Some(toml::Value::String(b64)) = tbl.get("base64") {
                        use base64::Engine;
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(b64)
                            .map_err(|e| anyhow::anyhow!("secret \"{k}\": invalid base64: {e}"))?;
                        if !bytes.is_empty() {
                            secrets.insert(k.clone(), bytes);
                        }
                    } else {
                        bail!(
                            "secret \"{k}\": inline table must have a \"base64\" key \
                             (e.g. {{ base64 = \"...\" }})"
                        );
                    }
                }
                other => {
                    let val = other.to_string();
                    if !val.is_empty() {
                        secrets.insert(k.clone(), val.into_bytes());
                    }
                }
            }
        }
    }

    Ok(ParsedItem {
        label,
        item_type,
        attributes,
        secrets,
    })
}

/// Find existing items that a new item with `label`/`attributes` in
/// `provider_id` would duplicate, for hint/prompt display.
///
/// Mirrors the provider's create-time dedup: when `attributes` is non-empty,
/// match by attribute subset; otherwise match by label (attribute-less items
/// are identified by their label).  `provider_id` empty means "all providers"
/// — the same default the create call uses.  Best-effort: returns an empty
/// vec on any search error rather than failing the caller.
pub(super) async fn find_conflicts(
    conn: &zbus::Connection,
    rosecd: bool,
    provider_id: &str,
    label: &str,
    attributes: &HashMap<String, String>,
) -> Vec<crate::ItemSummary> {
    let mut query: HashMap<String, String> = HashMap::new();
    if !provider_id.is_empty() {
        query.insert(
            rosec_core::ATTR_PROVIDER.to_string(),
            provider_id.to_string(),
        );
    }
    if attributes.is_empty() {
        // `name` is matched against the item label by the search extension.
        query.insert("name".to_string(), label.to_string());
    } else {
        for (k, v) in attributes {
            query.insert(k.clone(), v.clone());
        }
    }

    // no_unlock = true: conflict detection must not trigger an unlock prompt.
    let (unlocked, locked) =
        match crate::search_with_glob_fallback(conn, &query, rosecd, true).await {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

    let mut out = Vec::new();
    for (path, is_locked) in unlocked
        .into_iter()
        .map(|p| (p, false))
        .chain(locked.into_iter().map(|p| (p, true)))
    {
        if let Ok(summary) = crate::fetch_item_data(conn, &path, is_locked).await {
            // The label query is a glob match server-side; keep only exact
            // label matches so the hint mirrors the provider's dedup.
            if attributes.is_empty() && summary.label != label {
                continue;
            }
            out.push(summary);
        }
    }
    out
}

/// Determine the editor command.  Checks `$VISUAL`, then `$EDITOR`, then
/// falls back to `vi`.
pub(super) fn editor_command() -> String {
    std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string())
}

/// Open a temp file in the user's editor and return the edited content.
///
/// The file is created with a `.toml` extension so editors enable syntax
/// highlighting.  Returns `None` if the user quit without saving (content
/// unchanged from the initial template) or if the file is empty.
pub(super) fn open_editor(initial_content: &str) -> Result<Option<String>> {
    use std::io::Write;

    let dir = tempfile::tempdir()?;
    let file_path = dir.path().join("rosec-item.toml");
    {
        let mut f = std::fs::File::create(&file_path)?;
        f.write_all(initial_content.as_bytes())?;
        f.flush()?;
    }

    let editor = editor_command();
    let parts: Vec<&str> = editor.split_whitespace().collect();
    let (cmd, cmd_args) = parts.split_first().ok_or_else(|| {
        anyhow::anyhow!("$EDITOR / $VISUAL is empty; set it to your preferred editor")
    })?;

    let status = std::process::Command::new(cmd)
        .args(cmd_args.iter())
        .arg(&file_path)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to launch editor '{editor}': {e}"))?;

    if !status.success() {
        bail!(
            "editor exited with status {} — item not created",
            status.code().unwrap_or(-1)
        );
    }

    let edited = std::fs::read_to_string(&file_path)?;

    // If the user didn't change anything, treat it as abort.
    if edited.trim() == initial_content.trim() || edited.trim().is_empty() {
        return Ok(None);
    }

    Ok(Some(edited))
}

/// Data fetched from an existing item via D-Bus.
pub(super) struct FetchedItemData {
    pub(super) label: String,
    pub(super) item_type: String,
    pub(super) pub_attrs: HashMap<String, String>,
    /// Secret name → raw bytes (may not be valid UTF-8).
    pub(super) secrets: Vec<(String, Vec<u8>)>,
}

/// Fetch a full item's data (label, public attributes, secret names + values)
/// from D-Bus.  Unlike `fetch_item_data` (which returns only public metadata),
/// this also retrieves all secret attributes via the `org.rosec.Secrets`
/// extension interface.
pub(super) async fn fetch_full_item(
    conn: &zbus::Connection,
    item_path: &str,
) -> Result<FetchedItemData> {
    let item_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        item_path,
        "org.freedesktop.Secret.Item",
    )
    .await?;

    let label: String = item_proxy.get_property("Label").await?;
    let pub_attrs: HashMap<String, String> = item_proxy.get_property("Attributes").await?;

    // Normalize through ItemType so legacy strings like "sshkey" become "ssh-key".
    let item_type = rosec_core::ItemType::from_attributes(&pub_attrs)
        .as_str()
        .to_string();

    let secrets_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Secrets",
        "org.rosec.Secrets",
    )
    .await?;

    let item_obj_path = OwnedObjectPath::try_from(item_path.to_string())
        .map_err(|e| anyhow::anyhow!("invalid item path: {e}"))?;

    let secret_names: Vec<String> = secrets_proxy
        .call("GetSecretAttributeNames", &(&item_obj_path,))
        .await
        .unwrap_or_default();

    let mut secrets: Vec<(String, Vec<u8>)> = Vec::new();
    for name in &secret_names {
        let bytes: Vec<u8> = secrets_proxy
            .call("GetSecretAttribute", &(&item_obj_path, name.as_str()))
            .await
            .unwrap_or_default();
        secrets.push((name.clone(), bytes));
    }

    Ok(FetchedItemData {
        label,
        item_type,
        pub_attrs,
        secrets,
    })
}

/// Build a TOML document from an existing item's data, suitable for editing.
///
/// The document mirrors the template format: `[item]`, `[attributes]`,
/// `[secrets]`.  Internal/reserved attributes (`rosec:type`, `rosec:provider`,
/// `xdg:schema`) are omitted from `[attributes]` since they are handled by
/// `[item].type` or are read-only.
///
/// Secret values that are valid UTF-8 are emitted as plain TOML strings.
/// Binary (non-UTF-8) values are emitted as inline tables:
///   `key = { base64 = "..." }`
/// so that the import side can distinguish and decode them losslessly.
pub(super) fn build_item_toml(
    label: &str,
    item_type: &str,
    pub_attrs: &HashMap<String, String>,
    secrets: &[(String, Vec<u8>)],
) -> String {
    use base64::Engine;

    let mut out = String::new();

    out.push_str(&format!("# rosec item — type: {item_type}\n"));
    out.push_str("# Lines starting with '#' are comments and will be ignored.\n");
    out.push_str("# Empty secret values will not be stored.\n");
    out.push_str("# Removing a secret key will leave the existing value unchanged.\n\n");

    out.push_str("[item]\n");
    out.push_str(&format!("label = {}\n", toml_quote(label)));
    out.push_str(&format!(
        "type = \"{}\"    # generic | login | ssh-key | note | card | identity\n\n",
        item_type
    ));

    // [attributes] section — skip reserved/internal attrs
    out.push_str("[attributes]\n");
    let mut sorted_attrs: Vec<_> = pub_attrs
        .iter()
        .filter(|(k, _)| !k.starts_with("rosec:") && !k.starts_with("xdg:"))
        .collect();
    sorted_attrs.sort_by_key(|(k, _)| k.as_str());
    for (k, v) in &sorted_attrs {
        out.push_str(&format!("{} = {}\n", toml_key(k), toml_quote(v)));
    }
    out.push('\n');

    out.push_str("[secrets]\n");
    for (k, v) in secrets {
        let key = toml_key(k);
        match std::str::from_utf8(v) {
            Ok(text) => {
                if text.contains('\n') {
                    out.push_str(&format!("{key} = \"\"\"\n{}\"\"\"\n", toml_escape(text)));
                } else {
                    out.push_str(&format!("{key} = {}\n", toml_quote(text)));
                }
            }
            Err(_) => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(v);
                out.push_str(&format!("{key} = {{ base64 = \"{}\" }}\n", encoded));
            }
        }
    }

    out
}

/// TOML-safe quoting: wraps in double quotes, escaping backslashes, quotes,
/// and control characters (which are not allowed unescaped in TOML basic
/// strings).
pub(super) fn toml_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{0008}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            // All other control characters (U+0000..U+001F, U+007F) must use
            // the \uXXXX escape.
            c if c.is_control() => {
                let cp = c as u32;
                if cp <= 0xFFFF {
                    out.push_str(&format!("\\u{cp:04X}"));
                } else {
                    out.push_str(&format!("\\U{cp:08X}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Escape a string for use inside TOML triple-quoted (multi-line basic)
/// strings.  Newlines are preserved, but control characters and backslashes
/// are escaped.
pub(super) fn toml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push('\n'), // preserved in multi-line strings
            '\u{000C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                let cp = c as u32;
                if cp <= 0xFFFF {
                    out.push_str(&format!("\\u{cp:04X}"));
                } else {
                    out.push_str(&format!("\\U{cp:08X}"));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// TOML-safe key: bare keys may only contain `[A-Za-z0-9_-]`.  Anything else
/// (e.g. dots, colons) must be quoted.
pub(super) fn toml_key(k: &str) -> String {
    if k.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        k.to_string()
    } else {
        toml_quote(k)
    }
}
