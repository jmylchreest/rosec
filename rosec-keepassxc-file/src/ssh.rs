//! SSH key extraction from KeePassXC entries.
//!
//! KeePassXC stores SSH keys via two pieces on a single entry:
//!
//! 1. A `<Binary>` attachment containing the raw OpenSSH private-key file.
//! 2. A `KeeAgent.settings` custom string field — a chunk of XML telling
//!    KeePassXC's built-in SSH agent how to use the attachment.
//!
//! The XML is base64-encoded UTF-16 LE (with BOM) for backwards compat with
//! the original Windows KeeAgent plugin.  Newer KeePassXC builds may also
//! emit plain UTF-8 XML; we accept both.
//!
//! For each entry that opts in we:
//! - parse `KeeAgent.settings` to find the attachment name and confirm flag,
//! - look up the attachment by name,
//! - if the OpenSSH key is encrypted, decrypt it with the entry's password,
//! - return the (now-unencrypted) PEM.
//!
//! The host (`rosecd/src/ssh.rs`) re-parses the PEM to derive
//! `public_key_openssh` and `fingerprint`, so we leave those `None` here.
//!
//! Encrypted keys whose passphrase is *not* the entry password are skipped
//! with a debug log — we only know about the entry password.

use chrono::TimeZone;
use extism_pdk::info;
use keepass::{Database, db::EntryRef};
use ssh_key::{LineEnding, PrivateKey};
use zeroize::Zeroizing;

use crate::protocol::WasmSshKeyMeta;

// ── Public API ───────────────────────────────────────────────────────────────

/// Cheap probe: does this entry carry a usable SSH-key configuration?
///
/// Used by `cipher::build_public_attrs` to stamp `rosec:type=ssh-key`
/// without parsing the private key.  An entry counts as "an SSH key" if
/// it has a `KeeAgent.settings` attachment pointing at another
/// attachment (the OpenSSH PEM) that exists in the kdbx.
///
/// We deliberately ignore KeePassXC's own `AllowUseOfSshKey` and
/// `AddAtDatabaseOpen` flags — those control how *KeePassXC's built-in
/// SSH agent* behaves, which is irrelevant to rosec.
///
/// We do NOT support `<SelectedType>file</SelectedType>` (KeePassXC's
/// "External file" mode where the private key lives outside the kdbx on
/// the host filesystem).  Reasons: (1) the host_file allow-list would
/// need every external key path explicitly registered, which is awkward
/// UX; (2) external-file mode means the kdbx can't be sync'd or
/// backed up self-contained; (3) KeePassXC itself recommends Attachment
/// mode for the same portability reason.  If you have a key file on
/// disk, add it as an attachment via the entry's *Advanced* tab first.
pub(crate) fn entry_has_ssh_key(entry: &EntryRef<'_>) -> bool {
    let Some(settings) = read_keeagent_settings(entry) else {
        return false;
    };
    if settings.selected_type.as_deref() != Some("attachment") {
        // Common when the user picked External file mode in KeePassXC —
        // log once at debug so the user has a breadcrumb if they're
        // wondering why their entry isn't showing as ssh-key.
        let title = entry.get_title().unwrap_or("(unnamed)");
        info!(
            "ssh: entry '{title}' KeeAgent.settings SelectedType={:?} \
             — only 'attachment' is supported (re-import the key as an \
             attachment via the entry's Advanced tab)",
            settings.selected_type
        );
        return false;
    }
    settings
        .attachment_name
        .as_deref()
        .and_then(|n| entry.attachment_by_name(n))
        .is_some()
}

/// Build a `WasmSshKeyMeta` for an entry that carries an SSH key, or `None`
/// if the entry has no usable Attachment-mode `KeeAgent.settings`.
pub(crate) fn entry_to_ssh_key_meta(db: &Database, entry: &EntryRef<'_>) -> Option<WasmSshKeyMeta> {
    let settings = read_keeagent_settings(entry)?;
    if settings.selected_type.as_deref() != Some("attachment") {
        return None;
    }
    let attachment_name = settings.attachment_name.as_deref()?;
    entry.attachment_by_name(attachment_name)?;

    let revision_date_epoch_secs = entry
        .times
        .last_modification
        .map(|dt| chrono::Utc.from_utc_datetime(&dt).timestamp().max(0) as u64);

    let _ = db;

    // ssh_host / ssh-host: one or more host patterns the key should be
    // offered for.  Pulled from custom string fields; multi-line splits
    // into multiple entries (matches the bitwarden-pm convention).
    let ssh_hosts: Vec<String> = ["ssh_host", "ssh-host"]
        .into_iter()
        .filter_map(|n| entry.fields.get(n))
        .flat_map(|v| {
            v.get()
                .as_str()
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .collect();

    // ssh_user / ssh-user: SSH login user.  Falls back to entry username
    // (KeePassXC's standard Username field) when the custom field is absent.
    let ssh_user_custom = ["ssh_user", "ssh-user"]
        .into_iter()
        .filter_map(|n| entry.fields.get(n))
        .map(|v| v.get().as_str().trim().to_string())
        .find(|s| !s.is_empty());
    let ssh_user = ssh_user_custom.or_else(|| {
        entry
            .get_username()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    });

    // ssh_confirm / ssh-confirm: optional "true" override of the agent's
    // confirm-on-sign behaviour.  KeePassXC's own
    // UseConfirmConstraintWhenAdding flag in KeeAgent.settings already
    // populates `settings.require_confirm`; OR the two so either source
    // can opt in.
    let confirm_field = ["ssh_confirm", "ssh-confirm"]
        .into_iter()
        .filter_map(|n| entry.fields.get(n))
        .any(|v| v.get().as_str().trim().eq_ignore_ascii_case("true"));

    Some(WasmSshKeyMeta {
        item_id: entry.id().uuid().to_string(),
        item_name: entry.get_title().unwrap_or("(unnamed)").to_string(),
        public_key_openssh: None,
        fingerprint: None,
        ssh_hosts,
        ssh_user,
        require_confirm: settings.require_confirm || confirm_field,
        revision_date_epoch_secs,
    })
}

/// Resolve an entry's SSH private key as an unencrypted OpenSSH PEM string.
///
/// Returns `Err(reason)` if the entry has no SSH key, the attachment is
/// missing, the PEM doesn't parse, or the key is encrypted with a passphrase
/// other than the entry password.
pub(crate) fn resolve_ssh_private_key(entry: &EntryRef<'_>) -> Result<Zeroizing<String>, String> {
    let settings =
        read_keeagent_settings(entry).ok_or_else(|| "no KeeAgent.settings on entry".to_string())?;
    if settings.selected_type.as_deref() != Some("attachment") {
        return Err(
            "only KeeAgent.settings SelectedType=attachment is supported \
             — re-add the key as an attachment from the entry's Advanced tab"
                .to_string(),
        );
    }
    let attachment_name = settings
        .attachment_name
        .as_deref()
        .ok_or_else(|| "KeeAgent.settings has no AttachmentName".to_string())?;

    let attachment = entry
        .attachment_by_name(attachment_name)
        .ok_or_else(|| format!("attachment '{attachment_name}' not found"))?;
    let bytes = attachment.data.get();
    let pem_text = std::str::from_utf8(bytes)
        .map_err(|e| format!("attachment '{attachment_name}' is not valid UTF-8: {e}"))?;
    let pem_owned = Zeroizing::new(pem_text.to_owned());

    let key = PrivateKey::from_openssh(pem_owned.as_str())
        .map_err(|e| format!("not a valid OpenSSH key: {e}"))?;

    if key.is_encrypted() {
        let passphrase = entry
            .get_password()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "key is passphrase-protected but entry has no password".to_string())?;
        let decrypted = key
            .decrypt(passphrase.as_bytes())
            .map_err(|e| format!("decrypting key with entry password failed: {e}"))?;
        decrypted
            .to_openssh(LineEnding::LF)
            .map_err(|e| format!("re-encoding decrypted key failed: {e}"))
    } else {
        Ok(pem_owned)
    }
}

// ── KeeAgent.settings parsing ────────────────────────────────────────────────

const KEEAGENT_FIELD: &str = "KeeAgent.settings";

#[derive(Debug, Default)]
struct KeeAgentSettings {
    require_confirm: bool,
    selected_type: Option<String>,
    /// Set when `<SelectedType>attachment</SelectedType>` — name of the
    /// kdbx binary attachment holding the key.
    attachment_name: Option<String>,
}

fn read_keeagent_settings(entry: &EntryRef<'_>) -> Option<KeeAgentSettings> {
    // KeePassXC stores `KeeAgent.settings` as a *binary attachment* (see
    // `KeeAgentSettings::SETTINGS_BINARY` in the KeePassXC source) — NOT
    // as a custom string field on the entry.  The bytes are the raw XML
    // payload (typically UTF-8, sometimes UTF-16 with BOM for legacy
    // KeeAgent .NET compat).
    let title = entry.get_title().unwrap_or("(unnamed)");
    if let Some(att) = entry.attachment_by_name(KEEAGENT_FIELD) {
        let bytes = att.data.get();
        if let Some(xml) = decode_xml_bytes(bytes) {
            return Some(parse_keeagent_xml(&xml));
        }
        info!(
            "ssh: entry '{title}' KeeAgent.settings attachment ({} bytes) failed to decode as UTF-8/UTF-16 XML",
            bytes.len()
        );
    }
    // Fallback: a few legacy plugins stored the same XML as a
    // base64-encoded string in a custom field.  Keep this path so we
    // can read older databases.
    if let Some(raw) = entry.fields.get(KEEAGENT_FIELD) {
        let value = raw.get().as_str();
        if !value.is_empty()
            && let Some(xml) = decode_keeagent_payload(value)
        {
            return Some(parse_keeagent_xml(&xml));
        }
    }
    None
}

/// Decode a legacy field-stored `KeeAgent.settings` value to a UTF-8 XML
/// string.  The field-stored variant was base64-wrapped UTF-16 LE/BE for
/// .NET KeeAgent compat.
fn decode_keeagent_payload(value: &str) -> Option<String> {
    use base64::Engine;
    let trimmed = value.trim();

    // Path 1: base64 (the common case for legacy field storage).
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(trimmed)
        && let Some(text) = decode_xml_bytes(&bytes)
    {
        return Some(text);
    }

    // Path 2: plain UTF-8 XML, no base64 wrapper.
    if trimmed.starts_with("<?xml") || trimmed.starts_with("<EntrySettings") {
        return Some(trimmed.to_string());
    }

    None
}

fn decode_xml_bytes(bytes: &[u8]) -> Option<String> {
    // UTF-16 LE BOM
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let (cow, _, had_errors) = encoding_rs::UTF_16LE.decode(rest);
        if had_errors {
            return None;
        }
        return Some(cow.into_owned());
    }
    // UTF-16 BE BOM
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let (cow, _, had_errors) = encoding_rs::UTF_16BE.decode(rest);
        if had_errors {
            return None;
        }
        return Some(cow.into_owned());
    }
    // No BOM, but KeePassXC's KeeAgent.settings is UTF-16 LE — it
    // declares `encoding="UTF-16"` in the XML preamble itself but
    // doesn't write a BOM.  Detect via the tell-tale `XX 00 XX 00`
    // interleave on the first few bytes.  (XML always starts with `<`,
    // so byte 0 is non-zero; byte 1 is 0x00 for UTF-16 LE and non-zero
    // for UTF-16 BE / UTF-8.)
    if bytes.len() >= 4 && bytes[0] != 0 && bytes[1] == 0 && bytes[3] == 0 {
        let (cow, _, had_errors) = encoding_rs::UTF_16LE.decode(bytes);
        if !had_errors {
            return Some(cow.into_owned());
        }
    }
    if bytes.len() >= 4 && bytes[0] == 0 && bytes[1] != 0 && bytes[2] == 0 {
        let (cow, _, had_errors) = encoding_rs::UTF_16BE.decode(bytes);
        if !had_errors {
            return Some(cow.into_owned());
        }
    }
    // UTF-8 (with or without BOM).
    let utf8_bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let s = std::str::from_utf8(utf8_bytes).ok()?;
    Some(s.to_string())
}

fn parse_keeagent_xml(xml: &str) -> KeeAgentSettings {
    let (selected_type, attachment_name) = match scope(xml, "Location") {
        Some(loc) => (
            extract_text(loc, "SelectedType"),
            extract_text(loc, "AttachmentName"),
        ),
        None => (None, None),
    };
    KeeAgentSettings {
        require_confirm: extract_bool(xml, "UseConfirmConstraintWhenAdding").unwrap_or(false),
        selected_type,
        attachment_name,
    }
}

/// Extract `<Tag>...</Tag>` text content. Returns trimmed string.
fn extract_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end_rel = xml[start..].find(&close)?;
    let inner = xml[start..start + end_rel].trim();
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

fn extract_bool(xml: &str, tag: &str) -> Option<bool> {
    let v = extract_text(xml, tag)?;
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

/// Return the inner text between `<Tag>...</Tag>` (or `None` if missing).
fn scope<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end_rel = xml[start..].find(&close)?;
    Some(&xml[start..start + end_rel])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_keeagent_xml() {
        let xml = r#"<?xml version="1.0" encoding="utf-16"?>
<EntrySettings>
  <AllowUseOfSshKey>true</AllowUseOfSshKey>
  <AddAtDatabaseOpen>true</AddAtDatabaseOpen>
  <UseConfirmConstraintWhenAdding>true</UseConfirmConstraintWhenAdding>
  <Location>
    <SelectedType>attachment</SelectedType>
    <AttachmentName>id_ed25519</AttachmentName>
    <SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>
  </Location>
</EntrySettings>"#;

        let s = parse_keeagent_xml(xml);
        assert!(s.require_confirm);
        assert_eq!(s.selected_type.as_deref(), Some("attachment"));
        assert_eq!(s.attachment_name.as_deref(), Some("id_ed25519"));
    }

    #[test]
    fn extracts_attachment_name_when_location_present() {
        let xml = r#"<EntrySettings>
  <Location><SelectedType>attachment</SelectedType><AttachmentName>x</AttachmentName></Location>
</EntrySettings>"#;
        let s = parse_keeagent_xml(xml);
        assert_eq!(s.selected_type.as_deref(), Some("attachment"));
        assert_eq!(s.attachment_name.as_deref(), Some("x"));
    }

    #[test]
    fn decodes_base64_utf16le_bom() {
        // "<X>1</X>" in UTF-16 LE with BOM, then base64-encoded
        let bytes: Vec<u8> = [
            0xFF, 0xFE, b'<', 0, b'X', 0, b'>', 0, b'1', 0, b'<', 0, b'/', 0, b'X', 0, b'>', 0,
        ]
        .to_vec();
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let decoded = decode_keeagent_payload(&b64).unwrap();
        assert_eq!(decoded, "<X>1</X>");
    }

    #[test]
    fn accepts_plain_utf8_xml() {
        let xml = "<EntrySettings><AllowUseOfSshKey>true</AllowUseOfSshKey></EntrySettings>";
        let decoded = decode_keeagent_payload(xml).unwrap();
        assert!(decoded.contains("AllowUseOfSshKey"));
    }
}
