//! Mapping between KeePass entries and the rosec attribute model.
//!
//! - Item IDs are the entry's UUID as a hyphenated string.
//! - Public attributes carry non-sensitive metadata (`username`, `uri`,
//!   `folder`, `tag.N`, custom unprotected strings, plus `rosec:*`/`xdg:*`).
//! - Secret names list every fetchable sensitive value (`password`, `notes`,
//!   `totp` when present, plus custom protected strings).
//!
//! The KeePass file marks each field as protected or unprotected at write
//! time; we honour that flag rather than re-classifying client-side.

use std::collections::HashMap;

use keepass::{
    Database,
    db::{EntryRef, GroupId, fields},
};
use zeroize::Zeroizing;

use crate::protocol::WasmItemMeta;

// ── Attribute name constants (rosec convention) ──────────────────────────────

pub(crate) const ATTR_TYPE: &str = "rosec:type";
pub(crate) const ATTR_PROVIDER: &str = "rosec:provider";
pub(crate) const ATTR_FOLDER: &str = "rosec:keepassxc:folder";
pub(crate) const ATTR_UUID: &str = "rosec:keepassxc:uuid";
pub(crate) const ATTR_TOTP: &str = "rosec:totp";
pub(crate) const ATTR_XDG_SCHEMA: &str = "xdg:schema";

// Standard secret names exposed by KeePass entries.
pub(crate) const SECRET_PASSWORD: &str = "password";
pub(crate) const SECRET_NOTES: &str = "notes";
pub(crate) const SECRET_TOTP: &str = "totp";
/// Name used by `rosec` and `libsecret`-style consumers to fetch an SSH
/// private key.  Matches the convention used by the local vault and
/// bitwarden-pm providers; the host's `return_attr` default ordering
/// includes `private_key` so it's also what `inspect` shows for SSH items.
pub(crate) const SECRET_PRIVATE_KEY: &str = "private_key";

// ── Item type heuristic ──────────────────────────────────────────────────────

fn item_type_for(entry: &EntryRef<'_>) -> &'static str {
    // SSH config wins over the password/notes heuristic — an SSH-agent
    // entry typically also has a passphrase in the password field, but
    // the right `rosec:type` is `ssh-key`, not `login`.
    if crate::ssh::entry_has_ssh_key(entry) {
        return "ssh-key";
    }

    let has_password = entry.get_password().is_some_and(|s| !s.is_empty());
    let has_notes = entry.get(fields::NOTES).is_some_and(|s| !s.is_empty());

    if has_password {
        "login"
    } else if has_notes {
        "note"
    } else {
        "generic"
    }
}

// ── Folder path derivation ───────────────────────────────────────────────────

/// Compute "Group/Subgroup" path for an entry by walking up the parent chain.
///
/// The root group's name is omitted (it's typically just the database name);
/// returns `""` for entries that live directly under the root.
pub(crate) fn folder_path(db: &Database, entry: &EntryRef<'_>) -> String {
    let root_id = db.root().id();
    // Walk up by GroupId (Copy) instead of GroupRef so each iteration drops
    // its short-lived borrow before reassigning the loop variable.
    let mut current_id: Option<GroupId> = Some(entry.parent().id());
    let mut parts: Vec<String> = Vec::new();
    while let Some(id) = current_id {
        if id == root_id {
            break;
        }
        let Some(g) = db.group(id) else { break };
        parts.push(g.name.clone());
        current_id = g.parent().map(|p| p.id());
    }
    parts.reverse();
    parts.join("/")
}

// ── Public attributes ────────────────────────────────────────────────────────

pub(crate) fn build_public_attrs(
    provider_id: &str,
    db: &Database,
    entry: &EntryRef<'_>,
) -> HashMap<String, String> {
    let mut attrs = HashMap::new();

    attrs.insert(ATTR_TYPE.to_string(), item_type_for(entry).to_string());
    attrs.insert(ATTR_PROVIDER.to_string(), provider_id.to_string());
    attrs.insert(
        ATTR_XDG_SCHEMA.to_string(),
        "org.freedesktop.Secret.Generic".to_string(),
    );
    attrs.insert(ATTR_UUID.to_string(), entry.id().uuid().to_string());

    let folder = folder_path(db, entry);
    if !folder.is_empty() {
        attrs.insert(ATTR_FOLDER.to_string(), folder);
    }

    if let Some(u) = entry.get_username().filter(|s| !s.is_empty()) {
        attrs.insert("username".to_string(), u.to_string());
    }
    if let Some(u) = entry.get_url().filter(|s| !s.is_empty()) {
        attrs.insert("uri".to_string(), u.to_string());
    }

    // Stamp `rosec:totp=true` so `rosec search rosec:totp=true` and the
    // TOTP FUSE filesystem can find this entry.  The host's automatic
    // stamping only applies to the local vault provider, not WASM guests.
    if entry.get_raw_otp_value().is_some_and(|s| !s.is_empty()) {
        attrs.insert(ATTR_TOTP.to_string(), "true".to_string());
    }

    // Tags — first as "tag", subsequent as "tag.1", "tag.2", ... mirrors the
    // multi-value attribute convention used elsewhere in rosec.
    for (i, tag) in entry.tags.iter().enumerate() {
        let key = if i == 0 {
            "tag".to_string()
        } else {
            format!("tag.{i}")
        };
        attrs.insert(key, tag.clone());
    }

    // Custom unprotected fields.  Skip the well-known ones we already handled.
    for (name, value) in entry.fields.iter() {
        if is_well_known_field(name) {
            continue;
        }
        if !value.is_protected() {
            let s = value.get().as_str();
            if !s.is_empty() {
                attrs.insert(name.clone(), s.to_string());
            }
        }
    }

    attrs
}

fn is_well_known_field(name: &str) -> bool {
    matches!(
        name,
        fields::TITLE
            | fields::USERNAME
            | fields::PASSWORD
            | fields::URL
            | fields::NOTES
            | fields::OTP
    )
}

// ── Secret names list ────────────────────────────────────────────────────────

pub(crate) fn build_secret_names(entry: &EntryRef<'_>) -> Vec<String> {
    let mut names = Vec::new();

    // SSH-key entries advertise `private_key` first so the daemon's
    // default `return_attr` ordering (private_key → password → notes)
    // gives consumers the actual key when they call GetSecret.
    if crate::ssh::entry_has_ssh_key(entry) {
        names.push(SECRET_PRIVATE_KEY.to_string());
    }

    if entry.get_password().is_some_and(|s| !s.is_empty()) {
        names.push(SECRET_PASSWORD.to_string());
    }
    if entry.get(fields::NOTES).is_some_and(|s| !s.is_empty()) {
        names.push(SECRET_NOTES.to_string());
    }
    if entry.get_raw_otp_value().is_some_and(|s| !s.is_empty()) {
        names.push(SECRET_TOTP.to_string());
    }

    // Custom protected fields.
    for (name, value) in entry.fields.iter() {
        if is_well_known_field(name) {
            continue;
        }
        if value.is_protected() && !value.get().as_str().is_empty() {
            names.push(name.clone());
        }
    }

    names
}

// ── Secret resolution (name → bytes) ─────────────────────────────────────────

/// Returns the decrypted secret bytes inside a `Zeroizing` buffer so the
/// allocation is scrubbed when dropped.  The borrowed `&str` from
/// keepass-rs is backed by its `SecretBox` storage, which already
/// zeroizes on drop — what we wrap here is the *new* allocation we make
/// to ferry the bytes out of this function.
pub(crate) fn resolve_secret(entry: &EntryRef<'_>, attr: &str) -> Option<Zeroizing<Vec<u8>>> {
    // Fast path for the SSH PEM — routes through ssh::resolve_ssh_private_key
    // which handles attachment vs external-file lookup, decryption with the
    // entry password, and re-encoding as unencrypted OpenSSH PEM.
    if attr == SECRET_PRIVATE_KEY {
        return crate::ssh::resolve_ssh_private_key(entry)
            .ok()
            .map(|pem| Zeroizing::new(pem.as_bytes().to_vec()));
    }

    let value: Option<&str> = match attr {
        SECRET_PASSWORD => entry.get_password(),
        SECRET_NOTES => entry.get(fields::NOTES),
        SECRET_TOTP => entry.get_raw_otp_value(),
        custom => entry
            .fields
            .get(custom)
            .filter(|v| v.is_protected())
            .map(|v| v.get().as_str()),
    };
    value
        .filter(|s| !s.is_empty())
        .map(|s| Zeroizing::new(s.as_bytes().to_vec()))
}

// ── ItemMeta builder ─────────────────────────────────────────────────────────

pub(crate) fn entry_to_item_meta(
    provider_id: &str,
    db: &Database,
    entry: &EntryRef<'_>,
) -> WasmItemMeta {
    use chrono::TimeZone;

    let to_epoch = |dt: chrono::NaiveDateTime| -> u64 {
        chrono::Utc.from_utc_datetime(&dt).timestamp().max(0) as u64
    };

    WasmItemMeta {
        id: entry.id().uuid().to_string(),
        label: entry.get_title().unwrap_or("(unnamed)").to_string(),
        attributes: build_public_attrs(provider_id, db, entry),
        created_epoch_secs: entry.times.creation.map(to_epoch),
        modified_epoch_secs: entry.times.last_modification.map(to_epoch),
    }
}
