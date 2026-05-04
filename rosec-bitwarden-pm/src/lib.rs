//! Bitwarden PM WASM guest plugin for rosec.
//!
//! This is the Extism guest that implements the Bitwarden Password Manager
//! provider.  It exports plugin functions that the `rosec-wasm` host crate
//! calls via `Plugin::call()`.
//!
//! # Architecture
//!
//! - **Global state**: A `Mutex<Option<GuestState>>` holds the plugin's
//!   mutable state.  `init` populates `GuestConfig`; `unlock` populates
//!   `AuthState` (access token, refresh token, `VaultState`).
//! - **No async**: All functions are synchronous — HTTP goes through
//!   `extism_pdk::http::request`, not `reqwest`.
//! - **No notifications**: The host handles real-time sync nudges; the
//!   guest only does poll-based sync.
//! - **No OAuth credential storage**: Device registration credentials
//!   are passed from the host via `UnlockRequest.registration_fields`.

mod api;
mod cipher;
mod crypto;
mod error;
mod protocol;
mod vault;

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

use extism_pdk::*;
use zeroize::Zeroizing;

use crate::api::{ApiClient, ServerUrls, TwoFactorSubmission};
use crate::error::BitwardenError;
use crate::protocol::*;
use crate::vault::{
    CipherType, DecryptedCard, DecryptedCipher, DecryptedField, DecryptedIdentity, DecryptedLogin,
    DecryptedSshKey, VaultState,
};

// ═══════════════════════════════════════════════════════════════════
// Global state
// ═══════════════════════════════════════════════════════════════════

/// A `Mutex` wrapper that ignores poison.
///
/// WASM guests are **single-threaded** — there are no concurrent mutations.
/// The only way the inner `Mutex` becomes poisoned is when an Extism timeout
/// fires a WASM trap that kills execution without unwinding Rust destructors
/// (so `MutexGuard::drop` never runs).  Because the guest is single-threaded,
/// the data behind the lock is always in a consistent state after such a trap
/// — there was never a second thread racing to observe a half-written value.
///
/// `WasmCell::lock()` therefore returns the guard directly (no `Result`),
/// recovering from poison via `unwrap_or_else(|e| e.into_inner())`.
struct WasmCell<T>(Mutex<T>);

// SAFETY (not `unsafe`, but worth justifying): We are only ignoring poison,
// not bypassing any synchronisation.  The `Mutex` still provides interior
// mutability for a `static`.  On a single-threaded WASM target poison is a
// false-positive — the data is always valid.
impl<T> WasmCell<T> {
    const fn new(val: T) -> Self {
        Self(Mutex::new(val))
    }

    fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Global guest state behind a `WasmCell`.
///
/// `None` before `init` is called; `Some(GuestState)` after.
static STATE: WasmCell<Option<GuestState>> = WasmCell::new(None);

/// Top-level guest state.
struct GuestState {
    config: GuestConfig,
    auth: Option<AuthState>,
    /// Cached session from previous unlock — survives `lock()` so the next
    /// `unlock()` can use a `refresh_token` grant instead of a full
    /// `grant_type=password` login.  This prevents Bitwarden's server from
    /// invalidating other clients' sessions on every lock/unlock cycle.
    cached_session: Option<CachedSession>,
}

/// One-time configuration injected by `init`.
struct GuestConfig {
    provider_id: String,
    email: String,
    urls: ServerUrls,
    device_id: String,
}

/// Authenticated state — populated by `unlock`, cleared by `lock`.
struct AuthState {
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    /// The protected symmetric key from the login response.
    /// Cached here so we can reconstruct the vault on refresh-based unlock.
    protected_key: Zeroizing<String>,
    vault: VaultState,
}

/// Minimal session state preserved across lock/unlock cycles.
///
/// The `protected_key` is the server-encrypted vault key — it is useless
/// without the password-derived master key, so caching it does not weaken
/// the security model.  The user must still provide their password on
/// every unlock to derive vault decryption keys.
struct CachedSession {
    refresh_token: Zeroizing<String>,
    protected_key: Zeroizing<String>,
}

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

/// Attribute key for item type — mirrors `rosec_core::ATTR_TYPE`.
const ATTR_TYPE: &str = "rosec:type";
/// Attribute key for TOTP presence — mirrors `rosec_core::ATTR_TOTP`.
const ATTR_TOTP: &str = "rosec:totp";

/// PEM headers that indicate an SSH private key in a text field.
const PEM_HEADERS: &[&str] = &[
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
];

// ═══════════════════════════════════════════════════════════════════
// Attribute catalogue (35 descriptors)
// ═══════════════════════════════════════════════════════════════════

/// Build the full attribute descriptor catalogue.
///
/// Returns the same 35 descriptors as native `BITWARDEN_ATTRIBUTES` but
/// serialised as `WasmAttributeDescriptor` for JSON transport.
fn bitwarden_attribute_descriptors() -> Vec<WasmAttributeDescriptor> {
    vec![
        desc("name", false, &[], "Item display name"),
        desc(
            ATTR_TYPE,
            false,
            &[],
            "Item type (login, note, card, identity, ssh-key)",
        ),
        desc("folder", false, &[], "Folder name (if assigned)"),
        desc("notes", true, &[], "Free-form notes (always sensitive)"),
        desc(
            "username",
            false,
            &["login"],
            "Login username (public per attribute-model decision)",
        ),
        desc("password", true, &["login"], "Login password"),
        desc("totp", true, &["login"], "TOTP seed / otpauth URI"),
        desc("uri", false, &["login"], "Primary login URI"),
        desc("cardholder", true, &["card"], "Cardholder name (PII)"),
        desc("number", true, &["card"], "Card number"),
        desc(
            "brand",
            false,
            &["card"],
            "Card brand (Visa, Mastercard, etc.)",
        ),
        desc("exp_month", true, &["card"], "Card expiration month"),
        desc("exp_year", true, &["card"], "Card expiration year"),
        desc("code", true, &["card"], "Card security code (CVV)"),
        desc("private_key", true, &["ssh-key"], "SSH private key"),
        desc("public_key", false, &["ssh-key"], "SSH public key"),
        desc("fingerprint", false, &["ssh-key"], "SSH key fingerprint"),
        desc(
            "title",
            true,
            &["identity"],
            "Identity title (Mr, Ms, etc.)",
        ),
        desc("first_name", true, &["identity"], "First name"),
        desc("middle_name", true, &["identity"], "Middle name"),
        desc("last_name", true, &["identity"], "Last name"),
        desc("username", true, &["identity"], "Identity username (PII)"),
        desc("company", true, &["identity"], "Company name"),
        desc("ssn", true, &["identity"], "Social Security Number"),
        desc("passport_number", true, &["identity"], "Passport number"),
        desc(
            "license_number",
            true,
            &["identity"],
            "Driver's license number",
        ),
        desc("email", true, &["identity"], "Identity email address (PII)"),
        desc("phone", true, &["identity"], "Identity phone number (PII)"),
        desc("address1", true, &["identity"], "Address line 1"),
        desc("address2", true, &["identity"], "Address line 2"),
        desc("address3", true, &["identity"], "Address line 3"),
        desc("city", true, &["identity"], "City"),
        desc("state", true, &["identity"], "State / province"),
        desc("postal_code", true, &["identity"], "Postal / ZIP code"),
        desc("country", true, &["identity"], "Country"),
    ]
}

/// Helper: build a `WasmAttributeDescriptor`.
fn desc(
    name: &str,
    sensitive: bool,
    item_types: &[&str],
    description: &str,
) -> WasmAttributeDescriptor {
    WasmAttributeDescriptor {
        name: name.to_string(),
        sensitive,
        item_types: item_types.iter().map(|s| (*s).to_string()).collect(),
        description: description.to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════
// Helper functions (ported from native provider.rs)
// ═══════════════════════════════════════════════════════════════════

/// Populate public (non-sensitive) attributes for a decrypted cipher.
///
/// Port of `BitwardenProvider::populate_public_attrs`.
fn populate_public_attrs(attrs: &mut HashMap<String, String>, dc: &DecryptedCipher) {
    // xdg:schema — required for Secret Service compatibility
    let schema = match dc.cipher_type {
        CipherType::Login => "org.freedesktop.Secret.Generic",
        CipherType::SecureNote => "org.freedesktop.Secret.Note",
        _ => "org.freedesktop.Secret.Generic",
    };
    attrs.insert("xdg:schema".to_string(), schema.to_string());
    attrs.insert(ATTR_TYPE.to_string(), dc.cipher_type.as_str().to_string());

    if let Some(folder) = &dc.folder_name {
        attrs.insert("folder".to_string(), folder.clone());
    }
    if let Some(org_id) = &dc.organization_id {
        attrs.insert("org_id".to_string(), org_id.clone());
    }
    if let Some(org_name) = &dc.organization_name {
        attrs.insert("org".to_string(), org_name.clone());
    }

    // Login-specific public attributes
    if let Some(login) = &dc.login {
        // username is public per attribute-model decision
        if let Some(username) = &login.username {
            attrs.insert("username".to_string(), username.as_str().to_string());
        }
        // All URIs are public. First is "uri" (index 0); subsequent are "uri.1", "uri.2", etc.
        for (i, uri) in login.uris.iter().enumerate() {
            let key = if i == 0 {
                "uri".to_string()
            } else {
                format!("uri.{i}")
            };
            attrs.insert(key, uri.clone());
        }
        // Stamp TOTP presence for searchability.
        if login.totp.is_some() {
            attrs.insert(ATTR_TOTP.to_string(), "true".to_string());
        }
    }

    // Card-specific public attributes (brand only — cardholder is PII/sensitive)
    if let Some(card) = &dc.card
        && let Some(brand) = &card.brand
    {
        attrs.insert("brand".to_string(), brand.clone());
    }

    // SSH key public attributes
    if let Some(ssh_key) = &dc.ssh_key {
        if let Some(pub_key) = &ssh_key.public_key {
            attrs.insert("public_key".to_string(), pub_key.clone());
        }
        if let Some(fp) = &ssh_key.fingerprint {
            attrs.insert("fingerprint".to_string(), fp.clone());
        }
    }

    // Custom fields as attributes — only text (type 0), boolean (type 2),
    // and linked (type 3). Hidden fields (type 1) are sensitive and excluded.
    for (key, value) in index_custom_fields(&dc.fields, &[0, 2, 3]) {
        attrs.insert(key, value);
    }
}

/// Convert a `SystemTime` to seconds since the Unix epoch.
fn to_epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a `WasmItemMeta` from a decrypted cipher.
///
/// Port of `BitwardenProvider::cipher_to_meta`.
fn cipher_to_wasm_meta(provider_id: &str, dc: &DecryptedCipher) -> WasmItemMeta {
    let mut attributes = HashMap::new();
    populate_public_attrs(&mut attributes, dc);

    let created = dc.creation_date.as_ref().and_then(|s| parse_iso8601(s));
    let modified = dc.revision_date.as_ref().and_then(|s| parse_iso8601(s));

    // Inject provider_id attribute for the host (mirrors rosec:provider)
    attributes.insert("rosec:provider".to_string(), provider_id.to_string());

    WasmItemMeta {
        id: dc.id.clone(),
        label: dc.name.clone(),
        attributes,
        created_epoch_secs: created.map(to_epoch_secs),
        modified_epoch_secs: modified.map(to_epoch_secs),
    }
}

/// One sensitive field on a cipher subtype, used as the source-of-truth for
/// both `build_item_attributes` (which fields go into `secret_names`) and
/// `resolve_secret_attr` (how to fetch the bytes for a given name).
///
/// Some fields are reachable via the secret API but exposed as public
/// attributes rather than secret names — `login.username` is the only such
/// case today, marked `is_secret_name = false`.
struct CipherField<T> {
    /// Attribute name exposed via the secret API.
    name: &'static str,
    /// Whether this field appears in the `secret_names` list.
    is_secret_name: bool,
    /// Accessor for the field on the decrypted struct.
    getter: fn(&T) -> Option<&Zeroizing<String>>,
}

const LOGIN_SECRET_FIELDS: &[CipherField<DecryptedLogin>] = &[
    CipherField {
        name: "password",
        is_secret_name: true,
        getter: |l| l.password.as_ref(),
    },
    CipherField {
        name: "totp",
        is_secret_name: true,
        getter: |l| l.totp.as_ref(),
    },
    // Username is fetchable via the secret API but exposed as a public
    // attribute (per attribute-model decision) — not in secret_names.
    CipherField {
        name: "username",
        is_secret_name: false,
        getter: |l| l.username.as_ref(),
    },
];

const CARD_SECRET_FIELDS: &[CipherField<DecryptedCard>] = &[
    CipherField {
        name: "cardholder",
        is_secret_name: true,
        getter: |c| c.cardholder_name.as_ref(),
    },
    CipherField {
        name: "number",
        is_secret_name: true,
        getter: |c| c.number.as_ref(),
    },
    CipherField {
        name: "exp_month",
        is_secret_name: true,
        getter: |c| c.exp_month.as_ref(),
    },
    CipherField {
        name: "exp_year",
        is_secret_name: true,
        getter: |c| c.exp_year.as_ref(),
    },
    CipherField {
        name: "code",
        is_secret_name: true,
        getter: |c| c.code.as_ref(),
    },
];

const SSH_KEY_SECRET_FIELDS: &[CipherField<DecryptedSshKey>] = &[CipherField {
    name: "private_key",
    is_secret_name: true,
    getter: |s| s.private_key.as_ref(),
}];

const IDENTITY_SECRET_FIELDS: &[CipherField<DecryptedIdentity>] = &[
    CipherField {
        name: "title",
        is_secret_name: true,
        getter: |i| i.title.as_ref(),
    },
    CipherField {
        name: "first_name",
        is_secret_name: true,
        getter: |i| i.first_name.as_ref(),
    },
    CipherField {
        name: "middle_name",
        is_secret_name: true,
        getter: |i| i.middle_name.as_ref(),
    },
    CipherField {
        name: "last_name",
        is_secret_name: true,
        getter: |i| i.last_name.as_ref(),
    },
    CipherField {
        name: "username",
        is_secret_name: true,
        getter: |i| i.username.as_ref(),
    },
    CipherField {
        name: "company",
        is_secret_name: true,
        getter: |i| i.company.as_ref(),
    },
    CipherField {
        name: "ssn",
        is_secret_name: true,
        getter: |i| i.ssn.as_ref(),
    },
    CipherField {
        name: "passport_number",
        is_secret_name: true,
        getter: |i| i.passport_number.as_ref(),
    },
    CipherField {
        name: "license_number",
        is_secret_name: true,
        getter: |i| i.license_number.as_ref(),
    },
    CipherField {
        name: "email",
        is_secret_name: true,
        getter: |i| i.email.as_ref(),
    },
    CipherField {
        name: "phone",
        is_secret_name: true,
        getter: |i| i.phone.as_ref(),
    },
    CipherField {
        name: "address1",
        is_secret_name: true,
        getter: |i| i.address1.as_ref(),
    },
    CipherField {
        name: "address2",
        is_secret_name: true,
        getter: |i| i.address2.as_ref(),
    },
    CipherField {
        name: "address3",
        is_secret_name: true,
        getter: |i| i.address3.as_ref(),
    },
    CipherField {
        name: "city",
        is_secret_name: true,
        getter: |i| i.city.as_ref(),
    },
    CipherField {
        name: "state",
        is_secret_name: true,
        getter: |i| i.state.as_ref(),
    },
    CipherField {
        name: "postal_code",
        is_secret_name: true,
        getter: |i| i.postal_code.as_ref(),
    },
    CipherField {
        name: "country",
        is_secret_name: true,
        getter: |i| i.country.as_ref(),
    },
];

/// Look up `attr` in `table` and return the field's bytes, if any.
fn resolve_field<T>(table: &[CipherField<T>], obj: &T, attr: &str) -> Option<Vec<u8>> {
    table
        .iter()
        .find(|f| f.name == attr)
        .and_then(|f| (f.getter)(obj))
        .map(zeroizing_to_bytes)
}

/// Append every populated field marked `is_secret_name` to `out`.
fn append_secret_names<T>(table: &[CipherField<T>], obj: &T, out: &mut Vec<String>) {
    for f in table {
        if f.is_secret_name && (f.getter)(obj).is_some() {
            out.push(f.name.to_string());
        }
    }
}

/// Build item attributes (public + secret names) for a decrypted cipher.
///
/// Port of `BitwardenProvider::build_item_attributes`.
fn build_item_attributes(
    provider_id: &str,
    dc: &DecryptedCipher,
) -> (HashMap<String, String>, Vec<String>) {
    let mut public = HashMap::new();
    let mut secret_names = Vec::new();

    populate_public_attrs(&mut public, dc);

    public.insert("provider_id".to_string(), provider_id.to_string());

    // notes — always sensitive
    if dc.notes.is_some() {
        secret_names.push("notes".to_string());
    }

    if let Some(login) = &dc.login {
        append_secret_names(LOGIN_SECRET_FIELDS, login, &mut secret_names);
    }
    if let Some(card) = &dc.card {
        append_secret_names(CARD_SECRET_FIELDS, card, &mut secret_names);
    }
    if let Some(ssh_key) = &dc.ssh_key {
        append_secret_names(SSH_KEY_SECRET_FIELDS, ssh_key, &mut secret_names);
    }
    if let Some(ident) = &dc.identity {
        append_secret_names(IDENTITY_SECRET_FIELDS, ident, &mut secret_names);
    }

    for (key, _) in index_custom_fields(&dc.fields, &[1]) {
        secret_names.push(key);
    }

    (public, secret_names)
}

/// Convert a `Zeroizing<String>` to bytes (for secret attribute returns).
fn zeroizing_to_bytes(s: &Zeroizing<String>) -> Vec<u8> {
    s.as_bytes().to_vec()
}

/// Resolve a named secret attribute from a decrypted cipher.
///
/// Returns the secret value as bytes, or `None` if the attribute doesn't
/// exist on this cipher type or has no value.
///
/// Port of `BitwardenProvider::resolve_secret_attr`.
fn resolve_secret_attr(dc: &DecryptedCipher, attr: &str) -> Option<Vec<u8>> {
    if attr == "notes" {
        return dc.notes.as_ref().map(zeroizing_to_bytes);
    }
    if let Some(custom_name) = attr.strip_prefix("custom.") {
        return resolve_custom_field(dc, custom_name);
    }
    match dc.cipher_type {
        CipherType::Login => resolve_field(LOGIN_SECRET_FIELDS, dc.login.as_ref()?, attr),
        CipherType::Card => resolve_field(CARD_SECRET_FIELDS, dc.card.as_ref()?, attr),
        CipherType::SshKey => resolve_field(SSH_KEY_SECRET_FIELDS, dc.ssh_key.as_ref()?, attr),
        CipherType::Identity => resolve_field(IDENTITY_SECRET_FIELDS, dc.identity.as_ref()?, attr),
        CipherType::SecureNote | CipherType::Unknown(_) => None,
    }
}

/// Look up `custom.<name>[.<occurrence>]` against the cipher's custom fields.
fn resolve_custom_field(dc: &DecryptedCipher, custom_name: &str) -> Option<Vec<u8>> {
    let (base_name, occurrence) = match custom_name.rsplit_once('.') {
        Some((base, suffix)) => match suffix.parse::<usize>() {
            Ok(idx) => (base, idx),
            Err(_) => (custom_name, 0),
        },
        None => (custom_name, 0),
    };
    let mut count = 0usize;
    for field in &dc.fields {
        if field.name.as_deref() == Some(base_name) {
            if count == occurrence {
                return field.value.as_ref().map(zeroizing_to_bytes);
            }
            count += 1;
        }
    }
    None
}

// ── SSH key helpers ──────────────────────────────────────────────

/// Return `true` if `text` contains a recognised PEM private key header.
fn contains_pem(text: &str) -> bool {
    PEM_HEADERS.iter().any(|h| text.contains(h))
}

/// Extract the first PEM block from `text`, or `None`.
fn extract_pem_from_text(text: &str) -> Option<Zeroizing<String>> {
    for header in PEM_HEADERS {
        if let Some(start) = text.find(header) {
            let after = &text[start..];
            if let Some(end_marker) = after.find("-----END ") {
                let after_end = &after[end_marker..];
                let line_end = after_end.find('\n').unwrap_or(after_end.len());
                let pem = &after[..end_marker + line_end + 1];
                return Some(Zeroizing::new(pem.to_string()));
            }
        }
    }
    None
}

/// Extract the first recognisable PEM private key from any field of `dc`.
///
/// Search order: native `ssh_key.private_key` -> `notes` -> `login.password`
/// -> hidden custom fields (type 1).
fn extract_pem(dc: &DecryptedCipher) -> Option<Zeroizing<String>> {
    // 1. Native SSH key item
    if let Some(sk) = &dc.ssh_key
        && let Some(pk) = &sk.private_key
        && !pk.is_empty()
    {
        return Some(pk.clone());
    }

    // 2. Notes
    if let Some(notes) = &dc.notes
        && contains_pem(notes)
    {
        return extract_pem_from_text(notes);
    }

    // 3. Login password
    if let Some(login) = &dc.login
        && let Some(pw) = &login.password
        && contains_pem(pw)
    {
        return extract_pem_from_text(pw);
    }

    // 4. Hidden custom fields (field_type == 1)
    for field in &dc.fields {
        if field.field_type == 1
            && let Some(val) = &field.value
            && contains_pem(val)
        {
            return extract_pem_from_text(val);
        }
    }

    None
}

/// Build a `WasmSshKeyMeta` for a cipher that has discoverable SSH key
/// material, or `None` if the cipher has none.
///
/// Port of `BitwardenProvider::cipher_to_ssh_key_meta`.
fn cipher_to_ssh_key_meta(_provider_id: &str, dc: &DecryptedCipher) -> Option<WasmSshKeyMeta> {
    // Does this cipher have any SSH key material?
    let has_native_key = dc
        .ssh_key
        .as_ref()
        .is_some_and(|sk| sk.private_key.as_ref().is_some_and(|pk| !pk.is_empty()));

    let has_pem = !has_native_key && extract_pem(dc).is_some();

    if !has_native_key && !has_pem {
        return None;
    }

    let public_key_openssh = dc.ssh_key.as_ref().and_then(|sk| sk.public_key.clone());
    let fingerprint = dc.ssh_key.as_ref().and_then(|sk| sk.fingerprint.clone());

    // Extract custom.ssh_host / custom.ssh-host fields.
    let ssh_hosts: Vec<String> = dc
        .fields
        .iter()
        .filter(|f| matches!(f.name.as_deref(), Some("ssh_host" | "ssh-host")))
        .filter_map(|f| f.value.as_ref())
        .flat_map(|v| v.as_str().lines())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    // Extract custom.ssh_user / custom.ssh-user field (first wins).
    let ssh_user = dc
        .fields
        .iter()
        .filter(|f| matches!(f.name.as_deref(), Some("ssh_user" | "ssh-user")))
        .filter_map(|f| f.value.as_ref())
        .map(|v| v.as_str().trim().to_string())
        .find(|s| !s.is_empty());

    // Extract custom.ssh_confirm / custom.ssh-confirm flag.
    let require_confirm = dc.fields.iter().any(|f| {
        matches!(f.name.as_deref(), Some("ssh_confirm" | "ssh-confirm"))
            && f.value.as_ref().map(|v| v.as_str()) == Some("true")
    });

    let revision_date = dc.revision_date.as_deref().and_then(parse_iso8601);

    Some(WasmSshKeyMeta {
        item_id: dc.id.clone(),
        item_name: dc.name.clone(),
        public_key_openssh,
        fingerprint,
        ssh_hosts,
        ssh_user,
        require_confirm,
        revision_date_epoch_secs: revision_date.map(to_epoch_secs),
    })
}

// ── Custom field indexing ────────────────────────────────────────

/// Index custom fields for attribute maps.
///
/// Returns `(key, value)` pairs with proper indexing for duplicate names:
/// - Single occurrence: just `custom.<name>` -> value
/// - Multiple occurrences:
///   - `custom.<name>`   -> first value  (unindexed alias)
///   - `custom.<name>.0` -> first value
///   - `custom.<name>.1` -> second value
///   - `custom.<name>.2` -> third value
///
/// `allowed_types` filters which `field_type` values to include
/// (0 = text, 1 = hidden, 2 = boolean, 3 = linked).
fn index_custom_fields(fields: &[DecryptedField], allowed_types: &[u8]) -> Vec<(String, String)> {
    // Group field values by name, preserving order within each name.
    let mut groups: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut order: Vec<&str> = Vec::new();
    for field in fields {
        if !allowed_types.contains(&field.field_type) {
            continue;
        }
        if let (Some(name), Some(value)) = (&field.name, &field.value) {
            let name_str = name.as_str();
            let entry = groups.entry(name_str).or_default();
            if entry.is_empty() {
                order.push(name_str);
            }
            entry.push(value.as_str());
        }
    }

    let mut result = Vec::new();
    for name in order {
        let values = &groups[name];
        let base_key = format!("custom.{name}");
        if values.len() == 1 {
            result.push((base_key, values[0].to_string()));
        } else {
            result.push((base_key.clone(), values[0].to_string()));
            for (i, val) in values.iter().enumerate() {
                result.push((format!("{base_key}.{i}"), (*val).to_string()));
            }
        }
    }
    result
}

// ── ISO 8601 parsing ─────────────────────────────────────────────

/// Parse an ISO 8601 timestamp string to `SystemTime`.
///
/// Simple parser: `"2024-01-15T12:30:00.000Z"` — no chrono dependency.
fn parse_iso8601(s: &str) -> Option<SystemTime> {
    let s = s.trim_end_matches('Z');
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 {
        return None;
    }

    let date_parts: Vec<u64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    let time_str = parts[1].split('.').next()?;
    let time_parts: Vec<u64> = time_str.split(':').filter_map(|p| p.parse().ok()).collect();

    if date_parts.len() != 3 || time_parts.len() != 3 {
        return None;
    }

    let (year, month, day) = (date_parts[0], date_parts[1], date_parts[2]);
    let (hour, minute, second) = (time_parts[0], time_parts[1], time_parts[2]);

    let days_since_epoch = (year - 1970) * 365
        + (year - 1969) / 4
        + days_before_month(month, is_leap_year(year))
        + (day - 1);

    let secs = days_since_epoch * 86400 + hour * 3600 + minute * 60 + second;

    Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_before_month(month: u64, leap: bool) -> u64 {
    let days = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let d = days
        .get((month as usize).wrapping_sub(1))
        .copied()
        .unwrap_or(0);
    if leap && month > 2 { d + 1 } else { d }
}

// ═══════════════════════════════════════════════════════════════════
// Auth flow helpers
// ═══════════════════════════════════════════════════════════════════

/// Perform authentication + sync, preferring a cached refresh token when
/// available to avoid a full `grant_type=password` login.
///
/// A full password login causes Bitwarden's server to establish a new device
/// session, which can invalidate tokens held by other Bitwarden clients on
/// the same account.  By reusing the refresh token from the previous session
/// we keep the existing session alive and avoid deauthing other clients.
///
/// The password is **always** required — it derives the master key needed to
/// decrypt the protected symmetric vault key, regardless of the auth path.
fn authenticate(
    config: &GuestConfig,
    password: &str,
    two_factor: Option<TwoFactorSubmission>,
    cached_session: Option<CachedSession>,
) -> Result<AuthState, BitwardenError> {
    let email = &config.email;
    let api = ApiClient::new(config.urls.clone(), config.device_id.clone());

    // Step 1: Prelogin — always needed for KDF params.
    let kdf = api.prelogin(email)?;
    extism_pdk::debug!("got KDF params: {:?}", kdf);

    // Step 2: Key derivation — always needed to decrypt vault.
    let master_key = crypto::derive_master_key(password.as_bytes(), email, &kdf)?;
    let identity_keys = crypto::expand_master_key(&master_key)?;

    // Step 3: Obtain access token + protected key.
    //
    // Try refresh_token grant first (no new device session).
    // Fall back to full password login if refresh fails or isn't available.
    let (access_token, refresh_token, protected_key) = if two_factor.is_none() {
        if let Some(cached) = cached_session {
            match api.refresh_token(&cached.refresh_token) {
                Ok(resp) => {
                    extism_pdk::info!("unlocked via refresh token (no new device session)");
                    (resp.access_token, resp.refresh_token, cached.protected_key)
                }
                Err(e) => {
                    extism_pdk::info!(
                        "refresh token expired or rejected, falling back to password login: {e}"
                    );
                    full_password_login(&api, email, password, &master_key, None)?
                }
            }
        } else {
            full_password_login(&api, email, password, &master_key, None)?
        }
    } else {
        // 2FA requires a full password login.
        full_password_login(&api, email, password, &master_key, two_factor)?
    };

    // Step 4: Initialize vault state from protected key.
    let mut vault_state = VaultState::new(&identity_keys, &protected_key)?;

    // Step 5: Sync.
    let sync = api.sync(&access_token)?;
    vault_state.process_sync(&sync)?;

    Ok(AuthState {
        access_token,
        refresh_token,
        protected_key,
        vault: vault_state,
    })
}

/// Result of a password-based login: (access_token, refresh_token, protected_key).
type LoginTokens = (
    Zeroizing<String>,
    Option<Zeroizing<String>>,
    Zeroizing<String>,
);

/// Perform a full `grant_type=password` login.
fn full_password_login(
    api: &ApiClient,
    email: &str,
    password: &str,
    master_key: &[u8],
    two_factor: Option<TwoFactorSubmission>,
) -> Result<LoginTokens, BitwardenError> {
    let password_hash = crypto::derive_password_hash(master_key, password.as_bytes());
    let hash_b64 = crypto::b64_encode(&password_hash);
    let login_resp = api.login_password(email, &hash_b64, two_factor)?;

    let protected_key = login_resp
        .key
        .ok_or_else(|| BitwardenError::Auth("no protected key in login response".to_string()))?;

    Ok((
        login_resp.access_token,
        login_resp.refresh_token,
        protected_key,
    ))
}

/// Re-sync the vault using the existing access token.
///
/// If the access token has expired and a refresh token is available,
/// automatically refreshes the token and retries.
///
/// Port of `BitwardenProvider::resync`.
fn resync(auth: &mut AuthState, urls: &ServerUrls, device_id: &str) -> Result<(), BitwardenError> {
    let api = ApiClient::new(urls.clone(), device_id.to_string());

    match api.sync(&auth.access_token) {
        Ok(sync) => {
            auth.vault.process_sync(&sync)?;
            extism_pdk::debug!("vault resynced: ciphers={}", auth.vault.ciphers().len());
            Ok(())
        }
        Err(BitwardenError::Auth(_)) => {
            // Access token expired — try refreshing
            let refresh_token = match &auth.refresh_token {
                Some(rt) => rt.clone(),
                None => {
                    return Err(BitwardenError::Auth(
                        "access token expired and no refresh token available".to_string(),
                    ));
                }
            };

            extism_pdk::debug!("access token expired, refreshing");
            let refresh_resp = api.refresh_token(&refresh_token)?;
            auth.access_token = refresh_resp.access_token;
            if let Some(new_rt) = refresh_resp.refresh_token {
                auth.refresh_token = Some(new_rt);
            }
            extism_pdk::info!("access token refreshed");

            // Retry sync with new token
            let sync = api.sync(&auth.access_token)?;
            auth.vault.process_sync(&sync)?;
            extism_pdk::debug!(
                "vault resynced after token refresh: ciphers={}",
                auth.vault.ciphers().len()
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

// ── Response builders ────────────────────────────────────────────

/// Build an error `SimpleResponse` from a `BitwardenError`.
fn simple_err(e: &BitwardenError) -> SimpleResponse {
    SimpleResponse {
        ok: false,
        error: Some(e.to_string()),
        error_kind: Some(e.to_error_kind()),
        two_factor_methods: None,
    }
}

/// Build a `TwoFactorRequired` error response with the available methods.
fn simple_err_2fa(providers: &[u8], email_hint: Option<&str>) -> SimpleResponse {
    SimpleResponse {
        ok: false,
        error: Some("two-factor authentication required".to_string()),
        error_kind: Some(ErrorKind::TwoFactorRequired),
        two_factor_methods: Some(bitwarden_2fa_methods(providers, email_hint)),
    }
}

/// Map Bitwarden 2FA provider codes to protocol `TwoFactorMethod` descriptors.
///
/// If `email_hint` is provided (e.g. `"j***@example.com"`) and provider 1
/// (email) is in the list, the label is enhanced to show the masked address.
fn bitwarden_2fa_methods(providers: &[u8], email_hint: Option<&str>) -> Vec<TwoFactorMethod> {
    providers
        .iter()
        .filter_map(|&code| {
            let (id, label, prompt_kind) = match code {
                0 => ("0", "Authenticator app (TOTP)", "text"),
                1 => {
                    // Enhance label with email hint when available.
                    let label = match email_hint {
                        Some(hint) => {
                            return Some(TwoFactorMethod {
                                id: "1".to_string(),
                                label: format!("Email code ({hint})"),
                                prompt_kind: "text".to_string(),
                                challenge: None,
                            });
                        }
                        None => "Email code",
                    };
                    ("1", label, "text")
                }
                2 => ("2", "Duo (passcode)", "text"),
                3 => ("3", "YubiKey OTP (touch your key)", "text"),
                4 => ("4", "FIDO2 / WebAuthn security key", "fido2"),
                6 => ("6", "Organization Duo (passcode)", "text"),
                // Provider 5 = "remember" token, not user-facing
                _ => return None,
            };
            Some(TwoFactorMethod {
                id: id.to_string(),
                label: label.to_string(),
                prompt_kind: prompt_kind.to_string(),
                challenge: None,
            })
        })
        .collect()
}

/// Build an ok `SimpleResponse`.
fn simple_ok() -> SimpleResponse {
    SimpleResponse {
        ok: true,
        error: None,
        error_kind: None,
        two_factor_methods: None,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Plugin function exports
// ═══════════════════════════════════════════════════════════════════

/// Return the plugin manifest for discovery.
///
/// Called by the host **before** `init` — no global state is accessed.
/// This allows the host to scan `.wasm` files and discover provider
/// kinds, config requirements, and allowed hosts automatically.
#[plugin_fn]
pub fn plugin_manifest(_: ()) -> FnResult<Json<PluginManifest>> {
    Ok(Json(PluginManifest {
        kind: "bitwarden-pm".to_string(),
        name: "Bitwarden Password Manager".to_string(),
        description: "Bitwarden password manager vault (cloud or self-hosted)".to_string(),
        default_allowed_hosts: vec!["*.bitwarden.com".to_string(), "*.bitwarden.eu".to_string()],
        required_options: vec![PluginOptionDescriptor {
            key: "email".to_string(),
            description: "Bitwarden account email".to_string(),
            kind: "text".to_string(),
        }],
        optional_options: vec![
            PluginOptionDescriptor {
                key: "region".to_string(),
                description: "Cloud region: 'us' or 'eu' (default: us)".to_string(),
                kind: "text".to_string(),
            },
            PluginOptionDescriptor {
                key: "base_url".to_string(),
                description: "Self-hosted base URL, e.g. https://vault.example.com".to_string(),
                kind: "text".to_string(),
            },
            PluginOptionDescriptor {
                key: "api_url".to_string(),
                description: "Explicit API URL override (overrides region/base_url)".to_string(),
                kind: "text".to_string(),
            },
            PluginOptionDescriptor {
                key: "identity_url".to_string(),
                description: "Explicit identity URL override (overrides region/base_url)"
                    .to_string(),
                kind: "text".to_string(),
            },
            PluginOptionDescriptor {
                key: "collection".to_string(),
                description:
                    "Label stamped on all items as the 'collection' attribute (e.g. 'work')"
                        .to_string(),
                kind: "text".to_string(),
            },
        ],
        id_derivation_key: Some("email".to_string()),
    }))
}

/// Initialise the plugin with provider configuration.
///
/// Called once by the host after loading the WASM module.
/// Expects `InitRequest` JSON with `provider_id`, `provider_name`, and
/// `options` containing `email`, `device_id`, and URL configuration.
#[plugin_fn]
pub fn init(Json(req): Json<InitRequest>) -> FnResult<Json<InitResponse>> {
    let email = req
        .options
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    if email.is_empty() {
        return Ok(Json(InitResponse {
            ok: false,
            error: Some("missing required option: email".to_string()),
        }));
    }

    let device_id = req
        .options
        .get("device_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    if device_id.is_empty() {
        return Ok(Json(InitResponse {
            ok: false,
            error: Some("missing required option: device_id".to_string()),
        }));
    }

    // Resolve server URLs — same priority as native BitwardenConfig.
    let urls = match (
        req.options.get("api_url").and_then(|v| v.as_str()),
        req.options.get("identity_url").and_then(|v| v.as_str()),
    ) {
        (Some(api), Some(identity)) => {
            // Derive notifications URL from api_url by stripping "/api"
            // and appending "/notifications", or fallback to "{api}/notifications".
            let notifications_url = req
                .options
                .get("notifications_url")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| {
                    api.strip_suffix("/api")
                        .map(|base| format!("{base}/notifications"))
                        .unwrap_or_else(|| format!("{api}/notifications"))
                });
            ServerUrls {
                api_url: api.to_string(),
                identity_url: identity.to_string(),
                notifications_url,
            }
        }
        _ => match req.options.get("base_url").and_then(|v| v.as_str()) {
            Some(base) => ServerUrls::from_base(base),
            None => {
                let region = req
                    .options
                    .get("region")
                    .and_then(|v| v.as_str())
                    .unwrap_or("us");
                match region.to_ascii_lowercase().as_str() {
                    "eu" => ServerUrls::official_eu(),
                    _ => ServerUrls::official_us(),
                }
            }
        },
    };

    let config = GuestConfig {
        provider_id: req.provider_id,
        email,
        urls,
        device_id,
    };

    extism_pdk::info!(
        "bitwarden-wasm plugin initialised: provider_id={}",
        config.provider_id
    );

    let mut guard = STATE.lock();
    *guard = Some(GuestState {
        config,
        auth: None,
        cached_session: None,
    });

    Ok(Json(InitResponse {
        ok: true,
        error: None,
    }))
}

/// Return the current provider status (locked/unlocked + last sync time).
#[plugin_fn]
pub fn status(_input: ()) -> FnResult<Json<StatusResponse>> {
    let guard = STATE.lock();

    let Some(state) = guard.as_ref() else {
        // Not yet initialised — report as locked
        return Ok(Json(StatusResponse {
            locked: true,
            last_sync_epoch_secs: None,
        }));
    };

    match &state.auth {
        Some(auth) => Ok(Json(StatusResponse {
            locked: false,
            last_sync_epoch_secs: auth.vault.last_sync().map(to_epoch_secs),
        })),
        None => Ok(Json(StatusResponse {
            locked: true,
            last_sync_epoch_secs: None,
        })),
    }
}

/// Unlock the vault with a master password (and optional registration/auth fields).
#[plugin_fn]
pub fn unlock(Json(req): Json<UnlockRequest>) -> FnResult<Json<SimpleResponse>> {
    let mut guard = STATE.lock();

    let Some(state) = guard.as_mut() else {
        return Ok(Json(SimpleResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            two_factor_methods: None,
        }));
    };

    // Handle device registration if credentials were supplied
    if let Some(reg_fields) = &req.registration_fields {
        let client_id = reg_fields
            .get("client_id")
            .map(String::as_str)
            .unwrap_or_default();
        let client_secret = reg_fields
            .get("client_secret")
            .map(String::as_str)
            .unwrap_or_default();

        if client_id.is_empty() || client_secret.is_empty() {
            return Ok(Json(SimpleResponse {
                ok: false,
                error: Some("registration requires client_id and client_secret".to_string()),
                error_kind: Some(ErrorKind::InvalidInput),
                two_factor_methods: None,
            }));
        }

        let api = ApiClient::new(state.config.urls.clone(), state.config.device_id.clone());
        if let Err(e) = api.register_device(&state.config.email, client_id, client_secret) {
            return Ok(Json(simple_err(&e)));
        }
        extism_pdk::info!(
            "device registered for provider '{}'",
            state.config.provider_id
        );
    }

    // Build the TwoFactorSubmission from auth_fields if a 2FA token was
    // provided by the host (after a previous TwoFactorRequired challenge).
    let two_factor = match req.auth_fields.as_ref() {
        Some(af) if af.contains_key("__2fa_method_id") || af.contains_key("__2fa_token") => {
            let Some(method_id) = af.get("__2fa_method_id") else {
                return Ok(Json(SimpleResponse {
                    ok: false,
                    error: Some("missing __2fa_method_id in auth_fields".to_string()),
                    error_kind: Some(ErrorKind::InvalidInput),
                    two_factor_methods: None,
                }));
            };
            let Some(token) = af.get("__2fa_token") else {
                return Ok(Json(SimpleResponse {
                    ok: false,
                    error: Some("missing __2fa_token in auth_fields".to_string()),
                    error_kind: Some(ErrorKind::InvalidInput),
                    two_factor_methods: None,
                }));
            };
            if token.is_empty() {
                return Ok(Json(SimpleResponse {
                    ok: false,
                    error: Some("__2fa_token is empty".to_string()),
                    error_kind: Some(ErrorKind::InvalidInput),
                    two_factor_methods: None,
                }));
            }
            let Ok(provider) = method_id.parse::<u8>() else {
                return Ok(Json(SimpleResponse {
                    ok: false,
                    error: Some(format!("invalid __2fa_method_id: {method_id}")),
                    error_kind: Some(ErrorKind::InvalidInput),
                    two_factor_methods: None,
                }));
            };
            Some(TwoFactorSubmission {
                token: token.clone(),
                provider,
            })
        }
        _ => None,
    };

    // Take the cached session so it can be consumed by authenticate().
    let cached_session = state.cached_session.take();

    match authenticate(&state.config, &req.password, two_factor, cached_session) {
        Ok(auth) => {
            let ciphers = auth.vault.ciphers().len();
            state.auth = Some(auth);
            extism_pdk::info!("vault unlocked: ciphers={ciphers}");
            Ok(Json(simple_ok()))
        }
        Err(BitwardenError::TwoFactorRequired {
            providers,
            email_hint,
        }) => {
            extism_pdk::warn!("unlock requires 2FA, providers: {providers:?}");
            Ok(Json(simple_err_2fa(&providers, email_hint.as_deref())))
        }
        Err(e) => {
            extism_pdk::warn!("unlock failed: {e}");
            Ok(Json(simple_err(&e)))
        }
    }
}

/// Lock the vault — drop decrypted secrets but preserve the refresh token
/// so the next unlock can reuse the existing Bitwarden session instead of
/// performing a full password login (which deauths other clients).
#[plugin_fn]
pub fn lock(_input: ()) -> FnResult<Json<SimpleResponse>> {
    let mut guard = STATE.lock();

    if let Some(state) = guard.as_mut() {
        // Stash the refresh token + protected key before dropping auth.
        // The protected key is server-encrypted and useless without the
        // password-derived master key, so it's safe to hold in memory.
        state.cached_session = state.auth.as_ref().and_then(|auth| {
            auth.refresh_token.as_ref().map(|rt| CachedSession {
                refresh_token: rt.clone(),
                protected_key: auth.protected_key.clone(),
            })
        });
        // Drop all decrypted vault data, keys, and access token.
        state.auth = None;
        extism_pdk::info!("vault locked (session cached for refresh)");
    }

    Ok(Json(simple_ok()))
}

/// Re-sync the vault with the Bitwarden server.
#[plugin_fn]
pub fn sync(_input: ()) -> FnResult<Json<SimpleResponse>> {
    let mut guard = STATE.lock();

    let Some(state) = guard.as_mut() else {
        return Ok(Json(SimpleResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            two_factor_methods: None,
        }));
    };

    let Some(auth) = state.auth.as_mut() else {
        return Ok(Json(SimpleResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            two_factor_methods: None,
        }));
    };

    match resync(auth, &state.config.urls, &state.config.device_id) {
        Ok(()) => Ok(Json(simple_ok())),
        Err(e) => {
            extism_pdk::warn!("sync failed: {e}");
            Ok(Json(simple_err(&e)))
        }
    }
}

/// List all items in the vault.
#[plugin_fn]
pub fn list_items(_input: ()) -> FnResult<Json<ItemListResponse>> {
    let guard = STATE.lock();

    let Some(state) = guard.as_ref() else {
        return Ok(Json(ItemListResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            items: Vec::new(),
        }));
    };

    let Some(auth) = &state.auth else {
        return Ok(Json(ItemListResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            items: Vec::new(),
        }));
    };

    let provider_id = &state.config.provider_id;
    let items: Vec<WasmItemMeta> = auth
        .vault
        .ciphers()
        .iter()
        .map(|dc| cipher_to_wasm_meta(provider_id, dc))
        .collect();

    Ok(Json(ItemListResponse {
        ok: true,
        error: None,
        error_kind: None,
        items,
    }))
}

/// Search for items matching the given attributes.
#[plugin_fn]
pub fn search(Json(req): Json<SearchRequest>) -> FnResult<Json<ItemListResponse>> {
    let guard = STATE.lock();

    let Some(state) = guard.as_ref() else {
        return Ok(Json(ItemListResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            items: Vec::new(),
        }));
    };

    let Some(auth) = &state.auth else {
        return Ok(Json(ItemListResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            items: Vec::new(),
        }));
    };

    let provider_id = &state.config.provider_id;
    let items: Vec<WasmItemMeta> = auth
        .vault
        .ciphers()
        .iter()
        .filter_map(|dc| {
            let meta = cipher_to_wasm_meta(provider_id, dc);
            if req
                .attributes
                .iter()
                .all(|(key, value)| meta.attributes.get(key) == Some(value))
            {
                Some(meta)
            } else {
                None
            }
        })
        .collect();

    Ok(Json(ItemListResponse {
        ok: true,
        error: None,
        error_kind: None,
        items,
    }))
}

/// Get full attributes (public + secret names) for a single item.
#[plugin_fn]
pub fn get_item_attributes(
    Json(req): Json<ItemIdRequest>,
) -> FnResult<Json<ItemAttributesResponse>> {
    let guard = STATE.lock();

    let Some(state) = guard.as_ref() else {
        return Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            public: HashMap::new(),
            secret_names: Vec::new(),
        }));
    };

    let Some(auth) = &state.auth else {
        return Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            public: HashMap::new(),
            secret_names: Vec::new(),
        }));
    };

    let Some(dc) = auth.vault.cipher_by_id(&req.id) else {
        return Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some(format!("item not found: {}", req.id)),
            error_kind: Some(ErrorKind::NotFound),
            public: HashMap::new(),
            secret_names: Vec::new(),
        }));
    };

    let (public, secret_names) = build_item_attributes(&state.config.provider_id, dc);

    Ok(Json(ItemAttributesResponse {
        ok: true,
        error: None,
        error_kind: None,
        public,
        secret_names,
    }))
}

/// Get a specific secret attribute value for an item.
///
/// Returns the secret bytes base64-encoded.
#[plugin_fn]
pub fn get_secret_attr(Json(req): Json<SecretAttrRequest>) -> FnResult<Json<SecretAttrResponse>> {
    let guard = STATE.lock();

    let Some(state) = guard.as_ref() else {
        return Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            value_b64: None,
        }));
    };

    let Some(auth) = &state.auth else {
        return Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            value_b64: None,
        }));
    };

    let Some(dc) = auth.vault.cipher_by_id(&req.id) else {
        return Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some(format!("item not found: {}", req.id)),
            error_kind: Some(ErrorKind::NotFound),
            value_b64: None,
        }));
    };

    match resolve_secret_attr(dc, &req.attr) {
        Some(bytes) => {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            Ok(Json(SecretAttrResponse {
                ok: true,
                error: None,
                error_kind: None,
                value_b64: Some(b64),
            }))
        }
        None => Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some(format!("attribute not found: {}", req.attr)),
            error_kind: Some(ErrorKind::NotFound),
            value_b64: None,
        })),
    }
}

/// List all SSH keys in the vault.
#[plugin_fn]
pub fn list_ssh_keys(_input: ()) -> FnResult<Json<SshKeyListResponse>> {
    let guard = STATE.lock();

    let Some(state) = guard.as_ref() else {
        return Ok(Json(SshKeyListResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            keys: Vec::new(),
        }));
    };

    let Some(auth) = &state.auth else {
        return Ok(Json(SshKeyListResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            keys: Vec::new(),
        }));
    };

    let provider_id = &state.config.provider_id;
    let keys: Vec<WasmSshKeyMeta> = auth
        .vault
        .ciphers()
        .iter()
        .filter_map(|dc| cipher_to_ssh_key_meta(provider_id, dc))
        .collect();

    Ok(Json(SshKeyListResponse {
        ok: true,
        error: None,
        error_kind: None,
        keys,
    }))
}

/// Get the PEM-encoded SSH private key for an item.
#[plugin_fn]
pub fn get_ssh_private_key(
    Json(req): Json<SshPrivateKeyRequest>,
) -> FnResult<Json<SshPrivateKeyResponse>> {
    let guard = STATE.lock();

    let Some(state) = guard.as_ref() else {
        return Ok(Json(SshPrivateKeyResponse {
            ok: false,
            error: Some("plugin not initialised".to_string()),
            error_kind: Some(ErrorKind::Unavailable),
            pem: None,
        }));
    };

    let Some(auth) = &state.auth else {
        return Ok(Json(SshPrivateKeyResponse {
            ok: false,
            error: Some("vault is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            pem: None,
        }));
    };

    let Some(dc) = auth.vault.cipher_by_id(&req.item_id) else {
        return Ok(Json(SshPrivateKeyResponse {
            ok: false,
            error: Some(format!("item not found: {}", req.item_id)),
            error_kind: Some(ErrorKind::NotFound),
            pem: None,
        }));
    };

    match extract_pem(dc) {
        Some(pem) => Ok(Json(SshPrivateKeyResponse {
            ok: true,
            error: None,
            error_kind: None,
            pem: Some(pem.to_string()),
        })),
        None => Ok(Json(SshPrivateKeyResponse {
            ok: false,
            error: Some(format!(
                "no SSH key material found for item: {}",
                req.item_id
            )),
            error_kind: Some(ErrorKind::NotFound),
            pem: None,
        })),
    }
}

/// Return the provider's capabilities.
///
/// Bitwarden PM supports: Sync, Ssh, OfflineCache, Notifications, Totp
/// (NOT Write, NOT PasswordChange).
#[plugin_fn]
pub fn capabilities(_input: ()) -> FnResult<Json<CapabilitiesResponse>> {
    Ok(Json(CapabilitiesResponse {
        capabilities: vec![
            "sync".to_string(),
            "ssh".to_string(),
            "offline_cache".to_string(),
            "notifications".to_string(),
            "totp".to_string(),
        ],
    }))
}

/// Return the full attribute descriptor catalogue.
#[plugin_fn]
pub fn attribute_descriptors(_input: ()) -> FnResult<Json<AttributeDescriptorsResponse>> {
    Ok(Json(AttributeDescriptorsResponse {
        descriptors: bitwarden_attribute_descriptors(),
    }))
}

/// Return registration info (device registration instructions + fields).
#[plugin_fn]
pub fn registration_info(_input: ()) -> FnResult<Json<RegistrationInfoResponse>> {
    Ok(Json(RegistrationInfoResponse {
        has_registration: true,
        instructions: Some(
            "This device is not registered with Bitwarden. To register it, you need \
             your personal API key.\n\n\
             Find it at: Bitwarden web vault \u{2192} Account Settings \u{2192} Security \u{2192} Keys \u{2192} View API Key"
                .to_string(),
        ),
        fields: vec![
            WasmAuthField {
                id: "client_id".to_string(),
                label: "API key client_id".to_string(),
                placeholder: "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".to_string(),
                required: true,
                kind: "text".to_string(),
            },
            WasmAuthField {
                id: "client_secret".to_string(),
                label: "API key client_secret".to_string(),
                placeholder: String::new(),
                required: true,
                kind: "secret".to_string(),
            },
        ],
    }))
}

/// Return the auth fields for this provider (just the master password).
#[plugin_fn]
pub fn auth_fields(_input: ()) -> FnResult<Json<AuthFieldsResponse>> {
    // The password field is already declared via `password_field()` on the
    // host side.  `auth_fields` is for *additional* authentication fields
    // beyond the primary password (e.g. 2FA tokens).
    Ok(Json(AuthFieldsResponse { fields: vec![] }))
}

/// Return readiness probes for host-side connectivity checks.
///
/// The host evaluates these natively (no WASM involved) before calling
/// network-facing functions like `unlock`, `sync`, or
/// `check_remote_changed`.  This prevents DNS/TLS failures from causing
/// WASM traps that corrupt the plugin's internal state.
///
/// For Bitwarden PM, the identity server is the first endpoint hit during
/// unlock (prelogin + login).  If it's unreachable, there's no point
/// attempting the call.
#[plugin_fn]
pub fn readiness_probes(_input: ()) -> FnResult<Json<ReadinessProbesResponse>> {
    let guard = STATE.lock();

    let Some(state) = guard.as_ref() else {
        // Not initialised yet — no probes to declare.
        return Ok(Json(ReadinessProbesResponse { probes: vec![] }));
    };

    // Probe the API server's /alive health-check endpoint.
    // Both Bitwarden cloud and Vaultwarden return 200 with a small
    // timestamp body.  The previous OIDC discovery endpoint
    // (identity /.well-known/openid-configuration) returns 422 on
    // Vaultwarden, making it unsuitable as a universal probe.
    let probe_url = format!("{}/alive", state.config.urls.api_url);

    Ok(Json(ReadinessProbesResponse {
        probes: vec![ReadinessProbe::Http {
            url: probe_url,
            method: "GET".to_string(),
            expected_status: 200,
            timeout_secs: 5,
        }],
    }))
}

// ── Offline cache ────────────────────────────────────────────────

/// Export the current vault state as an opaque cache blob.
///
/// Serializes the vault state plus session metadata (refresh token,
/// protected key) into a versioned [`CacheBlobRef`], base64-encodes it,
/// and returns the result.  The host wraps this in an additional
/// AES-256-CBC + HMAC-SHA256 encryption layer before persisting to disk.
///
/// ## Refresh token in the cache blob
///
/// The cache blob includes the current refresh token (if available) so
/// that when the provider is restored from cache in offline mode, it can
/// automatically recover a live session once connectivity returns — the
/// guest uses the cached refresh token to obtain a new access token and
/// sync, clearing the `cached` flag without requiring a full re-unlock.
///
/// If the refresh token has expired or been revoked by the time
/// connectivity returns, the sync attempt fails with `AuthFailed` and
/// the host locks the provider, triggering a normal re-unlock prompt.
///
/// **This function is only called when the provider declares
/// `Capability::OfflineCache` *and* the host's per-provider
/// `offline_cache` config is `true` (default).**  The host gates
/// `try_export_cache()` on both conditions, so the refresh token is
/// never persisted to disk when caching is disabled by either the
/// guest (not declaring the capability) or the user (setting
/// `offline_cache = false` in config).
///
/// Returns an error response if the provider is locked (no vault state).
#[plugin_fn]
pub fn export_cache(_input: ()) -> FnResult<Json<ExportCacheResponse>> {
    use base64::Engine;

    let guard = STATE.lock();
    let Some(state) = guard.as_ref() else {
        return Ok(Json(ExportCacheResponse {
            ok: false,
            error: Some("not initialised".to_string()),
            error_kind: Some(ErrorKind::Locked),
            blob_b64: None,
        }));
    };
    let Some(auth) = &state.auth else {
        return Ok(Json(ExportCacheResponse {
            ok: false,
            error: Some("provider is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            blob_b64: None,
        }));
    };

    // Build a borrowing cache blob — avoids cloning VaultState (which
    // intentionally does not implement Clone to prevent untracked copies
    // of secret material).
    let protected_key_ref = if auth.protected_key.is_empty() {
        None
    } else {
        Some(&auth.protected_key)
    };

    let blob_ref = vault::CacheBlobRef {
        version: vault::CacheBlobRef::VERSION,
        vault: &auth.vault,
        refresh_token: auth.refresh_token.as_ref(),
        protected_key: protected_key_ref,
    };

    match blob_ref.to_bytes() {
        Ok(blob) => {
            let blob_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
            Ok(Json(ExportCacheResponse {
                ok: true,
                error: None,
                error_kind: None,
                blob_b64: Some(blob_b64),
            }))
        }
        Err(e) => Ok(Json(ExportCacheResponse {
            ok: false,
            error: Some(format!("cache export failed: {e}")),
            error_kind: Some(ErrorKind::Other),
            blob_b64: None,
        })),
    }
}

/// Restore vault state from a cache blob previously exported by
/// [`export_cache`].
///
/// Decodes the base64 blob, deserializes the versioned [`CacheBlob`]
/// envelope, and sets it as the current auth state.  This is used for
/// offline unlock when the network is unavailable.
///
/// ## Session recovery from cached tokens
///
/// If the cache blob contains a refresh token and protected key (v2+
/// blobs), the restored auth state includes them so that when
/// connectivity returns, [`resync`] can transparently refresh the access
/// token and sync the vault — clearing the `cached` flag without
/// requiring user interaction.
///
/// Legacy v1 blobs (bare `VaultState` without session metadata) are
/// still supported: the provider will be restored in read-only offline
/// mode with no tokens, and a full re-unlock will be required when
/// connectivity returns.
///
/// **The refresh token is only present in the cache blob when
/// `Capability::OfflineCache` is declared *and* the host's
/// `offline_cache` config is enabled.** If either condition is false,
/// the host never calls `export_cache` and no tokens are persisted.
#[plugin_fn]
pub fn restore_cache(Json(input): Json<RestoreCacheRequest>) -> FnResult<Json<SimpleResponse>> {
    use base64::Engine;

    let blob = match base64::engine::general_purpose::STANDARD.decode(&input.blob_b64) {
        Ok(b) => b,
        Err(e) => {
            return Ok(Json(SimpleResponse {
                ok: false,
                error: Some(format!("base64 decode failed: {e}")),
                error_kind: Some(ErrorKind::InvalidInput),
                two_factor_methods: None,
            }));
        }
    };

    let cache_blob = match vault::CacheBlob::from_bytes(&blob) {
        Ok(cb) => cb,
        Err(e) => {
            return Ok(Json(SimpleResponse {
                ok: false,
                error: Some(format!("cache restore failed: {e}")),
                error_kind: Some(ErrorKind::Other),
                two_factor_methods: None,
            }));
        }
    };

    let has_session = cache_blob.refresh_token.is_some();

    let mut guard = STATE.lock();
    let Some(state) = guard.as_mut() else {
        return Ok(Json(SimpleResponse {
            ok: false,
            error: Some("not initialised".to_string()),
            error_kind: Some(ErrorKind::Locked),
            two_factor_methods: None,
        }));
    };

    // Restore auth state from the cache blob.  If the blob includes
    // session tokens (v2+), the provider can attempt token refresh when
    // connectivity returns.  Otherwise it runs in read-only offline mode.
    state.auth = Some(AuthState {
        access_token: Zeroizing::new(String::new()),
        refresh_token: cache_blob.refresh_token,
        protected_key: cache_blob
            .protected_key
            .unwrap_or_else(|| Zeroizing::new(String::new())),
        vault: cache_blob.vault,
    });

    if has_session {
        extism_pdk::info!("cache restored with session tokens — online recovery possible");
    } else {
        extism_pdk::info!(
            "cache restored without session tokens (v1 blob) — full re-unlock required for online access"
        );
    }

    Ok(Json(SimpleResponse {
        ok: true,
        error: None,
        error_kind: None,
        two_factor_methods: None,
    }))
}

// ── Real-time notifications ─────────────────────────────────────

/// SignalR record separator — every frame is terminated by this byte.
const SIGNALR_RS: char = '\x1e';

/// Bitwarden `PushType` values (from `server/src/Core/Enums/PushType.cs`).
///
/// The SignalR hub sends all events via `ReceiveMessage` with the actual
/// event kind as a numeric value in `arguments[0].type`.
mod push_type {
    pub const SYNC_CIPHER_UPDATE: u32 = 0;
    pub const SYNC_CIPHER_CREATE: u32 = 1;
    pub const SYNC_LOGIN_DELETE: u32 = 2;
    pub const SYNC_FOLDER_DELETE: u32 = 3;
    pub const SYNC_CIPHERS: u32 = 4;
    pub const SYNC_VAULT: u32 = 5;
    pub const SYNC_ORG_KEYS: u32 = 6;
    pub const SYNC_FOLDER_CREATE: u32 = 7;
    pub const SYNC_FOLDER_UPDATE: u32 = 8;
    pub const SYNC_CIPHER_DELETE: u32 = 9;
    pub const SYNC_SETTINGS: u32 = 10;
    pub const LOG_OUT: u32 = 11;

    pub const SYNC_TYPES: &[u32] = &[
        SYNC_CIPHER_UPDATE,
        SYNC_CIPHER_CREATE,
        SYNC_LOGIN_DELETE,
        SYNC_FOLDER_DELETE,
        SYNC_CIPHERS,
        SYNC_VAULT,
        SYNC_ORG_KEYS,
        SYNC_FOLDER_CREATE,
        SYNC_FOLDER_UPDATE,
        SYNC_CIPHER_DELETE,
        SYNC_SETTINGS,
    ];
}

/// Minimal SignalR invocation message for frame parsing.
#[derive(serde::Deserialize)]
struct SignalRInvocation {
    target: Option<String>,
    #[serde(default)]
    arguments: Vec<SignalRArgument>,
}

#[derive(serde::Deserialize)]
struct SignalRArgument {
    #[serde(rename = "type")]
    push_type: Option<u32>,
}

/// Return the WebSocket subscription config for Bitwarden's SignalR hub.
///
/// Performs the SignalR negotiate step (HTTP POST) internally using the
/// Extism PDK HTTP capability.  Returns a ready-to-connect WebSocket URL
/// with the access token in the query string, plus the SignalR JSON
/// handshake as the `handshake_message`.
///
/// Returns an error if not authenticated (no access token).
#[plugin_fn]
pub fn get_notification_config(
    _input: (),
) -> FnResult<Json<protocol::NotificationConfigResponse>> {
    let guard = STATE.lock();
    let Some(state) = guard.as_ref() else {
        return Ok(Json(protocol::NotificationConfigResponse {
            ok: false,
            error: Some("not initialised".to_string()),
            error_kind: Some(protocol::ErrorKind::Locked),
            subscription: None,
        }));
    };
    let Some(auth) = &state.auth else {
        return Ok(Json(protocol::NotificationConfigResponse {
            ok: false,
            error: Some("provider is locked".to_string()),
            error_kind: Some(protocol::ErrorKind::Locked),
            subscription: None,
        }));
    };

    let notifications_url = &state.config.urls.notifications_url;
    let access_token = &auth.access_token;

    // ── Negotiate ────────────────────────────────────────────────
    let negotiate_url = format!(
        "{}/hub/negotiate?negotiateVersion=1",
        notifications_url.trim_end_matches('/')
    );

    let negotiate_req = extism_pdk::HttpRequest::new(&negotiate_url)
        .with_method("POST")
        .with_header("Authorization", format!("Bearer {}", access_token.as_str()));

    match extism_pdk::http::request::<()>(&negotiate_req, None) {
        Ok(resp) => {
            let status = resp.status_code();
            if !(200..300).contains(&(status as i32)) {
                extism_pdk::warn!(
                    "SignalR negotiate returned HTTP {status}"
                );
                // Non-fatal — proceed without negotiate (some Vaultwarden
                // instances don't support it).
            }
        }
        Err(e) => {
            extism_pdk::warn!("SignalR negotiate failed: {e}");
            // Non-fatal — try connecting anyway.
        }
    }

    // ── Build WebSocket URL ──────────────────────────────────────
    let (is_secure, without_schema) =
        if let Some(s) = notifications_url.strip_prefix("https://") {
            (true, s)
        } else if let Some(s) = notifications_url.strip_prefix("http://") {
            (false, s)
        } else {
            return Ok(Json(protocol::NotificationConfigResponse {
                ok: false,
                error: Some(format!(
                    "unsupported schema in notifications URL: {notifications_url}"
                )),
                error_kind: Some(protocol::ErrorKind::Other),
                subscription: None,
            }));
        };

    let (host, base_path) = match without_schema.split_once('/') {
        Some((h, p)) => (h, format!("{p}/hub")),
        None => (without_schema, "hub".to_string()),
    };

    let ws_schema = if is_secure { "wss" } else { "ws" };
    let ws_url = format!(
        "{ws_schema}://{host}/{base_path}?access_token={}",
        access_token.as_str()
    );

    // SignalR JSON hub protocol handshake.
    let handshake = format!("{{\"protocol\":\"json\",\"version\":1}}{SIGNALR_RS}");

    Ok(Json(protocol::NotificationConfigResponse {
        ok: true,
        error: None,
        error_kind: None,
        subscription: Some(protocol::WebSocketSubscription {
            url: ws_url,
            headers: std::collections::HashMap::new(),
            handshake_message: Some(handshake),
        }),
    }))
}

/// Parse a raw WebSocket frame from the Bitwarden SignalR hub.
///
/// Classifies each `\x1e`-delimited sub-frame as sync, lock, or ignore.
/// If a frame contains multiple sub-frames and at least one is a sync or
/// lock event, the most important action wins (lock > sync > ignore).
#[plugin_fn]
pub fn parse_notification(
    Json(frame): Json<protocol::NotificationFrame>,
) -> FnResult<Json<protocol::NotificationAction>> {
    use protocol::NotificationActionKind;

    let mut result = NotificationActionKind::Ignore;

    for sub_frame in frame.text.split(SIGNALR_RS) {
        let sub_frame = sub_frame.trim();
        if sub_frame.is_empty() {
            continue;
        }

        let inv: SignalRInvocation = match serde_json::from_str(sub_frame) {
            Ok(i) => i,
            Err(_) => {
                // Unparseable frame (ping, ack, handshake response, etc.)
                continue;
            }
        };

        let Some(target) = inv.target else {
            // No target — likely a ping frame (type 6).
            continue;
        };

        if target != "ReceiveMessage" {
            continue;
        }

        let Some(pt) = inv.arguments.first().and_then(|a| a.push_type) else {
            continue;
        };

        if pt == push_type::LOG_OUT {
            // Lock trumps everything.
            result = NotificationActionKind::Lock;
            break;
        } else if push_type::SYNC_TYPES.contains(&pt) && result != NotificationActionKind::Lock {
            result = NotificationActionKind::Sync;
        }
    }

    Ok(Json(protocol::NotificationAction { action: result }))
}
