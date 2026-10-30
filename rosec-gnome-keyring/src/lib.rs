//! GNOME Keyring read-only provider as an Extism WASM guest plugin for rosec.
//!
//! This plugin reads GNOME Keyring `.keyring` files from the user's keyring
//! directory (default: `~/.local/share/keyrings`) and exposes their contents
//! through the rosec Provider trait via the standard WASM guest protocol.
//!
//! It is **read-only** — it never writes back to the keyring files.  Its
//! primary use case is running rosec alongside an existing GNOME Keyring
//! installation, or migrating away from GNOME Keyring to a rosec LocalVault.
//!
//! # Security
//!
//! All secret material is stored in `Zeroizing<_>` wrappers and is scrubbed
//! from memory when the provider is locked (`lock()`) or the WASM module is
//! unloaded.  The password from `UnlockRequest` is never stored — only the
//! decrypted item payloads are kept in memory while unlocked.
//!
//! # Configuration
//!
//! ```toml
//! [[provider]]
//! kind     = "gnome-keyring"
//! id       = "gnome-keyring"
//! name     = "GNOME Keyring"
//!
//! # Optional: override the keyring directory (default: ~/.local/share/keyrings)
//! keyring_dir = "/home/alice/.local/share/keyrings"
//!
//! # Optional: only load specific keyring files (default: all *.keyring files)
//! # keyrings = ["login", "default"]
//! ```

mod keyring;
mod protocol;

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use extism_pdk::*;
use zeroize::{Zeroize, Zeroizing};

use crate::keyring::{AttributeValue, ParsedKeyring, parse_keyring_file};
use crate::protocol::*;

// ── Global state ──────────────────────────────────────────────────────────────

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

impl<T> WasmCell<T> {
    const fn new(val: T) -> Self {
        Self(Mutex::new(val))
    }

    fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

static STATE: WasmCell<Option<GuestState>> = WasmCell::new(None);

// ── State types ───────────────────────────────────────────────────────────────

struct GuestState {
    config: GuestConfig,
    /// `None` when locked; populated by `unlock()`, dropped by `lock()`.
    auth: Option<AuthState>,
}

struct GuestConfig {
    provider_id: String,
    /// Resolved keyring directory path.
    keyring_dir: String,
    /// Specific keyrings to load (empty = all `*.keyring` files).
    keyrings: Vec<String>,
}

/// All decrypted keyring data in memory.  Dropped (and secrets zeroized) on
/// `lock()`.
struct AuthState {
    keyrings: Vec<ParsedKeyring>,
}

impl Drop for AuthState {
    fn drop(&mut self) {
        // ParsedKeyring → KeyringItem → display_name/secret are Zeroizing<_>;
        // they self-zeroize on drop.  Explicitly drop to be explicit.
        self.keyrings.clear();
    }
}

// ── Attribute constants ───────────────────────────────────────────────────────

const ATTR_TYPE: &str = "rosec:type";
const ATTR_PROVIDER: &str = "rosec:provider";
const ATTR_KEYRING: &str = "rosec:gnome-keyring:keyring";
const ATTR_ITEM_ID: &str = "rosec:gnome-keyring:item-id";
const ATTR_XDG_SCHEMA: &str = "xdg:schema";

// ── Item ID helpers ───────────────────────────────────────────────────────────

/// Stable item ID: `<keyring_name>/<item_numeric_id>`.
fn item_id(keyring_name: &str, item_id: u32) -> String {
    format!("{keyring_name}/{item_id}")
}

/// Parse an item ID back into `(keyring_name, numeric_id)`.
fn parse_item_id(id: &str) -> Option<(&str, u32)> {
    let (k, n) = id.rsplit_once('/')?;
    let num = n.parse::<u32>().ok()?;
    Some((k, num))
}

// ── Item type mapping ─────────────────────────────────────────────────────────

/// Map GNOME Keyring item type to a rosec type string.
fn item_type_str(t: u32) -> &'static str {
    match t {
        1 => "generic",
        2 => "network",
        3 => "note",
        _ => "generic",
    }
}

// ── Build public attributes for one item ─────────────────────────────────────

fn build_public_attrs(
    provider_id: &str,
    keyring_name: &str,
    item: &crate::keyring::KeyringItem,
) -> HashMap<String, String> {
    let mut attrs = HashMap::new();

    attrs.insert(
        ATTR_TYPE.to_owned(),
        item_type_str(item.item_type).to_owned(),
    );
    attrs.insert(ATTR_PROVIDER.to_owned(), provider_id.to_owned());
    attrs.insert(ATTR_KEYRING.to_owned(), keyring_name.to_owned());
    attrs.insert(ATTR_ITEM_ID.to_owned(), item.id.to_string());

    // Expose all non-sensitive GNOME attributes as public attributes.
    // Everything from the keyring file is already "public" in the sense that
    // it was stored in the hashed (unencrypted) section.  We map string
    // values directly; uint32 values are stringified.
    for (k, v) in &item.attributes {
        let string_val = match v {
            AttributeValue::String(s) => s.clone(),
            AttributeValue::UInt32(n) => n.to_string(),
        };
        // Map the well-known `xdg:schema` attribute
        if k == "xdg:schema" {
            attrs.insert(ATTR_XDG_SCHEMA.to_owned(), string_val);
        } else {
            attrs.insert(k.clone(), string_val);
        }
    }

    attrs
}

// ── Build WasmItemMeta ────────────────────────────────────────────────────────

fn to_wasm_item(
    provider_id: &str,
    keyring_name: &str,
    item: &crate::keyring::KeyringItem,
) -> WasmItemMeta {
    WasmItemMeta {
        id: item_id(keyring_name, item.id),
        label: item.display_name.as_str().to_owned(),
        attributes: build_public_attrs(provider_id, keyring_name, item),
        created_epoch_secs: if item.ctime > 0 {
            Some(item.ctime)
        } else {
            None
        },
        modified_epoch_secs: if item.mtime > 0 {
            Some(item.mtime)
        } else {
            None
        },
    }
}

// ── plugin_manifest ───────────────────────────────────────────────────────────

// Export the Extism ABI only on WASM; native unit tests have no Extism host.
#[cfg_attr(target_family = "wasm", plugin_fn)]
pub fn plugin_manifest(_: ()) -> FnResult<Json<PluginManifest>> {
    Ok(Json(PluginManifest {
        kind: "gnome-keyring".into(),
        name: "GNOME Keyring".into(),
        description: "Read-only access to GNOME Keyring files (~/.local/share/keyrings)".into(),
        default_allowed_hosts: vec![],
        required_options: vec![],
        optional_options: vec![
            PluginOptionDescriptor {
                key: "keyring_dir".into(),
                description: "Path to keyring directory (default: ~/.local/share/keyrings)".into(),
                kind: "text".into(),
            },
            PluginOptionDescriptor {
                key: "keyrings".into(),
                description: "Comma-separated list of keyring names to load (default: all)".into(),
                kind: "text".into(),
            },
        ],
        id_derivation_key: None,
    }))
}

// ── init ──────────────────────────────────────────────────────────────────────

#[cfg_attr(target_family = "wasm", plugin_fn)]
pub fn init(Json(req): Json<InitRequest>) -> FnResult<Json<InitResponse>> {
    let keyring_dir = req
        .options
        .get("keyring_dir")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
        .or_else(|| {
            // Use home_dir injected by the host (WASI sandbox does not
            // forward env vars, so $HOME is unavailable inside the guest).
            req.options
                .get("home_dir")
                .and_then(|v| v.as_str())
                .map(|h| format!("{h}/.local/share/keyrings"))
        })
        .or_else(|| {
            // Last resort: try $HOME directly (works outside WASM).
            std::env::var("HOME")
                .ok()
                .map(|h| format!("{h}/.local/share/keyrings"))
        });

    let Some(keyring_dir) = keyring_dir else {
        return Ok(Json(InitResponse {
            ok: false,
            error: Some(
                "cannot determine keyring directory: set 'keyring_dir' in provider options \
                 or ensure $HOME is available"
                    .into(),
            ),
        }));
    };

    let keyrings: Vec<String> = req
        .options
        .get("keyrings")
        .and_then(|v| v.as_str())
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let config = GuestConfig {
        provider_id: req.provider_id,
        keyring_dir,
        keyrings,
    };

    let mut guard = STATE.lock();
    *guard = Some(GuestState { config, auth: None });

    Ok(Json(InitResponse {
        ok: true,
        error: None,
    }))
}

// ── status ────────────────────────────────────────────────────────────────────

#[cfg_attr(target_family = "wasm", plugin_fn)]
pub fn status(_: ()) -> FnResult<Json<StatusResponse>> {
    let guard = STATE.lock();
    let locked = guard.as_ref().map(|s| s.auth.is_none()).unwrap_or(true);
    Ok(Json(StatusResponse {
        locked,
        last_sync_epoch_secs: None,
    }))
}

// ── unlock ────────────────────────────────────────────────────────────────────

#[cfg_attr(target_family = "wasm", plugin_fn)]
pub fn unlock(Json(req): Json<UnlockRequest>) -> FnResult<Json<SimpleResponse>> {
    let mut password = Zeroizing::new(req.password);

    let mut guard = STATE.lock();

    let Some(state) = guard.as_mut() else {
        password.zeroize();
        return Ok(Json(SimpleResponse {
            ok: false,
            error: Some("plugin not initialised".into()),
            error_kind: Some(ErrorKind::Unavailable),
            two_factor_methods: None,
        }));
    };

    // Collect keyring file paths to load
    let paths = match collect_keyring_paths(&state.config) {
        Ok(p) => p,
        Err(e) => {
            password.zeroize();
            return Ok(Json(SimpleResponse {
                ok: false,
                error: Some(e),
                error_kind: Some(ErrorKind::Unavailable),
                two_factor_methods: None,
            }));
        }
    };
    if paths.is_empty() {
        password.zeroize();
        return Ok(Json(SimpleResponse {
            ok: false,
            error: Some(format!(
                "no keyring files found in {}",
                state.config.keyring_dir
            )),
            error_kind: Some(ErrorKind::Unavailable),
            two_factor_methods: None,
        }));
    }

    let mut loaded: Vec<ParsedKeyring> = Vec::new();
    let mut first_error: Option<String> = None;

    for (path, _name) in &paths {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                first_error.get_or_insert_with(|| format!("cannot read {path}: {e}"));
                continue;
            }
        };

        match parse_keyring_file(&bytes, &password) {
            Ok(kr) => loaded.push(kr),
            Err(crate::keyring::KeyringError::WrongPassword) => {
                // Wrong password — fail fast.
                password.zeroize();
                return Ok(Json(SimpleResponse {
                    ok: false,
                    error: Some("wrong password".into()),
                    error_kind: Some(ErrorKind::AuthFailed),
                    two_factor_methods: None,
                }));
            }
            Err(e) => {
                first_error.get_or_insert_with(|| format!("cannot parse {path}: {e}"));
            }
        }
    }

    password.zeroize();

    if loaded.is_empty() {
        return Ok(Json(SimpleResponse {
            ok: false,
            error: Some(first_error.unwrap_or_else(|| "no keyrings could be loaded".into())),
            error_kind: Some(ErrorKind::Unavailable),
            two_factor_methods: None,
        }));
    }

    state.auth = Some(AuthState { keyrings: loaded });

    Ok(Json(SimpleResponse {
        ok: true,
        error: None,
        error_kind: None,
        two_factor_methods: None,
    }))
}

// ── lock ──────────────────────────────────────────────────────────────────────

#[cfg_attr(target_family = "wasm", plugin_fn)]
pub fn lock(_: ()) -> FnResult<Json<SimpleResponse>> {
    let mut guard = STATE.lock();
    if let Some(state) = guard.as_mut() {
        // Drop AuthState — triggers Zeroizing drops on all secrets.
        state.auth = None;
    }
    Ok(Json(SimpleResponse {
        ok: true,
        error: None,
        error_kind: None,
        two_factor_methods: None,
    }))
}

// ── list_items ────────────────────────────────────────────────────────────────

#[cfg_attr(target_family = "wasm", plugin_fn)]
pub fn list_items(_: ()) -> FnResult<Json<ItemListResponse>> {
    let guard = STATE.lock();
    let Some(state) = guard.as_ref() else {
        return Ok(Json(ItemListResponse {
            ok: false,
            error: Some("plugin not initialised".into()),
            error_kind: Some(ErrorKind::Unavailable),
            items: vec![],
        }));
    };
    let Some(auth) = state.auth.as_ref() else {
        return Ok(Json(ItemListResponse {
            ok: false,
            error: Some("provider is locked".into()),
            error_kind: Some(ErrorKind::Locked),
            items: vec![],
        }));
    };

    let provider_id = &state.config.provider_id;
    let items: Vec<WasmItemMeta> = auth
        .keyrings
        .iter()
        .flat_map(|kr| {
            kr.items
                .iter()
                .map(|item| to_wasm_item(provider_id, &kr.name, item))
        })
        .collect();

    Ok(Json(ItemListResponse {
        ok: true,
        error: None,
        error_kind: None,
        items,
    }))
}

// ── search ────────────────────────────────────────────────────────────────────

#[cfg_attr(target_family = "wasm", plugin_fn)]
pub fn search(Json(req): Json<SearchRequest>) -> FnResult<Json<ItemListResponse>> {
    let guard = STATE.lock();
    let Some(state) = guard.as_ref() else {
        return Ok(Json(ItemListResponse {
            ok: false,
            error: Some("plugin not initialised".into()),
            error_kind: Some(ErrorKind::Unavailable),
            items: vec![],
        }));
    };
    let Some(auth) = state.auth.as_ref() else {
        return Ok(Json(ItemListResponse {
            ok: false,
            error: Some("provider is locked".into()),
            error_kind: Some(ErrorKind::Locked),
            items: vec![],
        }));
    };

    let provider_id = &state.config.provider_id;
    let items: Vec<WasmItemMeta> = auth
        .keyrings
        .iter()
        .flat_map(|kr| {
            kr.items
                .iter()
                .map(|item| to_wasm_item(provider_id, &kr.name, item))
        })
        .filter(|meta| {
            req.attributes
                .iter()
                .all(|(k, v)| meta.attributes.get(k).map(|s| s == v).unwrap_or(false))
        })
        .collect();

    Ok(Json(ItemListResponse {
        ok: true,
        error: None,
        error_kind: None,
        items,
    }))
}

// ── get_item_attributes ───────────────────────────────────────────────────────

#[cfg_attr(target_family = "wasm", plugin_fn)]
pub fn get_item_attributes(
    Json(req): Json<ItemIdRequest>,
) -> FnResult<Json<ItemAttributesResponse>> {
    let guard = STATE.lock();
    let Some(state) = guard.as_ref() else {
        return Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some("plugin not initialised".into()),
            error_kind: Some(ErrorKind::Unavailable),
            public: HashMap::new(),
            secret_names: vec![],
        }));
    };
    let Some(auth) = state.auth.as_ref() else {
        return Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some("provider is locked".into()),
            error_kind: Some(ErrorKind::Locked),
            public: HashMap::new(),
            secret_names: vec![],
        }));
    };

    let Some((keyring_name, numeric_id)) = parse_item_id(&req.id) else {
        return Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some(format!("invalid item id: {}", req.id)),
            error_kind: Some(ErrorKind::InvalidInput),
            public: HashMap::new(),
            secret_names: vec![],
        }));
    };

    let item = auth
        .keyrings
        .iter()
        .find(|kr| kr.name == keyring_name)
        .and_then(|kr| kr.items.iter().find(|i| i.id == numeric_id));

    let Some(item) = item else {
        return Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some(format!("item not found: {}", req.id)),
            error_kind: Some(ErrorKind::NotFound),
            public: HashMap::new(),
            secret_names: vec![],
        }));
    };

    let public = build_public_attrs(&state.config.provider_id, keyring_name, item);

    Ok(Json(ItemAttributesResponse {
        ok: true,
        error: None,
        error_kind: None,
        public,
        // The single secret is the raw keyring item secret, accessible as
        // either "password" (canonical) or "secret" (alias — used by the
        // portal and generic item lookups).
        secret_names: vec!["password".into(), "secret".into()],
    }))
}

// ── get_secret_attr ───────────────────────────────────────────────────────────

#[cfg_attr(target_family = "wasm", plugin_fn)]
pub fn get_secret_attr(Json(req): Json<SecretAttrRequest>) -> FnResult<Json<SecretAttrResponse>> {
    let guard = STATE.lock();
    let Some(state) = guard.as_ref() else {
        return Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some("plugin not initialised".into()),
            error_kind: Some(ErrorKind::Unavailable),
            value_b64: None,
        }));
    };
    let Some(auth) = state.auth.as_ref() else {
        return Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some("provider is locked".into()),
            error_kind: Some(ErrorKind::Locked),
            value_b64: None,
        }));
    };

    let Some((keyring_name, numeric_id)) = parse_item_id(&req.id) else {
        return Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some(format!("invalid item id: {}", req.id)),
            error_kind: Some(ErrorKind::InvalidInput),
            value_b64: None,
        }));
    };

    let item = auth
        .keyrings
        .iter()
        .find(|kr| kr.name == keyring_name)
        .and_then(|kr| kr.items.iter().find(|i| i.id == numeric_id));

    let Some(item) = item else {
        return Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some(format!("item not found: {}", req.id)),
            error_kind: Some(ErrorKind::NotFound),
            value_b64: None,
        }));
    };

    // gnome-keyring items have a single secret.  Accept both "password"
    // (canonical name) and "secret" (alias used by the portal layer and
    // generic item lookups) — they return the same underlying data.
    if req.attr != "password" && req.attr != "secret" {
        return Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some(format!("unknown secret attribute: {}", req.attr)),
            error_kind: Some(ErrorKind::NotFound),
            value_b64: None,
        }));
    }

    // Base64-encode the raw secret bytes for JSON transport.
    // The host decodes and zeroizes the b64 string immediately.
    let b64 = B64.encode(item.secret.as_slice());

    Ok(Json(SecretAttrResponse {
        ok: true,
        error: None,
        error_kind: None,
        value_b64: Some(b64),
    }))
}

// ── capabilities ─────────────────────────────────────────────────────────────

#[cfg_attr(target_family = "wasm", plugin_fn)]
pub fn capabilities(_: ()) -> FnResult<Json<CapabilitiesResponse>> {
    // Read-only: no Sync, no Write, no SSH, no KeyWrapping, no PasswordChange.
    Ok(Json(CapabilitiesResponse {
        capabilities: vec![],
    }))
}

// ── attribute_descriptors ─────────────────────────────────────────────────────

#[cfg_attr(target_family = "wasm", plugin_fn)]
pub fn attribute_descriptors(_: ()) -> FnResult<Json<AttributeDescriptorsResponse>> {
    fn desc(
        name: &str,
        sensitive: bool,
        item_types: &[&str],
        description: &str,
    ) -> WasmAttributeDescriptor {
        WasmAttributeDescriptor {
            name: name.into(),
            sensitive,
            item_types: item_types.iter().map(|s| (*s).into()).collect(),
            description: description.into(),
        }
    }

    Ok(Json(AttributeDescriptorsResponse {
        descriptors: vec![
            // Public attributes
            desc(
                "rosec:type",
                false,
                &[],
                "Item type: generic, network, note",
            ),
            desc(
                "rosec:gnome-keyring:keyring",
                false,
                &[],
                "Source keyring filename (without .keyring)",
            ),
            desc(
                "rosec:gnome-keyring:item-id",
                false,
                &[],
                "Numeric item ID within the keyring file",
            ),
            desc("xdg:schema", false, &[], "XDG schema identifier"),
            // Common GNOME Keyring attribute names (public)
            desc(
                "application",
                false,
                &["generic", "network"],
                "Application that owns this item",
            ),
            desc("server", false, &["network"], "Hostname or server address"),
            desc(
                "protocol",
                false,
                &["network"],
                "Network protocol (e.g. http, ftp, smb)",
            ),
            desc("user", false, &["generic", "network"], "Username"),
            desc(
                "domain",
                false,
                &["network"],
                "Authentication domain or realm",
            ),
            desc("port", false, &["network"], "Network port number"),
            desc(
                "object",
                false,
                &["network"],
                "Object path within the server",
            ),
            desc("authtype", false, &["network"], "Authentication type"),
            // Sensitive
            desc("password", true, &[], "The secret stored for this item"),
        ],
    }))
}

// ── auth_fields ───────────────────────────────────────────────────────────────

#[cfg_attr(target_family = "wasm", plugin_fn)]
pub fn auth_fields(_: ()) -> FnResult<Json<AuthFieldsResponse>> {
    // The standard password field provided by the host is sufficient.
    // GNOME Keyring doesn't use 2FA or extra auth fields.
    Ok(Json(AuthFieldsResponse { fields: vec![] }))
}

// ── registration_info ─────────────────────────────────────────────────────────

#[cfg_attr(target_family = "wasm", plugin_fn)]
pub fn registration_info(_: ()) -> FnResult<Json<RegistrationInfoResponse>> {
    // No first-time registration needed — just a password.
    Ok(Json(RegistrationInfoResponse {
        has_registration: false,
        instructions: None,
        fields: vec![],
    }))
}

// ── File collection helper ────────────────────────────────────────────────────

/// Returns `(file_path, keyring_name)` pairs for all `.keyring` files to load.
fn collect_keyring_paths(config: &GuestConfig) -> Result<Vec<(String, String)>, String> {
    let dir = &config.keyring_dir;

    // List the directory
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            return Err(format!("cannot read keyring directory {dir}: {e}"));
        }
    };

    let mut paths: Vec<(String, String)> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        let fname = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_owned(),
            None => continue,
        };

        // Only .keyring files
        let Some(stem) = fname.strip_suffix(".keyring") else {
            continue;
        };

        // If the config specifies a filter list, check it
        if !config.keyrings.is_empty() && !config.keyrings.iter().any(|k| k == stem) {
            continue;
        }

        paths.push((path.to_string_lossy().into_owned(), stem.to_owned()));
    }

    paths.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(paths)
}
