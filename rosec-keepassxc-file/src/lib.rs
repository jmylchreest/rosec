//! KeePassXC `.kdbx` file provider as an Extism WASM guest plugin for rosec.
//!
//! Reads a single user-configured `.kdbx` file via the `host_file` host
//! imports.  The master passphrase (and optional key file) are passed in
//! through `unlock()`; we decrypt the database in memory and serve items
//! through the standard rosec WASM provider protocol.
//!
//! # Status
//!
//! **EXPERIMENTAL.** Marked via `PluginManifest.experimental = true`.
//! Read-only: unlock decrypts via `keepass-rs`, but the plugin never writes
//! back to the .kdbx file.  Capabilities advertised: `Sync` only.
//!
//! # Configuration
//!
//! ```toml
//! [[provider]]
//! kind = "keepassxc-file"
//! id   = "kp-personal"
//! path = "/home/alice/Passwords.kdbx"
//! # Optional: key file as a second factor
//! # key_file = "/home/alice/Passwords.keyx"
//! ```

mod cipher;
mod host_file;
mod protocol;

use std::io::Cursor;
use std::sync::{Mutex, MutexGuard};

use base64::Engine;
use extism_pdk::*;
use keepass::{Database, DatabaseKey};

use crate::protocol::*;

// ── Global state ──────────────────────────────────────────────────────────────

/// `Mutex` wrapper that recovers from poison.  WASM guests are single-threaded,
/// so poison only happens via Extism timeout traps that skip Drop handlers —
/// the data is still consistent.
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

struct GuestState {
    config: GuestConfig,
    /// `None` when locked.
    auth: Option<AuthState>,
}

struct GuestConfig {
    provider_id: String,
    /// Host path to the `.kdbx` file.
    path: String,
    /// Optional host path to a key file.
    key_file: Option<String>,
}

/// Unlocked state — holds the decrypted KeePass database in memory.
struct AuthState {
    db: Database,
    /// Modification time of the file at unlock, for sync-on-mtime-change.
    last_mtime_secs: u64,
    /// Epoch seconds when the database was loaded — exposed via `status`.
    last_sync_epoch_secs: u64,
}

// ── plugin_manifest ───────────────────────────────────────────────────────────

#[plugin_fn]
pub fn plugin_manifest(_: ()) -> FnResult<Json<PluginManifest>> {
    Ok(Json(PluginManifest {
        kind: "keepassxc-file".into(),
        name: "KeePassXC (file)".into(),
        description: "Read a KeePassXC .kdbx database file directly (KDBX 4.x)".into(),
        version: None,
        default_allowed_hosts: vec![],
        required_options: vec![PluginOptionDescriptor {
            key: "path".into(),
            description: "Path to the .kdbx database file".into(),
            kind: "text".into(),
        }],
        optional_options: vec![PluginOptionDescriptor {
            key: "key_file".into(),
            description: "Path to a .key/.keyx key file (second factor)".into(),
            kind: "text".into(),
        }],
        id_derivation_key: Some("path".into()),
        experimental: true,
        experimental_features: vec![],
    }))
}

// ── init ──────────────────────────────────────────────────────────────────────

#[plugin_fn]
pub fn init(Json(req): Json<InitRequest>) -> FnResult<Json<InitResponse>> {
    let path = match req.options.get("path").and_then(|v| v.as_str()) {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => {
            return Ok(Json(InitResponse {
                ok: false,
                error: Some("'path' option is required".into()),
            }));
        }
    };

    let key_file = req
        .options
        .get("key_file")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let config = GuestConfig {
        provider_id: req.provider_id,
        path,
        key_file,
    };

    let mut guard = STATE.lock();
    *guard = Some(GuestState { config, auth: None });

    Ok(Json(InitResponse {
        ok: true,
        error: None,
    }))
}

// ── status ────────────────────────────────────────────────────────────────────

#[plugin_fn]
pub fn status(_: ()) -> FnResult<Json<StatusResponse>> {
    let guard = STATE.lock();
    let (locked, last_sync) = match guard.as_ref().and_then(|s| s.auth.as_ref()) {
        Some(auth) => (false, Some(auth.last_sync_epoch_secs)),
        None => (true, None),
    };
    Ok(Json(StatusResponse {
        locked,
        last_sync_epoch_secs: last_sync,
    }))
}

// ── unlock ────────────────────────────────────────────────────────────────────

fn open_database(path: &str, key_file: Option<&str>, password: &str) -> Result<Database, String> {
    let bytes = host_file::read(path).map_err(|e| format!("read '{path}': {e}"))?;

    if password.is_empty() && key_file.is_none() {
        return Err("master password or key file required".into());
    }

    // KeePassXC supports three auth modes:
    //   1. Password only         → with_password(pw)
    //   2. Password + key file   → with_password(pw).with_keyfile(...)
    //   3. Key file only         → with_keyfile(...)         (no password call)
    //
    // `with_password("")` does NOT mean "no password" — it derives a key from
    // the empty string, which is a different composite key than "no password
    // factor at all".  So we must skip with_password entirely when the user
    // didn't supply one.
    let mut key = DatabaseKey::new();
    if !password.is_empty() {
        key = key.with_password(password);
    }
    if let Some(kf_path) = key_file {
        let kf_bytes =
            host_file::read(kf_path).map_err(|e| format!("read key file '{kf_path}': {e}"))?;
        key = key
            .with_keyfile(&mut Cursor::new(kf_bytes))
            .map_err(|e| format!("invalid key file '{kf_path}': {e}"))?;
    }

    Database::open(&mut Cursor::new(bytes), key).map_err(|e| format!("kdbx open failed: {e}"))
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[plugin_fn]
pub fn unlock(Json(req): Json<UnlockRequest>) -> FnResult<Json<SimpleResponse>> {
    let mut guard = STATE.lock();

    let Some(state) = guard.as_mut() else {
        return Ok(Json(SimpleResponse {
            ok: false,
            error: Some("plugin not initialised".into()),
            error_kind: Some(ErrorKind::Unavailable),
            two_factor_methods: None,
        }));
    };

    let path = state.config.path.clone();
    let key_file = state.config.key_file.clone();

    let mtime_secs = host_file::stat(&path).map(|s| s.mtime_secs).unwrap_or(0);

    match open_database(&path, key_file.as_deref(), &req.password) {
        Ok(db) => {
            state.auth = Some(AuthState {
                db,
                last_mtime_secs: mtime_secs,
                last_sync_epoch_secs: now_epoch_secs(),
            });
            Ok(Json(SimpleResponse {
                ok: true,
                error: None,
                error_kind: None,
                two_factor_methods: None,
            }))
        }
        Err(msg) => {
            // Heuristic: keepass-rs returns an InvalidKey-shaped error string
            // for wrong password / wrong key file.  Map that to AuthFailed
            // so the rosec auth flow re-prompts for the master password
            // rather than treating it as an unavailable provider.
            let kind = if msg.contains("InvalidKey")
                || msg.to_lowercase().contains("incorrect password")
                || msg.contains("HmacBlock")
            {
                ErrorKind::AuthFailed
            } else {
                ErrorKind::Unavailable
            };
            Ok(Json(SimpleResponse {
                ok: false,
                error: Some(msg),
                error_kind: Some(kind),
                two_factor_methods: None,
            }))
        }
    }
}

// ── lock ──────────────────────────────────────────────────────────────────────

#[plugin_fn]
pub fn lock(_: ()) -> FnResult<Json<SimpleResponse>> {
    let mut guard = STATE.lock();
    if let Some(state) = guard.as_mut() {
        // Drop the in-memory database — keepass-rs holds secrets in
        // SecretBox/Zeroizing types that scrub on Drop.
        state.auth = None;
    }
    Ok(Json(SimpleResponse {
        ok: true,
        error: None,
        error_kind: None,
        two_factor_methods: None,
    }))
}

// ── sync ──────────────────────────────────────────────────────────────────────

#[plugin_fn]
pub fn sync(_: ()) -> FnResult<Json<SimpleResponse>> {
    let mut guard = STATE.lock();
    let Some(state) = guard.as_mut() else {
        return Ok(Json(SimpleResponse {
            ok: false,
            error: Some("plugin not initialised".into()),
            error_kind: Some(ErrorKind::Unavailable),
            two_factor_methods: None,
        }));
    };
    let Some(auth) = state.auth.as_mut() else {
        // Locked — sync is a no-op until next unlock.
        return Ok(Json(SimpleResponse {
            ok: true,
            error: None,
            error_kind: None,
            two_factor_methods: None,
        }));
    };

    // Re-stat the file; if mtime is unchanged, nothing to do.
    let stat = match host_file::stat(&state.config.path) {
        Ok(s) => s,
        Err(e) => {
            return Ok(Json(SimpleResponse {
                ok: false,
                error: Some(format!("stat: {e}")),
                error_kind: Some(ErrorKind::Unavailable),
                two_factor_methods: None,
            }));
        }
    };

    if stat.mtime_secs == auth.last_mtime_secs {
        // Stamp last_sync so status reports the freshness check happened.
        auth.last_sync_epoch_secs = now_epoch_secs();
        return Ok(Json(SimpleResponse {
            ok: true,
            error: None,
            error_kind: None,
            two_factor_methods: None,
        }));
    }

    // File on disk changed.  Without the master password we cannot re-decrypt;
    // ask the host to prompt for unlock again.  Returning Unavailable makes
    // the host treat this as a transient error rather than a hard failure.
    Ok(Json(SimpleResponse {
        ok: false,
        error: Some(
            "kdbx file changed on disk — re-authenticate to pick up the new contents".into(),
        ),
        error_kind: Some(ErrorKind::Unavailable),
        two_factor_methods: None,
    }))
}

// ── helpers for item-level functions ─────────────────────────────────────────

fn with_db<R>(f: impl FnOnce(&str, &Database) -> R) -> Result<R, String> {
    let guard = STATE.lock();
    let state = guard.as_ref().ok_or("plugin not initialised")?;
    let auth = state.auth.as_ref().ok_or("provider locked")?;
    Ok(f(&state.config.provider_id, &auth.db))
}

fn lookup_entry_by_id<'a>(db: &'a Database, id: &str) -> Option<keepass::db::EntryRef<'a>> {
    let target = uuid::Uuid::parse_str(id).ok()?;
    db.iter_all_entries().find(|e| e.id().uuid() == target)
}

fn matches_filter(
    attrs: &std::collections::HashMap<String, String>,
    filter: &std::collections::HashMap<String, String>,
) -> bool {
    filter
        .iter()
        .all(|(k, want)| attrs.get(k.as_str()).is_some_and(|got| got == want))
}

// ── list_items / search ───────────────────────────────────────────────────────

#[plugin_fn]
pub fn list_items(_: ()) -> FnResult<Json<ItemListResponse>> {
    match with_db(|provider_id, db| {
        db.iter_all_entries()
            .map(|e| cipher::entry_to_item_meta(provider_id, db, &e))
            .collect::<Vec<_>>()
    }) {
        Ok(items) => Ok(Json(ItemListResponse {
            ok: true,
            error: None,
            error_kind: None,
            items,
        })),
        Err(msg) => Ok(Json(ItemListResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(ErrorKind::Unavailable),
            items: vec![],
        })),
    }
}

#[plugin_fn]
pub fn search(Json(req): Json<SearchRequest>) -> FnResult<Json<ItemListResponse>> {
    match with_db(|provider_id, db| {
        db.iter_all_entries()
            .map(|e| cipher::entry_to_item_meta(provider_id, db, &e))
            .filter(|item| matches_filter(&item.attributes, &req.attributes))
            .collect::<Vec<_>>()
    }) {
        Ok(items) => Ok(Json(ItemListResponse {
            ok: true,
            error: None,
            error_kind: None,
            items,
        })),
        Err(msg) => Ok(Json(ItemListResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(ErrorKind::Unavailable),
            items: vec![],
        })),
    }
}

// ── attribute access ──────────────────────────────────────────────────────────

#[plugin_fn]
pub fn get_item_attributes(
    Json(req): Json<ItemIdRequest>,
) -> FnResult<Json<ItemAttributesResponse>> {
    let result: Result<Option<(_, _)>, String> = with_db(|provider_id, db| {
        lookup_entry_by_id(db, &req.id).map(|entry| {
            (
                cipher::build_public_attrs(provider_id, db, &entry),
                cipher::build_secret_names(&entry),
            )
        })
    });

    match result {
        Ok(Some((public, secret_names))) => Ok(Json(ItemAttributesResponse {
            ok: true,
            error: None,
            error_kind: None,
            public,
            secret_names,
        })),
        Ok(None) => Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some(format!("item not found: {}", req.id)),
            error_kind: Some(ErrorKind::NotFound),
            public: Default::default(),
            secret_names: vec![],
        })),
        Err(msg) => Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(ErrorKind::Unavailable),
            public: Default::default(),
            secret_names: vec![],
        })),
    }
}

#[plugin_fn]
pub fn get_secret_attr(Json(req): Json<SecretAttrRequest>) -> FnResult<Json<SecretAttrResponse>> {
    let bytes_result: Result<Option<Vec<u8>>, String> = with_db(|_, db| {
        lookup_entry_by_id(db, &req.id).and_then(|e| cipher::resolve_secret(&e, &req.attr))
    });

    match bytes_result {
        Ok(Some(bytes)) => Ok(Json(SecretAttrResponse {
            ok: true,
            error: None,
            error_kind: None,
            value_b64: Some(base64::engine::general_purpose::STANDARD.encode(&bytes)),
        })),
        Ok(None) => Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some(format!(
                "attribute '{}' not found on item {}",
                req.attr, req.id
            )),
            error_kind: Some(ErrorKind::NotFound),
            value_b64: None,
        })),
        Err(msg) => Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(ErrorKind::Unavailable),
            value_b64: None,
        })),
    }
}

// ── Static metadata queried once at plugin load ───────────────────────────────

#[plugin_fn]
pub fn capabilities(_: ()) -> FnResult<Json<CapabilitiesResponse>> {
    // Phase 1: read-only, sync via mtime polling.
    Ok(Json(CapabilitiesResponse {
        capabilities: vec!["Sync".into()],
    }))
}

#[plugin_fn]
pub fn auth_fields(_: ()) -> FnResult<Json<AuthFieldsResponse>> {
    // When a key file is configured the master password becomes optional
    // (KeePassXC permits key-file-only authentication).  When no key file
    // is configured the password is the sole factor and is required.
    let has_key_file = STATE
        .lock()
        .as_ref()
        .map(|s| s.config.key_file.is_some())
        .unwrap_or(false);

    Ok(Json(AuthFieldsResponse {
        fields: vec![WasmAuthField {
            id: "password".into(),
            label: if has_key_file {
                "Master password (leave empty if key file is the sole factor)".into()
            } else {
                "Master password".into()
            },
            placeholder: String::new(),
            required: !has_key_file,
            kind: "password".into(),
        }],
    }))
}

#[plugin_fn]
pub fn registration_info(_: ()) -> FnResult<Json<RegistrationInfoResponse>> {
    Ok(Json(RegistrationInfoResponse {
        has_registration: false,
        instructions: None,
        fields: vec![],
    }))
}

#[plugin_fn]
pub fn attribute_descriptors(_: ()) -> FnResult<Json<AttributeDescriptorsResponse>> {
    Ok(Json(AttributeDescriptorsResponse {
        descriptors: vec![],
    }))
}

#[plugin_fn]
pub fn readiness_probes(_: ()) -> FnResult<Json<ReadinessProbesResponse>> {
    // No remote endpoint to probe.
    Ok(Json(ReadinessProbesResponse { probes: vec![] }))
}

#[plugin_fn]
pub fn get_notification_config(_: ()) -> FnResult<Json<NotificationConfigResponse>> {
    Ok(Json(NotificationConfigResponse {
        ok: true,
        error: None,
        error_kind: None,
        subscription: None,
    }))
}
