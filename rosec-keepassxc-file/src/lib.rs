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
mod host_watch;
mod protocol;
mod ssh;
mod fido2;

use std::io::Cursor;
use std::sync::{Mutex, MutexGuard};

use base64::Engine;
use extism_pdk::*;
use keepass::{Database, DatabaseKey};
use zeroize::{Zeroize, Zeroizing};

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
    /// Cached master password.  Held in `Zeroizing` so it scrubs on lock().
    /// Lets `sync()` re-decrypt automatically when the kdbx file changes
    /// on disk (e.g. when KeePassXC saves a new entry) instead of
    /// forcing the user to re-authenticate.
    ///
    /// Trade-off: master password sits in WASM linear memory for the
    /// duration of the unlocked session.  Same threat model as the
    /// existing rosec-wasm cache_key mechanism for Bitwarden — acceptable
    /// because the WASM sandbox is process-isolated and lock() zeroizes
    /// the entire AuthState.
    master_password: Zeroizing<String>,
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
    info!("kdbx: reading file '{}'", path);
    let bytes = host_file::read(path).map_err(|e| format!("read '{path}': {e}"))?;
    info!("kdbx: read {} bytes; building key", bytes.len());

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

    info!("kdbx: starting Database::open (Argon2 KDF + decrypt + parse)");
    let db = Database::open(&mut Cursor::new(bytes), key)
        .map_err(|e| format!("kdbx open failed: {e}"))?;
    info!(
        "kdbx: open complete; entry count = {}",
        db.iter_all_entries().count()
    );
    Ok(db)
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[plugin_fn]
pub fn unlock(Json(mut req): Json<UnlockRequest>) -> FnResult<Json<SimpleResponse>> {
    let mut guard = STATE.lock();

    let Some(state) = guard.as_mut() else {
        // Scrub the password before returning so the caller-supplied bytes
        // don't linger in WASM linear memory.
        req.password.zeroize();
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

    // Hand-off the password to a Zeroizing buffer immediately, then scrub
    // the original on the request struct.  Two reasons:
    //  - `req.password` is an ordinary `String` whose backing allocation
    //    is freed (without zeroing) when this function returns.
    //  - The cached copy on `AuthState.master_password` lives for the
    //    duration of the unlocked session for host_watch re-decrypt; we
    //    don't want a *second* copy on the stack/heap as well.
    let password = Zeroizing::new(std::mem::take(&mut req.password));

    match open_database(&path, key_file.as_deref(), &password) {
        Ok(db) => {
            state.auth = Some(AuthState {
                db,
                last_mtime_secs: mtime_secs,
                last_sync_epoch_secs: now_epoch_secs(),
                master_password: password,
            });
            // Subscribe to host filesystem events for the kdbx (and the key
            // file, if any).  Failure here is non-fatal — we still fall back
            // to mtime polling on each sync().
            if let Err(e) = host_watch::watch(&path) {
                info!("host_watch: register failed for kdbx: {e}");
            }
            if let Some(kf) = &key_file
                && let Err(e) = host_watch::watch(kf)
            {
                info!("host_watch: register failed for key file: {e}");
            }
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

// ── host_watch event handler ──────────────────────────────────────────────────

/// Payload format must match `rosec_wasm::host_watch::WatchEvent`.
#[derive(Debug, serde::Deserialize)]
struct WatchEvent {
    path: String,
    kind: String,
}

/// Re-stat the kdbx and re-decrypt with the cached master password if mtime
/// has advanced.  Used by both `sync()` and `on_path_changed`.
///
/// Returns `Ok(true)` if a re-decrypt happened, `Ok(false)` if the file was
/// unchanged.  Returns `Err(msg)` on stat or decrypt failure; on decrypt
/// failure the caller is responsible for clearing `state.auth` (KeePassXC
/// may have rotated the master password externally).
fn try_redecrypt(state: &mut GuestState) -> Result<bool, String> {
    let Some(auth) = state.auth.as_mut() else {
        return Ok(false);
    };
    let stat = host_file::stat(&state.config.path).map_err(|e| format!("stat: {e}"))?;
    if stat.mtime_secs == auth.last_mtime_secs {
        auth.last_sync_epoch_secs = now_epoch_secs();
        return Ok(false);
    }
    info!(
        "kdbx: file mtime changed ({} -> {}), re-decrypting",
        auth.last_mtime_secs, stat.mtime_secs
    );
    let path = state.config.path.clone();
    let key_file = state.config.key_file.clone();
    // Hold the password by &Zeroizing<String>; no plaintext clone.
    let db = open_database(&path, key_file.as_deref(), &auth.master_password)?;
    auth.db = db;
    auth.last_mtime_secs = stat.mtime_secs;
    auth.last_sync_epoch_secs = now_epoch_secs();
    Ok(true)
}

/// Called by the host whenever a file we registered via `host_watch::watch`
/// changes on disk.  Triggers an immediate re-decrypt with the cached
/// master password.  Failure clears `auth` so the next call surfaces an
/// auth error rather than serving stale data.
#[plugin_fn]
pub fn on_path_changed(Json(evt): Json<WatchEvent>) -> FnResult<()> {
    info!("on_path_changed: {} {}", evt.kind, evt.path);
    let mut guard = STATE.lock();
    let Some(state) = guard.as_mut() else {
        return Ok(());
    };
    match try_redecrypt(state) {
        Ok(_) => {}
        Err(msg) => {
            warn!("on_path_changed: re-decrypt failed, locking provider: {msg}");
            state.auth = None;
        }
    }
    Ok(())
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
    if state.auth.is_none() {
        // Locked — sync is a no-op until next unlock.
        return Ok(Json(SimpleResponse {
            ok: true,
            error: None,
            error_kind: None,
            two_factor_methods: None,
        }));
    }

    match try_redecrypt(state) {
        Ok(_) => Ok(Json(SimpleResponse {
            ok: true,
            error: None,
            error_kind: None,
            two_factor_methods: None,
        })),
        Err(msg) => {
            // Re-decrypt failed.  Usually means the master password was
            // rotated externally (File → Database settings → Database
            // credentials).  Drop AuthState so the next call forces a
            // re-auth with the new password.
            warn!("kdbx: re-decrypt failed, locking provider: {msg}");
            state.auth = None;
            Ok(Json(SimpleResponse {
                ok: false,
                error: Some(format!(
                    "kdbx file changed on disk and re-decrypt failed ({msg}) — \
                     re-authenticate to continue"
                )),
                error_kind: Some(ErrorKind::AuthFailed),
                two_factor_methods: None,
            }))
        }
    }
}

// ── helpers for item-level functions ─────────────────────────────────────────

fn with_db<R>(f: impl FnOnce(&str, &Database) -> R) -> Result<R, (String, ErrorKind)> {
    let guard = STATE.lock();
    let state = guard
        .as_ref()
        .ok_or(("plugin not initialised".to_string(), ErrorKind::Unavailable))?;
    let auth = state
        .auth
        .as_ref()
        .ok_or(("provider locked".to_string(), ErrorKind::Locked))?;
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
        Err((msg, kind)) => Ok(Json(ItemListResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(kind),
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
        Err((msg, kind)) => Ok(Json(ItemListResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(kind),
            items: vec![],
        })),
    }
}

// ── attribute access ──────────────────────────────────────────────────────────

#[plugin_fn]
pub fn get_item_attributes(
    Json(req): Json<ItemIdRequest>,
) -> FnResult<Json<ItemAttributesResponse>> {
    let result = with_db(|provider_id, db| {
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
        Err((msg, kind)) => Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(kind),
            public: Default::default(),
            secret_names: vec![],
        })),
    }
}

#[plugin_fn]
pub fn get_secret_attr(Json(req): Json<SecretAttrRequest>) -> FnResult<Json<SecretAttrResponse>> {
    let bytes_result = with_db(|_, db| {
        lookup_entry_by_id(db, &req.id).and_then(|e| cipher::resolve_secret(&e, &req.attr))
    });

    match bytes_result {
        Ok(Some(bytes)) => {
            // Encode to base64 for transit, then drop the plaintext buffer
            // (Zeroizing scrubs on drop).  The base64 string itself is a
            // separate allocation owned by the response and serialized
            // through extism — it can't be wrapped in Zeroizing across the
            // protocol boundary, but it's confined to this WASM instance's
            // linear memory, which is destroyed when the plugin exits.
            let value_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            drop(bytes);
            Ok(Json(SecretAttrResponse {
                ok: true,
                error: None,
                error_kind: None,
                value_b64: Some(value_b64),
            }))
        }
        Ok(None) => Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some(format!(
                "attribute '{}' not found on item {}",
                req.attr, req.id
            )),
            error_kind: Some(ErrorKind::NotFound),
            value_b64: None,
        })),
        Err((msg, kind)) => Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(kind),
            value_b64: None,
        })),
    }
}

// ── SSH key extraction ────────────────────────────────────────────────────────

#[plugin_fn]
pub fn list_ssh_keys(_: ()) -> FnResult<Json<SshKeyListResponse>> {
    let result = with_db(|_, db| {
        db.iter_all_entries()
            .filter_map(|e| ssh::entry_to_ssh_key_meta(db, &e))
            .collect::<Vec<_>>()
    });
    match result {
        Ok(keys) => Ok(Json(SshKeyListResponse {
            ok: true,
            error: None,
            error_kind: None,
            keys,
        })),
        Err((msg, kind)) => Ok(Json(SshKeyListResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(kind),
            keys: Vec::new(),
        })),
    }
}

#[plugin_fn]
pub fn get_ssh_private_key(
    Json(req): Json<SshPrivateKeyRequest>,
) -> FnResult<Json<SshPrivateKeyResponse>> {
    let pem_result = with_db(|_, db| match lookup_entry_by_id(db, &req.item_id) {
        Some(entry) => ssh::resolve_ssh_private_key(&entry),
        None => Err(format!("item not found: {}", req.item_id)),
    });

    match pem_result {
        Ok(Ok(pem)) => {
            // The clone here is unavoidable — `SshPrivateKeyResponse.pem`
            // is `Option<String>`, and serde owns the buffer it serializes.
            // The `Zeroizing<String>` source is dropped at end of scope,
            // scrubbing that one copy; the host wraps the deserialized
            // string in `Zeroizing` again on receipt.
            let response = SshPrivateKeyResponse {
                ok: true,
                error: None,
                error_kind: None,
                pem: Some(pem.to_string()),
            };
            drop(pem);
            Ok(Json(response))
        }
        Ok(Err(msg)) => Ok(Json(SshPrivateKeyResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(ErrorKind::NotFound),
            pem: None,
        })),
        Err((msg, kind)) => Ok(Json(SshPrivateKeyResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(kind),
            pem: None,
        })),
    }
}

// ── Static metadata queried once at plugin load ───────────────────────────────


#[plugin_fn]
pub fn list_fido2_credentials(_: ()) -> FnResult<Json<Fido2CredentialListResponse>> {
    let result = with_db(|_, db| {
        db.iter_all_entries()
            .filter_map(|e| fido2::entry_to_fido2_meta(&e))
            .collect::<Vec<_>>()
    });
    match result {
        Ok(credentials) => Ok(Json(Fido2CredentialListResponse {
            ok: true,
            error: None,
            error_kind: None,
            credentials,
        })),
        Err((msg, kind)) => Ok(Json(Fido2CredentialListResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(kind),
            credentials: Vec::new(),
        })),
    }
}

#[plugin_fn]
pub fn get_fido2_key(Json(req): Json<Fido2KeyRequest>) -> FnResult<Json<Fido2KeyResponse>> {
    let pem_result = with_db(|_, db| match lookup_entry_by_id(db, &req.item_id) {
        Some(entry) => fido2::resolve_fido2_key(&entry, &req.credential_id),
        None => Err(format!("item not found: {}", req.item_id)),
    });

    match pem_result {
        Ok(Ok(pem)) => {
            // Same unavoidable clone as get_ssh_private_key: serde owns the
            // buffer; the Zeroizing source scrubs its copy on drop and the
            // host re-wraps on receipt.
            let response = Fido2KeyResponse {
                ok: true,
                error: None,
                error_kind: None,
                pem: Some(pem.to_string()),
            };
            drop(pem);
            Ok(Json(response))
        }
        Ok(Err(msg)) => Ok(Json(Fido2KeyResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(ErrorKind::NotFound),
            pem: None,
        })),
        Err((msg, kind)) => Ok(Json(Fido2KeyResponse {
            ok: false,
            error: Some(msg),
            error_kind: Some(kind),
            pem: None,
        })),
    }
}

#[plugin_fn]
pub fn capabilities(_: ()) -> FnResult<Json<CapabilitiesResponse>> {
    // Phase 1: read-only, sync via mtime polling.
    // Ssh: SSH key extraction from KeeAgent.settings + binary attachments.
    Ok(Json(CapabilitiesResponse {
        capabilities: vec!["Sync".into(), "Ssh".into(), "Fido2".into()],
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
