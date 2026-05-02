//! KeePassXC `.kdbx` file provider as an Extism WASM guest plugin for rosec.
//!
//! Reads a single user-configured `.kdbx` file via the `host_file` host
//! imports.  The master passphrase (and optional key file) are passed in
//! through `unlock()`; we decrypt the database in memory and serve items
//! through the standard rosec WASM provider protocol.
//!
//! # Status
//!
//! **EXPERIMENTAL.** Marked via `PluginManifest.experimental = true`.  The
//! current build only declares itself; actual unlock/list_items wiring lands
//! in a follow-up commit.
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

// Fields like `last_mtime_secs` and helpers like `host_file::read` are wired
// up in the follow-up commit that adds real kdbx parsing.  Keep the scaffold
// commit clippy-clean without scattering #[allow(dead_code)] across each
// individual item.
#![allow(dead_code)]

mod host_file;
mod protocol;

use std::sync::{Mutex, MutexGuard};

use extism_pdk::*;

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
    /// `None` when locked.  Will hold the decrypted database in a follow-up.
    auth: Option<AuthState>,
}

struct GuestConfig {
    provider_id: String,
    /// Host path to the `.kdbx` file.
    path: String,
    /// Optional host path to a key file.
    key_file: Option<String>,
}

/// Unlocked state — placeholder until kdbx parsing lands.
struct AuthState {
    /// Modification time of the file at unlock, for sync-on-mtime-change.
    last_mtime_secs: u64,
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
    let locked = guard.as_ref().map(|s| s.auth.is_none()).unwrap_or(true);
    Ok(Json(StatusResponse {
        locked,
        last_sync_epoch_secs: None,
    }))
}

// ── unlock ────────────────────────────────────────────────────────────────────

#[plugin_fn]
pub fn unlock(Json(_req): Json<UnlockRequest>) -> FnResult<Json<SimpleResponse>> {
    // Stub — real kdbx open lands in the next commit.
    Ok(Json(SimpleResponse {
        ok: false,
        error: Some("keepassxc-file unlock not yet implemented".into()),
        error_kind: Some(ErrorKind::Unavailable),
        two_factor_methods: None,
    }))
}

// ── lock ──────────────────────────────────────────────────────────────────────

#[plugin_fn]
pub fn lock(_: ()) -> FnResult<Json<SimpleResponse>> {
    let mut guard = STATE.lock();
    if let Some(state) = guard.as_mut() {
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
    // Re-stat the file; if mtime changed, re-decrypt.  Not yet wired.
    Ok(Json(SimpleResponse {
        ok: true,
        error: None,
        error_kind: None,
        two_factor_methods: None,
    }))
}

// ── list_items / search ───────────────────────────────────────────────────────

#[plugin_fn]
pub fn list_items(_: ()) -> FnResult<Json<ItemListResponse>> {
    Ok(Json(ItemListResponse {
        ok: true,
        error: None,
        error_kind: None,
        items: vec![],
    }))
}

#[plugin_fn]
pub fn search(Json(_req): Json<SearchRequest>) -> FnResult<Json<ItemListResponse>> {
    Ok(Json(ItemListResponse {
        ok: true,
        error: None,
        error_kind: None,
        items: vec![],
    }))
}

// ── attribute access ──────────────────────────────────────────────────────────

#[plugin_fn]
pub fn get_item_attributes(
    Json(_req): Json<ItemIdRequest>,
) -> FnResult<Json<ItemAttributesResponse>> {
    Ok(Json(ItemAttributesResponse {
        ok: false,
        error: Some("not implemented".into()),
        error_kind: Some(ErrorKind::NotFound),
        public: Default::default(),
        secret_names: vec![],
    }))
}

#[plugin_fn]
pub fn get_secret_attr(Json(_req): Json<SecretAttrRequest>) -> FnResult<Json<SecretAttrResponse>> {
    Ok(Json(SecretAttrResponse {
        ok: false,
        error: Some("not implemented".into()),
        error_kind: Some(ErrorKind::NotFound),
        value_b64: None,
    }))
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
    Ok(Json(AuthFieldsResponse {
        fields: vec![WasmAuthField {
            id: "password".into(),
            label: "Master password".into(),
            placeholder: String::new(),
            required: true,
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
