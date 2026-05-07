//! Bitwarden Secrets Manager WASM guest plugin for rosec.
//!
//! This is the Extism guest that implements the Bitwarden Secrets Manager
//! provider.  It exports plugin functions that the `rosec-wasm` host crate
//! calls via `Plugin::call()`.
//!
//! # Architecture
//!
//! - **Global state**: A `Mutex<Option<GuestState>>` holds the plugin state.
//!   `init` populates `GuestConfig`; `unlock` populates `AuthState`.
//! - **No async**: All functions are synchronous — HTTP goes through
//!   `extism_pdk::http::request`.
//! - **Credential persistence**: The host handles access token persistence
//!   via `rosec-wasm/src/wasm_cred.rs`.  The guest receives the raw access
//!   token in `UnlockRequest.registration_fields["access_token"]`.
//! - **SM-specific**: Exports `check_remote_changed` (not in PM guest) for
//!   delta-sync without a full secrets re-fetch.

mod api;
mod crypto;
mod error;
mod protocol;

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use extism_pdk::*;
use zeroize::Zeroizing;

use crate::api::{fetch_secrets, login, AccessToken, DecryptedSecret, SmUrls};
use crate::error::SmError;
use crate::protocol::*;

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
    auth: Option<AuthState>,
}

struct GuestConfig {
    provider_id: String,
    org_id: String,
    urls: SmUrls,
}

/// Authenticated state — populated by `unlock`, cleared by `lock`.
struct AuthState {
    /// Raw access token (kept for re-sync).
    access_token: Zeroizing<String>,
    /// Decrypted secrets.
    secrets: Vec<DecryptedSecret>,
    /// Short-lived Bearer JWT cached for delta-sync checks.
    bearer: Zeroizing<String>,
    /// Unix epoch seconds when `bearer` expires (per identity-server `expires_in`).
    bearer_expires_at_epoch: u64,
    /// Unix epoch seconds of the last successful sync.
    last_sync_epoch_secs: u64,
    /// ISO-8601 UTC timestamp of the last successful sync (for delta-sync).
    last_synced_iso8601: String,
}

/// Refresh the bearer ahead of its expiry by this margin so a delta-sync probe
/// in flight when the token is about to expire still completes against a fresh
/// JWT instead of returning 401.
const BEARER_REFRESH_MARGIN_SECS: u64 = 300;

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

/// Attribute key for item type — mirrors `rosec_core::ATTR_TYPE`.
const ATTR_TYPE: &str = "rosec:type";

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Build a `WasmItemMeta` from a decrypted SM secret.
fn secret_to_wasm_meta(provider_id: &str, secret: &DecryptedSecret) -> WasmItemMeta {
    let mut attributes = HashMap::new();
    attributes.insert(ATTR_TYPE.to_string(), "secret".to_string());
    attributes.insert("sm.key".to_string(), secret.key.clone());
    attributes.insert("sm.id".to_string(), secret.id.clone());
    if let Some(pid) = &secret.project_id {
        attributes.insert("sm.project_id".to_string(), pid.clone());
    }
    if let Some(name) = &secret.project_name {
        attributes.insert("sm.project".to_string(), name.clone());
    }
    // Inject provider_id for the host
    attributes.insert("rosec:provider".to_string(), provider_id.to_string());

    WasmItemMeta {
        id: secret.id.clone(),
        label: secret.key.clone(),
        attributes,
        created_epoch_secs: None,
        modified_epoch_secs: None,
    }
}

/// Get the secret bytes for a decrypted secret.
///
/// Returns `value` if non-empty, otherwise falls back to `note`.
fn secret_value_b64(secret: &DecryptedSecret) -> String {
    let src = if !secret.value.is_empty() {
        secret.value.as_bytes()
    } else {
        secret.note.as_bytes()
    };
    B64.encode(src)
}

/// Return current Unix epoch seconds (using WASM-compatible SystemTime).
fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format epoch seconds as an ISO-8601 UTC timestamp for delta-sync.
///
/// Simple formatter — no chrono dependency.  Outputs `"YYYY-MM-DDTHH:MM:SS.000Z"`.
fn epoch_to_iso8601(secs: u64) -> String {
    let s = secs;
    let second = s % 60;
    let m = s / 60;
    let minute = m % 60;
    let h = m / 60;
    let hour = h % 24;
    let days = h / 24;

    // Compute year/month/day from days since epoch (2000-03-01 epoch trick).
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        year, month, day, hour, minute, second
    )
}

/// Build an error `SimpleResponse` from a `SmError`.
fn simple_err(e: &SmError) -> SimpleResponse {
    SimpleResponse {
        ok: false,
        error: Some(e.to_string()),
        error_kind: Some(e.to_error_kind()),
        two_factor_methods: None,
    }
}

fn simple_ok() -> SimpleResponse {
    SimpleResponse {
        ok: true,
        error: None,
        error_kind: None,
        two_factor_methods: None,
    }
}

/// Resolve `SmUrls` from provider options.
fn urls_from_options(options: &HashMap<String, serde_json::Value>) -> SmUrls {
    if let Some(base) = options.get("server_url").and_then(|v| v.as_str()) {
        SmUrls::from_base(base)
    } else {
        let region = options
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("us");
        match region.to_ascii_lowercase().as_str() {
            "eu" => SmUrls::official_eu(),
            _ => SmUrls::official_us(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Plugin function exports
// ═══════════════════════════════════════════════════════════════════

/// Return the plugin manifest for discovery.
///
/// Called by the host **before** `init` — no global state is accessed.
#[plugin_fn]
pub fn plugin_manifest(_: ()) -> FnResult<Json<PluginManifest>> {
    Ok(Json(PluginManifest {
        kind: "bitwarden-sm".to_string(),
        name: "Bitwarden Secrets Manager".to_string(),
        description: "Bitwarden Secrets Manager machine account access token provider".to_string(),
        default_allowed_hosts: vec!["*.bitwarden.com".to_string(), "*.bitwarden.eu".to_string()],
        required_options: vec![PluginOptionDescriptor {
            key: "organization_id".to_string(),
            description: "Bitwarden organisation UUID (restricts which secrets are fetched)"
                .to_string(),
            kind: "text".to_string(),
        }],
        optional_options: vec![
            PluginOptionDescriptor {
                key: "region".to_string(),
                description: "Cloud region: 'us' or 'eu' (default: us)".to_string(),
                kind: "text".to_string(),
            },
            PluginOptionDescriptor {
                key: "server_url".to_string(),
                description: "Self-hosted base URL, e.g. https://vault.example.com".to_string(),
                kind: "text".to_string(),
            },
        ],
        id_derivation_key: Some("organization_id".to_string()),
    }))
}

/// Initialise the plugin with provider configuration.
#[plugin_fn]
pub fn init(Json(req): Json<InitRequest>) -> FnResult<Json<InitResponse>> {
    let org_id = req
        .options
        .get("organization_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    if org_id.is_empty() {
        return Ok(Json(InitResponse {
            ok: false,
            error: Some("missing required option: organization_id".to_string()),
        }));
    }

    let urls = urls_from_options(&req.options);

    let config = GuestConfig {
        provider_id: req.provider_id.clone(),
        org_id,
        urls,
    };

    extism_pdk::info!(
        "bitwarden-sm plugin initialised: provider_id={}",
        req.provider_id
    );

    let mut guard = STATE.lock();
    *guard = Some(GuestState { config, auth: None });

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
        return Ok(Json(StatusResponse {
            locked: true,
            last_sync_epoch_secs: None,
        }));
    };

    match &state.auth {
        Some(auth) => Ok(Json(StatusResponse {
            locked: false,
            last_sync_epoch_secs: Some(auth.last_sync_epoch_secs),
        })),
        None => Ok(Json(StatusResponse {
            locked: true,
            last_sync_epoch_secs: None,
        })),
    }
}

/// Unlock the SM provider.
///
/// The raw access token is provided in `registration_fields["access_token"]`.
/// The host persists it encrypted between sessions and passes it back here.
///
/// If `registration_fields` is absent or empty, return `RegistrationRequired`
/// so the host prompts the user to enter their access token.
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

    // Extract access token from registration_fields.
    let raw_token = req
        .registration_fields
        .as_ref()
        .and_then(|rf| rf.get("access_token"))
        .map(String::as_str)
        .unwrap_or("");

    if raw_token.is_empty() {
        // No token supplied — host must provide one via registration.
        return Ok(Json(SimpleResponse {
            ok: false,
            error: Some("access token required".to_string()),
            error_kind: Some(ErrorKind::RegistrationRequired),
            two_factor_methods: None,
        }));
    }

    let token = match AccessToken::parse(raw_token) {
        Ok(t) => t,
        Err(e) => {
            extism_pdk::warn!("SM access token parse failed: {e}");
            return Ok(Json(SimpleResponse {
                ok: false,
                error: Some(format!("invalid access token: {e}")),
                error_kind: Some(ErrorKind::AuthFailed),
                two_factor_methods: None,
            }));
        }
    };

    match fetch_secrets(&state.config.urls, &token, &state.config.org_id) {
        Ok((bearer, expires_in, secrets)) => {
            let count = secrets.len();
            let now = now_epoch_secs();
            state.auth = Some(AuthState {
                access_token: Zeroizing::new(raw_token.to_string()),
                secrets,
                bearer,
                bearer_expires_at_epoch: now.saturating_add(expires_in),
                last_sync_epoch_secs: now,
                last_synced_iso8601: epoch_to_iso8601(now),
            });
            extism_pdk::info!(
                "SM provider unlocked: provider_id={} secrets={count}",
                state.config.provider_id
            );
            Ok(Json(simple_ok()))
        }
        Err(e) => {
            extism_pdk::warn!("SM unlock failed: {e}");
            Ok(Json(simple_err(&e)))
        }
    }
}

/// Lock the provider — drop all sensitive state.
#[plugin_fn]
pub fn lock(_input: ()) -> FnResult<Json<SimpleResponse>> {
    let mut guard = STATE.lock();

    if let Some(state) = guard.as_mut() {
        state.auth = None;
        extism_pdk::info!("SM provider locked");
    }

    Ok(Json(simple_ok()))
}

/// Re-sync secrets from the Bitwarden SM API using the cached access token.
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
            error: Some("provider is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            two_factor_methods: None,
        }));
    };

    // Re-parse the cached access token and fetch fresh secrets.
    let token = match AccessToken::parse(&auth.access_token) {
        Ok(t) => t,
        Err(e) => {
            extism_pdk::warn!("SM sync: access token parse failed: {e}");
            return Ok(Json(SimpleResponse {
                ok: false,
                error: Some(format!("access token parse: {e}")),
                error_kind: Some(ErrorKind::AuthFailed),
                two_factor_methods: None,
            }));
        }
    };

    match fetch_secrets(&state.config.urls, &token, &state.config.org_id) {
        Ok((bearer, expires_in, secrets)) => {
            let count = secrets.len();
            let now = now_epoch_secs();
            auth.secrets = secrets;
            auth.bearer = bearer;
            auth.bearer_expires_at_epoch = now.saturating_add(expires_in);
            auth.last_sync_epoch_secs = now;
            auth.last_synced_iso8601 = epoch_to_iso8601(now);
            extism_pdk::info!("SM secrets synced: secrets={count}");
            Ok(Json(simple_ok()))
        }
        Err(e) => {
            extism_pdk::warn!("SM sync failed: {e}");
            Ok(Json(simple_err(&e)))
        }
    }
}

/// List all SM secrets as item metadata.
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
            error: Some("provider is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            items: Vec::new(),
        }));
    };

    let provider_id = &state.config.provider_id;
    let items: Vec<WasmItemMeta> = auth
        .secrets
        .iter()
        .map(|s| secret_to_wasm_meta(provider_id, s))
        .collect();

    Ok(Json(ItemListResponse {
        ok: true,
        error: None,
        error_kind: None,
        items,
    }))
}

/// Search for SM secrets matching the given attributes.
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
            error: Some("provider is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            items: Vec::new(),
        }));
    };

    let provider_id = &state.config.provider_id;
    let items: Vec<WasmItemMeta> = auth
        .secrets
        .iter()
        .filter_map(|s| {
            let meta = secret_to_wasm_meta(provider_id, s);
            if req
                .attributes
                .iter()
                .all(|(k, v)| meta.attributes.get(k) == Some(v))
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

/// Return public attributes + secret attribute names for a secret.
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
            error: Some("provider is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            public: HashMap::new(),
            secret_names: Vec::new(),
        }));
    };

    let secret = auth.secrets.iter().find(|s| s.id == req.id);

    let Some(secret) = secret else {
        return Ok(Json(ItemAttributesResponse {
            ok: false,
            error: Some(format!("secret not found: {}", req.id)),
            error_kind: Some(ErrorKind::NotFound),
            public: HashMap::new(),
            secret_names: Vec::new(),
        }));
    };

    let meta = secret_to_wasm_meta(&state.config.provider_id, secret);

    Ok(Json(ItemAttributesResponse {
        ok: true,
        error: None,
        error_kind: None,
        public: meta.attributes,
        secret_names: vec!["password".to_string()],
    }))
}

/// Return the secret bytes for a named attribute of a secret.
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
            error: Some("provider is locked".to_string()),
            error_kind: Some(ErrorKind::Locked),
            value_b64: None,
        }));
    };

    let secret = auth.secrets.iter().find(|s| s.id == req.id);

    let Some(secret) = secret else {
        return Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some(format!("secret not found: {}", req.id)),
            error_kind: Some(ErrorKind::NotFound),
            value_b64: None,
        }));
    };

    match req.attr.as_str() {
        "password" => Ok(Json(SecretAttrResponse {
            ok: true,
            error: None,
            error_kind: None,
            value_b64: Some(secret_value_b64(secret)),
        })),
        _ => Ok(Json(SecretAttrResponse {
            ok: false,
            error: Some(format!("unknown attribute: {}", req.attr)),
            error_kind: Some(ErrorKind::NotFound),
            value_b64: None,
        })),
    }
}

/// Return the capabilities this plugin supports.
///
/// SM supports `Sync` only.  `PasswordChange` is handled host-side by
/// `WasmProvider` (re-encrypts stored credentials).
#[plugin_fn]
pub fn capabilities(_input: ()) -> FnResult<Json<CapabilitiesResponse>> {
    Ok(Json(CapabilitiesResponse {
        capabilities: vec!["sync".to_string()],
    }))
}

/// Return attribute descriptors for SM secrets.
#[plugin_fn]
pub fn attribute_descriptors(_input: ()) -> FnResult<Json<AttributeDescriptorsResponse>> {
    let descriptors = vec![
        WasmAttributeDescriptor {
            name: ATTR_TYPE.to_string(),
            sensitive: false,
            item_types: vec![],
            description: "Item type (always 'secret' for SM items)".to_string(),
        },
        WasmAttributeDescriptor {
            name: "sm.key".to_string(),
            sensitive: false,
            item_types: vec!["secret".to_string()],
            description: "Secret name/key in Bitwarden Secrets Manager".to_string(),
        },
        WasmAttributeDescriptor {
            name: "sm.id".to_string(),
            sensitive: false,
            item_types: vec!["secret".to_string()],
            description: "Secret UUID in Bitwarden Secrets Manager".to_string(),
        },
        WasmAttributeDescriptor {
            name: "sm.project_id".to_string(),
            sensitive: false,
            item_types: vec!["secret".to_string()],
            description: "Project UUID the secret belongs to (if any)".to_string(),
        },
        WasmAttributeDescriptor {
            name: "sm.project".to_string(),
            sensitive: false,
            item_types: vec!["secret".to_string()],
            description: "Project name the secret belongs to (if any)".to_string(),
        },
        WasmAttributeDescriptor {
            name: "password".to_string(),
            sensitive: true,
            item_types: vec!["secret".to_string()],
            description: "Secret value (falls back to note if value is empty)".to_string(),
        },
    ];

    Ok(Json(AttributeDescriptorsResponse { descriptors }))
}

/// Return registration info for first-time setup.
///
/// SM requires the user to provide their machine account access token
/// (format: `0.{uuid}.{secret}:{base64_key}`).
#[plugin_fn]
pub fn registration_info(_input: ()) -> FnResult<Json<RegistrationInfoResponse>> {
    Ok(Json(RegistrationInfoResponse {
        has_registration: true,
        instructions: Some(
            "This provider needs a Bitwarden Secrets Manager access token.\n\n\
             Generate a machine account access token in the Bitwarden Secrets Manager \
             web app and paste it below.  The token will be encrypted with your unlock \
             password and stored locally."
                .to_string(),
        ),
        fields: vec![WasmAuthField {
            id: "access_token".to_string(),
            label: "Access Token".to_string(),
            placeholder: "0.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.xxxxxxxx\u{2026}".to_string(),
            required: true,
            kind: "secret".to_string(),
        }],
    }))
}

/// Return the unlock password field descriptor.
#[plugin_fn]
pub fn auth_fields(_input: ()) -> FnResult<Json<AuthFieldsResponse>> {
    Ok(Json(AuthFieldsResponse {
        fields: vec![WasmAuthField {
            id: "password".to_string(),
            label: "Unlock Password".to_string(),
            placeholder: "Password used to protect the stored access token".to_string(),
            required: true,
            kind: "password".to_string(),
        }],
    }))
}

/// SM-specific: delta-sync check.
///
/// Returns `{ ok: true, has_changes: bool }` — `has_changes = true` means
/// secrets have changed since the last sync.  On any error, returns
/// `{ ok: true, has_changes: true }` so the host falls back to a full sync.
///
/// The host calls this before deciding whether to do a full `sync`.
#[plugin_fn]
pub fn check_remote_changed(
    Json(req): Json<CheckRemoteChangedRequest>,
) -> FnResult<Json<CheckRemoteChangedResponse>> {
    let mut guard = STATE.lock();

    let Some(state) = guard.as_mut() else {
        // Not initialised — assume changed.
        return Ok(Json(CheckRemoteChangedResponse {
            ok: true,
            error: None,
            error_kind: None,
            has_changes: true,
        }));
    };

    let Some(auth) = state.auth.as_mut() else {
        // Locked — assume changed.
        return Ok(Json(CheckRemoteChangedResponse {
            ok: true,
            error: None,
            error_kind: None,
            has_changes: true,
        }));
    };

    // Refresh the bearer proactively if it's near expiry. The bearer is a
    // ~1h JWT; without this the delta probe would certainly return 401 once
    // expired and force a full secrets re-fetch via the `assume changed`
    // fallback below.
    let now = now_epoch_secs();
    if now.saturating_add(BEARER_REFRESH_MARGIN_SECS) >= auth.bearer_expires_at_epoch {
        match AccessToken::parse(&auth.access_token) {
            Ok(token) => match login(&state.config.urls, &token) {
                Ok(resp) => {
                    auth.bearer = Zeroizing::new(resp.access_token);
                    auth.bearer_expires_at_epoch = now.saturating_add(resp.expires_in);
                    extism_pdk::debug!("SM bearer refreshed for delta-sync probe");
                }
                Err(e) => {
                    extism_pdk::warn!("SM bearer refresh failed, assuming changed: {e}");
                    return Ok(Json(CheckRemoteChangedResponse {
                        ok: true,
                        error: None,
                        error_kind: None,
                        has_changes: true,
                    }));
                }
            },
            Err(e) => {
                extism_pdk::warn!(
                    "SM bearer refresh: access token parse failed, assuming changed: {e}"
                );
                return Ok(Json(CheckRemoteChangedResponse {
                    ok: true,
                    error: None,
                    error_kind: None,
                    has_changes: true,
                }));
            }
        }
    }

    match crate::api::check_secrets_changed(
        &state.config.urls,
        &auth.bearer,
        &state.config.org_id,
        &req.last_synced_iso8601,
    ) {
        Ok(has_changes) => {
            extism_pdk::debug!("SM delta-sync check has_changes={has_changes}");
            Ok(Json(CheckRemoteChangedResponse {
                ok: true,
                error: None,
                error_kind: None,
                has_changes,
            }))
        }
        Err(e) => {
            // Treat errors as "assume changed" — safe fallback.
            extism_pdk::warn!("SM delta-sync check failed, assuming changed: {e}");
            Ok(Json(CheckRemoteChangedResponse {
                ok: true,
                error: None,
                error_kind: None,
                has_changes: true,
            }))
        }
    }
}
