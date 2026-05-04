//! JSON protocol types for host ↔ guest communication.
//!
//! These types define the wire format between the WasmProvider host and
//! WASM guest plugins.  Both sides serialize/deserialize to JSON via
//! Extism byte buffers.
//!
//! This is a duplicate of `rosec-wasm/src/protocol.rs` (the host side),
//! with the addition of SM-specific `CheckRemoteChanged` types.
//! Keep both copies in sync.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── Init / lifecycle ─────────────────────────────────────────────

/// Sent to `init` — one-time plugin configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct InitRequest {
    pub provider_id: String,
    pub provider_name: String,
    pub options: HashMap<String, serde_json::Value>,
}

/// Returned by `init`.
#[derive(Debug, Serialize, Deserialize)]
pub struct InitResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
}

// ── Status ───────────────────────────────────────────────────────

/// Returned by `status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub locked: bool,
    pub last_sync_epoch_secs: Option<u64>,
}

// ── Unlock / Lock ────────────────────────────────────────────────

/// Sent to `unlock`.
#[derive(Serialize, Deserialize)]
pub struct UnlockRequest {
    /// The user's unlock password (used by the host for credential persistence).
    pub password: String,
    /// Additional registration fields (for first-time setup).
    /// For SM: `registration_fields["access_token"]` contains the raw access token.
    #[serde(default)]
    pub registration_fields: Option<HashMap<String, String>>,
    /// Additional auth fields for the current unlock attempt (e.g. a 2FA
    /// token).  Ephemeral per-unlock — not persisted across sessions.
    #[serde(default)]
    pub auth_fields: Option<HashMap<String, String>>,
}

impl std::fmt::Debug for UnlockRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockRequest")
            .field("password", &"[redacted]")
            .field(
                "registration_fields",
                &self.registration_fields.as_ref().map(|m| m.len()),
            )
            .field(
                "auth_fields",
                &self
                    .auth_fields
                    .as_ref()
                    .map(|m| m.keys().collect::<Vec<_>>()),
            )
            .finish()
    }
}

/// Returned by `unlock`, `lock`, `sync`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    /// Discriminates error kind for the host to map to ProviderError.
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    /// When `error_kind` is `TwoFactorRequired`, the available 2FA methods.
    #[serde(default)]
    pub two_factor_methods: Option<Vec<TwoFactorMethod>>,
}

/// Describes a single two-factor authentication method available for the
/// current provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorMethod {
    /// Opaque method identifier sent back to the guest in `auth_fields`.
    pub id: String,
    /// Human-readable label shown to the user.
    pub label: String,
    /// How the host should collect the credential: `"text"`, `"fido2"`,
    /// `"browser_redirect"`.
    pub prompt_kind: String,
    /// Optional challenge data for host-mediated methods.
    #[serde(default)]
    pub challenge: Option<String>,
}

// ── Items ────────────────────────────────────────────────────────

/// Returned by `list_items` and `search`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ItemListResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    #[serde(default)]
    pub items: Vec<WasmItemMeta>,
}

/// A single item's metadata — the WASM equivalent of `ItemMeta`.
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmItemMeta {
    pub id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub created_epoch_secs: Option<u64>,
    pub modified_epoch_secs: Option<u64>,
}

/// Sent to `search`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchRequest {
    pub attributes: HashMap<String, String>,
}

// ── Attributes ───────────────────────────────────────────────────

/// Sent to `get_item_attributes`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ItemIdRequest {
    pub id: String,
}

/// Returned by `get_item_attributes`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ItemAttributesResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    #[serde(default)]
    pub public: HashMap<String, String>,
    #[serde(default)]
    pub secret_names: Vec<String>,
}

// ── Secrets ──────────────────────────────────────────────────────

/// Sent to `get_secret_attr`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretAttrRequest {
    pub id: String,
    pub attr: String,
}

/// Returned by `get_secret_attr`.
///
/// Secret bytes are base64-encoded for JSON transport.
#[derive(Serialize, Deserialize)]
pub struct SecretAttrResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    /// Base64-encoded secret bytes.
    #[serde(default)]
    pub value_b64: Option<String>,
}

impl std::fmt::Debug for SecretAttrResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretAttrResponse")
            .field("ok", &self.ok)
            .field("error", &self.error)
            .field("error_kind", &self.error_kind)
            .field("value_b64", &self.value_b64.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

// ── Registration / Auth fields ───────────────────────────────────

/// Returned by `registration_info`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationInfoResponse {
    pub has_registration: bool,
    #[serde(default)]
    pub instructions: Option<String>,
    #[serde(default)]
    pub fields: Vec<WasmAuthField>,
}

/// Returned by `auth_fields`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthFieldsResponse {
    #[serde(default)]
    pub fields: Vec<WasmAuthField>,
}

/// An auth field descriptor.
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmAuthField {
    pub id: String,
    pub label: String,
    pub placeholder: String,
    pub required: bool,
    pub kind: String, // "text", "password", "secret"
}

// ── Attribute descriptors ────────────────────────────────────────

/// Returned by `attribute_descriptors`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttributeDescriptorsResponse {
    pub descriptors: Vec<WasmAttributeDescriptor>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WasmAttributeDescriptor {
    pub name: String,
    pub sensitive: bool,
    pub item_types: Vec<String>,
    pub description: String,
}

// ── Capabilities ─────────────────────────────────────────────────

/// Returned by `capabilities`.
#[derive(Debug, Serialize, Deserialize)]
pub struct CapabilitiesResponse {
    pub capabilities: Vec<String>,
}

// ── Plugin manifest (pre-init discovery) ─────────────────────────

/// Returned by `plugin_manifest` — called before `init` to discover
/// the plugin's kind, name, config requirements, and allowed hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// The provider kind string (e.g. `"bitwarden-sm"`).
    pub kind: String,
    /// Human-readable plugin name.
    pub name: String,
    /// Short description shown in `rosec provider kinds`.
    pub description: String,
    /// HTTP hosts the plugin needs access to (defaults).
    #[serde(default)]
    pub default_allowed_hosts: Vec<String>,
    /// Config options the plugin requires.
    #[serde(default)]
    pub required_options: Vec<PluginOptionDescriptor>,
    /// Config options the plugin accepts but doesn't require.
    #[serde(default)]
    pub optional_options: Vec<PluginOptionDescriptor>,
    /// Which required option key to hash for auto-generating provider IDs.
    #[serde(default)]
    pub id_derivation_key: Option<String>,
}

/// Describes a single config option a plugin accepts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginOptionDescriptor {
    pub key: String,
    pub description: String,
    #[serde(default = "default_option_kind")]
    pub kind: String,
}

fn default_option_kind() -> String {
    "text".into()
}

// ── SM-specific: delta-sync check ────────────────────────────────

/// Sent to `check_remote_changed`.
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckRemoteChangedRequest {
    /// ISO-8601 UTC timestamp of the last successful sync (e.g. `"2024-01-15T12:00:00.000Z"`).
    pub last_synced_iso8601: String,
}

/// Returned by `check_remote_changed`.
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckRemoteChangedResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    /// Whether the org's secrets have changed since `last_synced_iso8601`.
    pub has_changes: bool,
}

// ── Error classification ─────────────────────────────────────────

/// Allows the guest to communicate structured error kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Locked,
    NotFound,
    NotSupported,
    Unavailable,
    AlreadyExists,
    InvalidInput,
    RegistrationRequired,
    AuthFailed,
    TwoFactorRequired,
    Other,
}
