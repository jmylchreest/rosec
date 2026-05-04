//! JSON protocol types for host ↔ guest communication.
//!
//! These types define the wire format between the WasmProvider host and
//! WASM guest plugins.  Both sides serialize/deserialize to JSON via
//! Extism byte buffers.
//!
//! The guest crate duplicates these definitions (it cannot share a crate
//! because it targets `wasm32-wasip1`).  Keep both copies in sync.

use std::{collections::HashMap, fmt};

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
///
/// `Debug` is manually implemented to redact `password`,
/// `registration_fields`, and `auth_fields` (which may contain secrets).
#[derive(Serialize, Deserialize)]
pub struct UnlockRequest {
    /// The user's master password.
    pub password: String,
    /// Additional registration fields (for first-time setup).
    #[serde(default)]
    pub registration_fields: Option<HashMap<String, String>>,
    /// Additional auth fields for the current unlock attempt (e.g. a 2FA
    /// token).  These are distinct from `registration_fields` which are
    /// persisted across sessions — `auth_fields` are ephemeral per-unlock
    /// credentials.
    #[serde(default)]
    pub auth_fields: Option<HashMap<String, String>>,
}

impl fmt::Debug for UnlockRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockRequest")
            .field("password", &"[REDACTED]")
            .field(
                "registration_fields",
                &self.registration_fields.as_ref().map(|m| {
                    m.keys()
                        .map(|k| (k.as_str(), "[REDACTED]"))
                        .collect::<Vec<_>>()
                }),
            )
            .field(
                "auth_fields",
                &self.auth_fields.as_ref().map(|m| {
                    m.keys()
                        .map(|k| (k.as_str(), "[REDACTED]"))
                        .collect::<Vec<_>>()
                }),
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
    /// When `error_kind` is `TwoFactorRequired`, the available 2FA methods
    /// the user may choose from.  Each method describes a prompt kind so the
    /// host can collect the right credential (text code, hardware key, etc.).
    #[serde(default)]
    pub two_factor_methods: Option<Vec<TwoFactorMethod>>,
}

/// Describes a single two-factor authentication method available for the
/// current provider.
///
/// The host uses `prompt_kind` to decide how to collect the credential:
/// - `"text"` — prompt for a text string (TOTP code, email code, YubiKey OTP,
///   Duo passcode).
/// - `"fido2"` — perform a FIDO2/WebAuthn ceremony on the host (requires
///   hardware key access; deferred — not yet implemented).
/// - `"browser_redirect"` — open a URL and wait for a callback (deferred —
///   not yet implemented).
///
/// The `id` is opaque to the host — only the guest knows how to map it back
/// to a provider-specific code (e.g. Bitwarden provider=0 for TOTP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorMethod {
    /// Opaque method identifier sent back to the guest in `auth_fields`.
    pub id: String,
    /// Human-readable label shown to the user (e.g. "Authenticator app (TOTP)").
    pub label: String,
    /// How the host should collect the credential.
    pub prompt_kind: String,
    /// Optional challenge data for host-mediated methods (e.g. WebAuthn
    /// challenge JSON).  Unused for text-prompt methods.
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
/// `Debug` is manually implemented to redact `value_b64`.
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

impl fmt::Debug for SecretAttrResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretAttrResponse")
            .field("ok", &self.ok)
            .field("error", &self.error)
            .field("error_kind", &self.error_kind)
            .field("value_b64", &self.value_b64.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

// ── SSH ──────────────────────────────────────────────────────────

/// Returned by `list_ssh_keys`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SshKeyListResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    #[serde(default)]
    pub keys: Vec<WasmSshKeyMeta>,
}

/// A single SSH key's metadata — the WASM equivalent of `SshKeyMeta`.
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmSshKeyMeta {
    pub item_id: String,
    pub item_name: String,
    pub public_key_openssh: Option<String>,
    pub fingerprint: Option<String>,
    pub ssh_hosts: Vec<String>,
    pub ssh_user: Option<String>,
    pub require_confirm: bool,
    pub revision_date_epoch_secs: Option<u64>,
}

/// Sent to `get_ssh_private_key`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SshPrivateKeyRequest {
    pub item_id: String,
}

/// Returned by `get_ssh_private_key`.
///
/// `Debug` is manually implemented to redact `pem`.
#[derive(Serialize, Deserialize)]
pub struct SshPrivateKeyResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    /// PEM-encoded private key.
    #[serde(default)]
    pub pem: Option<String>,
}

impl fmt::Debug for SshPrivateKeyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshPrivateKeyResponse")
            .field("ok", &self.ok)
            .field("error", &self.error)
            .field("error_kind", &self.error_kind)
            .field("pem", &self.pem.as_ref().map(|_| "[REDACTED]"))
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

// ── Readiness probes ─────────────────────────────────────────────

/// Returned by `readiness_probes` — declares what the host should check
/// before attempting stateful calls like `unlock`.
///
/// The host evaluates these probes natively (no WASM execution), respecting
/// the Extism `allowed_hosts` security boundary.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReadinessProbesResponse {
    #[serde(default)]
    pub probes: Vec<ReadinessProbe>,
}

/// A single readiness probe declared by a WASM guest plugin.
///
/// The host evaluates these natively before attempting `unlock`.
/// Each variant carries only the fields relevant to its protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReadinessProbe {
    /// HTTP(S) probe — performs a request and checks the response status.
    Http {
        /// Full URL to probe (e.g. `"https://identity.bitwarden.com/alive"`).
        url: String,
        /// HTTP method (default: `"HEAD"`).
        #[serde(default = "default_probe_http_method")]
        method: String,
        /// Expected HTTP status code (default: 200).
        #[serde(default = "default_probe_expected_status")]
        expected_status: u16,
        /// Probe timeout in seconds (default: 5).
        #[serde(default = "default_probe_timeout")]
        timeout_secs: u32,
    },
    /// TCP probe — attempts a connection to `host:port`.
    Tcp {
        /// Hostname to connect to (e.g. `"vault.bitwarden.com"`).
        host: String,
        port: u16,
        /// Probe timeout in seconds (default: 5).
        #[serde(default = "default_probe_timeout")]
        timeout_secs: u32,
    },
}

fn default_probe_http_method() -> String {
    "HEAD".into()
}

fn default_probe_expected_status() -> u16 {
    200
}

fn default_probe_timeout() -> u32 {
    5
}

// ── Plugin manifest (pre-init discovery) ─────────────────────────

/// Returned by `plugin_manifest` — called before `init` to discover
/// the plugin's kind, name, config requirements, and allowed hosts.
///
/// This enables automatic plugin discovery: the host scans `.wasm`
/// files in known directories, calls `plugin_manifest()` on each,
/// and registers the discovered kinds dynamically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// The provider kind string (e.g. `"bitwarden-pm"`).
    pub kind: String,
    /// Human-readable plugin name (e.g. `"Bitwarden Password Manager"`).
    pub name: String,
    /// Short description shown in `rosec provider kinds`.
    pub description: String,
    /// Plugin version (semver).  Used by the host when the same kind is
    /// found in multiple directories to select the newest copy.
    /// Guests that omit this are treated as version `0.0.0`.
    #[serde(default)]
    pub version: Option<semver::Version>,
    /// HTTP hosts the plugin needs access to (defaults).
    /// Users can override via config.
    #[serde(default)]
    pub default_allowed_hosts: Vec<String>,
    /// Config options the plugin requires.
    #[serde(default)]
    pub required_options: Vec<PluginOptionDescriptor>,
    /// Config options the plugin accepts but doesn't require.
    #[serde(default)]
    pub optional_options: Vec<PluginOptionDescriptor>,
    /// Which required option key to hash for auto-generating provider IDs.
    /// e.g. `"email"` for bitwarden-pm.  If `None`, falls back to the kind.
    #[serde(default)]
    pub id_derivation_key: Option<String>,
    /// `true` if the plugin is experimental — shown to the user as a warning
    /// in `rosec provider kinds`, `rosec provider list`, `rosec status`, and
    /// confirmed via prompt in `rosec provider add`.
    ///
    /// Defaults to `false` so existing plugins (without this field) are
    /// treated as stable.
    #[serde(default)]
    pub experimental: bool,
    /// Names of provider-internal features that are experimental, even when
    /// the provider itself is stable.  Surfaced when the user enables one of
    /// these via config.  Unused for now — reserved for future per-feature
    /// gating.
    #[serde(default)]
    pub experimental_features: Vec<String>,
}

/// Describes a single config option a plugin accepts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginOptionDescriptor {
    /// Option key (e.g. `"email"`, `"region"`).
    pub key: String,
    /// Human-readable description for prompts.
    pub description: String,
    /// Input kind: `"text"`, `"password"`, or `"secret"`.
    #[serde(default = "default_option_kind")]
    pub kind: String,
}

fn default_option_kind() -> String {
    "text".into()
}

// ── SM-specific: delta-sync check ────────────────────────────────

/// Sent to `check_remote_changed` (SM guest only).
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckRemoteChangedRequest {
    /// ISO-8601 UTC timestamp of the last successful sync (e.g. `"2024-01-15T12:00:00.000Z"`).
    pub last_synced_iso8601: String,
}

/// Returned by `check_remote_changed` (SM guest only).
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

// ── Offline cache ────────────────────────────────────────────────

/// Returned by `export_cache` — the guest serialises its current in-memory
/// state into an opaque blob.  The host wraps this in an additional
/// encryption layer before persisting to disk.
///
/// The guest MAY pre-encrypt the blob (defense in depth) but is not
/// required to — the host wrapper provides confidentiality and integrity.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportCacheResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    /// Opaque cache blob, base64-encoded.  The host treats this as an
    /// opaque byte string — it never inspects or interprets the contents.
    #[serde(default)]
    pub blob_b64: Option<String>,
}

/// Sent to `restore_cache` — the host unwrapped the cache file and passes
/// the inner blob back to the guest to restore its in-memory state.
#[derive(Debug, Serialize, Deserialize)]
pub struct RestoreCacheRequest {
    /// The same opaque blob that was returned by `export_cache`, base64.
    pub blob_b64: String,
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
    /// The provider requires two-factor authentication to proceed.
    /// The `SimpleResponse::two_factor_methods` field describes the available
    /// methods the host can offer to the user.
    TwoFactorRequired,
    Other,
}

/// Response from the guest's `get_notification_config` function.
///
/// Called by the host after a successful online unlock or sync to obtain
/// WebSocket subscription details.  The guest performs any negotiate steps
/// internally (via its HTTP capability) and returns a ready-to-connect URL.
#[derive(Debug, Serialize, Deserialize)]
pub struct NotificationConfigResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    /// The subscription to establish.  `None` when `ok` is `false`.
    #[serde(default)]
    pub subscription: Option<WebSocketSubscription>,
}

/// Everything the host needs to establish a WebSocket connection.
///
/// The guest builds the full URL (including any auth tokens in query
/// params) and handles any protocol-specific negotiate steps internally.
/// The host is a generic WebSocket client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketSubscription {
    /// Full WebSocket URL, ready to connect.
    /// e.g. `"wss://notifications.example.com/hub?access_token=<jwt>"`
    pub url: String,
    /// Optional HTTP headers for the WebSocket upgrade request.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Optional message to send immediately after WebSocket connect
    /// (e.g. a protocol handshake frame).
    #[serde(default)]
    pub handshake_message: Option<String>,
}

/// A raw WebSocket text frame passed to the guest for parsing.
#[derive(Debug, Serialize, Deserialize)]
pub struct NotificationFrame {
    /// The raw text content of the WebSocket message.
    pub text: String,
}

/// Guest's interpretation of a received notification frame.
#[derive(Debug, Serialize, Deserialize)]
pub struct NotificationAction {
    /// What the host should do in response to this frame.
    pub action: NotificationActionKind,
}

/// Actions the host can take in response to a notification frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationActionKind {
    /// Trigger a sync (fires `on_remote_sync_nudge`).
    Sync,
    /// Lock the provider (fires `on_remote_lock_nudge`).
    Lock,
    /// Ignore this frame (ping, ack, handshake response, unknown).
    Ignore,
}
