use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub mod config;
pub mod config_edit;
pub mod credential;
pub mod dedup;
pub mod machine_key;
pub mod oauth;
pub mod prompt;
pub mod router;

/// Crate-wide mutex used by tests that mutate `XDG_DATA_HOME`.
///
/// Both `oauth` and `credential` tests call `unsafe { env::set_var(...) }`;
/// using a single process-wide lock prevents races when those tests run in
/// parallel in the same test binary.
#[cfg(test)]
pub(crate) static TEST_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub type Attributes = HashMap<String, String>;

#[derive(Debug, Clone)]
pub struct BackendStatus {
    pub locked: bool,
    pub last_sync: Option<SystemTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItemMeta {
    pub id: String,
    pub backend_id: String,
    pub label: String,
    pub attributes: Attributes,
    pub created: Option<SystemTime>,
    pub modified: Option<SystemTime>,
    pub locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub meta: VaultItemMeta,
    pub secret: Option<SecretBytes>,
}

pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Create from an already-zeroizing buffer (avoids a plain copy).
    pub fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes([redacted])")
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(self.0.to_vec()))
    }
}

impl Serialize for SecretBytes {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(serde::ser::Error::custom(
            "SecretBytes cannot be serialized",
        ))
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom(
            "SecretBytes cannot be deserialized",
        ))
    }
}

/// The kind of input a backend field expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFieldKind {
    /// Visible free-text (e.g. email address, organisation UUID).
    Text,
    /// Hidden input — value must never be echoed (master password, API token).
    Password,
    /// Like Password but semantically a long opaque token (access token, API key).
    /// Hidden in the same way as Password; the distinction lets UIs show different
    /// placeholder text or help copy.
    Secret,
}

/// Describes a single credential field that a backend needs for `unlock`.
///
/// Backends return a static slice of `AuthField` from `auth_fields()`.  The
/// daemon's prompt subprocess and the `rosec auth` CLI subcommand use this list
/// to build backend-agnostic input forms.
#[derive(Debug, Clone, Copy)]
pub struct AuthField {
    /// Machine-readable identifier — used as the key in the field map passed
    /// back to `unlock`.  Must be unique within a backend's field list.
    pub id: &'static str,
    /// Human-readable label shown next to the input widget.
    pub label: &'static str,
    /// Short placeholder / example shown inside the input box.
    pub placeholder: &'static str,
    /// Whether the field must be non-empty before unlock is attempted.
    pub required: bool,
    pub kind: AuthFieldKind,
}

/// Information returned by a backend when device/API-key registration is required.
///
/// The auth flow displays `instructions` to the user before prompting for the
/// `fields`.  Both are backend-defined so the copy is accurate and actionable.
#[derive(Debug, Clone, Copy)]
pub struct RegistrationInfo {
    /// Human-readable instructions telling the user how to obtain the required
    /// credentials.  Displayed verbatim by the CLI and prompt UI.
    ///
    /// Example (Bitwarden):
    /// ```text
    /// "Find your API key at: Bitwarden web vault → Account Settings →
    ///  Security → Keys → View API Key"
    /// ```
    pub instructions: &'static str,
    /// The fields to collect from the user (e.g. `client_id`, `client_secret`).
    /// These are passed back to `unlock` as `UnlockInput::WithRegistration`.
    pub fields: &'static [AuthField],
}

/// Credentials passed to `VaultBackend::unlock`.
///
/// This enum intentionally does NOT derive `Serialize` or `Deserialize`.
/// Credentials (master passwords, session tokens, OTPs) must never be
/// accidentally written to logs, D-Bus responses, or disk.
#[derive(Clone)]
pub enum UnlockInput {
    /// Standard password-only unlock (master password for PM backends, or a
    /// locally-derived key for token-based backends that use local encryption).
    Password(Zeroizing<String>),
    /// Password + registration credentials, supplied when the backend previously
    /// returned `BackendError::RegistrationRequired`.
    ///
    /// The backend uses `password` to derive the local storage key (to encrypt
    /// the registration credentials at rest), then performs device registration,
    /// then retries its normal unlock flow.
    WithRegistration {
        password: Zeroizing<String>,
        /// Field values keyed by the `AuthField::id` strings from
        /// `RegistrationInfo::fields`.
        registration_fields: HashMap<String, Zeroizing<String>>,
    },
    ApiKey {
        client_id: String,
        client_secret: Zeroizing<String>,
    },
    SessionToken(Zeroizing<String>),
    Otp(Zeroizing<String>),
}

impl std::fmt::Debug for UnlockInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => f.debug_tuple("Password").field(&"[redacted]").finish(),
            Self::WithRegistration { .. } => f
                .debug_struct("WithRegistration")
                .field("password", &"[redacted]")
                .field("registration_fields", &"[redacted]")
                .finish(),
            Self::ApiKey { client_id, .. } => f
                .debug_struct("ApiKey")
                .field("client_id", client_id)
                .field("client_secret", &"[redacted]")
                .finish(),
            Self::SessionToken(_) => f.debug_tuple("SessionToken").field(&"[redacted]").finish(),
            Self::Otp(_) => f.debug_tuple("Otp").field(&"[redacted]").finish(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BackendError {
    #[error("backend locked")]
    Locked,
    #[error("item not found")]
    NotFound,
    #[error("not supported")]
    NotSupported,
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    /// The backend requires device/API-key registration before it can unlock.
    ///
    /// The auth flow should prompt for `RegistrationInfo::fields` (obtained via
    /// `VaultBackend::registration_info()`) and retry with
    /// `UnlockInput::WithRegistration`.
    #[error("registration required")]
    RegistrationRequired,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

// ---------------------------------------------------------------------------
// Attribute model
// ---------------------------------------------------------------------------

/// Describes a single attribute that a backend can produce for vault items.
///
/// Backends return a static slice of these from [`VaultBackend::available_attributes`]
/// so the service layer can validate config and support introspection.
#[derive(Debug, Clone)]
pub struct AttributeDescriptor {
    /// Machine-readable attribute name (e.g. `"password"`, `"totp"`, `"number"`).
    ///
    /// Uses the flat, unprefixed naming convention.  Custom fields from the
    /// vault source are exposed with a `"custom."` prefix to avoid collisions.
    pub name: &'static str,

    /// `true` if the attribute value is sensitive (passwords, TOTP seeds, card
    /// numbers, private keys, PII).  Sensitive attributes are never exposed in
    /// the D-Bus `Attributes` property — only their *names* are discoverable
    /// via a rosec-specific D-Bus method, and their *values* are retrieved via
    /// [`VaultBackend::get_secret_attr`].
    pub sensitive: bool,

    /// Which item types this attribute applies to (e.g. `["login"]`, `["card"]`,
    /// `["login", "identity"]`).  An empty slice means the attribute is common
    /// to all item types (e.g. `"notes"`, `"name"`).
    pub item_types: &'static [&'static str],

    /// Human-readable description for documentation and CLI help.
    pub description: &'static str,
}

/// The full attribute set for a single vault item, split into public metadata
/// and the names of available sensitive (secret) attributes.
///
/// Produced by [`VaultBackend::get_item_attributes`].  The service layer uses
/// `public` for the D-Bus `Attributes` property and `secret_names` for the
/// rosec-specific secret attribute discovery method.
#[derive(Debug, Clone)]
pub struct ItemAttributes {
    /// Public attributes safe for D-Bus exposure, logging, and display.
    ///
    /// Includes non-sensitive fields like `name`, `type`, `folder`, `username`,
    /// `uri`, `brand`, `fingerprint`, and `custom.*` text fields.
    pub public: Attributes,

    /// Names of available sensitive attributes for this item.
    ///
    /// Does NOT contain the actual secret values — those are retrieved via
    /// [`VaultBackend::get_secret_attr`].  This list powers the rosec-specific
    /// `GetSecretAttributeNames` D-Bus method.
    pub secret_names: Vec<String>,
}

// ---------------------------------------------------------------------------
// SSH agent types
// ---------------------------------------------------------------------------

/// Public metadata for a single SSH key exposed by a backend.
///
/// Contains no private key material — use [`VaultBackend::get_ssh_private_key`]
/// to retrieve the actual key for signing.
#[derive(Debug, Clone)]
pub struct SshKeyMeta {
    /// Opaque item identifier, passed back to `get_ssh_private_key`.
    pub item_id: String,

    /// Human-readable vault item name.
    pub item_name: String,

    /// Backend that owns this key.
    pub backend_id: String,

    /// OpenSSH wire-format public key (the `authorized_keys` line), if known.
    ///
    /// `None` for PEM keys discovered in text fields — the public key will be
    /// derived from the private key when it is loaded.
    pub public_key_openssh: Option<String>,

    /// SHA-256 fingerprint string (e.g. `"SHA256:abc123…"`), if known.
    pub fingerprint: Option<String>,

    /// `Host` patterns from `custom.ssh_host` / `custom.ssh-host` fields.
    pub ssh_hosts: Vec<String>,

    /// SSH username from `custom.ssh_user` / `custom.ssh-user` field.
    /// Emitted as `User <value>` in generated SSH config snippets.
    pub ssh_user: Option<String>,

    /// Whether to require interactive confirmation before signing.
    /// Set when the vault item has `custom.ssh_confirm = "true"`.
    pub require_confirm: bool,

    /// Last revision timestamp — used for conflict resolution in config.d/.
    pub revision_date: Option<SystemTime>,
}

/// Raw private key material retrieved from a vault backend.
///
/// Contains PEM-encoded private key bytes.  The caller must parse and
/// zeroize the material after use.  Never stored to disk.
pub struct SshPrivateKeyMaterial {
    /// PEM-encoded private key (e.g. `-----BEGIN OPENSSH PRIVATE KEY-----`).
    pub pem: Zeroizing<String>,
}

impl std::fmt::Debug for SshPrivateKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshPrivateKeyMaterial")
            .field("pem", &"[redacted]")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Backend event callbacks
// ---------------------------------------------------------------------------

/// Callback type alias: a cheaply-cloneable, send-safe, zero-argument closure.
pub type CallbackFn = Arc<dyn Fn() + Send + Sync + 'static>;

/// Optional callback fired when a sync completes.
///
/// `changed` is `true` when the sync produced a material change to vault
/// contents (ciphers added, removed, or modified), `false` when the remote
/// was checked but nothing differed.
pub type SyncSucceededFn = Arc<dyn Fn(bool) + Send + Sync + 'static>;

/// Callbacks registered by `rosecd` on each backend after construction.
///
/// All fields are `Option` — backends fire only the callbacks that are set.
/// The default implementation of [`VaultBackend::set_event_callbacks`] is a
/// no-op, so backends that do not yet support the callback system compile and
/// run safely.
#[derive(Clone, Default)]
pub struct BackendCallbacks {
    /// Fired immediately after a successful unlock.
    pub on_unlocked: Option<CallbackFn>,
    /// Fired immediately after a successful lock.
    pub on_locked: Option<CallbackFn>,
    /// Fired after a sync completes successfully.
    ///
    /// `changed` is `true` when the vault contents changed materially
    /// (ciphers added / removed / modified); `false` when the sync ran
    /// but found nothing new.  Callers typically rebuild SSH keys only
    /// when `changed == true`.
    pub on_sync_succeeded: Option<SyncSucceededFn>,
    /// Fired after a sync attempt fails (network error, auth error, etc.).
    pub on_sync_failed: Option<CallbackFn>,
}

impl std::fmt::Debug for BackendCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendCallbacks")
            .field("on_unlocked", &self.on_unlocked.is_some())
            .field("on_locked", &self.on_locked.is_some())
            .field("on_sync_succeeded", &self.on_sync_succeeded.is_some())
            .field("on_sync_failed", &self.on_sync_failed.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------

#[async_trait::async_trait]
pub trait VaultBackend: Send + Sync {
    /// Return `self` as `&dyn std::any::Any` to allow downcasting to concrete types.
    ///
    /// Implementations should return `self` directly:
    /// ```ignore
    /// fn as_any(&self) -> &dyn std::any::Any { self }
    /// ```
    fn as_any(&self) -> &dyn std::any::Any;

    fn id(&self) -> &str;
    fn name(&self) -> &str;

    /// The backend type identifier (e.g. `"bitwarden"`, `"bitwarden-sm"`).
    ///
    /// Used by `rosec backend list` to show what kind of backend each entry is.
    fn kind(&self) -> &str;

    /// Register lifecycle event callbacks on this backend.
    ///
    /// Called once by `rosecd` after construction, before any unlock is
    /// attempted.  Backends store the callbacks and fire them at the
    /// appropriate points:
    ///
    /// - `on_unlocked` — after a successful [`unlock`][VaultBackend::unlock]
    /// - `on_locked`   — after a successful [`lock`][VaultBackend::lock]
    /// - `on_sync_succeeded(changed)` — after a successful [`sync`][VaultBackend::sync];
    ///   `changed` is `true` iff vault contents differ from before the sync
    /// - `on_sync_failed` — after a failed sync attempt
    ///
    /// The default is a no-op.  Backends that do not implement this method
    /// simply ignore all callbacks.
    fn set_event_callbacks(&self, _callbacks: BackendCallbacks) -> Result<(), BackendError> {
        Ok(())
    }

    /// The password / local-key field for this backend.
    ///
    /// The auth flow always prompts this field first, before anything else.
    /// Backends may customise the label and description:
    ///
    /// - Password Manager backends (Bitwarden PM): `"Master Password"` with the
    ///   standard Bitwarden placeholder.
    /// - Token-based backends (Bitwarden SM, future cloud providers): something
    ///   like `"Key encryption password"` with a description explaining it is
    ///   only used locally to protect the stored API token.
    ///
    /// The default is a generic master-password field.
    fn password_field(&self) -> AuthField {
        AuthField {
            id: "password",
            label: "Master Password",
            placeholder: "Enter your master password",
            required: true,
            kind: AuthFieldKind::Password,
        }
    }

    /// Registration information for backends that require device/API-key
    /// registration before the normal password-based unlock can succeed.
    ///
    /// Returns `None` for backends that never require registration (default).
    /// Returns `Some(RegistrationInfo)` for backends where the server may reject
    /// a first-time login from an unrecognised device and require an API key.
    ///
    /// When the auth flow receives `BackendError::RegistrationRequired`, it
    /// calls this method to obtain the instructions and fields to display,
    /// then retries unlock with `UnlockInput::WithRegistration`.
    fn registration_info(&self) -> Option<RegistrationInfo> {
        None
    }

    /// Describe any additional credential fields this backend needs for `unlock`,
    /// beyond the password field returned by `password_field()`.
    ///
    /// The returned slice drives the prompt UI (both the Wayland GUI and the
    /// TTY fallback) and the `rosec auth` CLI subcommand.  Field values are
    /// collected by the caller, assembled into a `HashMap<&str, Zeroizing<String>>`,
    /// and passed back to the backend via `unlock`.
    ///
    /// The default implementation returns an empty slice.
    fn auth_fields(&self) -> &'static [AuthField] {
        &[]
    }

    async fn status(&self) -> Result<BackendStatus, BackendError>;

    /// Authenticate this backend with the supplied credentials.
    ///
    /// `UnlockInput::Password(pw)` is the normal unlock path — the password is
    /// used directly (PM: vault decryption key) or as input to a key derivation
    /// function (SM: derives the storage key used to decrypt the persisted
    /// access token).  The password is **always required** and must be
    /// non-empty.
    ///
    /// `UnlockInput::WithRegistration { password, registration_fields }` is
    /// used when the backend previously returned `BackendError::RegistrationRequired`.
    /// The password serves the same role as above; `registration_fields` carries
    /// the additional credentials needed for first-time setup or token rotation
    /// (e.g. an SM access token, or PM device API key).
    ///
    /// In-memory credentials (decrypted vault keys, access tokens) are held as
    /// `Zeroizing<_>` and scrubbed on lock/drop.  `sync()` operates on these
    /// in-memory credentials and returns `BackendError::Locked` once they are
    /// gone — callers must unlock again before syncing after a lock.
    ///
    /// Returns `BackendError::RegistrationRequired` if the backend needs
    /// first-time setup before the normal password unlock can succeed.
    async fn unlock(&self, input: UnlockInput) -> Result<(), BackendError>;
    async fn lock(&self) -> Result<(), BackendError>;

    /// Pull fresh data from the remote source and update the in-memory vault.
    ///
    /// Returns `Ok(())` on success, `BackendError::Locked` if the backend is
    /// not yet authenticated.  The default returns `BackendError::Locked` so
    /// that backends without a custom sync implementation fail safely rather
    /// than silently succeeding.  Backends with network sync (Bitwarden PM/SM)
    /// override this.
    async fn sync(&self) -> Result<(), BackendError> {
        Err(BackendError::Locked)
    }

    /// Return the UTC timestamp of the last successful sync, or `None` if no
    /// sync has occurred since the backend was constructed.
    fn last_synced_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        None
    }

    /// Check whether the remote source has changed since our last sync.
    ///
    /// Returns `Ok(true)` if a sync is needed, `Ok(false)` if the local copy
    /// is up-to-date, or an error if the check itself failed.  The default
    /// returns `Ok(true)` (always sync), so backends that don't implement a
    /// cheap remote-check still behave correctly — just less efficiently.
    ///
    /// Implementations should use a lightweight API call (e.g.
    /// `GET /accounts/revision-date` for Bitwarden PM,
    /// `GET /organizations/{id}/secrets/sync` for Bitwarden SM).
    async fn check_remote_changed(&self) -> Result<bool, BackendError> {
        Ok(true)
    }

    async fn list_items(&self) -> Result<Vec<VaultItemMeta>, BackendError>;
    async fn get_item(&self, id: &str) -> Result<VaultItem, BackendError>;
    async fn get_secret(&self, id: &str) -> Result<SecretBytes, BackendError>;
    async fn search(&self, attrs: &Attributes) -> Result<Vec<VaultItemMeta>, BackendError>;

    // -----------------------------------------------------------------------
    // Attribute model (new)
    // -----------------------------------------------------------------------

    /// Static catalogue of all attributes this backend can produce.
    ///
    /// Returns a slice of [`AttributeDescriptor`]s describing every field this
    /// backend knows about (both public and sensitive).  The service layer uses
    /// this to validate `return_attr` glob patterns at startup and to power
    /// introspection / CLI help.
    ///
    /// Default: empty (backends that haven't migrated to the attribute model).
    fn available_attributes(&self) -> &'static [AttributeDescriptor] {
        &[]
    }

    /// Get the full attribute set (public metadata + secret attribute names)
    /// for a specific vault item.
    ///
    /// The default implementation falls back to the existing `get_item()` and
    /// uses `meta.attributes` as public, with no secret attributes.  Backends
    /// should override this to populate `secret_names`.
    async fn get_item_attributes(&self, id: &str) -> Result<ItemAttributes, BackendError> {
        let item = self.get_item(id).await?;
        Ok(ItemAttributes {
            public: item.meta.attributes,
            secret_names: Vec::new(),
        })
    }

    /// Retrieve a specific sensitive attribute value by name.
    ///
    /// For example: `get_secret_attr("cipher-uuid", "password")` returns the
    /// login password, `get_secret_attr("cipher-uuid", "totp")` returns the
    /// TOTP seed.
    ///
    /// Returns `BackendError::NotFound` if the attribute doesn't exist on the
    /// item, or `BackendError::NotSupported` if the backend hasn't implemented
    /// the attribute model.
    ///
    /// Default: returns `NotSupported`.
    async fn get_secret_attr(&self, _id: &str, _attr: &str) -> Result<SecretBytes, BackendError> {
        Err(BackendError::NotSupported)
    }

    // -----------------------------------------------------------------------
    // SSH agent interface
    // -----------------------------------------------------------------------

    /// List all SSH keys available from this backend (public metadata only).
    ///
    /// Returns one [`SshKeyMeta`] per discoverable SSH key.  Keys may come
    /// from:
    /// - Native SSH key vault items
    /// - PEM private key material found in notes, passwords, or hidden fields
    ///
    /// Called by the SSH agent layer after each sync and after unlock.  The
    /// default returns an empty list (backend does not expose SSH keys).
    async fn list_ssh_keys(&self) -> Result<Vec<SshKeyMeta>, BackendError> {
        Ok(Vec::new())
    }

    /// Retrieve the private key material for a specific SSH key by item ID.
    ///
    /// `id` matches [`SshKeyMeta::item_id`].  The returned
    /// [`SshPrivateKeyMaterial`] contains the raw PEM bytes — callers are
    /// responsible for parsing and zeroizing after use.
    ///
    /// Returns [`BackendError::NotFound`] if no SSH key exists for that ID,
    /// [`BackendError::Locked`] if the backend is locked, or
    /// [`BackendError::NotSupported`] if the backend never exposes private keys
    /// (default).
    async fn get_ssh_private_key(&self, _id: &str) -> Result<SshPrivateKeyMaterial, BackendError> {
        Err(BackendError::NotSupported)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DedupStrategy {
    Newest,
    Priority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DedupTimeFallback {
    Created,
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutoLockPolicy {
    pub on_logout: bool,
    pub on_session_lock: bool,
    pub idle_timeout_minutes: Option<u64>,
    pub max_unlocked_minutes: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_debug_redacts() {
        let sb = SecretBytes::new(b"hunter2".to_vec());
        let debug = format!("{sb:?}");
        assert_eq!(debug, "SecretBytes([redacted])");
        assert!(!debug.contains("hunter2"));
    }

    #[test]
    fn secret_bytes_clone_preserves_data() {
        let sb = SecretBytes::new(b"hello".to_vec());
        let cloned = sb.clone();
        assert_eq!(cloned.as_slice(), b"hello");
    }

    #[test]
    fn secret_bytes_serialize_fails() {
        let sb = SecretBytes::new(b"secret".to_vec());
        let result = serde_json::to_string(&sb);
        assert!(result.is_err());
    }

    #[test]
    fn secret_bytes_deserialize_fails() {
        let result: Result<SecretBytes, _> = serde_json::from_str("\"data\"");
        assert!(result.is_err());
    }

    #[test]
    fn unlock_input_debug_redacts_password() {
        let input = UnlockInput::Password(Zeroizing::new("secret".to_string()));
        let debug = format!("{input:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn unlock_input_debug_redacts_with_registration() {
        let mut reg_fields = HashMap::new();
        reg_fields.insert(
            "client_id".to_string(),
            Zeroizing::new("user.abc".to_string()),
        );
        reg_fields.insert(
            "client_secret".to_string(),
            Zeroizing::new("s3cr3t".to_string()),
        );
        let input = UnlockInput::WithRegistration {
            password: Zeroizing::new("masterpass".to_string()),
            registration_fields: reg_fields,
        };
        let debug = format!("{input:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("masterpass"));
        assert!(!debug.contains("user.abc"));
        assert!(!debug.contains("s3cr3t"));
    }

    #[test]
    fn unlock_input_debug_redacts_api_key() {
        let input = UnlockInput::ApiKey {
            client_id: "my-client".to_string(),
            client_secret: Zeroizing::new("my-secret".to_string()),
        };
        let debug = format!("{input:?}");
        assert!(debug.contains("my-client"));
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("my-secret"));
    }

    #[test]
    fn unlock_input_debug_redacts_session_token() {
        let input = UnlockInput::SessionToken(Zeroizing::new("tok".to_string()));
        let debug = format!("{input:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("tok"));
    }

    #[test]
    fn unlock_input_debug_redacts_otp() {
        let input = UnlockInput::Otp(Zeroizing::new("123456".to_string()));
        let debug = format!("{input:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("123456"));
    }
}
