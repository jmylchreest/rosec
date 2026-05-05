use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub mod config;
pub mod config_edit;
pub mod credential;
pub mod dedup;
pub mod limits;
pub mod machine_key;
pub mod oauth;
pub mod process;
pub mod prompt;
pub mod router;
pub mod totp;

/// Crate-wide mutex used by tests that mutate `XDG_DATA_HOME`.
///
/// Both `oauth` and `credential` tests call `unsafe { env::set_var(...) }`;
/// using a single process-wide lock prevents races when those tests run in
/// parallel in the same test binary.
#[cfg(test)]
pub(crate) static TEST_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub type Attributes = HashMap<String, String>;

// `id`, `label`, `created`, `modified` are first-class fields on ItemMeta /
// VaultItemData and must not appear as user-supplied attribute keys.
// The `rosec:` namespace mirrors the Secret Service spec's `xdg:schema`
// convention, separating provider/service-stamped attributes from arbitrary
// client-supplied ones.

/// Item identifier (first-class struct field).
pub const ATTR_ID: &str = "id";

/// Item display label (first-class struct field).
pub const ATTR_LABEL: &str = "label";

/// Creation timestamp (first-class struct field).
pub const ATTR_CREATED: &str = "created";

/// Last-modified timestamp (first-class struct field).
pub const ATTR_MODIFIED: &str = "modified";

/// Owning provider. Stamped by the service layer; exposed as a public,
/// searchable attribute.
pub const ATTR_PROVIDER: &str = "rosec:provider";

/// Item type classification (e.g. "login", "note", "ssh-key"). Used by
/// [`ItemType::from_attributes`] to pick the default secret attribute name.
pub const ATTR_TYPE: &str = "rosec:type";

/// Boolean flag stamped by providers when a `"totp"` secret attribute is present.
/// Searchable via `SearchItems({"rosec:totp": "true"})`.
pub const ATTR_TOTP: &str = "rosec:totp";

/// Attribute names rejected from user input — kept in sync with the consts above.
pub const RESERVED_ATTRIBUTES: &[&str] = &[
    ATTR_ID,
    ATTR_LABEL,
    ATTR_CREATED,
    ATTR_MODIFIED,
    ATTR_PROVIDER,
    ATTR_TYPE,
    ATTR_TOTP,
];

/// Declares what optional functionality a provider supports.
///
/// Providers return a static slice from [`Provider::capabilities`].  The service
/// layer and CLI check capabilities before calling optional trait methods.
///
/// Use [`require`] to gate an operation on a capability — it returns
/// `ProviderError::NotSupported` if the provider lacks the required capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Provider can sync with a remote source ([`Provider::sync`]).
    Sync,
    /// Provider supports write operations (create, update, delete items).
    Write,
    /// Provider exposes SSH keys ([`Provider::list_ssh_keys`], [`Provider::get_ssh_private_key`]).
    Ssh,
    /// Supports multiple unlock passwords wrapping the same vault key.
    KeyWrapping,
    /// Provider supports password changes ([`Provider::change_password`]).
    PasswordChange,
    /// Provider supports offline cache export/restore (`export_cache`, `restore_cache`).
    ///
    /// This is the guest-side feature toggle.  Actual caching also requires
    /// the host's per-provider `offline_cache` config to be `true` (default).
    /// See [`ProviderEntry::offline_cache`](crate::config::ProviderEntry::offline_cache).
    OfflineCache,
    /// Provider supports real-time notifications via a host-managed WebSocket.
    ///
    /// The guest implements `get_notification_config` (returns a WebSocket URL +
    /// optional handshake) and `parse_notification` (classifies received frames
    /// as sync, lock, or ignore).  The host manages the connection lifecycle.
    Notifications,
    /// Provider stores TOTP seeds and supports code generation
    /// (items may expose `"totp"` as a secret attribute).
    Totp,
}

/// Check that `provider` declares `cap`; return `ProviderError::NotSupported` if not.
pub fn require(provider: &dyn Provider, cap: Capability) -> Result<(), ProviderError> {
    if provider.capabilities().contains(&cap) {
        Ok(())
    } else {
        Err(ProviderError::NotSupported)
    }
}

/// Item type for determining default secret attribute.
///
/// Used by [`primary_secret`] to return the appropriate secret based on
/// item type when the caller doesn't specify an attribute name.
///
/// Canonical `rosec:type` strings: `"generic"`, `"login"`, `"ssh-key"`,
/// `"note"`, `"card"`, `"identity"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemType {
    /// Generic secret. Default attr: "secret".
    Generic,
    /// Login credential. Default attr: "password".
    Login,
    /// SSH private key. Default attr: "private_key".
    SshKey,
    /// Secure note. Default attr: "secret" (the note body).
    Note,
    /// Payment card. Default attr: "number".
    Card,
    /// Identity / personal information. Default attr: "secret".
    Identity,
}

impl ItemType {
    /// Derive from the `rosec:type` attribute or default to Generic.
    pub fn from_attributes(attrs: &HashMap<String, String>) -> Self {
        match attrs.get(ATTR_TYPE).map(|s| s.as_str()) {
            Some("login") => Self::Login,
            Some("ssh-key" | "sshkey" | "ssh_key") => Self::SshKey,
            Some("note") => Self::Note,
            Some("card") => Self::Card,
            Some("identity") => Self::Identity,
            _ => Self::Generic,
        }
    }

    /// The canonical `rosec:type` attribute value for this type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Login => "login",
            Self::SshKey => "ssh-key",
            Self::Note => "note",
            Self::Card => "card",
            Self::Identity => "identity",
        }
    }

    /// The default secret attribute name for this item type.
    pub fn default_secret_attr(&self) -> &'static str {
        match self {
            Self::Generic | Self::Note | Self::Identity => "secret",
            Self::Login => "password",
            Self::SshKey => "private_key",
            Self::Card => "number",
        }
    }
}

impl std::fmt::Display for ItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ItemType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "generic" => Ok(Self::Generic),
            "login" => Ok(Self::Login),
            "ssh-key" | "sshkey" | "ssh_key" => Ok(Self::SshKey),
            "note" => Ok(Self::Note),
            "card" => Ok(Self::Card),
            "identity" => Ok(Self::Identity),
            _ => Err(format!("unknown item type: {s}")),
        }
    }
}

/// A request to create a new vault item.
#[derive(Debug, Clone)]
pub struct NewItem {
    /// Display label (required, non-empty).
    pub label: String,
    /// Item type hint.
    ///
    /// If `Some`, the provider stamps `rosec:type` on the stored attributes
    /// internally.  Callers must **not** put `rosec:type` in `attributes`
    /// directly — that remains a reserved name rejected by [`validate`].
    pub item_type: Option<ItemType>,
    /// Public, searchable attributes. Reserved names are rejected by validate().
    pub attributes: HashMap<String, String>,
    /// Named secret values. At least one required.
    /// Keys like "secret", "password", "private_key" depending on item type.
    pub secrets: HashMap<String, SecretBytes>,
}

impl NewItem {
    /// Validate the item before creation.
    ///
    /// Returns an error if:
    /// - label is empty
    /// - no secrets provided
    /// - reserved attribute names are used
    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.label.is_empty() {
            return Err(ProviderError::InvalidInput("label cannot be empty".into()));
        }
        if self.secrets.is_empty() {
            return Err(ProviderError::InvalidInput(
                "at least one secret required".into(),
            ));
        }
        for key in RESERVED_ATTRIBUTES {
            if self.attributes.contains_key(*key) {
                return Err(ProviderError::InvalidInput(
                    format!("reserved attribute name: {}", key).into(),
                ));
            }
        }
        Ok(())
    }
}

/// A request to update an existing vault item.
///
/// All fields are optional — only provided values are changed.
#[derive(Debug, Clone, Default)]
pub struct ItemUpdate {
    /// New display label (None = no change).
    pub label: Option<String>,
    /// New item type (None = no change).
    ///
    /// If `Some`, the provider updates the stored `rosec:type` attribute.
    pub item_type: Option<ItemType>,
    /// Replace all public attributes (None = no change).
    /// Reserved names are validated when applied.
    pub attributes: Option<HashMap<String, String>>,
    /// Merge into existing secrets (None = no change).
    /// Only provided keys are updated; others remain untouched.
    pub secrets: Option<HashMap<String, SecretBytes>>,
}

#[derive(Debug, Clone)]
pub struct ProviderStatus {
    pub locked: bool,
    pub last_sync: Option<SystemTime>,
    /// True when in-memory data has not been confirmed against the remote.
    ///
    /// **Set on:** offline unlock (restore_cache path), failed sync
    /// (network dropped, data is stale).
    ///
    /// **Cleared on:** successful online unlock, successful sync.
    ///
    /// **Reset on:** lock (no data at all).
    ///
    /// This is a data-quality signal, not a provenance signal.
    /// Combined with `last_sync`, consumers can assess staleness severity.
    pub cached: bool,
    /// Whether offline caching is active for this provider.
    ///
    /// True only when both conditions are met: the provider declares
    /// `Capability::OfflineCache` (guest feature toggle) *and* the host's
    /// per-provider `offline_cache` config is `true` (default).
    pub offline_cache: bool,
    /// When the cache file was last written to disk.
    pub last_cache_write: Option<SystemTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemMeta {
    pub id: String,
    pub provider_id: String,
    pub label: String,
    pub attributes: Attributes,
    pub created: Option<SystemTime>,
    pub modified: Option<SystemTime>,
    pub locked: bool,
}

impl ItemMeta {
    /// Build cache-ready metadata from a newly created item.
    ///
    /// Stamps `rosec:provider` and (if present) `rosec:type` into the
    /// attributes — these reserved attributes are managed by the service
    /// layer, not supplied by callers.
    pub fn from_new_item(id: String, provider_id: String, item: &NewItem) -> Self {
        let mut attributes = item.attributes.clone();
        attributes
            .entry(ATTR_PROVIDER.to_string())
            .or_insert_with(|| provider_id.clone());
        if let Some(ref item_type) = item.item_type {
            attributes.insert(ATTR_TYPE.to_string(), item_type.to_string());
        }
        let now = Some(SystemTime::now());
        Self {
            id,
            provider_id,
            label: item.label.clone(),
            attributes,
            created: now,
            modified: now,
            locked: false,
        }
    }
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

/// The kind of input a provider field expects.
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

impl std::fmt::Display for AuthFieldKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Text => "text",
            Self::Password => "password",
            Self::Secret => "secret",
        })
    }
}

/// Describes a single credential field that a provider needs for `unlock`.
///
/// Providers return a static slice of `AuthField` from `auth_fields()`.  The
/// daemon's prompt subprocess and the `rosec auth` CLI subcommand use this list
/// to build provider-agnostic input forms.
#[derive(Debug, Clone, Copy)]
pub struct AuthField {
    /// Machine-readable identifier — used as the key in the field map passed
    /// back to `unlock`.  Must be unique within a provider's field list.
    pub id: &'static str,
    /// Human-readable label shown next to the input widget.
    pub label: &'static str,
    /// Short placeholder / example shown inside the input box.
    pub placeholder: &'static str,
    /// Whether the field must be non-empty before unlock is attempted.
    pub required: bool,
    pub kind: AuthFieldKind,
}

/// Information returned by a provider when device/API-key registration is required.
///
/// The auth flow displays `instructions` to the user before prompting for the
/// `fields`.  Both are provider-defined so the copy is accurate and actionable.
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

/// Describes a single two-factor authentication method available for a
/// provider.
///
/// This is a core type used by the service layer to prompt users and relay
/// 2FA credentials back to providers.  Providers return these as part of
/// `ProviderError::TwoFactorRequired`.
#[derive(Debug, Clone)]
pub struct TwoFactorMethod {
    /// Opaque method identifier — sent back to the provider in `auth_fields`
    /// so it can map back to its internal 2FA provider code.
    pub id: String,
    /// Human-readable label shown to the user (e.g. "Authenticator app (TOTP)").
    pub label: String,
    /// How the host should collect the credential:
    /// - `"text"` — prompt for a text string (TOTP, email code, YubiKey OTP, passcode).
    /// - `"fido2"` — perform a FIDO2/WebAuthn ceremony (deferred — not yet implemented).
    /// - `"browser_redirect"` — open a URL and wait for callback (deferred).
    pub prompt_kind: String,
    /// Optional challenge data for host-mediated methods (e.g. WebAuthn
    /// challenge JSON).  Unused for text-prompt methods.
    pub challenge: Option<String>,
}

/// Credentials passed to [`Provider::unlock`].
///
/// This enum intentionally does NOT derive `Serialize` or `Deserialize`.
/// Credentials (master passwords, session tokens, OTPs) must never be
/// accidentally written to logs, D-Bus responses, or disk.
#[derive(Clone)]
pub enum UnlockInput {
    /// Standard password-only unlock (master password for PM providers, or a
    /// locally-derived key for token-based providers that use local encryption).
    Password(Zeroizing<String>),
    /// Password + registration credentials, supplied when the provider previously
    /// returned `ProviderError::RegistrationRequired`.
    ///
    /// The provider uses `password` to derive the local storage key (to encrypt
    /// the registration credentials at rest), then performs device registration,
    /// then retries its normal unlock flow.
    WithRegistration {
        password: Zeroizing<String>,
        /// Field values keyed by the `AuthField::id` strings from
        /// `RegistrationInfo::fields`.
        registration_fields: HashMap<String, Zeroizing<String>>,
    },
    /// Password + ephemeral auth fields (e.g. a 2FA token), supplied when the
    /// provider previously returned `ProviderError::TwoFactorRequired`.
    ///
    /// Unlike registration fields, auth fields are not persisted — they are
    /// valid only for the current unlock attempt.
    WithAuth {
        password: Zeroizing<String>,
        /// Ephemeral credential fields keyed by provider-defined identifiers
        /// (e.g. `"__2fa_method_id"` and `"__2fa_token"`).
        auth_fields: HashMap<String, Zeroizing<String>>,
    },
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
            Self::WithAuth { .. } => f
                .debug_struct("WithAuth")
                .field("password", &"[redacted]")
                .field("auth_fields", &"[redacted]")
                .finish(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ProviderError {
    #[error("provider locked")]
    Locked,
    #[error("item not found")]
    NotFound,
    #[error("not supported")]
    NotSupported,
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    /// An item with the same attributes already exists (for create with replace=false).
    #[error("item already exists")]
    AlreadyExists,
    /// Invalid input (validation failed).
    #[error("invalid input: {0}")]
    InvalidInput(Box<str>),
    /// The provider requires device/API-key registration before it can unlock.
    ///
    /// The auth flow should prompt for `RegistrationInfo::fields` (obtained via
    /// `Provider::registration_info()`) and retry with
    /// `UnlockInput::WithRegistration`.
    #[error("registration required")]
    RegistrationRequired,
    /// The password (or passphrase) was incorrect.
    ///
    /// Unlike `RegistrationRequired`, this means the provider *has* stored
    /// credentials but the provided password produced a wrong decryption key.
    /// The auth flow should re-prompt for the password rather than asking the
    /// user to re-register.
    #[error("authentication failed")]
    AuthFailed,
    /// The provider requires two-factor authentication to proceed.
    ///
    /// The `methods` list describes the available 2FA methods the user may
    /// choose from.  The auth flow should present these to the user, collect
    /// the credential, and retry with `UnlockInput::WithAuth`.
    #[error("two-factor authentication required")]
    TwoFactorRequired {
        /// Available 2FA methods the provider supports for this account.
        methods: Vec<TwoFactorMethod>,
    },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Describes a single attribute that a provider can produce for items.
///
/// Providers return a static slice of these from [`Provider::available_attributes`]
/// so the service layer can validate config and support introspection.
#[derive(Debug, Clone)]
pub struct AttributeDescriptor {
    /// Machine-readable attribute name (e.g. `"password"`, `"totp"`, `"number"`).
    ///
    /// Uses the flat, unprefixed naming convention.  Custom fields from the
    /// source are exposed with a `"custom."` prefix to avoid collisions.
    pub name: &'static str,

    /// `true` if the attribute value is sensitive (passwords, TOTP seeds, card
    /// numbers, private keys, PII).  Sensitive attributes are never exposed in
    /// the D-Bus `Attributes` property — only their *names* are discoverable
    /// via a rosec-specific D-Bus method, and their *values* are retrieved via
    /// [`Provider::get_secret_attr`].
    pub sensitive: bool,

    /// Which item types this attribute applies to (e.g. `["login"]`, `["card"]`,
    /// `["login", "identity"]`).  An empty slice means the attribute is common
    /// to all item types (e.g. `"notes"`, `"name"`).
    pub item_types: &'static [&'static str],

    /// Human-readable description for documentation and CLI help.
    pub description: &'static str,
}

/// The full attribute set for a single item, split into public metadata
/// and the names of available sensitive (secret) attributes.
///
/// Produced by [`Provider::get_item_attributes`].  The service layer uses
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
    /// [`Provider::get_secret_attr`].  This list powers the rosec-specific
    /// `GetSecretAttributeNames` D-Bus method.
    pub secret_names: Vec<String>,
}

/// Public metadata for a single SSH key exposed by a provider.
///
/// Contains no private key material — use [`Provider::get_ssh_private_key`]
/// to retrieve the actual key for signing.
#[derive(Debug, Clone)]
pub struct SshKeyMeta {
    /// Opaque item identifier, passed back to `get_ssh_private_key`.
    pub item_id: String,

    /// Human-readable vault item name.
    pub item_name: String,

    /// Provider that owns this key.
    pub provider_id: String,

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

/// Raw private key material retrieved from a provider.
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

/// Cheaply-cloneable zero-argument event callback.
pub type CallbackFn = Arc<dyn Fn() + Send + Sync + 'static>;

/// Optional callback fired when a sync completes.
///
/// `changed` is `true` when the sync produced a material change to vault
/// contents (ciphers added, removed, or modified), `false` when the remote
/// was checked but nothing differed.
pub type SyncSucceededFn = Arc<dyn Fn(bool) + Send + Sync + 'static>;

/// Callbacks registered by `rosecd` on each provider after construction.
///
/// All fields are `Option` — providers fire only the callbacks that are set.
/// The default implementation of [`Provider::set_event_callbacks`] is a
/// no-op, so providers that do not yet support the callback system compile and
/// run safely.
#[derive(Clone, Default)]
pub struct ProviderCallbacks {
    /// Fired immediately after a successful unlock.
    pub on_unlocked: Option<CallbackFn>,
    /// Fired immediately after a successful lock.
    pub on_locked: Option<CallbackFn>,
    /// Fired after a sync completes successfully.
    ///
    /// `changed` is `true` when the contents changed materially
    /// (items added / removed / modified); `false` when the sync ran
    /// but found nothing new.  Callers typically rebuild SSH keys only
    /// when `changed == true`.
    pub on_sync_succeeded: Option<SyncSucceededFn>,
    /// Fired after a sync attempt fails (network error, auth error, etc.).
    pub on_sync_failed: Option<CallbackFn>,
    /// Nudge from the remote that a sync should happen (e.g. SignalR notification).
    ///
    /// Replaces the previous `as_any()` downcast pattern — providers that receive
    /// remote push notifications store this callback and invoke it when the remote
    /// signals that data has changed.  The daemon's handler then triggers a sync.
    pub on_remote_sync_nudge: Option<CallbackFn>,
    /// Nudge from the remote that the vault should be locked (e.g. SignalR logout).
    ///
    /// Same pattern as `on_remote_sync_nudge` — providers invoke this when the
    /// remote signals that the session should be terminated.
    pub on_remote_lock_nudge: Option<CallbackFn>,
}

impl std::fmt::Debug for ProviderCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderCallbacks")
            .field("on_unlocked", &self.on_unlocked.is_some())
            .field("on_locked", &self.on_locked.is_some())
            .field("on_sync_succeeded", &self.on_sync_succeeded.is_some())
            .field("on_sync_failed", &self.on_sync_failed.is_some())
            .field("on_remote_sync_nudge", &self.on_remote_sync_nudge.is_some())
            .field("on_remote_lock_nudge", &self.on_remote_lock_nudge.is_some())
            .finish()
    }
}

#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;

    /// The provider type identifier (e.g. `"bitwarden-pm"`, `"bitwarden-sm"`, `"local"`).
    ///
    /// Used by `rosec provider list` to show what kind of provider each entry is.
    fn kind(&self) -> &str;

    /// Declare what optional functionality this provider supports.
    ///
    /// The service layer and CLI check this before calling optional trait methods.
    /// Use [`require`] to gate an operation: it returns `ProviderError::NotSupported`
    /// if the provider lacks the required capability.
    ///
    /// Default: empty (no optional capabilities).
    fn capabilities(&self) -> &'static [Capability] {
        &[]
    }

    /// Register lifecycle event callbacks on this provider.
    ///
    /// Called once by `rosecd` after construction, before any unlock is
    /// attempted.  Providers store the callbacks and fire them at the
    /// appropriate points:
    ///
    /// - `on_unlocked` — after a successful [`unlock`][Provider::unlock]
    /// - `on_locked`   — after a successful [`lock`][Provider::lock]
    /// - `on_sync_succeeded(changed)` — after a successful [`sync`][Provider::sync];
    ///   `changed` is `true` iff contents differ from before the sync
    /// - `on_sync_failed` — after a failed sync attempt
    /// - `on_remote_sync_nudge` — stored and invoked when a remote push
    ///   notification signals that data has changed (e.g. SignalR)
    /// - `on_remote_lock_nudge` — invoked when the remote signals session
    ///   termination
    ///
    /// The default is a no-op.  Providers that do not implement this method
    /// simply ignore all callbacks.
    fn set_event_callbacks(&self, _callbacks: ProviderCallbacks) -> Result<(), ProviderError> {
        Ok(())
    }

    /// The password / local-key field for this provider.
    ///
    /// The auth flow always prompts this field first, before anything else.
    /// Providers may customise the label and description:
    ///
    /// - Password Manager providers (Bitwarden PM): `"Master Password"` with the
    ///   standard Bitwarden placeholder.
    /// - Token-based providers (Bitwarden SM, future cloud providers): something
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

    /// Registration information for providers that require device/API-key
    /// registration before the normal password-based unlock can succeed.
    ///
    /// Returns `None` for providers that never require registration (default).
    /// Returns `Some(RegistrationInfo)` for providers where the server may reject
    /// a first-time login from an unrecognised device and require an API key.
    ///
    /// When the auth flow receives `ProviderError::RegistrationRequired`, it
    /// calls this method to obtain the instructions and fields to display,
    /// then retries unlock with `UnlockInput::WithRegistration`.
    fn registration_info(&self) -> Option<RegistrationInfo> {
        None
    }

    /// Describe any additional credential fields this provider needs for `unlock`,
    /// beyond the password field returned by `password_field()`.
    ///
    /// The returned slice drives the prompt UI (both the Wayland GUI and the
    /// TTY fallback) and the `rosec auth` CLI subcommand.  Field values are
    /// collected by the caller, assembled into a `HashMap<&str, Zeroizing<String>>`,
    /// and passed back to the provider via `unlock`.
    ///
    /// The default implementation returns an empty slice.
    fn auth_fields(&self) -> &'static [AuthField] {
        &[]
    }

    /// Returns `true` if the user's password must be confirmed (typed twice)
    /// before the first unlock attempt.
    ///
    /// This is used by providers that create new persistent state on first
    /// unlock (e.g. a local vault whose file does not yet exist).  Because
    /// nothing has been stored yet, a typo in the password cannot be detected
    /// after the fact — so the daemon asks the user to enter it twice before
    /// proceeding.
    ///
    /// Providers that already have stored credentials (Bitwarden, SM) return
    /// `false` — the password is verified implicitly when decryption succeeds.
    fn needs_new_password_confirmation(&self) -> bool {
        false
    }

    async fn status(&self) -> Result<ProviderStatus, ProviderError>;

    /// Authenticate this provider with the supplied credentials.
    ///
    /// `UnlockInput::Password(pw)` is the normal unlock path — the password is
    /// used directly (PM: vault decryption key) or as input to a key derivation
    /// function (SM: derives the storage key used to decrypt the persisted
    /// access token).  The password is **always required** and must be
    /// non-empty.
    ///
    /// `UnlockInput::WithRegistration { password, registration_fields }` is
    /// used when the provider previously returned `ProviderError::RegistrationRequired`.
    /// The password serves the same role as above; `registration_fields` carries
    /// the additional credentials needed for first-time setup or token rotation
    /// (e.g. an SM access token, or PM device API key).
    ///
    /// In-memory credentials (decrypted vault keys, access tokens) are held as
    /// `Zeroizing<_>` and scrubbed on lock/drop.  `sync()` operates on these
    /// in-memory credentials and returns `ProviderError::Locked` once they are
    /// gone — callers must unlock again before syncing after a lock.
    ///
    /// Returns `ProviderError::RegistrationRequired` if the provider needs
    /// first-time setup before the normal password unlock can succeed.
    async fn unlock(&self, input: UnlockInput) -> Result<(), ProviderError>;
    async fn lock(&self) -> Result<(), ProviderError>;

    /// Maximum time the parallel unlock flow should wait for this provider's
    /// `unlock` call (including readiness probes) to complete.
    ///
    /// If the provider does not complete within this duration, the attempt is
    /// cancelled and reported as a timeout without blocking other providers.
    ///
    /// Default: 30 seconds.
    fn unlock_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    /// Change the unlock password for this provider.
    ///
    /// Semantics vary by provider type:
    ///
    /// - **Local vault**: finds the wrapping entry that `old_password` unlocks,
    ///   adds a new wrapping entry for `new_password`, then removes the old one.
    ///   The vault key itself is unchanged — only the key-wrapping layer is
    ///   rotated.  The vault must be unlocked.
    ///
    /// - **SM provider**: decrypts the stored access token with the old-password-
    ///   derived storage key, re-encrypts it with the new-password-derived key,
    ///   and persists the result.  The provider must be unlocked (so the access
    ///   token is available in memory for verification).
    ///
    /// Returns `ProviderError::AuthFailed` if `old_password` is incorrect.
    /// Returns `ProviderError::NotSupported` for providers that do not support
    /// password changes (the default).
    ///
    /// # Security
    ///
    /// Both passwords are held in `Zeroizing<String>` and scrubbed on drop.
    /// Implementations must not persist `old_password` or `new_password` in
    /// plaintext at any point.
    async fn change_password(
        &self,
        _old_password: Zeroizing<String>,
        _new_password: Zeroizing<String>,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::NotSupported)
    }

    /// Pull fresh data from the remote source and update the in-memory store.
    ///
    /// Gated behind [`Capability::Sync`].  Returns `Ok(())` on success,
    /// `ProviderError::Locked` if the provider is not yet authenticated.
    /// The default returns `ProviderError::NotSupported` — providers with
    /// network sync (Bitwarden PM/SM) override this.
    async fn sync(&self) -> Result<(), ProviderError> {
        Err(ProviderError::NotSupported)
    }

    /// Return the UTC timestamp of the last successful sync, or `None` if no
    /// sync has occurred since the provider was constructed.
    fn last_synced_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        None
    }

    /// Check whether the remote source has changed since our last sync.
    ///
    /// Returns `Ok(true)` if a sync is needed, `Ok(false)` if the local copy
    /// is up-to-date, or an error if the check itself failed.  The default
    /// returns `Ok(true)` (always sync), so providers that don't implement a
    /// cheap remote-check still behave correctly — just less efficiently.
    ///
    /// Implementations should use a lightweight API call (e.g.
    /// `GET /accounts/revision-date` for Bitwarden PM,
    /// `GET /organizations/{id}/secrets/sync` for Bitwarden SM).
    async fn check_remote_changed(&self) -> Result<bool, ProviderError> {
        Ok(true)
    }

    async fn list_items(&self) -> Result<Vec<ItemMeta>, ProviderError>;
    async fn search(&self, attrs: &Attributes) -> Result<Vec<ItemMeta>, ProviderError>;

    /// Static catalogue of all attributes this provider can produce.
    ///
    /// Returns a slice of [`AttributeDescriptor`]s describing every field this
    /// provider knows about (both public and sensitive).  The service layer uses
    /// this to validate `return_attr` glob patterns at startup and to power
    /// introspection / CLI help.
    ///
    /// Default: empty (providers that haven't migrated to the attribute model).
    fn available_attributes(&self) -> &'static [AttributeDescriptor] {
        &[]
    }

    /// Declare which item types this provider can create.
    ///
    /// Returns the [`ItemType`] values this provider supports for
    /// [`create_item`][Provider::create_item].  An empty slice means the
    /// provider either doesn't support writes or accepts any type.
    ///
    /// Used by the CLI to generate templates and validate user input.
    fn supported_item_types(&self) -> &'static [ItemType] {
        &[]
    }

    /// Get the full attribute set (public metadata + secret attribute names)
    /// for a specific item.
    ///
    /// All providers must implement this — there is no default.
    async fn get_item_attributes(&self, id: &str) -> Result<ItemAttributes, ProviderError>;

    /// Retrieve a specific sensitive attribute value by name.
    ///
    /// For example: `get_secret_attr("cipher-uuid", "password")` returns the
    /// login password, `get_secret_attr("cipher-uuid", "totp")` returns the
    /// TOTP seed.
    ///
    /// Returns `ProviderError::NotFound` if the attribute doesn't exist on the
    /// item.
    ///
    /// All providers must implement this — there is no default.
    async fn get_secret_attr(&self, id: &str, attr: &str) -> Result<SecretBytes, ProviderError>;

    /// List all SSH keys available from this provider (public metadata only).
    ///
    /// Gated behind [`Capability::Ssh`].  Returns one [`SshKeyMeta`] per
    /// discoverable SSH key.  Keys may come from:
    /// - Native SSH key items
    /// - PEM private key material found in notes, passwords, or hidden fields
    ///
    /// Called by the SSH agent layer after each sync and after unlock.  The
    /// default returns an empty list (provider does not expose SSH keys).
    async fn list_ssh_keys(&self) -> Result<Vec<SshKeyMeta>, ProviderError> {
        Ok(Vec::new())
    }

    /// Retrieve the private key material for a specific SSH key by item ID.
    ///
    /// `id` matches [`SshKeyMeta::item_id`].  The returned
    /// [`SshPrivateKeyMaterial`] contains the raw PEM bytes — callers are
    /// responsible for parsing and zeroizing after use.
    ///
    /// Returns [`ProviderError::NotFound`] if no SSH key exists for that ID,
    /// [`ProviderError::Locked`] if the provider is locked, or
    /// [`ProviderError::NotSupported`] if the provider never exposes private keys
    /// (default).
    async fn get_ssh_private_key(&self, _id: &str) -> Result<SshPrivateKeyMaterial, ProviderError> {
        Err(ProviderError::NotSupported)
    }
    // Write operations (gated behind Capability::Write)

    /// Create a new item in this provider.
    ///
    /// # Arguments
    /// * `item` - The item to create (label, attributes, secrets)
    /// * `replace` - If true and an item with matching attributes exists,
    ///   update it instead of creating a new one
    ///
    /// # Returns
    /// * `Ok(id)` - The ID of the created or updated item
    /// * `Err(ProviderError::AlreadyExists)` - Item exists and replace=false
    /// * `Err(ProviderError::InvalidInput)` - Validation failed
    /// * `Err(ProviderError::NotSupported)` - Provider is read-only
    /// * `Err(ProviderError::Locked)` - Provider is locked
    ///
    /// Attribute matching for replace uses all provided attributes (case-sensitive
    /// string equality per Secret Service spec).
    async fn create_item(&self, _item: NewItem, _replace: bool) -> Result<String, ProviderError> {
        Err(ProviderError::NotSupported)
    }

    /// Update an existing item.
    ///
    /// - `label`: replace label if Some
    /// - `attributes`: replace all attributes if Some (validated for reserved names)
    /// - `secrets`: merge into existing secrets if Some (only provided keys change)
    ///
    /// # Returns
    /// * `Err(ProviderError::NotFound)` - Item doesn't exist
    /// * `Err(ProviderError::InvalidInput)` - Reserved attribute name used
    /// * `Err(ProviderError::NotSupported)` - Provider is read-only
    /// * `Err(ProviderError::Locked)` - Provider is locked
    async fn update_item(&self, _id: &str, _update: ItemUpdate) -> Result<(), ProviderError> {
        Err(ProviderError::NotSupported)
    }

    /// Delete an item by ID.
    ///
    /// # Returns
    /// * `Err(ProviderError::NotFound)` - Item doesn't exist
    /// * `Err(ProviderError::NotSupported)` - Provider is read-only
    /// * `Err(ProviderError::Locked)` - Provider is locked
    async fn delete_item(&self, _id: &str) -> Result<(), ProviderError> {
        Err(ProviderError::NotSupported)
    }
    // Key-wrapping / password management (gated behind Capability::KeyWrapping)

    /// Add a password (wrapping entry) to this vault.
    ///
    /// The vault must be unlocked.  The new password wraps the same vault key
    /// that the existing entries protect.
    ///
    /// Returns the wrapping entry ID on success.
    /// Default: `NotSupported` (providers without key wrapping).
    async fn add_password(
        &self,
        _password: &[u8],
        _label: String,
    ) -> Result<String, ProviderError> {
        Err(ProviderError::NotSupported)
    }

    /// Remove a password (wrapping entry) from this vault by entry ID.
    ///
    /// The vault must be unlocked and must have at least 2 wrapping entries
    /// (the last entry cannot be removed).
    ///
    /// Default: `NotSupported`.
    async fn remove_password(&self, _entry_id: &str) -> Result<(), ProviderError> {
        Err(ProviderError::NotSupported)
    }

    /// List all wrapping entries (passwords) for this vault.
    ///
    /// Returns `Vec<(entry_id, Option<label>)>`.  The vault must be unlocked.
    ///
    /// Default: `NotSupported`.
    async fn list_passwords(&self) -> Result<Vec<(String, Option<String>)>, ProviderError> {
        Err(ProviderError::NotSupported)
    }
}

/// Get the primary secret for an item using type-aware default attribute.
///
/// Dispatches to `provider.get_secret_attr(id, type.default_secret_attr())` based
/// on the item's public attributes:
/// - `generic` (or unset) → `"secret"`
/// - `login` → `"password"`
/// - `ssh-key` → `"private_key"`
///
/// This replaces the former `get_primary_secret` method on the trait.
pub async fn primary_secret(
    provider: &dyn Provider,
    id: &str,
) -> Result<SecretBytes, ProviderError> {
    let attrs = provider.get_item_attributes(id).await?;
    let item_type = ItemType::from_attributes(&attrs.public);
    provider
        .get_secret_attr(id, item_type.default_secret_attr())
        .await
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

/// Controls which copy of a WASM provider is preferred when the same kind
/// is found in both the system and user provider directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WasmPreference {
    /// User-local copy always wins (default).
    #[default]
    User,
    /// System copy always wins.
    System,
    /// Pick the copy with the higher semver `version` field in its manifest.
    /// Ties or missing versions fall back to user-local.
    Newest,
}

/// Controls signature verification of WASM provider plugins before probing.
///
/// A `.wasm.sig` file (minisign format, ed25519) is expected alongside the
/// `.wasm` file.  The public key is baked into the `rosec-wasm` crate at
/// build time from the CI signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WasmVerify {
    /// Signature is required.  Plugins without a valid `.wasm.sig` are
    /// rejected and never loaded.
    #[default]
    #[serde(alias = "if-present")]
    Required,
    /// Signature verification is disabled.  All plugins are loaded regardless.
    /// Only use for local development builds.
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoLockPolicy {
    pub on_logout: bool,
    pub on_session_lock: bool,
    pub idle_timeout_minutes: Option<u64>,
    pub max_unlocked_minutes: Option<u64>,
}

/// Per-provider autolock overrides.
///
/// All fields are optional — `None` means "inherit from the global `[autolock]`
/// section".  Only explicitly set fields override the global defaults.
///
/// For timeout fields, `Some(0)` explicitly disables the timeout (equivalent
/// to the global `None`), and `Some(N)` sets a timeout of N minutes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AutoLockOverride {
    pub on_logout: Option<bool>,
    pub on_session_lock: Option<bool>,
    pub idle_timeout_minutes: Option<u64>,
    pub max_unlocked_minutes: Option<u64>,
}

impl AutoLockPolicy {
    /// Produce an effective policy by layering per-provider overrides on top of
    /// the global policy.  Fields present in `overrides` replace the
    /// corresponding global field; `None` fields inherit from `self`.
    ///
    /// For timeout fields in the override, `Some(0)` maps to `None` (disabled)
    /// in the resulting policy, matching the "0 means disabled" convention.
    pub fn merge(&self, overrides: &AutoLockOverride) -> Self {
        Self {
            on_logout: overrides.on_logout.unwrap_or(self.on_logout),
            on_session_lock: overrides.on_session_lock.unwrap_or(self.on_session_lock),
            idle_timeout_minutes: match overrides.idle_timeout_minutes {
                Some(0) => None,
                Some(n) => Some(n),
                None => self.idle_timeout_minutes,
            },
            max_unlocked_minutes: match overrides.max_unlocked_minutes {
                Some(0) => None,
                Some(n) => Some(n),
                None => self.max_unlocked_minutes,
            },
        }
    }
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
    fn autolock_merge_inherits_when_no_overrides() {
        let global = AutoLockPolicy {
            on_logout: true,
            on_session_lock: false,
            idle_timeout_minutes: Some(15),
            max_unlocked_minutes: Some(240),
        };
        let overrides = AutoLockOverride::default();
        let merged = global.merge(&overrides);
        assert_eq!(merged, global);
    }

    #[test]
    fn autolock_merge_overrides_booleans() {
        let global = AutoLockPolicy {
            on_logout: true,
            on_session_lock: false,
            idle_timeout_minutes: None,
            max_unlocked_minutes: None,
        };
        let overrides = AutoLockOverride {
            on_logout: Some(false),
            on_session_lock: Some(true),
            ..Default::default()
        };
        let merged = global.merge(&overrides);
        assert!(!merged.on_logout);
        assert!(merged.on_session_lock);
        assert!(merged.idle_timeout_minutes.is_none());
        assert!(merged.max_unlocked_minutes.is_none());
    }

    #[test]
    fn autolock_merge_overrides_timeouts() {
        let global = AutoLockPolicy {
            on_logout: true,
            on_session_lock: false,
            idle_timeout_minutes: Some(15),
            max_unlocked_minutes: Some(240),
        };
        let overrides = AutoLockOverride {
            idle_timeout_minutes: Some(30),
            max_unlocked_minutes: Some(480),
            ..Default::default()
        };
        let merged = global.merge(&overrides);
        assert_eq!(merged.idle_timeout_minutes, Some(30));
        assert_eq!(merged.max_unlocked_minutes, Some(480));
    }

    #[test]
    fn autolock_merge_zero_disables_timeout() {
        let global = AutoLockPolicy {
            on_logout: true,
            on_session_lock: false,
            idle_timeout_minutes: Some(15),
            max_unlocked_minutes: Some(240),
        };
        let overrides = AutoLockOverride {
            idle_timeout_minutes: Some(0),
            max_unlocked_minutes: Some(0),
            ..Default::default()
        };
        let merged = global.merge(&overrides);
        assert!(merged.idle_timeout_minutes.is_none());
        assert!(merged.max_unlocked_minutes.is_none());
    }

    #[test]
    fn autolock_merge_partial_override() {
        let global = AutoLockPolicy {
            on_logout: true,
            on_session_lock: false,
            idle_timeout_minutes: Some(15),
            max_unlocked_minutes: Some(240),
        };
        // Only override idle_timeout, everything else inherits
        let overrides = AutoLockOverride {
            idle_timeout_minutes: Some(60),
            ..Default::default()
        };
        let merged = global.merge(&overrides);
        assert!(merged.on_logout);
        assert!(!merged.on_session_lock);
        assert_eq!(merged.idle_timeout_minutes, Some(60));
        assert_eq!(merged.max_unlocked_minutes, Some(240));
    }

    // Capability / require tests

    /// Minimal test provider for capability checks.
    struct TestProvider {
        caps: &'static [Capability],
    }

    #[async_trait::async_trait]
    impl Provider for TestProvider {
        fn id(&self) -> &str {
            "test"
        }
        fn name(&self) -> &str {
            "Test"
        }
        fn kind(&self) -> &str {
            "test"
        }
        fn capabilities(&self) -> &'static [Capability] {
            self.caps
        }
        async fn status(&self) -> Result<ProviderStatus, ProviderError> {
            Ok(ProviderStatus {
                locked: true,
                last_sync: None,
                cached: false,
                offline_cache: false,
                last_cache_write: None,
            })
        }
        async fn unlock(&self, _input: UnlockInput) -> Result<(), ProviderError> {
            Err(ProviderError::NotSupported)
        }
        async fn lock(&self) -> Result<(), ProviderError> {
            Ok(())
        }
        async fn list_items(&self) -> Result<Vec<ItemMeta>, ProviderError> {
            Ok(Vec::new())
        }
        async fn search(&self, _attrs: &Attributes) -> Result<Vec<ItemMeta>, ProviderError> {
            Ok(Vec::new())
        }
        async fn get_item_attributes(&self, _id: &str) -> Result<ItemAttributes, ProviderError> {
            Err(ProviderError::NotFound)
        }
        async fn get_secret_attr(
            &self,
            _id: &str,
            _attr: &str,
        ) -> Result<SecretBytes, ProviderError> {
            Err(ProviderError::NotFound)
        }
    }

    #[test]
    fn require_succeeds_for_declared_capability() {
        let p = TestProvider {
            caps: &[Capability::Write, Capability::Ssh],
        };
        assert!(require(&p, Capability::Write).is_ok());
        assert!(require(&p, Capability::Ssh).is_ok());
    }

    #[test]
    fn require_fails_for_missing_capability() {
        let p = TestProvider { caps: &[] };
        let err = require(&p, Capability::Sync).unwrap_err();
        assert!(matches!(err, ProviderError::NotSupported));
    }
}
