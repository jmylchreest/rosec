//! VaultBackend implementation for Bitwarden.

use std::sync::Arc;
use std::time::SystemTime;

use rosec_core::{
    AttributeDescriptor, Attributes, AuthField, AuthFieldKind, BackendCallbacks, BackendError,
    BackendStatus, ItemAttributes, RegistrationInfo, SecretBytes, SshKeyMeta,
    SshPrivateKeyMaterial, UnlockInput, VaultBackend, VaultItem, VaultItemMeta,
};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::api::{ApiClient, ServerUrls, TwoFactorSubmission};
use crate::crypto;
use crate::error::BitwardenError;
use crate::notifications::{self, NotificationsConfig};
use crate::oauth_cred;
use crate::vault::{CipherType, DecryptedCipher, DecryptedField, VaultState};

// ---------------------------------------------------------------------------
// Attribute catalogue
// ---------------------------------------------------------------------------

/// Static catalogue of all attributes the Bitwarden backend can produce.
///
/// Each entry documents whether the attribute is sensitive and which item
/// types it applies to.  The service layer uses this for `return_attr` glob
/// validation and for CLI/D-Bus introspection.
static BITWARDEN_ATTRIBUTES: &[AttributeDescriptor] = &[
    // -- Common (all item types) --
    AttributeDescriptor {
        name: "name",
        sensitive: false,
        item_types: &[],
        description: "Item display name",
    },
    AttributeDescriptor {
        name: "type",
        sensitive: false,
        item_types: &[],
        description: "Item type (login, note, card, identity, sshkey)",
    },
    AttributeDescriptor {
        name: "folder",
        sensitive: false,
        item_types: &[],
        description: "Folder name (if assigned)",
    },
    AttributeDescriptor {
        name: "notes",
        sensitive: true,
        item_types: &[],
        description: "Free-form notes (always sensitive)",
    },
    // -- Login --
    AttributeDescriptor {
        name: "username",
        sensitive: false,
        item_types: &["login"],
        description: "Login username (public per attribute-model decision)",
    },
    AttributeDescriptor {
        name: "password",
        sensitive: true,
        item_types: &["login"],
        description: "Login password",
    },
    AttributeDescriptor {
        name: "totp",
        sensitive: true,
        item_types: &["login"],
        description: "TOTP seed / otpauth URI",
    },
    AttributeDescriptor {
        name: "uri",
        sensitive: false,
        item_types: &["login"],
        description: "Primary login URI",
    },
    // -- Card --
    AttributeDescriptor {
        name: "cardholder",
        sensitive: true,
        item_types: &["card"],
        description: "Cardholder name (PII)",
    },
    AttributeDescriptor {
        name: "number",
        sensitive: true,
        item_types: &["card"],
        description: "Card number",
    },
    AttributeDescriptor {
        name: "brand",
        sensitive: false,
        item_types: &["card"],
        description: "Card brand (Visa, Mastercard, etc.)",
    },
    AttributeDescriptor {
        name: "exp_month",
        sensitive: true,
        item_types: &["card"],
        description: "Card expiration month",
    },
    AttributeDescriptor {
        name: "exp_year",
        sensitive: true,
        item_types: &["card"],
        description: "Card expiration year",
    },
    AttributeDescriptor {
        name: "code",
        sensitive: true,
        item_types: &["card"],
        description: "Card security code (CVV)",
    },
    // -- SSH Key --
    AttributeDescriptor {
        name: "private_key",
        sensitive: true,
        item_types: &["sshkey"],
        description: "SSH private key",
    },
    AttributeDescriptor {
        name: "public_key",
        sensitive: false,
        item_types: &["sshkey"],
        description: "SSH public key",
    },
    AttributeDescriptor {
        name: "fingerprint",
        sensitive: false,
        item_types: &["sshkey"],
        description: "SSH key fingerprint",
    },
    // -- Identity (all PII → sensitive) --
    AttributeDescriptor {
        name: "title",
        sensitive: true,
        item_types: &["identity"],
        description: "Identity title (Mr, Ms, etc.)",
    },
    AttributeDescriptor {
        name: "first_name",
        sensitive: true,
        item_types: &["identity"],
        description: "First name",
    },
    AttributeDescriptor {
        name: "middle_name",
        sensitive: true,
        item_types: &["identity"],
        description: "Middle name",
    },
    AttributeDescriptor {
        name: "last_name",
        sensitive: true,
        item_types: &["identity"],
        description: "Last name",
    },
    AttributeDescriptor {
        name: "username",
        sensitive: true,
        item_types: &["identity"],
        description: "Identity username (PII)",
    },
    AttributeDescriptor {
        name: "company",
        sensitive: true,
        item_types: &["identity"],
        description: "Company name",
    },
    AttributeDescriptor {
        name: "ssn",
        sensitive: true,
        item_types: &["identity"],
        description: "Social Security Number",
    },
    AttributeDescriptor {
        name: "passport_number",
        sensitive: true,
        item_types: &["identity"],
        description: "Passport number",
    },
    AttributeDescriptor {
        name: "license_number",
        sensitive: true,
        item_types: &["identity"],
        description: "Driver's license number",
    },
    AttributeDescriptor {
        name: "email",
        sensitive: true,
        item_types: &["identity"],
        description: "Identity email address (PII)",
    },
    AttributeDescriptor {
        name: "phone",
        sensitive: true,
        item_types: &["identity"],
        description: "Identity phone number (PII)",
    },
    AttributeDescriptor {
        name: "address1",
        sensitive: true,
        item_types: &["identity"],
        description: "Address line 1",
    },
    AttributeDescriptor {
        name: "address2",
        sensitive: true,
        item_types: &["identity"],
        description: "Address line 2",
    },
    AttributeDescriptor {
        name: "address3",
        sensitive: true,
        item_types: &["identity"],
        description: "Address line 3",
    },
    AttributeDescriptor {
        name: "city",
        sensitive: true,
        item_types: &["identity"],
        description: "City",
    },
    AttributeDescriptor {
        name: "state",
        sensitive: true,
        item_types: &["identity"],
        description: "State / province",
    },
    AttributeDescriptor {
        name: "postal_code",
        sensitive: true,
        item_types: &["identity"],
        description: "Postal / ZIP code",
    },
    AttributeDescriptor {
        name: "country",
        sensitive: true,
        item_types: &["identity"],
        description: "Country",
    },
];

/// Bitwarden cloud region for official servers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitwardenRegion {
    /// US cloud (default): `api.bitwarden.com` / `identity.bitwarden.com`
    Us,
    /// EU cloud: `api.bitwarden.eu` / `identity.bitwarden.eu`
    Eu,
}

impl BitwardenRegion {
    /// Parse from a string (`"us"` or `"eu"`, case-insensitive).
    /// Returns `None` for unrecognised values.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "us" => Some(Self::Us),
            "eu" => Some(Self::Eu),
            _ => None,
        }
    }
}

/// Configuration for the Bitwarden backend.
///
/// URL resolution priority (highest to lowest):
/// 1. Both `api_url` **and** `identity_url` explicitly set — used directly.
/// 2. `base_url` set — derives `{base}/api` and `{base}/identity`.
/// 3. `region == Eu` — uses official EU endpoints.
/// 4. Default — official US cloud.
#[derive(Debug, Clone)]
pub struct BitwardenConfig {
    /// Unique instance identifier (from the `id` field in `[[backend]]` config).
    /// Used as the D-Bus identity for this backend instance; allows multiple
    /// Bitwarden accounts (e.g. `"personal"`, `"work"`) to coexist.
    pub id: String,
    /// User email address (required).
    pub email: String,
    /// Official cloud region shorthand (`"us"` | `"eu"`).
    /// Ignored when `base_url` or explicit URL overrides are set.
    pub region: Option<BitwardenRegion>,
    /// Self-hosted base URL (e.g. `"https://vault.example.com"`).
    /// Derives `{base}/api` and `{base}/identity`.
    /// Takes priority over `region`.
    pub base_url: Option<String>,
    /// Explicit API URL override (highest priority).
    /// Must be set together with `identity_url` to take effect.
    pub api_url: Option<String>,
    /// Explicit identity URL override (highest priority).
    /// Must be set together with `api_url` to take effect.
    pub identity_url: Option<String>,
    /// Enable real-time sync via SignalR WebSocket (default: `true`).
    ///
    /// When `true`, the backend connects to the Bitwarden notifications hub
    /// (`/notifications/hub`) on unlock and listens for server-push events.
    /// On receiving a cipher-update or sync nudge, the `on_sync` callback is
    /// invoked.  Set to `false` to fall back to polling-only behaviour.
    pub realtime_sync: bool,
    /// Fallback poll interval in seconds (default: `3600`).
    ///
    /// How often the background timer fires to re-sync the vault even when no
    /// SignalR nudge has been received.  If `realtime_sync = true`, this acts
    /// as a safety net; if `realtime_sync = false`, it is the only sync trigger.
    pub notifications_poll_interval_secs: u64,
}

/// Handle to a running notifications background task.
///
/// Dropping this cancels the task: the watch sender is dropped, which closes
/// the channel and causes the task to exit on its next cancellation check.
struct NotificationsHandle {
    /// Dropping this sender signals the notifications task to stop.
    _cancel_tx: tokio::sync::watch::Sender<()>,
    /// Join handle for the spawned task (used only for clean shutdown).
    _task: tokio::task::JoinHandle<()>,
}

/// Bitwarden vault backend for rosec.
///
/// Implements the `VaultBackend` trait to provide read-only access to
/// a Bitwarden vault. Authentication requires a master password provided
/// via the `unlock` method.
pub struct BitwardenBackend {
    config: BitwardenConfig,
    api: ApiClient,
    state: Mutex<Option<AuthState>>,
    /// Active notifications task, if any.  `None` when locked or
    /// `realtime_sync = false`.  Replaced on each unlock.
    notifications: Mutex<Option<NotificationsHandle>>,
    /// Lifecycle event callbacks registered by `rosecd` after construction.
    callbacks: std::sync::RwLock<BackendCallbacks>,
    /// SignalR nudge callbacks: fired when the server pushes a sync/lock event.
    /// These are *not* the same as `BackendCallbacks` — they trigger external
    /// actions (ServiceState sync / auto-lock) rather than reporting backend
    /// state changes.
    on_sync_nudge: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync + 'static>>>,
    on_lock_nudge: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync + 'static>>>,
}

/// Internal authenticated state.
struct AuthState {
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    vault: VaultState,
}

impl std::fmt::Debug for BitwardenBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitwardenBackend")
            .field("id", &self.config.id)
            .field("email", &self.config.email)
            .field("region", &self.config.region)
            .field("base_url", &self.config.base_url)
            .finish()
    }
}

impl BitwardenBackend {
    /// Create a new Bitwarden backend with the given configuration.
    ///
    /// URL resolution priority:
    /// 1. Both `api_url` and `identity_url` set → use directly.
    /// 2. `base_url` set → derive `{base}/api` + `{base}/identity`.
    /// 3. `region == Eu` → official EU cloud.
    /// 4. Default → official US cloud.
    pub fn new(config: BitwardenConfig) -> Result<Self, BitwardenError> {
        let urls = match (&config.api_url, &config.identity_url) {
            (Some(api), Some(identity)) => {
                // Derive notifications URL from api_url by stripping a trailing
                // "/api" segment and appending "/notifications", or fall back to
                // an adjacent path if the URL doesn't end in "/api".
                let notifications_url = api
                    .strip_suffix("/api")
                    .map(|base| format!("{base}/notifications"))
                    .unwrap_or_else(|| format!("{api}/notifications"));
                ServerUrls {
                    api_url: api.clone(),
                    identity_url: identity.clone(),
                    notifications_url,
                }
            }
            _ => match &config.base_url {
                Some(base) => ServerUrls::from_base(base),
                None => match config.region {
                    Some(BitwardenRegion::Eu) => ServerUrls::official_eu(),
                    _ => ServerUrls::official_us(),
                },
            },
        };

        let api = ApiClient::new(urls)?;

        Ok(Self {
            config,
            api,
            state: Mutex::new(None),
            notifications: Mutex::new(None),
            callbacks: std::sync::RwLock::new(BackendCallbacks::default()),
            on_sync_nudge: std::sync::Mutex::new(None),
            on_lock_nudge: std::sync::Mutex::new(None),
        })
    }

    /// Set the SignalR nudge callbacks used by the real-time notifications task.
    ///
    /// - `on_sync_nudge` — called when the Bitwarden server pushes a cipher-update
    ///   event; typically calls `ServiceState::try_sync_backend`.
    /// - `on_lock_nudge` — called on a `LogOut` event; typically calls
    ///   `ServiceState::auto_lock`.
    ///
    /// These are separate from the `BackendCallbacks` registered via
    /// `set_event_callbacks` on the `VaultBackend` trait.  The nudge callbacks
    /// trigger *external* actions; the event callbacks report *backend* state changes.
    ///
    /// Must be called after construction, once `ServiceState` is available.
    /// Safe to call even when `realtime_sync = false` (stored but never used).
    pub fn set_signalr_callbacks(
        &self,
        on_sync_nudge: Arc<dyn Fn() + Send + Sync + 'static>,
        on_lock_nudge: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> Result<(), BackendError> {
        let mut sync_guard = self
            .on_sync_nudge
            .lock()
            .map_err(|_| BackendError::Other(anyhow::anyhow!("on_sync_nudge mutex poisoned")))?;
        let mut lock_guard = self
            .on_lock_nudge
            .lock()
            .map_err(|_| BackendError::Other(anyhow::anyhow!("on_lock_nudge mutex poisoned")))?;
        *sync_guard = Some(on_sync_nudge);
        *lock_guard = Some(on_lock_nudge);
        Ok(())
    }

    /// Perform the full authentication + sync flow.
    async fn authenticate(
        &self,
        password: &str,
        two_factor: Option<TwoFactorSubmission>,
    ) -> Result<AuthState, BitwardenError> {
        let email = &self.config.email;

        // Step 1: Prelogin
        let kdf = self.api.prelogin(email).await?;
        debug!(?kdf, "got KDF params");

        // Step 2: Key derivation
        let master_key = crypto::derive_master_key(password.as_bytes(), email, &kdf)?;
        let password_hash = crypto::derive_password_hash(&master_key, password.as_bytes());
        let identity_keys = crypto::expand_master_key(&master_key)?;

        // Step 3: Login
        let hash_b64 = crypto::b64_encode(&password_hash);
        let login_resp = match self.api.login_password(email, &hash_b64, two_factor).await {
            Ok(resp) => resp,
            Err(BitwardenError::DeviceVerificationRequired) => {
                // The server doesn't recognise this device UUID.
                // Try auto-registration with the stored API key (happy path for
                // repeat logins after the first explicit registration).
                match oauth_cred::load_and_decrypt(&self.config.id, &master_key, email) {
                    Ok(Some(cred)) => {
                        info!(
                            backend = %self.config.id,
                            "device not registered; attempting auto-registration with stored API key"
                        );
                        self.api
                            .register_device(email, &cred.client_id, &cred.client_secret)
                            .await?;
                        info!(backend = %self.config.id, "device registered; retrying login");
                        self.api.login_password(email, &hash_b64, None).await?
                    }
                    Ok(None) => {
                        // No stored API key — propagate so the auth flow can
                        // prompt for registration credentials via registration_info().
                        return Err(BitwardenError::DeviceVerificationRequired);
                    }
                    Err(e) => {
                        // Decrypt failed — most likely the master password was
                        // changed since the credential was stored (HMAC mismatch
                        // because the derived storage key differs).  Delete the
                        // stale credential and fall through to registration so
                        // the client can re-prompt.
                        warn!(
                            backend = %self.config.id,
                            error = %e,
                            "stored OAuth credential could not be decrypted \
                             (master password may have changed); removing stale credential"
                        );
                        if let Err(rm_err) = rosec_core::oauth::clear(&self.config.id) {
                            warn!(
                                backend = %self.config.id,
                                error = %rm_err,
                                "failed to remove stale credential file"
                            );
                        }
                        return Err(BitwardenError::DeviceVerificationRequired);
                    }
                }
            }
            Err(e) => return Err(e),
        };

        let protected_key = login_resp.key.as_deref().ok_or_else(|| {
            BitwardenError::Auth("no protected key in login response".to_string())
        })?;

        // Step 4: Initialize vault state from protected key
        let mut vault = VaultState::new(&identity_keys, protected_key)?;

        // Step 5: Sync — access_token is already Zeroizing<String>
        let sync = self.api.sync(&login_resp.access_token).await?;
        vault.process_sync(&sync)?;

        Ok(AuthState {
            // Fields are already Zeroizing<String> from the response struct
            access_token: login_resp.access_token,
            refresh_token: login_resp.refresh_token,
            vault,
        })
    }

    /// Register this device with Bitwarden and persist the API key.
    ///
    /// Called when `unlock` is invoked with `UnlockInput::WithRegistration`.
    /// Derives the master key from `password`, registers the device via the
    /// personal API key, then encrypts and saves the API key for future use.
    async fn register_and_save(
        &self,
        password: &str,
        reg_fields: std::collections::HashMap<String, zeroize::Zeroizing<String>>,
    ) -> Result<(), BitwardenError> {
        let email = &self.config.email;

        let client_id = reg_fields
            .get("client_id")
            .ok_or_else(|| BitwardenError::Auth("missing client_id".to_string()))?;
        let client_secret = reg_fields
            .get("client_secret")
            .ok_or_else(|| BitwardenError::Auth("missing client_secret".to_string()))?;

        // Derive master key (needed both for registration auth and for encrypting
        // the API key at rest).
        let kdf = self.api.prelogin(email).await?;
        let master_key = crypto::derive_master_key(password.as_bytes(), email, &kdf)?;

        // Register the device UUID with Bitwarden.
        self.api
            .register_device(email, client_id, client_secret)
            .await?;

        // Persist the API key encrypted with a key derived from master_key.
        oauth_cred::encrypt_and_save(
            &self.config.id,
            &master_key,
            email,
            client_id,
            client_secret,
        )?;

        info!(
            "device registered and API key saved for backend '{}'",
            self.config.id
        );
        Ok(())
    }

    /// Re-sync the vault using the existing access token.
    ///
    /// If the access token has expired and a refresh token is available,
    /// automatically refreshes the token and retries the sync.
    async fn resync(state: &mut AuthState, api: &ApiClient) -> Result<(), BitwardenError> {
        match api.sync(&state.access_token).await {
            Ok(sync) => {
                state.vault.process_sync(&sync)?;
                debug!(ciphers = state.vault.ciphers().len(), "vault resynced");
                Ok(())
            }
            Err(BitwardenError::Auth(_)) => {
                // Access token expired — try refreshing
                let refresh_token = match &state.refresh_token {
                    Some(rt) => rt.clone(),
                    None => {
                        return Err(BitwardenError::Auth(
                            "access token expired and no refresh token available".to_string(),
                        ));
                    }
                };

                debug!("access token expired, refreshing");
                let refresh_resp = api.refresh_token(&refresh_token).await?;
                // Fields are already Zeroizing<String> from the response struct
                state.access_token = refresh_resp.access_token;
                // Capture rotated refresh token if the server issued a new one
                if let Some(new_rt) = refresh_resp.refresh_token {
                    state.refresh_token = Some(new_rt);
                }
                info!("access token refreshed");

                // Retry sync with new token
                let sync = api.sync(&state.access_token).await?;
                state.vault.process_sync(&sync)?;
                debug!(
                    ciphers = state.vault.ciphers().len(),
                    "vault resynced after token refresh"
                );
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Map a decrypted cipher to a VaultItemMeta.
    ///
    /// Takes `backend_id` explicitly so multiple Bitwarden instances attribute
    /// their items to the correct instance ID rather than a hardcoded string.
    ///
    /// Only populates **public** attributes — no sensitive data appears here.
    /// Sensitive attribute names are available via `build_item_attributes()`.
    fn cipher_to_meta(backend_id: &str, dc: &DecryptedCipher) -> VaultItemMeta {
        let mut attributes = Attributes::new();

        // xdg:schema — required for Secret Service compatibility
        let schema = match dc.cipher_type {
            CipherType::Login => "org.freedesktop.Secret.Generic",
            CipherType::SecureNote => "org.freedesktop.Secret.Note",
            _ => "org.freedesktop.Secret.Generic",
        };
        attributes.insert("xdg:schema".to_string(), schema.to_string());

        // Standard attributes for D-Bus Secret Service compatibility
        attributes.insert("type".to_string(), dc.cipher_type.as_str().to_string());

        if let Some(folder) = &dc.folder_name {
            attributes.insert("folder".to_string(), folder.clone());
        }

        if let Some(org_id) = &dc.organization_id {
            attributes.insert("org_id".to_string(), org_id.clone());
        }
        if let Some(org_name) = &dc.organization_name {
            attributes.insert("org".to_string(), org_name.clone());
        }

        // Login-specific public attributes
        if let Some(login) = &dc.login {
            // username is public per attribute-model decision
            if let Some(username) = &login.username {
                attributes.insert("username".to_string(), username.as_str().to_string());
            }
            // All URIs are public. First is "uri" (index 0, backwards compat);
            // subsequent ones are "uri.1", "uri.2", etc.
            for (i, uri) in login.uris.iter().enumerate() {
                let key = if i == 0 {
                    "uri".to_string()
                } else {
                    format!("uri.{i}")
                };
                attributes.insert(key, uri.clone());
            }
        }

        // Card-specific public attributes (brand only — cardholder is PII/sensitive)
        if let Some(card) = &dc.card
            && let Some(brand) = &card.brand
        {
            attributes.insert("brand".to_string(), brand.clone());
        }

        // SSH key public attributes
        if let Some(ssh_key) = &dc.ssh_key {
            if let Some(pub_key) = &ssh_key.public_key {
                attributes.insert("public_key".to_string(), pub_key.clone());
            }
            if let Some(fp) = &ssh_key.fingerprint {
                attributes.insert("fingerprint".to_string(), fp.clone());
            }
        }

        // Custom fields as attributes — only text (type 0) and boolean (type 2).
        // Hidden fields (type 1) are sensitive and excluded from public attrs.
        //
        // When a field name appears more than once, indexed keys are emitted:
        //   custom.ssh-host   → first value (unindexed alias)
        //   custom.ssh-host.0 → first value
        //   custom.ssh-host.1 → second value
        //   custom.ssh-host.2 → third value
        // When a name appears only once, just the unindexed key is used.
        for (key, value) in index_custom_fields(&dc.fields, &[0, 2]) {
            attributes.insert(key, value);
        }

        let created = dc.creation_date.as_ref().and_then(|s| parse_iso8601(s));
        let modified = dc.revision_date.as_ref().and_then(|s| parse_iso8601(s));

        VaultItemMeta {
            id: dc.id.clone(),
            backend_id: backend_id.to_string(),
            label: dc.name.clone(),
            attributes,
            created,
            modified,
            locked: false,
        }
    }

    /// Get the "primary secret" for a cipher — the password for logins,
    /// notes for secure notes, etc.
    ///
    /// Returns the secret bytes wrapped in `SecretBytes` (zeroized on drop).
    /// Uses `Zeroizing<Vec<u8>>` internally to avoid any plain-text intermediate buffer.
    fn get_primary_secret(dc: &DecryptedCipher) -> Option<SecretBytes> {
        // Helper: borrow a Zeroizing<String> and produce a Zeroizing<Vec<u8>>
        // without going through a plain intermediate buffer.
        // Takes &String (the deref target of Zeroizing<String>) so it works
        // directly with Option::map after .as_deref().
        fn to_secret_bytes(s: &String) -> Zeroizing<Vec<u8>> {
            Zeroizing::new(s.as_bytes().to_vec())
        }

        let bytes: Option<Zeroizing<Vec<u8>>> = match dc.cipher_type {
            CipherType::Login => dc
                .login
                .as_ref()
                .and_then(|l| l.password.as_deref())
                .or(dc.login.as_ref().and_then(|l| l.totp.as_deref()))
                .or(dc.notes.as_deref())
                .map(to_secret_bytes),
            CipherType::SecureNote => dc.notes.as_deref().map(to_secret_bytes),
            CipherType::Card => dc
                .card
                .as_ref()
                .and_then(|c| c.number.as_deref())
                .map(to_secret_bytes),
            CipherType::SshKey => dc
                .ssh_key
                .as_ref()
                .and_then(|sk| sk.private_key.as_deref())
                .or(dc.notes.as_deref())
                .map(to_secret_bytes),
            CipherType::Identity | CipherType::Unknown(_) => {
                dc.notes.as_deref().map(to_secret_bytes)
            }
        };
        bytes.map(SecretBytes::from_zeroizing)
    }

    /// Build [`ItemAttributes`] for a decrypted cipher.
    ///
    /// Populates:
    /// - `public`: non-sensitive attributes safe for D-Bus exposure
    /// - `secret_names`: names of sensitive attributes that have values
    ///
    /// Duplicate custom field names are suffixed: `custom.ssh-host`,
    /// `custom.ssh-host.1`, `custom.ssh-host.2`, etc.
    fn build_item_attributes(backend_id: &str, dc: &DecryptedCipher) -> ItemAttributes {
        let mut public = Attributes::new();
        let mut secret_names = Vec::new();

        // -- Common public attributes --
        let schema = match dc.cipher_type {
            CipherType::Login => "org.freedesktop.Secret.Generic",
            CipherType::SecureNote => "org.freedesktop.Secret.Note",
            _ => "org.freedesktop.Secret.Generic",
        };
        public.insert("xdg:schema".to_string(), schema.to_string());
        public.insert("type".to_string(), dc.cipher_type.as_str().to_string());
        public.insert("backend_id".to_string(), backend_id.to_string());

        if let Some(folder) = &dc.folder_name {
            public.insert("folder".to_string(), folder.clone());
        }
        if let Some(org_id) = &dc.organization_id {
            public.insert("org_id".to_string(), org_id.clone());
        }

        // notes — always sensitive
        if dc.notes.is_some() {
            secret_names.push("notes".to_string());
        }

        // -- Login --
        if let Some(login) = &dc.login {
            // username is public
            if let Some(username) = &login.username {
                public.insert("username".to_string(), username.as_str().to_string());
            }
            // All URIs are public. First is "uri" (index 0, backwards compat);
            // subsequent ones are "uri.1", "uri.2", etc.
            for (i, uri) in login.uris.iter().enumerate() {
                let key = if i == 0 {
                    "uri".to_string()
                } else {
                    format!("uri.{i}")
                };
                public.insert(key, uri.clone());
            }
            // sensitive
            if login.password.is_some() {
                secret_names.push("password".to_string());
            }
            if login.totp.is_some() {
                secret_names.push("totp".to_string());
            }
        }

        // -- Card --
        if let Some(card) = &dc.card {
            // brand is public
            if let Some(brand) = &card.brand {
                public.insert("brand".to_string(), brand.clone());
            }
            // all others are sensitive
            if card.cardholder_name.is_some() {
                secret_names.push("cardholder".to_string());
            }
            if card.number.is_some() {
                secret_names.push("number".to_string());
            }
            if card.exp_month.is_some() {
                secret_names.push("exp_month".to_string());
            }
            if card.exp_year.is_some() {
                secret_names.push("exp_year".to_string());
            }
            if card.code.is_some() {
                secret_names.push("code".to_string());
            }
        }

        // -- SSH Key --
        if let Some(ssh_key) = &dc.ssh_key {
            // public_key and fingerprint are public
            if let Some(pub_key) = &ssh_key.public_key {
                public.insert("public_key".to_string(), pub_key.clone());
            }
            if let Some(fp) = &ssh_key.fingerprint {
                public.insert("fingerprint".to_string(), fp.clone());
            }
            // private_key is sensitive
            if ssh_key.private_key.is_some() {
                secret_names.push("private_key".to_string());
            }
        }

        // -- Identity (all fields are sensitive PII) --
        if let Some(ident) = &dc.identity {
            let ident_fields: &[(&str, &Option<Zeroizing<String>>)] = &[
                ("title", &ident.title),
                ("first_name", &ident.first_name),
                ("middle_name", &ident.middle_name),
                ("last_name", &ident.last_name),
                ("username", &ident.username),
                ("company", &ident.company),
                ("ssn", &ident.ssn),
                ("passport_number", &ident.passport_number),
                ("license_number", &ident.license_number),
                ("email", &ident.email),
                ("phone", &ident.phone),
                ("address1", &ident.address1),
                ("address2", &ident.address2),
                ("address3", &ident.address3),
                ("city", &ident.city),
                ("state", &ident.state),
                ("postal_code", &ident.postal_code),
                ("country", &ident.country),
            ];
            for (name, value) in ident_fields {
                if value.is_some() {
                    secret_names.push((*name).to_string());
                }
            }
        }

        // -- Custom fields --
        // Public (text/boolean/linked) fields are indexed via `index_custom_fields`.
        // Hidden fields go into `secret_names` with the same indexing scheme.
        for (key, value) in index_custom_fields(&dc.fields, &[0, 2, 3]) {
            public.insert(key, value);
        }
        for (key, _) in index_custom_fields(&dc.fields, &[1]) {
            secret_names.push(key);
        }

        ItemAttributes {
            public,
            secret_names,
        }
    }

    /// Resolve a named secret attribute from a decrypted cipher.
    ///
    /// Returns `None` if the attribute doesn't exist on this cipher or has no value.
    fn resolve_secret_attr(dc: &DecryptedCipher, attr: &str) -> Option<SecretBytes> {
        // Helper: borrow a Zeroizing<String> → SecretBytes
        fn to_sb(s: &Zeroizing<String>) -> SecretBytes {
            SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec()))
        }

        // notes — common to all types
        if attr == "notes" {
            return dc.notes.as_ref().map(to_sb);
        }

        // Custom fields (prefixed with "custom.")
        // Supports suffixed names: "custom.ssh-host" returns the first field
        // named "ssh-host", "custom.ssh-host.1" returns the second, etc.
        if let Some(custom_name) = attr.strip_prefix("custom.") {
            // Check if the name has a numeric suffix (e.g. "ssh-host.2")
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
                        return field.value.as_ref().map(to_sb);
                    }
                    count += 1;
                }
            }
            return None;
        }

        // Type-specific attributes
        match dc.cipher_type {
            CipherType::Login => {
                let login = dc.login.as_ref()?;
                match attr {
                    "password" => login.password.as_ref().map(to_sb),
                    "totp" => login.totp.as_ref().map(to_sb),
                    "username" => login.username.as_ref().map(to_sb),
                    _ => None,
                }
            }
            CipherType::Card => {
                let card = dc.card.as_ref()?;
                match attr {
                    "cardholder" => card.cardholder_name.as_ref().map(to_sb),
                    "number" => card.number.as_ref().map(to_sb),
                    "exp_month" => card.exp_month.as_ref().map(to_sb),
                    "exp_year" => card.exp_year.as_ref().map(to_sb),
                    "code" => card.code.as_ref().map(to_sb),
                    _ => None,
                }
            }
            CipherType::SshKey => {
                let ssh = dc.ssh_key.as_ref()?;
                match attr {
                    "private_key" => ssh.private_key.as_ref().map(to_sb),
                    _ => None,
                }
            }
            CipherType::Identity => {
                let ident = dc.identity.as_ref()?;
                match attr {
                    "title" => ident.title.as_ref().map(to_sb),
                    "first_name" => ident.first_name.as_ref().map(to_sb),
                    "middle_name" => ident.middle_name.as_ref().map(to_sb),
                    "last_name" => ident.last_name.as_ref().map(to_sb),
                    "username" => ident.username.as_ref().map(to_sb),
                    "company" => ident.company.as_ref().map(to_sb),
                    "ssn" => ident.ssn.as_ref().map(to_sb),
                    "passport_number" => ident.passport_number.as_ref().map(to_sb),
                    "license_number" => ident.license_number.as_ref().map(to_sb),
                    "email" => ident.email.as_ref().map(to_sb),
                    "phone" => ident.phone.as_ref().map(to_sb),
                    "address1" => ident.address1.as_ref().map(to_sb),
                    "address2" => ident.address2.as_ref().map(to_sb),
                    "address3" => ident.address3.as_ref().map(to_sb),
                    "city" => ident.city.as_ref().map(to_sb),
                    "state" => ident.state.as_ref().map(to_sb),
                    "postal_code" => ident.postal_code.as_ref().map(to_sb),
                    "country" => ident.country.as_ref().map(to_sb),
                    _ => None,
                }
            }
            CipherType::SecureNote | CipherType::Unknown(_) => None,
        }
    }

    // -----------------------------------------------------------------------
    // SSH key helpers
    // -----------------------------------------------------------------------

    /// PEM headers that indicate an SSH private key in a text field.
    const PEM_HEADERS: &'static [&'static str] = &[
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ];

    /// Return `true` if `text` contains a recognised PEM private key header.
    fn contains_pem(text: &str) -> bool {
        Self::PEM_HEADERS.iter().any(|h| text.contains(h))
    }

    /// Extract the first PEM block from `text`, or `None`.
    fn extract_pem_from_text(text: &str) -> Option<Zeroizing<String>> {
        for header in Self::PEM_HEADERS {
            if let Some(start) = text.find(header) {
                let after = &text[start..];
                // Find the matching -----END …----- footer
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
    /// Search order: native `ssh_key.private_key` → `notes` → `login.password`
    /// → hidden custom fields (type 1).
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
            && Self::contains_pem(notes)
        {
            return Self::extract_pem_from_text(notes);
        }

        // 3. Login password
        if let Some(login) = &dc.login
            && let Some(pw) = &login.password
            && Self::contains_pem(pw)
        {
            return Self::extract_pem_from_text(pw);
        }

        // 4. Hidden custom fields (field_type == 1)
        for field in &dc.fields {
            if field.field_type == 1
                && let Some(val) = &field.value
                && Self::contains_pem(val)
            {
                return Self::extract_pem_from_text(val);
            }
        }

        None
    }

    /// Build an [`SshKeyMeta`] for a cipher that has discoverable SSH key
    /// material, or `None` if the cipher has none.
    fn cipher_to_ssh_key_meta(backend_id: &str, dc: &DecryptedCipher) -> Option<SshKeyMeta> {
        // Does this cipher have any SSH key material?
        let has_native_key = dc
            .ssh_key
            .as_ref()
            .is_some_and(|sk| sk.private_key.as_ref().is_some_and(|pk| !pk.is_empty()));

        let has_pem = !has_native_key && Self::extract_pem(dc).is_some();

        if !has_native_key && !has_pem {
            return None;
        }

        // Public key and fingerprint — available from native SSH key items.
        let public_key_openssh = dc.ssh_key.as_ref().and_then(|sk| sk.public_key.clone());
        let fingerprint = dc.ssh_key.as_ref().and_then(|sk| sk.fingerprint.clone());

        // Extract custom.ssh_host / custom.ssh-host fields.
        // Multiple fields are supported, and each value may contain
        // newline-separated host patterns (equivalent to multiple fields).
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

        Some(SshKeyMeta {
            item_id: dc.id.clone(),
            item_name: dc.name.clone(),
            backend_id: backend_id.to_string(),
            public_key_openssh,
            fingerprint,
            ssh_hosts,
            ssh_user,
            require_confirm,
            revision_date,
        })
    }
}

#[async_trait::async_trait]
impl VaultBackend for BitwardenBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Returns the instance ID from config (e.g. `"personal"`, `"work"`).
    /// This is what distinguishes multiple Bitwarden accounts from each other.
    fn id(&self) -> &str {
        &self.config.id
    }

    /// Human-readable name: `"Bitwarden (<email>)"` so multiple instances are
    /// distinguishable in UIs without exposing which is "personal" vs "work".
    fn name(&self) -> &str {
        &self.config.email
    }

    fn kind(&self) -> &str {
        "bitwarden"
    }

    fn set_event_callbacks(&self, callbacks: BackendCallbacks) -> Result<(), BackendError> {
        *self
            .callbacks
            .write()
            .map_err(|_| BackendError::Other(anyhow::anyhow!("callbacks lock poisoned")))? =
            callbacks;
        Ok(())
    }

    fn password_field(&self) -> AuthField {
        AuthField {
            id: "password",
            label: "Master Password",
            placeholder: "Enter your Bitwarden master password",
            required: true,
            kind: AuthFieldKind::Password,
        }
    }

    fn registration_info(&self) -> Option<RegistrationInfo> {
        static INFO: RegistrationInfo = RegistrationInfo {
            instructions: "\
This device is not registered with Bitwarden. To register it, you need \
your personal API key.\n\n\
Find it at: Bitwarden web vault → Account Settings → Security → Keys → View API Key",
            fields: &[
                AuthField {
                    id: "client_id",
                    label: "API key client_id",
                    placeholder: "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    required: true,
                    kind: AuthFieldKind::Text,
                },
                AuthField {
                    id: "client_secret",
                    label: "API key client_secret",
                    placeholder: "",
                    required: true,
                    kind: AuthFieldKind::Secret,
                },
            ],
        };
        Some(INFO)
    }

    async fn status(&self) -> Result<BackendStatus, BackendError> {
        let guard = self.state.lock().await;
        match &*guard {
            Some(state) => Ok(BackendStatus {
                locked: false,
                last_sync: state.vault.last_sync(),
            }),
            None => Ok(BackendStatus {
                locked: true,
                last_sync: None,
            }),
        }
    }

    async fn unlock(&self, input: UnlockInput) -> Result<(), BackendError> {
        let (password, registration) = match input {
            UnlockInput::Password(p) => (p, None),
            UnlockInput::WithRegistration {
                password,
                registration_fields,
            } => (password, Some(registration_fields)),
            _ => return Err(BackendError::NotSupported),
        };

        // If registration credentials were supplied, register the device first
        // and persist the encrypted API key before attempting unlock.
        if let Some(reg_fields) = registration {
            self.register_and_save(&password, reg_fields)
                .await
                .map_err(BackendError::from)?;
        }

        let auth_state = self
            .authenticate(&password, None)
            .await
            .map_err(BackendError::from)?;

        let ciphers = auth_state.vault.ciphers().len();

        // Start the notifications task before storing auth state so the
        // access token is still accessible here (not moved into AuthState).
        let notifications_handle = if self.config.realtime_sync {
            let access_token = auth_state.access_token.clone();
            let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(());
            let on_sync_nudge = self
                .on_sync_nudge
                .lock()
                .expect("on_sync_nudge mutex poisoned")
                .clone();
            let on_lock_nudge = self
                .on_lock_nudge
                .lock()
                .expect("on_lock_nudge mutex poisoned")
                .clone();
            let task = notifications::start(NotificationsConfig {
                notifications_url: self.api.notifications_url().to_string(),
                access_token,
                backend_id: self.config.id.clone(),
                on_sync_nudge,
                on_lock_nudge,
                cancel_rx,
            });
            Some(NotificationsHandle {
                _cancel_tx: cancel_tx,
                _task: task,
            })
        } else {
            None
        };

        let mut state_guard = self.state.lock().await;
        *state_guard = Some(auth_state);
        drop(state_guard);

        let mut notif_guard = self.notifications.lock().await;
        *notif_guard = notifications_handle;
        drop(notif_guard);

        info!(ciphers, "Bitwarden vault unlocked");

        // Fire on_unlocked callback.
        if let Some(f) = self
            .callbacks
            .read()
            .map_err(|_| BackendError::Other(anyhow::anyhow!("callbacks lock poisoned")))?
            .on_unlocked
            .clone()
        {
            f();
        }

        Ok(())
    }

    async fn lock(&self) -> Result<(), BackendError> {
        // Stop the notifications task first (drop cancels it).
        let mut notif_guard = self.notifications.lock().await;
        *notif_guard = None;
        drop(notif_guard);

        let mut guard = self.state.lock().await;
        *guard = None;
        info!("Bitwarden vault locked");

        // Fire on_locked callback.
        if let Some(f) = self
            .callbacks
            .read()
            .map_err(|_| BackendError::Other(anyhow::anyhow!("callbacks lock poisoned")))?
            .on_locked
            .clone()
        {
            f();
        }

        Ok(())
    }

    async fn sync(&self) -> Result<(), BackendError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;

        // Snapshot cipher fingerprints before sync to detect material changes.
        let before: std::collections::HashSet<(String, Option<String>)> = state
            .vault
            .ciphers()
            .iter()
            .map(|c| (c.id.clone(), c.revision_date.clone()))
            .collect();

        let result = Self::resync(state, &self.api)
            .await
            .map_err(BackendError::from);

        // Read callbacks before dropping the guard (we need `state` above).
        let (on_sync_succeeded, on_sync_failed) = {
            let cb = self
                .callbacks
                .read()
                .map_err(|_| BackendError::Other(anyhow::anyhow!("callbacks lock poisoned")))?;
            (cb.on_sync_succeeded.clone(), cb.on_sync_failed.clone())
        };
        drop(guard);

        match &result {
            Ok(()) => {
                if let Some(f) = on_sync_succeeded {
                    // Re-acquire read lock to get post-sync ciphers.
                    let guard = self.state.lock().await;
                    let changed = if let Some(state) = guard.as_ref() {
                        let after: std::collections::HashSet<(String, Option<String>)> = state
                            .vault
                            .ciphers()
                            .iter()
                            .map(|c| (c.id.clone(), c.revision_date.clone()))
                            .collect();
                        after != before
                    } else {
                        false
                    };
                    drop(guard);
                    f(changed);
                }
            }
            Err(_) => {
                if let Some(f) = on_sync_failed {
                    f();
                }
            }
        }

        result
    }

    async fn list_items(&self) -> Result<Vec<VaultItemMeta>, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;
        let backend_id = &self.config.id;

        let items: Vec<VaultItemMeta> = state
            .vault
            .ciphers()
            .iter()
            .map(|dc| Self::cipher_to_meta(backend_id, dc))
            .collect();

        Ok(items)
    }

    async fn get_item(&self, id: &str) -> Result<VaultItem, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let dc = state.vault.cipher_by_id(id).ok_or(BackendError::NotFound)?;

        let secret = Self::get_primary_secret(dc);

        Ok(VaultItem {
            meta: Self::cipher_to_meta(&self.config.id, dc),
            secret,
        })
    }

    async fn get_secret(&self, id: &str) -> Result<SecretBytes, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let dc = state.vault.cipher_by_id(id).ok_or(BackendError::NotFound)?;

        Self::get_primary_secret(dc)
            .ok_or_else(|| BackendError::Other(anyhow::anyhow!("no secret for cipher {id}")))
    }

    async fn search(&self, attrs: &Attributes) -> Result<Vec<VaultItemMeta>, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;
        let backend_id = &self.config.id;

        let items: Vec<VaultItemMeta> = state
            .vault
            .ciphers()
            .iter()
            .filter_map(|dc| {
                let meta = Self::cipher_to_meta(backend_id, dc);
                if attrs
                    .iter()
                    .all(|(key, value)| meta.attributes.get(key) == Some(value))
                {
                    Some(meta)
                } else {
                    None
                }
            })
            .collect();

        Ok(items)
    }

    fn available_attributes(&self) -> &'static [AttributeDescriptor] {
        BITWARDEN_ATTRIBUTES
    }

    async fn get_item_attributes(&self, id: &str) -> Result<ItemAttributes, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let dc = state.vault.cipher_by_id(id).ok_or(BackendError::NotFound)?;

        Ok(Self::build_item_attributes(&self.config.id, dc))
    }

    async fn get_secret_attr(&self, id: &str, attr: &str) -> Result<SecretBytes, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let dc = state.vault.cipher_by_id(id).ok_or(BackendError::NotFound)?;

        Self::resolve_secret_attr(dc, attr).ok_or_else(|| BackendError::NotFound)
    }

    // -----------------------------------------------------------------------
    // SSH agent interface
    // -----------------------------------------------------------------------

    async fn list_ssh_keys(&self) -> Result<Vec<SshKeyMeta>, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;
        let backend_id = self.config.id.clone();

        let keys = state
            .vault
            .ciphers()
            .iter()
            .filter_map(|dc| Self::cipher_to_ssh_key_meta(&backend_id, dc))
            .collect();

        Ok(keys)
    }

    async fn get_ssh_private_key(&self, id: &str) -> Result<SshPrivateKeyMaterial, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let dc = state.vault.cipher_by_id(id).ok_or(BackendError::NotFound)?;

        Self::extract_pem(dc)
            .map(|pem| SshPrivateKeyMaterial { pem })
            .ok_or(BackendError::NotFound)
    }
}

/// Index custom fields for attribute maps.
///
/// Returns `(key, value)` pairs with proper indexing for duplicate names:
/// - Single occurrence: just `custom.<name>` → value
/// - Multiple occurrences:
///   - `custom.<name>` → first value  (unindexed alias)
///   - `custom.<name>.0` → first value
///   - `custom.<name>.1` → second value
///   - `custom.<name>.2` → third value
///
/// `allowed_types` filters which `field_type` values to include
/// (0 = text, 1 = hidden, 2 = boolean, 3 = linked).
fn index_custom_fields(fields: &[DecryptedField], allowed_types: &[u8]) -> Vec<(String, String)> {
    use std::collections::HashMap;

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
            // Single occurrence — unindexed key only.
            result.push((base_key, values[0].to_string()));
        } else {
            // Multiple occurrences — unindexed alias + indexed keys.
            result.push((base_key.clone(), values[0].to_string()));
            for (i, val) in values.iter().enumerate() {
                result.push((format!("{base_key}.{i}"), (*val).to_string()));
            }
        }
    }
    result
}

/// Parse an ISO 8601 timestamp string to SystemTime.
fn parse_iso8601(s: &str) -> Option<SystemTime> {
    // Simple ISO 8601 parsing: "2024-01-15T12:30:00.000Z"
    // We don't bring in chrono just for this.
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

    // Approximate: days since epoch
    let days_since_epoch = (year - 1970) * 365
        + (year - 1969) / 4 // leap years (approximate)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{
        CipherType, DecryptedCard, DecryptedCipher, DecryptedField, DecryptedIdentity,
        DecryptedLogin, DecryptedSshKey,
    };

    // --- BitwardenRegion ---

    #[test]
    fn region_parse_us() {
        assert_eq!(BitwardenRegion::parse("us"), Some(BitwardenRegion::Us));
        assert_eq!(BitwardenRegion::parse("US"), Some(BitwardenRegion::Us));
    }

    #[test]
    fn region_parse_eu() {
        assert_eq!(BitwardenRegion::parse("eu"), Some(BitwardenRegion::Eu));
        assert_eq!(BitwardenRegion::parse("EU"), Some(BitwardenRegion::Eu));
    }

    #[test]
    fn region_parse_invalid() {
        assert_eq!(BitwardenRegion::parse("au"), None);
        assert_eq!(BitwardenRegion::parse(""), None);
    }

    // --- URL resolution via BitwardenBackend::new ---

    fn make_config(id: &str, email: &str) -> BitwardenConfig {
        BitwardenConfig {
            id: id.to_string(),
            email: email.to_string(),
            region: None,
            base_url: None,
            api_url: None,
            identity_url: None,
            realtime_sync: false, // no network in unit tests
            notifications_poll_interval_secs: 3600,
        }
    }

    #[test]
    fn url_resolution_default_is_us() {
        // No region/base_url/explicit URLs → official US cloud
        let backend = BitwardenBackend::new(make_config("personal", "a@b.com")).unwrap();
        // We can't inspect private fields directly, but we can verify it constructs without error.
        // The URL used is validated indirectly by other tests; just confirm construction succeeds.
        assert_eq!(backend.id(), "personal");
        assert_eq!(backend.name(), "a@b.com");
        assert_eq!(backend.kind(), "bitwarden");
    }

    #[test]
    fn url_resolution_eu_region() {
        let mut config = make_config("work-eu", "b@c.com");
        config.region = Some(BitwardenRegion::Eu);
        let backend = BitwardenBackend::new(config).unwrap();
        assert_eq!(backend.id(), "work-eu");
    }

    #[test]
    fn url_resolution_base_url_overrides_region() {
        let mut config = make_config("selfhosted", "c@d.com");
        config.region = Some(BitwardenRegion::Eu); // should be ignored
        config.base_url = Some("https://vault.example.com".to_string());
        let backend = BitwardenBackend::new(config).unwrap();
        assert_eq!(backend.id(), "selfhosted");
    }

    #[test]
    fn url_resolution_explicit_urls_override_all() {
        let mut config = make_config("custom", "d@e.com");
        config.region = Some(BitwardenRegion::Eu); // ignored
        config.base_url = Some("https://vault.example.com".to_string()); // ignored
        config.api_url = Some("https://api.custom.example.com".to_string());
        config.identity_url = Some("https://identity.custom.example.com".to_string());
        let backend = BitwardenBackend::new(config).unwrap();
        assert_eq!(backend.id(), "custom");
    }

    #[test]
    fn url_resolution_partial_explicit_urls_falls_through_to_base() {
        // Only api_url set (not identity_url) → falls through to base_url
        let mut config = make_config("partial", "e@f.com");
        config.base_url = Some("https://vault.example.com".to_string());
        config.api_url = Some("https://api.custom.example.com".to_string());
        // identity_url is None → explicit pair incomplete → uses base_url
        let backend = BitwardenBackend::new(config).unwrap();
        assert_eq!(backend.id(), "partial");
    }

    #[test]
    fn multiple_instances_have_distinct_ids() {
        let b1 = BitwardenBackend::new(make_config("personal", "alice@example.com")).unwrap();
        let b2 = BitwardenBackend::new(make_config("work", "alice@corp.com")).unwrap();
        assert_ne!(b1.id(), b2.id());
        assert_eq!(b1.id(), "personal");
        assert_eq!(b2.id(), "work");
        assert_eq!(b1.name(), "alice@example.com");
        assert_eq!(b2.name(), "alice@corp.com");
    }

    // --- parse_iso8601 ---

    #[test]
    fn parse_iso8601_basic() {
        let t = parse_iso8601("2024-01-15T12:30:00.000Z");
        assert!(t.is_some());
        let d = t.unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap();
        // 2024-01-15 12:30:00 UTC
        // days: (2024-1970)*365 + leap_days + 14 (jan 1-14)
        // Just verify it's in a plausible range (2024 epoch seconds ~1705000000)
        assert!(d.as_secs() > 1_700_000_000);
        assert!(d.as_secs() < 1_710_000_000);
    }

    #[test]
    fn parse_iso8601_no_millis() {
        let t = parse_iso8601("2024-01-01T00:00:00Z");
        assert!(t.is_some());
    }

    #[test]
    fn parse_iso8601_invalid_no_t() {
        assert!(parse_iso8601("2024-01-01 00:00:00Z").is_none());
    }

    #[test]
    fn parse_iso8601_invalid_incomplete_date() {
        assert!(parse_iso8601("2024-01T00:00:00Z").is_none());
    }

    #[test]
    fn parse_iso8601_invalid_incomplete_time() {
        assert!(parse_iso8601("2024-01-01T00:00Z").is_none());
    }

    #[test]
    fn parse_iso8601_empty() {
        assert!(parse_iso8601("").is_none());
    }

    // --- is_leap_year ---

    #[test]
    fn leap_year_checks() {
        assert!(is_leap_year(2000)); // divisible by 400
        assert!(!is_leap_year(1900)); // divisible by 100 but not 400
        assert!(is_leap_year(2024)); // divisible by 4, not 100
        assert!(!is_leap_year(2023)); // odd year
    }

    // --- days_before_month ---

    #[test]
    fn days_before_month_non_leap() {
        assert_eq!(days_before_month(1, false), 0); // Jan
        assert_eq!(days_before_month(2, false), 31); // Feb
        assert_eq!(days_before_month(3, false), 59); // Mar
        assert_eq!(days_before_month(12, false), 334); // Dec
    }

    #[test]
    fn days_before_month_leap() {
        assert_eq!(days_before_month(1, true), 0); // Jan — no leap adjustment
        assert_eq!(days_before_month(2, true), 31); // Feb — no leap adjustment (month <= 2)
        assert_eq!(days_before_month(3, true), 60); // Mar — +1 for leap
        assert_eq!(days_before_month(12, true), 335); // Dec — +1
    }

    #[test]
    fn days_before_month_out_of_range() {
        // month 0 or 13+ should not panic, just return 0
        assert_eq!(days_before_month(0, false), 0);
        assert_eq!(days_before_month(13, false), 0);
    }

    // --- Helper to build a minimal DecryptedCipher ---

    fn make_cipher(cipher_type: CipherType) -> DecryptedCipher {
        DecryptedCipher {
            id: "test-id-123".to_string(),
            name: "Test Item".to_string(),
            cipher_type,
            folder_name: None,
            notes: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            fields: Vec::new(),
            creation_date: Some("2024-06-15T10:30:00.000Z".to_string()),
            revision_date: Some("2024-06-20T14:00:00.000Z".to_string()),
            organization_id: None,
            organization_name: None,
        }
    }

    // --- cipher_to_meta ---

    #[test]
    fn cipher_to_meta_login_basic() {
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: Some(Zeroizing::new("alice".to_string())),
            password: Some(Zeroizing::new("secret123".to_string())),
            totp: None,
            uris: vec!["https://example.com".to_string()],
        });

        let meta = BitwardenBackend::cipher_to_meta("test-backend", &dc);
        assert_eq!(meta.id, "test-id-123");
        assert_eq!(meta.backend_id, "test-backend");
        assert_eq!(meta.label, "Test Item");
        assert!(!meta.locked);
        assert_eq!(meta.attributes.get("type"), Some(&"login".to_string()));
        assert_eq!(meta.attributes.get("username"), Some(&"alice".to_string()));
        assert_eq!(
            meta.attributes.get("uri"),
            Some(&"https://example.com".to_string())
        );
        assert_eq!(
            meta.attributes.get("xdg:schema"),
            Some(&"org.freedesktop.Secret.Generic".to_string())
        );
        assert!(meta.created.is_some());
        assert!(meta.modified.is_some());
    }

    #[test]
    fn cipher_to_meta_secure_note_schema() {
        let dc = make_cipher(CipherType::SecureNote);
        let meta = BitwardenBackend::cipher_to_meta("test-backend", &dc);
        assert_eq!(
            meta.attributes.get("xdg:schema"),
            Some(&"org.freedesktop.Secret.Note".to_string())
        );
        assert_eq!(meta.attributes.get("type"), Some(&"note".to_string()));
    }

    #[test]
    fn cipher_to_meta_card_public_attrs_only() {
        let mut dc = make_cipher(CipherType::Card);
        dc.card = Some(DecryptedCard {
            cardholder_name: Some(Zeroizing::new("John Doe".to_string())),
            number: Some(Zeroizing::new("4111111111111111".to_string())),
            brand: Some("Visa".to_string()),
            exp_month: Some(Zeroizing::new("12".to_string())),
            exp_year: Some(Zeroizing::new("2028".to_string())),
            code: Some(Zeroizing::new("123".to_string())),
        });

        let meta = BitwardenBackend::cipher_to_meta("test-backend", &dc);
        assert_eq!(meta.attributes.get("type"), Some(&"card".to_string()));
        // brand is public
        assert_eq!(meta.attributes.get("brand"), Some(&"Visa".to_string()));
        // cardholder is sensitive — NOT in public attributes
        assert!(!meta.attributes.contains_key("cardholder"));
        // number, exp_month, exp_year, code are all sensitive
        assert!(!meta.attributes.contains_key("number"));
        assert!(!meta.attributes.contains_key("exp_month"));
        assert!(!meta.attributes.contains_key("exp_year"));
        assert!(!meta.attributes.contains_key("code"));
    }

    #[test]
    fn cipher_to_meta_with_folder_and_org() {
        let mut dc = make_cipher(CipherType::Login);
        dc.folder_name = Some("Work".to_string());
        dc.organization_id = Some("org-abc".to_string());

        let meta = BitwardenBackend::cipher_to_meta("test-backend", &dc);
        assert_eq!(meta.attributes.get("folder"), Some(&"Work".to_string()));
        assert_eq!(meta.attributes.get("org_id"), Some(&"org-abc".to_string()));
    }

    #[test]
    fn cipher_to_meta_custom_fields_prefixed_and_hidden_excluded() {
        let mut dc = make_cipher(CipherType::Login);
        dc.fields = vec![
            DecryptedField {
                name: Some("api_key_label".to_string()),
                value: Some(Zeroizing::new("visible-value".to_string())),
                field_type: 0, // text — should be exposed with custom. prefix
            },
            DecryptedField {
                name: Some("secret_field".to_string()),
                value: Some(Zeroizing::new("hidden-value".to_string())),
                field_type: 1, // hidden — should NOT be exposed
            },
            DecryptedField {
                name: Some("bool_field".to_string()),
                value: Some(Zeroizing::new("true".to_string())),
                field_type: 2, // boolean — exposed as public with custom. prefix
            },
        ];

        let meta = BitwardenBackend::cipher_to_meta("test-backend", &dc);
        // Text fields exposed with custom. prefix
        assert_eq!(
            meta.attributes.get("custom.api_key_label"),
            Some(&"visible-value".to_string())
        );
        // Hidden fields excluded entirely
        assert!(!meta.attributes.contains_key("custom.secret_field"));
        assert!(!meta.attributes.contains_key("secret_field"));
        // Boolean fields exposed as public with custom. prefix
        assert_eq!(
            meta.attributes.get("custom.bool_field"),
            Some(&"true".to_string())
        );
        // Bare names (without prefix) should not exist
        assert!(!meta.attributes.contains_key("api_key_label"));
        assert!(!meta.attributes.contains_key("bool_field"));
    }

    #[test]
    fn cipher_to_meta_no_dates() {
        let mut dc = make_cipher(CipherType::Login);
        dc.creation_date = None;
        dc.revision_date = None;

        let meta = BitwardenBackend::cipher_to_meta("test-backend", &dc);
        assert!(meta.created.is_none());
        assert!(meta.modified.is_none());
    }

    // --- get_primary_secret ---

    #[test]
    fn get_primary_secret_login_password() {
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: Some(Zeroizing::new("user".to_string())),
            password: Some(Zeroizing::new("my-password".to_string())),
            totp: None,
            uris: Vec::new(),
        });

        let secret = BitwardenBackend::get_primary_secret(&dc);
        assert!(secret.is_some());
        assert_eq!(secret.unwrap().as_slice(), b"my-password");
    }

    #[test]
    fn get_primary_secret_login_no_password() {
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: Some(Zeroizing::new("user".to_string())),
            password: None,
            totp: None,
            uris: Vec::new(),
        });

        assert!(BitwardenBackend::get_primary_secret(&dc).is_none());
    }

    #[test]
    fn get_primary_secret_secure_note() {
        let mut dc = make_cipher(CipherType::SecureNote);
        dc.notes = Some(Zeroizing::new("my secret note".to_string()));

        let secret = BitwardenBackend::get_primary_secret(&dc);
        assert!(secret.is_some());
        assert_eq!(secret.unwrap().as_slice(), b"my secret note");
    }

    #[test]
    fn get_primary_secret_card_number() {
        let mut dc = make_cipher(CipherType::Card);
        dc.card = Some(DecryptedCard {
            cardholder_name: Some(Zeroizing::new("Test".to_string())),
            number: Some(Zeroizing::new("4111111111111111".to_string())),
            brand: None,
            exp_month: None,
            exp_year: None,
            code: None,
        });

        let secret = BitwardenBackend::get_primary_secret(&dc);
        assert!(secret.is_some());
        assert_eq!(secret.unwrap().as_slice(), b"4111111111111111");
    }

    #[test]
    fn get_primary_secret_ssh_key() {
        let mut dc = make_cipher(CipherType::SshKey);
        dc.ssh_key = Some(DecryptedSshKey {
            private_key: Some(Zeroizing::new(
                "-----BEGIN RSA PRIVATE KEY-----".to_string(),
            )),
            public_key: Some("ssh-rsa AAAA...".to_string()),
            fingerprint: None,
        });

        let secret = BitwardenBackend::get_primary_secret(&dc);
        assert!(secret.is_some());
        assert_eq!(
            secret.unwrap().as_slice(),
            b"-----BEGIN RSA PRIVATE KEY-----"
        );
    }

    #[test]
    fn get_primary_secret_ssh_key_falls_back_to_notes() {
        let mut dc = make_cipher(CipherType::SshKey);
        dc.ssh_key = Some(DecryptedSshKey {
            private_key: None,
            public_key: Some("ssh-rsa AAAA...".to_string()),
            fingerprint: None,
        });
        dc.notes = Some(Zeroizing::new("fallback note".to_string()));

        let secret = BitwardenBackend::get_primary_secret(&dc);
        assert!(secret.is_some());
        assert_eq!(secret.unwrap().as_slice(), b"fallback note");
    }

    #[test]
    fn get_primary_secret_identity_uses_notes() {
        let mut dc = make_cipher(CipherType::Identity);
        dc.notes = Some(Zeroizing::new("identity notes".to_string()));

        let secret = BitwardenBackend::get_primary_secret(&dc);
        assert!(secret.is_some());
        assert_eq!(secret.unwrap().as_slice(), b"identity notes");
    }

    #[test]
    fn get_primary_secret_none_when_empty() {
        let dc = make_cipher(CipherType::Login);
        // No login data at all
        assert!(BitwardenBackend::get_primary_secret(&dc).is_none());
    }

    #[test]
    fn get_primary_secret_login_falls_back_to_totp() {
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: Some(Zeroizing::new("user".to_string())),
            password: None,
            totp: Some(Zeroizing::new("otpauth://totp/test".to_string())),
            uris: Vec::new(),
        });

        let secret = BitwardenBackend::get_primary_secret(&dc);
        assert!(secret.is_some());
        assert_eq!(secret.unwrap().as_slice(), b"otpauth://totp/test");
    }

    #[test]
    fn get_primary_secret_login_falls_back_to_notes() {
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: Some(Zeroizing::new("user".to_string())),
            password: None,
            totp: None,
            uris: Vec::new(),
        });
        dc.notes = Some(Zeroizing::new("login notes fallback".to_string()));

        let secret = BitwardenBackend::get_primary_secret(&dc);
        assert!(secret.is_some());
        assert_eq!(secret.unwrap().as_slice(), b"login notes fallback");
    }

    #[test]
    fn get_primary_secret_login_prefers_password_over_totp() {
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: None,
            password: Some(Zeroizing::new("the-password".to_string())),
            totp: Some(Zeroizing::new("the-totp".to_string())),
            uris: Vec::new(),
        });
        dc.notes = Some(Zeroizing::new("the-notes".to_string()));

        let secret = BitwardenBackend::get_primary_secret(&dc);
        assert!(secret.is_some());
        assert_eq!(secret.unwrap().as_slice(), b"the-password");
    }

    // --- available_attributes ---

    #[test]
    fn available_attributes_returns_non_empty_catalogue() {
        assert!(!BITWARDEN_ATTRIBUTES.is_empty());
        // Spot-check a few well-known entries
        let names: Vec<&str> = BITWARDEN_ATTRIBUTES.iter().map(|a| a.name).collect();
        assert!(names.contains(&"password"));
        assert!(names.contains(&"username"));
        assert!(names.contains(&"notes"));
        assert!(names.contains(&"number"));
        assert!(names.contains(&"private_key"));
        assert!(names.contains(&"ssn"));
    }

    #[test]
    fn available_attributes_notes_is_sensitive_and_common() {
        let notes = BITWARDEN_ATTRIBUTES
            .iter()
            .find(|a| a.name == "notes")
            .expect("notes descriptor must exist");
        assert!(notes.sensitive);
        assert!(notes.item_types.is_empty(), "notes applies to all types");
    }

    #[test]
    fn available_attributes_username_login_is_public() {
        let login_username = BITWARDEN_ATTRIBUTES
            .iter()
            .find(|a| a.name == "username" && a.item_types.contains(&"login"))
            .expect("login username descriptor must exist");
        assert!(!login_username.sensitive);
    }

    #[test]
    fn available_attributes_identity_username_is_sensitive() {
        let ident_username = BITWARDEN_ATTRIBUTES
            .iter()
            .find(|a| a.name == "username" && a.item_types.contains(&"identity"))
            .expect("identity username descriptor must exist");
        assert!(ident_username.sensitive);
    }

    // --- build_item_attributes ---

    #[test]
    fn build_item_attributes_login() {
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: Some(Zeroizing::new("alice".to_string())),
            password: Some(Zeroizing::new("secret123".to_string())),
            totp: Some(Zeroizing::new("otpauth://totp/test".to_string())),
            uris: vec!["https://example.com".to_string()],
        });
        dc.notes = Some(Zeroizing::new("some notes".to_string()));

        let attrs = BitwardenBackend::build_item_attributes("bw", &dc);

        // Public attrs
        assert_eq!(attrs.public.get("type"), Some(&"login".to_string()));
        assert_eq!(attrs.public.get("username"), Some(&"alice".to_string()));
        assert_eq!(
            attrs.public.get("uri"),
            Some(&"https://example.com".to_string())
        );
        assert_eq!(attrs.public.get("backend_id"), Some(&"bw".to_string()));
        // Sensitive attrs must NOT be in public
        assert!(!attrs.public.contains_key("password"));
        assert!(!attrs.public.contains_key("totp"));
        assert!(!attrs.public.contains_key("notes"));

        // Secret names
        assert!(attrs.secret_names.contains(&"password".to_string()));
        assert!(attrs.secret_names.contains(&"totp".to_string()));
        assert!(attrs.secret_names.contains(&"notes".to_string()));
        // username should NOT be in secret_names (it's public for login)
        assert!(!attrs.secret_names.contains(&"username".to_string()));
    }

    #[test]
    fn build_item_attributes_login_minimal() {
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: None,
            password: None,
            totp: None,
            uris: Vec::new(),
        });

        let attrs = BitwardenBackend::build_item_attributes("bw", &dc);
        assert_eq!(attrs.public.get("type"), Some(&"login".to_string()));
        assert!(!attrs.public.contains_key("username"));
        assert!(!attrs.public.contains_key("uri"));
        assert!(attrs.secret_names.is_empty());
    }

    #[test]
    fn build_item_attributes_card() {
        let mut dc = make_cipher(CipherType::Card);
        dc.card = Some(DecryptedCard {
            cardholder_name: Some(Zeroizing::new("John Doe".to_string())),
            number: Some(Zeroizing::new("4111111111111111".to_string())),
            brand: Some("Visa".to_string()),
            exp_month: Some(Zeroizing::new("12".to_string())),
            exp_year: Some(Zeroizing::new("2028".to_string())),
            code: Some(Zeroizing::new("123".to_string())),
        });

        let attrs = BitwardenBackend::build_item_attributes("bw", &dc);

        // brand is public
        assert_eq!(attrs.public.get("brand"), Some(&"Visa".to_string()));
        // All card data fields are sensitive
        assert!(!attrs.public.contains_key("cardholder"));
        assert!(!attrs.public.contains_key("number"));
        assert!(!attrs.public.contains_key("exp_month"));
        assert!(!attrs.public.contains_key("exp_year"));
        assert!(!attrs.public.contains_key("code"));

        assert!(attrs.secret_names.contains(&"cardholder".to_string()));
        assert!(attrs.secret_names.contains(&"number".to_string()));
        assert!(attrs.secret_names.contains(&"exp_month".to_string()));
        assert!(attrs.secret_names.contains(&"exp_year".to_string()));
        assert!(attrs.secret_names.contains(&"code".to_string()));
    }

    #[test]
    fn build_item_attributes_ssh_key() {
        let mut dc = make_cipher(CipherType::SshKey);
        dc.ssh_key = Some(DecryptedSshKey {
            private_key: Some(Zeroizing::new(
                "-----BEGIN RSA PRIVATE KEY-----".to_string(),
            )),
            public_key: Some("ssh-rsa AAAA...".to_string()),
            fingerprint: Some("SHA256:abc123".to_string()),
        });

        let attrs = BitwardenBackend::build_item_attributes("bw", &dc);

        // public_key and fingerprint are public
        assert_eq!(
            attrs.public.get("public_key"),
            Some(&"ssh-rsa AAAA...".to_string())
        );
        assert_eq!(
            attrs.public.get("fingerprint"),
            Some(&"SHA256:abc123".to_string())
        );
        // private_key is sensitive
        assert!(!attrs.public.contains_key("private_key"));
        assert!(attrs.secret_names.contains(&"private_key".to_string()));
    }

    #[test]
    fn build_item_attributes_identity() {
        let mut dc = make_cipher(CipherType::Identity);
        dc.identity = Some(DecryptedIdentity {
            title: Some(Zeroizing::new("Mr".to_string())),
            first_name: Some(Zeroizing::new("John".to_string())),
            middle_name: None,
            last_name: Some(Zeroizing::new("Doe".to_string())),
            username: Some(Zeroizing::new("jdoe".to_string())),
            company: Some(Zeroizing::new("ACME".to_string())),
            ssn: Some(Zeroizing::new("123-45-6789".to_string())),
            passport_number: None,
            license_number: None,
            email: Some(Zeroizing::new("john@example.com".to_string())),
            phone: Some(Zeroizing::new("+1234567890".to_string())),
            address1: Some(Zeroizing::new("123 Main St".to_string())),
            address2: None,
            address3: None,
            city: Some(Zeroizing::new("Springfield".to_string())),
            state: Some(Zeroizing::new("IL".to_string())),
            postal_code: Some(Zeroizing::new("62701".to_string())),
            country: Some(Zeroizing::new("US".to_string())),
        });

        let attrs = BitwardenBackend::build_item_attributes("bw", &dc);

        // ALL identity fields are sensitive — none in public
        assert!(!attrs.public.contains_key("title"));
        assert!(!attrs.public.contains_key("first_name"));
        assert!(!attrs.public.contains_key("last_name"));
        assert!(!attrs.public.contains_key("username"));
        assert!(!attrs.public.contains_key("ssn"));
        assert!(!attrs.public.contains_key("email"));
        assert!(!attrs.public.contains_key("phone"));
        assert!(!attrs.public.contains_key("address1"));
        assert!(!attrs.public.contains_key("city"));
        assert!(!attrs.public.contains_key("state"));
        assert!(!attrs.public.contains_key("postal_code"));
        assert!(!attrs.public.contains_key("country"));
        assert!(!attrs.public.contains_key("company"));

        // Secret names include all present fields
        assert!(attrs.secret_names.contains(&"title".to_string()));
        assert!(attrs.secret_names.contains(&"first_name".to_string()));
        assert!(attrs.secret_names.contains(&"last_name".to_string()));
        assert!(attrs.secret_names.contains(&"username".to_string()));
        assert!(attrs.secret_names.contains(&"company".to_string()));
        assert!(attrs.secret_names.contains(&"ssn".to_string()));
        assert!(attrs.secret_names.contains(&"email".to_string()));
        assert!(attrs.secret_names.contains(&"phone".to_string()));
        assert!(attrs.secret_names.contains(&"address1".to_string()));
        assert!(attrs.secret_names.contains(&"city".to_string()));
        assert!(attrs.secret_names.contains(&"state".to_string()));
        assert!(attrs.secret_names.contains(&"postal_code".to_string()));
        assert!(attrs.secret_names.contains(&"country".to_string()));
        // None fields should NOT be in secret_names
        assert!(!attrs.secret_names.contains(&"middle_name".to_string()));
        assert!(!attrs.secret_names.contains(&"passport_number".to_string()));
        assert!(!attrs.secret_names.contains(&"license_number".to_string()));
        assert!(!attrs.secret_names.contains(&"address2".to_string()));
        assert!(!attrs.secret_names.contains(&"address3".to_string()));
    }

    #[test]
    fn build_item_attributes_secure_note() {
        let mut dc = make_cipher(CipherType::SecureNote);
        dc.notes = Some(Zeroizing::new("my secret note".to_string()));

        let attrs = BitwardenBackend::build_item_attributes("bw", &dc);

        assert_eq!(
            attrs.public.get("xdg:schema"),
            Some(&"org.freedesktop.Secret.Note".to_string())
        );
        assert_eq!(attrs.public.get("type"), Some(&"note".to_string()));
        assert!(!attrs.public.contains_key("notes"));
        assert!(attrs.secret_names.contains(&"notes".to_string()));
    }

    #[test]
    fn build_item_attributes_custom_fields() {
        let mut dc = make_cipher(CipherType::Login);
        dc.fields = vec![
            DecryptedField {
                name: Some("api_key".to_string()),
                value: Some(Zeroizing::new("visible".to_string())),
                field_type: 0, // text — public with custom. prefix
            },
            DecryptedField {
                name: Some("secret_token".to_string()),
                value: Some(Zeroizing::new("hidden-val".to_string())),
                field_type: 1, // hidden — sensitive with custom. prefix
            },
            DecryptedField {
                name: Some("enabled".to_string()),
                value: Some(Zeroizing::new("true".to_string())),
                field_type: 2, // boolean — public with custom. prefix
            },
            DecryptedField {
                name: None, // nameless field — skipped
                value: Some(Zeroizing::new("orphan".to_string())),
                field_type: 0,
            },
        ];

        let attrs = BitwardenBackend::build_item_attributes("bw", &dc);

        // Text field → public
        assert_eq!(
            attrs.public.get("custom.api_key"),
            Some(&"visible".to_string())
        );
        // Hidden field → sensitive
        assert!(!attrs.public.contains_key("custom.secret_token"));
        assert!(
            attrs
                .secret_names
                .contains(&"custom.secret_token".to_string())
        );
        // Boolean field → public
        assert_eq!(
            attrs.public.get("custom.enabled"),
            Some(&"true".to_string())
        );
        // Nameless field → skipped
        assert!(!attrs.public.contains_key("custom."));
    }

    #[test]
    fn build_item_attributes_folder_and_org() {
        let mut dc = make_cipher(CipherType::Login);
        dc.folder_name = Some("Work".to_string());
        dc.organization_id = Some("org-abc".to_string());

        let attrs = BitwardenBackend::build_item_attributes("bw", &dc);
        assert_eq!(attrs.public.get("folder"), Some(&"Work".to_string()));
        assert_eq!(attrs.public.get("org_id"), Some(&"org-abc".to_string()));
    }

    // --- resolve_secret_attr ---

    #[test]
    fn resolve_secret_attr_notes_common() {
        let mut dc = make_cipher(CipherType::Login);
        dc.notes = Some(Zeroizing::new("my notes".to_string()));

        let result = BitwardenBackend::resolve_secret_attr(&dc, "notes");
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), b"my notes");
    }

    #[test]
    fn resolve_secret_attr_notes_missing() {
        let dc = make_cipher(CipherType::Login);
        assert!(BitwardenBackend::resolve_secret_attr(&dc, "notes").is_none());
    }

    #[test]
    fn resolve_secret_attr_login_password() {
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: Some(Zeroizing::new("user".to_string())),
            password: Some(Zeroizing::new("pw123".to_string())),
            totp: None,
            uris: Vec::new(),
        });

        let result = BitwardenBackend::resolve_secret_attr(&dc, "password");
        assert_eq!(result.unwrap().as_slice(), b"pw123");
    }

    #[test]
    fn resolve_secret_attr_login_totp() {
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: None,
            password: None,
            totp: Some(Zeroizing::new("otpauth://totp/test".to_string())),
            uris: Vec::new(),
        });

        let result = BitwardenBackend::resolve_secret_attr(&dc, "totp");
        assert_eq!(result.unwrap().as_slice(), b"otpauth://totp/test");
    }

    #[test]
    fn resolve_secret_attr_login_username_as_secret() {
        // For login, username can be retrieved as a secret attr too
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: Some(Zeroizing::new("alice".to_string())),
            password: None,
            totp: None,
            uris: Vec::new(),
        });

        let result = BitwardenBackend::resolve_secret_attr(&dc, "username");
        assert_eq!(result.unwrap().as_slice(), b"alice");
    }

    #[test]
    fn resolve_secret_attr_login_nonexistent() {
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: None,
            password: None,
            totp: None,
            uris: Vec::new(),
        });

        assert!(BitwardenBackend::resolve_secret_attr(&dc, "number").is_none());
        assert!(BitwardenBackend::resolve_secret_attr(&dc, "bogus").is_none());
    }

    #[test]
    fn resolve_secret_attr_card_all_fields() {
        let mut dc = make_cipher(CipherType::Card);
        dc.card = Some(DecryptedCard {
            cardholder_name: Some(Zeroizing::new("Jane Doe".to_string())),
            number: Some(Zeroizing::new("4111111111111111".to_string())),
            brand: Some("Visa".to_string()),
            exp_month: Some(Zeroizing::new("06".to_string())),
            exp_year: Some(Zeroizing::new("2030".to_string())),
            code: Some(Zeroizing::new("999".to_string())),
        });

        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "cardholder")
                .unwrap()
                .as_slice(),
            b"Jane Doe"
        );
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "number")
                .unwrap()
                .as_slice(),
            b"4111111111111111"
        );
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "exp_month")
                .unwrap()
                .as_slice(),
            b"06"
        );
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "exp_year")
                .unwrap()
                .as_slice(),
            b"2030"
        );
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "code")
                .unwrap()
                .as_slice(),
            b"999"
        );
        // brand is not a secret attr (public only)
        assert!(BitwardenBackend::resolve_secret_attr(&dc, "brand").is_none());
    }

    #[test]
    fn resolve_secret_attr_ssh_private_key() {
        let mut dc = make_cipher(CipherType::SshKey);
        dc.ssh_key = Some(DecryptedSshKey {
            private_key: Some(Zeroizing::new(
                "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
            )),
            public_key: Some("ssh-ed25519 AAAA...".to_string()),
            fingerprint: Some("SHA256:xyz".to_string()),
        });

        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "private_key")
                .unwrap()
                .as_slice(),
            b"-----BEGIN OPENSSH PRIVATE KEY-----"
        );
        // public_key and fingerprint are not secret attrs
        assert!(BitwardenBackend::resolve_secret_attr(&dc, "public_key").is_none());
        assert!(BitwardenBackend::resolve_secret_attr(&dc, "fingerprint").is_none());
    }

    #[test]
    fn resolve_secret_attr_identity_pii_fields() {
        let mut dc = make_cipher(CipherType::Identity);
        dc.identity = Some(DecryptedIdentity {
            title: Some(Zeroizing::new("Dr".to_string())),
            first_name: Some(Zeroizing::new("Alice".to_string())),
            middle_name: Some(Zeroizing::new("B".to_string())),
            last_name: Some(Zeroizing::new("Smith".to_string())),
            username: Some(Zeroizing::new("asmith".to_string())),
            company: Some(Zeroizing::new("Widgets Inc".to_string())),
            ssn: Some(Zeroizing::new("987-65-4321".to_string())),
            passport_number: Some(Zeroizing::new("AB123456".to_string())),
            license_number: Some(Zeroizing::new("DL-789".to_string())),
            email: Some(Zeroizing::new("alice@widgets.com".to_string())),
            phone: Some(Zeroizing::new("+1-555-1234".to_string())),
            address1: Some(Zeroizing::new("456 Oak Ave".to_string())),
            address2: Some(Zeroizing::new("Suite 100".to_string())),
            address3: None,
            city: Some(Zeroizing::new("Portland".to_string())),
            state: Some(Zeroizing::new("OR".to_string())),
            postal_code: Some(Zeroizing::new("97201".to_string())),
            country: Some(Zeroizing::new("US".to_string())),
        });

        // Spot-check several identity PII fields
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "title")
                .unwrap()
                .as_slice(),
            b"Dr"
        );
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "first_name")
                .unwrap()
                .as_slice(),
            b"Alice"
        );
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "middle_name")
                .unwrap()
                .as_slice(),
            b"B"
        );
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "ssn")
                .unwrap()
                .as_slice(),
            b"987-65-4321"
        );
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "passport_number")
                .unwrap()
                .as_slice(),
            b"AB123456"
        );
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "license_number")
                .unwrap()
                .as_slice(),
            b"DL-789"
        );
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "address1")
                .unwrap()
                .as_slice(),
            b"456 Oak Ave"
        );
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "address2")
                .unwrap()
                .as_slice(),
            b"Suite 100"
        );
        assert!(BitwardenBackend::resolve_secret_attr(&dc, "address3").is_none());
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "city")
                .unwrap()
                .as_slice(),
            b"Portland"
        );
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "country")
                .unwrap()
                .as_slice(),
            b"US"
        );
    }

    #[test]
    fn resolve_secret_attr_secure_note_only_notes() {
        let mut dc = make_cipher(CipherType::SecureNote);
        dc.notes = Some(Zeroizing::new("top secret".to_string()));

        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "notes")
                .unwrap()
                .as_slice(),
            b"top secret"
        );
        // No other attrs for secure notes
        assert!(BitwardenBackend::resolve_secret_attr(&dc, "password").is_none());
    }

    #[test]
    fn resolve_secret_attr_custom_fields() {
        let mut dc = make_cipher(CipherType::Login);
        dc.fields = vec![
            DecryptedField {
                name: Some("api_key".to_string()),
                value: Some(Zeroizing::new("text-val".to_string())),
                field_type: 0,
            },
            DecryptedField {
                name: Some("secret_token".to_string()),
                value: Some(Zeroizing::new("hidden-val".to_string())),
                field_type: 1,
            },
        ];

        // Text custom field — resolve by custom. prefix
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "custom.api_key")
                .unwrap()
                .as_slice(),
            b"text-val"
        );
        // Hidden custom field — also resolvable
        assert_eq!(
            BitwardenBackend::resolve_secret_attr(&dc, "custom.secret_token")
                .unwrap()
                .as_slice(),
            b"hidden-val"
        );
        // Non-existent custom field
        assert!(BitwardenBackend::resolve_secret_attr(&dc, "custom.nope").is_none());
        // Bare name (without custom. prefix) should not resolve as custom
        assert!(BitwardenBackend::resolve_secret_attr(&dc, "api_key").is_none());
    }

    #[test]
    fn resolve_secret_attr_wrong_type_returns_none() {
        // Card cipher asked for login attrs
        let mut dc = make_cipher(CipherType::Card);
        dc.card = Some(DecryptedCard {
            cardholder_name: Some(Zeroizing::new("Jane".to_string())),
            number: None,
            brand: None,
            exp_month: None,
            exp_year: None,
            code: None,
        });

        assert!(BitwardenBackend::resolve_secret_attr(&dc, "password").is_none());
        assert!(BitwardenBackend::resolve_secret_attr(&dc, "totp").is_none());
        assert!(BitwardenBackend::resolve_secret_attr(&dc, "private_key").is_none());
    }
}
