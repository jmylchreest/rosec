//! Bitwarden Secrets Manager backend for rosec.
//!
//! Native implementation — no Bitwarden SDK dependency.  All HTTP requests
//! and cryptographic operations are performed directly using the same
//! `reqwest` + `aes`/`cbc`/`hmac` stack used by `rosec-bitwarden`.
//!
//! # Authentication
//!
//! SM uses *machine account access tokens* — not Bitwarden master passwords.
//! The token format is:
//! ```text
//! 0.{service-account-uuid}.{client_secret}:{base64_16_byte_enc_key_seed}
//! ```
//!
//! ## Storage key derivation
//!
//! The access token is stored encrypted at rest.  The storage key is derived
//! from **both** a machine-local secret and the user's unlock password:
//!
//! ```text
//! HKDF-SHA256(ikm: machine_secret || password, salt: backend_id) → 64-byte storage key
//! ```
//!
//! This means:
//! - A password is **always required** to unlock — there is no auto-unlock path.
//! - The same password participates in the opportunistic unlock sweep alongside
//!   Bitwarden PM backends, so users with a shared password only type it once.
//! - Wrong password → wrong storage key → decryption failure (no stored hash to
//!   compare against — the ciphertext is the proof).
//! - Changing the password or rotating the token requires re-running
//!   `rosec backend auth`.
//!
//! ## First-time setup
//!
//! `unlock()` returns `BackendError::RegistrationRequired` if no encrypted token
//! is found on disk.  The auth flow then prompts for `registration_info()` fields
//! (the access token itself) and retries with `UnlockInput::WithRegistration`.
//! The backend derives the storage key from the password, encrypts the token, and
//! persists it.  Subsequent unlocks only need the password.
//!
//! # Configuration
//!
//! ```toml
//! [[backend]]
//! id   = "my-sm"
//! kind = "bitwarden-sm"
//!
//! [backend.options]
//! organization_id = "00000000-…"   # required — filters which secrets to expose
//! server_url      = "https://…"    # optional — omit for official cloud
//! ```
//!
//! The access token is **not** stored in `config.toml`.  It is collected
//! interactively on first `rosec backend auth` and persisted encrypted at
//! `$XDG_DATA_HOME/rosec/oauth/<id>.toml`.

mod api;

use std::time::SystemTime;

use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use rosec_core::credential::StorageKey;
use rosec_core::{
    Attributes, AuthField, AuthFieldKind, BackendCallbacks, BackendError, BackendStatus,
    RegistrationInfo, SecretBytes, UnlockInput, VaultBackend, VaultItem, VaultItemMeta,
};
use sha2::Sha256;
use std::sync::RwLock;

use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use api::{AccessToken, DecryptedSecret, SmApiClient, SmUrls, fetch_secrets};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Cloud region for official Bitwarden cloud hosting.
#[derive(Debug, Clone, Default)]
pub enum SmRegion {
    #[default]
    Us,
    Eu,
}

/// Configuration for the Bitwarden SM backend.
#[derive(Debug, Clone)]
pub struct SmConfig {
    /// Backend instance ID (used as `VaultBackend::id()`).
    pub id: String,
    /// Optional human-readable name.
    pub name: Option<String>,
    /// Cloud region (`us` or `eu`) for official Bitwarden cloud.
    /// Ignored when `server_url` is set.
    pub region: SmRegion,
    /// Optional base URL for a self-hosted instance.
    /// When set, takes precedence over `region`.
    pub server_url: Option<String>,
    /// SM organisation UUID — restricts which secrets are fetched.
    pub organization_id: String,
}

// ---------------------------------------------------------------------------
// Internal auth state
// ---------------------------------------------------------------------------

/// State present after a successful login + secrets fetch.
struct AuthState {
    /// Cached vault items.
    secrets: Vec<DecryptedSecret>,
    /// Timestamp of last successful sync (legacy; kept for `BackendStatus`).
    last_sync: Option<SystemTime>,
    /// UTC timestamp of the last successful sync (used for delta-sync checks).
    last_synced_at: DateTime<Utc>,
    /// Short-lived Bearer token from the most recent login.
    /// Used by `check_remote_changed` to avoid a redundant login round-trip
    /// when the token is still fresh.  May be stale — callers must handle
    /// auth errors by falling back to a full re-login.
    bearer: Zeroizing<String>,
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Bitwarden Secrets Manager backend.
///
/// Starts locked.  Call `unlock(UnlockInput::Password(...))` to authenticate;
/// the token is scrubbed from memory on drop.
pub struct SmBackend {
    config: SmConfig,
    /// Access token stored Zeroizing so it is scrubbed on drop.
    access_token: Mutex<Option<Zeroizing<String>>>,
    /// Authenticated state; `None` when locked.
    state: Mutex<Option<AuthState>>,
    /// Lifecycle event callbacks (SSH manager, etc.).
    callbacks: RwLock<BackendCallbacks>,
}

impl std::fmt::Debug for SmBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmBackend")
            .field("id", &self.config.id)
            .field("organization_id", &self.config.organization_id)
            .finish()
    }
}

impl SmBackend {
    /// Create a new (locked) SM backend.
    pub fn new(config: SmConfig) -> Self {
        Self {
            config,
            access_token: Mutex::new(None),
            state: Mutex::new(None),
            callbacks: RwLock::new(BackendCallbacks::default()),
        }
    }

    /// Build the API client URL set from config.
    ///
    /// Priority: explicit `server_url` > `region` (eu/us) > default US cloud.
    fn urls(&self) -> SmUrls {
        if let Some(base) = &self.config.server_url {
            return SmUrls::from_base(base);
        }
        match self.config.region {
            SmRegion::Eu => SmUrls::official_eu(),
            SmRegion::Us => SmUrls::official_us(),
        }
    }

    /// Derive the 64-byte storage key for this SM backend.
    ///
    /// Uses HKDF-SHA256 with the backend ID as salt and `machine_secret ||
    /// password` as IKM.  Both factors are required: the machine secret ties
    /// the ciphertext to this installation; the password provides the
    /// interactive access-control gate.  Neither alone is sufficient.
    fn derive_storage_key(&self, password: &str) -> Result<StorageKey, BackendError> {
        let seed = rosec_core::machine_key::load_or_create()
            .map_err(|e| BackendError::Unavailable(format!("machine key: {e}")))?;
        // Concatenate machine secret and password as IKM so both are required.
        let mut ikm = Zeroizing::new(Vec::with_capacity(seed.len() + password.len()));
        ikm.extend_from_slice(&seed);
        ikm.extend_from_slice(password.as_bytes());
        let (_, hkdf) = Hkdf::<Sha256>::extract(Some(self.config.id.as_bytes()), &ikm);
        let info = format!("rosec-sm-token-v2:{}", self.config.id);
        let mut key_material = Zeroizing::new(vec![0u8; 64]);
        hkdf.expand(info.as_bytes(), &mut key_material)
            .map_err(|e| BackendError::Unavailable(format!("SM key derivation failed: {e}")))?;
        StorageKey::from_bytes(&key_material)
            .map_err(|e| BackendError::Unavailable(format!("SM storage key: {e}")))
    }

    /// Perform the API login + secrets fetch.
    async fn do_unlock(&self, raw_token: &str) -> Result<AuthState, BackendError> {
        let org_id = Uuid::parse_str(&self.config.organization_id).map_err(|e| {
            BackendError::Unavailable(format!(
                "invalid organization_id '{}': {e}",
                self.config.organization_id
            ))
        })?;

        let token = AccessToken::parse(raw_token)
            .map_err(|e| BackendError::Unavailable(format!("SM access token parse: {e}")))?;

        let client = SmApiClient::new(self.urls())
            .map_err(|e| BackendError::Unavailable(format!("SM HTTP client: {e}")))?;

        let (bearer, secrets) = fetch_secrets(&client, &token, org_id)
            .await
            .map_err(|e| BackendError::Unavailable(format!("SM login/fetch: {e}")))?;

        debug!(backend = %self.config.id, count = secrets.len(), "SM unlock complete");

        let now = Utc::now();
        Ok(AuthState {
            secrets,
            last_sync: Some(SystemTime::now()),
            last_synced_at: now,
            bearer,
        })
    }
}

#[async_trait::async_trait]
impl VaultBackend for SmBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        &self.config.id
    }

    fn name(&self) -> &str {
        self.config
            .name
            .as_deref()
            .unwrap_or("Bitwarden Secrets Manager")
    }

    fn kind(&self) -> &str {
        "bitwarden-sm"
    }

    fn set_event_callbacks(&self, callbacks: BackendCallbacks) -> Result<(), BackendError> {
        *self.callbacks.write().map_err(|_| {
            BackendError::Other(anyhow::anyhow!("callbacks lock poisoned"))
        })? = callbacks;
        Ok(())
    }

    async fn status(&self) -> Result<BackendStatus, BackendError> {
        let state = self.state.lock().await;
        Ok(BackendStatus {
            locked: state.is_none(),
            last_sync: state.as_ref().and_then(|s| s.last_sync),
        })
    }

    /// The unlock password for SM is not the access token — it is a
    /// user-chosen passphrase used to derive the storage key that protects
    /// the encrypted access token on disk.  The same password participates in
    /// the opportunistic unlock sweep alongside PM backends.
    fn password_field(&self) -> AuthField {
        AuthField {
            id: "password",
            label: "Unlock Password",
            placeholder: "Password used to protect the stored access token",
            required: true,
            kind: AuthFieldKind::Password,
        }
    }

    /// First-time setup requires the Bitwarden SM access token in addition to
    /// the unlock password.  The token is encrypted with the derived storage
    /// key and persisted to disk; subsequent unlocks only need the password.
    fn registration_info(&self) -> Option<RegistrationInfo> {
        static FIELDS: &[AuthField] = &[AuthField {
            id: "access_token",
            label: "Access Token",
            placeholder: "0.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.xxxxxxxx…",
            required: true,
            kind: AuthFieldKind::Secret,
        }];
        Some(RegistrationInfo {
            instructions: "\
This backend needs a Bitwarden Secrets Manager access token to complete setup.\n\n\
Generate a machine account access token in the Bitwarden Secrets Manager web app \
and paste it below.  The token will be encrypted with your unlock password and \
stored locally — you will not need to enter it again.",
            fields: FIELDS,
        })
    }

    /// Authenticate the SM backend.
    ///
    /// Two cases:
    ///
    /// - **`Password(pw)`** — normal unlock after initial setup.  Derives the
    ///   storage key from `pw` and the machine secret, loads the encrypted
    ///   access token from disk, decrypts it, and authenticates with Bitwarden.
    ///   Wrong password → wrong key → decryption failure.  No stored token →
    ///   `BackendError::RegistrationRequired` (first-time setup required).
    ///
    /// - **`WithRegistration { password, registration_fields }`** — first-time
    ///   setup or token rotation.  Derives the storage key from `password`,
    ///   encrypts the `access_token` from `registration_fields`, persists it,
    ///   then authenticates.
    async fn unlock(&self, input: UnlockInput) -> Result<(), BackendError> {
        let (password, token_to_save) = match input {
            UnlockInput::Password(pw) => (pw, None),
            UnlockInput::WithRegistration {
                password,
                ref registration_fields,
            } => {
                let token = registration_fields
                    .get("access_token")
                    .ok_or_else(|| {
                        BackendError::Unavailable(
                            "registration_fields missing 'access_token'".to_string(),
                        )
                    })?
                    .clone();
                (password, Some(token))
            }
            other => {
                warn!(backend = %self.config.id, "SM backend received unexpected input: {:?}", other);
                return Err(BackendError::NotSupported);
            }
        };

        let storage_key = self.derive_storage_key(password.as_str())?;

        let token = if let Some(new_token) = token_to_save {
            // First-time setup or token rotation: encrypt and persist the new token.
            rosec_core::credential::encrypt_and_save(
                &self.config.id,
                &storage_key,
                "access_token",
                new_token.as_str(),
            )
            .map_err(|e| BackendError::Unavailable(format!("failed to save SM token: {e}")))?;
            info!(backend = %self.config.id, "SM access token saved (encrypted)");
            new_token
        } else {
            // Normal unlock: derive key from password and decrypt stored token.
            // A decryption/MAC failure means the stored credential was encrypted
            // with a different key (e.g. the old machine-key-only KDF before the
            // passphrase-in-KDF change).  Treat it the same as "no credential
            // stored" — the user must re-enter the access token via the
            // registration flow.  Log the underlying reason at debug level so
            // it is visible when tracing is enabled, but do not surface it to
            // the user (it would be confusing and contains no actionable detail).
            match rosec_core::credential::load_and_decrypt(&self.config.id, &storage_key) {
                Ok(Some(cred)) => cred.client_secret,
                Ok(None) => return Err(BackendError::RegistrationRequired),
                Err(e) => {
                    debug!(backend = %self.config.id,
                        "credential decryption failed, re-registration required: {e}");
                    return Err(BackendError::RegistrationRequired);
                }
            }
        };

        let auth = self.do_unlock(token.as_str()).await?;

        {
            let mut token_guard = self.access_token.lock().await;
            *token_guard = Some(token);
        }
        {
            let mut state_guard = self.state.lock().await;
            *state_guard = Some(auth);
        }

        if let Some(cb) = self.callbacks.read().map_err(|_| {
            BackendError::Other(anyhow::anyhow!("callbacks lock poisoned"))
        })?.on_unlocked.clone() {
            cb();
        }
        Ok(())
    }

    /// Re-fetch all secrets from the Bitwarden SM API using the in-memory token.
    ///
    /// Requires the backend to be unlocked — the access token is held in memory
    /// only while unlocked (zeroized on lock/drop).  Returns
    /// `BackendError::Locked` if called while locked; the caller must unlock
    /// first.  There is no disk fallback: the password used to derive the
    /// storage key is not retained after unlock.
    async fn sync(&self) -> Result<(), BackendError> {
        let token = {
            let guard = self.access_token.lock().await;
            guard.as_deref().map(|t| Zeroizing::new(t.to_string()))
        };
        let token = token.ok_or(BackendError::Locked)?;

        // Snapshot the current secret IDs so we can detect changes after sync.
        let before_ids: std::collections::HashSet<uuid::Uuid> = {
            let guard = self.state.lock().await;
            guard
                .as_ref()
                .map(|s| s.secrets.iter().map(|x| x.id).collect())
                .unwrap_or_default()
        };

        let sync_result = self.do_unlock(token.as_str()).await;

        match sync_result {
            Ok(auth) => {
                let changed = {
                    let after_ids: std::collections::HashSet<uuid::Uuid> =
                        auth.secrets.iter().map(|x| x.id).collect();
                    after_ids != before_ids
                };

                // Atomically replace the in-memory state.
                {
                    let mut tok = self.access_token.lock().await;
                    *tok = Some(token);
                }
                {
                    let mut state_guard = self.state.lock().await;
                    *state_guard = Some(auth);
                }

                info!(backend = %self.config.id, changed, "SM secrets synced");

                if let Some(cb) = self.callbacks.read().map_err(|_| {
                    BackendError::Other(anyhow::anyhow!("callbacks lock poisoned"))
                })?.on_sync_succeeded.clone() {
                    cb(changed);
                }
                Ok(())
            }
            Err(e) => {
                if let Some(cb) = self.callbacks.read().map_err(|_| {
                    BackendError::Other(anyhow::anyhow!("callbacks lock poisoned"))
                })?.on_sync_failed.clone() {
                    cb();
                }
                Err(e)
            }
        }
    }

    async fn lock(&self) -> Result<(), BackendError> {
        {
            let mut token_guard = self.access_token.lock().await;
            *token_guard = None; // Zeroizing<String> is scrubbed on drop
        }
        {
            let mut state_guard = self.state.lock().await;
            *state_guard = None;
        }
        info!(backend = %self.config.id, "SM backend locked");

        if let Some(cb) = self.callbacks.read().map_err(|_| {
            BackendError::Other(anyhow::anyhow!("callbacks lock poisoned"))
        })?.on_locked.clone() {
            cb();
        }
        Ok(())
    }

    fn last_synced_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        // Use `try_lock` so this never blocks on a hot path — if the state
        // mutex is held by an ongoing sync, we just return the cached value
        // from the last time we could read it.  Callers tolerate a slightly
        // stale timestamp here.
        self.state
            .try_lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.last_synced_at))
    }

    /// Check whether the SM org has changed since our last sync without
    /// performing a full secrets fetch.
    ///
    /// Uses `GET /organizations/{org_id}/secrets/sync?lastSyncedDate=` which
    /// returns `{ "hasChanges": bool }`.  If the backend is locked (no cached
    /// bearer / no stored token) we re-authenticate first.  Returns `Ok(true)`
    /// on any transient error so the caller falls back to a full sync.
    async fn check_remote_changed(&self) -> Result<bool, BackendError> {
        // Snapshot the current bearer + last_synced_at under a single lock hold.
        // The clone is required: we cannot hold the mutex across the async HTTP
        // call below.  Zeroizing<String> ensures the copy is zeroed on drop.
        let (bearer, last_synced_at) = {
            let guard = self.state.lock().await;
            match guard.as_ref() {
                Some(s) => (s.bearer.clone(), s.last_synced_at),
                // Backend is locked — no state yet, assume changed.
                None => return Ok(true),
            }
        };

        let org_id = Uuid::parse_str(&self.config.organization_id)
            .map_err(|e| BackendError::Unavailable(format!("invalid organization_id: {e}")))?;

        let client = SmApiClient::new(self.urls())
            .map_err(|e| BackendError::Unavailable(format!("SM HTTP client: {e}")))?;

        let last_synced_str: String = last_synced_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        match client
            .check_secrets_changed(&bearer, org_id, &last_synced_str)
            .await
        {
            Ok(changed) => {
                debug!(backend = %self.config.id, changed, "SM delta-sync check");
                Ok(changed)
            }
            Err(e) => {
                // A 401 means the cached bearer expired — treat as changed so
                // the caller triggers a full sync (which re-authenticates).
                // Any other transient error also falls back to sync.
                debug!(backend = %self.config.id, error = %e,
                    "SM delta-sync check failed, assuming changed");
                Ok(true)
            }
        }
    }

    async fn list_items(&self) -> Result<Vec<VaultItemMeta>, BackendError> {
        let state = self.state.lock().await;
        let auth = state.as_ref().ok_or(BackendError::Locked)?;
        Ok(auth
            .secrets
            .iter()
            .map(|s| secret_to_meta(s, &self.config.id))
            .collect())
    }

    async fn get_item(&self, id: &str) -> Result<VaultItem, BackendError> {
        let state = self.state.lock().await;
        let auth = state.as_ref().ok_or(BackendError::Locked)?;
        let target_id = Uuid::parse_str(id).map_err(|_| BackendError::NotFound)?;
        let secret = auth
            .secrets
            .iter()
            .find(|s| s.id == target_id)
            .ok_or(BackendError::NotFound)?;
        Ok(VaultItem {
            meta: secret_to_meta(secret, &self.config.id),
            secret: Some(secret_value(secret)),
        })
    }

    async fn get_secret(&self, id: &str) -> Result<SecretBytes, BackendError> {
        let state = self.state.lock().await;
        let auth = state.as_ref().ok_or(BackendError::Locked)?;
        let target_id = Uuid::parse_str(id).map_err(|_| BackendError::NotFound)?;
        let secret = auth
            .secrets
            .iter()
            .find(|s| s.id == target_id)
            .ok_or(BackendError::NotFound)?;
        Ok(secret_value(secret))
    }

    async fn search(&self, attrs: &Attributes) -> Result<Vec<VaultItemMeta>, BackendError> {
        let state = self.state.lock().await;
        let auth = state.as_ref().ok_or(BackendError::Locked)?;
        Ok(auth
            .secrets
            .iter()
            .map(|s| secret_to_meta(s, &self.config.id))
            .filter(|meta| attrs.iter().all(|(k, v)| meta.attributes.get(k) == Some(v)))
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn secret_to_meta(secret: &DecryptedSecret, backend_id: &str) -> VaultItemMeta {
    let mut attributes = Attributes::new();
    attributes.insert("type".to_string(), "secret".to_string());
    attributes.insert("sm.key".to_string(), secret.key.clone());
    attributes.insert("sm.id".to_string(), secret.id.to_string());
    if let Some(pid) = secret.project_id {
        attributes.insert("sm.project_id".to_string(), pid.to_string());
    }
    if let Some(name) = &secret.project_name {
        attributes.insert("sm.project".to_string(), name.clone());
    }
    VaultItemMeta {
        id: secret.id.to_string(),
        backend_id: backend_id.to_string(),
        label: secret.key.clone(),
        attributes,
        created: None,
        modified: None,
        locked: false,
    }
}

fn secret_value(secret: &DecryptedSecret) -> SecretBytes {
    let src = if !secret.value.is_empty() {
        secret.value.as_bytes()
    } else {
        secret.note.as_bytes()
    };
    SecretBytes::from_zeroizing(Zeroizing::new(src.to_vec()))
}

// ---------------------------------------------------------------------------
// Re-export for consumers
// ---------------------------------------------------------------------------

pub use SmBackend as BitwardenSmBackend;
pub use SmConfig as BitwardenSmConfig;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// RAII guard that sets an env var for the duration of a test and restores
    /// (or removes) it on drop.  Tests that manipulate env vars must be run
    /// single-threaded (`cargo test -- --test-threads=1`) or use separate temp
    /// dirs per test to avoid interference.
    struct ScopedEnv {
        key: &'static str,
        previous: Option<String>,
    }

    fn scoped_env(key: &'static str, value: &str) -> ScopedEnv {
        let previous = std::env::var(key).ok();
        // SAFETY: tests are the only callers; env mutation is inherently
        // unsafe in multi-threaded contexts — run with --test-threads=1.
        unsafe { std::env::set_var(key, value) };
        ScopedEnv { key, previous }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            match &self.previous {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    fn make_backend() -> SmBackend {
        SmBackend::new(SmConfig {
            id: "test-sm".to_string(),
            name: Some("Test SM".to_string()),
            region: SmRegion::Us,
            server_url: None,
            organization_id: "00000000-0000-0000-0000-000000000000".to_string(),
        })
    }

    async fn inject_state(b: &SmBackend, secrets: Vec<DecryptedSecret>) {
        let mut state = b.state.lock().await;
        *state = Some(AuthState {
            secrets,
            last_sync: Some(SystemTime::now()),
            last_synced_at: chrono::Utc::now(),
            bearer: Zeroizing::new(String::new()),
        });
    }

    #[tokio::test]
    async fn starts_locked() {
        assert!(make_backend().status().await.unwrap().locked);
    }

    #[tokio::test]
    async fn list_items_when_locked_returns_error() {
        assert!(matches!(
            make_backend().list_items().await,
            Err(BackendError::Locked)
        ));
    }

    #[tokio::test]
    async fn get_secret_when_locked_returns_error() {
        assert!(matches!(
            make_backend()
                .get_secret("00000000-0000-0000-0000-000000000000")
                .await,
            Err(BackendError::Locked)
        ));
    }

    #[tokio::test]
    async fn unlock_without_stored_token_returns_registration_required() {
        // Normal unlock with no token on disk → RegistrationRequired (first-time setup).
        let tmp =
            std::env::temp_dir().join(format!("rosec-sm-test-{}-noreg", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let result = {
            let _env = scoped_env("XDG_DATA_HOME", tmp.to_str().unwrap());
            make_backend()
                .unlock(UnlockInput::Password(Zeroizing::new(
                    "my-unlock-password".to_string(),
                )))
                .await
        };
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(matches!(result, Err(BackendError::RegistrationRequired)));
    }

    #[tokio::test]
    async fn lock_clears_state() {
        let b = make_backend();
        inject_state(&b, Vec::new()).await;
        assert!(!b.status().await.unwrap().locked);
        b.lock().await.unwrap();
        assert!(b.status().await.unwrap().locked);
    }

    #[tokio::test]
    async fn list_items_returns_secrets_when_unlocked() {
        let b = make_backend();
        let secret_id = Uuid::new_v4();
        inject_state(
            &b,
            vec![DecryptedSecret {
                id: secret_id,
                key: "MY_API_KEY".to_string(),
                value: Zeroizing::new("s3cr3t".to_string()),
                note: Zeroizing::new("".to_string()),
                project_id: None,
                project_name: None,
            }],
        )
        .await;
        let items = b.list_items().await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "MY_API_KEY");
        assert_eq!(items[0].backend_id, "test-sm");
        assert_eq!(
            items[0].attributes.get("sm.key").map(String::as_str),
            Some("MY_API_KEY")
        );
        assert_eq!(
            items[0].attributes.get("sm.id").map(String::as_str),
            Some(secret_id.to_string().as_str())
        );
    }

    #[tokio::test]
    async fn get_secret_returns_value() {
        let b = make_backend();
        let secret_id = Uuid::new_v4();
        inject_state(
            &b,
            vec![DecryptedSecret {
                id: secret_id,
                key: "DB_PASS".to_string(),
                value: Zeroizing::new("hunter2".to_string()),
                note: Zeroizing::new("".to_string()),
                project_id: None,
                project_name: None,
            }],
        )
        .await;
        assert_eq!(
            b.get_secret(&secret_id.to_string())
                .await
                .unwrap()
                .as_slice(),
            b"hunter2"
        );
    }

    #[tokio::test]
    async fn get_secret_falls_back_to_note_when_value_empty() {
        let b = make_backend();
        let secret_id = Uuid::new_v4();
        inject_state(
            &b,
            vec![DecryptedSecret {
                id: secret_id,
                key: "NOTE_ONLY".to_string(),
                value: Zeroizing::new("".to_string()),
                note: Zeroizing::new("from-note".to_string()),
                project_id: None,
                project_name: None,
            }],
        )
        .await;
        assert_eq!(
            b.get_secret(&secret_id.to_string())
                .await
                .unwrap()
                .as_slice(),
            b"from-note"
        );
    }

    #[tokio::test]
    async fn get_secret_not_found() {
        let b = make_backend();
        inject_state(&b, Vec::new()).await;
        assert!(matches!(
            b.get_secret("00000000-0000-0000-0000-000000000001").await,
            Err(BackendError::NotFound)
        ));
    }

    #[tokio::test]
    async fn search_filters_by_attributes() {
        let b = make_backend();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        inject_state(
            &b,
            vec![
                DecryptedSecret {
                    id: id1,
                    key: "KEY_A".to_string(),
                    value: Zeroizing::new("a".to_string()),
                    note: Zeroizing::new("".to_string()),
                    project_id: None,
                    project_name: None,
                },
                DecryptedSecret {
                    id: id2,
                    key: "KEY_B".to_string(),
                    value: Zeroizing::new("b".to_string()),
                    note: Zeroizing::new("".to_string()),
                    project_id: None,
                    project_name: None,
                },
            ],
        )
        .await;
        let mut query = Attributes::new();
        query.insert("sm.key".to_string(), "KEY_A".to_string());
        let results = b.search(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].label, "KEY_A");
    }

    #[test]
    fn secret_to_meta_sets_attributes() {
        let secret = DecryptedSecret {
            id: Uuid::nil(),
            key: "MY_SECRET".to_string(),
            value: Zeroizing::new("v".to_string()),
            note: Zeroizing::new("n".to_string()),
            project_id: Some(Uuid::nil()),
            project_name: Some("my-project".to_string()),
        };
        let meta = secret_to_meta(&secret, "backend-x");
        assert_eq!(meta.label, "MY_SECRET");
        assert_eq!(meta.backend_id, "backend-x");
        assert_eq!(
            meta.attributes.get("type").map(String::as_str),
            Some("secret")
        );
        assert!(meta.attributes.contains_key("sm.key"));
        assert!(meta.attributes.contains_key("sm.id"));
        assert!(meta.attributes.contains_key("sm.project_id"));
        assert_eq!(
            meta.attributes.get("sm.project").map(String::as_str),
            Some("my-project")
        );
    }

    #[tokio::test]
    async fn get_item_when_locked_returns_error() {
        assert!(matches!(
            make_backend()
                .get_item("00000000-0000-0000-0000-000000000000")
                .await,
            Err(BackendError::Locked)
        ));
    }

    #[tokio::test]
    async fn get_item_found_and_not_found() {
        let b = make_backend();
        let secret_id = Uuid::new_v4();
        inject_state(
            &b,
            vec![DecryptedSecret {
                id: secret_id,
                key: "FOUND_KEY".to_string(),
                value: Zeroizing::new("found-value".to_string()),
                note: Zeroizing::new("".to_string()),
                project_id: None,
                project_name: None,
            }],
        )
        .await;
        let item = b.get_item(&secret_id.to_string()).await.unwrap();
        assert_eq!(item.meta.label, "FOUND_KEY");
        assert_eq!(item.secret.unwrap().as_slice(), b"found-value");
        assert!(matches!(
            b.get_item("00000000-0000-0000-0000-000000000099").await,
            Err(BackendError::NotFound)
        ));
    }

    #[tokio::test]
    async fn search_returns_empty_when_no_match() {
        let b = make_backend();
        inject_state(
            &b,
            vec![DecryptedSecret {
                id: Uuid::new_v4(),
                key: "UNRELATED".to_string(),
                value: Zeroizing::new("x".to_string()),
                note: Zeroizing::new("".to_string()),
                project_id: None,
                project_name: None,
            }],
        )
        .await;
        let mut query = Attributes::new();
        query.insert("sm.key".to_string(), "DOES_NOT_EXIST".to_string());
        assert!(b.search(&query).await.unwrap().is_empty());
    }
}
