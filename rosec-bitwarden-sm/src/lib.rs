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
//! Tokens are stored encrypted on disk and are never interactively prompted
//! after the first `backend add`.  The backend starts locked; `unlock()`
//! performs the API login and secret fetch.
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
//! `$XDG_DATA_HOME/rosec/oauth/<id>.toml`, protected by a per-installation
//! machine key at `$XDG_DATA_HOME/rosec/machine-key`.

mod api;

use std::time::SystemTime;

use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use rosec_core::{
    AuthField, AuthFieldKind, Attributes, BackendError, BackendStatus, RecoveryOutcome,
    SecretBytes, UnlockInput, VaultBackend, VaultItem, VaultItemMeta,
};
use rosec_core::credential::StorageKey;
use sha2::Sha256;
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
    bearer: String,
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
    /// Uses HKDF-SHA256 keyed with the per-installation machine key seed
    /// and the backend ID as domain separator.  No user password required —
    /// the machine key is generated once and stored at mode-0600 on disk.
    fn derive_storage_key(&self) -> Result<StorageKey, BackendError> {
        let seed = rosec_core::machine_key::load_or_create()
            .map_err(|e| BackendError::Unavailable(format!("machine key: {e}")))?;
        let (_, hkdf) = Hkdf::<Sha256>::extract(
            Some(self.config.id.as_bytes()),
            &seed,
        );
        let info = format!("rosec-sm-token-v1:{}", self.config.id);
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

    /// The "password" for SM is the access token itself — no separate master
    /// password is involved.  Leaving the field blank on a re-auth re-uses the
    /// stored token; entering a new value rotates it.
    fn password_field(&self) -> AuthField {
        AuthField {
            id: "access_token",
            label: "Access Token",
            placeholder: "Blank = use stored token; enter new token to rotate",
            required: false,
            kind: AuthFieldKind::Secret,
        }
    }

    /// SM uses `can_auto_unlock` — no interactive prompts after initial setup.
    fn can_auto_unlock(&self) -> bool {
        true
    }

    async fn status(&self) -> Result<BackendStatus, BackendError> {
        let state = self.state.lock().await;
        Ok(BackendStatus {
            locked: state.is_none(),
            last_sync: state.as_ref().and_then(|s| s.last_sync),
        })
    }

    async fn unlock(&self, input: UnlockInput) -> Result<(), BackendError> {
        // The "password" field IS the access token for SM.
        // A blank value means "re-use stored token"; non-blank saves/rotates it.
        let provided = match input {
            UnlockInput::Password(p) => p,
            other => {
                warn!(backend = %self.config.id, "SM backend got unexpected input: {:?}", other);
                return Err(BackendError::NotSupported);
            }
        };

        let storage_key = self.derive_storage_key()?;

        let token = if provided.is_empty() {
            // Re-auth with stored token.
            let cred = rosec_core::credential::load_and_decrypt(&self.config.id, &storage_key)
                .map_err(|e| BackendError::Unavailable(format!("failed to load SM token: {e}")))?
                .ok_or(BackendError::RegistrationRequired)?;
            cred.client_secret
        } else {
            // New or rotated token — encrypt and persist.
            rosec_core::credential::encrypt_and_save(
                &self.config.id,
                &storage_key,
                "access_token",
                provided.as_str(),
            )
            .map_err(|e| BackendError::Unavailable(format!("failed to save SM token: {e}")))?;
            info!(backend = %self.config.id, "SM access token saved (encrypted)");
            provided
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
        Ok(())
    }

    /// Re-fetch all secrets from the Bitwarden SM API using the stored token.
    ///
    /// Unlike `recover()`, `sync()` always performs a fresh network fetch even
    /// if the backend is already unlocked — this ensures the in-memory cache
    /// reflects any secrets added, updated, or deleted since last login.
    ///
    /// The token is read from in-memory state first (fastest path), falling
    /// back to the encrypted credential store if the backend was restarted.
    async fn sync(&self) -> Result<(), BackendError> {
        // Read the in-memory token first; fall back to disk.
        let token = {
            let guard = self.access_token.lock().await;
            guard.as_deref().map(|t| Zeroizing::new(t.to_string()))
        };

        let token = match token {
            Some(t) => t,
            None => {
                let storage_key = self.derive_storage_key()?;
                match rosec_core::credential::load_and_decrypt(&self.config.id, &storage_key) {
                    Ok(Some(cred)) => cred.client_secret,
                    Ok(None) => return Err(BackendError::Locked),
                    Err(e) => return Err(BackendError::Unavailable(
                        format!("failed to load SM token for sync: {e}")
                    )),
                }
            }
        };

        let auth = self.do_unlock(token.as_str()).await?;

        // Atomically replace the in-memory state.
        {
            let mut tok = self.access_token.lock().await;
            *tok = Some(token);
        }
        {
            let mut state_guard = self.state.lock().await;
            *state_guard = Some(auth);
        }

        info!(backend = %self.config.id, "SM secrets synced");
        Ok(())
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
        Ok(())
    }

    async fn recover(&self) -> Result<RecoveryOutcome, BackendError> {
        // Try in-memory token first (fastest path, avoids disk I/O).
        // Fall back to loading from the encrypted credential store so that
        // recover() works correctly after a rosecd restart.
        let token = {
            let guard = self.access_token.lock().await;
            guard.as_deref().map(|t| t.to_string())
        };

        let token = match token {
            Some(t) => Zeroizing::new(t),
            None => {
                let storage_key = match self.derive_storage_key() {
                    Ok(k) => k,
                    Err(e) => return Ok(RecoveryOutcome::Failed(e.to_string())),
                };
                match rosec_core::credential::load_and_decrypt(&self.config.id, &storage_key) {
                    Ok(Some(cred)) => cred.client_secret,
                    Ok(None) => return Ok(RecoveryOutcome::Failed(
                        "no stored token — run `rosec backend auth`".to_string()
                    )),
                    Err(e) => return Ok(RecoveryOutcome::Failed(e)),
                }
            }
        };

        match self.do_unlock(token.as_str()).await {
            Ok(auth) => {
                {
                    let mut tok = self.access_token.lock().await;
                    *tok = Some(token);
                }
                let mut state_guard = self.state.lock().await;
                *state_guard = Some(auth);
                Ok(RecoveryOutcome::Recovered)
            }
            Err(e) => Ok(RecoveryOutcome::Failed(e.to_string())),
        }
    }

    fn last_synced_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        // Use `try_lock` so this never blocks on a hot path — if the state
        // mutex is held by an ongoing sync, we just return the cached value
        // from the last time we could read it.  Callers tolerate a slightly
        // stale timestamp here.
        self.state.try_lock().ok().and_then(|g| g.as_ref().map(|s| s.last_synced_at))
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
        let (bearer, last_synced_at) = {
            let guard = self.state.lock().await;
            match guard.as_ref() {
                Some(s) => (s.bearer.clone(), s.last_synced_at),
                // Backend is locked — no state yet, assume changed.
                None => return Ok(true),
            }
        };

        let org_id = Uuid::parse_str(&self.config.organization_id).map_err(|e| {
            BackendError::Unavailable(format!("invalid organization_id: {e}"))
        })?;

        let client = SmApiClient::new(self.urls())
            .map_err(|e| BackendError::Unavailable(format!("SM HTTP client: {e}")))?;

        let last_synced_str: String = last_synced_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        match client.check_secrets_changed(&bearer, org_id, &last_synced_str).await {
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
        Ok(auth.secrets.iter().map(|s| secret_to_meta(s, &self.config.id)).collect())
    }

    async fn get_item(&self, id: &str) -> Result<VaultItem, BackendError> {
        let state = self.state.lock().await;
        let auth = state.as_ref().ok_or(BackendError::Locked)?;
        let target_id = Uuid::parse_str(id).map_err(|_| BackendError::NotFound)?;
        let secret = auth.secrets.iter().find(|s| s.id == target_id).ok_or(BackendError::NotFound)?;
        Ok(VaultItem {
            meta: secret_to_meta(secret, &self.config.id),
            secret: Some(secret_value(secret)),
        })
    }

    async fn get_secret(&self, id: &str) -> Result<SecretBytes, BackendError> {
        let state = self.state.lock().await;
        let auth = state.as_ref().ok_or(BackendError::Locked)?;
        let target_id = Uuid::parse_str(id).map_err(|_| BackendError::NotFound)?;
        let secret = auth.secrets.iter().find(|s| s.id == target_id).ok_or(BackendError::NotFound)?;
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
    let bytes = if !secret.value.is_empty() {
        secret.value.as_bytes().to_vec()
    } else {
        secret.note.as_bytes().to_vec()
    };
    SecretBytes::new(bytes)
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
    use std::sync::Mutex;

    static TEST_ENV_MUTEX: Mutex<()> = Mutex::new(());

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
            bearer: String::new(),
        });
    }

    #[tokio::test]
    async fn starts_locked() {
        assert!(make_backend().status().await.unwrap().locked);
    }

    #[tokio::test]
    async fn list_items_when_locked_returns_error() {
        assert!(matches!(make_backend().list_items().await, Err(BackendError::Locked)));
    }

    #[tokio::test]
    async fn get_secret_when_locked_returns_error() {
        assert!(matches!(
            make_backend().get_secret("00000000-0000-0000-0000-000000000000").await,
            Err(BackendError::Locked)
        ));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn unlock_blank_token_without_stored_token_returns_registration_required() {
        // An empty token means "use stored" — if nothing is stored, RegistrationRequired.
        let tmp = std::env::temp_dir()
            .join(format!("rosec-sm-test-{}-blank", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let _guard = TEST_ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let result = make_backend()
            .unlock(UnlockInput::Password(Zeroizing::new(String::new())))
            .await;
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        drop(_guard);
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
        inject_state(&b, vec![DecryptedSecret {
            id: secret_id,
            key: "MY_API_KEY".to_string(),
            value: Zeroizing::new("s3cr3t".to_string()),
            note: Zeroizing::new("".to_string()),
            project_id: None,
            project_name: None,
        }]).await;
        let items = b.list_items().await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "MY_API_KEY");
        assert_eq!(items[0].backend_id, "test-sm");
        assert_eq!(items[0].attributes.get("sm.key").map(String::as_str), Some("MY_API_KEY"));
        assert_eq!(items[0].attributes.get("sm.id").map(String::as_str), Some(secret_id.to_string().as_str()));
    }

    #[tokio::test]
    async fn get_secret_returns_value() {
        let b = make_backend();
        let secret_id = Uuid::new_v4();
        inject_state(&b, vec![DecryptedSecret {
            id: secret_id,
            key: "DB_PASS".to_string(),
            value: Zeroizing::new("hunter2".to_string()),
            note: Zeroizing::new("".to_string()),
            project_id: None,
            project_name: None,
        }]).await;
        assert_eq!(b.get_secret(&secret_id.to_string()).await.unwrap().as_slice(), b"hunter2");
    }

    #[tokio::test]
    async fn get_secret_falls_back_to_note_when_value_empty() {
        let b = make_backend();
        let secret_id = Uuid::new_v4();
        inject_state(&b, vec![DecryptedSecret {
            id: secret_id,
            key: "NOTE_ONLY".to_string(),
            value: Zeroizing::new("".to_string()),
            note: Zeroizing::new("from-note".to_string()),
            project_id: None,
            project_name: None,
        }]).await;
        assert_eq!(b.get_secret(&secret_id.to_string()).await.unwrap().as_slice(), b"from-note");
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
        inject_state(&b, vec![
            DecryptedSecret { id: id1, key: "KEY_A".to_string(), value: Zeroizing::new("a".to_string()), note: Zeroizing::new("".to_string()), project_id: None, project_name: None },
            DecryptedSecret { id: id2, key: "KEY_B".to_string(), value: Zeroizing::new("b".to_string()), note: Zeroizing::new("".to_string()), project_id: None, project_name: None },
        ]).await;
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
        assert_eq!(meta.attributes.get("type").map(String::as_str), Some("secret"));
        assert!(meta.attributes.contains_key("sm.key"));
        assert!(meta.attributes.contains_key("sm.id"));
        assert!(meta.attributes.contains_key("sm.project_id"));
        assert_eq!(meta.attributes.get("sm.project").map(String::as_str), Some("my-project"));
    }

    #[test]
    fn can_auto_unlock_returns_true() {
        assert!(make_backend().can_auto_unlock());
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn recover_when_no_token_stored_returns_failed() {
        let tmp = std::env::temp_dir()
            .join(format!("rosec-sm-test-{}-recover", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let _guard = TEST_ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let outcome = make_backend().recover().await.unwrap();
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        drop(_guard);
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(matches!(outcome, RecoveryOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn get_item_when_locked_returns_error() {
        assert!(matches!(
            make_backend().get_item("00000000-0000-0000-0000-000000000000").await,
            Err(BackendError::Locked)
        ));
    }

    #[tokio::test]
    async fn get_item_found_and_not_found() {
        let b = make_backend();
        let secret_id = Uuid::new_v4();
        inject_state(&b, vec![DecryptedSecret {
            id: secret_id,
            key: "FOUND_KEY".to_string(),
            value: Zeroizing::new("found-value".to_string()),
            note: Zeroizing::new("".to_string()),
            project_id: None,
            project_name: None,
        }]).await;
        let item = b.get_item(&secret_id.to_string()).await.unwrap();
        assert_eq!(item.meta.label, "FOUND_KEY");
        assert_eq!(item.secret.unwrap().as_slice(), b"found-value");
        assert!(matches!(b.get_item("00000000-0000-0000-0000-000000000099").await, Err(BackendError::NotFound)));
    }

    #[tokio::test]
    async fn search_returns_empty_when_no_match() {
        let b = make_backend();
        inject_state(&b, vec![DecryptedSecret {
            id: Uuid::new_v4(),
            key: "UNRELATED".to_string(),
            value: Zeroizing::new("x".to_string()),
            note: Zeroizing::new("".to_string()),
            project_id: None,
            project_name: None,
        }]).await;
        let mut query = Attributes::new();
        query.insert("sm.key".to_string(), "DOES_NOT_EXIST".to_string());
        assert!(b.search(&query).await.unwrap().is_empty());
    }
}
