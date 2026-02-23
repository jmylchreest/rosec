//! Bitwarden Secrets Manager backend for rosec.
//!
//! # License
//!
//! This crate uses the [Bitwarden SDK](https://github.com/bitwarden/sdk-sm), which is
//! distributed under the **Bitwarden SDK License Agreement v1** — a proprietary license
//! that is **not** OSI-approved.  The rest of the rosec workspace is MIT-licensed.
//!
//! Distro packagers who cannot ship proprietary code should exclude this crate by not
//! enabling the `bitwarden-sm` workspace feature in `rosecd`.
//!
//! # Authentication
//!
//! SM uses *machine account access tokens* — not Bitwarden master passwords.
//! The token format is:
//! ```text
//! 0.{service-account-uuid}.{client_secret}:{base64_encryption_key}
//! ```
//! Tokens are provided as `UnlockInput::SessionToken` and are never interactively
//! prompted.  The backend starts locked; `unlock()` performs the SDK login.
//!
//! # Configuration
//!
//! ```toml
//! [[backend]]
//! id       = "my-sm"
//! kind     = "bitwarden-sm"
//!
//! [backend.options]
//! access_token    = "0.uuid.secret:key"   # required — Zeroizing in memory
//! organization_id = "00000000-…"          # required — filters which secrets to expose
//! server_url      = "https://…"           # optional — omit for official cloud
//! ```

use std::time::SystemTime;

use hkdf::Hkdf;
use rosec_core::{
    AuthField, AuthFieldKind, Attributes, BackendError, BackendStatus, RecoveryOutcome,
    RegistrationInfo, SecretBytes, UnlockInput, VaultBackend, VaultItem, VaultItemMeta,
};
use rosec_core::credential::StorageKey;
use sha2::Sha256;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use bitwarden::{
    auth::login::AccessTokenLoginRequest,
    secrets_manager::{
        secrets::{SecretIdentifiersRequest, SecretsGetRequest},
        ClientSecretsExt,
    },
    Client, ClientSettings, DeviceType,
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for the Bitwarden SM backend.
#[derive(Debug, Clone)]
pub struct SmConfig {
    /// Backend instance ID (used as `VaultBackend::id()`).
    pub id: String,
    /// Optional human-readable name.
    pub name: Option<String>,
    /// Optional base URL for a self-hosted instance.
    pub server_url: Option<String>,
    /// SM organisation UUID — restricts which secrets are fetched.
    pub organization_id: String,
}

// ---------------------------------------------------------------------------
// Internal auth state
// ---------------------------------------------------------------------------

/// State present after a successful `login_access_token` call.
struct AuthState {
    /// The authenticated SDK client — retained for future refresh/sync support.
    #[allow(dead_code)]
    client: Client,
    /// Cached vault items (key → meta + secret).
    secrets: Vec<SmSecret>,
    /// Timestamp of last successful sync.
    last_sync: Option<SystemTime>,
}

/// A decrypted secret fetched from the SM API.
struct SmSecret {
    id: Uuid,
    key: String,
    value: Zeroizing<String>,
    note: Zeroizing<String>,
    project_id: Option<Uuid>,
}

impl std::fmt::Debug for SmSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmSecret")
            .field("id", &self.id)
            .field("key", &self.key)
            .field("value", &"[redacted]")
            .field("note", &"[redacted]")
            .field("project_id", &self.project_id)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Bitwarden Secrets Manager backend.
///
/// Starts locked.  Call `unlock(UnlockInput::SessionToken(token))` to
/// authenticate; the token is scrubbed from memory on drop.
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

    /// Build SDK `ClientSettings` from config, if a custom server URL is set.
    fn client_settings(&self) -> Option<ClientSettings> {
        self.config.server_url.as_ref().map(|base| {
            let base = base.trim_end_matches('/');
            ClientSettings {
                identity_url: format!("{base}/identity"),
                api_url: format!("{base}/api"),
                user_agent: "rosec".to_string(),
                device_type: DeviceType::SDK,
                device_identifier: None,
                bitwarden_package_type: None,
                bitwarden_client_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }
        })
    }

    /// Derive the 64-byte storage key for this SM backend.
    ///
    /// Uses HKDF-SHA256 with the user-supplied password as the input key material
    /// and the backend ID as a domain-separator in the info string.
    ///
    /// Unlike Bitwarden PM, SM has no server-side KDF for the password — this
    /// password is used *only* locally to protect the stored access token.
    fn derive_storage_key(&self, password: &str) -> Result<StorageKey, BackendError> {
        // Use HKDF with the raw password bytes as IKM (no pre-existing PRK).
        // Salt is the backend ID bytes to scope the key per-backend.
        let (_, hkdf) = Hkdf::<Sha256>::extract(
            Some(self.config.id.as_bytes()),
            password.as_bytes(),
        );
        let info = format!("rosec-sm-token-v1:{}", self.config.id);
        let mut key_material = zeroize::Zeroizing::new(vec![0u8; 64]);
        hkdf.expand(info.as_bytes(), &mut key_material)
            .map_err(|e| BackendError::Unavailable(format!("SM key derivation failed: {e}")))?;
        StorageKey::from_bytes(&key_material)
            .map_err(|e| BackendError::Unavailable(format!("SM storage key: {e}")))
    }

    /// Perform the SDK login + secrets fetch.
    async fn do_unlock(&self, token: &str) -> Result<AuthState, BackendError> {
        let org_id = Uuid::parse_str(&self.config.organization_id).map_err(|e| {
            BackendError::Unavailable(format!(
                "invalid organization_id '{}': {e}",
                self.config.organization_id
            ))
        })?;

        let client = Client::new(self.client_settings());

        client
            .auth()
            .login_access_token(&AccessTokenLoginRequest {
                access_token: token.to_string(),
                state_file: None,
            })
            .await
            .map_err(|e| BackendError::Unavailable(format!("SM login failed: {e}")))?;

        info!(backend = %self.config.id, "SM access token authenticated");

        // List all secret identifiers for the organisation
        let identifiers = client
            .secrets()
            .list(&SecretIdentifiersRequest {
                organization_id: org_id,
            })
            .await
            .map_err(|e| BackendError::Unavailable(format!("SM list secrets failed: {e}")))?;

        debug!(
            backend = %self.config.id,
            count = identifiers.data.len(),
            "SM secret identifiers fetched"
        );

        let secrets = if identifiers.data.is_empty() {
            Vec::new()
        } else {
            let ids: Vec<Uuid> = identifiers.data.iter().map(|s| s.id).collect();
            let response = client
                .secrets()
                .get_by_ids(SecretsGetRequest { ids })
                .await
                .map_err(|e| BackendError::Unavailable(format!("SM get secrets failed: {e}")))?;

            response
                .data
                .into_iter()
                .map(|s| SmSecret {
                    id: s.id,
                    key: s.key,
                    value: Zeroizing::new(s.value),
                    note: Zeroizing::new(s.note),
                    project_id: s.project_id,
                })
                .collect()
        };

        info!(
            backend = %self.config.id,
            count = secrets.len(),
            "SM secrets loaded"
        );

        Ok(AuthState {
            client,
            secrets,
            last_sync: Some(SystemTime::now()),
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

    fn password_field(&self) -> AuthField {
        AuthField {
            id: "password",
            label: "Key encryption password",
            placeholder: "Password used locally to protect the stored access token",
            required: true,
            kind: AuthFieldKind::Password,
        }
    }

    fn registration_info(&self) -> Option<RegistrationInfo> {
        static INFO: RegistrationInfo = RegistrationInfo {
            instructions: "\
Provide the Bitwarden Secrets Manager machine account access token.\n\n\
Find it at: Bitwarden web vault → Secrets Manager → Machine Accounts → \
<your account> → Access Tokens → Create",
            fields: &[
                AuthField {
                    id: "access_token",
                    label: "Access Token",
                    placeholder: "0.uuid.client_secret:base64_key",
                    required: true,
                    kind: AuthFieldKind::Secret,
                },
            ],
        };
        Some(INFO)
    }

    async fn status(&self) -> Result<BackendStatus, BackendError> {
        let state = self.state.lock().await;
        Ok(BackendStatus {
            locked: state.is_none(),
            last_sync: state.as_ref().and_then(|s| s.last_sync),
        })
    }

    async fn unlock(&self, input: UnlockInput) -> Result<(), BackendError> {
        let (password, registration) = match input {
            UnlockInput::Password(p) => (p, None),
            UnlockInput::WithRegistration { password, registration_fields } => {
                (password, Some(registration_fields))
            }
            other => {
                warn!(backend = %self.config.id, "SM backend got unexpected input: {:?}", other);
                return Err(BackendError::NotSupported);
            }
        };

        let storage_key = self.derive_storage_key(&password)?;

        let token = if let Some(reg_fields) = registration {
            // First-time: user supplied the access token — encrypt and persist it.
            let raw_token = reg_fields
                .get("access_token")
                .ok_or_else(|| BackendError::Unavailable("missing access_token field".to_string()))?
                .clone();

            rosec_core::credential::encrypt_and_save(
                &self.config.id,
                &storage_key,
                // SM uses "access_token" as both client_id and the secret blob.
                "access_token",
                raw_token.as_str(),
            )
            .map_err(|e| BackendError::Unavailable(format!("failed to save SM token: {e}")))?;

            info!(backend = %self.config.id, "SM access token saved (encrypted)");
            raw_token
        } else {
            // Subsequent unlock: load and decrypt the stored token.
            let cred = rosec_core::credential::load_and_decrypt(&self.config.id, &storage_key)
                .map_err(|e| BackendError::Unavailable(format!("failed to load SM token: {e}")))?
                .ok_or(BackendError::RegistrationRequired)?;
            cred.client_secret
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
        // Re-authenticate using the in-memory token from the last successful unlock.
        // The encrypted-on-disk token requires the user password to decrypt, so
        // recovery can only proceed if the token is already held in memory.
        let token = {
            let token_guard = self.access_token.lock().await;
            match token_guard.as_deref() {
                Some(t) => t.to_string(),
                None => return Ok(RecoveryOutcome::Failed("no in-memory token (re-auth required)".to_string())),
            }
        };

        match self.do_unlock(&token) .await {
            Ok(auth) => {
                let mut state_guard = self.state.lock().await;
                *state_guard = Some(auth);
                Ok(RecoveryOutcome::Recovered)
            }
            Err(e) => Ok(RecoveryOutcome::Failed(e.to_string())),
        }
    }

    async fn list_items(&self) -> Result<Vec<VaultItemMeta>, BackendError> {
        let state = self.state.lock().await;
        let auth = state.as_ref().ok_or(BackendError::Locked)?;

        let items = auth
            .secrets
            .iter()
            .map(|s| secret_to_meta(s, &self.config.id))
            .collect();
        Ok(items)
    }

    async fn get_item(&self, id: &str) -> Result<VaultItem, BackendError> {
        let state = self.state.lock().await;
        let auth = state.as_ref().ok_or(BackendError::Locked)?;

        let target_id = Uuid::parse_str(id)
            .map_err(|_| BackendError::NotFound)?;

        let secret = auth
            .secrets
            .iter()
            .find(|s| s.id == target_id)
            .ok_or(BackendError::NotFound)?;

        let meta = secret_to_meta(secret, &self.config.id);
        let value = secret_value(secret);
        Ok(VaultItem {
            meta,
            secret: Some(value),
        })
    }

    async fn get_secret(&self, id: &str) -> Result<SecretBytes, BackendError> {
        let state = self.state.lock().await;
        let auth = state.as_ref().ok_or(BackendError::Locked)?;

        let target_id = Uuid::parse_str(id)
            .map_err(|_| BackendError::NotFound)?;

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

        let items = auth
            .secrets
            .iter()
            .map(|s| secret_to_meta(s, &self.config.id))
            .filter(|meta| {
                attrs
                    .iter()
                    .all(|(k, v)| meta.attributes.get(k) == Some(v))
            })
            .collect();
        Ok(items)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map an `SmSecret` to a `VaultItemMeta`.
///
/// Attributes exposed:
/// - `sm.key`          — the secret key name
/// - `sm.id`           — the secret UUID
/// - `sm.project_id`   — the project UUID (if set)
fn secret_to_meta(secret: &SmSecret, backend_id: &str) -> VaultItemMeta {
    let mut attributes = Attributes::new();
    attributes.insert("sm.key".to_string(), secret.key.clone());
    attributes.insert("sm.id".to_string(), secret.id.to_string());
    if let Some(pid) = secret.project_id {
        attributes.insert("sm.project_id".to_string(), pid.to_string());
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

/// Primary secret for an SM secret: `value`, falling back to `note` if value
/// is empty, consistent with the existing Bitwarden PM backend behaviour.
fn secret_value(secret: &SmSecret) -> SecretBytes {
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

    fn make_backend() -> SmBackend {
        SmBackend::new(SmConfig {
            id: "test-sm".to_string(),
            name: Some("Test SM".to_string()),
            server_url: None,
            organization_id: "00000000-0000-0000-0000-000000000000".to_string(),
        })
    }

    #[tokio::test]
    async fn starts_locked() {
        let b = make_backend();
        let status = b.status().await.unwrap();
        assert!(status.locked);
    }

    #[tokio::test]
    async fn list_items_when_locked_returns_error() {
        let b = make_backend();
        assert!(matches!(b.list_items().await, Err(BackendError::Locked)));
    }

    #[tokio::test]
    async fn get_secret_when_locked_returns_error() {
        let b = make_backend();
        assert!(matches!(
            b.get_secret("00000000-0000-0000-0000-000000000000").await,
            Err(BackendError::Locked)
        ));
    }

    #[tokio::test]
    async fn unlock_password_without_stored_token_returns_registration_required() {
        // With the new encrypted-token flow, supplying a password when no token
        // has been stored yet returns RegistrationRequired (not Unavailable).
        let b = make_backend();
        use zeroize::Zeroizing;
        let result = b
            .unlock(UnlockInput::Password(Zeroizing::new("pw".to_string())))
            .await;
        assert!(matches!(result, Err(BackendError::RegistrationRequired)));
    }

    #[tokio::test]
    async fn lock_clears_state() {
        let b = make_backend();
        // Inject a fake auth state manually (bypass real SDK call)
        {
            let client = Client::new(None);
            let mut state = b.state.lock().await;
            *state = Some(AuthState {
                client,
                secrets: Vec::new(),
                last_sync: Some(SystemTime::now()),
            });
        }
        assert!(!b.status().await.unwrap().locked);
        b.lock().await.unwrap();
        assert!(b.status().await.unwrap().locked);
    }

    #[tokio::test]
    async fn list_items_returns_secrets_when_unlocked() {
        let b = make_backend();
        let secret_id = Uuid::new_v4();
        {
            let client = Client::new(None);
            let mut state = b.state.lock().await;
            *state = Some(AuthState {
                client,
                secrets: vec![SmSecret {
                    id: secret_id,
                    key: "MY_API_KEY".to_string(),
                    value: Zeroizing::new("s3cr3t".to_string()),
                    note: Zeroizing::new("".to_string()),
                    project_id: None,
                }],
                last_sync: Some(SystemTime::now()),
            });
        }
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
        {
            let client = Client::new(None);
            let mut state = b.state.lock().await;
            *state = Some(AuthState {
                client,
                secrets: vec![SmSecret {
                    id: secret_id,
                    key: "DB_PASS".to_string(),
                    value: Zeroizing::new("hunter2".to_string()),
                    note: Zeroizing::new("".to_string()),
                    project_id: None,
                }],
                last_sync: None,
            });
        }
        let bytes = b.get_secret(&secret_id.to_string()).await.unwrap();
        assert_eq!(bytes.as_slice(), b"hunter2");
    }

    #[tokio::test]
    async fn get_secret_falls_back_to_note_when_value_empty() {
        let b = make_backend();
        let secret_id = Uuid::new_v4();
        {
            let client = Client::new(None);
            let mut state = b.state.lock().await;
            *state = Some(AuthState {
                client,
                secrets: vec![SmSecret {
                    id: secret_id,
                    key: "NOTE_ONLY".to_string(),
                    value: Zeroizing::new("".to_string()),
                    note: Zeroizing::new("from-note".to_string()),
                    project_id: None,
                }],
                last_sync: None,
            });
        }
        let bytes = b.get_secret(&secret_id.to_string()).await.unwrap();
        assert_eq!(bytes.as_slice(), b"from-note");
    }

    #[tokio::test]
    async fn get_secret_not_found() {
        let b = make_backend();
        {
            let client = Client::new(None);
            let mut state = b.state.lock().await;
            *state = Some(AuthState {
                client,
                secrets: Vec::new(),
                last_sync: None,
            });
        }
        let result = b
            .get_secret("00000000-0000-0000-0000-000000000001")
            .await;
        assert!(matches!(result, Err(BackendError::NotFound)));
    }

    #[tokio::test]
    async fn search_filters_by_attributes() {
        let b = make_backend();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        {
            let client = Client::new(None);
            let mut state = b.state.lock().await;
            *state = Some(AuthState {
                client,
                secrets: vec![
                    SmSecret {
                        id: id1,
                        key: "KEY_A".to_string(),
                        value: Zeroizing::new("a".to_string()),
                        note: Zeroizing::new("".to_string()),
                        project_id: None,
                    },
                    SmSecret {
                        id: id2,
                        key: "KEY_B".to_string(),
                        value: Zeroizing::new("b".to_string()),
                        note: Zeroizing::new("".to_string()),
                        project_id: None,
                    },
                ],
                last_sync: None,
            });
        }
        let mut query = Attributes::new();
        query.insert("sm.key".to_string(), "KEY_A".to_string());
        let results = b.search(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].label, "KEY_A");
    }

    #[test]
    fn secret_to_meta_sets_attributes() {
        let secret = SmSecret {
            id: Uuid::nil(),
            key: "MY_SECRET".to_string(),
            value: Zeroizing::new("v".to_string()),
            note: Zeroizing::new("n".to_string()),
            project_id: Some(Uuid::nil()),
        };
        let meta = secret_to_meta(&secret, "backend-x");
        assert_eq!(meta.label, "MY_SECRET");
        assert_eq!(meta.backend_id, "backend-x");
        assert!(meta.attributes.contains_key("sm.key"));
        assert!(meta.attributes.contains_key("sm.id"));
        assert!(meta.attributes.contains_key("sm.project_id"));
    }

    #[test]
    fn can_auto_unlock_returns_false() {
        // SM now requires a password to decrypt the stored token, so it cannot
        // auto-unlock silently — the default false applies.
        let b = make_backend();
        assert!(!b.can_auto_unlock());
    }

    #[tokio::test]
    async fn recover_when_no_token_stored_returns_failed() {
        let b = make_backend();
        // Backend starts with no token — recover() should report failure without panicking.
        let outcome = b.recover().await.unwrap();
        assert!(matches!(outcome, RecoveryOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn get_item_when_locked_returns_error() {
        let b = make_backend();
        assert!(matches!(
            b.get_item("00000000-0000-0000-0000-000000000000").await,
            Err(BackendError::Locked)
        ));
    }

    #[tokio::test]
    async fn get_item_found_and_not_found() {
        let b = make_backend();
        let secret_id = Uuid::new_v4();
        {
            let client = Client::new(None);
            let mut state = b.state.lock().await;
            *state = Some(AuthState {
                client,
                secrets: vec![SmSecret {
                    id: secret_id,
                    key: "FOUND_KEY".to_string(),
                    value: Zeroizing::new("found-value".to_string()),
                    note: Zeroizing::new("".to_string()),
                    project_id: None,
                }],
                last_sync: None,
            });
        }
        // Found case
        let item = b.get_item(&secret_id.to_string()).await.unwrap();
        assert_eq!(item.meta.label, "FOUND_KEY");
        assert_eq!(item.meta.id, secret_id.to_string());
        assert!(item.secret.is_some());
        let secret_bytes = item.secret.unwrap();
        assert_eq!(secret_bytes.as_slice(), b"found-value");

        // Not-found case
        let missing = b
            .get_item("00000000-0000-0000-0000-000000000099")
            .await;
        assert!(matches!(missing, Err(BackendError::NotFound)));
    }

    #[tokio::test]
    async fn search_returns_empty_when_no_match() {
        let b = make_backend();
        {
            let client = Client::new(None);
            let mut state = b.state.lock().await;
            *state = Some(AuthState {
                client,
                secrets: vec![SmSecret {
                    id: Uuid::new_v4(),
                    key: "UNRELATED".to_string(),
                    value: Zeroizing::new("x".to_string()),
                    note: Zeroizing::new("".to_string()),
                    project_id: None,
                }],
                last_sync: None,
            });
        }
        let mut query = Attributes::new();
        query.insert("sm.key".to_string(), "DOES_NOT_EXIST".to_string());
        let results = b.search(&query).await.unwrap();
        assert!(results.is_empty());
    }
}
