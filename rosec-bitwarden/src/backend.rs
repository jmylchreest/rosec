//! VaultBackend implementation for Bitwarden.

use std::time::SystemTime;

use rosec_core::{
    Attributes, BackendError, BackendStatus, RecoveryOutcome, SecretBytes, UnlockInput,
    VaultBackend, VaultItem, VaultItemMeta,
};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::api::{ApiClient, ServerUrls, TwoFactorSubmission};
use crate::crypto;
use crate::error::BitwardenError;
use crate::vault::{CipherType, DecryptedCipher, VaultState};

/// Configuration for the Bitwarden backend.
#[derive(Debug, Clone)]
pub struct BitwardenConfig {
    /// Server base URL. If None, uses official Bitwarden cloud (US).
    pub server_url: Option<String>,
    /// User email address.
    pub email: String,
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
            .field("email", &self.config.email)
            .field("server_url", &self.config.server_url)
            .finish()
    }
}

impl BitwardenBackend {
    /// Create a new Bitwarden backend with the given configuration.
    pub fn new(config: BitwardenConfig) -> Result<Self, BitwardenError> {
        let urls = match &config.server_url {
            Some(url) => ServerUrls::from_base(url),
            None => ServerUrls::official_us(),
        };

        let api = ApiClient::new(urls)?;

        Ok(Self {
            config,
            api,
            state: Mutex::new(None),
        })
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
        let login_resp = self
            .api
            .login_password(email, &hash_b64, two_factor)
            .await?;

        let protected_key = login_resp
            .key
            .as_deref()
            .ok_or_else(|| BitwardenError::Auth("no protected key in login response".to_string()))?;

        // Step 4: Initialize vault state from protected key
        let mut vault = VaultState::new(&identity_keys, protected_key)?;

        // Step 5: Sync
        let sync = self.api.sync(&login_resp.access_token).await?;
        vault.process_sync(&sync)?;

        info!(
            ciphers = vault.ciphers().len(),
            "Bitwarden vault synced"
        );

        Ok(AuthState {
            access_token: Zeroizing::new(login_resp.access_token),
            refresh_token: login_resp.refresh_token.map(Zeroizing::new),
            vault,
        })
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
                state.access_token = Zeroizing::new(refresh_resp.access_token);
                // Capture rotated refresh token if the server issued a new one
                if let Some(new_rt) = refresh_resp.refresh_token {
                    state.refresh_token = Some(Zeroizing::new(new_rt));
                }
                info!("access token refreshed");

                // Retry sync with new token
                let sync = api.sync(&state.access_token).await?;
                state.vault.process_sync(&sync)?;
                debug!(ciphers = state.vault.ciphers().len(), "vault resynced after token refresh");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Map a decrypted cipher to a VaultItemMeta.
    fn cipher_to_meta(dc: &DecryptedCipher) -> VaultItemMeta {
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

        // Login-specific attributes
        if let Some(login) = &dc.login {
            if let Some(username) = &login.username {
                attributes.insert("username".to_string(), username.clone());
            }
            if let Some(uri) = login.uris.first() {
                attributes.insert("uri".to_string(), uri.clone());
            }
        }

        // Card-specific attributes
        if let Some(card) = &dc.card
            && let Some(cardholder) = &card.cardholder_name
        {
            attributes.insert("cardholder".to_string(), cardholder.clone());
        }

        // Custom fields as attributes
        for field in &dc.fields {
            if let (Some(name), Some(value)) = (&field.name, &field.value) {
                // Only expose text fields (type 0), not hidden (1) or boolean (2)
                if field.field_type == 0 {
                    attributes.insert(name.clone(), value.as_str().to_string());
                }
            }
        }

        let created = dc
            .creation_date
            .as_ref()
            .and_then(|s| parse_iso8601(s));
        let modified = dc
            .revision_date
            .as_ref()
            .and_then(|s| parse_iso8601(s));

        VaultItemMeta {
            id: dc.id.clone(),
            backend_id: "bitwarden".to_string(),
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
    fn get_primary_secret(dc: &DecryptedCipher) -> Option<SecretBytes> {
        let bytes = match dc.cipher_type {
            CipherType::Login => dc
                .login
                .as_ref()
                .and_then(|l| l.password.as_deref())
                .map(|p| p.as_bytes().to_vec()),
            CipherType::SecureNote => dc
                .notes
                .as_deref()
                .map(|n| n.as_bytes().to_vec()),
            CipherType::Card => dc
                .card
                .as_ref()
                .and_then(|c| c.number.as_deref())
                .map(|n| n.as_bytes().to_vec()),
            CipherType::SshKey => dc
                .ssh_key
                .as_ref()
                .and_then(|sk| sk.private_key.as_deref())
                .or(dc.notes.as_deref())
                .map(|n| n.as_bytes().to_vec()),
            CipherType::Identity | CipherType::Unknown(_) => dc
                .notes
                .as_deref()
                .map(|n| n.as_bytes().to_vec()),
        };
        bytes.map(SecretBytes::new)
    }
}

#[async_trait::async_trait]
impl VaultBackend for BitwardenBackend {
    fn id(&self) -> &str {
        "bitwarden"
    }

    fn name(&self) -> &str {
        "Bitwarden"
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
        let password = match input {
            UnlockInput::Password(p) => p,
            UnlockInput::ApiKey { .. } => {
                return Err(BackendError::NotSupported);
            }
            UnlockInput::SessionToken(_) => {
                return Err(BackendError::NotSupported);
            }
            UnlockInput::Otp(_) => {
                return Err(BackendError::NotSupported);
            }
        };

        let auth_state = self
            .authenticate(&password, None)
            .await
            .map_err(BackendError::from)?;

        let mut guard = self.state.lock().await;
        *guard = Some(auth_state);

        info!("Bitwarden vault unlocked");
        Ok(())
    }

    async fn lock(&self) -> Result<(), BackendError> {
        let mut guard = self.state.lock().await;
        *guard = None;
        info!("Bitwarden vault locked");
        Ok(())
    }

    async fn recover(&self) -> Result<RecoveryOutcome, BackendError> {
        // Try to re-sync if we have an active session
        let mut guard = self.state.lock().await;
        if let Some(state) = guard.as_mut() {
            match Self::resync(state, &self.api).await {
                Ok(()) => Ok(RecoveryOutcome::Recovered),
                Err(e) => {
                    warn!(error = %e, "recovery re-sync failed");
                    Ok(RecoveryOutcome::Failed(e.to_string()))
                }
            }
        } else {
            Ok(RecoveryOutcome::Failed("vault is locked".to_string()))
        }
    }

    async fn list_items(&self) -> Result<Vec<VaultItemMeta>, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let items: Vec<VaultItemMeta> = state
            .vault
            .ciphers()
            .iter()
            .map(Self::cipher_to_meta)
            .collect();

        Ok(items)
    }

    async fn get_item(&self, id: &str) -> Result<VaultItem, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let dc = state
            .vault
            .cipher_by_id(id)
            .ok_or(BackendError::NotFound)?;

        let secret = Self::get_primary_secret(dc);

        Ok(VaultItem {
            meta: Self::cipher_to_meta(dc),
            secret,
        })
    }

    async fn get_secret(&self, id: &str) -> Result<SecretBytes, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let dc = state
            .vault
            .cipher_by_id(id)
            .ok_or(BackendError::NotFound)?;

        Self::get_primary_secret(dc)
            .ok_or_else(|| BackendError::Other(anyhow::anyhow!("no secret for cipher {id}")))
    }

    async fn search(&self, attrs: &Attributes) -> Result<Vec<VaultItemMeta>, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let items: Vec<VaultItemMeta> = state
            .vault
            .ciphers()
            .iter()
            .filter_map(|dc| {
                let meta = Self::cipher_to_meta(dc);
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
    let d = days.get((month as usize).wrapping_sub(1)).copied().unwrap_or(0);
    if leap && month > 2 { d + 1 } else { d }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{
        CipherType, DecryptedCard, DecryptedCipher, DecryptedField, DecryptedLogin,
        DecryptedSshKey,
    };

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
        }
    }

    // --- cipher_to_meta ---

    #[test]
    fn cipher_to_meta_login_basic() {
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: Some("alice".to_string()),
            password: Some(Zeroizing::new("secret123".to_string())),
            totp: None,
            uris: vec!["https://example.com".to_string()],
        });

        let meta = BitwardenBackend::cipher_to_meta(&dc);
        assert_eq!(meta.id, "test-id-123");
        assert_eq!(meta.backend_id, "bitwarden");
        assert_eq!(meta.label, "Test Item");
        assert!(!meta.locked);
        assert_eq!(meta.attributes.get("type"), Some(&"login".to_string()));
        assert_eq!(meta.attributes.get("username"), Some(&"alice".to_string()));
        assert_eq!(meta.attributes.get("uri"), Some(&"https://example.com".to_string()));
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
        let meta = BitwardenBackend::cipher_to_meta(&dc);
        assert_eq!(
            meta.attributes.get("xdg:schema"),
            Some(&"org.freedesktop.Secret.Note".to_string())
        );
        assert_eq!(meta.attributes.get("type"), Some(&"note".to_string()));
    }

    #[test]
    fn cipher_to_meta_card_with_cardholder() {
        let mut dc = make_cipher(CipherType::Card);
        dc.card = Some(DecryptedCard {
            cardholder_name: Some("John Doe".to_string()),
            number: Some(Zeroizing::new("4111111111111111".to_string())),
            brand: Some("Visa".to_string()),
            exp_month: Some("12".to_string()),
            exp_year: Some("2028".to_string()),
            code: Some(Zeroizing::new("123".to_string())),
        });

        let meta = BitwardenBackend::cipher_to_meta(&dc);
        assert_eq!(meta.attributes.get("cardholder"), Some(&"John Doe".to_string()));
        assert_eq!(meta.attributes.get("type"), Some(&"card".to_string()));
    }

    #[test]
    fn cipher_to_meta_with_folder_and_org() {
        let mut dc = make_cipher(CipherType::Login);
        dc.folder_name = Some("Work".to_string());
        dc.organization_id = Some("org-abc".to_string());

        let meta = BitwardenBackend::cipher_to_meta(&dc);
        assert_eq!(meta.attributes.get("folder"), Some(&"Work".to_string()));
        assert_eq!(meta.attributes.get("org_id"), Some(&"org-abc".to_string()));
    }

    #[test]
    fn cipher_to_meta_text_fields_exposed_hidden_fields_excluded() {
        let mut dc = make_cipher(CipherType::Login);
        dc.fields = vec![
            DecryptedField {
                name: Some("api_key_label".to_string()),
                value: Some(Zeroizing::new("visible-value".to_string())),
                field_type: 0, // text — should be exposed
            },
            DecryptedField {
                name: Some("secret_field".to_string()),
                value: Some(Zeroizing::new("hidden-value".to_string())),
                field_type: 1, // hidden — should NOT be exposed
            },
            DecryptedField {
                name: Some("bool_field".to_string()),
                value: Some(Zeroizing::new("true".to_string())),
                field_type: 2, // boolean — should NOT be exposed
            },
        ];

        let meta = BitwardenBackend::cipher_to_meta(&dc);
        assert_eq!(
            meta.attributes.get("api_key_label"),
            Some(&"visible-value".to_string())
        );
        assert!(!meta.attributes.contains_key("secret_field"));
        assert!(!meta.attributes.contains_key("bool_field"));
    }

    #[test]
    fn cipher_to_meta_no_dates() {
        let mut dc = make_cipher(CipherType::Login);
        dc.creation_date = None;
        dc.revision_date = None;

        let meta = BitwardenBackend::cipher_to_meta(&dc);
        assert!(meta.created.is_none());
        assert!(meta.modified.is_none());
    }

    // --- get_primary_secret ---

    #[test]
    fn get_primary_secret_login_password() {
        let mut dc = make_cipher(CipherType::Login);
        dc.login = Some(DecryptedLogin {
            username: Some("user".to_string()),
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
            username: Some("user".to_string()),
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
            cardholder_name: Some("Test".to_string()),
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
            private_key: Some(Zeroizing::new("-----BEGIN RSA PRIVATE KEY-----".to_string())),
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
}
