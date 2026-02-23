//! Bitwarden HTTP API client.
//!
//! Implements the prelogin, login, token refresh, and sync endpoints
//! for both official Bitwarden servers and Vaultwarden.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::crypto::{self, KdfParams};
use crate::error::BitwardenError;

/// API server URLs.
#[derive(Debug, Clone)]
pub struct ServerUrls {
    pub api_url: String,
    pub identity_url: String,
}

impl ServerUrls {
    /// Construct URLs from a base URL (for self-hosted servers).
    pub fn from_base(base_url: &str) -> Self {
        let base = base_url.trim_end_matches('/');
        Self {
            api_url: format!("{base}/api"),
            identity_url: format!("{base}/identity"),
        }
    }

    /// Official Bitwarden cloud (US).
    pub fn official_us() -> Self {
        Self {
            api_url: "https://api.bitwarden.com".to_string(),
            identity_url: "https://identity.bitwarden.com".to_string(),
        }
    }

    /// Official Bitwarden cloud (EU).
    pub fn official_eu() -> Self {
        Self {
            api_url: "https://api.bitwarden.eu".to_string(),
            identity_url: "https://identity.bitwarden.eu".to_string(),
        }
    }
}

/// Bitwarden API client.
pub struct ApiClient {
    http: reqwest::Client,
    urls: ServerUrls,
    device_id: String,
}

impl ApiClient {
    pub fn new(urls: ServerUrls) -> Result<Self, BitwardenError> {
        let http = reqwest::Client::builder()
            .user_agent(format!("rosec/{}", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()?;

        let device_id = load_or_create_device_id();

        Ok(Self {
            http,
            urls,
            device_id,
        })
    }

    /// Step 1: Prelogin — get KDF parameters for the user.
    pub async fn prelogin(&self, email: &str) -> Result<KdfParams, BitwardenError> {
        let url = format!("{}/accounts/prelogin", self.urls.identity_url);
        let body = PreloginRequest {
            email: email.to_string(),
        };

        debug!(email, "prelogin request");

        let resp = self
            .http
            .post(&url)
            .header("Bitwarden-Client-Name", "cli")
            .header("Device-Type", "8")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(BitwardenError::Api(format!(
                "prelogin failed ({status}): {text}"
            )));
        }

        let prelogin: PreloginResponse = resp.json().await?;
        debug!(kdf = prelogin.kdf, iterations = prelogin.kdf_iterations, "prelogin response");

        match prelogin.kdf {
            0 => Ok(KdfParams::Pbkdf2 {
                iterations: prelogin.kdf_iterations,
            }),
            1 => Ok(KdfParams::Argon2id {
                iterations: prelogin.kdf_iterations,
                memory_mb: prelogin.kdf_memory.unwrap_or(64),
                parallelism: prelogin.kdf_parallelism.unwrap_or(4),
            }),
            other => Err(BitwardenError::Api(format!("unknown KDF type: {other}"))),
        }
    }

    /// Step 2: Login with email + password hash.
    ///
    /// Returns the login response containing access token, refresh token,
    /// and the protected symmetric key.
    pub async fn login_password(
        &self,
        email: &str,
        password_hash_b64: &str,
        two_factor: Option<TwoFactorSubmission>,
    ) -> Result<LoginResponse, BitwardenError> {
        let url = format!("{}/connect/token", self.urls.identity_url);

        let auth_email = crypto::b64_url_encode(email.as_bytes());

        let mut form = HashMap::new();
        form.insert("grant_type", "password".to_string());
        form.insert("scope", "api offline_access".to_string());
        form.insert("client_id", "cli".to_string());
        form.insert("deviceType", "8".to_string());
        form.insert("deviceIdentifier", self.device_id.clone());
        form.insert("deviceName", "rosec".to_string());
        form.insert("devicePushToken", String::new());
        form.insert("username", email.to_string());
        form.insert("password", password_hash_b64.to_string());

        if let Some(tf) = two_factor {
            form.insert("twoFactorToken", tf.token);
            form.insert("twoFactorProvider", tf.provider.to_string());
        }

        debug!(email, "login request");

        let resp = self
            .http
            .post(&url)
            .header("Bitwarden-Client-Name", "cli")
            .header("Device-Type", "8")
            .header("auth-email", auth_email)
            .form(&form)
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            // Check for 2FA required
            if let Ok(err_resp) = serde_json::from_str::<LoginErrorResponse>(&body)
                && err_resp
                    .error_description
                    .as_deref()
                    .is_some_and(|d| d.contains("Two factor required"))
            {
                let providers = err_resp.two_factor_providers.unwrap_or_default();
                return Err(BitwardenError::TwoFactorRequired { providers });
            }
            return Err(BitwardenError::Auth(format!(
                "login failed ({status}): {body}"
            )));
        }

        let login: LoginResponse = serde_json::from_str(&body)
            .map_err(|e| BitwardenError::Api(format!("login response parse: {e}")))?;

        debug!("login successful");
        Ok(login)
    }

    /// Refresh the access token using a refresh token.
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<RefreshResponse, BitwardenError> {
        let url = format!("{}/connect/token", self.urls.identity_url);

        let mut form = HashMap::new();
        form.insert("grant_type", "refresh_token");
        form.insert("client_id", "cli");
        form.insert("refresh_token", refresh_token);

        let resp = self
            .http
            .post(&url)
            .header("Bitwarden-Client-Name", "cli")
            .header("Device-Type", "8")
            .form(&form)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(BitwardenError::Auth(format!(
                "token refresh failed ({status}): {text}"
            )));
        }

        let refresh: RefreshResponse = resp.json().await?;
        debug!("token refreshed");
        Ok(refresh)
    }

    /// Sync the vault — fetch all ciphers, folders, and profile data.
    pub async fn sync(&self, access_token: &str) -> Result<SyncResponse, BitwardenError> {
        let url = format!("{}/sync", self.urls.api_url);

        debug!("sync request");

        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .header("Bitwarden-Client-Name", "cli")
            .header("Device-Type", "8")
            .send()
            .await?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(BitwardenError::Auth("access token expired".to_string()));
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(BitwardenError::Api(format!(
                "sync failed ({status}): {text}"
            )));
        }

        let sync: SyncResponse = resp.json().await.map_err(|e| {
            warn!("sync response parse error: {e}");
            BitwardenError::Api(format!("sync response parse: {e}"))
        })?;

        debug!(
            ciphers = sync.ciphers.len(),
            folders = sync.folders.len(),
            "sync complete"
        );
        Ok(sync)
    }
}

// --- Device ID persistence ---

/// Return the path for the persistent device ID file:
/// `$XDG_DATA_HOME/rosec/device_id` (default `~/.local/share/rosec/device_id`).
fn device_id_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share"))
        })?;
    Some(base.join("rosec").join("device_id"))
}

/// Load a persisted device ID or create a new one.
///
/// If the file cannot be read or written (permissions, missing HOME, etc.),
/// falls back to a fresh UUID for this session.
fn load_or_create_device_id() -> String {
    let Some(path) = device_id_path() else {
        warn!("cannot determine data directory; using ephemeral device ID");
        return uuid::Uuid::new_v4().to_string();
    };

    // Try reading an existing device ID
    if let Ok(contents) = std::fs::read_to_string(&path) {
        let id = contents.trim().to_string();
        if !id.is_empty() {
            debug!("loaded persistent device ID from {}", path.display());
            return id;
        }
    }

    // Generate and persist a new one
    let id = uuid::Uuid::new_v4().to_string();
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        warn!(error = %e, "failed to create data directory; using ephemeral device ID");
        return id;
    }
    if let Err(e) = std::fs::write(&path, &id) {
        warn!(error = %e, "failed to persist device ID to {}", path.display());
    } else {
        debug!("persisted new device ID to {}", path.display());
    }
    id
}

// --- Request / Response types ---

#[derive(Debug, Serialize)]
struct PreloginRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
struct PreloginResponse {
    #[serde(alias = "Kdf", alias = "kdf")]
    kdf: u8,
    #[serde(alias = "KdfIterations", alias = "kdfIterations")]
    kdf_iterations: u32,
    #[serde(alias = "KdfMemory", alias = "kdfMemory")]
    kdf_memory: Option<u32>,
    #[serde(alias = "KdfParallelism", alias = "kdfParallelism")]
    kdf_parallelism: Option<u32>,
}

/// Two-factor authentication submission.
#[derive(Debug, Clone)]
pub struct TwoFactorSubmission {
    pub token: String,
    pub provider: u8,
}

/// Two-factor provider types.
pub mod two_factor_provider {
    pub const AUTHENTICATOR: u8 = 0;
    pub const EMAIL: u8 = 1;
    pub const DUO: u8 = 2;
    pub const YUBIKEY: u8 = 3;
    pub const WEBAUTHN: u8 = 7;
}

#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    #[serde(alias = "Key")]
    pub key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginErrorResponse {
    #[serde(alias = "error_description")]
    error_description: Option<String>,
    #[serde(alias = "TwoFactorProviders")]
    two_factor_providers: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncResponse {
    #[serde(alias = "Profile")]
    pub profile: SyncProfile,
    #[serde(alias = "Folders", default)]
    pub folders: Vec<SyncFolder>,
    #[serde(alias = "Ciphers", default)]
    pub ciphers: Vec<SyncCipher>,
}

#[derive(Debug, Deserialize)]
pub struct SyncProfile {
    #[serde(alias = "Key")]
    pub key: Option<String>,
    #[serde(alias = "PrivateKey")]
    pub private_key: Option<String>,
    #[serde(alias = "Organizations", default)]
    pub organizations: Vec<SyncOrganization>,
}

#[derive(Debug, Deserialize)]
pub struct SyncOrganization {
    #[serde(alias = "Id")]
    pub id: String,
    #[serde(alias = "Key")]
    pub key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncFolder {
    #[serde(alias = "Id")]
    pub id: String,
    #[serde(alias = "Name")]
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct SyncCipher {
    #[serde(alias = "Id")]
    pub id: Option<String>,
    #[serde(alias = "FolderId")]
    pub folder_id: Option<String>,
    #[serde(alias = "OrganizationId")]
    pub organization_id: Option<String>,
    #[serde(alias = "Type")]
    pub cipher_type: Option<u8>,
    #[serde(alias = "Name")]
    pub name: Option<String>,
    #[serde(alias = "Notes")]
    pub notes: Option<String>,
    #[serde(alias = "Key")]
    pub key: Option<String>,
    #[serde(alias = "Reprompt")]
    pub reprompt: Option<u8>,
    #[serde(alias = "DeletedDate")]
    pub deleted_date: Option<String>,
    #[serde(alias = "RevisionDate")]
    pub revision_date: Option<String>,
    #[serde(alias = "CreationDate")]
    pub creation_date: Option<String>,
    #[serde(alias = "Login")]
    pub login: Option<SyncLogin>,
    #[serde(alias = "Card")]
    pub card: Option<SyncCard>,
    #[serde(alias = "Identity")]
    pub identity: Option<SyncIdentity>,
    #[serde(alias = "SecureNote")]
    pub secure_note: Option<serde_json::Value>,
    #[serde(alias = "SshKey")]
    pub ssh_key: Option<SyncSshKey>,
    #[serde(alias = "Fields", default)]
    pub fields: Option<Vec<SyncField>>,
}

#[derive(Debug, Deserialize)]
pub struct SyncLogin {
    #[serde(alias = "Username")]
    pub username: Option<String>,
    #[serde(alias = "Password")]
    pub password: Option<String>,
    #[serde(alias = "Totp")]
    pub totp: Option<String>,
    #[serde(alias = "Uris", default)]
    pub uris: Option<Vec<SyncUri>>,
}

#[derive(Debug, Deserialize)]
pub struct SyncUri {
    #[serde(alias = "Uri")]
    pub uri: Option<String>,
    #[serde(alias = "Match")]
    pub match_type: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub struct SyncCard {
    #[serde(alias = "CardholderName")]
    pub cardholder_name: Option<String>,
    #[serde(alias = "Number")]
    pub number: Option<String>,
    #[serde(alias = "Brand")]
    pub brand: Option<String>,
    #[serde(alias = "ExpMonth")]
    pub exp_month: Option<String>,
    #[serde(alias = "ExpYear")]
    pub exp_year: Option<String>,
    #[serde(alias = "Code")]
    pub code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncIdentity {
    #[serde(alias = "Title")]
    pub title: Option<String>,
    #[serde(alias = "FirstName")]
    pub first_name: Option<String>,
    #[serde(alias = "LastName")]
    pub last_name: Option<String>,
    #[serde(alias = "Email")]
    pub email: Option<String>,
    #[serde(alias = "Phone")]
    pub phone: Option<String>,
    #[serde(alias = "Username")]
    pub username: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncSshKey {
    #[serde(alias = "PrivateKey")]
    pub private_key: Option<String>,
    #[serde(alias = "PublicKey")]
    pub public_key: Option<String>,
    #[serde(alias = "Fingerprint", alias = "keyFingerprint")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncField {
    #[serde(alias = "Type")]
    pub field_type: Option<u8>,
    #[serde(alias = "Name")]
    pub name: Option<String>,
    #[serde(alias = "Value")]
    pub value: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls_from_base_trims_trailing_slash() {
        let urls = ServerUrls::from_base("https://vault.example.com/");
        assert_eq!(urls.api_url, "https://vault.example.com/api");
        assert_eq!(urls.identity_url, "https://vault.example.com/identity");
    }

    #[test]
    fn server_urls_from_base_no_trailing_slash() {
        let urls = ServerUrls::from_base("https://vault.example.com");
        assert_eq!(urls.api_url, "https://vault.example.com/api");
        assert_eq!(urls.identity_url, "https://vault.example.com/identity");
    }

    #[test]
    fn server_urls_official_us() {
        let urls = ServerUrls::official_us();
        assert_eq!(urls.api_url, "https://api.bitwarden.com");
        assert_eq!(urls.identity_url, "https://identity.bitwarden.com");
    }

    #[test]
    fn server_urls_official_eu() {
        let urls = ServerUrls::official_eu();
        assert_eq!(urls.api_url, "https://api.bitwarden.eu");
        assert_eq!(urls.identity_url, "https://identity.bitwarden.eu");
    }

    #[test]
    fn device_id_path_returns_some_on_typical_system() {
        // On a typical Linux system with HOME set, device_id_path should return Some
        // We don't modify env vars (unsafe in Rust 2024) — just verify the path structure
        if let Some(path) = device_id_path() {
            assert!(path.ends_with("rosec/device_id"));
        }
        // If neither XDG_DATA_HOME nor HOME is set (unlikely in CI), returns None — that's fine
    }

    #[test]
    fn device_id_path_structure() {
        // Verify the path ends with the expected components regardless of prefix
        if let Some(path) = device_id_path() {
            let components: Vec<_> = path.components().collect();
            let len = components.len();
            assert!(len >= 2);
            assert_eq!(
                components[len - 1].as_os_str(),
                "device_id"
            );
            assert_eq!(
                components[len - 2].as_os_str(),
                "rosec"
            );
        }
    }

    #[test]
    fn two_factor_provider_constants() {
        assert_eq!(two_factor_provider::AUTHENTICATOR, 0);
        assert_eq!(two_factor_provider::EMAIL, 1);
        assert_eq!(two_factor_provider::DUO, 2);
        assert_eq!(two_factor_provider::YUBIKEY, 3);
        assert_eq!(two_factor_provider::WEBAUTHN, 7);
    }

    #[test]
    fn login_response_deserialize() {
        let json = r#"{
            "access_token": "eyJhbGc...",
            "refresh_token": "refresh123",
            "Key": "2.encryptedKey"
        }"#;
        let resp: LoginResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "eyJhbGc...");
        assert_eq!(resp.refresh_token, Some("refresh123".to_string()));
        assert_eq!(resp.key, Some("2.encryptedKey".to_string()));
    }

    #[test]
    fn login_response_deserialize_no_optional_fields() {
        let json = r#"{"access_token": "tok"}"#;
        let resp: LoginResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "tok");
        assert!(resp.refresh_token.is_none());
        assert!(resp.key.is_none());
    }

    #[test]
    fn refresh_response_deserialize_with_rotated_token() {
        let json = r#"{
            "access_token": "new-access",
            "refresh_token": "new-refresh"
        }"#;
        let resp: RefreshResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "new-access");
        assert_eq!(resp.refresh_token, Some("new-refresh".to_string()));
    }

    #[test]
    fn refresh_response_deserialize_no_rotated_token() {
        let json = r#"{"access_token": "new-access"}"#;
        let resp: RefreshResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "new-access");
        assert!(resp.refresh_token.is_none());
    }
}
