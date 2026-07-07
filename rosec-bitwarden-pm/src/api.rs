//! Bitwarden HTTP API client for the WASM guest.
//!
//! Ported from `rosec-bitwarden/src/api.rs`.  Major changes:
//! - `reqwest::Client` → `extism_pdk::HttpRequest` (Extism PDK HTTP)
//! - All methods are synchronous (no async/await)
//! - Device ID comes from host via init options (no file persistence)
//! - `notifications_url()` removed (host handles real-time sync)
//! - tracing → extism_pdk logging macros

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, KdfParams};
use crate::error::BitwardenError;

/// Client version advertised to the Bitwarden server.
///
/// The server's `SyncController.FilterSSHKeys` strips SSH-key ciphers
/// (type 5) for clients older than `SSHKeyCipherMinimumVersion`
/// (`2024.12.0`).  We must send at least that version so the server
/// includes them in sync responses.
const CLIENT_VERSION: &str = "2025.1.0";

/// API server URLs.
#[derive(Debug, Clone)]
pub struct ServerUrls {
    pub api_url: String,
    pub identity_url: String,
    pub notifications_url: String,
}

impl ServerUrls {
    /// Construct URLs from a base URL (for self-hosted servers).
    pub fn from_base(base_url: &str) -> Self {
        let base = base_url.trim_end_matches('/');
        Self {
            api_url: format!("{base}/api"),
            identity_url: format!("{base}/identity"),
            notifications_url: format!("{base}/notifications"),
        }
    }

    /// Official Bitwarden cloud (US).
    pub fn official_us() -> Self {
        Self {
            api_url: "https://api.bitwarden.com".to_string(),
            identity_url: "https://identity.bitwarden.com".to_string(),
            notifications_url: "https://notifications.bitwarden.com".to_string(),
        }
    }

    /// Official Bitwarden cloud (EU).
    pub fn official_eu() -> Self {
        Self {
            api_url: "https://api.bitwarden.eu".to_string(),
            identity_url: "https://identity.bitwarden.eu".to_string(),
            notifications_url: "https://notifications.bitwarden.eu".to_string(),
        }
    }
}

/// Bitwarden API client using Extism PDK HTTP.
pub struct ApiClient {
    urls: ServerUrls,
    device_id: String,
}

impl ApiClient {
    pub fn new(urls: ServerUrls, device_id: String) -> Self {
        Self { urls, device_id }
    }

    /// Step 1: Prelogin — get KDF parameters for the user.
    pub fn prelogin(&self, email: &str) -> Result<KdfParams, BitwardenError> {
        let url = format!("{}/accounts/prelogin", self.urls.identity_url);
        let body = PreloginRequest {
            email: email.to_string(),
        };

        extism_pdk::debug!("prelogin request: email={email}");

        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| BitwardenError::Api(format!("serialize: {e}")))?;

        let req = extism_pdk::HttpRequest::new(&url)
            .with_method("POST")
            .with_header("Content-Type", "application/json")
            .with_header("Bitwarden-Client-Name", "cli")
            .with_header("Bitwarden-Client-Version", CLIENT_VERSION)
            .with_header("Device-Type", "8");

        let resp = extism_pdk::http::request::<Vec<u8>>(&req, Some(body_bytes))
            .map_err(|e| BitwardenError::Http(format!("prelogin request: {e}")))?;

        let status = resp.status_code();
        if !(200..300).contains(&status) {
            let text = resp.body();
            let text_str = String::from_utf8_lossy(&text);
            return Err(BitwardenError::Api(format!(
                "prelogin failed ({status}): {text_str}"
            )));
        }

        let prelogin: PreloginResponse = serde_json::from_slice(&resp.body())
            .map_err(|e| BitwardenError::Api(format!("prelogin response parse: {e}")))?;

        extism_pdk::debug!(
            "prelogin response: kdf={}, iterations={}",
            prelogin.kdf,
            prelogin.kdf_iterations
        );

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
    pub fn login_password(
        &self,
        email: &str,
        password_hash_b64: &str,
        two_factor: Option<TwoFactorSubmission>,
    ) -> Result<LoginResponse, BitwardenError> {
        let url = format!("{}/connect/token", self.urls.identity_url);

        let auth_email = crypto::b64_url_encode(email.as_bytes());

        let mut params = Vec::new();
        params.push(("grant_type", "password".to_string()));

        extism_pdk::debug!("login request: email={email}");
        params.push(("scope", "api offline_access".to_string()));
        params.push(("client_id", "cli".to_string()));
        params.push(("deviceType", "8".to_string()));
        params.push(("deviceIdentifier", self.device_id.clone()));
        params.push(("deviceName", "rosec".to_string()));
        params.push(("devicePushToken", String::new()));
        params.push(("username", email.to_string()));
        params.push(("password", password_hash_b64.to_string()));

        if let Some(tf) = two_factor {
            params.push(("twoFactorToken", tf.token));
            params.push(("twoFactorProvider", tf.provider.to_string()));
            params.push(("twoFactorRemember", "0".to_string()));
        }

        let mut form_body = url_encode_form(&params);
        // Zeroize sensitive params before proceeding.
        for (_, v) in &mut params {
            v.zeroize();
        }
        drop(params);

        let req = extism_pdk::HttpRequest::new(&url)
            .with_method("POST")
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_header("Bitwarden-Client-Name", "cli")
            .with_header("Bitwarden-Client-Version", CLIENT_VERSION)
            .with_header("Device-Type", "8")
            .with_header("auth-email", &auth_email);

        let resp = extism_pdk::http::request::<Vec<u8>>(&req, Some(form_body.as_bytes().to_vec()))
            .map_err(|e| BitwardenError::Http(format!("login request: {e}")))?;
        form_body.zeroize();

        let status = resp.status_code();
        let body = resp.body();
        let body_str = String::from_utf8_lossy(&body);

        if !(200..300).contains(&status) {
            if let Ok(err_resp) = serde_json::from_str::<LoginErrorResponse>(&body_str) {
                // Device not registered
                if err_resp.error.as_deref() == Some("device_error") {
                    return Err(BitwardenError::DeviceVerificationRequired);
                }
                // 2FA required
                if err_resp
                    .error_description
                    .as_deref()
                    .is_some_and(|d| d.contains("Two factor required"))
                {
                    let providers = err_resp.two_factor_providers.unwrap_or_default();

                    // Extract the email hint from TwoFactorProviders2 provider "1".
                    let email_hint = err_resp
                        .two_factor_providers2
                        .as_ref()
                        .and_then(|p2| p2.get("1"))
                        .and_then(|v| v.get("Email"))
                        .and_then(|v| v.as_str())
                        .map(String::from);

                    return Err(BitwardenError::TwoFactorRequired {
                        providers,
                        email_hint,
                    });
                }
            }
            return Err(BitwardenError::Auth(format!(
                "login failed ({status}): {body_str}"
            )));
        }

        let login: LoginResponse = serde_json::from_str(&body_str)
            .map_err(|e| BitwardenError::Api(format!("login response parse: {e}")))?;

        extism_pdk::debug!("login successful");

        Ok(login)
    }

    /// Register this device with Bitwarden using the personal API key.
    pub fn register_device(
        &self,
        email: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(), BitwardenError> {
        let url = format!("{}/connect/token", self.urls.identity_url);

        let auth_email = crypto::b64_url_encode(email.as_bytes());

        extism_pdk::debug!("register_device request: email={email}");

        let mut params = vec![
            ("grant_type", "client_credentials".to_string()),
            ("scope", "api".to_string()),
            ("client_id", client_id.to_string()),
            ("client_secret", client_secret.to_string()),
            ("username", email.to_string()),
            ("deviceType", "8".to_string()),
            ("deviceIdentifier", self.device_id.clone()),
            ("deviceName", "rosec".to_string()),
        ];

        let mut form_body = url_encode_form(&params);
        // Zeroize sensitive params before proceeding.
        for (_, v) in &mut params {
            v.zeroize();
        }
        drop(params);

        let req = extism_pdk::HttpRequest::new(&url)
            .with_method("POST")
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_header("Bitwarden-Client-Name", "cli")
            .with_header("Bitwarden-Client-Version", CLIENT_VERSION)
            .with_header("Device-Type", "8")
            .with_header("auth-email", &auth_email);

        let resp = extism_pdk::http::request::<Vec<u8>>(&req, Some(form_body.as_bytes().to_vec()))
            .map_err(|e| BitwardenError::Http(format!("register_device request: {e}")))?;
        form_body.zeroize();

        let status = resp.status_code();
        if !(200..300).contains(&status) {
            let body = resp.body();
            let body_str = String::from_utf8_lossy(&body);
            return Err(BitwardenError::Auth(format!(
                "device registration failed ({status}): {body_str}"
            )));
        }

        // Discard the token — we only needed to register the device UUID.
        extism_pdk::debug!("device registered successfully");
        Ok(())
    }

    /// Refresh the access token using a refresh token.
    pub fn refresh_token(&self, refresh_token: &str) -> Result<RefreshResponse, BitwardenError> {
        let url = format!("{}/connect/token", self.urls.identity_url);

        let mut params = vec![
            ("grant_type", "refresh_token".to_string()),
            ("client_id", "cli".to_string()),
            ("refresh_token", refresh_token.to_string()),
        ];

        let mut form_body = url_encode_form(&params);
        // Zeroize sensitive params before proceeding.
        for (_, v) in &mut params {
            v.zeroize();
        }
        drop(params);

        let req = extism_pdk::HttpRequest::new(&url)
            .with_method("POST")
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_header("Bitwarden-Client-Name", "cli")
            .with_header("Bitwarden-Client-Version", CLIENT_VERSION)
            .with_header("Device-Type", "8");

        let resp = extism_pdk::http::request::<Vec<u8>>(&req, Some(form_body.as_bytes().to_vec()))
            .map_err(|e| BitwardenError::Http(format!("refresh_token request: {e}")))?;
        form_body.zeroize();

        let status = resp.status_code();
        if !(200..300).contains(&status) {
            let body = resp.body();
            let body_str = String::from_utf8_lossy(&body);
            return Err(BitwardenError::Auth(format!(
                "token refresh failed ({status}): {body_str}"
            )));
        }

        let refresh: RefreshResponse = serde_json::from_slice(&resp.body())
            .map_err(|e| BitwardenError::Api(format!("refresh response parse: {e}")))?;

        extism_pdk::debug!("token refreshed");

        Ok(refresh)
    }

    /// Sync the vault — fetch all ciphers, folders, and profile data.
    pub fn sync(&self, access_token: &str) -> Result<SyncResponse, BitwardenError> {
        let url = format!("{}/sync", self.urls.api_url);

        extism_pdk::debug!("sync request");

        let req = extism_pdk::HttpRequest::new(&url)
            .with_method("GET")
            .with_header("Authorization", format!("Bearer {access_token}"))
            .with_header("Bitwarden-Client-Name", "cli")
            .with_header("Bitwarden-Client-Version", CLIENT_VERSION)
            .with_header("Device-Type", "8");

        let resp = extism_pdk::http::request::<Vec<u8>>(&req, None::<Vec<u8>>)
            .map_err(|e| BitwardenError::Http(format!("sync request: {e}")))?;

        let status = resp.status_code();
        if status == 401 {
            return Err(BitwardenError::Auth("access token expired".to_string()));
        }

        if !(200..300).contains(&status) {
            let body = resp.body();
            let body_str = String::from_utf8_lossy(&body);
            return Err(BitwardenError::Api(format!(
                "sync failed ({status}): {body_str}"
            )));
        }

        let body = resp.body();
        let sync: SyncResponse = serde_json::from_slice(&body).map_err(|e| {
            extism_pdk::warn!("sync response parse error: {e}");
            BitwardenError::Api(format!("sync response parse: {e}"))
        })?;

        extism_pdk::debug!(
            "sync complete: ciphers={}, folders={}",
            sync.ciphers.len(),
            sync.folders.len()
        );

        Ok(sync)
    }
}

/// URL-encode form parameters (application/x-www-form-urlencoded).
fn url_encode_form(params: &[(&str, String)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Minimal percent-encoding for form values.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(HEX_CHARS[(b >> 4) as usize] as char);
                out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";


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
#[derive(Clone)]
pub struct TwoFactorSubmission {
    pub token: String,
    pub provider: u8,
}

impl std::fmt::Debug for TwoFactorSubmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorSubmission")
            .field("token", &"[redacted]")
            .field("provider", &self.provider)
            .finish()
    }
}

/// Deserialize a `String` field directly into a `Zeroizing<String>`.
fn deser_zeroizing_string<'de, D>(de: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(de)?;
    Ok(Zeroizing::new(s))
}

/// Deserialize an `Option<String>` field directly into an `Option<Zeroizing<String>>`.
fn deser_opt_zeroizing_string<'de, D>(de: D) -> Result<Option<Zeroizing<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(de)?;
    Ok(opt.map(Zeroizing::new))
}

/// Login response — tokens and the protected vault key are all sensitive.
#[derive(Deserialize)]
pub struct LoginResponse {
    #[serde(deserialize_with = "deser_zeroizing_string")]
    pub access_token: Zeroizing<String>,
    #[serde(default, deserialize_with = "deser_opt_zeroizing_string")]
    pub refresh_token: Option<Zeroizing<String>>,
    /// The user's protected symmetric vault key, returned by the server on login.
    #[serde(
        alias = "Key",
        default,
        deserialize_with = "deser_opt_zeroizing_string"
    )]
    pub key: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for LoginResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginResponse")
            .field("access_token", &"[redacted]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("key", &self.key.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct LoginErrorResponse {
    #[serde(alias = "error")]
    error: Option<String>,
    #[serde(alias = "error_description")]
    error_description: Option<String>,
    #[serde(
        alias = "TwoFactorProviders",
        default,
        deserialize_with = "deser_two_factor_providers"
    )]
    two_factor_providers: Option<Vec<u8>>,
    /// Per-provider metadata.  Keyed by provider code (as a string).
    /// Provider 1 (email) has `{ "Email": "j***@example.com" }`.
    #[serde(alias = "TwoFactorProviders2", default)]
    two_factor_providers2: Option<HashMap<String, serde_json::Value>>,
}

/// Bitwarden SaaS returns `TwoFactorProviders` as `["0","7","3"]` (strings),
/// while Vaultwarden / older API versions may return `[0,7,3]` (numbers).
/// Accept both forms.
fn deser_two_factor_providers<'de, D>(de: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ProviderCode {
        Num(u8),
        Str(String),
    }

    let Some(codes) = Option::<Vec<ProviderCode>>::deserialize(de)? else {
        return Ok(None);
    };

    codes
        .into_iter()
        .map(|c| match c {
            ProviderCode::Num(n) => Ok(n),
            ProviderCode::Str(s) => s.parse::<u8>().map_err(serde::de::Error::custom),
        })
        .collect::<Result<Vec<u8>, _>>()
        .map(Some)
}

/// Refresh response — tokens are sensitive.
#[derive(Deserialize)]
pub struct RefreshResponse {
    #[serde(deserialize_with = "deser_zeroizing_string")]
    pub access_token: Zeroizing<String>,
    #[serde(default, deserialize_with = "deser_opt_zeroizing_string")]
    pub refresh_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for RefreshResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshResponse")
            .field("access_token", &"[redacted]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
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
    #[allow(dead_code)]
    pub key: Option<String>,
    #[serde(alias = "PrivateKey", alias = "privateKey")]
    pub private_key: Option<String>,
    #[serde(alias = "Organizations", default)]
    pub organizations: Vec<SyncOrganization>,
}

#[derive(Debug, Deserialize)]
pub struct SyncOrganization {
    #[serde(alias = "Id")]
    pub id: String,
    #[serde(alias = "Name", default)]
    pub name: Option<String>,
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
    #[serde(alias = "FolderId", alias = "folderId")]
    pub folder_id: Option<String>,
    #[serde(alias = "OrganizationId", alias = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(alias = "Type", alias = "type")]
    pub cipher_type: Option<u8>,
    #[serde(alias = "Name")]
    pub name: Option<String>,
    #[serde(alias = "Notes")]
    pub notes: Option<String>,
    #[serde(alias = "Key")]
    pub key: Option<String>,
    #[serde(alias = "Reprompt")]
    #[allow(dead_code)]
    pub reprompt: Option<u8>,
    #[serde(alias = "DeletedDate", alias = "deletedDate")]
    pub deleted_date: Option<String>,
    #[serde(alias = "RevisionDate", alias = "revisionDate")]
    pub revision_date: Option<String>,
    #[serde(alias = "CreationDate", alias = "creationDate")]
    pub creation_date: Option<String>,
    #[serde(alias = "Login")]
    pub login: Option<SyncLogin>,
    #[serde(alias = "Card")]
    pub card: Option<SyncCard>,
    #[serde(alias = "Identity")]
    pub identity: Option<SyncIdentity>,
    #[serde(alias = "SecureNote", alias = "secureNote")]
    #[allow(dead_code)]
    pub secure_note: Option<serde_json::Value>,
    #[serde(alias = "SshKey", alias = "sshKey", alias = "SSHKey")]
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
    #[serde(rename = "fido2Credentials", alias = "Fido2Credentials", default)]
    pub fido2_credentials: Option<Vec<SyncFido2Credential>>,
}

/// One FIDO2 credential (passkey) attached to a login cipher. Every field
/// is an encrypted cipher string, decrypted alongside the login.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncFido2Credential {
    #[serde(alias = "CredentialId", default)]
    pub credential_id: Option<String>,
    // KeyType (constant "public-key") is intentionally not modelled: it is the
    // WebAuthn credential type, not a signing parameter. Algorithm dispatch
    // uses key_algorithm + key_curve. The struct has no deny_unknown_fields,
    // so the field is simply ignored on deserialize.
    #[serde(alias = "KeyAlgorithm", default)]
    pub key_algorithm: Option<String>,
    #[serde(alias = "KeyCurve", default)]
    pub key_curve: Option<String>,
    #[serde(alias = "KeyValue", default)]
    pub key_value: Option<String>,
    #[serde(alias = "RpId", default)]
    pub rp_id: Option<String>,
    #[serde(alias = "RpName", default)]
    pub rp_name: Option<String>,
    #[serde(alias = "UserHandle", default)]
    pub user_handle: Option<String>,
    #[serde(alias = "UserName", default)]
    pub user_name: Option<String>,
    #[serde(alias = "UserDisplayName", default)]
    pub user_display_name: Option<String>,
    #[serde(alias = "Counter", default)]
    pub counter: Option<String>,
    #[serde(alias = "Discoverable", default)]
    pub discoverable: Option<String>,
    #[serde(alias = "CreationDate", default)]
    #[allow(dead_code)]
    pub creation_date: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncUri {
    #[serde(alias = "Uri")]
    pub uri: Option<String>,
    #[serde(alias = "Match", alias = "match")]
    #[allow(dead_code)]
    pub match_type: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub struct SyncCard {
    #[serde(alias = "CardholderName", alias = "cardholderName")]
    pub cardholder_name: Option<String>,
    #[serde(alias = "Number")]
    pub number: Option<String>,
    #[serde(alias = "Brand")]
    pub brand: Option<String>,
    #[serde(alias = "ExpMonth", alias = "expMonth")]
    pub exp_month: Option<String>,
    #[serde(alias = "ExpYear", alias = "expYear")]
    pub exp_year: Option<String>,
    #[serde(alias = "Code")]
    pub code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncIdentity {
    #[serde(alias = "Title")]
    pub title: Option<String>,
    #[serde(alias = "FirstName", alias = "firstName")]
    pub first_name: Option<String>,
    #[serde(alias = "MiddleName", alias = "middleName")]
    pub middle_name: Option<String>,
    #[serde(alias = "LastName", alias = "lastName")]
    pub last_name: Option<String>,
    #[serde(alias = "Username")]
    pub username: Option<String>,
    #[serde(alias = "Company")]
    pub company: Option<String>,
    #[serde(alias = "Ssn")]
    pub ssn: Option<String>,
    #[serde(alias = "PassportNumber", alias = "passportNumber")]
    pub passport_number: Option<String>,
    #[serde(alias = "LicenseNumber", alias = "licenseNumber")]
    pub license_number: Option<String>,
    #[serde(alias = "Email")]
    pub email: Option<String>,
    #[serde(alias = "Phone")]
    pub phone: Option<String>,
    #[serde(alias = "Address1", alias = "address1")]
    pub address1: Option<String>,
    #[serde(alias = "Address2", alias = "address2")]
    pub address2: Option<String>,
    #[serde(alias = "Address3", alias = "address3")]
    pub address3: Option<String>,
    #[serde(alias = "City")]
    pub city: Option<String>,
    #[serde(alias = "State")]
    pub state: Option<String>,
    #[serde(alias = "PostalCode", alias = "postalCode")]
    pub postal_code: Option<String>,
    #[serde(alias = "Country")]
    pub country: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncSshKey {
    #[serde(alias = "PrivateKey", alias = "privateKey")]
    pub private_key: Option<String>,
    #[serde(alias = "PublicKey", alias = "publicKey")]
    pub public_key: Option<String>,
    #[serde(alias = "Fingerprint", alias = "keyFingerprint")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncField {
    #[serde(alias = "Type", alias = "type")]
    pub field_type: Option<u8>,
    #[serde(alias = "Name")]
    pub name: Option<String>,
    #[serde(alias = "Value")]
    pub value: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::LoginErrorResponse;

    /// Bitwarden SaaS returns provider codes as JSON strings: `["0","7","3"]`.
    #[test]
    fn login_error_parses_two_factor_providers_as_strings() {
        let payload = r#"{
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["0", "7", "3"]
        }"#;
        let parsed: LoginErrorResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed.two_factor_providers, Some(vec![0, 7, 3]));
    }

    /// Vaultwarden / older API versions may return numeric codes: `[0,7,3]`.
    #[test]
    fn login_error_parses_two_factor_providers_as_numbers() {
        let payload = r#"{
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": [0, 7, 3]
        }"#;
        let parsed: LoginErrorResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed.two_factor_providers, Some(vec![0, 7, 3]));
    }

    /// Missing TwoFactorProviders field should deserialize as None.
    #[test]
    fn login_error_parses_without_two_factor_providers() {
        let payload = r#"{
            "error": "invalid_grant",
            "error_description": "Some other error."
        }"#;
        let parsed: LoginErrorResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed.two_factor_providers, None);
    }

    /// Real-world Bitwarden SaaS response with TwoFactorProviders2 metadata.
    #[test]
    fn login_error_parses_full_two_factor_response() {
        let payload = r#"{
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["0", "7", "3"],
            "TwoFactorProviders2": {
                "0": null,
                "7": {"challenge": "abc", "timeout": 60000},
                "3": {"Nfc": true}
            },
            "MasterPasswordPolicy": {"Object": "masterPasswordPolicy"}
        }"#;
        let parsed: LoginErrorResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed.two_factor_providers, Some(vec![0, 7, 3]));
        let p2 = parsed.two_factor_providers2.unwrap();
        assert!(p2.contains_key("0"));
        assert!(p2.contains_key("7"));
        assert!(p2.contains_key("3"));
    }

    /// Empty TwoFactorProviders array should parse as Some(vec![]).
    #[test]
    fn login_error_parses_empty_two_factor_providers_array() {
        let payload = r#"{
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": []
        }"#;
        let parsed: LoginErrorResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed.two_factor_providers, Some(vec![]));
    }

    /// Single TOTP provider as string.
    #[test]
    fn login_error_parses_single_provider_string() {
        let payload = r#"{
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["0"]
        }"#;
        let parsed: LoginErrorResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed.two_factor_providers, Some(vec![0]));
    }

    /// Mixed string and number provider codes — Bitwarden's API should not do
    /// this, but our deserializer handles each element independently.
    #[test]
    fn login_error_parses_mixed_string_and_number_providers() {
        let payload = r#"{
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["0", 3, "1"]
        }"#;
        let parsed: LoginErrorResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed.two_factor_providers, Some(vec![0, 3, 1]));
    }

    /// TwoFactorProviders with only an unrecognised provider code (7 = WebAuthn
    /// in some Bitwarden versions) — should still parse, even though the guest
    /// plugin will later filter it out.
    #[test]
    fn login_error_parses_unrecognised_provider_codes() {
        let payload = r#"{
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["7", "99"]
        }"#;
        let parsed: LoginErrorResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed.two_factor_providers, Some(vec![7, 99]));
    }

    /// TwoFactorProviders set to null (not missing — explicitly null).
    #[test]
    fn login_error_parses_null_two_factor_providers() {
        let payload = r#"{
            "error": "invalid_grant",
            "error_description": "Some error.",
            "TwoFactorProviders": null
        }"#;
        let parsed: LoginErrorResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed.two_factor_providers, None);
    }

    /// Non-2FA error response — no TwoFactorProviders, different error description.
    #[test]
    fn login_error_parses_plain_auth_failure() {
        let payload = r#"{
            "error": "invalid_grant",
            "error_description": "Username or password is incorrect."
        }"#;
        let parsed: LoginErrorResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed.two_factor_providers, None);
        assert_eq!(parsed.two_factor_providers2, None);
        assert_eq!(
            parsed.error_description,
            Some("Username or password is incorrect.".to_string())
        );
    }

    /// Email hint extraction from TwoFactorProviders2 for provider 1.
    #[test]
    fn login_error_extracts_email_hint_from_providers2() {
        let payload = r#"{
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["1"],
            "TwoFactorProviders2": {
                "1": {"Email": "j***@example.com"}
            }
        }"#;
        let parsed: LoginErrorResponse = serde_json::from_str(payload).unwrap();
        let p2 = parsed.two_factor_providers2.unwrap();
        let email = p2
            .get("1")
            .and_then(|v| v.get("Email"))
            .and_then(|v| v.as_str());
        assert_eq!(email, Some("j***@example.com"));
    }

    /// TwoFactorProviders2 with provider 1 but no Email field.
    #[test]
    fn login_error_providers2_missing_email_field() {
        let payload = r#"{
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["1"],
            "TwoFactorProviders2": {
                "1": {}
            }
        }"#;
        let parsed: LoginErrorResponse = serde_json::from_str(payload).unwrap();
        let p2 = parsed.two_factor_providers2.unwrap();
        let email = p2
            .get("1")
            .and_then(|v| v.get("Email"))
            .and_then(|v| v.as_str());
        assert_eq!(email, None);
    }
}
