//! Native Bitwarden Secrets Manager API client.
//!
//! Implements the SM authentication and secret-fetch flow without the Bitwarden
//! SDK, using the same HTTP endpoints and cryptographic operations directly:
//!
//! 1. Parse the access token (`0.{uuid}.{secret}:{base64_16_key}`)
//! 2. Derive the token encryption key via PBKDF-HMAC-SHA256 + HKDF
//! 3. POST `{identity}/connect/token` (client_credentials) → JWT + encrypted_payload
//! 4. Decrypt `encrypted_payload` → org encryption key (64-byte AES-256-CBC-HMAC)
//! 5. GET  `{api}/organizations/{org}/secrets` → list of secret UUIDs
//! 6. POST `{api}/secrets/get-by-ids`          → encrypted secret blobs
//! 7. Decrypt each secret's `key`, `value`, `note` with the org key

use std::collections::HashMap;

use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::debug;
use uuid::Uuid;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

// ---------------------------------------------------------------------------
// Parsed access token
// ---------------------------------------------------------------------------

/// A parsed Bitwarden SM access token.
///
/// Token format: `0.{access_token_id}.{client_secret}:{base64_16_byte_enc_key}`
pub struct AccessToken {
    pub access_token_id: Uuid,
    pub client_secret: Zeroizing<String>,
    /// Raw 16-byte seed used to derive the token encryption key.
    enc_key_seed: Zeroizing<[u8; 16]>,
}

impl AccessToken {
    /// Parse a raw access token string.
    pub fn parse(raw: &str) -> Result<Self, SmApiError> {
        let (first, enc_key_b64) = raw
            .split_once(':')
            .ok_or(SmApiError::InvalidToken("missing ':' separator"))?;

        let parts: Vec<&str> = first.split('.').collect();
        if parts.len() != 3 {
            return Err(SmApiError::InvalidToken(
                "expected 3 dot-separated parts before ':'",
            ));
        }
        if parts[0] != "0" {
            return Err(SmApiError::InvalidToken(
                "unsupported token version (expected '0')",
            ));
        }

        let access_token_id = parts[1]
            .parse::<Uuid>()
            .map_err(|_| SmApiError::InvalidToken("invalid UUID in token"))?;

        let client_secret = Zeroizing::new(parts[2].to_string());

        // The enc key is a standard base64-encoded 16-byte value (padding optional).
        let key_bytes = B64
            .decode(enc_key_b64)
            .map_err(|_| SmApiError::InvalidToken("invalid base64 in encryption key"))?;
        if key_bytes.len() != 16 {
            return Err(SmApiError::InvalidToken("encryption key must be 16 bytes"));
        }
        let mut seed = Zeroizing::new([0u8; 16]);
        seed.copy_from_slice(&key_bytes);

        Ok(Self {
            access_token_id,
            client_secret,
            enc_key_seed: seed,
        })
    }

    /// Derive the 64-byte token encryption key.
    ///
    /// Matches the SDK's `derive_shareable_key(seed, "accesstoken", Some("sm-access-token"))`:
    ///   prk  = HMAC-SHA256(key="bitwarden-accesstoken", data=seed_16_bytes)
    ///   key  = HKDF-Expand(prk, info="sm-access-token", len=64)
    ///   → [enc_key: 32 bytes | mac_key: 32 bytes]
    pub fn derive_token_enc_key(&self) -> Zeroizing<[u8; 64]> {
        // PRK = HMAC-SHA256(key = "bitwarden-accesstoken", data = seed)
        let mut mac =
            HmacSha256::new_from_slice(b"bitwarden-accesstoken").expect("HMAC key size is valid");
        mac.update(self.enc_key_seed.as_ref());
        let prk_generic = mac.finalize().into_bytes();
        let mut prk = Zeroizing::new([0u8; 32]);
        prk.copy_from_slice(&prk_generic);

        let expanded = hkdf_expand_sha256(&*prk, Some(b"sm-access-token"), 64);
        let mut out = Zeroizing::new([0u8; 64]);
        out.copy_from_slice(&expanded);
        out
    }
}

// ---------------------------------------------------------------------------
// API server URLs
// ---------------------------------------------------------------------------

pub struct SmUrls {
    pub api_url: String,
    pub identity_url: String,
}

impl SmUrls {
    /// Official Bitwarden cloud — US region (default).
    pub fn official_us() -> Self {
        Self {
            api_url: "https://api.bitwarden.com".to_string(),
            identity_url: "https://identity.bitwarden.com".to_string(),
        }
    }

    /// Official Bitwarden cloud — EU region.
    pub fn official_eu() -> Self {
        Self {
            api_url: "https://api.bitwarden.eu".to_string(),
            identity_url: "https://identity.bitwarden.eu".to_string(),
        }
    }

    /// Self-hosted instance with a single base URL.
    /// Matches the SDK convention of appending `/api` and `/identity`.
    pub fn from_base(base: &str) -> Self {
        let base = base.trim_end_matches('/');
        Self {
            api_url: format!("{base}/api"),
            identity_url: format!("{base}/identity"),
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

pub struct SmApiClient {
    http: HttpClient,
    urls: SmUrls,
}

impl SmApiClient {
    pub fn new(urls: SmUrls) -> Result<Self, SmApiError> {
        let http = HttpClient::builder()
            .user_agent(format!("rosec/{}", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .https_only(true)
            .build()
            .map_err(SmApiError::Http)?;
        Ok(Self { http, urls })
    }

    /// Step 3: Authenticate with client_credentials grant.
    ///
    /// Returns the short-lived Bearer token and the `encrypted_payload` field
    /// (an EncString containing the org encryption key).
    pub async fn login(&self, token: &AccessToken) -> Result<LoginResponse, SmApiError> {
        let url = format!("{}/connect/token", self.urls.identity_url);

        let mut form = HashMap::new();
        form.insert("grant_type", "client_credentials".to_string());
        form.insert("scope", "api.secrets".to_string());
        form.insert("client_id", token.access_token_id.to_string());
        form.insert("client_secret", token.client_secret.as_str().to_string());

        debug!("SM login request");

        let resp = self
            .http
            .post(&url)
            // DeviceType::SDK = 21 — matches the SDK's default for service-account access tokens.
            .header("Device-Type", "21")
            .header("Bitwarden-Client-Name", "rosec")
            .header("Bitwarden-Client-Version", env!("CARGO_PKG_VERSION"))
            .form(&form)
            .send()
            .await
            .map_err(SmApiError::Http)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(SmApiError::Api(format!(
                "SM login failed ({status}): {body}"
            )));
        }

        let login: LoginResponse = resp.json().await.map_err(SmApiError::Http)?;
        debug!("SM login ok");
        Ok(login)
    }

    /// Step 5: List all secret identifiers for the organisation.
    pub async fn list_secrets(
        &self,
        bearer: &str,
        org_id: Uuid,
    ) -> Result<Vec<SecretIdentifier>, SmApiError> {
        let url = format!("{}/organizations/{org_id}/secrets", self.urls.api_url);

        debug!(%org_id, "SM list secrets");

        let resp = self
            .http
            .get(&url)
            .bearer_auth(bearer)
            .header("Bitwarden-Client-Name", "cli")
            .send()
            .await
            .map_err(SmApiError::Http)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(SmApiError::Api(format!(
                "SM list secrets failed ({status}): {body}"
            )));
        }

        let list: SecretIdentifiersResponse = resp.json().await.map_err(SmApiError::Http)?;
        debug!(count = list.secrets.len(), "SM secret identifiers fetched");
        Ok(list.secrets)
    }

    /// Delta-sync check: returns `true` if the org's secrets have changed since
    /// `last_synced` (an ISO-8601 UTC timestamp string).
    ///
    /// Uses `GET /organizations/{org_id}/secrets/sync?lastSyncedDate={ts}`.
    /// The response is `{ "hasChanges": bool }`.  A network or parse error is
    /// propagated as `Err`; the caller should treat that as "assume changed".
    pub async fn check_secrets_changed(
        &self,
        bearer: &str,
        org_id: Uuid,
        last_synced: &str,
    ) -> Result<bool, SmApiError> {
        let url = format!(
            "{}/organizations/{org_id}/secrets/sync?lastSyncedDate={last_synced}",
            self.urls.api_url
        );

        debug!(%org_id, %last_synced, "SM delta-sync check");

        let resp = self
            .http
            .get(&url)
            .bearer_auth(bearer)
            .header("Bitwarden-Client-Name", "rosec")
            .header("Bitwarden-Client-Version", env!("CARGO_PKG_VERSION"))
            .send()
            .await
            .map_err(SmApiError::Http)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(SmApiError::Api(format!(
                "SM sync check failed ({status}): {body}"
            )));
        }

        #[derive(Deserialize)]
        struct SyncResponse {
            #[serde(rename = "hasChanges")]
            has_changes: bool,
        }

        let sync: SyncResponse = resp.json().await.map_err(SmApiError::Http)?;
        debug!(
            has_changes = sync.has_changes,
            "SM delta-sync check complete"
        );
        Ok(sync.has_changes)
    }

    /// Fetch all projects for the given organisation.
    ///
    /// Returns a map of project UUID → project name.  The map is empty if the
    /// org has no projects or if the server returns a non-2xx status (treated
    /// as a non-fatal condition — secrets will just lack a `sm.project` name).
    pub async fn list_projects(
        &self,
        bearer: &str,
        org_id: Uuid,
    ) -> Result<HashMap<Uuid, String>, SmApiError> {
        let url = format!("{}/organizations/{org_id}/projects", self.urls.api_url);
        debug!(%org_id, "SM list projects");

        let resp = self
            .http
            .get(&url)
            .bearer_auth(bearer)
            .header("Bitwarden-Client-Name", "rosec")
            .header("Bitwarden-Client-Version", env!("CARGO_PKG_VERSION"))
            .send()
            .await
            .map_err(SmApiError::Http)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(SmApiError::Api(format!(
                "SM list projects failed ({status}): {body}"
            )));
        }

        let list: ProjectsResponse = resp.json().await.map_err(SmApiError::Http)?;
        debug!(count = list.data.len(), "SM projects fetched");
        Ok(list.data.into_iter().map(|p| (p.id, p.name)).collect())
    }

    /// Step 6: Fetch full secret blobs by IDs.
    pub async fn get_secrets_by_ids(
        &self,
        bearer: &str,
        ids: &[Uuid],
    ) -> Result<Vec<RawSecret>, SmApiError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let url = format!("{}/secrets/get-by-ids", self.urls.api_url);

        debug!(count = ids.len(), "SM get secrets by IDs");

        let body = SecretsGetRequest { ids: ids.to_vec() };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(bearer)
            .header("Bitwarden-Client-Name", "cli")
            .json(&body)
            .send()
            .await
            .map_err(SmApiError::Http)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(SmApiError::Api(format!(
                "SM get secrets failed ({status}): {text}"
            )));
        }

        let secrets: SecretsResponse = resp.json().await.map_err(SmApiError::Http)?;
        debug!(count = secrets.data.len(), "SM secrets fetched");
        Ok(secrets.data)
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    // Deserialized as plain String then immediately wrapped; the raw String
    // field is consumed (moved) into Zeroizing so no lingering copy exists
    // beyond the serde frame.
    pub access_token: String,
    pub encrypted_payload: String,
}

impl LoginResponse {
    /// Consume the response, wrapping the bearer token in a Zeroizing guard.
    pub fn into_zeroizing_token(self) -> (Zeroizing<String>, String) {
        (Zeroizing::new(self.access_token), self.encrypted_payload)
    }
}

#[derive(Debug, Deserialize)]
pub struct SecretIdentifier {
    pub id: Uuid,
}

#[derive(Debug, Deserialize)]
struct SecretIdentifiersResponse {
    secrets: Vec<SecretIdentifier>,
}

#[derive(Debug, Serialize)]
struct SecretsGetRequest {
    ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize)]
struct SecretsResponse {
    data: Vec<RawSecret>,
}

/// A raw (still-encrypted) secret blob from the API.
#[derive(Debug, Deserialize)]
pub struct RawSecret {
    pub id: Uuid,
    pub key: String,
    pub value: Option<String>,
    pub note: Option<String>,
    #[serde(rename = "projects")]
    pub projects: Option<Vec<SecretProject>>,
}

#[derive(Debug, Deserialize)]
pub struct SecretProject {
    pub id: Uuid,
}

/// Response from `GET /organizations/{org_id}/projects`.
#[derive(Debug, Deserialize)]
struct ProjectsResponse {
    data: Vec<RawProject>,
}

#[derive(Debug, Deserialize)]
pub struct RawProject {
    pub id: Uuid,
    pub name: String,
}

// ---------------------------------------------------------------------------
// Cryptography
// ---------------------------------------------------------------------------

/// Decrypt and return the 64-byte organisation encryption key embedded in the
/// `encrypted_payload` field of the login response.
///
/// `encrypted_payload` is an EncString (type 2 = AES-256-CBC-HMAC-SHA256),
/// encrypted with the token encryption key derived from the access token seed.
/// Once decrypted, it is JSON of the form `{"encryptionKey":"<base64>"}` where
/// the base64 value is the raw 64-byte org key.
pub fn decrypt_org_key(
    encrypted_payload: &str,
    token_enc_key: &[u8; 64],
) -> Result<Zeroizing<[u8; 64]>, SmApiError> {
    let payload_bytes = decrypt_enc_string(encrypted_payload, token_enc_key)?;

    #[derive(Deserialize)]
    struct Payload {
        #[serde(rename = "encryptionKey")]
        encryption_key: String,
    }

    let payload: Payload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| SmApiError::Crypto(format!("payload JSON parse: {e}")))?;

    let key_bytes = B64
        .decode(&payload.encryption_key)
        .map_err(|e| SmApiError::Crypto(format!("org key base64: {e}")))?;

    if key_bytes.len() != 64 {
        return Err(SmApiError::Crypto(format!(
            "org key must be 64 bytes, got {}",
            key_bytes.len()
        )));
    }

    let mut key = Zeroizing::new([0u8; 64]);
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Decrypt an EncString field (type 2: `2.{iv_b64}|{data_b64}|{mac_b64}`) using
/// the given 64-byte AES-256-CBC-HMAC-SHA256 key (`[enc_key_32 | mac_key_32]`).
pub fn decrypt_enc_string(enc: &str, key64: &[u8; 64]) -> Result<Zeroizing<Vec<u8>>, SmApiError> {
    // Strip the "2." type prefix.
    let body = enc.strip_prefix("2.").ok_or_else(|| {
        SmApiError::Crypto(format!("unsupported EncString type (expected '2.'): {enc}"))
    })?;

    let parts: Vec<&str> = body.split('|').collect();
    if parts.len() != 3 {
        return Err(SmApiError::Crypto(
            "EncString type 2 must have 3 pipe-separated parts".to_string(),
        ));
    }

    let iv = B64
        .decode(parts[0])
        .map_err(|e| SmApiError::Crypto(format!("EncString IV base64: {e}")))?;
    let data = B64
        .decode(parts[1])
        .map_err(|e| SmApiError::Crypto(format!("EncString data base64: {e}")))?;
    let mac = B64
        .decode(parts[2])
        .map_err(|e| SmApiError::Crypto(format!("EncString MAC base64: {e}")))?;

    if iv.len() != 16 {
        return Err(SmApiError::Crypto(
            "EncString IV must be 16 bytes".to_string(),
        ));
    }
    if mac.len() != 32 {
        return Err(SmApiError::Crypto(
            "EncString MAC must be 32 bytes".to_string(),
        ));
    }

    let enc_key = &key64[..32];
    let mac_key = &key64[32..];

    // Verify HMAC-SHA256(mac_key, iv || data) == mac before decrypting.
    let mut hmac = HmacSha256::new_from_slice(mac_key)
        .map_err(|e| SmApiError::Crypto(format!("HMAC key: {e}")))?;
    hmac.update(&iv);
    hmac.update(&data);
    hmac.verify_slice(&mac)
        .map_err(|_| SmApiError::Crypto("EncString MAC verification failed".to_string()))?;

    // AES-256-CBC decrypt with PKCS7 padding.
    let mut buf = Zeroizing::new(data.clone());
    let plaintext = Aes256CbcDec::new_from_slices(enc_key, &iv)
        .map_err(|e| SmApiError::Crypto(format!("AES key/IV: {e}")))?
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| SmApiError::Crypto(format!("AES decrypt: {e}")))?;

    Ok(Zeroizing::new(plaintext.to_vec()))
}

/// Decrypt an optional EncString field, returning an empty string if absent.
pub fn decrypt_field_opt(
    enc: Option<&str>,
    org_key: &[u8; 64],
) -> Result<Zeroizing<String>, SmApiError> {
    match enc {
        None | Some("") => Ok(Zeroizing::new(String::new())),
        Some(s) => {
            let bytes = decrypt_enc_string(s, org_key)?;
            let text = String::from_utf8(bytes.to_vec())
                .map_err(|e| SmApiError::Crypto(format!("UTF-8 decode: {e}")))?;
            Ok(Zeroizing::new(text))
        }
    }
}

/// HKDF-Expand (RFC 5869) using HMAC-SHA256.
///
/// `prk` is the pseudo-random key (output of HKDF-Extract or PBKDF).
/// `info` is optional context / application-specific information.
/// `length` is the desired output length in bytes (≤ 255 * 32).
fn hkdf_expand_sha256(prk: &[u8], info: Option<&[u8]>, length: usize) -> Zeroizing<Vec<u8>> {
    use hkdf::Hkdf;
    // Both error cases represent programming errors (wrong PRK size or oversized
    // output length), not runtime conditions.  Use unreachable! so violations are
    // caught clearly in tests without masking them with a panic message that looks
    // like a handled error.
    let hk = Hkdf::<Sha256>::from_prk(prk)
        .unwrap_or_else(|_| unreachable!("PRK must be a valid HKDF pseudo-random key"));
    let mut okm = Zeroizing::new(vec![0u8; length]);
    hk.expand(info.unwrap_or(b""), &mut okm)
        .unwrap_or_else(|_| unreachable!("HKDF output length must be ≤ 255 * HashLen"));
    okm
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SmApiError {
    #[error("invalid access token: {0}")]
    InvalidToken(&'static str),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API error: {0}")]
    Api(String),

    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<SmApiError> for rosec_core::BackendError {
    fn from(e: SmApiError) -> Self {
        rosec_core::BackendError::Unavailable(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// High-level convenience: authenticate + fetch all secrets
// ---------------------------------------------------------------------------

/// A fully decrypted SM secret.
pub struct DecryptedSecret {
    pub id: Uuid,
    pub key: String,
    pub value: Zeroizing<String>,
    pub note: Zeroizing<String>,
    pub project_id: Option<Uuid>,
    /// Resolved project name, populated from the projects list fetched at sync
    /// time.  `None` if the secret has no project or the project fetch failed.
    pub project_name: Option<String>,
}

impl std::fmt::Debug for DecryptedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedSecret")
            .field("id", &self.id)
            .field("key", &self.key)
            .field("value", &"[redacted]")
            .field("note", &"[redacted]")
            .field("project_id", &self.project_id)
            .field("project_name", &self.project_name)
            .finish()
    }
}

/// Authenticate and fetch all secrets for the given organisation in one call.
///
/// Returns `(bearer_token, secrets)`.  The bearer token is a short-lived JWT
/// that callers may cache for subsequent lightweight API calls (e.g. the
/// delta-sync check) without re-authenticating immediately.
///
/// This is the replacement for the SDK's `Client::new` + `login_access_token` +
/// `secrets().list()` + `secrets().get_by_ids()` sequence.
pub async fn fetch_secrets(
    client: &SmApiClient,
    token: &AccessToken,
    org_id: Uuid,
) -> Result<(Zeroizing<String>, Vec<DecryptedSecret>), SmApiError> {
    // Step 3: authenticate — immediately wrap the bearer token in Zeroizing.
    let login = client.login(token).await?;
    debug!("SM access token authenticated");
    let (bearer, encrypted_payload) = login.into_zeroizing_token();

    // Step 4: derive org encryption key from the encrypted_payload in the login response
    let token_enc_key = token.derive_token_enc_key();
    let org_key = decrypt_org_key(&encrypted_payload, &token_enc_key)?;

    // Step 5: list secret identifiers
    let identifiers = client.list_secrets(&bearer, org_id).await?;
    debug!(count = identifiers.len(), "SM secret identifiers fetched");

    if identifiers.is_empty() {
        return Ok((bearer, Vec::new()));
    }

    // Step 6: fetch encrypted blobs
    let ids: Vec<Uuid> = identifiers.iter().map(|s| s.id).collect();
    let raw_secrets = client.get_secrets_by_ids(&bearer, &ids).await?;

    // Step 6b: fetch project names (non-fatal — empty map if endpoint fails or
    // org has no projects).
    let project_names: HashMap<Uuid, String> = client
        .list_projects(&bearer, org_id)
        .await
        .unwrap_or_default();

    // Step 7: decrypt
    let mut secrets = Vec::with_capacity(raw_secrets.len());
    for raw in raw_secrets {
        let key = decrypt_field_opt(Some(&raw.key), &org_key)?;
        let value = decrypt_field_opt(raw.value.as_deref(), &org_key)?;
        let note = decrypt_field_opt(raw.note.as_deref(), &org_key)?;
        let project_id = raw
            .projects
            .as_deref()
            .and_then(|p| p.first())
            .map(|p| p.id);
        let project_name = project_id.and_then(|id| project_names.get(&id).cloned());

        secrets.push(DecryptedSecret {
            id: raw.id,
            key: key.as_str().to_string(),
            value,
            note,
            project_id,
            project_name,
        });
    }

    debug!(count = secrets.len(), "SM secrets loaded and decrypted");
    Ok((bearer, secrets))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector from the Bitwarden SDK access_token.rs test:
    // "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ=="
    // Expected derived key (base64):
    // "H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg=="
    const TEST_TOKEN: &str = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
    const EXPECTED_KEY_B64: &str =
        "H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg==";

    #[test]
    fn parse_access_token() {
        let t = AccessToken::parse(TEST_TOKEN).unwrap();
        assert_eq!(
            t.access_token_id.to_string(),
            "ec2c1d46-6a4b-4751-a310-af9601317f2d"
        );
        assert_eq!(t.client_secret.as_str(), "C2IgxjjLF7qSshsbwe8JGcbM075YXw");
    }

    #[test]
    fn derive_token_enc_key_matches_sdk() {
        let t = AccessToken::parse(TEST_TOKEN).unwrap();
        let key = t.derive_token_enc_key();
        assert_eq!(B64.encode(*key), EXPECTED_KEY_B64);
    }

    #[test]
    fn parse_token_missing_colon() {
        assert!(AccessToken::parse("0.uuid.secret-no-colon").is_err());
    }

    #[test]
    fn parse_token_wrong_version() {
        assert!(
            AccessToken::parse(
                "1.ec2c1d46-6a4b-4751-a310-af9601317f2d.secret:X8vbvA0bduihIDe/qrzIQQ=="
            )
            .is_err()
        );
    }

    #[test]
    fn parse_token_bad_uuid() {
        assert!(AccessToken::parse("0.not-a-uuid.secret:X8vbvA0bduihIDe/qrzIQQ==").is_err());
    }

    #[test]
    fn decrypt_enc_string_type2() {
        // Self-generated test vector using the same key layout:
        //   key = "hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw=="
        //   enc_key = key[0..32], mac_key = key[32..64]
        //   iv  = 0x01 * 16 (fixed)
        //   plaintext = "EncryptMe!"
        // Generated by encrypting with AES-256-CBC and computing HMAC-SHA256(mac_key, iv||ciphertext).
        let key_bytes = B64.decode("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==").unwrap();
        let mut key64 = [0u8; 64];
        key64.copy_from_slice(&key_bytes);

        let enc = "2.AQEBAQEBAQEBAQEBAQEBAQ==|kcArgC3nLK58WUYK6yyQ+w==|9HRDjijjSa2tyToYilyG3mvJvHKhw3ZqFE7tFVaQh8Q=";
        let plaintext = decrypt_enc_string(enc, &key64).unwrap();
        assert_eq!(std::str::from_utf8(&plaintext).unwrap(), "EncryptMe!");
    }

    #[test]
    fn decrypt_enc_string_wrong_type() {
        let key = [0u8; 64];
        let result = decrypt_enc_string("0.iv|data", &key);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_enc_string_bad_mac() {
        // Use valid structure but corrupt the MAC
        let key_bytes = B64.decode("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==").unwrap();
        let mut key64 = [0u8; 64];
        key64.copy_from_slice(&key_bytes);

        // Valid IV and data, but MAC is all zeros (wrong)
        let bad_mac = B64.encode([0u8; 32]);
        let enc = format!("2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|{bad_mac}");
        let result = decrypt_enc_string(&enc, &key64);
        assert!(result.is_err());
    }

    #[test]
    fn sm_urls_official() {
        let urls = SmUrls::official_us();
        assert!(urls.api_url.contains("bitwarden.com"));
        assert!(urls.identity_url.contains("bitwarden.com"));
    }

    #[test]
    fn sm_urls_from_base() {
        let urls = SmUrls::from_base("https://vault.example.com");
        assert_eq!(urls.api_url, "https://vault.example.com/api");
        assert_eq!(urls.identity_url, "https://vault.example.com/identity");
    }
}
