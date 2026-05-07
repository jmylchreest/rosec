//! Bitwarden Secrets Manager HTTP API client for the WASM guest.
//!
//! Ported from the native `rosec-bitwarden-sm/src/api.rs`.  Major changes:
//! - `reqwest::Client` → `extism_pdk::http::request` (Extism PDK HTTP, synchronous)
//! - All methods are synchronous (no async/await)
//! - `uuid::Uuid` → plain `String` (serde_json handles UUIDs as strings)
//! - tracing → `extism_pdk` logging macros
//!
//! # Flow
//!
//! 1. Parse the access token (`0.{uuid}.{secret}:{base64_16_key}`)
//! 2. Derive the token encryption key via HMAC-SHA256 PRK + HKDF-Expand
//! 3. POST `{identity}/connect/token` (client_credentials) → JWT + encrypted_payload
//! 4. Decrypt `encrypted_payload` → org encryption key (64-byte AES-256-CBC-HMAC)
//! 5. GET  `{api}/organizations/{org}/secrets` → list of secret UUIDs
//! 6. POST `{api}/secrets/get-by-ids`          → encrypted secret blobs
//! 7. GET  `{api}/organizations/{org}/projects` → project names (optional)
//! 8. Decrypt each secret key/value/note with the org key

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{decrypt_field_opt, decrypt_org_key, derive_token_enc_key};
use crate::error::SmError;

/// A parsed Bitwarden SM access token.
///
/// Token format: `0.{access_token_id}.{client_secret}:{base64_16_byte_enc_key}`
pub struct AccessToken {
    pub access_token_id: String,
    pub client_secret: Zeroizing<String>,
    enc_key_seed: Zeroizing<[u8; 16]>,
}

impl AccessToken {
    /// Parse a raw access token string.
    pub fn parse(raw: &str) -> Result<Self, SmError> {
        let (first, enc_key_b64) = raw
            .split_once(':')
            .ok_or(SmError::InvalidToken("missing ':' separator"))?;

        let parts: Vec<&str> = first.split('.').collect();
        if parts.len() != 3 {
            return Err(SmError::InvalidToken(
                "expected 3 dot-separated parts before ':'",
            ));
        }
        if parts[0] != "0" {
            return Err(SmError::InvalidToken(
                "unsupported token version (expected '0')",
            ));
        }

        // Validate it looks like a UUID (36 chars).
        let id = parts[1];
        if id.len() != 36 {
            return Err(SmError::InvalidToken("invalid UUID in token"));
        }

        let client_secret = Zeroizing::new(parts[2].to_string());

        let key_bytes = B64
            .decode(enc_key_b64)
            .map_err(|_| SmError::InvalidToken("invalid base64 in encryption key"))?;
        if key_bytes.len() != 16 {
            return Err(SmError::InvalidToken("encryption key must be 16 bytes"));
        }
        let mut seed = Zeroizing::new([0u8; 16]);
        seed.copy_from_slice(&key_bytes);

        Ok(Self {
            access_token_id: id.to_string(),
            client_secret,
            enc_key_seed: seed,
        })
    }

    /// Derive the 64-byte token encryption key.
    pub fn derive_enc_key(&self) -> Result<Zeroizing<[u8; 64]>, SmError> {
        derive_token_enc_key(&self.enc_key_seed)
    }
}

pub struct SmUrls {
    pub api_url: String,
    pub identity_url: String,
}

impl SmUrls {
    pub fn official_us() -> Self {
        Self {
            api_url: "https://api.bitwarden.com".to_string(),
            identity_url: "https://identity.bitwarden.com".to_string(),
        }
    }

    pub fn official_eu() -> Self {
        Self {
            api_url: "https://api.bitwarden.eu".to_string(),
            identity_url: "https://identity.bitwarden.eu".to_string(),
        }
    }

    pub fn from_base(base: &str) -> Self {
        let base = base.trim_end_matches('/');
        Self {
            api_url: format!("{base}/api"),
            identity_url: format!("{base}/identity"),
        }
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                let hi = char::from_digit((b >> 4) as u32, 16)
                    .unwrap_or('0')
                    .to_ascii_uppercase();
                let lo = char::from_digit((b & 0xf) as u32, 16)
                    .unwrap_or('0')
                    .to_ascii_uppercase();
                out.push('%');
                out.push(hi);
                out.push(lo);
            }
        }
    }
    out
}

fn url_encode_form(params: &[(&str, String)]) -> Vec<u8> {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
        .into_bytes()
}

#[derive(Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub encrypted_payload: String,
    pub expires_in: u64,
}

impl std::fmt::Debug for LoginResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginResponse")
            .field("access_token", &"[redacted]")
            .field("encrypted_payload", &"[redacted]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct SecretIdentifiersResponse {
    secrets: Vec<SecretIdentifier>,
}

#[derive(Debug, Deserialize)]
pub struct SecretIdentifier {
    pub id: String,
}

#[derive(Debug, Serialize)]
struct SecretsGetRequest {
    ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SecretsGetResponse {
    data: Vec<RawSecret>,
}

#[derive(Debug, Deserialize)]
pub struct RawSecret {
    pub id: String,
    pub key: String,
    pub value: Option<String>,
    pub note: Option<String>,
    pub projects: Option<Vec<SecretProject>>,
}

#[derive(Debug, Deserialize)]
pub struct SecretProject {
    pub id: String,
}

#[derive(Debug, Deserialize)]
struct ProjectsResponse {
    data: Vec<RawProject>,
}

#[derive(Debug, Deserialize)]
struct RawProject {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
struct SyncCheckResponse {
    #[serde(rename = "hasChanges")]
    has_changes: bool,
}

/// Step 3: Authenticate with the `client_credentials` grant.
pub fn login(urls: &SmUrls, token: &AccessToken) -> Result<LoginResponse, SmError> {
    let url = format!("{}/connect/token", urls.identity_url);

    let mut params: Vec<(&str, String)> = vec![
        ("grant_type", "client_credentials".to_string()),
        ("scope", "api.secrets".to_string()),
        ("client_id", token.access_token_id.clone()),
        ("client_secret", token.client_secret.as_str().to_string()),
    ];

    extism_pdk::debug!("SM login request");

    let body = url_encode_form(&params);
    for (_, v) in &mut params {
        v.zeroize();
    }
    drop(params);

    let req = extism_pdk::HttpRequest::new(&url)
        .with_method("POST")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Device-Type", "21")
        .with_header("Bitwarden-Client-Name", "rosec")
        .with_header("Bitwarden-Client-Version", env!("CARGO_PKG_VERSION"));

    let resp = extism_pdk::http::request::<Vec<u8>>(&req, Some(body))
        .map_err(|e| SmError::Http(format!("SM login request: {e}")))?;

    let status = resp.status_code();
    if !(200..300).contains(&status) {
        let text = String::from_utf8_lossy(&resp.body()).to_string();
        return Err(SmError::Api(format!("SM login failed ({status}): {text}")));
    }

    let login_resp: LoginResponse = serde_json::from_slice(&resp.body())
        .map_err(|e| SmError::Api(format!("SM login response parse: {e}")))?;

    extism_pdk::debug!("SM login ok");
    Ok(login_resp)
}

/// Step 5: List all secret identifiers for the organisation.
pub fn list_secrets(
    urls: &SmUrls,
    bearer: &str,
    org_id: &str,
) -> Result<Vec<SecretIdentifier>, SmError> {
    let url = format!("{}/organizations/{org_id}/secrets", urls.api_url);

    extism_pdk::debug!("SM list secrets org={org_id}");

    let req = extism_pdk::HttpRequest::new(&url)
        .with_method("GET")
        .with_header("Authorization", format!("Bearer {bearer}"))
        .with_header("Bitwarden-Client-Name", "rosec")
        .with_header("Bitwarden-Client-Version", env!("CARGO_PKG_VERSION"));

    let resp = extism_pdk::http::request::<Vec<u8>>(&req, None)
        .map_err(|e| SmError::Http(format!("SM list secrets request: {e}")))?;

    let status = resp.status_code();
    if !(200..300).contains(&status) {
        let text = String::from_utf8_lossy(&resp.body()).to_string();
        return Err(SmError::Api(format!(
            "SM list secrets failed ({status}): {text}"
        )));
    }

    let list: SecretIdentifiersResponse = serde_json::from_slice(&resp.body())
        .map_err(|e| SmError::Api(format!("SM list secrets response parse: {e}")))?;

    extism_pdk::debug!("SM secret identifiers fetched count={}", list.secrets.len());
    Ok(list.secrets)
}

/// Step 6: Fetch full secret blobs by IDs.
pub fn get_secrets_by_ids(
    urls: &SmUrls,
    bearer: &str,
    ids: &[String],
) -> Result<Vec<RawSecret>, SmError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let url = format!("{}/secrets/get-by-ids", urls.api_url);

    extism_pdk::debug!("SM get secrets by IDs count={}", ids.len());

    let body_req = SecretsGetRequest { ids: ids.to_vec() };
    let body_bytes = serde_json::to_vec(&body_req)
        .map_err(|e| SmError::Api(format!("serialize secrets request: {e}")))?;

    let req = extism_pdk::HttpRequest::new(&url)
        .with_method("POST")
        .with_header("Authorization", format!("Bearer {bearer}"))
        .with_header("Content-Type", "application/json")
        .with_header("Bitwarden-Client-Name", "rosec")
        .with_header("Bitwarden-Client-Version", env!("CARGO_PKG_VERSION"));

    let resp = extism_pdk::http::request::<Vec<u8>>(&req, Some(body_bytes))
        .map_err(|e| SmError::Http(format!("SM get secrets request: {e}")))?;

    let status = resp.status_code();
    if !(200..300).contains(&status) {
        let text = String::from_utf8_lossy(&resp.body()).to_string();
        return Err(SmError::Api(format!(
            "SM get secrets failed ({status}): {text}"
        )));
    }

    let secrets: SecretsGetResponse = serde_json::from_slice(&resp.body())
        .map_err(|e| SmError::Api(format!("SM get secrets response parse: {e}")))?;

    extism_pdk::debug!("SM secrets fetched count={}", secrets.data.len());
    Ok(secrets.data)
}

/// Step 6b: Fetch project names for the organisation (non-fatal).
///
/// Returns a map of project UUID → project name.  Empty map if the org has no
/// projects or if the request fails.
pub fn list_projects(urls: &SmUrls, bearer: &str, org_id: &str) -> HashMap<String, String> {
    let url = format!("{}/organizations/{org_id}/projects", urls.api_url);

    extism_pdk::debug!("SM list projects org={org_id}");

    let req = extism_pdk::HttpRequest::new(&url)
        .with_method("GET")
        .with_header("Authorization", format!("Bearer {bearer}"))
        .with_header("Bitwarden-Client-Name", "rosec")
        .with_header("Bitwarden-Client-Version", env!("CARGO_PKG_VERSION"));

    let resp = match extism_pdk::http::request::<Vec<u8>>(&req, None) {
        Ok(r) => r,
        Err(e) => {
            extism_pdk::warn!("SM list projects request failed: {e}");
            return HashMap::new();
        }
    };

    if !(200..300u16).contains(&resp.status_code()) {
        extism_pdk::warn!("SM list projects returned status {}", resp.status_code());
        return HashMap::new();
    }

    let list: ProjectsResponse = match serde_json::from_slice(&resp.body()) {
        Ok(l) => l,
        Err(e) => {
            extism_pdk::warn!("SM list projects response parse failed: {e}");
            return HashMap::new();
        }
    };

    extism_pdk::debug!("SM projects fetched count={}", list.data.len());
    list.data.into_iter().map(|p| (p.id, p.name)).collect()
}

/// Delta-sync check: returns `true` if the org's secrets have changed since
/// `last_synced` (an ISO-8601 UTC timestamp string).
pub fn check_secrets_changed(
    urls: &SmUrls,
    bearer: &str,
    org_id: &str,
    last_synced: &str,
) -> Result<bool, SmError> {
    let url = format!(
        "{}/organizations/{org_id}/secrets/sync?lastSyncedDate={last_synced}",
        urls.api_url
    );

    extism_pdk::debug!("SM delta-sync check org={org_id}");

    let req = extism_pdk::HttpRequest::new(&url)
        .with_method("GET")
        .with_header("Authorization", format!("Bearer {bearer}"))
        .with_header("Bitwarden-Client-Name", "rosec")
        .with_header("Bitwarden-Client-Version", env!("CARGO_PKG_VERSION"));

    let resp = extism_pdk::http::request::<Vec<u8>>(&req, None)
        .map_err(|e| SmError::Http(format!("SM sync check request: {e}")))?;

    let status = resp.status_code();
    if !(200..300).contains(&status) {
        let text = String::from_utf8_lossy(&resp.body()).to_string();
        return Err(SmError::Api(format!(
            "SM sync check failed ({status}): {text}"
        )));
    }

    let sync: SyncCheckResponse = serde_json::from_slice(&resp.body())
        .map_err(|e| SmError::Api(format!("SM sync check response parse: {e}")))?;

    extism_pdk::debug!("SM delta-sync check has_changes={}", sync.has_changes);
    Ok(sync.has_changes)
}

/// A fully decrypted SM secret.
pub struct DecryptedSecret {
    pub id: String,
    pub key: String,
    pub value: Zeroizing<String>,
    pub note: Zeroizing<String>,
    pub project_id: Option<String>,
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
/// Returns `(bearer_token, expires_in_secs, secrets)`.  The bearer token is a
/// short-lived JWT that callers may cache for subsequent lightweight API
/// calls; `expires_in_secs` is its lifetime as reported by the identity
/// server.
pub fn fetch_secrets(
    urls: &SmUrls,
    token: &AccessToken,
    org_id: &str,
) -> Result<(Zeroizing<String>, u64, Vec<DecryptedSecret>), SmError> {
    // Step 3: authenticate
    let login_resp = login(urls, token)?;
    extism_pdk::debug!("SM access token authenticated");
    let bearer = Zeroizing::new(login_resp.access_token);
    let expires_in = login_resp.expires_in;
    let encrypted_payload = login_resp.encrypted_payload;

    // Step 4: derive org encryption key
    let token_enc_key = token.derive_enc_key()?;
    let org_key = decrypt_org_key(&encrypted_payload, &token_enc_key)?;

    // Step 5: list secret identifiers
    let identifiers = list_secrets(urls, &bearer, org_id)?;
    extism_pdk::debug!("SM secret identifiers fetched count={}", identifiers.len());

    if identifiers.is_empty() {
        return Ok((bearer, expires_in, Vec::new()));
    }

    // Step 6: fetch encrypted blobs
    let ids: Vec<String> = identifiers.into_iter().map(|s| s.id).collect();
    let raw_secrets = get_secrets_by_ids(urls, &bearer, &ids)?;

    // Step 6b: fetch project names (non-fatal)
    let project_names = list_projects(urls, &bearer, org_id);

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
            .map(|p| p.id.clone());
        let project_name = project_id
            .as_deref()
            .and_then(|id| project_names.get(id))
            .cloned();

        secrets.push(DecryptedSecret {
            id: raw.id,
            key: key.as_str().to_string(),
            value,
            note,
            project_id,
            project_name,
        });
    }

    extism_pdk::debug!("SM secrets loaded and decrypted count={}", secrets.len());
    Ok((bearer, expires_in, secrets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_access_token_ok() {
        let raw = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        let t = AccessToken::parse(raw).unwrap();
        assert_eq!(t.access_token_id, "ec2c1d46-6a4b-4751-a310-af9601317f2d");
        assert_eq!(t.client_secret.as_str(), "C2IgxjjLF7qSshsbwe8JGcbM075YXw");
    }

    #[test]
    fn parse_access_token_missing_colon() {
        assert!(AccessToken::parse("0.uuid.secret-no-colon").is_err());
    }

    #[test]
    fn parse_access_token_wrong_version() {
        assert!(AccessToken::parse(
            "1.ec2c1d46-6a4b-4751-a310-af9601317f2d.secret:X8vbvA0bduihIDe/qrzIQQ=="
        )
        .is_err());
    }

    #[test]
    fn parse_access_token_bad_key() {
        assert!(
            AccessToken::parse("0.ec2c1d46-6a4b-4751-a310-af9601317f2d.secret:not-valid-b64!")
                .is_err()
        );
    }

    #[test]
    fn sm_urls_from_base() {
        let urls = SmUrls::from_base("https://vault.example.com");
        assert_eq!(urls.api_url, "https://vault.example.com/api");
        assert_eq!(urls.identity_url, "https://vault.example.com/identity");
    }

    #[test]
    fn sm_urls_official_us() {
        let urls = SmUrls::official_us();
        assert!(urls.api_url.contains("bitwarden.com"));
    }
}
