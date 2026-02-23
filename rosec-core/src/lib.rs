use std::collections::HashMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub mod config;
pub mod dedup;
pub mod prompt;
pub mod router;

pub type Attributes = HashMap<String, String>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStatus {
    pub locked: bool,
    pub last_sync: Option<SystemTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItemMeta {
    pub id: String,
    pub backend_id: String,
    pub label: String,
    pub attributes: Attributes,
    pub created: Option<SystemTime>,
    pub modified: Option<SystemTime>,
    pub locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub meta: VaultItemMeta,
    pub secret: Option<SecretBytes>,
}

pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
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

#[derive(Clone)]
pub enum UnlockInput {
    Password(Zeroizing<String>),
    ApiKey {
        client_id: String,
        client_secret: Zeroizing<String>,
    },
    SessionToken(Zeroizing<String>),
    Otp(Zeroizing<String>),
}

impl std::fmt::Debug for UnlockInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => f.debug_tuple("Password").field(&"[redacted]").finish(),
            Self::ApiKey { client_id, .. } => f
                .debug_struct("ApiKey")
                .field("client_id", client_id)
                .field("client_secret", &"[redacted]")
                .finish(),
            Self::SessionToken(_) => {
                f.debug_tuple("SessionToken").field(&"[redacted]").finish()
            }
            Self::Otp(_) => f.debug_tuple("Otp").field(&"[redacted]").finish(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryOutcome {
    Recovered,
    Failed(String),
}

#[derive(thiserror::Error, Debug)]
pub enum BackendError {
    #[error("backend locked")]
    Locked,
    #[error("item not found")]
    NotFound,
    #[error("not supported")]
    NotSupported,
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[async_trait::async_trait]
pub trait VaultBackend: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;

    async fn status(&self) -> Result<BackendStatus, BackendError>;
    async fn unlock(&self, input: UnlockInput) -> Result<(), BackendError>;
    async fn lock(&self) -> Result<(), BackendError>;
    async fn recover(&self) -> Result<RecoveryOutcome, BackendError>;

    async fn list_items(&self) -> Result<Vec<VaultItemMeta>, BackendError>;
    async fn get_item(&self, id: &str) -> Result<VaultItem, BackendError>;
    async fn get_secret(&self, id: &str) -> Result<SecretBytes, BackendError>;
    async fn search(&self, attrs: &Attributes) -> Result<Vec<VaultItemMeta>, BackendError>;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoLockPolicy {
    pub on_logout: bool,
    pub on_session_lock: bool,
    pub idle_timeout_minutes: Option<u64>,
    pub max_unlocked_minutes: Option<u64>,
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
    fn unlock_input_debug_redacts_api_key() {
        let input = UnlockInput::ApiKey {
            client_id: "my-client".to_string(),
            client_secret: Zeroizing::new("my-secret".to_string()),
        };
        let debug = format!("{input:?}");
        assert!(debug.contains("my-client"));
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("my-secret"));
    }

    #[test]
    fn unlock_input_debug_redacts_session_token() {
        let input = UnlockInput::SessionToken(Zeroizing::new("tok".to_string()));
        let debug = format!("{input:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("tok"));
    }

    #[test]
    fn unlock_input_debug_redacts_otp() {
        let input = UnlockInput::Otp(Zeroizing::new("123456".to_string()));
        let debug = format!("{input:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("123456"));
    }
}
