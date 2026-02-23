use std::collections::HashMap;
use std::sync::Mutex;

use rosec_core::BackendError;
use uuid::Uuid;
use zeroize::Zeroizing;
use zvariant::Value;

use crate::crypto::{derive_session_key, generate_dh_keypair, SessionAlgorithm};

/// Information stored per open session.
#[derive(Debug)]
struct SessionInfo {
    /// The negotiated algorithm for this session.
    /// Retained for debug output and future per-algorithm policy decisions.
    #[allow(dead_code)]
    algorithm: SessionAlgorithm,
    /// AES-128 session key — present only for DH-encrypted sessions.
    ///
    /// `None` for `plain` sessions. Zeroized on drop.
    aes_key: Option<Zeroizing<[u8; 16]>>,
}

#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: std::sync::Arc<Mutex<HashMap<String, SessionInfo>>>,
}

impl Clone for SessionManager {
    fn clone(&self) -> Self {
        // Share the same inner Arc so that all clones see the same sessions.
        Self {
            sessions: std::sync::Arc::clone(&self.sessions),
        }
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new session.
    ///
    /// * For `"plain"` sessions: `input` is ignored; returns `("", path)`.
    /// * For `"dh-ietf1024-sha256-aes128-cbc-pkcs7"` sessions: `input` must be
    ///   a `Vec<u8>` (the client DH public key, 128 bytes big-endian).  The
    ///   server performs DH and returns `(server_pubkey_bytes, path)`.
    pub fn open_session(
        &self,
        algorithm: &str,
        input: &Value<'_>,
    ) -> Result<(Value<'static>, String), BackendError> {
        let algo = SessionAlgorithm::parse(algorithm)?;

        let id = Uuid::new_v4().simple().to_string();
        let path = format!("/org/freedesktop/secrets/session/s{id}");

        match algo {
            SessionAlgorithm::Plain => {
                let info = SessionInfo {
                    algorithm: algo,
                    aes_key: None,
                };
                self.insert(path.clone(), info)?;
                Ok((Value::from(""), path))
            }
            SessionAlgorithm::DhIetf1024 => {
                // Extract client public key bytes from the input Array<Byte>
                let client_pubkey: Vec<u8> = match input {
                    Value::Array(arr) => arr
                        .iter()
                        .map(|v| match v {
                            Value::U8(b) => Ok(*b),
                            _ => Err(BackendError::Unavailable(
                                "DH input must be Array<Byte>".to_string(),
                            )),
                        })
                        .collect::<Result<Vec<u8>, _>>()?,
                    _ => {
                        return Err(BackendError::Unavailable(
                            "DH session requires Array<Byte> input (client public key)".to_string(),
                        ))
                    }
                };

                let server_kp = generate_dh_keypair()?;
                let aes_key = derive_session_key(&server_kp, &client_pubkey)?;

                let server_pubkey = server_kp.public_bytes.clone();
                let info = SessionInfo {
                    algorithm: algo,
                    aes_key: Some(aes_key),
                };
                self.insert(path.clone(), info)?;

                // Return server public key as Array<Byte> (ay signature)
                let output = Value::from(server_pubkey);
                Ok((output, path))
            }
        }
    }

    fn insert(&self, path: String, info: SessionInfo) -> Result<(), BackendError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| BackendError::Unavailable("session lock poisoned".to_string()))?;
        sessions.insert(path, info);
        Ok(())
    }

    pub fn close_session(&self, path: &str) -> Result<(), BackendError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| BackendError::Unavailable("session lock poisoned".to_string()))?;
        sessions.remove(path);
        Ok(())
    }

    pub fn is_valid(&self, path: &str) -> Result<bool, BackendError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| BackendError::Unavailable("session lock poisoned".to_string()))?;
        Ok(sessions.contains_key(path))
    }

    /// Validate that a session path is non-empty, not root, and refers to a
    /// known open session. Returns an error describing the failure.
    pub fn validate(&self, session: &str) -> Result<(), BackendError> {
        if session.is_empty() || session == "/" {
            return Err(BackendError::Unavailable("no session provided".to_string()));
        }
        let valid = self.is_valid(session)?;
        if valid {
            Ok(())
        } else {
            Err(BackendError::Unavailable("invalid session".to_string()))
        }
    }

    /// Return a copy of the AES-128 session key for a DH-encrypted session.
    ///
    /// Returns `None` for plain sessions or unknown session paths.
    pub fn get_session_key(&self, path: &str) -> Result<Option<Zeroizing<[u8; 16]>>, BackendError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| BackendError::Unavailable("session lock poisoned".to_string()))?;
        let info = match sessions.get(path) {
            Some(i) => i,
            None => return Ok(None),
        };
        Ok(info.aes_key.as_ref().map(|k| Zeroizing::new(**k)))
    }

    pub fn count(&self) -> Result<usize, BackendError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| BackendError::Unavailable("session lock poisoned".to_string()))?;
        Ok(sessions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_session_key, generate_dh_keypair};

    fn plain_input() -> Value<'static> {
        Value::from("")
    }

    fn dh_input(pubkey_bytes: &[u8]) -> Value<'static> {
        Value::from(pubkey_bytes.to_vec())
    }

    #[test]
    fn open_and_validate_session() {
        let mgr = SessionManager::new();
        let (_output, path) = mgr.open_session("plain", &plain_input()).unwrap();

        assert!(mgr.validate(&path).is_ok());
        assert!(mgr.is_valid(&path).unwrap());
        assert_eq!(mgr.count().unwrap(), 1);
    }

    #[test]
    fn plain_session_output_is_empty_string() {
        let mgr = SessionManager::new();
        let (output, _path) = mgr.open_session("plain", &plain_input()).unwrap();
        let s: &str = output.downcast_ref().unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn plain_session_has_no_aes_key() {
        let mgr = SessionManager::new();
        let (_, path) = mgr.open_session("plain", &plain_input()).unwrap();
        let key = mgr.get_session_key(&path).unwrap();
        assert!(key.is_none());
    }

    #[test]
    fn dh_session_negotiates_key() {
        let mgr = SessionManager::new();
        let client_kp = generate_dh_keypair().unwrap();
        let input = dh_input(&client_kp.public_bytes);

        let (output, path) = mgr
            .open_session("dh-ietf1024-sha256-aes128-cbc-pkcs7", &input)
            .unwrap();

        // Output must be the server public key (128 bytes)
        let server_pubkey: Vec<u8> = match &output {
            Value::Array(arr) => arr
                .iter()
                .map(|v| match v {
                    Value::U8(b) => *b,
                    _ => panic!("expected U8"),
                })
                .collect(),
            _ => panic!("expected Array output for DH session"),
        };
        assert_eq!(server_pubkey.len(), 128);

        // AES key must be stored and be 16 bytes
        let key = mgr.get_session_key(&path).unwrap();
        assert!(key.is_some());
        assert_eq!(key.unwrap().len(), 16);
    }

    #[test]
    fn dh_session_key_matches_client_derived_key() {
        let mgr = SessionManager::new();
        let client_kp = generate_dh_keypair().unwrap();
        let input = dh_input(&client_kp.public_bytes);

        let (output, path) = mgr
            .open_session("dh-ietf1024-sha256-aes128-cbc-pkcs7", &input)
            .unwrap();

        let server_pubkey: Vec<u8> = match &output {
            Value::Array(arr) => arr
                .iter()
                .map(|v| match v {
                    Value::U8(b) => *b,
                    _ => panic!("expected U8"),
                })
                .collect(),
            _ => panic!("expected Array"),
        };

        // Client derives its key using the server's public key
        let client_key = derive_session_key(&client_kp, &server_pubkey).unwrap();
        // Server-side key stored in the session manager
        let server_key = mgr.get_session_key(&path).unwrap().unwrap();

        assert_eq!(
            client_key.as_ref(),
            server_key.as_ref(),
            "client and server must independently derive the same AES key"
        );
    }

    #[test]
    fn dh_session_invalid_pubkey_rejected() {
        let mgr = SessionManager::new();
        // Wrong-length public key (64 bytes instead of 128)
        let input = dh_input(&[0u8; 64]);
        assert!(mgr
            .open_session("dh-ietf1024-sha256-aes128-cbc-pkcs7", &input)
            .is_err());
    }

    #[test]
    fn dh_session_non_array_input_rejected() {
        let mgr = SessionManager::new();
        let input = Value::from("not-an-array");
        assert!(mgr
            .open_session("dh-ietf1024-sha256-aes128-cbc-pkcs7", &input)
            .is_err());
    }

    #[test]
    fn validate_rejects_empty_path() {
        let mgr = SessionManager::new();
        let err = mgr.validate("").unwrap_err();
        match err {
            BackendError::Unavailable(msg) => assert!(msg.contains("no session")),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_root_path() {
        let mgr = SessionManager::new();
        let err = mgr.validate("/").unwrap_err();
        match err {
            BackendError::Unavailable(msg) => assert!(msg.contains("no session")),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_unknown_session() {
        let mgr = SessionManager::new();
        let err = mgr
            .validate("/org/freedesktop/secrets/session/nonexistent")
            .unwrap_err();
        match err {
            BackendError::Unavailable(msg) => assert!(msg.contains("invalid session")),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn close_session_removes_it() {
        let mgr = SessionManager::new();
        let (_, path) = mgr.open_session("plain", &plain_input()).unwrap();
        assert_eq!(mgr.count().unwrap(), 1);

        mgr.close_session(&path).unwrap();
        assert_eq!(mgr.count().unwrap(), 0);
        assert!(!mgr.is_valid(&path).unwrap());
    }

    #[test]
    fn validate_after_close_fails() {
        let mgr = SessionManager::new();
        let (_, path) = mgr.open_session("plain", &plain_input()).unwrap();
        mgr.close_session(&path).unwrap();

        let err = mgr.validate(&path).unwrap_err();
        match err {
            BackendError::Unavailable(msg) => assert!(msg.contains("invalid session")),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn multiple_sessions_independent() {
        let mgr = SessionManager::new();
        let (_, path1) = mgr.open_session("plain", &plain_input()).unwrap();
        let (_, path2) = mgr.open_session("plain", &plain_input()).unwrap();
        assert_ne!(path1, path2);
        assert_eq!(mgr.count().unwrap(), 2);

        mgr.close_session(&path1).unwrap();
        assert_eq!(mgr.count().unwrap(), 1);
        assert!(!mgr.is_valid(&path1).unwrap());
        assert!(mgr.is_valid(&path2).unwrap());
    }

    #[test]
    fn session_path_format() {
        let mgr = SessionManager::new();
        let (_, path) = mgr.open_session("plain", &plain_input()).unwrap();
        assert!(path.starts_with("/org/freedesktop/secrets/session/s"));
        // The 's' prefix + 32 hex chars = 33 chars after the prefix
        let suffix = path
            .strip_prefix("/org/freedesktop/secrets/session/s")
            .unwrap();
        assert_eq!(suffix.len(), 32);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn close_nonexistent_session_is_noop() {
        let mgr = SessionManager::new();
        assert!(mgr
            .close_session("/org/freedesktop/secrets/session/snonexistent")
            .is_ok());
    }

    #[test]
    fn get_session_key_unknown_path_returns_none() {
        let mgr = SessionManager::new();
        let key = mgr.get_session_key("/nonexistent").unwrap();
        assert!(key.is_none());
    }

    #[test]
    fn unknown_algorithm_rejected() {
        let mgr = SessionManager::new();
        let result = mgr.open_session("bogus", &plain_input());
        assert!(result.is_err());
    }
}
