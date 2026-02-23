use std::collections::HashMap;
use std::sync::Mutex;

use rosec_core::BackendError;
use uuid::Uuid;
use zvariant::Value;

use crate::crypto::SessionAlgorithm;

#[derive(Debug, Default, Clone)]
pub struct SessionManager {
    sessions: std::sync::Arc<Mutex<HashMap<String, SessionInfo>>>,
}

#[derive(Debug, Clone)]
struct SessionInfo {
    /// The negotiated algorithm for this session (e.g. "plain").
    /// Retained for future DH-IETF session encryption support.
    #[allow(dead_code)]
    algorithm: String,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open_session(&self, algorithm: &str) -> Result<(Value<'_>, String), BackendError> {
        let _algorithm = SessionAlgorithm::parse(algorithm)?;
        let id = Uuid::new_v4().simple().to_string();
        let path = format!("/org/freedesktop/secrets/session/s{id}");
        let info = SessionInfo {
            algorithm: algorithm.to_string(),
        };
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| BackendError::Unavailable("session lock poisoned".to_string()))?;
        sessions.insert(path.clone(), info);
        Ok((Value::from(""), path))
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

    #[test]
    fn open_and_validate_session() {
        let mgr = SessionManager::new();
        let (_output, path) = mgr.open_session("plain").unwrap();

        assert!(mgr.validate(&path).is_ok());
        assert!(mgr.is_valid(&path).unwrap());
        assert_eq!(mgr.count().unwrap(), 1);
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
        let (_output, path) = mgr.open_session("plain").unwrap();
        assert_eq!(mgr.count().unwrap(), 1);

        mgr.close_session(&path).unwrap();
        assert_eq!(mgr.count().unwrap(), 0);
        assert!(!mgr.is_valid(&path).unwrap());
    }

    #[test]
    fn validate_after_close_fails() {
        let mgr = SessionManager::new();
        let (_output, path) = mgr.open_session("plain").unwrap();
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
        let (_, path1) = mgr.open_session("plain").unwrap();
        let (_, path2) = mgr.open_session("plain").unwrap();
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
        let (_, path) = mgr.open_session("plain").unwrap();
        // Should start with the expected prefix and contain a UUID hex string
        assert!(path.starts_with("/org/freedesktop/secrets/session/s"));
        // The 's' prefix + 32 hex chars = 33 chars after the prefix
        let suffix = path
            .strip_prefix("/org/freedesktop/secrets/session/s")
            .unwrap();
        assert_eq!(suffix.len(), 32);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn open_session_output_is_empty_string() {
        let mgr = SessionManager::new();
        let (output, _path) = mgr.open_session("plain").unwrap();
        // For plain sessions, the output should be an empty string
        let s: &str = output.downcast_ref().unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn close_nonexistent_session_is_noop() {
        let mgr = SessionManager::new();
        // Closing a session that doesn't exist should not error
        assert!(mgr
            .close_session("/org/freedesktop/secrets/session/snonexistent")
            .is_ok());
    }
}
