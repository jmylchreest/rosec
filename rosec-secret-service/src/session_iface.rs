//! D-Bus interface for `org.freedesktop.Secret.Session`.
//!
//! Each open session gets an object at `/org/freedesktop/secrets/session/<id>`.
//! The spec requires a `Close()` method on this interface.

use std::sync::Arc;

use zbus::fdo::Error as FdoError;
use zbus::interface;

use crate::session::SessionManager;

/// D-Bus object implementing `org.freedesktop.Secret.Session`.
pub struct SecretSession {
    path: String,
    sessions: Arc<SessionManager>,
}

impl SecretSession {
    pub fn new(path: String, sessions: Arc<SessionManager>) -> Self {
        Self { path, sessions }
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl SecretSession {
    /// Close this session.
    fn close(&self) -> Result<(), FdoError> {
        self.sessions
            .close_session(&self.path)
            .map_err(|e| FdoError::Failed(e.to_string()))
    }
}
