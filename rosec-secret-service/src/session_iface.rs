//! D-Bus interface for `org.freedesktop.Secret.Session`.
//!
//! Each open session gets an object at `/org/freedesktop/secrets/session/<id>`.
//! The spec requires a `Close()` method on this interface.

use std::sync::Arc;

use crate::error::SecretServiceError;
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
    async fn close(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), SecretServiceError> {
        let owner = crate::session::SessionOwner::from_request(conn, &header)?;
        self.sessions.close_for(&self.path, &owner)?;
        let _ = conn
            .object_server()
            .remove::<Self, _>(self.path.as_str())
            .await;
        Ok(())
    }
}
