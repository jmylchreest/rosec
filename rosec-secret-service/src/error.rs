//! Custom D-Bus errors for the Secret Service specification.
//!
//! The freedesktop Secret Service spec defines `org.freedesktop.Secret.Error.IsLocked`
//! as a custom error that must be raised when a client attempts to access an item
//! or collection that is locked.  This module provides a `SecretServiceError` enum
//! that includes this error alongside the standard `fdo::Error` variants.

/// Secret-Service-specific D-Bus errors.
///
/// This enum covers the custom `org.freedesktop.Secret.Error.IsLocked` error
/// defined by the spec, plus common fdo error wrappers so that callers can use
/// `?` on existing `FdoError` results without manual conversion.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum SecretServiceError {
    /// Standard zbus error (automatic `From<zbus::Error>` impl).
    #[zbus(error)]
    ZBus(zbus::Error),

    /// `org.freedesktop.Secret.Error.IsLocked` -- the item or collection is
    /// locked and must be unlocked before this operation can proceed.
    IsLocked(String),

    /// The requested transfer session does not exist or has been closed.
    NoSession(String),

    /// Generic failure (maps to `org.freedesktop.Secret.Error.Failed`).
    Failed(String),

    /// Operation not supported (maps to `org.freedesktop.Secret.Error.NotSupported`).
    NotSupported(String),
}

impl From<zbus::fdo::Error> for SecretServiceError {
    fn from(err: zbus::fdo::Error) -> Self {
        match err {
            zbus::fdo::Error::NotSupported(msg) => SecretServiceError::NotSupported(msg),
            other => SecretServiceError::Failed(format!("{other}")),
        }
    }
}
