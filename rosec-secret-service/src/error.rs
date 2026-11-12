//! Secret Service errors alongside unmodified standard D-Bus errors.
use zbus::DBusError;

/// Only the three errors defined by Secret Service use its custom namespace.
/// Standard errors retain both their original name and description.
#[derive(Debug)]
pub enum SecretServiceError {
    IsLocked(String),
    NoSession(String),
    NoSuchObject(String),
    Failed(String),
    NotSupported(String),
    InvalidArgs(String),
    DBus(zbus::BoxDBusError),
}

impl DBusError for SecretServiceError {
    fn name(&self) -> zbus::names::ErrorName<'_> {
        let name = match self {
            Self::IsLocked(_) => "org.freedesktop.Secret.Error.IsLocked",
            Self::NoSession(_) => "org.freedesktop.Secret.Error.NoSession",
            Self::NoSuchObject(_) => "org.freedesktop.Secret.Error.NoSuchObject",
            Self::Failed(_) => "org.freedesktop.DBus.Error.Failed",
            Self::NotSupported(_) => "org.freedesktop.DBus.Error.NotSupported",
            Self::InvalidArgs(_) => "org.freedesktop.DBus.Error.InvalidArgs",
            Self::DBus(error) => return error.name(),
        };
        // Every name above is a fixed, valid D-Bus error name.
        zbus::names::ErrorName::from_static_str_unchecked(name)
    }

    fn description(&self) -> Option<&str> {
        match self {
            Self::IsLocked(message)
            | Self::NoSession(message)
            | Self::NoSuchObject(message)
            | Self::Failed(message)
            | Self::NotSupported(message)
            | Self::InvalidArgs(message) => Some(message),
            Self::DBus(error) => error.description(),
        }
    }

    fn create_reply(&self, call: &zbus::message::Header<'_>) -> zbus::Result<zbus::Message> {
        match self {
            Self::DBus(error) => error.create_reply(call),
            _ => zbus::Message::error(call, self.name())
                .build(&self.description().unwrap_or_default()),
        }
    }
}

impl std::fmt::Display for SecretServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}",
            self.name(),
            self.description().unwrap_or_default()
        )
    }
}
impl std::error::Error for SecretServiceError {}

impl From<zbus::fdo::Error> for SecretServiceError {
    fn from(error: zbus::fdo::Error) -> Self {
        Self::DBus(Box::new(error))
    }
}
impl From<zbus::Error> for SecretServiceError {
    fn from(error: zbus::Error) -> Self {
        Self::DBus(error.into())
    }
}
