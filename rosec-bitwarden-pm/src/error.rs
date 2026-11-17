//! Error types for the Bitwarden WASM guest plugin.

use crate::protocol::ErrorKind;

#[derive(Debug)]
#[allow(dead_code)]
pub enum BitwardenError {
    Api(String),
    Auth(String),
    TwoFactorRequired {
        providers: Vec<u8>,
        email_hint: Option<String>,
    },
    /// Server rejected login because this device UUID is not yet registered.
    DeviceVerificationRequired,
    Crypto(String),
    CipherParse(String),
    Locked,
    NotFound(String),
    Http(String),
}

impl std::fmt::Display for BitwardenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api(msg) => write!(f, "API error: {msg}"),
            Self::Auth(msg) => write!(f, "authentication failed: {msg}"),
            Self::TwoFactorRequired { .. } => write!(f, "two-factor authentication required"),
            Self::DeviceVerificationRequired => {
                write!(
                    f,
                    "new device verification required — run `rosec provider register <id>` first"
                )
            }
            Self::Crypto(msg) => write!(f, "crypto error: {msg}"),
            Self::CipherParse(msg) => write!(f, "cipher string parse error: {msg}"),
            Self::Locked => write!(f, "vault is locked"),
            Self::NotFound(msg) => write!(f, "item not found: {msg}"),
            Self::Http(msg) => write!(f, "HTTP error: {msg}"),
        }
    }
}

impl BitwardenError {
    /// Map this error to a protocol `ErrorKind` for the host.
    ///
    /// `Crypto` and `CipherParse` errors are mapped to `AuthFailed` because in
    /// the Bitwarden PM guest they almost always mean the password-derived key
    /// was wrong (cannot decrypt the vault's `protected_key`).  The host uses
    /// this to distinguish "wrong password — don't re-prompt" from internal
    /// errors.
    pub fn to_error_kind(&self) -> ErrorKind {
        match self {
            Self::Locked => ErrorKind::Locked,
            Self::NotFound(_) => ErrorKind::NotFound,
            Self::TwoFactorRequired { .. } => ErrorKind::TwoFactorRequired,
            Self::DeviceVerificationRequired => ErrorKind::RegistrationRequired,
            Self::Auth(_) | Self::Crypto(_) | Self::CipherParse(_) => ErrorKind::AuthFailed,
            Self::Http(_) => ErrorKind::Unavailable,
            Self::Api(_) => ErrorKind::Other,
        }
    }
}
