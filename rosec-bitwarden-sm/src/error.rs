//! Error types for the Bitwarden SM WASM guest plugin.

use crate::protocol::ErrorKind;

#[derive(Debug)]
pub enum SmError {
    Api(String),
    Crypto(String),
    InvalidToken(&'static str),
    Http(String),
}

impl std::fmt::Display for SmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api(msg) => write!(f, "API error: {msg}"),
            Self::Crypto(msg) => write!(f, "crypto error: {msg}"),
            Self::InvalidToken(msg) => write!(f, "invalid access token: {msg}"),
            Self::Http(msg) => write!(f, "HTTP error: {msg}"),
        }
    }
}

impl SmError {
    /// Map this error to a protocol `ErrorKind` for the host.
    pub fn to_error_kind(&self) -> ErrorKind {
        match self {
            Self::Http(_) => ErrorKind::Unavailable,
            Self::Api(_) | Self::Crypto(_) | Self::InvalidToken(_) => ErrorKind::Other,
        }
    }
}
