//! Error types for the Bitwarden backend.

#[derive(Debug, thiserror::Error)]
pub enum BitwardenError {
    #[error("API error: {0}")]
    Api(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("two-factor authentication required")]
    TwoFactorRequired { providers: Vec<u8> },

    /// Server rejected login because this device UUID is not yet registered.
    /// The user must run `rosec backend register <id>` with their personal
    /// API key to register the device, then retry authentication.
    #[error("new device verification required — run `rosec backend register <id>` first")]
    DeviceVerificationRequired,

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("cipher string parse error: {0}")]
    CipherParse(String),

    #[error("vault is locked")]
    Locked,

    #[error("item not found: {0}")]
    NotFound(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl From<BitwardenError> for rosec_core::BackendError {
    fn from(err: BitwardenError) -> Self {
        match err {
            BitwardenError::Locked => Self::Locked,
            BitwardenError::NotFound(_) => Self::NotFound,
            BitwardenError::TwoFactorRequired { .. } => {
                Self::Unavailable("two-factor authentication required".to_string())
            }
            BitwardenError::DeviceVerificationRequired => Self::RegistrationRequired,
            other => Self::Other(anyhow::anyhow!("{other}")),
        }
    }
}
