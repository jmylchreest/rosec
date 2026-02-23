//! Error types for the Bitwarden backend.

#[derive(Debug, thiserror::Error)]
pub enum BitwardenError {
    #[error("API error: {0}")]
    Api(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("two-factor authentication required")]
    TwoFactorRequired { providers: Vec<u8> },

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
            other => Self::Other(anyhow::anyhow!("{other}")),
        }
    }
}
