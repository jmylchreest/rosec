//! Bitwarden vault backend for rosec.
//!
//! Provides read-only access to a Bitwarden password vault through
//! the standard Bitwarden API, compatible with both official servers
//! and Vaultwarden.
//!
//! # Architecture
//!
//! - **`api`**: HTTP client for Bitwarden API endpoints (prelogin, login, sync)
//! - **`crypto`**: Key derivation (PBKDF2, Argon2id, HKDF) and encryption (AES-CBC, HMAC-SHA256, RSA-OAEP)
//! - **`cipher`**: Cipher string parsing and decryption (`2.iv|ct|mac` format)
//! - **`vault`**: Decrypted vault state management
//! - **`backend`**: `VaultBackend` trait implementation
//!
//! # Usage
//!
//! ```rust,ignore
//! use rosec_bitwarden::{BitwardenBackend, BitwardenConfig};
//! use rosec_core::{UnlockInput, VaultBackend};
//!
//! let config = BitwardenConfig {
//!     id: "personal".to_string(),
//!     email: "user@example.com".to_string(),
//!     region: None,    // default: official US cloud
//!     base_url: None,
//!     api_url: None,
//!     identity_url: None,
//! };
//!
//! let backend = BitwardenBackend::new(config)?;
//! backend.unlock(UnlockInput::Password(zeroize::Zeroizing::new("master_password".to_string()))).await?;
//!
//! let items = backend.list_items().await?;
//! ```

pub mod api;
pub mod backend;
pub mod cipher;
pub mod crypto;
pub mod error;
pub mod notifications;
pub mod oauth_cred;
pub mod vault;

pub use backend::{BitwardenBackend, BitwardenConfig, BitwardenRegion};
pub use error::BitwardenError;
