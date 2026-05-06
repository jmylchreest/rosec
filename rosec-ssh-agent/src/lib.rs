//! SSH agent for rosec.
//!
//! Exposes SSH keys from unlocked providers over the standard OpenSSH
//! agent protocol.  Backed by a shared [`KeyStore`] that `rosecd` populates
//! and clears as providers are locked/unlocked.
//!
//! # Architecture
//!
//! ```text
//! rosecd  ─────── KeyStore (Arc<RwLock<…>>) ──────► SshAgent (listen)
//!  │                   ▲                                   │
//!  │  provider unlocked │                            UnixListener
//!  └──────── populate_from_providers()                      │
//!                                                   per-connection
//!                                              AgentSession (clone of store)
//! ```
//!
//! # Key discovery
//!
//! Keys are discovered from two sources:
//!
//! 1. **Native SSH key items** (`CipherType::SshKey`): the `private_key` PEM
//!    field is parsed directly.
//! 2. **PEM keys in any vault item**: the `notes`, `password`, and hidden
//!    `custom.*` fields are scanned for recognised PEM headers.
//!
//! The item name and `revision_date` are preserved so that the FUSE layer can
//! use them for config generation and conflict resolution.

pub mod keystore;
pub mod pem;
pub mod sandbox;
pub mod session;

pub use keystore::{KeyEntry, KeyStore};
pub use session::{ConfirmCallback, SshAgent};
