//! FUSE virtual filesystem for rosec SSH keys and config snippets.
//!
//! Mounts at `$XDG_RUNTIME_DIR/rosec/ssh/` and exposes:
//!
//! ```text
//! ssh/
//! ├── keys/
//! │   ├── by-name/<item-name>.pub
//! │   ├── by-fingerprint/<sha256>.pub
//! │   └── by-host/<hostname>.pub      (* → _star, ? → _qmark)
//! └── config.d/<normalised-name>.conf
//! ```
//!
//! The filesystem is **read-only** and entirely in-memory.  No private key
//! material is ever written — only OpenSSH public keys and generated SSH
//! config snippets.
//!
//! Call [`mount`] to start the background FUSE thread.  The returned
//! [`MountHandle`] keeps the filesystem alive; drop it to unmount.

pub mod config;
pub mod fs;
pub mod naming;

pub use config::build_config_snippets;
pub use fs::{MountHandle, SshFuse, mount};
