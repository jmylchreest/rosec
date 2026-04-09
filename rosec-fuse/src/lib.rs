//! FUSE virtual filesystems for rosec.
//!
//! ## SSH (`$XDG_RUNTIME_DIR/rosec/ssh/`)
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
//! ## TOTP (`$XDG_RUNTIME_DIR/rosec/totp/`)
//!
//! ```text
//! totp/
//! ├── by-name/<item-label>.code
//! └── by-id/<hex-id>.code
//! ```
//!
//! Both filesystems are **read-only** and entirely in-memory.

pub mod config;
pub mod fs;
pub mod naming;
pub mod totp_fs;

pub use config::build_config_snippets;
pub use fs::{MountHandle, SshFuse, mount};
pub use totp_fs::{TotpEntry, TotpFuse, TotpMountHandle, totp_mount};
