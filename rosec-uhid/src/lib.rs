//! rosec virtual FIDO2 authenticator frontend.
//!
//! Presents a virtual CTAP2 security key over `/dev/uhid` so unmodified
//! browsers (Firefox, Chromium) use rosec-stored passkeys with no extension
//! or browser patch. See `docs/developers/fido2-passkeys.md` for the full
//! design.
//!
//! Split into a privileged, disposable broker and an unprivileged frontend:
//!
//! - [`uhid`] — `/dev/uhid` codec and the hard-coded FIDO report descriptor.
//! - [`broker`] — the privileged half: create the device and pass its fd.
//! - [`ctaphid`] — CTAPHID transport framing (channels, fragmentation).
//!
//! The CTAP2 command layer and ceremony engine live in the daemon, driven by
//! the fd the broker hands over.

pub mod broker;
pub mod ctap2;
pub mod ctaphid;
pub mod uhid;

/// Default path of the broker's fd-passing socket. A per-user socket under
/// the runtime dir would also work; a single system socket with per-caller
/// `SO_PEERCRED` keeps the privileged surface to one place.
pub const BROKER_SOCKET_PATH: &str = "/run/rosec/uhid-broker.sock";
