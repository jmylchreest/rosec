//! Linux sandboxing primitives shared across rosec binaries and crates.
//!
//! Each binary or library that needs OS-level confinement has its own
//! `sandbox.rs` (or `sandbox/` module). This crate hosts the primitives
//! that aren't tied to a single binary's needs: process hardening
//! (`PR_SET_DUMPABLE`, `mlockall`, `NO_NEW_PRIVS`) and — once added — the
//! Landlock-ruleset-from-paths helpers used by the WASM-provider sandbox
//! and by rosec-prompt.
//!
//! Per-binary specifics (e.g. rosec-prompt's GUI/TTY-mode-aware ruleset,
//! rosec-pam-unlock's PAM-context ruleset, the WASM provider's
//! policy-derived ruleset) live in those crates' own `sandbox` modules
//! and call into the helpers here.

mod distro_compat;
pub mod landlock;
pub mod process;
pub mod spawn;

pub use process::{
    harden, harden_introspectable, harden_no_memlock, harden_setuid_capable, set_not_dumpable,
};
