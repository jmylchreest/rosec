//! Distro-specific path additions for the Landlock ruleset.
//!
//! Most Linux distros put libraries and data under `/usr/lib`, `/usr/share`,
//! `/etc`, etc. — a single `/usr` rule covers them. NixOS is the notable
//! exception: every package lives at `/nix/store/<hash>-<pkg>-<ver>/`, so
//! a ruleset that doesn't include `/nix/store` can't even `dlopen(libc)`.
//!
//! We detect such cases by file-system probe — no compile-time feature
//! flags so the same binary works across distros without rebuild. This
//! file is the home for that compatibility logic; keeping it here means
//! the main `landlock.rs` doesn't grow ad-hoc detection branches.

use std::path::PathBuf;
use tracing::debug;

use super::landlock::PathRule;

/// Read-only paths to add to every Landlock ruleset based on what's
/// present on the running system. Empty on a typical FHS distro.
pub fn portability_paths() -> Vec<PathRule> {
    let mut out = Vec::new();

    // NixOS: every binary's libs (including ours) live in /nix/store.
    // Content is mounted read-only post-install.
    if PathBuf::from("/nix/store").exists() {
        debug!("distro_compat: /nix/store detected (NixOS), adding ro");
        out.push(PathRule::ro("/nix/store"));
    }

    out
}
