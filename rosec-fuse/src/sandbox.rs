//! FUSE mount-time sandbox knobs.
//!
//! The kernel already applies `NoSuid` for non-root FUSE mounts, but listing
//! the flags here documents intent and survives any change to the kernel
//! default. rosec's FUSE filesystems serve only public SSH key bytes and
//! ASCII TOTP digits — never executable code, never devices, never setuid.

use fuser::{MountOption, SessionACL};

/// Defence-in-depth mount flags applied to every rosec FUSE mount.
///
/// `fs_name` is included for `mount`/`mountinfo` readability (e.g.
/// `rosec-ssh`, `rosec-totp`) and identification in stale-mount cleanup.
pub fn mount_options(fs_name: &str) -> Vec<MountOption> {
    vec![
        MountOption::RO,
        MountOption::NoSuid,
        MountOption::NoDev,
        MountOption::NoExec,
        MountOption::FSName(fs_name.to_string()),
    ]
}

/// All rosec FUSE mounts use Owner ACL — only the user who owns the mount
/// can access it. Re-exported here so callers don't need a separate `fuser`
/// import for sandbox configuration.
pub const ACL: SessionACL = SessionACL::Owner;
