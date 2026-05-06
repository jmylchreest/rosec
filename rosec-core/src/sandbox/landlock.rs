//! Landlock helpers shared across rosec binaries.
//!
//! Each binary builds its own ruleset (the WASM-provider thread, rosec-prompt
//! at startup, rosec-pam-unlock at startup) but they share the same need for:
//!   - ABI version negotiation (graceful degradation on older kernels)
//!   - "build a filesystem ruleset from a list of (path, mode) pairs" — the
//!     same translation pattern is used by all callers
//!   - "build a network ruleset from a list of TCP ports for connect/bind"
//!
//! See `docs/developers/landlock.md` for the broader threat model.
//!
//! # Scope
//!
//! Landlock is **per-thread by default** in Linux. Calling
//! [`apply_paths_and_ports`] (or any helper here) restricts only the calling
//! thread; sibling threads in the same process are unaffected. Threads
//! spawned by the calling thread *afterwards* and child processes forked from
//! it inherit the ruleset.
//!
//! Source: [docs.kernel.org/userspace-api/landlock](https://docs.kernel.org/userspace-api/landlock.html)
//! — "Every new thread resulting from a clone(2) inherits Landlock domain
//! restrictions from its parent. This is similar to seccomp inheritance ...
//! one process's thread may apply Landlock rules to itself, but they will not
//! be automatically applied to other sibling threads."
//!
//! # Compatibility
//!
//! All helpers use [`CompatLevel::BestEffort`] so older kernels get a
//! degraded-but-not-broken ruleset rather than an outright failure. The
//! daemon **never fails to start** because Landlock is unsupported — it's
//! defence-in-depth.
//!
//! ABI floors:
//!   - V1 (kernel 5.13) — filesystem PathBeneath
//!   - V3 (kernel 6.2)  — refined PathBeneath (truncation)
//!   - V4 (kernel 6.7)  — TCP connect/bind rules

use std::path::Path;

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    PathFd, PathFdError, RestrictionStatus, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus,
};
use tracing::{debug, info, warn};

/// Highest Landlock ABI we knowingly target. Older kernels degrade
/// automatically via `CompatLevel::BestEffort`.
///
///   - V1 (kernel 5.13) — filesystem PathBeneath
///   - V3 (kernel 6.2)  — refined PathBeneath
///   - V4 (kernel 6.7)  — TCP connect/bind rules
///
/// We request V4 because we use TCP connect rules; kernels at V1–V3 will
/// silently drop the network rules and keep the filesystem ones.
const TARGET_ABI: ABI = ABI::V4;

/// Filesystem access mode for [`PathRule`] — read-only or read-write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsMode {
    Ro,
    Rw,
}

/// A single filesystem rule: which path is allowed, and at what access mode.
#[derive(Debug, Clone)]
pub struct PathRule {
    pub path: std::path::PathBuf,
    pub mode: FsMode,
}

impl PathRule {
    pub fn ro(p: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: p.into(),
            mode: FsMode::Ro,
        }
    }
    pub fn rw(p: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: p.into(),
            mode: FsMode::Rw,
        }
    }
}

/// A network rule: TCP connect to `port`. Port `0` means "any in
/// `ip_local_port_range`" per the Landlock ABI.
#[derive(Debug, Clone, Copy)]
pub struct ConnectPort(pub u16);

/// Apply a Landlock ruleset built from filesystem path rules and TCP-connect
/// port rules to the **calling thread**. Returns the kernel's enforcement
/// status (which may be `PartiallyEnforced` on older kernels).
///
/// Paths that don't exist are skipped with a `warn!` rather than failing the
/// whole apply — the caller's ruleset is built from policy declarations that
/// may legitimately reference paths the user hasn't created yet (e.g. a
/// `.kdbx` file path the user supplied but hasn't populated).
///
/// # Panics
///
/// Does not panic on its own; returns `RulesetError` for unrecoverable
/// build failures (ABI handshake, ruleset creation). Apply this at thread
/// startup; if it returns `Err` the caller decides whether to abort or
/// continue without sandbox.
pub fn apply_paths_and_ports(
    paths: &[PathRule],
    ports: &[ConnectPort],
) -> Result<RestrictionStatus, RulesetError> {
    let abi = TARGET_ABI;
    debug!(
        ?abi,
        "landlock: requesting target ABI (BestEffort fallback)"
    );

    let fs_access = AccessFs::from_all(abi);
    let net_access = AccessNet::from_all(abi);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(fs_access)?
        .handle_access(net_access)?
        .create()?;

    for rule in paths {
        match path_beneath_rule(&rule.path, rule.mode, abi) {
            Ok(Some(r)) => {
                ruleset = ruleset.add_rule(r)?;
            }
            Ok(None) => {
                debug!(
                    path = %rule.path.display(),
                    mode = ?rule.mode,
                    "landlock: skipping non-existent path"
                );
            }
            Err(e) => {
                warn!(
                    path = %rule.path.display(),
                    error = %e,
                    "landlock: failed to add path rule, skipping"
                );
            }
        }
    }

    for ConnectPort(port) in ports {
        let rule = NetPort::new(*port, AccessNet::ConnectTcp);
        ruleset = ruleset.add_rule(rule)?;
    }

    let status = ruleset.restrict_self()?;
    log_status(&status);
    Ok(status)
}

/// Build a single PathBeneath rule, returning `Ok(None)` if the path doesn't
/// exist (caller's policy may declare future-created paths) or `Err` for an
/// actual filesystem error.
fn path_beneath_rule(
    path: &Path,
    mode: FsMode,
    abi: ABI,
) -> Result<Option<PathBeneath<PathFd>>, PathFdError> {
    let fd = match PathFd::new(path) {
        Ok(fd) => fd,
        Err(PathFdError::OpenCall { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let rights: BitFlags<AccessFs> = match mode {
        FsMode::Ro => AccessFs::from_read(abi),
        FsMode::Rw => AccessFs::from_all(abi),
    };
    Ok(Some(
        PathBeneath::new(fd, rights).set_compatibility(CompatLevel::BestEffort),
    ))
}

fn log_status(status: &RestrictionStatus) {
    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!(
                abi = ?status.no_new_privs,
                "landlock: ruleset fully enforced"
            );
        }
        RulesetStatus::PartiallyEnforced => {
            info!(
                "landlock: ruleset partially enforced — kernel ABI is older than the requested ruleset; \
                 some access types are not restricted"
            );
        }
        RulesetStatus::NotEnforced => {
            warn!(
                "landlock: ruleset NOT enforced — Landlock is unsupported on this kernel \
                 or disabled at boot. Continuing without OS-level sandboxing."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonexistent_path_skipped() {
        let abi = ABI::V1;
        let r = path_beneath_rule(
            std::path::Path::new("/nonexistent/__rosec_test__"),
            FsMode::Ro,
            abi,
        );
        assert!(matches!(r, Ok(None)));
    }
}
