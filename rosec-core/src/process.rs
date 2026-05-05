//! Process-level security hardening.
//!
//! Call [`harden`] as the **very first thing** in `main()` — before any
//! threads are spawned, before any secrets touch process memory, before any
//! `execve` is even contemplated. All three operations are best-effort and
//! non-fatal: a debug log is emitted on failure but the process continues.
//!
//! # What `harden` does
//!
//! - **`PR_SET_NO_NEW_PRIVS = 1`** — once set, no subsequent `execve` can
//!   gain privileges via setuid / setgid / file capabilities. None of these
//!   binaries should ever invoke a setuid program; setting this once
//!   forecloses an entire class of escalation regardless.
//!
//! - **`PR_SET_DUMPABLE = 0`** — disables core dumps and blocks
//!   `/proc/<pid>/mem` reads from non-root processes. Critical for any
//!   binary that holds passwords or keys in memory: a crash without this
//!   could write those buffers to disk.
//!
//! - **`mlockall(MCL_CURRENT | MCL_FUTURE)`** — pins all present and future
//!   memory pages into RAM so they cannot be paged or swapped to disk.
//!   Requires `RLIMIT_MEMLOCK` headroom (typically generous on systemd
//!   distributions) or `CAP_IPC_LOCK`. Failures are silently tolerated —
//!   the process continues without memory locking.

#[cfg(unix)]
pub fn harden() {
    set_no_new_privs();
    set_not_dumpable();
    lock_memory();
}

#[cfg(not(unix))]
pub fn harden() {}

/// Subset of [`harden`] for processes that must remain introspectable by an
/// external service for the duration of a specific call.
///
/// Skips `PR_SET_DUMPABLE=0` because that flag re-owns `/proc/<pid>/*` to
/// root, which breaks anything that reads `/proc/<pid>/root` to identify
/// the requesting process — notably `xdg-desktop-portal`, which uses it
/// for sandbox-permission checks.
///
/// Callers should invoke [`set_not_dumpable`] manually once the
/// introspection-requiring phase is done and sensitive data is about to
/// enter memory.
#[cfg(unix)]
pub fn harden_introspectable() {
    set_no_new_privs();
    lock_memory();
}

#[cfg(not(unix))]
pub fn harden_introspectable() {}

#[cfg(unix)]
fn set_no_new_privs() {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS) takes a single flag argument and
    // has no preconditions. The set bit is sticky for the process lifetime.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        tracing::debug!("PR_SET_NO_NEW_PRIVS=1 failed (non-fatal): {err}");
    }
}

/// Set `PR_SET_DUMPABLE=0` on the current process. Disables core dumps and
/// re-owns `/proc/<pid>/*` to root, blocking any non-root process from
/// reading our memory or fds.
///
/// Exposed as `pub` so callers using [`harden_introspectable`] can flip
/// dumpable off after the introspection-requiring call has completed.
/// Best-effort — logs and continues on failure.
#[cfg(unix)]
pub fn set_not_dumpable() {
    // SAFETY: prctl(PR_SET_DUMPABLE) takes a plain integer. No pointers.
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0i64, 0i64, 0i64, 0i64) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        tracing::debug!("PR_SET_DUMPABLE=0 failed (non-fatal): {err}");
    }
}

#[cfg(not(unix))]
pub fn set_not_dumpable() {}

#[cfg(unix)]
fn lock_memory() {
    // SAFETY: mlockall takes a flag argument; failure is reported via errno.
    let ret = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        // ENOMEM (RLIMIT_MEMLOCK exceeded) and EPERM (no CAP_IPC_LOCK) are
        // expected on systems with tight defaults. Not actionable by users.
        tracing::debug!("mlockall failed (non-fatal): {err}");
    }
}
