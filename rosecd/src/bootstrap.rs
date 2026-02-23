/// Process-level security hardening applied at daemon startup.
///
/// Must be called as the **very first thing** in `main()`, before any threads
/// are spawned or secrets are touched.  All operations are best-effort and
/// non-fatal: a warning is logged if a call fails, but the daemon continues.
///
/// # What this does
///
/// 1. **`PR_SET_DUMPABLE 0`** — prevents `/proc/<pid>/mem` reads by non-root
///    processes and disables core dumps, protecting secrets from being written
///    to disk on crash.
///
/// 2. **`mlockall(MCL_CURRENT | MCL_FUTURE)`** — pins all present and future
///    memory pages into RAM so they are never paged/swapped to disk.  Requires
///    `CAP_IPC_LOCK` (or running as root); logs a warning if the capability is
///    absent.
#[cfg(unix)]
pub fn secure_bootstrap() {
    set_not_dumpable();
    lock_memory();
}

/// No-op on non-unix platforms.
#[cfg(not(unix))]
pub fn secure_bootstrap() {}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn set_not_dumpable() {
    // SAFETY: prctl is safe to call with PR_SET_DUMPABLE and a plain integer arg.
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0i64, 0i64, 0i64, 0i64) };
    if ret == 0 {
        tracing::info!("PR_SET_DUMPABLE=0: core dumps and /proc/pid/mem access disabled");
    } else {
        let err = std::io::Error::last_os_error();
        tracing::warn!("PR_SET_DUMPABLE=0 failed (non-fatal): {err}");
    }
}

#[cfg(unix)]
fn lock_memory() {
    // SAFETY: mlockall is safe to call; failure is non-fatal.
    let ret = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if ret == 0 {
        tracing::info!("mlockall(MCL_CURRENT|MCL_FUTURE): all memory pages locked in RAM");
    } else {
        let err = std::io::Error::last_os_error();
        // ENOMEM or EPERM are the typical cases (no CAP_IPC_LOCK).
        tracing::warn!(
            "mlockall failed (non-fatal — daemon will run without memory locking): {err}"
        );
    }
}
