//! rosec-pam-unlock — pam_exec hook for auto-unlocking rosec vaults at login.
//!
//! This binary is intended to be invoked by `pam_exec.so` with the
//! `expose_authtok` option, which provides the user's login password on
//! stdin (null-terminated).
//!
//! It connects to the D-Bus session bus, enumerates locked vault backends,
//! and attempts to unlock each one using the login password via the
//! `AuthBackendFromPipe` method on `org.rosec.Daemon`.  The password is
//! passed through a pipe fd (SCM_RIGHTS), never as a D-Bus message payload,
//! so it is invisible to `dbus-monitor`.
//!
//! # PAM configuration
//!
//! Add to the appropriate PAM config (e.g. `/etc/pam.d/system-login`):
//!
//! ```text
//! auth  optional  pam_exec.so  expose_authtok quiet /usr/lib/rosec/rosec-pam-unlock
//! ```
//!
//! # Security
//!
//! - The password is read from stdin and zeroized after use.
//! - The password is sent to the daemon via a pipe fd — never on the D-Bus wire.
//! - Errors are silently ignored — this module must never block login.
//! - No sensitive data is written to stdout/stderr/syslog.
//! - The D-Bus session bus is per-user, limiting exposure.

use std::io::Read as _;
use std::os::unix::io::FromRawFd as _;

use zeroize::Zeroize as _;

/// Exit codes for pam_exec. PAM_SUCCESS = 0, PAM_IGNORE = 25.
/// We use PAM_SUCCESS on success and PAM_IGNORE on any failure so that
/// the `optional` module never blocks login.
const PAM_SUCCESS: i32 = 0;
const PAM_IGNORE: i32 = 25;

fn main() -> ! {
    let code = match run() {
        Ok(()) => PAM_SUCCESS,
        Err(()) => PAM_IGNORE,
    };
    std::process::exit(code);
}

fn run() -> Result<(), ()> {
    let mut password = read_password_from_stdin().map_err(|_| ())?;
    if password.is_empty() {
        return Err(());
    }

    let result = unlock_vaults(&password);

    // Zeroize the password regardless of outcome.
    password.zeroize();

    result
}

/// Read the password from stdin as provided by `pam_exec` with `expose_authtok`.
///
/// pam_exec sends the password null-terminated on stdin. We read until EOF
/// or the first null byte, whichever comes first.
fn read_password_from_stdin() -> Result<Vec<u8>, ()> {
    let mut buf = Vec::with_capacity(256);

    // Read all available stdin. pam_exec closes the write end after
    // sending the password, so read_to_end will return once done.
    std::io::stdin().read_to_end(&mut buf).map_err(|_| ())?;

    // Strip trailing null byte if present (pam_exec null-terminates).
    if buf.last() == Some(&0) {
        buf.pop();
    }

    // Also strip any trailing newline that some PAM configurations add.
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }

    Ok(buf)
}

/// Create a pipe, write `data` to the write end, close it, and return the
/// read end as a `zvariant::OwnedFd` suitable for D-Bus fd-passing.
///
/// The password travels through kernel pipe buffers only — never through
/// the D-Bus message payload.
fn make_password_pipe(data: &[u8]) -> Result<zvariant::OwnedFd, ()> {
    let mut fds = [0_i32; 2];

    // SAFETY: pipe() writes exactly two fds into the array.
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(());
    }

    let read_fd = fds[0];
    let write_fd = fds[1];

    // Write the password to the write end.
    {
        // SAFETY: write_fd is a valid fd from pipe().
        let mut write_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
        use std::io::Write as _;
        let write_result = write_file.write_all(data);
        // write_file is dropped here → write end closed, signalling EOF to reader.
        if write_result.is_err() {
            // Close the read end too on failure.
            unsafe { libc::close(read_fd) };
            return Err(());
        }
    }

    // Wrap the read end in OwnedFd for D-Bus fd-passing.
    // SAFETY: read_fd is a valid fd from pipe(); OwnedFd takes ownership.
    let owned: std::os::fd::OwnedFd = unsafe { std::os::fd::OwnedFd::from_raw_fd(read_fd) };
    Ok(zvariant::OwnedFd::from(owned))
}

/// Connect to the D-Bus session bus and attempt to unlock all locked vaults.
fn unlock_vaults(password: &[u8]) -> Result<(), ()> {
    // Build a minimal tokio runtime for the async D-Bus calls.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?;

    rt.block_on(unlock_vaults_async(password))
}

async fn unlock_vaults_async(password: &[u8]) -> Result<(), ()> {
    let conn = zbus::Connection::session().await.map_err(|_| ())?;

    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await
    .map_err(|_| ())?;

    // BackendList returns Vec<(id, name, kind, locked)>.
    let backends: Vec<(String, String, String, bool)> =
        proxy.call("BackendList", &()).await.map_err(|_| ())?;

    let mut any_unlocked = false;
    for (id, _name, kind, locked) in &backends {
        if kind != "vault" || !locked {
            continue;
        }

        // Create a fresh pipe for each unlock attempt — each pipe is
        // consumed (read + closed) by the daemon, so we cannot reuse them.
        let pipe_fd = make_password_pipe(password).map_err(|_| ())?;

        // AuthBackendFromPipe(backend_id, pipe_fd) — password travels via
        // the pipe fd, never as a D-Bus message string.
        let result: Result<bool, zbus::Error> = proxy
            .call("AuthBackendFromPipe", &(id.as_str(), pipe_fd))
            .await;
        if result.is_ok() {
            any_unlocked = true;
        }
    }

    if any_unlocked { Ok(()) } else { Err(()) }
}
