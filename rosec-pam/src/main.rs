//! rosec-pam-unlock — pam_exec hook for unlocking rosec vaults on screen unlock.
//!
//! Invoked by `pam_exec.so expose_authtok`, which feeds the password on stdin
//! (NUL-terminated). We forward it to `rosecd` via the D-Bus method
//! `AuthProviderFromPipe`, passing the password through a pipe fd (SCM_RIGHTS)
//! so it never lands on the D-Bus wire visible to `dbus-monitor`.
//!
//! # Scope: screen unlock only, not initial login
//!
//! At initial login `$DBUS_SESSION_BUS_ADDRESS` is unset and `rosecd` is not
//! yet running, so the connection fails and the helper returns `PAM_IGNORE`
//! — login is never blocked; vaults simply stay locked until the user
//! unlocks them interactively (e.g. via `rosec provider auth`).
//!
//! Add to a screen-locker's PAM config (`/etc/pam.d/hyprlock`,
//! `/etc/pam.d/swaylock`, etc), **not** to `/etc/pam.d/login`:
//!
//! ```text
//! auth  optional  pam_exec.so  expose_authtok quiet /usr/lib/rosec/rosec-pam-unlock
//! ```
//!
//! # Security invariants
//!
//! - Password is held in `Zeroizing<Vec<u8>>` and scrubbed on drop.
//! - Password reaches `rosecd` via a pipe fd, never as a D-Bus payload.
//! - All errors return `PAM_IGNORE` — this module must never block login.
//! - No sensitive data is ever written to stdout/stderr/syslog.

use std::io::Read as _;
use std::os::unix::io::FromRawFd as _;

use anyhow::{Context as _, Result, anyhow, bail};
use zeroize::Zeroizing;

/// Exit codes for pam_exec. PAM_SUCCESS = 0, PAM_IGNORE = 25.
/// We use PAM_SUCCESS on success and PAM_IGNORE on any failure so that
/// the `optional` module never blocks login.
const PAM_SUCCESS: i32 = 0;
const PAM_IGNORE: i32 = 25;

/// D-Bus wire type for `org.rosec.Daemon.ProviderList` entries.
///
/// Fields: `(id, name, kind, locked, cached, offline_cache, last_cache_write_epoch, last_sync_epoch, capabilities)`.
type ProviderEntry = (
    String,
    String,
    String,
    bool,
    bool,
    bool,
    u64,
    u64,
    Vec<String>,
);

/// Log a debug message to syslog.  Only active in debug builds — release
/// builds compile this to a no-op so no sensitive data reaches syslog.
fn debug_log(_msg: &str) {
    #[cfg(debug_assertions)]
    {
        // SAFETY: We pass a valid format string and C string.
        unsafe {
            libc::openlog(
                c"rosec-pam-unlock".as_ptr(),
                libc::LOG_PID | libc::LOG_NDELAY,
                libc::LOG_AUTH,
            );
            if let Ok(cmsg) = std::ffi::CString::new(_msg) {
                libc::syslog(libc::LOG_DEBUG, c"%s".as_ptr(), cmsg.as_ptr());
            }
        }
    }
}

/// Operating mode — determined by argv.
enum Mode {
    /// Default: unlock locked providers with a single password.
    Unlock,
    /// --chauthtok: change provider passwords (old\0new\0 on stdin).
    Chauthtok,
}

fn main() -> ! {
    // Apply process hardening before stdin is read or D-Bus is touched.
    rosec_core::process::harden();

    if std::env::args().any(|a| a == "--version" || a == "-V") {
        eprintln!(
            "rosec-pam-unlock {} ({})",
            env!("ROSEC_VERSION"),
            env!("ROSEC_GIT_SHA")
        );
        std::process::exit(0);
    }

    let mode = if std::env::args().any(|a| a == "--chauthtok") {
        Mode::Chauthtok
    } else {
        Mode::Unlock
    };

    debug_log("helper started");
    let (label, result) = match mode {
        Mode::Unlock => ("helper", run()),
        Mode::Chauthtok => ("chauthtok helper", run_chauthtok()),
    };
    let code = match result {
        Ok(()) => {
            debug_log(&format!("{label} exiting PAM_SUCCESS"));
            PAM_SUCCESS
        }
        Err(e) => {
            // Log the full error chain at the FFI boundary so an operator
            // debugging a 3 AM incident has the actual root cause and not
            // a stripped Result<_, ()>. PAM_IGNORE keeps the optional
            // module non-blocking — login is never gated on this helper.
            debug_log(&format!("{label} exiting PAM_IGNORE: {e:#}"));
            PAM_IGNORE
        }
    };
    std::process::exit(code);
}

fn run() -> Result<()> {
    // Surface DBUS_SESSION_BUS_ADDRESS / XDG_RUNTIME_DIR for incident debugging
    // (debug builds only — `debug_log` is a no-op in release).
    let dbus_addr = std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap_or_default();
    let xdg_runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
    debug_log(&format!(
        "env: DBUS_SESSION_BUS_ADDRESS={dbus_addr:?} XDG_RUNTIME_DIR={xdg_runtime:?}"
    ));

    // If DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR are both unset,
    // try to determine them from the target user.  GDM's session worker
    // runs as root and may not have these in its environment, but we
    // need them to reach the user's session bus.
    ensure_session_bus_env();

    let password = read_password_from_stdin().context("read password from stdin")?;
    if password.is_empty() {
        bail!("password is empty");
    }

    debug_log(&format!("read {} bytes from stdin", password.len()));

    // password is Zeroizing<Vec<u8>> — zeroized automatically on drop.
    unlock_vaults(&password)
}

/// Ensure `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` are set.
///
/// During a GDM login/unlock, the PAM session worker runs as root and
/// may not have these variables.  We derive them from the target user's
/// UID (via `PAM_USER` → getpwnam, or from the real UID of the process).
///
/// The well-known user bus path on systemd systems is:
///   `unix:path=/run/user/<UID>/bus`
fn ensure_session_bus_env() {
    let has_dbus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some();
    let has_xdg = std::env::var_os("XDG_RUNTIME_DIR").is_some();

    if has_dbus && has_xdg {
        return;
    }

    let uid = match get_target_uid() {
        Some(u) => u,
        None => return,
    };
    debug_log(&format!("target uid={uid}"));

    let runtime_dir = format!("/run/user/{uid}");

    if !has_xdg {
        debug_log(&format!("setting XDG_RUNTIME_DIR={runtime_dir}"));
        // SAFETY: This binary is single-threaded at this point (called
        // before the tokio runtime is built).
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", &runtime_dir) };
    }

    if !has_dbus {
        let bus_path = format!("unix:path={runtime_dir}/bus");
        let socket_path = format!("{runtime_dir}/bus");
        if std::path::Path::new(&socket_path).exists() {
            debug_log(&format!("setting DBUS_SESSION_BUS_ADDRESS={bus_path}"));
            // SAFETY: This binary is single-threaded at this point.
            unsafe { std::env::set_var("DBUS_SESSION_BUS_ADDRESS", &bus_path) };
        } else {
            debug_log(&format!("bus socket {socket_path} does not exist"));
        }
    }
}

/// Get the UID of the user we're trying to unlock for.
///
/// Strategy:
/// 1. `PAM_USER` env var → getpwnam → uid (most reliable in PAM context).
/// 2. Real UID of the process (works when GDM runs the session worker
///    with the user's real UID).
/// 3. Refuse if running as root with no `PAM_USER` — guessing here
///    would attempt to unlock root's vaults using the user's password,
///    or worse, redirect to a different user's session bus.
fn get_target_uid() -> Option<u32> {
    if let Ok(user) = std::env::var("PAM_USER")
        && let Some(uid) = username_to_uid(&user)
    {
        return Some(uid);
    }

    // SAFETY: getuid() is always safe — no pointers, no side effects.
    let ruid = unsafe { libc::getuid() };
    if ruid != 0 {
        return Some(ruid);
    }

    // euid=0 with no PAM_USER — we have no safe way to identify the target.
    eprintln!(
        "rosec-pam-unlock: refusing to operate (euid=0, PAM_USER unset). \
         Configure pam_exec to forward PAM_USER (default for pam_unix)."
    );
    None
}

/// Look up a username and return its UID, or `None` if not found.
fn username_to_uid(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: getpwnam returns a pointer to a static struct or null.
    // We only read the uid field and do not store the pointer.
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    if pw.is_null() {
        None
    } else {
        // SAFETY: pw is non-null, pw_uid is a plain integer field.
        Some(unsafe { (*pw).pw_uid })
    }
}

/// Read the password from stdin as provided by `pam_exec` with `expose_authtok`.
///
/// pam_exec sends the password null-terminated on stdin. We read until EOF
/// or the first null byte, whichever comes first, capped at
/// [`MAX_PASSWORD_PAYLOAD_BYTES`] so a misbehaving caller cannot drive us
/// into unbounded allocation by holding stdin open.
fn read_password_from_stdin() -> Result<Zeroizing<Vec<u8>>> {
    use rosec_core::limits::MAX_PASSWORD_PAYLOAD_BYTES;
    let mut buf = Zeroizing::new(Vec::with_capacity(256));

    let stdin = std::io::stdin();
    let mut limited = stdin.lock().take(MAX_PASSWORD_PAYLOAD_BYTES + 1);
    limited
        .read_to_end(&mut buf)
        .context("read_to_end on stdin")?;
    if buf.len() as u64 > MAX_PASSWORD_PAYLOAD_BYTES {
        bail!("password payload exceeds {MAX_PASSWORD_PAYLOAD_BYTES} bytes");
    }

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
fn make_password_pipe(data: &[u8]) -> Result<zvariant::OwnedFd> {
    let mut fds = [0_i32; 2];

    // SAFETY: pipe() writes exactly two fds into the array.
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).context("pipe(2) for password fd");
    }

    let read_fd = fds[0];
    let write_fd = fds[1];

    {
        // SAFETY: write_fd is a valid fd from pipe().
        let mut write_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
        use std::io::Write as _;
        let write_result = write_file.write_all(data);
        // write_file is dropped here → write end closed, signalling EOF to reader.
        if let Err(e) = write_result {
            // Close the read end too on failure.
            unsafe { libc::close(read_fd) };
            return Err(anyhow::Error::from(e)).context("write password to pipe");
        }
    }

    // Wrap the read end in OwnedFd for D-Bus fd-passing.
    // SAFETY: read_fd is a valid fd from pipe(); OwnedFd takes ownership.
    let owned: std::os::fd::OwnedFd = unsafe { std::os::fd::OwnedFd::from_raw_fd(read_fd) };
    Ok(zvariant::OwnedFd::from(owned))
}

/// Connect to the D-Bus session bus and attempt to unlock all locked vaults.
fn unlock_vaults(password: &[u8]) -> Result<()> {
    // Build a minimal tokio runtime for the async D-Bus calls.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    rt.block_on(unlock_vaults_async(password))
}

/// Connect to rosecd, trying the session bus first, then the private bus socket.
async fn pam_connect() -> Result<zbus::Connection> {
    debug_log("attempting connection to rosecd");

    if let Ok(conn) = zbus::Connection::session().await {
        debug_log("connected via session bus");
        return Ok(conn);
    }

    // Fall back to private bus socket at $XDG_RUNTIME_DIR/rosec/bus.
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let socket = format!("{runtime_dir}/rosec/bus");
        if std::path::Path::new(&socket).exists() {
            let addr = format!("unix:path={socket}");
            debug_log(&format!("trying private bus at {addr}"));
            let builder = zbus::connection::Builder::address(&*addr)
                .with_context(|| format!("parse private bus address {addr}"))?;
            return builder
                .build()
                .await
                .with_context(|| format!("connect to private bus at {addr}"));
        }
    }

    bail!("no connection to rosecd available (session bus failed, no private bus socket)");
}

async fn unlock_vaults_async(password: &[u8]) -> Result<()> {
    let conn = pam_connect().await?;

    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await
    .context("create org.rosec.Daemon proxy")?;

    debug_log("calling ProviderList");
    let providers: Vec<ProviderEntry> = proxy
        .call("ProviderList", &())
        .await
        .context("ProviderList call")?;

    debug_log(&format!("found {} providers", providers.len()));

    let locked: Vec<_> = providers
        .iter()
        .filter(|(_, _, _, is_locked, ..)| *is_locked)
        .collect();

    if locked.is_empty() {
        debug_log("no locked providers found");
        return Ok(());
    }

    debug_log(&format!("unlocking {} providers in parallel", locked.len()));

    // Spawn all unlock attempts concurrently.  Each gets its own pipe
    // and D-Bus call — the daemon handles them in parallel.
    let mut handles = Vec::with_capacity(locked.len());
    for (id, name, _kind, ..) in &locked {
        let pipe_fd = make_password_pipe(password).context("create password pipe")?;

        let proxy = proxy.clone();
        let id = id.clone();
        let name = name.clone();
        handles.push(tokio::spawn(async move {
            debug_log(&format!("attempting to unlock provider {name} ({id})"));
            let result: Result<bool, zbus::Error> = proxy
                .call("AuthProviderFromPipe", &(id.as_str(), pipe_fd))
                .await;
            match &result {
                Ok(true) => {
                    debug_log(&format!("provider {name} ({id}) unlocked successfully"));
                    true
                }
                Ok(false) => {
                    debug_log(&format!("provider {name} ({id}) auth returned false"));
                    false
                }
                Err(e) => {
                    debug_log(&format!("provider {name} ({id}) auth failed: {e}"));
                    false
                }
            }
        }));
    }

    let mut any_unlocked = false;
    for handle in handles {
        if let Ok(true) = handle.await {
            any_unlocked = true;
        }
    }

    if any_unlocked {
        debug_log("at least one provider unlocked");
        Ok(())
    } else {
        bail!("no providers were unlocked");
    }
}
// chauthtok mode — password change
type ZeroVec = Zeroizing<Vec<u8>>;

/// Read two NUL-terminated password strings from stdin.
///
/// Protocol: `<old_password>\0<new_password>\0<EOF>`.
fn read_two_passwords_from_stdin() -> Result<(ZeroVec, ZeroVec)> {
    use rosec_core::limits::MAX_PASSWORD_PAYLOAD_BYTES;
    use std::io::Read as _;
    // Zeroizing wraps the combined buffer so the concatenated passwords are
    // scrubbed on drop — the sliced-out copies below get their own Zeroizing.
    let mut buf = Zeroizing::new(Vec::with_capacity(512));
    let stdin = std::io::stdin();
    let mut limited = stdin.lock().take(MAX_PASSWORD_PAYLOAD_BYTES + 1);
    limited
        .read_to_end(&mut buf)
        .context("read chauthtok payload from stdin")?;
    if buf.len() as u64 > MAX_PASSWORD_PAYLOAD_BYTES {
        bail!("chauthtok payload exceeds {MAX_PASSWORD_PAYLOAD_BYTES} bytes");
    }

    // Find the first NUL separator.
    let sep = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow!("chauthtok payload missing NUL separator between old and new"))?;
    let mut old_pw = Zeroizing::new(buf[..sep].to_vec());

    // Everything after the first NUL is the new password (strip trailing NUL).
    let rest = &buf[sep + 1..];
    let mut new_pw = Zeroizing::new(if rest.last() == Some(&0) {
        rest[..rest.len() - 1].to_vec()
    } else {
        rest.to_vec()
    });

    // Strip trailing newlines.
    if old_pw.last() == Some(&b'\n') {
        old_pw.pop();
    }
    if new_pw.last() == Some(&b'\n') {
        new_pw.pop();
    }

    if old_pw.is_empty() || new_pw.is_empty() {
        bail!("chauthtok: empty old or new password");
    }

    Ok((old_pw, new_pw))
}

fn run_chauthtok() -> Result<()> {
    ensure_session_bus_env();

    let (old_pw, new_pw) = read_two_passwords_from_stdin().context("read old/new passwords")?;

    debug_log(&format!(
        "read old={} bytes, new={} bytes from stdin",
        old_pw.len(),
        new_pw.len()
    ));

    // old_pw and new_pw are Zeroizing<Vec<u8>> — zeroized automatically on drop.
    change_vault_passwords(&old_pw, &new_pw)
}

fn change_vault_passwords(old_password: &[u8], new_password: &[u8]) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    rt.block_on(change_vault_passwords_async(old_password, new_password))
}

async fn change_vault_passwords_async(old_password: &[u8], new_password: &[u8]) -> Result<()> {
    let conn = pam_connect().await?;

    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await
    .context("create org.rosec.Daemon proxy")?;

    debug_log("calling ProviderList");
    let providers: Vec<ProviderEntry> = proxy
        .call("ProviderList", &())
        .await
        .context("ProviderList call")?;

    // Only attempt password change on unlocked local vault providers.
    // Locked providers can't have their password changed (they need to
    // be unlocked first to re-wrap the vault key).
    let targets: Vec<_> = providers
        .iter()
        .filter(|(_, _, kind, locked, ..)| kind == "local" && !locked)
        .collect();

    if targets.is_empty() {
        debug_log("no unlocked local vault providers found");
        return Ok(());
    }

    debug_log(&format!(
        "attempting password change on {} provider(s)",
        targets.len()
    ));

    let mut any_changed = false;
    for (id, name, ..) in &targets {
        let old_pipe = make_password_pipe(old_password).context("create old password pipe")?;
        let new_pipe = make_password_pipe(new_password).context("create new password pipe")?;

        debug_log(&format!("changing password for provider {name} ({id})"));
        let result: Result<(), zbus::Error> = proxy
            .call("ChangeProviderPassword", &(id.as_str(), old_pipe, new_pipe))
            .await;

        match &result {
            Ok(()) => {
                debug_log(&format!("provider {name} ({id}) password changed"));
                any_changed = true;
            }
            Err(e) => {
                // Not an error — the old password may not match this vault's
                // wrapping entry.  Log and continue.
                debug_log(&format!(
                    "provider {name} ({id}) password change failed: {e}"
                ));
            }
        }
    }

    if any_changed {
        debug_log("at least one provider password changed");
        Ok(())
    } else {
        debug_log("no provider passwords were changed");
        Ok(())
    }
}
