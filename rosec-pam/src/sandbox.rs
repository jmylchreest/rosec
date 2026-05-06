//! Landlock ruleset for the rosec-pam-unlock binary.
//!
//! This helper runs as `pam_exec`'s child process — short-lived, single
//! purpose: read a password from stdin, send it to rosecd over D-Bus, exit.
//! Its filesystem and network needs are minimal and well-known, so the
//! ruleset can be tight.

use rosec_core::sandbox::landlock::{self, ConnectPort, PathRule};

/// Apply the rosec-pam-unlock Landlock ruleset to the calling thread.
/// Best-effort: logs and continues on older kernels that don't support
/// Landlock at all (PAM helper must never block login).
pub fn restrict() {
    let paths = vec![
        // Shared libraries the binary loads (libc, libdbus, tokio deps).
        // PathBeneath descends recursively.
        PathRule::ro("/usr/lib"),
        PathRule::ro("/lib"),
        PathRule::ro("/usr/lib64"),
        PathRule::ro("/lib64"),
        PathRule::ro("/etc/ld.so.cache"),
        PathRule::ro("/etc/ld.so.preload"),
        // /proc/self/* for libc-internal lookups + syslog wiring.
        PathRule::ro("/proc/self"),
        // syslog socket (libc::syslog uses /dev/log).
        PathRule::rw("/dev/log"),
        // The user's session bus socket. ensure_session_bus_env() may set
        // XDG_RUNTIME_DIR to /run/user/<uid> at runtime; allow the whole
        // /run/user tree (each /run/user/<uid> is owned 0700 by the user, so
        // Landlock + UNIX perms together still confine us).
        PathRule::rw("/run/user"),
        // System bus, when rosecd is on the system bus (private-bus path).
        PathRule::rw("/run/dbus"),
    ];

    // pam_exec passes the password via an anonymous pipe — no FS rule
    // needed; stdin fd is inherited and Landlock doesn't gate already-open
    // fds. No outbound TCP either; D-Bus is Unix-socket only.
    let ports: Vec<ConnectPort> = Vec::new();

    if let Err(e) = landlock::apply_paths_and_ports(&paths, &ports) {
        eprintln!("rosec-pam-unlock: landlock apply failed (continuing): {e}");
    }
}
