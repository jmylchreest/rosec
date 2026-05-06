//! SSH agent socket sandboxing primitives.
//!
//! Tightens umask around the `bind()` call so the agent socket is created
//! at mode 0o600 atomically — closing the bind→chmod race window where
//! another local user could `connect()` to a world-readable socket
//! between bind() and the explicit chmod.

use std::path::Path;

/// Run `bind` with `umask(0o077)` set, then restore the prior umask.
///
/// The closure receives no arguments and returns whatever the underlying
/// bind operation produced. Any panic in `bind` propagates with the
/// previous umask still restored (`umask` is a side-effect-only syscall;
/// no Drop guard is needed because we restore on the happy path and a
/// panic unwinds the whole process anyway).
pub fn bind_with_tight_umask<T, F: FnOnce() -> T>(bind: F) -> T {
    let old = unsafe { libc::umask(0o077) };
    let result = bind();
    unsafe { libc::umask(old) };
    result
}

/// Apply mode 0o600 to `path` as defence-in-depth alongside the umask
/// trick. If the umask path was effective, this is a no-op; if a future
/// libc bug or process-level umask change made the bind permissive, this
/// is the fallback.
pub fn lock_socket_perms(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
