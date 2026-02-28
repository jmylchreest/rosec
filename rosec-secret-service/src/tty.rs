/// TTY-based credential collection utilities used by the daemon.
///
/// These functions run inside `rosecd` and operate on a file descriptor
/// received from the caller via D-Bus fd-passing (SCM_RIGHTS).  Because the
/// caller passes the TTY fd — not a password string — `dbus-monitor` sees only
/// `unixfd:N`, never any credential.
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::os::unix::io::RawFd;

use anyhow::{Result, anyhow};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Descriptor for a single prompt field, mirroring the wire format returned by
/// `GetAuthFields` / `GetRegistrationInfo`.
#[derive(Debug, Clone)]
pub struct TtyField {
    pub id: String,
    pub label: String,
    /// One of `"text"`, `"password"`, or `"secret"`.
    pub kind: String,
    pub placeholder: String,
}

// ---------------------------------------------------------------------------
// TermiosGuard — RAII terminal-state restoration
// ---------------------------------------------------------------------------

/// Restores the original `termios` settings on the given fd when dropped.
///
/// This ensures that even if the calling thread panics, is cancelled, or exits
/// abnormally, the terminal echo flag (and all other settings) are restored.
struct TermiosGuard {
    fd: RawFd,
    orig: libc::termios,
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        // Best-effort restore; if the fd is already closed (EBADF) or the
        // terminal is gone, there is nothing we can do — and that is fine
        // because the terminal state no longer matters for a dead fd.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig);
        }
    }
}

// ---------------------------------------------------------------------------
// Low-level read
// ---------------------------------------------------------------------------

/// Read one line from `fd` with terminal echo disabled.
///
/// Flushes any stale input (via `TCSAFLUSH`), saves the current `termios`,
/// clears `ECHO`/`ECHONL`, reads a line, then restores the original settings.
/// The returned string has the trailing newline stripped.
///
/// A `TermiosGuard` ensures the original terminal settings are restored even
/// if the read is interrupted, the thread panics, or the function exits early
/// via `?`.
///
/// The read buffer is `Zeroizing<Vec<u8>>` so the raw bytes are scrubbed on
/// drop — no plain copy of the secret ever lingers on the heap.
pub fn read_hidden(fd: RawFd) -> io::Result<Zeroizing<String>> {
    use std::os::unix::io::FromRawFd as _;

    // Save current termios and install the RAII guard immediately.
    // SAFETY: fd is valid (caller verified) and term is properly initialised.
    let guard = unsafe {
        let mut term = std::mem::MaybeUninit::<libc::termios>::uninit();
        if libc::tcgetattr(fd, term.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        TermiosGuard {
            fd,
            orig: term.assume_init(),
        }
    };

    let mut noecho = guard.orig;
    // Disable echo and the newline-echo-when-echo-off flag.
    noecho.c_lflag &= !(libc::ECHO as libc::tcflag_t);
    noecho.c_lflag &= !(libc::ECHONL as libc::tcflag_t);

    // TCSAFLUSH: apply new settings AND discard any unread input in the
    // kernel tty buffer (e.g. stale keypresses from between prompts).
    unsafe {
        if libc::tcsetattr(fd, libc::TCSAFLUSH, &noecho) != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // Read one line into a Zeroizing buffer so the raw bytes are scrubbed on
    // drop regardless of what happens next.
    let mut buf = Zeroizing::new(Vec::<u8>::new());
    let result = {
        // SAFETY: we borrow the fd for reading; ManuallyDrop prevents double-close
        // since the original TTY File in the caller still owns the fd.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let file = std::mem::ManuallyDrop::new(file);
        let mut reader = io::BufReader::new(&*file);
        reader.read_until(b'\n', &mut buf)
    };

    // The guard restores termios on drop (runs when this function returns),
    // but we also restore explicitly here so the newline write below sees
    // the original settings.
    drop(guard);

    // Print a newline since ECHO is off (the user's Enter was not echoed).
    let _ = unsafe { libc::write(fd, b"\n".as_ptr().cast(), 1) };

    result?;

    // Strip trailing CR/LF and convert to a Zeroizing<String>.  The Vec is
    // zeroized on drop; the String is wrapped in Zeroizing immediately.
    while buf.last() == Some(&b'\n') || buf.last() == Some(&b'\r') {
        buf.pop();
    }
    let s = std::str::from_utf8(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .to_string();
    Ok(Zeroizing::new(s))
}

// ---------------------------------------------------------------------------
// Field prompting
// ---------------------------------------------------------------------------

/// Collect a single field value from the terminal using the given `fd`.
///
/// For hidden fields (`password`/`secret`) echo is suppressed via
/// [`read_hidden`].  For visible fields (`text`) a simple line read is
/// performed.  All blocking I/O runs on a `spawn_blocking` thread so the
/// tokio executor is not stalled.
///
/// Returns `Zeroizing<String>` so the value is scrubbed on drop.
pub async fn prompt_field_on_fd(
    fd: RawFd,
    label: &str,
    placeholder: &str,
    kind: &str,
) -> Result<Zeroizing<String>> {
    let prompt_str = if placeholder.is_empty() {
        format!("{label}: ")
    } else {
        format!("{label} [{placeholder}]: ")
    };

    let kind = kind.to_string();
    let value = tokio::task::spawn_blocking(move || -> Result<Zeroizing<String>> {
        use std::os::unix::io::FromRawFd as _;

        // Borrow the fd as a File for writing the prompt; ManuallyDrop so we
        // don't close it (the caller still owns it).
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let file = std::mem::ManuallyDrop::new(file);
        let mut writer = &*file;

        match kind.as_str() {
            "password" | "secret" => {
                writer.write_all(prompt_str.as_bytes())?;
                writer.flush()?;
                Ok(read_hidden(fd)?)
            }
            _ => {
                writer.write_all(prompt_str.as_bytes())?;
                writer.flush()?;
                let mut line = String::new();
                io::BufReader::new(&*file).read_line(&mut line)?;
                Ok(Zeroizing::new(
                    line.trim_end_matches('\n')
                        .trim_end_matches('\r')
                        .to_string(),
                ))
            }
        }
    })
    .await
    .map_err(|e| anyhow!("prompt task panicked: {e}"))??;

    Ok(value)
}

// ---------------------------------------------------------------------------
// Bulk field collection
// ---------------------------------------------------------------------------

/// Collect all `fields` from the terminal using `fd`, printing a blank line
/// before the first prompt.
///
/// Returns a map of `field.id → Zeroizing<String>`.
pub async fn collect_tty_on_fd(
    fd: RawFd,
    fields: &[TtyField],
) -> Result<HashMap<String, Zeroizing<String>>> {
    // Print a blank line before the first prompt for visual spacing.
    let _ = tokio::task::spawn_blocking(move || {
        use std::os::unix::io::FromRawFd as _;
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let file = std::mem::ManuallyDrop::new(file);
        let mut w = &*file;
        let _ = w.write_all(b"\n");
        let _ = w.flush();
    })
    .await;

    let mut map = HashMap::new();
    for field in fields {
        let v = prompt_field_on_fd(fd, &field.label, &field.placeholder, &field.kind).await?;
        map.insert(field.id.clone(), v);
    }
    Ok(map)
}
