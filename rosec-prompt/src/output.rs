//! Stdout helpers for emitting JSON results without leaving plaintext
//! credential bytes in non-zeroizing buffers.
//!
//! `std::process::exit()` bypasses Rust's stdio buffers, so a final flush is
//! mandatory — without it the JSON can be lost. The other risk is that
//! `serde_json::to_string` produces a plain `String` whose backing
//! allocation contains plaintext password / TOTP-seed bytes and is dropped
//! without scrubbing. This module's helpers route serialisation through a
//! `Zeroizing<Vec<u8>>` and write it directly to fd 1 via `libc::write`,
//! bypassing both hazards.

use anyhow::Result;
use zeroize::Zeroizing;

/// Serialize `value` into a `Zeroizing<Vec<u8>>` and write the bytes
/// straight to fd 1 (stdout) via `libc::write`. The buffer drops at end
/// of scope and zeroes its memory — credential bytes never live in a
/// non-zeroizing allocation.
pub(crate) fn emit_secret_json<T: serde::Serialize>(value: &T) -> Result<()> {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(256));
    serde_json::to_writer(&mut *buf, value)?;
    buf.push(b'\n');
    let mut written = 0usize;
    while written < buf.len() {
        // SAFETY: fd 1 is always valid; ptr is from a live Vec; len is bounded.
        let n = unsafe {
            libc::write(
                1,
                buf.as_ptr().add(written) as *const _,
                buf.len() - written,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        written += n as usize;
    }
    Ok(())
}

/// Emit the empty JSON object `{}` and exit 0. Used when the protocol
/// expects an acknowledgement-only result (TOTP copy, confirm-only dialog).
pub(crate) fn emit_empty_and_exit() -> ! {
    use std::io::Write as _;
    let _ = std::io::stdout().write_all(b"{}\n");
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}
