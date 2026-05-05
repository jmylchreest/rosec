//! Shared input-size caps used by stdin-driven helpers.
//!
//! Centralised so the PAM helper, the prompt subprocess, and any future
//! caller use the same numbers — and so changes are reviewed in one place.

/// Maximum size of a password / passphrase payload read from stdin.
///
/// Covers the PAM `expose_authtok` unlock payload (one password) and the
/// PAM chauthtok payload (two NUL-separated passwords).  4 KiB is well
/// above any realistic password length and well above PAM_MAX_RESP_SIZE
/// (512), but small enough to bound a misbehaving caller's allocation.
pub const MAX_PASSWORD_PAYLOAD_BYTES: u64 = 4096;

/// Maximum size of a JSON prompt request consumed by `rosec-prompt` on stdin.
///
/// Covers theme + many fields + info text with comfortable headroom while
/// preventing a misbehaving caller from driving us into unbounded
/// allocation by holding stdin open.
pub const MAX_PROMPT_REQUEST_BYTES: u64 = 64 * 1024;
