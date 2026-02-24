//! Generic OAuth `client_credentials` credential store.
//!
//! Any backend that authenticates via OAuth2 `client_credentials` (e.g.
//! Bitwarden personal API key, future cloud-provider backends) can use this
//! module to securely persist and retrieve a `client_id` / `client_secret`
//! pair on disk.
//!
//! # Storage format
//!
//! Credentials are stored as TOML at:
//! ```text
//! $XDG_DATA_HOME/rosec/oauth/<backend-id>.toml   (default: ~/.local/share/…)
//! ```
//!
//! The file is created with mode `0600` (owner read/write only) on Unix.
//! The `client_secret` is **never** written in plaintext.  Instead, the
//! caller (e.g. `rosec-bitwarden::oauth_cred`) derives an encryption key
//! from the master password, encrypts the secret with AES-256-CBC + HMAC-SHA256,
//! and passes the pre-encrypted bytes here for persistence.  `load_encrypted`
//! returns those bytes unchanged — decryption is again the caller's responsibility.
//!
//! # Security note
//!
//! `client_secret` is wrapped in `Zeroizing<String>` in `OAuthCredential` so it
//! is scrubbed from memory when the struct is dropped.  It is **never** logged or
//! printed.  The on-disk TOML contains only the Base64-encoded ciphertext, IV, and
//! MAC — no plaintext secret ever touches the filesystem.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::warn;
use zeroize::Zeroizing;

/// An in-memory OAuth `client_credentials` key pair.
///
/// `Debug` is manually implemented to redact `client_secret`.
pub struct OAuthCredential {
    /// The OAuth `client_id` (not secret — safe to log/display).
    pub client_id: String,
    /// The OAuth `client_secret` — zeroized on drop, never logged.
    pub client_secret: Zeroizing<String>,
}

impl std::fmt::Debug for OAuthCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthCredential")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[redacted]")
            .finish()
    }
}

/// Encrypted fields stored on disk.
///
/// All three Base64 strings are opaque to this module — they are produced and
/// consumed by the caller's crypto layer.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedFields {
    /// Base64-encoded AES-CBC IV (16 bytes).
    pub iv_b64: String,
    /// Base64-encoded AES-CBC ciphertext.
    pub ciphertext_b64: String,
    /// Base64-encoded HMAC-SHA256 over IV + ciphertext.
    pub mac_b64: String,
}

/// TOML-serialisable wrapper (used only for disk I/O — not exposed publicly).
#[derive(Serialize, Deserialize)]
struct StoredCredential {
    /// OAuth `client_id` — not secret, stored as plain text.
    client_id: String,
    /// Encrypted `client_secret` fields.
    #[serde(flatten)]
    encrypted: EncryptedFields,
}

/// Return the path for a backend's OAuth credential file.
///
/// `$XDG_DATA_HOME/rosec/oauth/<backend-id>.toml`
/// (default: `~/.local/share/rosec/oauth/<backend-id>.toml`)
pub fn credential_path(backend_id: &str) -> Option<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
    // Sanitise the backend ID so it is safe as a filename component.
    let safe_id: String = backend_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Some(
        base.join("rosec")
            .join("oauth")
            .join(format!("{safe_id}.toml")),
    )
}

/// Load the encrypted fields for `backend_id` from disk.
///
/// Returns `None` if the file does not exist or cannot be parsed.
/// Logs a warning (but does not error) on parse failures so a corrupt file
/// does not hard-block authentication.
///
/// The returned `(client_id, EncryptedFields)` must be decrypted by the caller.
pub fn load_encrypted(backend_id: &str) -> Option<(String, EncryptedFields)> {
    let path = credential_path(backend_id)?;
    let contents = std::fs::read_to_string(&path).ok()?;
    match toml::from_str::<StoredCredential>(&contents) {
        Ok(stored) => Some((stored.client_id, stored.encrypted)),
        Err(e) => {
            warn!(path = %path.display(), error = %e, "failed to parse OAuth credential file");
            None
        }
    }
}

/// Persist pre-encrypted credential fields for `backend_id` to disk with mode `0600`.
///
/// Creates intermediate directories if needed.
/// Returns an error string suitable for display to the user.
///
/// The caller is responsible for deriving the encryption key and encrypting the
/// `client_secret` before calling this function.  This module never sees the
/// plaintext secret.
pub fn save_encrypted(
    backend_id: &str,
    client_id: &str,
    encrypted: &EncryptedFields,
) -> Result<(), String> {
    let path = credential_path(backend_id)
        .ok_or_else(|| "cannot determine data directory (HOME not set)".to_string())?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create directory {}: {e}", parent.display()))?;
    }

    let stored = StoredCredential {
        client_id: client_id.to_string(),
        encrypted: EncryptedFields {
            iv_b64: encrypted.iv_b64.clone(),
            ciphertext_b64: encrypted.ciphertext_b64.clone(),
            mac_b64: encrypted.mac_b64.clone(),
        },
    };
    let toml_str =
        toml::to_string(&stored).map_err(|e| format!("failed to serialise credential: {e}"))?;

    // Write with restrictive permissions atomically.
    write_secret_file(&path, toml_str.as_bytes())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;

    Ok(())
}

/// Delete the stored credential for `backend_id`.
///
/// Returns `true` if a file was removed, `false` if nothing existed.
/// Returns an error string if the file exists but could not be removed.
pub fn clear(backend_id: &str) -> Result<bool, String> {
    let path = credential_path(backend_id)
        .ok_or_else(|| "cannot determine data directory (HOME not set)".to_string())?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("failed to remove {}: {e}", path.display())),
    }
}

/// Write `data` to `path` with Unix mode `0600`, replacing any existing file.
///
/// Uses a write-then-rename strategy so the file is never partially written.
fn write_secret_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    // Write to a sibling temp file first.
    let tmp_path = path.with_extension("toml.tmp");

    {
        // Open with mode 0600 at creation time to avoid a TOCTOU window
        // where the file would be world-readable between open() and chmod().
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;

        f.write_all(data)?;
        f.flush()?;
    }

    // Atomic rename.
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn with_tmp_home(f: impl FnOnce()) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = std::env::temp_dir().join(format!("rosec-oauth-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        // Hold the crate-wide env mutex so credential tests running in parallel
        // cannot clobber XDG_DATA_HOME at the same time.
        let _guard = crate::TEST_ENV_MUTEX.lock().unwrap();
        unsafe { env::set_var("XDG_DATA_HOME", &tmp) };
        f();
        unsafe { env::remove_var("XDG_DATA_HOME") };
        drop(_guard);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn credential_path_ends_with_backend_id() {
        let path = credential_path("my-backend").unwrap();
        assert!(path.ends_with("rosec/oauth/my-backend.toml"));
    }

    #[test]
    fn credential_path_sanitises_special_chars() {
        let path = credential_path("back/end!@#").unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("back_end___"));
    }

    fn make_encrypted() -> EncryptedFields {
        EncryptedFields {
            iv_b64: "aGVsbG8=".to_string(),
            ciphertext_b64: "d29ybGQ=".to_string(),
            mac_b64: "dGVzdA==".to_string(),
        }
    }

    #[test]
    fn roundtrip_save_load_clear() {
        with_tmp_home(|| {
            let enc = make_encrypted();
            save_encrypted("test-backend", "user.abc123", &enc).unwrap();

            let (client_id, loaded) = load_encrypted("test-backend").expect("should load");
            assert_eq!(client_id, "user.abc123");
            assert_eq!(loaded.iv_b64, enc.iv_b64);
            assert_eq!(loaded.ciphertext_b64, enc.ciphertext_b64);
            assert_eq!(loaded.mac_b64, enc.mac_b64);

            assert!(clear("test-backend").unwrap());
            assert!(!clear("test-backend").unwrap()); // second clear: already gone
            assert!(load_encrypted("test-backend").is_none());
        });
    }

    #[test]
    fn load_missing_returns_none() {
        with_tmp_home(|| {
            assert!(load_encrypted("nonexistent-backend").is_none());
        });
    }

    #[test]
    fn debug_redacts_secret() {
        let cred = OAuthCredential {
            client_id: "user.xyz".to_string(),
            client_secret: Zeroizing::new("topsecret".to_string()),
        };
        let debug = format!("{cred:?}");
        assert!(debug.contains("user.xyz"));
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("topsecret"));
    }

    #[test]
    #[cfg(unix)]
    fn saved_file_has_mode_0600() {
        with_tmp_home(|| {
            use std::os::unix::fs::PermissionsExt;
            let enc = make_encrypted();
            save_encrypted("perm-test", "user.perm", &enc).unwrap();
            let path = credential_path("perm-test").unwrap();
            let meta = std::fs::metadata(&path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "file must be mode 0600, got {:o}", mode);
        });
    }
}
