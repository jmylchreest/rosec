//! Per-installation machine key.
//!
//! A random 32-byte seed generated once on first use and stored at:
//! ```text
//! $XDG_DATA_HOME/rosec/machine-key   (default: ~/.local/share/rosec/machine-key)
//! ```
//! The file is created with mode `0600`.  It is used to derive backend-specific
//! encryption keys so that credentials stored by token-based backends (e.g.
//! Bitwarden Secrets Manager) can be decrypted without any user interaction.
//!
//! # Security model
//!
//! This key protects stored credentials with the same level of security as the
//! user's home directory.  It is appropriate for backends that already store a
//! machine account credential (not a user master password) — if an attacker can
//! read `~/.local/share/rosec/`, they already have access to the encrypted token
//! file, and both are protected only by filesystem permissions.

use std::path::PathBuf;

use rand::RngCore;
use zeroize::Zeroizing;

/// Load the machine key seed, generating and persisting it if absent.
///
/// Returns a 32-byte zeroizing buffer.
pub fn load_or_create() -> Result<Zeroizing<Vec<u8>>, String> {
    let path = machine_key_path()?;

    if path.exists() {
        let bytes = std::fs::read(&path)
            .map_err(|e| format!("failed to read machine key at {}: {e}", path.display()))?;
        if bytes.len() != 32 {
            return Err(format!(
                "machine key at {} has unexpected length {} (expected 32)",
                path.display(),
                bytes.len()
            ));
        }
        return Ok(Zeroizing::new(bytes));
    }

    // Generate a fresh seed.
    let mut seed = Zeroizing::new(vec![0u8; 32]);
    rand::rng().fill_bytes(&mut seed);

    // Write with mode 0600.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    write_secret(&path, &seed)?;

    Ok(seed)
}

fn machine_key_path() -> Result<PathBuf, String> {
    let base = if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(xdg)
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".local/share")
    } else {
        return Err("cannot locate machine key: neither XDG_DATA_HOME nor HOME is set".to_string());
    };
    Ok(base.join("rosec").join("machine-key"))
}

fn write_secret(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write as _;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut f| f.write_all(data))
            .map_err(|e| format!("failed to write machine key to {}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
            .map_err(|e| format!("failed to write machine key to {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_tmp_home(f: impl FnOnce()) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = std::env::temp_dir().join(format!("rosec-machinekey-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let _guard = crate::TEST_ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        f();
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        drop(_guard);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn generates_32_bytes() {
        with_tmp_home(|| {
            let key = load_or_create().unwrap();
            assert_eq!(key.len(), 32);
        });
    }

    #[test]
    fn stable_across_calls() {
        with_tmp_home(|| {
            let k1 = load_or_create().unwrap();
            let k2 = load_or_create().unwrap();
            assert_eq!(k1.as_slice(), k2.as_slice());
        });
    }

    #[test]
    fn different_installs_get_different_keys() {
        with_tmp_home(|| {
            let k1 = load_or_create().unwrap();
            // Remove the file to simulate a new install.
            std::fs::remove_file(machine_key_path().unwrap()).unwrap();
            let k2 = load_or_create().unwrap();
            assert_ne!(k1.as_slice(), k2.as_slice());
        });
    }
}
