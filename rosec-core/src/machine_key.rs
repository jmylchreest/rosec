//! Per-installation machine key.
//!
//! A random 32-byte seed generated once on first use and stored at:
//! ```text
//! $XDG_DATA_HOME/rosec/machine-key   (default: ~/.local/share/rosec/machine-key)
//! ```
//! The file is created with mode `0600`.  It is used to derive provider-specific
//! encryption keys so that credentials stored by token-based providers (e.g.
//! Bitwarden Secrets Manager) can be decrypted without any user interaction.
//!
//! # Security model
//!
//! This key protects stored credentials with the same level of security as the
//! user's home directory.  It is appropriate for providers that already store a
//! machine account credential (not a user master password) — if an attacker can
//! read `~/.local/share/rosec/`, they already have access to the encrypted token
//! file, and both are protected only by filesystem permissions.

use std::path::PathBuf;

use rand::Rng;
use zeroize::Zeroizing;

/// Load the machine key seed, generating and persisting it if absent.
///
/// Returns a 32-byte zeroizing buffer.
pub fn load_or_create() -> Result<Zeroizing<Vec<u8>>, String> {
    let path = machine_key_path()?;

    if path.exists() {
        let bytes = Zeroizing::new(std::fs::read(&path).map_err(|_| "Failed to read machine key")?);
        if bytes.len() != 32 {
            return Err(format!(
                "machine key at {} has unexpected length {} (expected 32)",
                path.display(),
                bytes.len()
            ));
        }
        return Ok(bytes);
    }

    let mut seed = Zeroizing::new(vec![0u8; 32]);
    rand::rng().fill_bytes(&mut seed);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    if !write_secret(&path, &seed)? {
        // Another provider/process published the installation key first.
        // Read that winner instead of ever replacing it with our candidate.
        return load_or_create();
    }

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

/// Atomically publish a complete key without replacing another creator's key.
fn write_secret(path: &std::path::Path, data: &[u8]) -> Result<bool, String> {
    use std::io::Write;
    let parent = path.parent().ok_or("Missing machine key directory")?;
    let mut file =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "Cannot create machine key")?;
    file.write_all(data)
        .map_err(|_| "Cannot write machine key")?;
    file.as_file()
        .sync_all()
        .map_err(|_| "Cannot persist machine key")?;
    match file.persist_noclobber(path) {
        Ok(_) => Ok(true),
        Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(_) => Err("Cannot publish machine key".into()),
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
    fn concurrent_first_use_keeps_one_installation_key() {
        with_tmp_home(|| {
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
            let tasks: Vec<_> = (0..8)
                .map(|_| {
                    let barrier = std::sync::Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        load_or_create().unwrap()
                    })
                })
                .collect();
            let keys: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
            assert!(keys.iter().all(|key| **key == *keys[0]));
            assert_eq!(*load_or_create().unwrap(), *keys[0]);
        });
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
