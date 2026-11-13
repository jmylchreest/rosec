//! Durable replacement, optimistic concurrency and encrypted recovery snapshots.
use crate::types::VaultFile;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub(crate) fn revision(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn adjacent(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
fn private_file(path: &Path, exclusive: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true);
    if exclusive {
        options.create_new(true);
    } else {
        options.create(true).truncate(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
pub(crate) fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_checked(path, bytes, || Ok(()))
}
fn write_checked(
    path: &Path,
    bytes: &[u8],
    before_replace: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    let temp = adjacent(path, &format!(".{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = private_file(&temp, true)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        before_replace()?;
        std::fs::rename(&temp, path)?;
        File::open(parent(path))?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}
fn snapshot(path: &Path, bytes: &[u8]) -> anyhow::Result<PathBuf> {
    let backup = adjacent(path, &format!(".recovery-{}", uuid::Uuid::new_v4()));
    // Unique name and create_new: never replace an earlier recovery point.
    let mut file = private_file(&backup, true)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(parent(path))?.sync_all()?;
    Ok(backup)
}
/// A lease lasts until a vault is locked/dropped. Recovery cannot race an unlocked writer.
/// Keep the lock file: removing it would let writers lock different inodes.
pub(crate) struct Lease {
    _file: File,
    path: PathBuf,
}
pub(crate) fn acquire(path: &Path) -> anyhow::Result<Lease> {
    std::fs::create_dir_all(parent(path))?;
    let file = private_file(&adjacent(path, ".lock"), false)?;
    file.try_lock().map_err(|e| {
        anyhow::anyhow!(
            "vault is already in use; lock it before recovery or opening another writer: {e}"
        )
    })?;
    Ok(Lease {
        _file: file,
        path: path.to_path_buf(),
    })
}
pub(crate) fn replace(
    lease: &Lease,
    bytes: &[u8],
    expected: Option<[u8; 32]>,
    force_snapshot: bool,
) -> anyhow::Result<()> {
    let path = &lease.path;
    let old = match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    anyhow::ensure!(
        old.as_deref().map(revision) == expected,
        "vault changed on disk; lock and unlock it again before writing"
    );
    if let Some(old) = old {
        let previous: VaultFile = serde_json::from_slice(&old)?;
        let next: VaultFile = serde_json::from_slice(bytes)?;
        if force_snapshot || previous.version != next.version {
            snapshot(path, &old)?;
        }
    }
    write_secret_file(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wire(version: u32) -> Vec<u8> {
        serde_json::to_vec(&VaultFile {
            version,
            wrapping_entries: vec![],
            encrypted_data: "fixture".into(),
            hmac: "fixture".into(),
        })
        .unwrap()
    }
    #[test]
    fn transitions_snapshot_exact_original_and_stale_writers_fail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let lease = acquire(&path).unwrap();
        let old = wire(2);
        let new = wire(3);
        replace(&lease, &old, None, false).unwrap();
        replace(&lease, &old, Some(revision(&old)), false).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        replace(&lease, &new, Some(revision(&old)), false).unwrap();
        let backup = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.to_string_lossy().contains(".recovery-"))
            .unwrap();
        assert_eq!(std::fs::read(backup).unwrap(), old);
        assert!(replace(&lease, &old, Some(revision(&old)), false).is_err());
        assert_eq!(std::fs::read(path).unwrap(), new);
    }
    #[test]
    fn failed_temp_creation_leaves_original_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let lease = acquire(&path).unwrap();
        let old = wire(2);
        replace(&lease, &old, None, false).unwrap();
        assert!(
            write_checked(&path, b"new", || Err(std::io::Error::other(
                "injected before rename"
            )))
            .is_err()
        );
        assert_eq!(std::fs::read(path).unwrap(), old);
    }
}
