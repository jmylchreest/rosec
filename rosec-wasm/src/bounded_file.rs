use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Read a regular file within an allocation limit, including if it grows after opening.
pub(crate) fn read(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    fn too_large(limit: u64) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds {limit} bytes"),
        )
    }

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected a regular file",
        ));
    }
    if metadata.len() > limit {
        return Err(too_large(limit));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(too_large(limit));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_limit_and_rejects_oversize_files_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        std::fs::write(&path, b"test").unwrap();
        assert_eq!(read(&path, 4).unwrap(), b"test");
        assert_eq!(
            read(&path, 3).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read(dir.path(), 4).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
