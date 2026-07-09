//! Shared read-only synthetic-tree machinery for the FUSE filesystems.
//!
//! Both the SSH and TOTP filesystems expose a small static directory tree of
//! generated files, backed by an in-memory snapshot swapped under an `RwLock`.
//! The per-inode layout and file content differ (stored bytes vs freshly
//! generated TOTP codes), but the FUSE plumbing — attribute lookups, directory
//! listing, and the read-only operation handlers — is identical.
//!
//! This module holds that shared half: implement [`SynthSnapshot`] for a
//! snapshot type, then have its `Filesystem` methods delegate to the free
//! functions here (`lookup`, `getattr`, `read`, `readdir`, …).

use std::ffi::OsStr;
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    Errno, FileAttr, FileHandle, FileType, FopenFlags, Generation, INodeNo, ReplyAttr, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
};
use zeroize::Zeroizing;

/// Attribute/entry cache lifetime handed back to the kernel.
const TTL: Duration = Duration::from_secs(1);

/// Build a read-only [`FileAttr`] for a synthetic inode (dirs `0o500`, files
/// `0o400`, owned by the mounting user).
pub fn make_attr(
    ino: INodeNo,
    kind: FileType,
    size: u64,
    nlink: u32,
    mtime: SystemTime,
) -> FileAttr {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    FileAttr {
        ino,
        size,
        blocks: size.div_ceil(512),
        atime: mtime,
        mtime,
        ctime: mtime,
        crtime: UNIX_EPOCH,
        kind,
        perm: if kind == FileType::Directory {
            0o500
        } else {
            0o400
        },
        nlink,
        uid,
        gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

/// A snapshot of a read-only synthetic tree — enough for the shared FUSE
/// handlers to answer lookups, listings, and reads. The concrete snapshot owns
/// the per-inode layout and the content source.
pub trait SynthSnapshot: Send + Sync {
    /// Attributes for an inode, or `None` if it does not exist.
    fn file_attr(&self, ino: u64) -> Option<FileAttr>;
    /// Children of a directory inode: `(name, child_ino, is_dir)`.
    fn dir_children(&self, ino: u64) -> Option<&[(String, u64, bool)]>;
    /// Whether an inode is one of the tree's directories.
    fn is_dir(&self, ino: u64) -> bool;
    /// The parent of an inode (the root is its own parent).
    fn parent_ino(&self, ino: u64) -> u64;
    /// Whether an inode names a readable file.
    fn contains_file(&self, ino: u64) -> bool;
    /// Bytes for `[offset, offset + size)` of a file — stored or generated.
    /// Wrapped in `Zeroizing` so sensitive content (e.g. TOTP codes) is
    /// scrubbed once the reply has been sent; `Err(errno)` distinguishes a
    /// missing file (`ENOENT`) from a content-generation failure (`EIO`).
    fn read_file(&self, ino: u64, offset: u64, size: u32) -> Result<Zeroizing<Vec<u8>>, Errno>;
    /// Number of files, for `statfs`.
    fn file_count(&self) -> u64;

    /// Resolve a name within a directory to its inode.
    fn lookup_in_dir(&self, parent: u64, name: &str) -> Option<u64> {
        self.dir_children(parent)?
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, ino, _)| *ino)
    }
}

/// Take the snapshot read lock, replying `EIO` on poisoning.
macro_rules! snapshot {
    ($lock:expr, $reply:expr) => {
        match $lock.read() {
            Ok(guard) => guard,
            Err(_) => {
                $reply.error(Errno::EIO);
                return;
            }
        }
    };
}

pub fn lookup<S: SynthSnapshot>(
    lock: &RwLock<S>,
    parent: INodeNo,
    name: &OsStr,
    reply: ReplyEntry,
) {
    let Some(name_str) = name.to_str() else {
        reply.error(Errno::ENOENT);
        return;
    };
    let snap = snapshot!(lock, reply);
    match snap
        .lookup_in_dir(parent.0, name_str)
        .and_then(|ino| snap.file_attr(ino))
    {
        Some(attr) => reply.entry(&TTL, &attr, Generation(0)),
        None => reply.error(Errno::ENOENT),
    }
}

pub fn getattr<S: SynthSnapshot>(lock: &RwLock<S>, ino: INodeNo, reply: ReplyAttr) {
    let snap = snapshot!(lock, reply);
    match snap.file_attr(ino.0) {
        Some(attr) => reply.attr(&TTL, &attr),
        None => reply.error(Errno::ENOENT),
    }
}

pub fn access<S: SynthSnapshot>(lock: &RwLock<S>, ino: INodeNo, reply: ReplyEmpty) {
    let snap = snapshot!(lock, reply);
    match snap.file_attr(ino.0) {
        Some(_) => reply.ok(),
        None => reply.error(Errno::ENOENT),
    }
}

pub fn open<S: SynthSnapshot>(lock: &RwLock<S>, ino: INodeNo, reply: ReplyOpen) {
    let snap = snapshot!(lock, reply);
    if snap.contains_file(ino.0) {
        reply.opened(FileHandle(0), FopenFlags::empty());
    } else {
        reply.error(Errno::ENOENT);
    }
}

pub fn opendir<S: SynthSnapshot>(lock: &RwLock<S>, ino: INodeNo, reply: ReplyOpen) {
    let snap = snapshot!(lock, reply);
    if snap.is_dir(ino.0) {
        reply.opened(FileHandle(0), FopenFlags::empty());
    } else {
        reply.error(Errno::ENOENT);
    }
}

pub fn read<S: SynthSnapshot>(
    lock: &RwLock<S>,
    ino: INodeNo,
    offset: u64,
    size: u32,
    reply: ReplyData,
) {
    let snap = snapshot!(lock, reply);
    match snap.read_file(ino.0, offset, size) {
        Ok(bytes) => reply.data(&bytes),
        Err(e) => reply.error(e),
    }
}

pub fn readdir<S: SynthSnapshot>(
    lock: &RwLock<S>,
    ino: INodeNo,
    offset: u64,
    mut reply: ReplyDirectory,
) {
    let snap = snapshot!(lock, reply);
    if !snap.is_dir(ino.0) {
        reply.error(Errno::ENOENT);
        return;
    }

    let mut entries: Vec<(u64, FileType, String)> = vec![
        (ino.0, FileType::Directory, ".".to_string()),
        (
            snap.parent_ino(ino.0),
            FileType::Directory,
            "..".to_string(),
        ),
    ];
    if let Some(children) = snap.dir_children(ino.0) {
        for (name, child_ino, is_dir) in children {
            entries.push((
                *child_ino,
                if *is_dir {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                },
                name.clone(),
            ));
        }
    }

    for (i, (child_ino, kind, name)) in entries.iter().enumerate() {
        if (i as u64) < offset {
            continue;
        }
        if reply.add(INodeNo(*child_ino), (i + 1) as u64, *kind, name) {
            break;
        }
    }
    reply.ok();
}

pub fn statfs<S: SynthSnapshot>(lock: &RwLock<S>, reply: ReplyStatfs) {
    let snap = snapshot!(lock, reply);
    reply.statfs(0, 0, 0, snap.file_count(), 0, 4096, 255, 0);
}
