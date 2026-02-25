//! FUSE filesystem implementation.
//!
//! Presents a read-only virtual filesystem:
//!
//! ```text
//! /                         ino 1  (root)
//! ├── keys/                 ino 2
//! │   ├── by-name/          ino 3
//! │   │   └── <name>.pub    ino 100+
//! │   ├── by-fingerprint/   ino 4
//! │   │   └── <fp>.pub      ino 100+
//! │   └── by-host/          ino 5
//! │       └── <host>.pub    ino 100+
//! └── config.d/             ino 6
//!     └── <stem>.conf       ino 100+
//! ```
//!
//! The snapshot is rebuilt each time [`SshFuse::update`] is called.  All
//! filesystem methods share the snapshot via `RwLock<Snapshot>`.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use fuser::{
    AccessFlags, BackgroundSession, Config, Errno, FileAttr, FileHandle, FileType, Filesystem,
    FopenFlags, Generation, INodeNo, LockOwner, MountOption, OpenFlags, ReplyAttr, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, Request, SessionACL,
};
use rosec_ssh_agent::KeyEntry;
use tracing::{debug, warn};

use crate::config::build_config_snippets;
use crate::naming::{normalise_host_pattern, sanitise_filename};

// Well-known inode numbers for static directories
const INO_ROOT: u64 = 1;
const INO_KEYS: u64 = 2;
const INO_BY_NAME: u64 = 3;
const INO_BY_FINGERPRINT: u64 = 4;
const INO_BY_HOST: u64 = 5;
const INO_CONFIG_D: u64 = 6;

/// First inode for dynamic entries (files).
const INO_DYNAMIC_START: u64 = 100;

static STATIC_DIRS: &[u64] = &[
    INO_ROOT,
    INO_KEYS,
    INO_BY_NAME,
    INO_BY_FINGERPRINT,
    INO_BY_HOST,
    INO_CONFIG_D,
];

/// A file entry in the virtual filesystem.
#[derive(Debug, Clone)]
struct VirtFile {
    content: Vec<u8>,
}

/// Snapshot of the virtual filesystem built from the current key store state.
#[derive(Debug)]
struct Snapshot {
    /// All virtual files, indexed by inode.
    files: HashMap<u64, VirtFile>,
    /// Children of each directory inode: (name, child_ino, is_dir).
    dir_children: HashMap<u64, Vec<(String, u64, bool)>>,
    /// Modification time for all entries.
    mtime: SystemTime,
}

impl Default for Snapshot {
    fn default() -> Self {
        let mut snap = Self {
            files: HashMap::new(),
            dir_children: HashMap::new(),
            mtime: UNIX_EPOCH,
        };
        for &ino in STATIC_DIRS {
            snap.dir_children.insert(ino, Vec::new());
        }
        snap
    }
}

impl Snapshot {
    fn build(entries: &[&KeyEntry], agent_sock: &Path, keys_by_name_dir: &Path) -> Self {
        let mtime = SystemTime::now();
        let mut snap = Snapshot {
            files: HashMap::new(),
            dir_children: HashMap::new(),
            mtime,
        };
        for &ino in STATIC_DIRS {
            snap.dir_children.insert(ino, Vec::new());
        }

        // root children
        let root = snap
            .dir_children
            .get_mut(&INO_ROOT)
            .expect("root initialised");
        root.push(("keys".to_string(), INO_KEYS, true));
        root.push(("config.d".to_string(), INO_CONFIG_D, true));
        // keys/ children
        let keys = snap
            .dir_children
            .get_mut(&INO_KEYS)
            .expect("keys initialised");
        keys.push(("by-name".to_string(), INO_BY_NAME, true));
        keys.push(("by-fingerprint".to_string(), INO_BY_FINGERPRINT, true));
        keys.push(("by-host".to_string(), INO_BY_HOST, true));

        let mut next_ino = INO_DYNAMIC_START;
        let mut alloc_ino = || {
            let ino = next_ino;
            next_ino += 1;
            ino
        };

        for entry in entries {
            let pubkey = entry.public_key_openssh.as_bytes().to_vec();

            // by-name/<item-name>.pub
            let name_file = format!("{}.pub", sanitise_filename(&entry.item_name));
            let ino_name = alloc_ino();
            snap.files.insert(
                ino_name,
                VirtFile {
                    content: pubkey.clone(),
                },
            );
            snap.dir_children
                .get_mut(&INO_BY_NAME)
                .expect("by-name initialised")
                .push((name_file, ino_name, false));

            // by-fingerprint/<fp>.pub — sanitise (replaces ':', '/' etc.)
            let fp_file = format!("{}.pub", sanitise_filename(&entry.fingerprint));
            let ino_fp = alloc_ino();
            snap.files.insert(
                ino_fp,
                VirtFile {
                    content: pubkey.clone(),
                },
            );
            snap.dir_children
                .get_mut(&INO_BY_FINGERPRINT)
                .expect("by-fingerprint initialised")
                .push((fp_file, ino_fp, false));

            // by-host/<normalised-host>.pub (one per ssh_host)
            for host in &entry.ssh_hosts {
                let host_file = format!("{}.pub", normalise_host_pattern(host));
                let exists = snap
                    .dir_children
                    .get(&INO_BY_HOST)
                    .is_some_and(|v| v.iter().any(|(n, _, _)| n == &host_file));
                if exists {
                    continue; // dedup — conflict resolution picks winner in config.d
                }
                let ino_host = alloc_ino();
                snap.files.insert(
                    ino_host,
                    VirtFile {
                        content: pubkey.clone(),
                    },
                );
                snap.dir_children
                    .get_mut(&INO_BY_HOST)
                    .expect("by-host initialised")
                    .push((host_file, ino_host, false));
            }
        }

        // config.d/ snippets
        let snippets = build_config_snippets(entries, agent_sock, keys_by_name_dir);
        for snippet in snippets {
            let filename = format!("{}.conf", snippet.filename_stem);
            let ino = alloc_ino();
            snap.files.insert(
                ino,
                VirtFile {
                    content: snippet.content.into_bytes(),
                },
            );
            snap.dir_children
                .get_mut(&INO_CONFIG_D)
                .expect("config.d initialised")
                .push((filename, ino, false));
        }

        snap
    }

    fn file_attr(&self, ino: u64) -> Option<FileAttr> {
        let (kind, size, nlink) = match ino {
            INO_ROOT | INO_KEYS | INO_BY_NAME | INO_BY_FINGERPRINT | INO_BY_HOST | INO_CONFIG_D => {
                (FileType::Directory, 4096u64, 2u32)
            }
            _ => {
                let f = self.files.get(&ino)?;
                (FileType::RegularFile, f.content.len() as u64, 1u32)
            }
        };
        Some(make_attr(INodeNo(ino), kind, size, nlink, self.mtime))
    }

    fn lookup_in_dir(&self, parent: u64, name: &str) -> Option<u64> {
        self.dir_children
            .get(&parent)?
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, ino, _)| *ino)
    }

    fn is_dir(&self, ino: u64) -> bool {
        STATIC_DIRS.contains(&ino)
    }

    fn parent_ino(&self, ino: u64) -> u64 {
        match ino {
            INO_ROOT => INO_ROOT,
            INO_KEYS | INO_CONFIG_D => INO_ROOT,
            INO_BY_NAME | INO_BY_FINGERPRINT | INO_BY_HOST => INO_KEYS,
            _ => INO_ROOT,
        }
    }
}

fn make_attr(ino: INodeNo, kind: FileType, size: u64, nlink: u32, mtime: SystemTime) -> FileAttr {
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
            0o555
        } else {
            0o444
        },
        nlink,
        uid,
        gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

/// The FUSE filesystem object.
///
/// `Filesystem` in fuser 0.17 takes `&self` — interior mutability via
/// `RwLock` lets us swap the snapshot on updates.
pub struct SshFuse {
    snapshot: RwLock<Snapshot>,
    agent_sock: PathBuf,
    keys_by_name_dir: PathBuf,
}

impl SshFuse {
    /// Create a new filesystem with an empty snapshot.
    pub fn new(agent_sock: PathBuf, keys_by_name_dir: PathBuf) -> Self {
        Self {
            snapshot: RwLock::new(Snapshot::default()),
            agent_sock,
            keys_by_name_dir,
        }
    }

    /// Rebuild the snapshot from a new set of key entries.
    ///
    /// Call this after each vault sync or lock/unlock event.
    pub fn update(&self, entries: &[&KeyEntry]) {
        let snap = Snapshot::build(entries, &self.agent_sock, &self.keys_by_name_dir);
        match self.snapshot.write() {
            Ok(mut guard) => *guard = snap,
            Err(e) => warn!("FUSE snapshot lock poisoned: {e}"),
        }
    }
}

impl Filesystem for SshFuse {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        let snap = match self.snapshot.read() {
            Ok(g) => g,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        match snap.lookup_in_dir(parent.0, name_str) {
            None => reply.error(Errno::ENOENT),
            Some(ino) => match snap.file_attr(ino) {
                None => reply.error(Errno::ENOENT),
                Some(attr) => {
                    debug!(parent = parent.0, name = name_str, ino, "fuse lookup");
                    reply.entry(&Duration::from_secs(1), &attr, Generation(0));
                }
            },
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let snap = match self.snapshot.read() {
            Ok(g) => g,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        match snap.file_attr(ino.0) {
            None => reply.error(Errno::ENOENT),
            Some(attr) => reply.attr(&Duration::from_secs(1), &attr),
        }
    }

    fn access(&self, _req: &Request, ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        // Permission checks are handled by the kernel (SessionACL::Owner
        // restricts to our UID), so we only need to verify the inode exists.
        let snap = match self.snapshot.read() {
            Ok(g) => g,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        match snap.file_attr(ino.0) {
            None => reply.error(Errno::ENOENT),
            Some(_) => reply.ok(),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        // Read-only filesystem — just check the inode exists.
        let snap = match self.snapshot.read() {
            Ok(g) => g,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        if snap.files.contains_key(&ino.0) {
            reply.opened(FileHandle(0), FopenFlags::empty());
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let snap = match self.snapshot.read() {
            Ok(g) => g,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        if snap.is_dir(ino.0) {
            reply.opened(FileHandle(0), FopenFlags::empty());
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let snap = match self.snapshot.read() {
            Ok(g) => g,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        match snap.files.get(&ino.0) {
            None => reply.error(Errno::ENOENT),
            Some(f) => {
                let start = (offset as usize).min(f.content.len());
                let end = (start + size as usize).min(f.content.len());
                reply.data(&f.content[start..end]);
            }
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let snap = match self.snapshot.read() {
            Ok(g) => g,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        if !snap.is_dir(ino.0) {
            reply.error(Errno::ENOENT);
            return;
        }
        let parent_ino = snap.parent_ino(ino.0);

        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino.0, FileType::Directory, ".".to_string()),
            (parent_ino, FileType::Directory, "..".to_string()),
        ];
        if let Some(children) = snap.dir_children.get(&ino.0) {
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

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let snap = match self.snapshot.read() {
            Ok(g) => g,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        let files = snap.files.len() as u64;
        // bsize, frsize=4096; blocks=0 (virtual); bfree/bavail=0 (read-only);
        // files=count; ffree=0; namelen=255
        reply.statfs(0, 0, 0, files, 0, 4096, 255, 0);
    }
}

/// A handle to a mounted FUSE filesystem.
///
/// Dropping this handle unmounts the filesystem via `fusermount3 -u` and
/// removes the agent socket file.  The `BackgroundSession` drop handles the
/// kernel-side unmount; we call `fusermount3 -u` as a belt-and-suspenders
/// cleanup in case the kernel mount outlives the process (e.g. on panic).
pub struct MountHandle {
    session: Option<BackgroundSession>,
    /// Shared reference to the filesystem for calling [`SshFuse::update`].
    pub fuse: Arc<SshFuse>,
    mountpoint: PathBuf,
    agent_sock: PathBuf,
}

impl std::fmt::Debug for MountHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountHandle")
            .field("mountpoint", &self.mountpoint)
            .finish_non_exhaustive()
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        // Drop the BackgroundSession first — this signals the FUSE thread to
        // stop and performs the kernel unmount via the fuser drop handler.
        drop(self.session.take());

        // Belt-and-suspenders: also call fusermount3 -u in case the above
        // didn't fully clean up (e.g. when the process is killed).
        let _ = std::process::Command::new("fusermount3")
            .args(["-u", self.mountpoint.to_string_lossy().as_ref()])
            .output();

        // Remove the agent socket.
        if self.agent_sock.exists() {
            let _ = std::fs::remove_file(&self.agent_sock);
        }
    }
}

/// Mount the FUSE filesystem at `mountpoint` and return a [`MountHandle`].
///
/// The mount is read-only and restricted to the owner (`SessionACL::Owner`).
/// `AutoUnmount` is intentionally omitted — it is incompatible with
/// `SessionACL::Owner` in fuser 0.17.  Cleanup is handled by [`MountHandle`]'s
/// `Drop` impl instead.
pub fn mount(mountpoint: &Path, agent_sock: PathBuf) -> anyhow::Result<MountHandle> {
    // Clean up any stale FUSE mount from a previous crashed instance.
    // `fusermount3 -uz` (lazy unmount) is safe to call unconditionally:
    // - If a stale mount exists, it will be cleaned up
    // - If nothing is mounted, it fails harmlessly
    // We ignore the exit status because failure just means nothing was mounted.
    let _ = std::process::Command::new("fusermount3")
        .args(["-uz", mountpoint.to_string_lossy().as_ref()])
        .output();

    std::fs::create_dir_all(mountpoint)
        .with_context(|| format!("create FUSE mountpoint {:?}", mountpoint))?;

    let keys_by_name_dir = mountpoint.join("keys").join("by-name");
    let fuse = Arc::new(SshFuse::new(agent_sock.clone(), keys_by_name_dir));

    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RO,
        MountOption::FSName("rosec-ssh".to_string()),
    ];
    config.acl = SessionACL::Owner;

    let fs_wrapper = ArcFuse(Arc::clone(&fuse));
    let session = fuser::spawn_mount2(fs_wrapper, mountpoint, &config)
        .with_context(|| format!("mount FUSE at {:?}", mountpoint))?;

    Ok(MountHandle {
        session: Some(session),
        fuse,
        mountpoint: mountpoint.to_path_buf(),
        agent_sock,
    })
}

/// Newtype wrapper so we can pass `Arc<SshFuse>` as a `Filesystem`.
struct ArcFuse(Arc<SshFuse>);

impl Filesystem for ArcFuse {
    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        self.0.lookup(req, parent, name, reply);
    }

    fn getattr(&self, req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        self.0.getattr(req, ino, fh, reply);
    }

    fn access(&self, req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        self.0.access(req, ino, mask, reply);
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        self.0.open(req, ino, flags, reply);
    }

    fn opendir(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        self.0.opendir(req, ino, flags, reply);
    }

    fn read(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        flags: OpenFlags,
        lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        self.0
            .read(req, ino, fh, offset, size, flags, lock_owner, reply);
    }

    fn readdir(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        self.0.readdir(req, ino, fh, offset, reply);
    }

    fn statfs(&self, req: &Request, ino: INodeNo, reply: ReplyStatfs) {
        self.0.statfs(req, ino, reply);
    }
}
