//! FUSE virtual filesystem for TOTP codes.
//!
//! Mounts at `$XDG_RUNTIME_DIR/rosec/totp/` and exposes:
//!
//! ```text
//! totp/
//! ├── by-name/<item-label>.code
//! └── by-id/<hex-id>.code
//! ```
//!
//! Each `.code` file returns the current TOTP code (+ newline) when read.
//! Codes are computed dynamically on each `read()` — never cached.

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
use rosec_core::totp::TotpParams;
use tracing::warn;

use crate::naming::sanitise_filename;

const INO_ROOT: u64 = 1;
const INO_BY_NAME: u64 = 2;
const INO_BY_ID: u64 = 3;

const INO_DYNAMIC_START: u64 = 100;

static STATIC_DIRS: &[u64] = &[INO_ROOT, INO_BY_NAME, INO_BY_ID];

/// A TOTP entry stored in the snapshot.
pub struct TotpEntry {
    pub item_id: String,
    pub item_name: String,
    pub params: TotpParams,
}

impl std::fmt::Debug for TotpEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpEntry")
            .field("item_id", &self.item_id)
            .field("item_name", &self.item_name)
            .finish_non_exhaustive()
    }
}

/// Snapshot of the TOTP filesystem.
///
/// Unlike the SSH FUSE, file content is NOT stored — codes are generated
/// dynamically from `TotpParams` on each `read()`.
struct Snapshot {
    /// Inode → TotpParams for dynamic code generation.
    params: HashMap<u64, TotpParams>,
    /// Predictable file size per inode: `digits + 1` (code + newline).
    file_sizes: HashMap<u64, u64>,
    /// Children of each directory: `(name, child_ino, is_dir)`.
    dir_children: HashMap<u64, Vec<(String, u64, bool)>>,
}

impl Default for Snapshot {
    fn default() -> Self {
        let mut snap = Self {
            params: HashMap::new(),
            file_sizes: HashMap::new(),
            dir_children: HashMap::new(),
        };
        for &ino in STATIC_DIRS {
            snap.dir_children.insert(ino, Vec::new());
        }
        snap
    }
}

impl Snapshot {
    fn build(entries: &[TotpEntry]) -> Self {
        let mut snap = Self::default();

        let root = snap
            .dir_children
            .get_mut(&INO_ROOT)
            .expect("root initialised");
        root.push(("by-name".to_string(), INO_BY_NAME, true));
        root.push(("by-id".to_string(), INO_BY_ID, true));

        let mut next_ino = INO_DYNAMIC_START;
        let mut alloc_ino = || {
            let ino = next_ino;
            next_ino += 1;
            ino
        };

        for entry in entries {
            let size = (entry.params.digits + 1) as u64; // code + newline

            // by-name/<item-name>.code
            let name_file = format!("{}.code", sanitise_filename(&entry.item_name));
            let ino_name = alloc_ino();
            snap.params.insert(ino_name, entry.params.clone());
            snap.file_sizes.insert(ino_name, size);
            snap.dir_children
                .get_mut(&INO_BY_NAME)
                .expect("by-name initialised")
                .push((name_file, ino_name, false));

            // by-id/<hex-id>.code
            let id_file = format!("{}.code", sanitise_filename(&entry.item_id));
            let ino_id = alloc_ino();
            snap.params.insert(ino_id, entry.params.clone());
            snap.file_sizes.insert(ino_id, size);
            snap.dir_children
                .get_mut(&INO_BY_ID)
                .expect("by-id initialised")
                .push((id_file, ino_id, false));
        }

        snap
    }

    /// mtime for files: start of the current TOTP period.
    /// Changes every 30s so `watch cat` can detect refreshes.
    fn totp_mtime(&self, ino: u64) -> SystemTime {
        if let Some(p) = self.params.get(&ino) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let period_start = now - (now % p.period);
            UNIX_EPOCH + Duration::from_secs(period_start)
        } else {
            SystemTime::now()
        }
    }

    fn file_attr(&self, ino: u64) -> Option<FileAttr> {
        let (kind, size, nlink, mtime) = if STATIC_DIRS.contains(&ino) {
            (FileType::Directory, 4096u64, 2u32, SystemTime::now())
        } else {
            let size = *self.file_sizes.get(&ino)?;
            let mtime = self.totp_mtime(ino);
            (FileType::RegularFile, size, 1u32, mtime)
        };
        Some(make_attr(INodeNo(ino), kind, size, nlink, mtime))
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
            INO_BY_NAME | INO_BY_ID => INO_ROOT,
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

/// The TOTP FUSE filesystem object.
pub struct TotpFuse {
    snapshot: RwLock<Snapshot>,
}

impl Default for TotpFuse {
    fn default() -> Self {
        Self {
            snapshot: RwLock::new(Snapshot::default()),
        }
    }
}

impl TotpFuse {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild the snapshot from a new set of TOTP entries.
    pub fn update(&self, entries: &[TotpEntry]) {
        let snap = Snapshot::build(entries);
        match self.snapshot.write() {
            Ok(mut guard) => *guard = snap,
            Err(e) => warn!("TOTP FUSE snapshot lock poisoned: {e}"),
        }
    }
}

impl Filesystem for TotpFuse {
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
                    // Short TTL so mtime/content refresh every period.
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
        let snap = match self.snapshot.read() {
            Ok(g) => g,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        if snap.params.contains_key(&ino.0) {
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
        match snap.params.get(&ino.0) {
            None => reply.error(Errno::ENOENT),
            Some(params) => {
                // Generate the code fresh on every read.
                let code = rosec_core::totp::generate_code_now(params);
                let content = format!("{code}\n");
                let bytes = content.as_bytes();
                let start = (offset as usize).min(bytes.len());
                let end = (start + size as usize).min(bytes.len());
                reply.data(&bytes[start..end]);
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
        let files = snap.params.len() as u64;
        reply.statfs(0, 0, 0, files, 0, 4096, 255, 0);
    }
}

/// Newtype wrapper so we can pass `Arc<TotpFuse>` as a `Filesystem`.
struct ArcTotpFuse(Arc<TotpFuse>);

impl Filesystem for ArcTotpFuse {
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

/// Handle to the mounted TOTP FUSE filesystem.
pub struct TotpMountHandle {
    session: Option<BackgroundSession>,
    pub fuse: Arc<TotpFuse>,
    mountpoint: PathBuf,
}

impl std::fmt::Debug for TotpMountHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpMountHandle")
            .field("mountpoint", &self.mountpoint)
            .finish_non_exhaustive()
    }
}

impl Drop for TotpMountHandle {
    fn drop(&mut self) {
        drop(self.session.take());
        let _ = std::process::Command::new("fusermount3")
            .args(["-u", self.mountpoint.to_string_lossy().as_ref()])
            .output();
    }
}

/// Mount the TOTP FUSE filesystem at `mountpoint`.
pub fn totp_mount(mountpoint: &Path) -> anyhow::Result<TotpMountHandle> {
    // Clean up stale FUSE mount from a previous crash.
    let mp = mountpoint.to_string_lossy();
    let _ = std::process::Command::new("fusermount3")
        .args(["-uz", mp.as_ref()])
        .output();

    if mountpoint.symlink_metadata().is_ok()
        && std::fs::read_dir(mountpoint).is_err()
        && std::fs::remove_dir(mountpoint).is_err()
    {
        let _ = std::process::Command::new("fusermount3")
            .args(["-u", mp.as_ref()])
            .output();
        let _ = std::fs::remove_dir(mountpoint);
    }

    std::fs::create_dir_all(mountpoint)
        .with_context(|| format!("create TOTP FUSE mountpoint {:?}", mountpoint))?;

    let fuse = Arc::new(TotpFuse::new());

    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RO,
        MountOption::FSName("rosec-totp".to_string()),
    ];
    config.acl = SessionACL::Owner;

    let fs_wrapper = ArcTotpFuse(Arc::clone(&fuse));
    let session = fuser::spawn_mount2(fs_wrapper, mountpoint, &config)
        .with_context(|| format!("mount TOTP FUSE at {:?}", mountpoint))?;

    std::thread::sleep(std::time::Duration::from_millis(50));
    std::fs::read_dir(mountpoint).with_context(|| {
        format!(
            "TOTP FUSE health check failed: mount at {:?} is not responding",
            mountpoint
        )
    })?;

    Ok(TotpMountHandle {
        session: Some(session),
        fuse,
        mountpoint: mountpoint.to_path_buf(),
    })
}
