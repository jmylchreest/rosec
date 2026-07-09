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
//! ├── config.d/             ino 6
//! │   └── <stem>.conf       ino 100+
//! └── allowed_signers       ino 7  (synthesised; only keys with
//!                                   `custom.ssh_signing_principal`
//!                                   land here, one line per
//!                                   principal × key pair)
//! ```
//!
//! The snapshot is rebuilt each time [`SshFuse::update`] is called.  All
//! filesystem methods share the snapshot via `RwLock<Snapshot>`.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use fuser::{
    AccessFlags, BackgroundSession, Config, Errno, FileAttr, FileHandle, FileType, Filesystem,
    INodeNo, LockOwner, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyOpen, ReplyStatfs, Request,
};
use rosec_ssh_agent::KeyEntry;
use tracing::warn;
use zeroize::Zeroizing;

use crate::config::build_config_snippets;
use crate::fs::ArcFs;
use crate::naming::{normalise_host_pattern, sanitise_filename};
use crate::tree::{self, SynthSnapshot};

// Well-known inode numbers for static directories
const INO_ROOT: u64 = 1;
const INO_KEYS: u64 = 2;
const INO_BY_NAME: u64 = 3;
const INO_BY_FINGERPRINT: u64 = 4;
const INO_BY_HOST: u64 = 5;
const INO_CONFIG_D: u64 = 6;
/// Static inode for the synthesised `allowed_signers` file at the root.
/// Reserved a fixed number rather than allocating dynamically so the file
/// has a stable path/inode across rebuilds (matters for `gpg.ssh.allowedSignersFile`
/// being pinned by users to this path).
const INO_ALLOWED_SIGNERS: u64 = 7;

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

        let root = snap
            .dir_children
            .get_mut(&INO_ROOT)
            .expect("root initialised");
        root.push(("keys".to_string(), INO_KEYS, true));
        root.push(("config.d".to_string(), INO_CONFIG_D, true));
        root.push(("allowed_signers".to_string(), INO_ALLOWED_SIGNERS, false));
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

            // by-fingerprint/<fp>.pub — one file per unique fingerprint (multiple
            // vault items may share the same key material).
            let fp_file = format!("{}.pub", sanitise_filename(&entry.fingerprint));
            let fp_exists = snap
                .dir_children
                .get(&INO_BY_FINGERPRINT)
                .is_some_and(|v| v.iter().any(|(n, _, _)| n == &fp_file));
            if !fp_exists {
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
            }

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

        // `/allowed_signers` — one `<principal> namespaces="git" <key>`
        // line per (principal × public-key) pair, dedup'd, only for keys
        // that carry at least one `custom.ssh_signing_principal`.  Empty
        // is fine: git treats it as "no key trusted", which is the
        // correct fail-closed behaviour before the user opts any key in.
        let mut allowed_lines: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        for entry in entries {
            if entry.signing_principals.is_empty() {
                continue;
            }
            let pubkey_line = entry.public_key_openssh.trim();
            if pubkey_line.is_empty() {
                continue;
            }
            for principal in &entry.signing_principals {
                let principal = principal.trim();
                if principal.is_empty() {
                    continue;
                }
                if !seen.insert((principal.to_string(), pubkey_line.to_string())) {
                    continue;
                }
                allowed_lines.push(format!("{principal} namespaces=\"git\" {pubkey_line}"));
            }
        }
        let allowed_content = if allowed_lines.is_empty() {
            // Keep a marker so users opening the file see what it's for.
            String::from(
                "# rosec allowed_signers — populated from items with\n\
                 # `custom.ssh_signing_principal` (or its dash spelling).\n\
                 # See `gpg.ssh.allowedSignersFile` in git's docs.\n",
            )
        } else {
            let mut out = allowed_lines.join("\n");
            out.push('\n');
            out
        };
        snap.files.insert(
            INO_ALLOWED_SIGNERS,
            VirtFile {
                content: allowed_content.into_bytes(),
            },
        );

        snap
    }
}

impl SynthSnapshot for Snapshot {
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
        Some(tree::make_attr(INodeNo(ino), kind, size, nlink, self.mtime))
    }

    fn dir_children(&self, ino: u64) -> Option<&[(String, u64, bool)]> {
        self.dir_children.get(&ino).map(Vec::as_slice)
    }

    fn is_dir(&self, ino: u64) -> bool {
        STATIC_DIRS.contains(&ino)
    }

    fn parent_ino(&self, ino: u64) -> u64 {
        match ino {
            INO_ROOT => INO_ROOT,
            INO_KEYS | INO_CONFIG_D | INO_ALLOWED_SIGNERS => INO_ROOT,
            INO_BY_NAME | INO_BY_FINGERPRINT | INO_BY_HOST => INO_KEYS,
            _ => INO_ROOT,
        }
    }

    fn contains_file(&self, ino: u64) -> bool {
        self.files.contains_key(&ino)
    }

    fn read_file(&self, ino: u64, offset: u64, size: u32) -> Result<Zeroizing<Vec<u8>>, Errno> {
        let f = self.files.get(&ino).ok_or(Errno::ENOENT)?;
        let start = (offset as usize).min(f.content.len());
        let end = (start + size as usize).min(f.content.len());
        Ok(Zeroizing::new(f.content[start..end].to_vec()))
    }

    fn file_count(&self) -> u64 {
        self.files.len() as u64
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
        tree::lookup(&self.snapshot, parent, name, reply);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        tree::getattr(&self.snapshot, ino, reply);
    }

    fn access(&self, _req: &Request, ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        tree::access(&self.snapshot, ino, reply);
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        tree::open(&self.snapshot, ino, reply);
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        tree::opendir(&self.snapshot, ino, reply);
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
        tree::read(&self.snapshot, ino, offset, size, reply);
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        tree::readdir(&self.snapshot, ino, offset, reply);
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        tree::statfs(&self.snapshot, reply);
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
    //
    // After a daemon crash the kernel still sees a FUSE mount whose session is
    // gone, so any access returns ENOTCONN ("Transport endpoint is not
    // connected").  `create_dir_all` then fails with EEXIST because the path
    // exists but isn't a usable directory.
    //
    // Strategy:
    //   1. Always attempt `fusermount3 -uz` (lazy unmount).  Harmless if
    //      nothing is mounted.
    //   2. Probe with `symlink_metadata` (lstat, does not traverse mounts).
    //      If the path exists but `read_dir` fails, it is stale — remove it.
    //   3. If `remove_dir` fails (e.g. still mounted), try `fusermount3 -u`
    //      (synchronous unmount) as a fallback, then remove again.
    let mp = mountpoint.to_string_lossy();
    let _ = std::process::Command::new("fusermount3")
        .args(["-uz", mp.as_ref()])
        .output();

    // symlink_metadata uses lstat which succeeds on stale FUSE mounts
    // (unlike stat/exists which fail with ENOTCONN).
    if mountpoint.symlink_metadata().is_ok() && std::fs::read_dir(mountpoint).is_err() {
        // Path exists but is broken — remove it.
        if std::fs::remove_dir(mountpoint).is_err() {
            // remove_dir can fail if still mounted; try synchronous unmount.
            let _ = std::process::Command::new("fusermount3")
                .args(["-u", mp.as_ref()])
                .output();
            let _ = std::fs::remove_dir(mountpoint);
        }
    }

    std::fs::create_dir_all(mountpoint)
        .with_context(|| format!("create FUSE mountpoint {:?}", mountpoint))?;

    let keys_by_name_dir = mountpoint.join("keys").join("by-name");
    let fuse = Arc::new(SshFuse::new(agent_sock.clone(), keys_by_name_dir));

    let mut config = Config::default();
    config.mount_options = crate::sandbox::mount_options("rosec-ssh");
    config.acl = crate::sandbox::ACL;

    let fs_wrapper = ArcFs(Arc::clone(&fuse));
    let session = fuser::spawn_mount2(fs_wrapper, mountpoint, &config)
        .with_context(|| format!("mount FUSE at {:?}", mountpoint))?;

    // Health check: verify the FUSE session is actually serving requests.
    // spawn_mount2 can return Ok even when the background session thread
    // dies immediately (e.g. under certain systemd hardening directives),
    // leaving a stale "Transport endpoint is not connected" mount.
    // A small delay gives the background thread time to initialise.
    std::thread::sleep(std::time::Duration::from_millis(50));
    std::fs::read_dir(mountpoint).with_context(|| {
        format!(
            "FUSE health check failed: mount at {:?} is not responding \
             (the background session may have died)",
            mountpoint
        )
    })?;

    Ok(MountHandle {
        session: Some(session),
        fuse,
        mountpoint: mountpoint.to_path_buf(),
        agent_sock,
    })
}
