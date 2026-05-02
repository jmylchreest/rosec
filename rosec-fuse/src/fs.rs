//! Shared FUSE plumbing used by [`crate::ssh_fs`] and [`crate::totp_fs`].

use std::ffi::OsStr;
use std::sync::Arc;

use fuser::{
    AccessFlags, FileHandle, Filesystem, INodeNo, LockOwner, OpenFlags, ReplyAttr, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, Request,
};

/// Newtype that lets us hand an `Arc<T>` to fuser, which expects a value
/// implementing `Filesystem`.  Forwards every call to the inner `T`.
pub(crate) struct ArcFs<T>(pub Arc<T>);

impl<T> Filesystem for ArcFs<T>
where
    T: Filesystem + Send + Sync + 'static,
{
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

    #[allow(clippy::too_many_arguments)]
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
