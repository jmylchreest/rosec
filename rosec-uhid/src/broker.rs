//! Privileged broker: create the FIDO uhid device and pass its fd.
//!
//! Runs as root (socket-activated), does the one thing that needs privilege —
//! opening `/dev/uhid` and materialising a device whose HID descriptor is
//! **hard-coded** to the FIDO usage page ([`crate::uhid::FIDO_REPORT_DESCRIPTOR`])
//! — then hands the fd to the requesting user's daemon over a Unix socket and
//! forgets about it. The broker never speaks CTAP and holds no state after
//! fd-passing; closing the fd (including on daemon death) destroys the device.
//!
//! Because the descriptor is fixed here, the broker cannot be coerced into
//! creating a keyboard or any other input device, regardless of what a caller
//! asks for. The request message carries no descriptor — only the caller's
//! identity, which comes from `SO_PEERCRED`, not the message body.

use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::uhid;

/// Bound on waiting for the kernel to enumerate a just-created hidraw node.
const ENUMERATE_DEADLINE: Duration = Duration::from_secs(2);
const ENUMERATE_POLL: Duration = Duration::from_millis(20);

/// A device the broker has granted to one caller uid. One device per user, so
/// a caller cannot exhaust devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// uid the hidraw node is chowned to (`0600`), from `SO_PEERCRED`.
    pub uid: u32,
    /// `HID_UNIQ` for this device: correlates it to its hidraw node, and marks
    /// it gone when the node vanishes (peer closed the fd).
    pub uniq: String,
}

/// `HID_UNIQ` for a caller's device. Per-uid; only the root broker creates
/// uhid devices, so a caller can neither forge nor collide it.
pub fn uniq_for(uid: u32) -> String {
    format!("rosec-uhid-{uid}")
}

/// Drop grants whose hidraw node no longer exists, so a uid whose device died
/// is re-admitted rather than refused until the broker restarts. Before
/// [`admit`].
pub fn evict_dead_grants(grants: &mut Vec<Grant>) {
    grants.retain(|g| find_hidraw_by_uniq(&g.uniq).is_some());
}

/// One live device per uid: a uid that already holds one is refused. Run
/// [`evict_dead_grants`] first so a uid whose device died is allowed.
pub fn admit(existing: &[Grant], caller_uid: u32) -> Result<Grant, &'static str> {
    if existing.iter().any(|g| g.uid == caller_uid) {
        return Err("uid already holds a live virtual authenticator");
    }
    Ok(Grant {
        uid: caller_uid,
        uniq: uniq_for(caller_uid),
    })
}

/// Create the FIDO uhid device with `uniq` as its `HID_UNIQ`: open `/dev/uhid`
/// and write the hard-coded `UHID_CREATE2`. Returns the device fd (an owned
/// `File`); dropping it or exiting destroys the device.
///
/// Requires `CAP_SYS_ADMIN` / root — `/dev/uhid` is `0600 root:root` by
/// design (arbitrary HID creation is an input-injection primitive).
pub fn create_device(uhid_path: &Path, uniq: &str) -> Result<std::fs::File> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(uhid_path)
        .with_context(|| format!("opening {}", uhid_path.display()))?;
    file.write_all(&uhid::create2_event(uniq))
        .context("writing UHID_CREATE2")?;
    Ok(file)
}

/// Chown the device's hidraw node to `uid` at `0600` — a seatless virtual
/// device must not rely on the seat-scoped `uaccess` tag.
///
/// The node is located by `HID_UNIQ`, so it is the *exact* device this call
/// created, never a vendor:product scan that could hit another user's device
/// on a multi-user host. Polls, since the node enumerates asynchronously after
/// `UHID_CREATE2`.
pub fn chown_hidraw_for(uid: u32, uniq: &str) -> Result<PathBuf> {
    let node = wait_for_hidraw(uniq)?;
    nix::unistd::chown(
        &node,
        Some(nix::unistd::Uid::from_raw(uid)),
        Some(nix::unistd::Gid::from_raw(uid)),
    )
    .with_context(|| format!("chowning {}", node.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", node.display()))?;
    Ok(node)
}

/// Poll `/sys/class/hidraw` for the node whose `HID_UNIQ` matches `uniq`, up to
/// [`ENUMERATE_DEADLINE`] (the node appears asynchronously after
/// `UHID_CREATE2`).
fn wait_for_hidraw(uniq: &str) -> Result<PathBuf> {
    let start = Instant::now();
    loop {
        if let Some(node) = find_hidraw_by_uniq(uniq) {
            return Ok(node);
        }
        if start.elapsed() >= ENUMERATE_DEADLINE {
            anyhow::bail!("hidraw node for {uniq} did not enumerate within {ENUMERATE_DEADLINE:?}");
        }
        std::thread::sleep(ENUMERATE_POLL);
    }
}

/// Find the `/dev/hidrawN` whose backing HID device carries `HID_UNIQ=<uniq>`
/// in its sysfs `uevent`. `None` if absent (not yet enumerated, or already
/// destroyed).
fn find_hidraw_by_uniq(uniq: &str) -> Option<PathBuf> {
    let want = format!("HID_UNIQ={uniq}");
    for entry in std::fs::read_dir("/sys/class/hidraw").ok()?.flatten() {
        let uevent = entry.path().join("device/uevent");
        if let Ok(contents) = std::fs::read_to_string(&uevent)
            && contents.lines().any(|l| l == want)
        {
            return Some(PathBuf::from("/dev").join(entry.file_name()));
        }
    }
    None
}

/// Send `fd` to the peer of `stream` via `SCM_RIGHTS` with a one-byte
/// payload. After this the caller may drop its copy of `fd` — the peer owns
/// a duplicate and its lifetime now governs the device.
pub fn send_fd(stream: &UnixStream, fd: RawFd) -> Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
    use std::io::IoSlice;
    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    let iov = [IoSlice::new(&[0u8])];
    sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
        .context("sendmsg SCM_RIGHTS")?;
    Ok(())
}

/// Read the peer's credentials (`SO_PEERCRED`) from a connected stream. The
/// caller's identity for the grant comes from here, never from message data.
pub fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let cred = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .context("SO_PEERCRED")?;
    Ok(cred.uid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_device_per_uid() {
        let mut granted: Vec<Grant> = Vec::new();
        let g = admit(&granted, 1000).unwrap();
        assert_eq!(g.uid, 1000);
        granted.push(g);
        // Same uid again is refused.
        assert!(admit(&granted, 1000).is_err());
        // A different uid is admitted.
        assert!(admit(&granted, 1001).is_ok());
    }

    #[test]
    fn uniq_is_per_uid_and_carried_by_the_grant() {
        assert_eq!(uniq_for(1000), "rosec-uhid-1000");
        assert_ne!(uniq_for(1000), uniq_for(1001));
        assert_eq!(admit(&[], 1000).unwrap().uniq, "rosec-uhid-1000");
    }

    #[test]
    fn evict_drops_grants_whose_device_is_gone() {
        // A grant whose uniq matches no live hidraw node (no such device on
        // this machine) is treated as dead and released, so its uid can be
        // re-admitted.
        let mut granted = vec![Grant {
            uid: 4242,
            uniq: "rosec-uhid-test-nonexistent-4242".into(),
        }];
        evict_dead_grants(&mut granted);
        assert!(granted.is_empty());
        assert!(admit(&granted, 4242).is_ok());
    }
}
