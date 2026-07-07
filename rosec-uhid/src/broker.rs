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

use anyhow::{Context, Result};

use crate::uhid;

/// A request the broker will honour for exactly one caller uid: one device
/// per user (enforced by [`Broker`]), so a caller cannot exhaust devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// uid the created hidraw node is chowned to (`0600`), from `SO_PEERCRED`.
    pub uid: u32,
}

/// Whether a new grant is permitted, given the callers already served. The
/// policy is one live device per uid — a repeat request from a uid that
/// already holds one is refused rather than stacking a second authenticator.
pub fn admit(existing: &[Grant], caller_uid: u32) -> Result<Grant, &'static str> {
    if existing.iter().any(|g| g.uid == caller_uid) {
        return Err("uid already holds a virtual authenticator");
    }
    Ok(Grant { uid: caller_uid })
}

/// Create the FIDO uhid device: open `/dev/uhid` and write the hard-coded
/// `UHID_CREATE2`. Returns the device fd (an owned `File`); dropping it or
/// exiting destroys the device.
///
/// Requires `CAP_SYS_ADMIN` / root — `/dev/uhid` is `0600 root:root` by
/// design (arbitrary HID creation is an input-injection primitive).
pub fn create_device(uhid_path: &Path) -> Result<std::fs::File> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(uhid_path)
        .with_context(|| format!("opening {}", uhid_path.display()))?;
    file.write_all(&uhid::create2_event())
        .context("writing UHID_CREATE2")?;
    Ok(file)
}

/// Chown the hidraw node backing our uhid device to `uid` at `0600`, so it
/// is reachable only by the user who owns the credentials behind it — not
/// left to the seat-scoped `uaccess` tag, which is wrong for a seatless
/// virtual device on a multi-user host.
///
/// Best-effort node discovery walks sysfs for the hidraw whose parent uhid
/// device advertises our vendor/product. Returns the chowned path.
pub fn chown_hidraw_for(uid: u32) -> Result<PathBuf> {
    let node = find_rosec_hidraw().context("locating the rosec hidraw node")?;
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

/// Find the `/dev/hidrawN` whose backing HID device is a rosec virtual
/// authenticator (matched by vendor:product in the sysfs `uevent`).
fn find_rosec_hidraw() -> Result<PathBuf> {
    let want = format!(
        "HID_ID=0003:{:08X}:{:08X}",
        uhid::ROSEC_VENDOR,
        uhid::ROSEC_PRODUCT
    );
    for entry in std::fs::read_dir("/sys/class/hidraw")
        .context("reading /sys/class/hidraw")?
        .flatten()
    {
        let uevent = entry.path().join("device/uevent");
        if let Ok(contents) = std::fs::read_to_string(&uevent)
            && contents.lines().any(|l| l.eq_ignore_ascii_case(&want))
        {
            let name = entry.file_name();
            return Ok(PathBuf::from("/dev").join(name));
        }
    }
    anyhow::bail!("no hidraw node found for rosec vendor/product (device not yet enumerated?)")
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
}
