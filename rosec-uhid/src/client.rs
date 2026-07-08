//! Client side of the broker handshake — how rosecd obtains the virtual
//! authenticator device fd, with the checks that make trusting a world-
//! connectable system socket safe.
//!
//! The broker socket lives at a shared system path (`/run/rosec/uhid.sock`)
//! and is mode `0666`, so before rosecd trusts anything it receives it must
//! verify two things: the peer really is root (an imposter that squatted the
//! path would not be), and the passed fd really is the uhid character device
//! (not some other fd a squatter handed over to turn rosecd into a signing
//! oracle). Either check failing means the handshake is untrustworthy and we
//! refuse rather than drive a forged device.

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::broker::peer_uid;

/// The virtual HID device the broker creates and passes back.
pub const UHID_DEVICE: &str = "/dev/uhid";

/// Connect to the privileged broker, verify it is root, receive the virtual
/// authenticator device fd, and confirm it is the uhid device.
pub fn connect_and_receive(socket_path: &Path) -> Result<File> {
    let stream = UnixStream::connect(socket_path)
        .with_context(|| format!("connecting to broker at {}", socket_path.display()))?;

    // The broker must be root. A non-root peer at this path is an imposter
    // (the real broker is a root system service); refuse before trusting any
    // fd it sends.
    let broker_uid = peer_uid(&stream)?;
    if broker_uid != 0 {
        bail!(
            "broker peer is uid {broker_uid}, not root — refusing possible imposter at {}",
            socket_path.display()
        );
    }

    receive_device_fd(&stream, Path::new(UHID_DEVICE))
}

/// Receive one fd via `SCM_RIGHTS` and confirm it is the character device at
/// `expected_device` (matched by device number). Split from the uid check so
/// it is testable with a socketpair and a stand-in character device.
pub fn receive_device_fd(stream: &UnixStream, expected_device: &Path) -> Result<File> {
    let fd = recv_fd(stream)?;
    // SAFETY: `recv_fd` returned a freshly received, owned fd.
    let file = unsafe { File::from_raw_fd(fd) };

    let got = nix::sys::stat::fstat(&file).context("fstat received fd")?;
    if got.st_mode & libc::S_IFMT != libc::S_IFCHR {
        bail!("received fd is not a character device — refusing");
    }
    let want = nix::sys::stat::stat(expected_device)
        .with_context(|| format!("stat {}", expected_device.display()))?;
    if got.st_rdev != want.st_rdev {
        bail!(
            "received fd is not {} (device-number mismatch) — refusing",
            expected_device.display()
        );
    }
    Ok(file)
}

/// Receive a single fd sent via `SCM_RIGHTS` (companion to
/// [`crate::broker::send_fd`]).
fn recv_fd(stream: &UnixStream) -> Result<RawFd> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    use std::io::IoSliceMut;

    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg_space = nix::cmsg_space!(RawFd);
    // MSG_CMSG_CLOEXEC: the received fd must be close-on-exec so it does not
    // leak into rosec-prompt (or any other) child processes the daemon spawns
    // during a ceremony. Set atomically at receive time — a post-hoc
    // fcntl(F_SETFD) would race a concurrent fork() on the multi-threaded
    // runtime.
    let msg = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .context("recvmsg SCM_RIGHTS")?;

    for cmsg in msg.cmsgs().context("decoding control messages")? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg
            && let Some(&fd) = fds.first()
        {
            return Ok(fd);
        }
    }
    bail!("broker sent no file descriptor");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::send_fd;

    #[test]
    fn accepts_the_expected_char_device() {
        let (broker_end, client_end) = UnixStream::pair().unwrap();
        // /dev/null stands in for the uhid char device.
        let devnull = File::open("/dev/null").unwrap();
        send_fd(&broker_end, devnull.as_raw_fd()).unwrap();

        let got = receive_device_fd(&client_end, Path::new("/dev/null")).unwrap();
        let st = nix::sys::stat::fstat(&got).unwrap();
        assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFCHR);
    }

    #[test]
    fn rejects_a_regular_file_fd() {
        let (broker_end, client_end) = UnixStream::pair().unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let f = File::open(tmp.path()).unwrap();
        send_fd(&broker_end, f.as_raw_fd()).unwrap();

        let err = receive_device_fd(&client_end, Path::new("/dev/null")).unwrap_err();
        assert!(err.to_string().contains("not a character device"));
    }

    #[test]
    fn rejects_the_wrong_char_device() {
        // Sent /dev/null but expecting /dev/zero → device-number mismatch.
        let (broker_end, client_end) = UnixStream::pair().unwrap();
        let devnull = File::open("/dev/null").unwrap();
        send_fd(&broker_end, devnull.as_raw_fd()).unwrap();

        let err = receive_device_fd(&client_end, Path::new("/dev/zero")).unwrap_err();
        assert!(err.to_string().contains("device-number mismatch"));
    }
}
