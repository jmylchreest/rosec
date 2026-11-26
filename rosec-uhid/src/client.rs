//! Receive a FIDO report socket from the privileged broker.

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::broker::peer_uid;

/// The kernel UHID device opened by the privileged broker.
pub const UHID_DEVICE: &str = "/dev/uhid";

/// A root broker returned a kernel device using the legacy handoff.
#[derive(Debug)]
pub struct LegacyBroker;

impl std::fmt::Display for LegacyBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("legacy UHID broker returned a kernel device")
    }
}

impl std::error::Error for LegacyBroker {}

/// Connect to the broker, authenticate its uid and receive a report socket.
pub fn connect_and_receive(socket_path: &Path) -> Result<File> {
    let stream = UnixStream::connect(socket_path)
        .with_context(|| format!("connecting to broker at {}", socket_path.display()))?;
    let broker_uid = peer_uid(&stream)?;
    if broker_uid != 0 {
        bail!("broker peer is uid {broker_uid}, expected root");
    }

    receive_report_socket(&stream, Path::new(UHID_DEVICE))
}

fn receive_report_socket(stream: &UnixStream, uhid_device: &Path) -> Result<File> {
    use nix::sys::socket::{SockType, getsockopt, sockopt};

    let fd = recv_fd(stream)?;
    // SAFETY: recv_fd returns a freshly received, owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let socket_type = match getsockopt(&file, sockopt::SockType) {
        Ok(socket_type) => socket_type,
        Err(nix::errno::Errno::ENOTSOCK) => {
            use nix::sys::stat::{SFlag, fstat, stat};

            if let (Ok(received), Ok(expected)) = (fstat(&file), stat(uhid_device))
                && received.st_mode & libc::S_IFMT == SFlag::S_IFCHR.bits()
                && received.st_rdev == expected.st_rdev
            {
                return Err(LegacyBroker.into());
            }
            bail!("broker did not send a report socket");
        }
        Err(error) => return Err(error).context("checking broker report socket type"),
    };
    if socket_type != SockType::SeqPacket {
        bail!("broker sent an unexpected socket type");
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
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

    #[test]
    fn receives_a_sequenced_packet_socket() {
        let (broker, client) = UnixStream::pair().unwrap();
        let (report_socket, _peer) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        send_fd(&broker, report_socket.as_raw_fd()).unwrap();
        receive_report_socket(&client, Path::new(UHID_DEVICE)).unwrap();
    }

    #[test]
    fn identifies_a_legacy_device_descriptor() {
        let (broker, client) = UnixStream::pair().unwrap();
        let device = File::open("/dev/null").unwrap();
        send_fd(&broker, device.as_raw_fd()).unwrap();
        let error = receive_report_socket(&client, Path::new("/dev/null")).unwrap_err();
        assert!(error.is::<LegacyBroker>());
    }

    #[test]
    fn unrelated_device_is_not_reported_as_a_legacy_broker() {
        let (broker, client) = UnixStream::pair().unwrap();
        let device = File::open("/dev/null").unwrap();
        send_fd(&broker, device.as_raw_fd()).unwrap();
        let error = receive_report_socket(&client, Path::new("/dev/zero")).unwrap_err();
        assert!(!error.is::<LegacyBroker>());
    }
}
