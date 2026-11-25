//! Receive a FIDO report socket from the privileged broker.

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::broker::peer_uid;

/// The kernel UHID device opened by the privileged broker.
pub const UHID_DEVICE: &str = "/dev/uhid";

/// Connect to the broker, authenticate its uid and receive a report socket.
pub fn connect_and_receive(socket_path: &Path) -> Result<File> {
    let stream = UnixStream::connect(socket_path)
        .with_context(|| format!("connecting to broker at {}", socket_path.display()))?;
    let broker_uid = peer_uid(&stream)?;
    if broker_uid != 0 {
        bail!("broker peer is uid {broker_uid}, expected root");
    }

    receive_report_socket(&stream)
}

fn receive_report_socket(stream: &UnixStream) -> Result<File> {
    use nix::sys::socket::{SockType, getsockopt, sockopt};

    let fd = recv_fd(stream)?;
    // SAFETY: recv_fd returns a freshly received, owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let socket_type = getsockopt(&file, sockopt::SockType)
        .context("broker did not send a report socket; update the system broker")?;
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
        receive_report_socket(&client).unwrap();
    }

    #[test]
    fn rejects_a_device_descriptor() {
        let (broker, client) = UnixStream::pair().unwrap();
        let device = File::open("/dev/null").unwrap();
        send_fd(&broker, device.as_raw_fd()).unwrap();
        assert!(receive_report_socket(&client).is_err());
    }
}
