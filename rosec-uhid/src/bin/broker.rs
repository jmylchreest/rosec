//! Privileged, socket-activated FIDO report relay. The broker retains the
//! UHID device and gives each admitted uid a connected report socket.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use anyhow::{Context, Result};
use rosec_uhid::broker::{self, Grant};
use rosec_uhid::client::UHID_DEVICE as UHID_PATH;
use tracing::{debug, error, info, warn};

const SYSTEMD_LISTEN_FD: i32 = 3;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let listener = take_listener().context("acquiring the broker socket")?;
    info!("rosec-uhid ready");

    let mut granted: Vec<Grant> = Vec::new();
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(e) = handle(&stream, &mut granted) {
                    warn!("request failed: {e:#}");
                }
            }
            Err(e) => error!("accept failed: {e}"),
        }
    }
    Ok(())
}

/// Take the socket-activated listener (fd 3) if present, else bind the
/// default path (useful for a manual run).
fn take_listener() -> Result<UnixListener> {
    let listen_fds = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse::<i32>().ok());
    if listen_fds.is_some_and(|n| n >= 1) {
        // SAFETY: systemd guarantees fd 3 is a listening socket when
        // LISTEN_FDS >= 1 and this is the activated process.
        let listener = unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) };
        return Ok(listener);
    }
    let path = Path::new(rosec_uhid::BROKER_SOCKET_PATH);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let _ = std::fs::remove_file(path);
    UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))
}

/// Serve one request: identify the caller, enforce one-live-device-per-uid,
/// create the device, chown its hidraw node to the caller, start its report relay.
fn handle(stream: &UnixStream, granted: &mut Vec<Grant>) -> Result<()> {
    let uid = broker::peer_uid(stream)?;

    // Re-admit a uid whose device died (daemon restart); else it stays locked
    // out until the broker itself restarts.
    broker::evict_dead_grants(granted);

    let grant = match broker::admit(granted, uid) {
        Ok(g) => g,
        Err(reason) => {
            warn!(uid, "refusing request: {reason}");
            return Ok(());
        }
    };

    let device = broker::create_device(Path::new(UHID_PATH), &grant.uniq)
        .with_context(|| format!("creating uhid device for uid {uid}"))?;

    // Fail closed: if the node can't be secured, drop the device (fd closes on
    // return, destroying it) rather than hand out an unprotected or wrong one.
    let node = match broker::chown_hidraw_for(uid, &grant.uniq) {
        Ok(node) => node,
        Err(e) => {
            warn!(uid, "refusing grant, could not secure hidraw node: {e:#}");
            return Ok(());
        }
    };
    debug!(uid, node = %node.display(), "granted virtual authenticator");

    let (relay_end, client_end) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::SeqPacket,
        None,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC | nix::sys::socket::SockFlag::SOCK_NONBLOCK,
    )
    .context("creating report socket pair")?;
    std::thread::Builder::new()
        .name("rosec-uhid-relay".into())
        .spawn(move || {
            if let Err(e) = relay(device, relay_end.into()) {
                debug!(uid, "report relay stopped: {e:#}");
            }
        })
        .context("starting report relay")?;
    broker::send_fd(stream, client_end.as_raw_fd()).context("passing report socket")?;
    granted.push(grant);
    Ok(())
}

fn relay(mut device: File, mut channel: File) -> Result<()> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use rosec_uhid::uhid;
    use std::os::fd::AsFd;

    use rosec_uhid::ctaphid::REPORT_SIZE;
    let mut frame = [0u8; REPORT_SIZE + 1];
    let mut event = [0u8; uhid::EVENT_BUF_SIZE];
    let disconnected = PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL;
    loop {
        let (from_client, from_device) = {
            let mut fds = [
                PollFd::new(channel.as_fd(), PollFlags::POLLIN),
                PollFd::new(device.as_fd(), PollFlags::POLLIN),
            ];
            match poll(&mut fds, PollTimeout::NONE) {
                Err(nix::errno::Errno::EINTR) => continue,
                result => result?,
            };
            (
                fds[0].revents().unwrap_or(PollFlags::empty()),
                fds[1].revents().unwrap_or(PollFlags::empty()),
            )
        };
        if from_client.intersects(disconnected) || from_device.intersects(disconnected) {
            return Ok(());
        }

        if from_client.contains(PollFlags::POLLIN) {
            let size = channel.read(&mut frame)?;
            if size == 0 {
                return Ok(());
            }
            anyhow::ensure!(size == REPORT_SIZE, "invalid FIDO report length");
            device.write_all(&uhid::input2_event(&frame[..size]))?;
        }
        if from_device.contains(PollFlags::POLLIN) {
            let size = device.read(&mut event)?;
            if size == 0 {
                return Ok(());
            }
            if matches!(
                uhid::parse_event(&event[..size]),
                Some(uhid::Event::Output(_))
            ) {
                channel.write_all(&event[..size])?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
    use rosec_uhid::{ctaphid::REPORT_SIZE, uhid};

    fn packet_pair() -> (File, File) {
        let (a, b) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        for socket in [&a, &b] {
            nix::sys::socket::setsockopt(
                socket,
                nix::sys::socket::sockopt::ReceiveTimeout,
                &nix::sys::time::TimeVal::new(2, 0),
            )
            .unwrap();
        }
        (a.into(), b.into())
    }

    #[test]
    fn concurrent_relays_keep_reports_and_lifetimes_separate() {
        let (mut client_a, channel_a) = packet_pair();
        let (mut client_b, channel_b) = packet_pair();
        let (mut kernel_a, device_a) = packet_pair();
        let (mut kernel_b, device_b) = packet_pair();
        let a = std::thread::spawn(|| relay(device_a, channel_a));
        let b = std::thread::spawn(|| relay(device_b, channel_b));

        let report_a = [0x11; REPORT_SIZE];
        let report_b = [0x22; REPORT_SIZE];
        client_a.write_all(&report_a).unwrap();
        client_b.write_all(&report_b).unwrap();
        let mut received = [0; REPORT_SIZE + 6];
        kernel_a.read_exact(&mut received).unwrap();
        assert_eq!(received.as_slice(), uhid::input2_event(&report_a));
        kernel_b.read_exact(&mut received).unwrap();
        assert_eq!(received.as_slice(), uhid::input2_event(&report_b));

        drop(client_a);
        a.join().unwrap().unwrap();
        assert_eq!(kernel_a.read(&mut received).unwrap(), 0);
        client_b.write_all(&report_b).unwrap();
        kernel_b.read_exact(&mut received).unwrap();
        assert_eq!(received.as_slice(), uhid::input2_event(&report_b));
        drop(client_b);
        b.join().unwrap().unwrap();
    }
}
