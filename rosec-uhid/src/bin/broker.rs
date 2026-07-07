//! `rosec-uhid-broker` — privileged, socket-activated helper that creates a
//! FIDO uhid device per requesting user and passes its fd back.
//!
//! It runs as root only long enough to open `/dev/uhid`, materialise a device
//! whose descriptor is hard-coded to the FIDO usage page, chown the resulting
//! hidraw node to the caller, and hand the device fd over `SCM_RIGHTS`. It
//! speaks no CTAP and keeps no state; the caller's daemon owns the device
//! lifetime thereafter (closing the fd destroys it).
//!
//! Invoked via systemd socket activation: the listening socket arrives on
//! fd 3 (`LISTEN_FDS`). One device is granted per uid.

use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use anyhow::{Context, Result};
use rosec_uhid::broker::{self, Grant};
use tracing::{error, info, warn};

const UHID_PATH: &str = "/dev/uhid";
const SYSTEMD_LISTEN_FD: i32 = 3;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let listener = take_listener().context("acquiring the broker socket")?;
    info!("rosec-uhid-broker ready");

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

/// Serve one request: identify the caller, enforce one-device-per-uid,
/// create the device, chown its hidraw node to the caller, pass the fd.
fn handle(stream: &UnixStream, granted: &mut Vec<Grant>) -> Result<()> {
    let uid = broker::peer_uid(stream)?;

    let grant = match broker::admit(granted, uid) {
        Ok(g) => g,
        Err(reason) => {
            warn!(uid, "refusing request: {reason}");
            return Ok(());
        }
    };

    let device = broker::create_device(Path::new(UHID_PATH))
        .with_context(|| format!("creating uhid device for uid {uid}"))?;

    // Give the kernel a moment to enumerate the hidraw node, then chown it to
    // the caller so only they can open it (not the seat-active user).
    match broker::chown_hidraw_for(uid) {
        Ok(node) => info!(uid, node = %node.display(), "granted virtual authenticator"),
        Err(e) => {
            // The device still works via the fd; the node ownership is the
            // multi-user hardening. Surface loudly but don't fail the grant.
            warn!(
                uid,
                "could not chown hidraw node: {e:#} (multi-user isolation degraded)"
            );
        }
    }

    broker::send_fd(stream, device.as_raw_fd()).context("passing device fd")?;
    granted.push(grant);
    // `device` drops here — but the peer now holds a dup'd fd via SCM_RIGHTS,
    // so the device stays alive as long as the peer keeps it.
    Ok(())
}
