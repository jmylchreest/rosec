//! Verify the daemon before sending PAM credentials over D-Bus.

use anyhow::{Context as _, Result};

const DEFAULT_DAEMON_PATHS: &str = "/usr/bin/rosecd,@ORIGIN@/rosecd,@ORIGIN@/../../bin/rosecd";

fn daemon_executables(
    configured: Option<&str>,
    helper: &std::path::Path,
) -> Result<Vec<std::path::PathBuf>> {
    let mut paths = Vec::new();
    for entry in configured.unwrap_or(DEFAULT_DAEMON_PATHS).split(',') {
        let entry = entry.trim();
        let path = if let Some(mut relative) = entry.strip_prefix("@ORIGIN@/") {
            let mut directory = helper.parent().context("locate PAM helper directory")?;
            while let Some(rest) = relative.strip_prefix("../") {
                directory = directory
                    .parent()
                    .context("daemon path goes above filesystem root")?;
                relative = rest;
            }
            let relative = std::path::Path::new(relative);
            anyhow::ensure!(
                !relative.as_os_str().is_empty()
                    && relative
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_))),
                "invalid helper-relative PAM daemon path"
            );
            directory.join(relative)
        } else {
            entry.into()
        };
        anyhow::ensure!(
            path.is_absolute(),
            "ROSEC_PAM_DAEMON_PATH entries must be absolute or start with @ORIGIN@/"
        );
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn check_daemon_executable(executable: &std::path::Path, peer: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let installed = std::fs::metadata(executable).context("stat configured rosecd executable")?;
    anyhow::ensure!(
        executable.is_absolute()
            && installed.is_file()
            && installed.uid() == 0
            && installed.mode() & 0o022 == 0,
        "configured rosecd must be an absolute path to a root-owned executable"
    );
    let canonical = executable
        .canonicalize()
        .context("resolve configured rosecd executable")?;
    for entry in executable.ancestors().chain(canonical.ancestors()) {
        let metadata = std::fs::symlink_metadata(entry).context("stat rosecd installation path")?;
        // Root-owned entries in a root-owned sticky directory cannot be
        // replaced by the users who can add their own entries there.
        let trusted_mode = metadata.is_symlink()
            || metadata.mode() & 0o022 == 0
            || (metadata.is_dir() && metadata.mode() & 0o1000 != 0);
        anyhow::ensure!(
            metadata.uid() == 0 && trusted_mode,
            "configured rosecd must be under a trusted system installation"
        );
    }
    let running = std::fs::metadata(peer).context("stat D-Bus peer executable")?;
    anyhow::ensure!(
        (installed.dev(), installed.ino()) == (running.dev(), running.ino()),
        "D-Bus peer executable differs from the installed rosecd"
    );
    Ok(())
}

pub(super) async fn daemon_proxy(conn: zbus::Connection) -> Result<zbus::Proxy<'static>> {
    let bus = zbus::fdo::DBusProxy::new(&conn).await?;
    let owner = bus
        .get_name_owner(zbus::names::BusName::try_from("org.freedesktop.secrets")?)
        .await
        .context("resolve the Secret Service owner")?;
    let destination = zbus::names::BusName::Unique(owner.into_inner());
    let uid = bus.get_connection_unix_user(destination.clone()).await?;
    anyhow::ensure!(
        uid == unsafe { libc::getuid() },
        "rosecd is running under a different uid"
    );
    let pid = bus
        .get_connection_unix_process_id(destination.clone())
        .await?;
    let helper = std::env::current_exe().context("locate installed PAM helper")?;
    let candidates = daemon_executables(option_env!("ROSEC_PAM_DAEMON_PATH"), &helper)?;
    let peer = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
    anyhow::ensure!(
        candidates
            .iter()
            .any(|path| check_daemon_executable(path, &peer).is_ok()),
        "D-Bus peer does not match a trusted rosecd executable"
    );
    drop(bus);
    // Bind every subsequent request, including credential transfer, to the
    // verified unique connection. A new well-known name owner cannot take over.
    zbus::Proxy::new_owned(conn, destination, "/org/rosec/Daemon", "org.rosec.Daemon")
        .await
        .context("create verified rosec daemon proxy")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locates_daemon_in_package_layouts() {
        for (helper, daemon) in [
            ("/usr/lib/rosec/rosec-pam-unlock", "/usr/bin/rosecd"),
            ("/usr/local/bin/rosec-pam-unlock", "/usr/local/bin/rosecd"),
            (
                "/nix/store/example-rosec/libexec/rosec/rosec-pam-unlock",
                "/nix/store/example-rosec/bin/rosecd",
            ),
        ] {
            assert!(
                daemon_executables(None, std::path::Path::new(helper))
                    .unwrap()
                    .contains(&std::path::PathBuf::from(daemon))
            );
        }
    }

    #[test]
    fn accepts_configured_path_lists_and_defaults() {
        use std::path::{Path, PathBuf};
        let helper = Path::new("/nix/store/example-rosec/libexec/rosec/rosec-pam-unlock");
        assert_eq!(
            daemon_executables(None, helper).unwrap(),
            daemon_executables(Some(DEFAULT_DAEMON_PATHS), helper).unwrap()
        );
        assert_eq!(
            daemon_executables(Some("@ORIGIN@/../../bin/rosecd"), helper).unwrap(),
            [PathBuf::from("/nix/store/example-rosec/bin/rosecd")]
        );
        assert_eq!(
            daemon_executables(Some("/opt/bin/rosecd, /usr/bin/rosecd"), helper).unwrap(),
            [
                PathBuf::from("/opt/bin/rosecd"),
                PathBuf::from("/usr/bin/rosecd")
            ]
        );
        assert!(daemon_executables(Some("/usr/bin/rosecd,rosecd"), helper).is_err());
    }

    #[test]
    fn only_matches_the_configured_executable_inode() {
        let installed = std::path::Path::new("/usr/bin/false");
        assert!(check_daemon_executable(installed, installed).is_ok());
        assert!(check_daemon_executable(installed, std::path::Path::new("/usr/bin/true")).is_err());
    }
}
