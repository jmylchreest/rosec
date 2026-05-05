//! `rosec enable` / `rosec disable` — manage D-Bus activation + systemd unit files.
//!
//! Template files live alongside this module in `templates/` and are embedded
//! at compile time via [`include_str!`].  Templates containing `@@ROSECD@@`
//! have that placeholder replaced with the resolved absolute path to `rosecd`.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

const TEMPLATE_SERVICE: &str = include_str!("templates/rosecd.service");
const TEMPLATE_SOCKET: &str = include_str!("templates/rosecd.socket");
const TEMPLATE_DBUS_SECRETS: &str = include_str!("templates/org.freedesktop.secrets.service");
const TEMPLATE_DBUS_KEYRING_MASK: &str = include_str!("templates/org.gnome.keyring.service");
const TEMPLATE_PORTAL: &str = include_str!("templates/rosec.portal");
const TEMPLATE_PORTAL_DBUS: &str =
    include_str!("templates/org.freedesktop.impl.portal.desktop.rosec.service");

/// Placeholder in templates replaced with the resolved `rosecd` binary path.
const ROSECD_PLACEHOLDER: &str = "@@ROSECD@@";

const DBUS_SECRETS_SERVICE: &str = "org.freedesktop.secrets.service";
const DBUS_KEYRING_SERVICE: &str = "org.gnome.keyring.service";
const DBUS_PORTAL_SERVICE: &str = "org.freedesktop.impl.portal.desktop.rosec.service";
const PORTAL_FILE: &str = "rosec.portal";
const SYSTEMD_SERVICE_UNIT: &str = "rosecd.service";
const SYSTEMD_SOCKET_UNIT: &str = "rosecd.socket";

/// Known Secret Service providers that may already own the bus name.
const KNOWN_PROVIDERS: &[(&str, &str)] = &[
    (
        "gnome-keyring",
        "/usr/share/dbus-1/services/org.freedesktop.secrets.service",
    ),
    (
        "gnome-keyring",
        "/usr/share/dbus-1/services/org.gnome.keyring.service",
    ),
    (
        "kwallet/ksecretd",
        "/usr/share/dbus-1/services/org.kde.secretservicecompat.service",
    ),
    (
        "keepassxc",
        "/usr/share/dbus-1/services/org.keepassxc.KeePassXC.BrowserServer.service",
    ),
];

/// Render a template by replacing `@@ROSECD@@` with the binary path.
fn render(template: &str, rosecd: &Path) -> String {
    template.replace(ROSECD_PLACEHOLDER, &rosecd.display().to_string())
}

/// Return `~/.local/share/dbus-1/services/`.
fn user_dbus_services_dir() -> Result<PathBuf> {
    let data_home = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
            PathBuf::from(home).join(".local/share")
        });
    Ok(data_home.join("dbus-1/services"))
}

/// Return `~/.local/share/xdg-desktop-portal/portals/`.
fn user_portals_dir() -> Result<PathBuf> {
    let data_home = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
            PathBuf::from(home).join(".local/share")
        });
    Ok(data_home.join("xdg-desktop-portal/portals"))
}

/// Return `~/.config/systemd/user/`.
fn user_systemd_dir() -> Result<PathBuf> {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
            PathBuf::from(home).join(".config")
        });
    Ok(config_home.join("systemd/user"))
}

/// Resolve the absolute path to `rosecd`.
///
/// Strategy:
///   1. Sibling of the current executable (same directory as `rosec`).
///   2. Fall back to `$PATH` lookup via `which rosecd`.
///   3. Error if neither works.
fn resolve_rosecd() -> Result<PathBuf> {
    // Try sibling of current executable.
    if let Ok(self_exe) = std::env::current_exe() {
        let candidate = self_exe
            .canonicalize()
            .unwrap_or(self_exe)
            .parent()
            .map(|dir| dir.join("rosecd"));
        if let Some(p) = candidate
            && p.is_file()
        {
            return Ok(p);
        }
    }

    // Fall back to $PATH.
    let output = std::process::Command::new("which").arg("rosecd").output();
    if let Ok(out) = output
        && out.status.success()
    {
        let path_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !path_str.is_empty() {
            let p = PathBuf::from(&path_str);
            if p.is_file() {
                return Ok(p);
            }
        }
    }

    bail!(
        "could not locate rosecd binary.\n\
         Ensure rosecd is installed and either:\n\
         - in the same directory as rosec, or\n\
         - on your $PATH"
    )
}

/// Detect which Secret Service providers already have system-wide D-Bus
/// activation files installed.
fn detect_existing_providers() -> Vec<(&'static str, &'static str)> {
    KNOWN_PROVIDERS
        .iter()
        .filter(|(_, path)| Path::new(path).exists())
        .copied()
        .collect()
}

/// Write a file, creating parent directories as needed. Returns `Ok(true)` if
/// written, `Ok(false)` if the file already has identical contents (skip).
fn install_file(path: &Path, contents: &str) -> Result<bool> {
    if let Ok(existing) = std::fs::read_to_string(path)
        && existing == contents
    {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("failed to create {}: {e}", parent.display()))?;
    }
    std::fs::write(path, contents)
        .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", path.display()))?;
    Ok(true)
}

/// Remove a file if it exists. Returns whether a file was actually removed.
fn remove_file_if_exists(path: &Path) -> Result<bool> {
    if path.exists() {
        std::fs::remove_file(path)
            .map_err(|e| anyhow::anyhow!("failed to remove {}: {e}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Run `systemctl --user <args>`, printing warnings on failure but never
/// aborting — systemd may not be available (e.g. WSL, containers).
fn run_systemctl(extra_args: &[&str]) {
    let mut args = vec!["--user"];
    args.extend_from_slice(extra_args);
    let display_cmd = format!("systemctl {}", args.join(" "));

    let status = std::process::Command::new("systemctl").args(&args).status();
    match status {
        Ok(s) if s.success() => println!("{display_cmd} ... ok"),
        Ok(s) => {
            eprintln!(
                "warning: {display_cmd} exited with {}",
                s.code().map_or("signal".to_string(), |c| c.to_string())
            );
        }
        Err(e) => {
            eprintln!("warning: could not run systemctl: {e}");
        }
    }
}

/// XDG autostart `.desktop` files that gnome-keyring ships.
/// We create user-local overrides with `Hidden=true` to prevent the desktop
/// session from launching them.
const GNOME_KEYRING_AUTOSTART_DESKTOPS: &[&str] =
    &["gnome-keyring-secrets.desktop", "gnome-keyring-ssh.desktop"];

/// System-wide XDG autostart directory.
const XDG_AUTOSTART_SYSTEM: &str = "/etc/xdg/autostart";

/// Return `~/.config/autostart/`.
fn user_autostart_dir() -> Result<PathBuf> {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
            PathBuf::from(home).join(".config")
        });
    Ok(config_home.join("autostart"))
}

/// Create user-local `~/.config/autostart/<name>.desktop` with `Hidden=true`
/// for each gnome-keyring autostart entry that exists system-wide.
fn mask_gnome_keyring_autostart() -> Result<()> {
    let autostart_dir = user_autostart_dir()?;
    for desktop in GNOME_KEYRING_AUTOSTART_DESKTOPS {
        let system_file = Path::new(XDG_AUTOSTART_SYSTEM).join(desktop);
        if !system_file.exists() {
            continue;
        }
        let user_file = autostart_dir.join(desktop);
        let contents = "[Desktop Entry]\nHidden=true\n";
        if install_file(&user_file, contents)? {
            println!("installed {} (masks autostart)", user_file.display());
        } else {
            println!("unchanged {}", user_file.display());
        }
    }
    Ok(())
}

/// Remove user-local autostart overrides that rosec created.
fn unmask_gnome_keyring_autostart() -> Result<()> {
    let autostart_dir = user_autostart_dir()?;
    for desktop in GNOME_KEYRING_AUTOSTART_DESKTOPS {
        let user_file = autostart_dir.join(desktop);
        if !user_file.exists() {
            continue;
        }
        let contents = std::fs::read_to_string(&user_file).unwrap_or_default();
        if contents.contains("Hidden=true") {
            std::fs::remove_file(&user_file)
                .map_err(|e| anyhow::anyhow!("failed to remove {}: {e}", user_file.display()))?;
            println!("removed {} (autostart mask)", user_file.display());
        } else {
            eprintln!(
                "warning: {} does not look like a rosec autostart mask, leaving it alone",
                user_file.display()
            );
        }
    }
    Ok(())
}

/// The gnome-keyring systemd user socket unit to mask.
const GNOME_KEYRING_SOCKET_UNIT: &str = "gnome-keyring-daemon.socket";

/// Mask gnome-keyring's systemd user socket via `systemctl --user mask`.
fn mask_gnome_keyring_systemd_socket() -> Result<()> {
    run_systemctl(&["mask", GNOME_KEYRING_SOCKET_UNIT]);
    Ok(())
}

/// Unmask gnome-keyring's systemd user socket via `systemctl --user unmask`.
fn unmask_gnome_keyring_systemd_socket() -> Result<()> {
    run_systemctl(&["unmask", GNOME_KEYRING_SOCKET_UNIT]);
    Ok(())
}

/// `rosec enable [flags]`
pub fn cmd_enable(args: crate::cli::EnableArgs) -> Result<()> {
    let enable_systemd = !args.no_systemd;
    let mask = args.mask;
    let force = args.force;

    let rosecd = resolve_rosecd()?;
    println!("using rosecd: {}", rosecd.display());

    let dbus_dir = user_dbus_services_dir()?;
    let portals_dir = user_portals_dir()?;
    let systemd_dir = user_systemd_dir()?;
    let secrets_path = dbus_dir.join(DBUS_SECRETS_SERVICE);
    let keyring_path = dbus_dir.join(DBUS_KEYRING_SERVICE);
    let portal_dbus_path = dbus_dir.join(DBUS_PORTAL_SERVICE);
    let portal_path = portals_dir.join(PORTAL_FILE);
    let service_path = systemd_dir.join(SYSTEMD_SERVICE_UNIT);
    let socket_path = systemd_dir.join(SYSTEMD_SOCKET_UNIT);

    if secrets_path.exists() && !force {
        let existing = std::fs::read_to_string(&secrets_path).unwrap_or_default();
        if existing.contains("rosecd") {
            println!("rosec is already enabled ({})", secrets_path.display());
            println!("run `rosec enable --force` to overwrite");
            return Ok(());
        }
        bail!(
            "{} already exists but points to another service.\n\
             Use `rosec enable --force` to overwrite it.",
            secrets_path.display()
        );
    }

    let existing = detect_existing_providers();
    if !existing.is_empty() {
        println!("Detected existing Secret Service providers:");
        for (name, path) in &existing {
            println!("  {name:<20} {path}");
        }
        println!();
        let has_gnome_keyring = existing.iter().any(|(n, _)| *n == "gnome-keyring");
        if has_gnome_keyring && !mask {
            println!(
                "gnome-keyring detected. Pass --mask to suppress it via D-Bus override,\n\
                 XDG autostart masking, and systemd socket masking."
            );
        } else if has_gnome_keyring && mask {
            println!("gnome-keyring will be masked (D-Bus, autostart, systemd socket).");
        }
        println!();
    }

    let contents = render(TEMPLATE_DBUS_SECRETS, &rosecd);
    if install_file(&secrets_path, &contents)? {
        println!("installed {}", secrets_path.display());
    } else {
        println!("unchanged {}", secrets_path.display());
    }

    if mask {
        let has_gnome_keyring = existing.iter().any(|(n, _)| *n == "gnome-keyring");
        if has_gnome_keyring || force {
            if install_file(&keyring_path, TEMPLATE_DBUS_KEYRING_MASK)? {
                println!(
                    "installed {} (masks gnome-keyring D-Bus)",
                    keyring_path.display()
                );
            } else {
                println!("unchanged {}", keyring_path.display());
            }
        }
    }

    if mask {
        mask_gnome_keyring_autostart()?;
    }

    if mask {
        mask_gnome_keyring_systemd_socket()?;
    }

    let portal_dbus_contents = render(TEMPLATE_PORTAL_DBUS, &rosecd);
    if install_file(&portal_dbus_path, &portal_dbus_contents)? {
        println!("installed {}", portal_dbus_path.display());
    } else {
        println!("unchanged {}", portal_dbus_path.display());
    }

    if install_file(&portal_path, TEMPLATE_PORTAL)? {
        println!("installed {}", portal_path.display());
    } else {
        println!("unchanged {}", portal_path.display());
    }

    if enable_systemd {
        let svc_contents = render(TEMPLATE_SERVICE, &rosecd);
        if install_file(&service_path, &svc_contents)? {
            println!("installed {}", service_path.display());
        } else {
            println!("unchanged {}", service_path.display());
        }

        if install_file(&socket_path, TEMPLATE_SOCKET)? {
            println!("installed {}", socket_path.display());
        } else {
            println!("unchanged {}", socket_path.display());
        }

        run_systemctl(&["daemon-reload"]);
        run_systemctl(&["enable", "--now", "rosecd.service"]);
    }

    println!();
    println!("rosec is now enabled as the Secret Service provider.");
    if mask {
        println!();
        println!("gnome-keyring has been masked. You may need to log out and back in");
        println!("(or kill the running gnome-keyring-daemon) for masking to take full effect.");
    } else {
        println!();
        println!("Note: if another Secret Service provider (e.g. gnome-keyring) is running,");
        println!("you may need to stop it or pass --mask to suppress it.");
    }
    Ok(())
}

/// `rosec disable [flags]`
pub fn cmd_disable(args: crate::cli::DisableArgs) -> Result<()> {
    let disable_systemd = !args.no_systemd;

    let dbus_dir = user_dbus_services_dir()?;
    let portals_dir = user_portals_dir()?;
    let systemd_dir = user_systemd_dir()?;
    let secrets_path = dbus_dir.join(DBUS_SECRETS_SERVICE);
    let keyring_path = dbus_dir.join(DBUS_KEYRING_SERVICE);
    let portal_dbus_path = dbus_dir.join(DBUS_PORTAL_SERVICE);
    let portal_path = portals_dir.join(PORTAL_FILE);
    let service_path = systemd_dir.join(SYSTEMD_SERVICE_UNIT);
    let socket_path = systemd_dir.join(SYSTEMD_SOCKET_UNIT);

    let mut removed_any = false;

    if disable_systemd {
        run_systemctl(&["disable", "--now", "rosecd.service"]);
        run_systemctl(&["disable", "--now", "rosecd.socket"]);
    }

    if remove_file_if_exists(&secrets_path)? {
        println!("removed {}", secrets_path.display());
        removed_any = true;
    }

    if remove_file_if_exists(&portal_dbus_path)? {
        println!("removed {}", portal_dbus_path.display());
        removed_any = true;
    }

    if keyring_path.exists() {
        let contents = std::fs::read_to_string(&keyring_path).unwrap_or_default();
        if contents.contains("/bin/false") {
            std::fs::remove_file(&keyring_path)
                .map_err(|e| anyhow::anyhow!("failed to remove {}: {e}", keyring_path.display()))?;
            println!(
                "removed {} (gnome-keyring D-Bus mask)",
                keyring_path.display()
            );
            removed_any = true;
        } else {
            eprintln!(
                "warning: {} does not look like a rosec mask file, leaving it alone",
                keyring_path.display()
            );
        }
    }

    unmask_gnome_keyring_autostart()?;

    unmask_gnome_keyring_systemd_socket()?;

    if remove_file_if_exists(&portal_path)? {
        println!("removed {}", portal_path.display());
        removed_any = true;
    }

    if disable_systemd {
        if remove_file_if_exists(&service_path)? {
            println!("removed {}", service_path.display());
            removed_any = true;
        }
        if remove_file_if_exists(&socket_path)? {
            println!("removed {}", socket_path.display());
            removed_any = true;
        }
        run_systemctl(&["daemon-reload"]);
    }

    if !removed_any {
        println!("rosec was not enabled (nothing to disable)");
    } else {
        println!();
        println!("rosec has been disabled as the Secret Service provider.");
        let existing = detect_existing_providers();
        let has_gnome_keyring = existing.iter().any(|(n, _)| *n == "gnome-keyring");
        if has_gnome_keyring {
            println!("gnome-keyring will resume handling Secret Service requests.");
        }
    }
    Ok(())
}
