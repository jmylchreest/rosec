//! Landlock ruleset for the rosec-prompt binary.
//!
//! Mode-aware: rosec-prompt runs in three distinct shapes (TTY, GUI,
//! `--screenshot-helper`) with very different filesystem and IPC needs.
//! Applying Landlock *after* mode selection lets each shape get the
//! tightest ruleset that still works.
//!
//! All modes share a small set of base paths (libs, ld.so cache, /proc/self).
//! GUI mode adds compositor sockets, GPU device nodes, font/icon data, and
//! the wl-copy/xclip exec paths. Screenshot-helper mode adds the D-Bus
//! session bus + read access to the portal output dir.
//!
//! Best-effort: older kernels degrade rather than fail. The prompt is the
//! user's only path to entering credentials, so failing it on Landlock
//! errors would be worse than running unconfined.

use rosec_core::sandbox::landlock::{self, ConnectPort, PathRule};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Tty,
    Gui,
    ScreenshotHelper,
}

/// Apply the rosec-prompt Landlock ruleset for the given mode.
pub fn restrict(mode: Mode) {
    let mut paths = base_paths();
    match mode {
        Mode::Tty => add_tty_paths(&mut paths),
        Mode::Gui => {
            add_tty_paths(&mut paths);
            add_gui_paths(&mut paths);
        }
        Mode::ScreenshotHelper => {
            add_screenshot_helper_paths(&mut paths);
        }
    }

    // No outbound TCP from the prompt — all I/O is local sockets / files.
    let ports: Vec<ConnectPort> = Vec::new();

    if let Err(e) = landlock::apply_paths_and_ports(&paths, &ports) {
        eprintln!("rosec-prompt: landlock apply failed (continuing): {e}");
    }
}

fn base_paths() -> Vec<PathRule> {
    vec![
        // Shared libraries: /lib + /lib64 + /usr/lib (covered via /usr in
        // GUI mode; explicit here for TTY mode).
        PathRule::ro("/usr/lib"),
        PathRule::ro("/lib"),
        PathRule::ro("/usr/lib64"),
        PathRule::ro("/lib64"),
        // ld.so config — covered via /etc in GUI mode but TTY mode
        // narrows /etc to specific files only.
        PathRule::ro("/etc/ld.so.cache"),
        PathRule::ro("/etc/ld.so.preload"),
        // Self-introspection: /proc/self/exe for current_exe()-based
        // re-spawn (screenshot helper), /proc/self/maps for malloc, etc.
        PathRule::ro("/proc/self"),
    ]
}

fn add_tty_paths(paths: &mut Vec<PathRule>) {
    // TTY mode reads the password from /dev/tty (rpassword opens it).
    paths.push(PathRule::rw("/dev/tty"));
    // /etc/{passwd,group} for libc user lookups some logging code uses.
    paths.push(PathRule::ro("/etc/passwd"));
    paths.push(PathRule::ro("/etc/group"));
}

fn add_gui_paths(paths: &mut Vec<PathRule>) {
    // Compositor sockets — both Wayland and X11 prefixes; Landlock only
    // gates path-based opens so allowing both is fine even when only one
    // is in use.
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        paths.push(PathRule::rw(xdg));
    }
    paths.push(PathRule::rw("/tmp/.X11-unix"));

    // /dev/null for subprocess stdio redirection (clipboard_write spawns
    // wl-copy/xclip with Stdio::null()).
    paths.push(PathRule::rw("/dev/null"));

    // GPU device nodes for the iced/wgpu render path.
    paths.push(PathRule::rw("/dev/dri"));
    paths.push(PathRule::ro("/sys/devices"));
    paths.push(PathRule::ro("/sys/dev"));
    paths.push(PathRule::ro("/sys/class/drm"));

    // The GUI stack reads a long tail of distro data: fonts, icons,
    // themes, mime, X11 (including xkb compose files in
    // /usr/share/X11/locale/), glib schemas, locale data. Rather than
    // play whack-a-mole with each new ENOENT (the xkbcommon "No Compose
    // file" error was the first one we hit), grant ro access to the
    // whole /usr tree — it's distro-managed read-only system data, no
    // user secrets there.
    paths.push(PathRule::ro("/usr"));

    // /etc holds fontconfig + locale aliases + ld.so.cache + xkb defaults.
    // Some files here are sensitive (/etc/shadow) but UNIX perms already
    // gate those for non-root processes. ro at /etc as a layer is fine.
    paths.push(PathRule::ro("/etc"));

    // Mesa / wgpu shader caches (writable).
    if let Some(home) = std::env::var_os("HOME") {
        let home = std::path::PathBuf::from(home);
        paths.push(PathRule::rw(home.join(".cache")));
        paths.push(PathRule::ro(home.join(".config")));
        paths.push(PathRule::ro(home.join(".local/share")));
    }

    // D-Bus session bus (portal access for the screenshot helper re-exec).
    if let Some(addr) = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok()
        && let Some(socket) = addr.strip_prefix("unix:path=")
    {
        paths.push(PathRule::rw(socket));
    }
}

fn add_screenshot_helper_paths(paths: &mut Vec<PathRule>) {
    // The screenshot helper uses the D-Bus session bus to call the
    // xdg-desktop-portal Screenshot interface, then reads the PNG from
    // wherever the portal wrote it (typically /run/user/<uid>/doc/...).
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        paths.push(PathRule::rw(xdg));
    }
    if let Some(addr) = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok()
        && let Some(socket) = addr.strip_prefix("unix:path=")
    {
        paths.push(PathRule::rw(socket));
    }
    // /tmp may be used by some portal implementations as fallback.
    paths.push(PathRule::rw("/tmp"));
}
