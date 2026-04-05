use std::collections::HashMap;
use std::io::{self, BufRead, Read};
use std::path::PathBuf;

use clap::Parser;
use sha2::{Digest, Sha256};

use anyhow::{Result, bail};
use zbus::Connection;
use zeroize::Zeroizing;
use zvariant::{OwnedObjectPath, OwnedValue};

use rosec_core::WasmPreference;
use rosec_core::config::Config;
use rosec_core::config_edit;

mod cli;
mod enable;

use cli::*;

/// D-Bus wire type for `org.rosec.Daemon.ProviderList` entries.
///
/// Fields: `(id, name, kind, locked, cached, offline_cache, last_cache_write_epoch, last_sync_epoch, capabilities)`.
type ProviderEntry = (
    String,
    String,
    String,
    bool,
    bool,
    bool,
    u64,
    u64,
    Vec<String>,
);

#[tokio::main]
async fn main() -> Result<()> {
    // Reset SIGPIPE to default so piping output to `head` etc. exits cleanly
    // instead of panicking with "broken pipe".
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Provider { action } => cmd_provider(action).await,
        Commands::Config { action } => cmd_config(action),
        Commands::Status => cmd_status().await,
        Commands::Sync => cmd_sync().await,
        Commands::Search(args) => cmd_search(args).await,
        Commands::Item { action } => cmd_item(action).await,
        Commands::Get(args) => cmd_get(args).await,
        Commands::Inspect(args) => cmd_inspect(args).await,
        Commands::Lock => cmd_lock().await,
        Commands::Unlock => cmd_unlock().await,
        Commands::Enable(args) => enable::cmd_enable(args),
        Commands::Disable(args) => enable::cmd_disable(args),
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Command implementations
// ───────────────────────────────────────────────────────────────────────────

fn cmd_provider_kinds() {
    println!("Available provider kinds:\n");
    println!("  local");
    println!("    A local encrypted vault file on disk.");
    println!("    Options: --id <id>, --path <path>, --collection <name>");
    println!();
    for kind in config_edit::KNOWN_KINDS {
        // "local" is already printed above with its custom description.
        if *kind == "local" {
            continue;
        }
        let required = config_edit::required_options_for_kind(kind);
        let optional = config_edit::optional_options_for_kind(kind);
        println!("  {kind}");
        if !required.is_empty() {
            println!("    Required:");
            for (key, desc) in required {
                println!("      {key:<20}  {desc}");
            }
        }
        if !optional.is_empty() {
            println!("    Optional:");
            for (key, desc) in optional {
                println!("      {key:<20}  {desc}");
            }
        }
        println!();
    }

    // List dynamically discovered WASM plugin kinds.
    let registry = rosec_wasm::discovery::scan_plugins(
        WasmPreference::default(),
        rosec_core::WasmVerify::default(),
    );
    for kind in registry.kinds() {
        let plugin = registry
            .get(kind)
            .expect("kind from registry.kinds() must exist");
        println!("  {kind}");
        println!("    {}", plugin.manifest.description);
        if !plugin.manifest.required_options.is_empty() {
            println!("    Required:");
            for opt in &plugin.manifest.required_options {
                println!("      {:<20}  {}", opt.key, opt.description);
            }
        }
        if !plugin.manifest.optional_options.is_empty() {
            println!("    Optional:");
            for opt in &plugin.manifest.optional_options {
                println!("      {:<20}  {}", opt.key, opt.description);
            }
        }
        println!();
    }
}

async fn conn() -> Result<Connection> {
    // 1. Explicit override via ROSEC_SOCKET env var.
    if let Ok(socket) = std::env::var("ROSEC_SOCKET") {
        let addr = format!("unix:path={socket}");
        return Ok(zbus::connection::Builder::address(&*addr)?.build().await?);
    }

    // 2. Try the session bus.
    if let Ok(c) = Connection::session().await {
        return Ok(c);
    }

    // 3. Fall back to the private bus socket at $XDG_RUNTIME_DIR/rosec/bus.
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let socket = std::path::Path::new(&runtime_dir).join("rosec").join("bus");
        if socket.exists() {
            let addr = format!("unix:path={}", socket.display());
            return Ok(zbus::connection::Builder::address(&*addr)?.build().await?);
        }
    }

    // Nothing worked.
    Err(anyhow::anyhow!(
        "cannot connect to rosecd: no session bus, ROSEC_SOCKET not set, \
         and $XDG_RUNTIME_DIR/rosec/bus not found"
    ))
}

/// Poll rosecd's `ProviderList` until `id` appears (max 3 s, 200 ms intervals).
///
/// Returns `Some(proxy)` if the daemon is running and the provider appeared,
/// `None` if the daemon isn't running or the provider didn't appear in time.
async fn wait_for_daemon_reload(id: &str) -> Option<zbus::Proxy<'static>> {
    let conn = conn().await.ok()?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await
    .ok()?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if let Ok(entries) = proxy
            .call::<_, _, Vec<ProviderEntry>>("ProviderList", &())
            .await
            && entries.iter().any(|(bid, ..)| bid == id)
        {
            return Some(proxy);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Generate a default password label: `user@hostname`.
fn default_password_label() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".into());

    let host = {
        let mut buf = [0u8; 256];
        // SAFETY: gethostname writes into a fixed-size buffer we own.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        if rc == 0 {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..len]).into_owned()
        } else {
            "localhost".into()
        }
    };

    format!("{user}@{host}")
}

/// Resolve the config file path from `--config <path>` flag or XDG default.
fn config_path() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == "--config" || args[i] == "-c" {
            return PathBuf::from(&args[i + 1]);
        }
        if let Some(p) = args[i].strip_prefix("--config=") {
            return PathBuf::from(p);
        }
    }
    default_config_path()
}

fn default_config_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("rosec").join("config.toml")
}

fn load_config() -> Config {
    let path = config_path();
    if !path.exists() {
        return Config::default();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Prompt helpers (local config-value collection only — not credentials)
// ---------------------------------------------------------------------------
//
// These functions are used by `cmd_provider_add` to collect non-secret
// configuration values (email address, region, base_url, etc.) that go into
// config.toml.  Credential prompting (passwords, tokens) is handled entirely
// inside `rosecd` via `UnlockWithTty` / `AuthProviderWithTty` — the TTY fd is
// passed via D-Bus fd-passing so credentials never appear in any D-Bus message.

// ---------------------------------------------------------------------------
// Lazy-unlock: detect "locked::<provider_id>" D-Bus errors and prompt
// ---------------------------------------------------------------------------

/// Extract a `"locked::<provider_id>"` provider ID from a `zbus::Error`, if present.
///
/// The daemon returns `org.freedesktop.DBus.Error.Failed("locked::<id>")` when
/// a provider needs interactive authentication.  This helper parses that sentinel
/// and returns `Some(provider_id)` or `None`.
fn extract_locked_provider(err: &zbus::Error) -> Option<String> {
    if let zbus::Error::MethodError(_, Some(detail), _) = err {
        let msg = detail.as_str();
        if let Some(id) = msg.strip_prefix("locked::") {
            return Some(id.to_string());
        }
    }
    None
}

/// Attempt to interactively unlock a provider after receiving a `"locked::<id>"`
/// D-Bus error.
///
/// This function implements the Secret Service spec Prompt flow:
///   1. Call `Service.Unlock([collection])` — the daemon allocates a Prompt object.
///   2. Subscribe to `Prompt.Completed` on that path.
///   3. Call `Prompt.Prompt("")` to tell the daemon to show the credential dialog.
///   4. Await the `Completed` signal; race against Ctrl+C.
///   5. On Ctrl+C: call `org.rosec.Daemon.CancelPrompt(prompt_path)` then exit.
///
/// Credentials never cross D-Bus — the daemon handles everything internally.
///
/// Returns `Ok(true)` if the provider was successfully unlocked (caller should
/// retry the original operation).  Returns `Ok(false)` if the error was not a
/// locked sentinel (caller should propagate the original error).
async fn try_lazy_unlock(conn: &Connection, err: &zbus::Error) -> Result<bool> {
    // Only trigger for the locked sentinel — not for generic errors.
    if extract_locked_provider(err).is_none() {
        return Ok(false);
    }

    trigger_unlock(conn).await?;
    Ok(true)
}

/// Trigger the spec-compliant Unlock → Prompt → Completed flow.
///
/// Calls `Service.Unlock([default_collection])`.  If a prompt is required,
/// subscribes to `Prompt.Completed`, fires `Prompt.Prompt("")`, and awaits the
/// signal.  On success, triggers a cache refresh so subsequent operations see
/// the newly-unlocked items.
///
/// Credentials never cross D-Bus — the daemon handles everything internally.
async fn trigger_unlock(conn: &Connection) -> Result<()> {
    use futures_util::StreamExt as _;

    // Build a Secret Service proxy for Unlock().
    let service_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    // Call Unlock([default_collection]).  Returns (unlocked_list, prompt_path).
    // prompt_path == "/" means everything was already unlocked (auto-unlock providers).
    let collection_path =
        OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default".to_string())?;
    let (_, prompt_path): (Vec<OwnedObjectPath>, OwnedObjectPath) = service_proxy
        .call("Unlock", &(vec![collection_path],))
        .await?;
    let prompt_path = prompt_path.to_string();

    if prompt_path == "/" {
        // Already unlocked (auto-unlock providers recovered silently).
        return Ok(());
    }

    // Build a proxy on the prompt object so we can subscribe to Completed.
    let prompt_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        prompt_path.as_str(),
        "org.freedesktop.Secret.Prompt",
    )
    .await?;

    // Subscribe to the Completed signal *before* calling Prompt() to avoid
    // a race where Completed fires before we start listening.
    let mut completed_stream = prompt_proxy.receive_signal("Completed").await?;

    // Tell the daemon to display the credential dialog.
    let _: () = prompt_proxy.call("Prompt", &("",)).await?;

    // Await Completed or Ctrl+C.
    let dismissed = tokio::select! {
        msg = completed_stream.next() => {
            match msg {
                None => {
                    // Stream ended without a signal — treat as cancelled.
                    true
                }
                Some(message) => {
                    // Completed signal body: (dismissed: bool, result: Variant)
                    // We only need the first field.
                    let body = message.body();
                    match body.deserialize::<(bool, zvariant::OwnedValue)>() {
                        Ok((d, _)) => d,
                        Err(_) => true, // parse error → treat as dismissed
                    }
                }
            }
        }
        _ = tokio::signal::ctrl_c() => {
            // User pressed Ctrl+C — cancel the prompt subprocess and exit.
            let daemon_proxy = zbus::Proxy::new(
                conn,
                "org.freedesktop.secrets",
                "/org/rosec/Daemon",
                "org.rosec.Daemon",
            )
            .await?;
            let cancel_path = OwnedObjectPath::try_from(prompt_path.clone())
                .unwrap_or_else(|_| {
                    // "/" is always a valid D-Bus object path.
                    OwnedObjectPath::try_from("/".to_string())
                        .unwrap_or_else(|_| unreachable!("root path is always valid"))
                });
            let _: Result<bool, _> = daemon_proxy.call("CancelPrompt", &(&cancel_path,)).await;
            bail!("cancelled by user");
        }
    };

    if dismissed {
        bail!("unlock cancelled or failed");
    }

    // Unlock succeeded.  Trigger a cache sync so the retry finds items.
    // Use the daemon proxy for SyncProvider; need to look up which provider unlocked.
    // Use "all" shorthand: call Refresh which rebuilds the cache from in-memory state.
    let daemon_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;
    let _: Result<u32, _> = daemon_proxy.call("Refresh", &()).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Secure field collection (used locally for config-value prompts in `add`)
// ---------------------------------------------------------------------------

/// Open `/dev/tty` and return it as a `zvariant::OwnedFd` for D-Bus fd-passing.
///
/// The returned `OwnedFd` can be passed directly to `UnlockWithTty` /
/// `AuthProviderWithTty`.  `dbus-monitor` sees only the fd number, never the
/// terminal contents.
fn open_tty_owned_fd() -> Result<zvariant::OwnedFd> {
    use std::os::unix::io::{FromRawFd as _, IntoRawFd as _};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| anyhow::anyhow!("cannot open /dev/tty: {e}"))?;
    let raw = file.into_raw_fd();
    // SAFETY: raw is a freshly-opened, valid, owned fd.
    let std_owned: std::os::fd::OwnedFd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    Ok(zvariant::OwnedFd::from(std_owned))
}

/// Write a password to the write end of a pipe and return the read end as an
/// `OwnedFd` suitable for D-Bus fd-passing.
///
/// The write end is closed after the password is written so the daemon sees
/// EOF when it reads.  The password bytes are never visible in any D-Bus
/// message payload — only the fd number travels over the bus.
fn password_to_pipe_fd(password: &[u8]) -> Result<zvariant::OwnedFd> {
    use std::io::Write as _;
    use std::os::unix::io::FromRawFd as _;

    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe() writes two valid fds into the array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("pipe() failed: {}", std::io::Error::last_os_error());
    }
    let read_fd = fds[0];
    let write_fd = fds[1];

    {
        // SAFETY: write_fd is a valid fd from pipe() above.
        let mut write_file: std::fs::File = unsafe { std::fs::File::from_raw_fd(write_fd) };
        write_file.write_all(password)?;
        // write_file dropped here → write end closed → daemon sees EOF on read
    }

    // SAFETY: read_fd is a valid fd from pipe() above.
    let std_owned: std::os::fd::OwnedFd = unsafe { std::os::fd::OwnedFd::from_raw_fd(read_fd) };
    Ok(zvariant::OwnedFd::from(std_owned))
}

/// Read one line from `fd` with terminal echo disabled.
///
/// Flushes any stale input (via `TCSAFLUSH`), saves the current `termios`,
/// clears `ECHO`/`ECHONL`, reads a line, then restores the original settings.
/// The returned string has the trailing newline stripped.
///
/// A `TermiosGuard` ensures the original terminal settings are restored even
/// if the read is interrupted, the thread panics, or the function exits early
/// via `?`.  Additionally, the original termios is registered in a
/// process-global so that a SIGINT handler can restore it if the process is
/// killed while echo is disabled.
///
/// The read buffer is `Zeroizing<Vec<u8>>` so the raw bytes are scrubbed on
/// drop — no plain copy of the secret ever lingers on the heap.
#[cfg(unix)]
fn read_hidden(fd: std::os::unix::io::RawFd) -> io::Result<Zeroizing<String>> {
    use std::os::unix::io::FromRawFd as _;

    /// RAII guard that restores the original `termios` on drop.
    struct TermiosGuard {
        fd: std::os::unix::io::RawFd,
        orig: libc::termios,
    }

    impl Drop for TermiosGuard {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig);
            }
            // Clear the global signal-handler backup since we've restored.
            tty_signal::clear();
        }
    }

    // Save current termios and install the RAII guard immediately.
    // SAFETY: fd is valid (we just opened it) and term is properly initialised.
    let guard = unsafe {
        let mut term = std::mem::MaybeUninit::<libc::termios>::uninit();
        if libc::tcgetattr(fd, term.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        TermiosGuard {
            fd,
            orig: term.assume_init(),
        }
    };

    // Register the original termios in a process-global so the SIGINT handler
    // can restore it if the process is killed while echo is off.
    tty_signal::install(fd, &guard.orig);

    let mut noecho = guard.orig;
    // Disable echo and the newline-echo-when-echo-off flag.
    noecho.c_lflag &= !(libc::ECHO as libc::tcflag_t);
    noecho.c_lflag &= !(libc::ECHONL as libc::tcflag_t);

    // TCSAFLUSH: apply new settings AND discard any unread input in the
    // kernel tty buffer (e.g. stale keypresses from between prompts).
    unsafe {
        if libc::tcsetattr(fd, libc::TCSAFLUSH, &noecho) != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // Read one line into a Zeroizing buffer so the raw bytes are scrubbed on
    // drop regardless of what happens next.
    let mut buf = Zeroizing::new(Vec::<u8>::new());
    let result = {
        // SAFETY: we borrow the fd for reading; ManuallyDrop prevents double-close
        // since the original `tty: File` in the caller still owns the fd.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let file = std::mem::ManuallyDrop::new(file);
        let mut reader = io::BufReader::new(&*file);
        reader.read_until(b'\n', &mut buf)
    };

    // The guard restores termios on drop (runs when this function returns),
    // but we also restore explicitly here so the newline write below sees
    // the original settings.
    drop(guard);

    // Print a newline since ECHO is off (the user's Enter was not echoed).
    let _ = unsafe { libc::write(fd, b"\n".as_ptr().cast(), 1) };

    result?;

    // Strip trailing CR/LF and convert to a Zeroizing<String>.  The Vec is
    // zeroized on drop; the String is wrapped in Zeroizing immediately.
    while buf.last() == Some(&b'\n') || buf.last() == Some(&b'\r') {
        buf.pop();
    }
    let s = std::str::from_utf8(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .to_string();
    Ok(Zeroizing::new(s))
}

/// Process-global SIGINT handler that restores terminal settings.
///
/// When `read_hidden` disables echo, it registers the original termios here.
/// If SIGINT arrives before the guard drops, the handler restores the terminal
/// then re-raises SIGINT with the default disposition so the process exits
/// with the correct signal status.
#[cfg(unix)]
mod tty_signal {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicI32, Ordering};

    /// The fd on which echo was disabled, or -1 if none.
    static TTY_FD: AtomicI32 = AtomicI32::new(-1);

    /// Original termios to restore.  Protected by a Mutex, but the signal
    /// handler only reads it via a `try_lock` (non-blocking) to avoid
    /// deadlock.  Worst-case the handler can't acquire the lock and skips
    /// the restore — the process is dying anyway.
    static ORIG_TERMIOS: Mutex<Option<libc::termios>> = Mutex::new(None);

    /// One-shot flag for installing the signal handler.
    static INSTALLED: std::sync::Once = std::sync::Once::new();

    /// Register the original termios and install the SIGINT handler (once).
    pub(super) fn install(fd: std::os::unix::io::RawFd, orig: &libc::termios) {
        TTY_FD.store(fd, Ordering::Release);
        if let Ok(mut guard) = ORIG_TERMIOS.lock() {
            *guard = Some(*orig);
        }
        INSTALLED.call_once(|| unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = sigint_handler as *const () as libc::sighandler_t;
            sa.sa_flags = libc::SA_RESETHAND; // one-shot: auto-restores default
            libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        });
    }

    /// Clear the saved state (called by `TermiosGuard::drop` after normal restore).
    pub(super) fn clear() {
        TTY_FD.store(-1, Ordering::Release);
        if let Ok(mut guard) = ORIG_TERMIOS.lock() {
            *guard = None;
        }
    }

    /// Async-signal-safe(ish) SIGINT handler.
    ///
    /// Restores the original termios using `tcsetattr` (async-signal-safe per
    /// POSIX) then re-raises SIGINT with the default handler.  The `SA_RESETHAND`
    /// flag ensures this handler runs at most once.
    extern "C" fn sigint_handler(_sig: libc::c_int) {
        let fd = TTY_FD.load(Ordering::Acquire);
        if fd >= 0 {
            // try_lock avoids deadlock if the signal arrived while the main
            // thread holds the mutex.  If it fails, we skip — the process is
            // about to die.
            if let Ok(guard) = ORIG_TERMIOS.try_lock()
                && let Some(ref orig) = *guard
            {
                unsafe {
                    libc::tcsetattr(fd, libc::TCSANOW, orig);
                    // Write a newline so the shell prompt starts on a clean line.
                    libc::write(fd, b"\n".as_ptr().cast(), 1);
                }
            }
        }
        // Re-raise SIGINT with default handler (SA_RESETHAND already cleared us).
        unsafe {
            libc::raise(libc::SIGINT);
        }
    }
}

/// Collect a single field value from the terminal.
///
/// Opens `/dev/tty` once per call so that both the prompt write and the input
/// read use the same file descriptor.  For hidden fields (`password`/`secret`)
/// echo is suppressed via `read_hidden`, which calls `tcsetattr` on that same
/// fd.  For visible fields (`text`) the prompt and read also go through the
/// same fd, avoiding any stdin/tty split-brain.
///
/// All blocking I/O runs on a dedicated `spawn_blocking` thread so the tokio
/// executor is not stalled.  Returns `Zeroizing<String>` so the value is
/// scrubbed on drop.
async fn prompt_field(label: &str, placeholder: &str, kind: &str) -> Result<Zeroizing<String>> {
    let prompt_str = if placeholder.is_empty() {
        format!("{label}: ")
    } else {
        format!("{label} [{placeholder}]: ")
    };

    let kind = kind.to_string();
    let value = tokio::task::spawn_blocking(move || -> Result<Zeroizing<String>> {
        use std::io::Write as _;
        use std::os::unix::io::AsRawFd as _;

        // Open /dev/tty once for this prompt — all I/O goes through this fd.
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")?;
        let fd = tty.as_raw_fd();

        match kind.as_str() {
            "password" | "secret" => {
                // Write the prompt to our tty fd, then suppress echo and read
                // from the same fd.  We implement the echo toggle directly so
                // that prompt write and input read share the same file object
                // (and therefore the same kernel file-description / termios).
                let mut tty_write = &tty;
                write!(tty_write, "{prompt_str}")?;
                tty_write.flush()?;

                // Disable echo via tcsetattr on this fd.
                Ok(read_hidden(fd)?)
            }
            _ => {
                let mut writer = &tty;
                write!(writer, "{prompt_str}")?;
                writer.flush()?;
                let mut line = String::new();
                io::BufReader::new(&tty).read_line(&mut line)?;
                Ok(Zeroizing::new(
                    line.trim_end_matches('\n')
                        .trim_end_matches('\r')
                        .to_string(),
                ))
            }
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("prompt task panicked: {e}"))??;

    Ok(value)
}

// ---------------------------------------------------------------------------
// provider / providers subcommand tree
// ---------------------------------------------------------------------------

async fn cmd_provider(action: Option<ProviderCommands>) -> Result<()> {
    let action = action.unwrap_or(ProviderCommands::List);
    match action {
        ProviderCommands::List => cmd_provider_list().await,
        ProviderCommands::Kinds => {
            cmd_provider_kinds();
            Ok(())
        }
        ProviderCommands::Auth(args) => cmd_provider_auth(&args).await,
        ProviderCommands::Add(args) => cmd_provider_add(args).await,
        ProviderCommands::Remove(args) => cmd_provider_remove(&args.id).await,
        ProviderCommands::Enable(args) => cmd_provider_set_enabled(&args.id, true).await,
        ProviderCommands::Disable(args) => cmd_provider_set_enabled(&args.id, false).await,
        ProviderCommands::Attach(args) => cmd_provider_attach(args).await,
        ProviderCommands::Detach(args) => cmd_provider_detach(&args.id).await,
        ProviderCommands::AddPassword(args) => cmd_provider_add_password(args).await,
        ProviderCommands::RemovePassword(args) => cmd_provider_remove_password(&args).await,
        ProviderCommands::ListPasswords(args) => cmd_provider_list_passwords(&args.id).await,
        ProviderCommands::ChangePassword(args) => cmd_provider_change_password(&args.id).await,
    }
}

/// `rosec provider list` — show all configured providers with lock state.
async fn cmd_provider_list() -> Result<()> {
    // Load config to detect disabled providers.
    let cfg = load_config();
    if cfg.provider.is_empty() {
        println!("No providers configured. Run `rosec provider add <kind>` to add one.");
        return Ok(());
    }

    // Collect disabled entries from config (they won't appear in D-Bus).
    let disabled: Vec<&rosec_core::config::ProviderEntry> =
        cfg.provider.iter().filter(|p| !p.enabled).collect();

    // Try D-Bus first for live state.
    if let Ok(conn) = conn().await
        && let Ok(proxy) = zbus::Proxy::new(
            &conn,
            "org.freedesktop.secrets",
            "/org/rosec/Daemon",
            "org.rosec.Daemon",
        )
        .await
        && let Ok(entries) = proxy
            .call::<_, _, Vec<ProviderEntry>>("ProviderList", &())
            .await
    {
        if entries.is_empty() && disabled.is_empty() {
            println!("No providers configured. Run `rosec provider add <kind>` to add one.");
            return Ok(());
        }

        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Build row data with sync strings for column width measurement.
        struct RowData {
            id: String,
            name: String,
            kind: String,
            state: String,
            caps: String,
            sync: String,
        }

        let mut rows: Vec<RowData> = entries
            .iter()
            .map(
                |(id, name, kind, locked, cached, _, _, last_sync, capabilities)| {
                    let state = match (*locked, *cached) {
                        (true, _) => "locked".to_string(),
                        (false, true) => "unlocked (cached)".to_string(),
                        (false, false) => "unlocked".to_string(),
                    };
                    let sync = if *locked {
                        String::new()
                    } else {
                        format_relative_time(*last_sync, now_epoch)
                    };
                    let caps = capability_codes(capabilities);
                    RowData {
                        id: id.clone(),
                        name: name.clone(),
                        kind: kind.clone(),
                        state,
                        caps,
                        sync,
                    }
                },
            )
            .collect();

        for entry in &disabled {
            rows.push(RowData {
                id: entry.id.clone(),
                name: entry.id.clone(),
                kind: entry.kind.clone(),
                state: "disabled".to_string(),
                caps: String::new(),
                sync: String::new(),
            });
        }

        let id_w = rows.iter().map(|r| r.id.len()).max().unwrap_or(2).max(2);
        let name_w = rows.iter().map(|r| r.name.len()).max().unwrap_or(4).max(4);
        let kind_w = rows.iter().map(|r| r.kind.len()).max().unwrap_or(4).max(4);
        let caps_w = rows
            .iter()
            .map(|r| r.caps.len())
            .max()
            .unwrap_or(0)
            .max("CAPS".len());
        let state_w = rows.iter().map(|r| r.state.len()).max().unwrap_or(5).max(5);
        let sync_w = rows.iter().map(|r| r.sync.len()).max().unwrap_or(0).max(
            if rows.iter().any(|r| !r.sync.is_empty()) {
                "LAST SYNC".len()
            } else {
                0
            },
        );

        let has_sync_col = sync_w > 0;

        // Priority: ID > NAME > KIND > CAPS > STATE > SYNC (fit to terminal).
        let mut cols = vec![
            ColSpec {
                natural: id_w,
                min: 2,
                allocated: 0,
            },
            ColSpec {
                natural: name_w,
                min: 4,
                allocated: 0,
            },
            ColSpec {
                natural: kind_w,
                min: 4,
                allocated: 0,
            },
            ColSpec {
                natural: caps_w,
                min: "CAPS".len(),
                allocated: 0,
            },
            ColSpec {
                natural: state_w,
                min: 5,
                allocated: 0,
            },
        ];
        if has_sync_col {
            cols.push(ColSpec {
                natural: sync_w,
                min: "SYNC".len(),
                allocated: 0,
            });
        }

        fit_columns(&mut cols, 2, terminal_width());
        let id_w = cols[0].allocated;
        let name_w = cols[1].allocated;
        let kind_w = cols[2].allocated;
        let caps_w = cols[3].allocated;
        let state_w = cols[4].allocated;
        let sync_w = if has_sync_col { cols[5].allocated } else { 0 };

        if has_sync_col {
            println!(
                "{:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  {:<state_w$}  LAST SYNC",
                "ID", "NAME", "KIND", "CAPS", "STATE",
            );
        } else {
            println!(
                "{:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  STATE",
                "ID", "NAME", "KIND", "CAPS",
            );
        }
        let sep_w = id_w
            + 2
            + name_w
            + 2
            + kind_w
            + 2
            + caps_w
            + 2
            + state_w
            + if has_sync_col { 2 + sync_w } else { 0 };
        println!("{}", "\u{2500}".repeat(sep_w));

        for row in &rows {
            if has_sync_col {
                println!(
                    "{:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  {:<state_w$}  {}",
                    trunc(&row.id, id_w),
                    trunc(&row.name, name_w),
                    trunc(&row.kind, kind_w),
                    trunc(&row.caps, caps_w),
                    trunc(&row.state, state_w),
                    trunc(&row.sync, sync_w),
                );
            } else {
                println!(
                    "{:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  {}",
                    trunc(&row.id, id_w),
                    trunc(&row.name, name_w),
                    trunc(&row.kind, kind_w),
                    trunc(&row.caps, caps_w),
                    trunc(&row.state, state_w),
                );
            }
        }
        println!(
            "\nCAPS: S=Sync W=Write s=Ssh K=KeyWrapping P=PasswordChange C=Cache N=Notifications"
        );
        return Ok(());
    }

    // Fallback: read config directly (daemon not running).
    let nat_id = cfg
        .provider
        .iter()
        .map(|p| p.id.len())
        .max()
        .unwrap_or(2)
        .max(2);
    let nat_kind = cfg
        .provider
        .iter()
        .map(|p| p.kind.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let state_w = "(daemon not running)".len().max("STATE".len());

    let mut cols = [
        ColSpec {
            natural: nat_id,
            min: 2,
            allocated: 0,
        },
        ColSpec {
            natural: nat_kind,
            min: 4,
            allocated: 0,
        },
        ColSpec {
            natural: state_w,
            min: "STATE".len(),
            allocated: 0,
        },
    ];
    fit_columns(&mut cols, 2, terminal_width());
    let id_w = cols[0].allocated;
    let kind_w = cols[1].allocated;

    println!("{:<id_w$}  {:<kind_w$}  STATE", "ID", "KIND");
    let sep_w = id_w + 2 + kind_w + 2 + state_w;
    println!("{}", "\u{2500}".repeat(sep_w));
    for entry in &cfg.provider {
        let state = if entry.enabled {
            "(daemon not running)"
        } else {
            "disabled"
        };
        println!(
            "{:<id_w$}  {:<kind_w$}  {state}",
            trunc(&entry.id, id_w),
            trunc(&entry.kind, kind_w),
        );
    }
    Ok(())
}

/// `rosec provider auth <id>` — interactively authenticate a provider.
///
/// Opens `/dev/tty` and passes the fd to `rosecd` via D-Bus fd-passing.
/// All credential prompting happens inside the daemon — credentials never
/// appear in any D-Bus message payload.
async fn cmd_provider_auth(args: &ProviderAuthArgs) -> Result<()> {
    let provider_id = args.id.as_str();
    let force = args.force;

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let tty_fd = open_tty_owned_fd()?;
    let _: () = proxy
        .call("AuthProviderWithTty", &(provider_id, tty_fd, force))
        .await?;

    println!("Provider '{provider_id}' authenticated.");
    Ok(())
}

/// `rosec provider add <kind> [--id <id>] [key=value ...]`
async fn cmd_provider_add(args: ProviderAddArgs) -> Result<()> {
    // Scan for discovered plugin kinds so we can validate and prompt correctly.
    let registry = rosec_wasm::discovery::scan_plugins(
        WasmPreference::default(),
        rosec_core::WasmVerify::default(),
    );

    let all_kinds: Vec<String> = {
        let mut v: Vec<String> = config_edit::KNOWN_KINDS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        for kind in registry.kinds() {
            if !v.iter().any(|k| k == kind) {
                v.push(kind.to_string());
            }
        }
        v
    };
    let all_kinds_display = all_kinds.join(", ");

    let kind = &args.kind;

    let is_builtin = config_edit::KNOWN_KINDS.contains(&kind.as_str());
    let is_discovered = registry.contains_kind(kind);

    if !is_builtin && !is_discovered {
        bail!("unknown provider kind '{kind}'. Known kinds: {all_kinds_display}");
    }

    // Extract flags and key=value pairs from clap-parsed args.
    let custom_id: Option<String> = args.id;
    let mut custom_path: Option<String> = args.path;
    let mut collection: Option<String> = args.collection;
    let mut options: Vec<(String, String)> = Vec::new();
    for opt in &args.options {
        if let Some((k, v)) = opt.split_once('=') {
            match k {
                "path" => custom_path = Some(v.to_string()),
                "collection" => collection = Some(v.to_string()),
                _ => options.push((k.to_string(), v.to_string())),
            }
        }
    }

    // Snapshot the keys already supplied on the command line.
    let supplied: std::collections::HashSet<String> =
        options.iter().map(|(k, _)| k.clone()).collect();

    // Collect required options first — we need them to auto-generate the ID.
    // For built-in kinds, use config_edit; for discovered kinds, use the registry.
    if is_discovered {
        if let Some(req_opts) = rosec_wasm::discovery::required_options(&registry, kind) {
            for opt in &req_opts {
                if !supplied.contains(&opt.key) {
                    let v = prompt_field(&opt.description, "", &opt.kind).await?;
                    let s = v.as_str().to_string();
                    if !s.is_empty() {
                        options.push((opt.key.clone(), s));
                    }
                }
            }
        }
    } else {
        for (key, description) in config_edit::required_options_for_kind(kind) {
            if !supplied.contains(*key) {
                let field_kind = if key.contains("secret") || key.contains("password") {
                    "secret"
                } else {
                    "text"
                };
                let v = prompt_field(description, "", field_kind).await?;
                let s = v.as_str().to_string();
                if !s.is_empty() {
                    options.push((key.to_string(), s));
                }
            }
        }
    }

    // Determine the provider ID: explicit --id wins; otherwise derive from credentials.
    let id = match custom_id {
        Some(ref id) => id.clone(),
        None => derive_provider_id(kind, &options, &registry),
    };

    // Prompt for optional options not already supplied.
    let supplied_after_required: std::collections::HashSet<String> =
        options.iter().map(|(k, _)| k.clone()).collect();
    if is_discovered {
        if let Some(opt_opts) = rosec_wasm::discovery::optional_options(&registry, kind) {
            for opt in &opt_opts {
                if !supplied_after_required.contains(&opt.key) {
                    let v = prompt_field(
                        &format!("{} (optional, Enter to skip)", opt.description),
                        "",
                        &opt.kind,
                    )
                    .await?;
                    let s = v.as_str().to_string();
                    if !s.is_empty() {
                        options.push((opt.key.clone(), s));
                    }
                }
            }
        }
    } else {
        for (key, description) in config_edit::optional_options_for_kind(kind) {
            if !supplied_after_required.contains(*key) {
                let v = prompt_field(
                    &format!("{description} (optional, Enter to skip)"),
                    "",
                    "text",
                )
                .await?;
                let s = v.as_str().to_string();
                if !s.is_empty() {
                    options.push((key.to_string(), s));
                }
            }
        }
    }

    // Inject --path and --collection into options if they were supplied as flags.
    if let Some(ref p) = custom_path {
        options.push(("path".to_string(), p.clone()));
    }
    if let Some(ref c) = collection {
        options.push(("collection".to_string(), c.clone()));
    }

    // For local vaults, ensure a path is present — derive one from the ID if
    // the user did not supply an explicit --path or path= argument.
    if kind == "local" && custom_path.is_none() {
        let path = default_vault_path(&id);
        options.push(("path".to_string(), path));
    }

    // Resolve the vault path for local providers so we can check for conflicts.
    if kind == "local" {
        let path_value = options
            .iter()
            .find(|(k, _)| k == "path")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let resolved = expand_tilde(path_value);
        if std::path::Path::new(&resolved).exists() {
            bail!(
                "a vault file already exists at {resolved}\n\
                 Use `rosec provider attach --path {resolved}` to attach an existing vault."
            );
        }
    }

    // Check for duplicate ID early (add_provider also checks, but this gives
    // a friendlier message before we touch the config file).
    let cfg_data = load_config();
    if cfg_data.provider.iter().any(|p| p.id == id) {
        bail!("provider '{id}' already exists. Use --id to choose a different name.");
    }

    let cfg = config_path();
    config_edit::add_provider(&cfg, &id, kind, &options)?;
    println!("Added provider '{id}' (kind: {kind}) to {}", cfg.display());

    // If rosecd is running, wait for it to hot-reload the new provider then
    // immediately kick off the auth flow so the user doesn't have to run
    // `rosec provider auth <id>` manually as a separate step.
    if let Some(proxy) = wait_for_daemon_reload(&id).await {
        println!("rosecd picked up the new provider — starting authentication.");
        let tty_fd = open_tty_owned_fd()?;
        let _: () = proxy
            .call("AuthProviderWithTty", &(id.as_str(), tty_fd, false))
            .await?;
        println!("Provider '{id}' authenticated.");
    } else {
        println!("rosecd will hot-reload the config automatically if it is running.");
        println!("Run `rosec provider auth {id}` to authenticate.");
    }

    Ok(())
}

/// Derive a short, stable provider ID from the credential that identifies the account.
///
/// Format: `{kind}-{first8hexchars of sha256(credential)}`
///
/// - `bitwarden-sm`: hashes the organization_id
/// - anything else: falls back to the kind string itself
fn derive_provider_id(
    kind: &str,
    options: &[(String, String)],
    registry: &rosec_wasm::PluginRegistry,
) -> String {
    // For built-in kinds, use hardcoded credential keys.
    // For discovered kinds, use the manifest's id_derivation_key.
    let discovered_key = rosec_wasm::discovery::id_derivation_key(registry, kind);

    let credential_key = match kind {
        "bitwarden-sm" => "organization_id",
        _ => match discovered_key.as_deref() {
            Some(k) => k,
            None => return kind.to_string(),
        },
    };

    let value = options
        .iter()
        .find(|(k, _)| k == credential_key)
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    if value.is_empty() {
        return kind.to_string();
    }

    let hash = Sha256::digest(value.as_bytes());
    // Use the first 4 bytes (8 hex chars) — low collision probability for personal use
    let short = format!(
        "{:08x}",
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
    );
    format!("{kind}-{short}")
}

/// `rosec provider remove <id>`
///
/// For external providers, removes the config entry.
/// For local vaults, also offers to delete the vault file from disk.
async fn cmd_provider_remove(id: &str) -> Result<()> {
    let cfg = config_path();

    // Check if this is a local vault with a path — if so, offer to delete the file.
    let cfg_data = load_config();
    let vault_path = cfg_data
        .provider
        .iter()
        .find(|p| p.id == *id && p.kind == "local")
        .and_then(|p| p.path.as_deref())
        .map(expand_tilde);

    config_edit::remove_provider(&cfg, id)?;
    println!("Removed provider '{id}' from {}", cfg.display());

    if let Some(ref path) = vault_path
        && std::path::Path::new(path).exists()
    {
        let confirm = prompt_field(
            &format!("Also delete the vault file at {path}? (yes/no)"),
            "no",
            "text",
        )
        .await?;
        if confirm.as_str() == "yes" {
            match std::fs::remove_file(path) {
                Ok(()) => println!("Deleted vault file: {path}"),
                Err(e) => eprintln!("warning: could not delete vault file {path}: {e}"),
            }
        } else {
            println!("Vault file kept at {path}.");
            println!("Use `rosec provider attach --path {path}` to re-attach later.");
        }
    }

    println!("rosecd will hot-reload the config automatically if it is running.");
    Ok(())
}

/// `rosec provider enable <id>` / `rosec provider disable <id>`
async fn cmd_provider_set_enabled(id: &str, enabled: bool) -> Result<()> {
    let cfg = config_path();
    config_edit::set_provider_enabled(&cfg, id, enabled)?;

    if enabled {
        println!("Provider '{id}' enabled.");
    } else {
        println!("Provider '{id}' disabled.");
    }
    println!("rosecd will hot-reload the config automatically if it is running.");
    Ok(())
}

/// `rosec provider attach --path <file> [--id <id>] [--collection <c>]`
///
/// Adds an existing vault file to the config without creating it.
async fn cmd_provider_attach(args: ProviderAttachArgs) -> Result<()> {
    let vault_path = args.path;
    let collection = args.collection;

    // Derive ID from filename if not specified.
    let id = match args.id {
        Some(id) => id,
        None => derive_vault_id_from_path(&vault_path),
    };

    let cfg = config_path();
    config_edit::add_local_provider(&cfg, &id, &vault_path, collection.as_deref())?;

    println!("Attached vault '{id}' ({vault_path}) to {}", cfg.display());
    println!("rosecd will hot-reload the config automatically if it is running.");
    println!("Run `rosec provider auth {id}` to authenticate.");
    Ok(())
}

/// `rosec provider detach <id>`
///
/// Removes the vault from the config file but leaves the vault file on disk.
async fn cmd_provider_detach(id: &str) -> Result<()> {
    let cfg = config_path();
    config_edit::remove_provider(&cfg, id)?;
    println!("Detached vault '{id}' from {}", cfg.display());
    println!(
        "The vault file was NOT deleted. Use `rosec provider remove` to also delete the file."
    );
    println!("rosecd will hot-reload the config automatically if it is running.");
    Ok(())
}

/// `rosec provider add-password <id> [--label <label>]`
///
/// Add a new unlock password to a vault. The vault must be unlocked (running in
/// rosecd).
async fn cmd_provider_add_password(args: ProviderAddPasswordArgs) -> Result<()> {
    let vault_id = args.id.as_str();

    // Default label: user@hostname
    let label = args.label.unwrap_or_else(default_password_label);

    // Prompt for the new password.
    let pw = prompt_field("New password", "", "password").await?;
    if pw.is_empty() {
        bail!("password cannot be empty");
    }
    let pw_confirm = prompt_field("Confirm password", "", "password").await?;
    if pw.as_str() != pw_confirm.as_str() {
        bail!("passwords do not match");
    }

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let entry_id: String = proxy
        .call("AddPassword", &(vault_id, pw.as_bytes().to_vec(), &label))
        .await?;

    println!("Added password entry {entry_id} (label: {label}) to vault '{vault_id}'.");
    Ok(())
}

/// `rosec provider list-passwords <vault-id>`
///
/// List the wrapping entries (unlock passwords) for a vault. The vault must be
/// unlocked. Shows the entry ID and label for each password.
async fn cmd_provider_list_passwords(vault_id: &str) -> Result<()> {
    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let entries: Vec<(String, String)> = proxy.call("ListPasswords", &(vault_id,)).await?;

    if entries.is_empty() {
        println!("No password entries found for vault '{vault_id}'.");
        return Ok(());
    }

    println!("Password entries for vault '{vault_id}':\n");
    println!("  {:<40} LABEL", "ENTRY ID");
    println!("  {:<40} -----", "--------");
    for (id, label) in &entries {
        let display_label = if label.is_empty() { "(none)" } else { label };
        println!("  {:<40} {}", id, display_label);
    }

    Ok(())
}

/// `rosec provider change-password <vault-id>`
///
/// Change the unlock password for a vault.  Prompts for the current password,
/// new password, and confirmation.  The wrapping entry matched by the old
/// password is atomically replaced with a new one for the new password.
async fn cmd_provider_change_password(vault_id: &str) -> Result<()> {
    let old_pw = prompt_field("Current password", "", "password").await?;
    if old_pw.is_empty() {
        bail!("current password cannot be empty");
    }

    let new_pw = prompt_field("New password", "", "password").await?;
    if new_pw.is_empty() {
        bail!("new password cannot be empty");
    }

    let confirm_pw = prompt_field("Confirm new password", "", "password").await?;
    if new_pw.as_str() != confirm_pw.as_str() {
        bail!("passwords do not match");
    }

    let old_fd = password_to_pipe_fd(old_pw.as_bytes())?;
    let new_fd = password_to_pipe_fd(new_pw.as_bytes())?;

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let _: () = proxy
        .call("ChangeProviderPassword", &(vault_id, old_fd, new_fd))
        .await?;

    println!("Password changed for vault '{vault_id}'.");
    Ok(())
}

/// `rosec provider remove-password <vault-id> <entry-id>`
///
/// Remove an unlock password from a vault. The vault must be unlocked and must
/// have at least 2 passwords.
async fn cmd_provider_remove_password(args: &ProviderRemovePasswordArgs) -> Result<()> {
    let vault_id = args.id.as_str();
    let entry_id = args.entry_id.as_str();

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    // First list passwords to show the user what they're removing.
    let entries: Vec<(String, String)> = proxy.call("ListPasswords", &(vault_id,)).await?;

    let target = entries
        .iter()
        .find(|(id, _)| id == entry_id)
        .ok_or_else(|| {
            anyhow::anyhow!("password entry '{entry_id}' not found in vault '{vault_id}'")
        })?;

    let label_display = if target.1.is_empty() {
        "(no label)".to_string()
    } else {
        target.1.clone()
    };

    println!("Removing password entry: {entry_id} {label_display}");

    let _: () = proxy.call("RemovePassword", &(vault_id, entry_id)).await?;

    println!("Removed password entry '{entry_id}' from vault '{vault_id}'.");
    Ok(())
}

/// Default vault file path: `$XDG_DATA_HOME/rosec/vaults/<id>.vault`.
fn default_vault_path(id: &str) -> String {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("rosec")
        .join("vaults")
        .join(format!("{id}.vault"))
        .to_string_lossy()
        .into_owned()
}

/// Derive a vault ID from a file path.
///
/// Takes the filename stem (e.g. `/mnt/shared/team.vault` → `team`).
fn derive_vault_id_from_path(path: &str) -> String {
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("vault")
        .to_string()
}

/// Expand `~` to `$HOME` in a path string.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return format!("{}/{rest}", home.to_string_lossy());
    }
    path.to_string()
}

// ---------------------------------------------------------------------------
// Top-level commands
// ---------------------------------------------------------------------------

async fn cmd_status() -> Result<()> {
    // ── Header ──────────────────────────────────────────────────────
    let ver = format!("{} ({})", env!("ROSEC_VERSION"), env!("ROSEC_GIT_SHA"));
    let cfg_path = config_path();
    let cfg_display = cfg_path
        .strip_prefix(
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default(),
        )
        .map(|rel| format!("~/{}", rel.display()))
        .unwrap_or_else(|_| cfg_path.display().to_string());

    let socket_display = if std::env::var_os("ROSEC_SOCKET").is_some() {
        "private socket"
    } else {
        "session bus"
    };

    println!("  {:<14}{ver}", "Daemon");
    println!("  {:<14}{cfg_display}", "Config");
    println!("  {:<14}{socket_display}", "Socket");
    println!();

    // ── Daemon connection ───────────────────────────────────────────
    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let (cache_size,): (u32,) = proxy.call("Status", &()).await?;

    // ── Provider table ──────────────────────────────────────────────
    let cfg = load_config();
    let disabled: Vec<&rosec_core::config::ProviderEntry> =
        cfg.provider.iter().filter(|p| !p.enabled).collect();
    let providers: Vec<ProviderEntry> = proxy.call("ProviderList", &()).await?;

    println!("Providers");

    if providers.is_empty() && disabled.is_empty() {
        println!("  (none configured)");
    } else {
        // Build state + sync strings for column width measurement.
        struct RowData {
            id: String,
            name: String,
            kind: String,
            caps: String,
            state: String,
            sync: String,
        }

        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut rows: Vec<RowData> = providers
            .iter()
            .map(
                |(
                    id,
                    name,
                    kind,
                    locked,
                    cached,
                    _offline_cache,
                    _last_cache_write,
                    last_sync,
                    capabilities,
                )| {
                    let state = match (*locked, *cached) {
                        (true, _) => "locked".to_string(),
                        (false, true) => "unlocked (cached)".to_string(),
                        (false, false) => "unlocked".to_string(),
                    };
                    let sync = if *locked {
                        String::new()
                    } else {
                        format_relative_time(*last_sync, now_epoch)
                    };
                    let caps = capability_codes(capabilities);
                    RowData {
                        id: id.clone(),
                        name: name.clone(),
                        kind: kind.clone(),
                        caps,
                        state,
                        sync,
                    }
                },
            )
            .collect();

        for entry in &disabled {
            rows.push(RowData {
                id: entry.id.clone(),
                name: entry.id.clone(),
                kind: entry.kind.clone(),
                caps: String::new(),
                state: "disabled".to_string(),
                sync: String::new(),
            });
        }

        let id_w = rows.iter().map(|r| r.id.len()).max().unwrap_or(2).max(2);
        let name_w = rows.iter().map(|r| r.name.len()).max().unwrap_or(4).max(4);
        let kind_w = rows.iter().map(|r| r.kind.len()).max().unwrap_or(4).max(4);
        let caps_w = rows
            .iter()
            .map(|r| r.caps.len())
            .max()
            .unwrap_or(0)
            .max("CAPS".len());
        let state_w = rows.iter().map(|r| r.state.len()).max().unwrap_or(5).max(5);
        let sync_w = rows.iter().map(|r| r.sync.len()).max().unwrap_or(0).max(
            if rows.iter().any(|r| !r.sync.is_empty()) {
                "LAST SYNC".len()
            } else {
                0
            },
        );

        let has_sync_col = sync_w > 0;

        // Priority ordering: ID > NAME > KIND > CAPS > STATE > SYNC
        let mut cols = vec![
            ColSpec {
                natural: id_w,
                min: 2,
                allocated: 0,
            },
            ColSpec {
                natural: name_w,
                min: 4,
                allocated: 0,
            },
            ColSpec {
                natural: kind_w,
                min: 4,
                allocated: 0,
            },
            ColSpec {
                natural: caps_w,
                min: "CAPS".len(),
                allocated: 0,
            },
            ColSpec {
                natural: state_w,
                min: 5,
                allocated: 0,
            },
        ];
        if has_sync_col {
            cols.push(ColSpec {
                natural: sync_w,
                min: "SYNC".len(),
                allocated: 0,
            });
        }

        fit_columns(&mut cols, 2, terminal_width().saturating_sub(2)); // 2-char indent
        let id_w = cols[0].allocated;
        let name_w = cols[1].allocated;
        let kind_w = cols[2].allocated;
        let caps_w = cols[3].allocated;
        let state_w = cols[4].allocated;
        let sync_w = if has_sync_col { cols[5].allocated } else { 0 };

        // Header
        if has_sync_col {
            println!(
                "  {:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  {:<state_w$}  LAST SYNC",
                "ID", "NAME", "KIND", "CAPS", "STATE",
            );
        } else {
            println!(
                "  {:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  STATE",
                "ID", "NAME", "KIND", "CAPS",
            );
        }
        let sep_w = id_w
            + 2
            + name_w
            + 2
            + kind_w
            + 2
            + caps_w
            + 2
            + state_w
            + if has_sync_col { 2 + sync_w } else { 0 };
        println!("  {}", "\u{2500}".repeat(sep_w));

        for row in &rows {
            if has_sync_col {
                println!(
                    "  {:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  {:<state_w$}  {}",
                    trunc(&row.id, id_w),
                    trunc(&row.name, name_w),
                    trunc(&row.kind, kind_w),
                    trunc(&row.caps, caps_w),
                    trunc(&row.state, state_w),
                    trunc(&row.sync, sync_w),
                );
            } else {
                println!(
                    "  {:<id_w$}  {:<name_w$}  {:<kind_w$}  {:<caps_w$}  {}",
                    trunc(&row.id, id_w),
                    trunc(&row.name, name_w),
                    trunc(&row.kind, kind_w),
                    trunc(&row.caps, caps_w),
                    trunc(&row.state, state_w),
                );
            }
        }
    }
    println!();

    // ── Daemon summary ──────────────────────────────────────────────
    println!("Daemon");
    println!("  {:<14}{cache_size} items", "Items");
    println!();

    // ── Components ──────────────────────────────────────────────────
    println!("Components");
    println!("  {:<22}{ver}", "rosec");

    for bin in &["rosecd", "rosec-prompt"] {
        let bin_ver = probe_binary_version(bin).unwrap_or_else(|| "not found".to_string());
        println!("  {:<22}{bin_ver}", bin);
    }

    let pam_unlock_ver = probe_binary_version("rosec-pam-unlock")
        .or_else(|| probe_binary_version_at("/usr/lib/rosec/rosec-pam-unlock"));
    println!(
        "  {:<22}{}",
        "rosec-pam-unlock",
        pam_unlock_ver.unwrap_or_else(|| "not found".to_string())
    );

    let pam_so = std::path::Path::new("/usr/lib/security/pam_rosec.so");
    println!(
        "  {:<22}{}",
        "pam_rosec.so",
        if pam_so.exists() {
            "installed"
        } else {
            "not found"
        }
    );

    Ok(())
}

/// Run `<binary> --version` and return the first line of output, or `None`.
fn probe_binary_version(name: &str) -> Option<String> {
    let output = std::process::Command::new(name)
        .arg("--version")
        .output()
        .ok()?;
    // Some binaries print to stdout, others to stderr.
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        String::from_utf8_lossy(&output.stdout).to_string()
    };
    let line = text.lines().next()?.trim().to_string();
    // Strip the binary name prefix to just show the version part.
    let ver = line
        .strip_prefix(name)
        .map(|s| s.trim().to_string())
        .unwrap_or(line);
    if ver.is_empty() { None } else { Some(ver) }
}

/// Run a binary at an absolute path with `--version`.
fn probe_binary_version_at(path: &str) -> Option<String> {
    if !std::path::Path::new(path).exists() {
        return None;
    }
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()?;
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        String::from_utf8_lossy(&output.stdout).to_string()
    };
    let line = text.lines().next()?.trim().to_string();
    let bin_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let ver = line
        .strip_prefix(bin_name)
        .map(|s| s.trim().to_string())
        .unwrap_or(line);
    if ver.is_empty() { None } else { Some(ver) }
}

async fn cmd_sync() -> Result<()> {
    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    // Fetch the list of providers so we know which ones to sync.
    let providers: Vec<ProviderEntry> = proxy.call("ProviderList", &()).await?;

    for (id, _name, _kind, _locked, _, _, _, _, capabilities) in &providers {
        if !capabilities.iter().any(|c| c == "Sync") {
            continue;
        }
        eprint!("Syncing '{id}'...");
        match proxy.call::<_, _, u32>("SyncProvider", &(id,)).await {
            Ok(count) => {
                println!(" {count} items");
            }
            Err(zbus::Error::MethodError(_, Some(detail), _))
                if detail.as_str().starts_with("locked::") =>
            {
                // Daemon says this provider needs credentials first.
                // Pass a TTY fd so the daemon can prompt in-process —
                // credentials never appear in any D-Bus message.
                let provider_id = detail.as_str().strip_prefix("locked::").unwrap_or("");
                eprintln!(" locked");
                let tty_fd = open_tty_owned_fd()?;
                let _: () = proxy
                    .call("AuthProviderWithTty", &(provider_id, tty_fd))
                    .await?;
                // Retry sync now that the provider is unlocked.
                eprint!("Syncing '{id}' (retrying)...");
                match proxy.call::<_, _, u32>("SyncProvider", &(id,)).await {
                    Ok(count) => println!(" {count} items"),
                    Err(e) => eprintln!(" failed: {e}"),
                }
            }
            Err(e) => eprintln!(" failed: {e}"),
        }
    }

    Ok(())
}

/// Ensure the daemon's cache is fresh by syncing providers in parallel.
///
/// Syncs unlocked providers that haven't synced in the last 60 seconds.
///
/// Uses per-provider `last_sync` from `ProviderList` to decide which providers
/// are stale.  If all providers are fresh, this is a single cheap D-Bus call
/// with no network I/O.
///
/// Locked providers are skipped — the caller handles unlock via the Prompt flow
/// and can call this again afterwards to sync the newly-unlocked providers.
async fn preemptive_sync(conn: &Connection) -> Result<()> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let providers: Vec<ProviderEntry> = proxy.call("ProviderList", &()).await?;

    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let futures: Vec<_> = providers
        .into_iter()
        .filter(|(_, _, _, locked, _, _, _, last_sync, capabilities)| {
            // Skip locked providers, providers without Sync capability,
            // and providers synced within the last 60 s.
            if *locked {
                return false;
            }
            if !capabilities.iter().any(|c| c == "Sync") {
                return false;
            }
            *last_sync == 0 || now_epoch.saturating_sub(*last_sync) >= 60
        })
        .map(|(id, ..)| {
            let conn = conn.clone();
            async move {
                let p = zbus::Proxy::new(
                    &conn,
                    "org.freedesktop.secrets",
                    "/org/rosec/Daemon",
                    "org.rosec.Daemon",
                )
                .await;
                match p {
                    Ok(p) => {
                        if let Err(e) = p.call::<_, _, u32>("SyncProvider", &(&id,)).await {
                            eprintln!("sync {id}: {e}");
                        }
                    }
                    Err(e) => eprintln!("sync {id}: {e}"),
                }
            }
        })
        .collect();

    futures_util::future::join_all(futures).await;

    Ok(())
}

/// Returns `true` if the daemon reports at least one locked provider that has
/// the `Sync` capability.
///
/// Used by `cmd_search` with `--sync` to decide whether an unlock prompt is
/// worthwhile — there is no point prompting for a provider that cannot sync.
async fn any_syncable_providers_locked(conn: &Connection) -> Result<bool> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;
    let providers: Vec<ProviderEntry> = proxy.call("ProviderList", &()).await?;
    Ok(providers
        .iter()
        .any(|(_, _, _, locked, _, _, _, _, capabilities)| {
            *locked && capabilities.iter().any(|c| c == "Sync")
        }))
}

/// Output format for `rosec search`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Human,
    Table,
    Kv,
    Json,
}

/// Convert a clap `Format` enum to the internal `OutputFormat`.
fn cli_format_to_output(f: Format) -> OutputFormat {
    match f {
        Format::Human => OutputFormat::Human,
        Format::Table => OutputFormat::Table,
        Format::Kv => OutputFormat::Kv,
        Format::Json => OutputFormat::Json,
    }
}

/// All data fetched for a single search result item.
struct ItemSummary {
    label: String,
    attrs: HashMap<String, String>,
    path: String,
    locked: bool,
}

impl ItemSummary {
    /// The 16-char hex hash that uniquely identifies this item.
    ///
    /// Path segment format: `{provider}_{uuid_sanitised}_{hash:016x}`
    /// The hash is the last `_`-delimited token — always exactly 16 hex chars.
    /// It is derived from `sha256("{provider_id}:{item_id}")[0..8]` so it is
    /// stable across restarts and toolchain upgrades, and collision probability
    /// is ~1 in 2^64 across all items in a vault.
    ///
    /// Pass this directly to `rosec get`.
    fn display_id(&self) -> &str {
        let seg = self.path.rsplit('/').next().unwrap_or(self.path.as_str());
        seg.rsplit('_').next().unwrap_or(seg)
    }
}

/// Returns true if the value string contains any wildmatch glob metacharacters.
fn is_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

/// Spec-compliant exact-match search via `org.freedesktop.Secret.Service.SearchItems`.
/// Handles lazy-unlock automatically unless `no_unlock` is set.
async fn search_exact(
    conn: &Connection,
    attrs: &HashMap<String, String>,
    no_unlock: bool,
) -> Result<(Vec<String>, Vec<String>)> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    let convert =
        |(u, l): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)| -> (Vec<String>, Vec<String>) {
            (
                u.into_iter().map(|p| p.to_string()).collect(),
                l.into_iter().map(|p| p.to_string()).collect(),
            )
        };

    match proxy.call("SearchItems", &(attrs,)).await {
        Ok(result) => Ok(convert(result)),
        Err(ref e) if !no_unlock && try_lazy_unlock(conn, e).await? => {
            Ok(convert(proxy.call("SearchItems", &(attrs,)).await?))
        }
        Err(e) => Err(e.into()),
    }
}

/// Detect whether the active Secret Service provider is rosecd.
///
/// Attempts a cheap `org.freedesktop.DBus.Introspectable.Introspect` call on
/// `/org/rosec/Daemon`.  Returns `true` if the call succeeds (object exists),
/// `false` for any error (object absent, service unknown, etc.).
///
/// Call this once per command and pass the result as `is_rosecd: bool` to
/// avoid redundant round-trips.
async fn is_rosecd(conn: &Connection) -> bool {
    let proxy = match zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.freedesktop.DBus.Introspectable",
    )
    .await
    {
        Ok(p) => p,
        Err(_) => return false,
    };
    proxy.call::<_, _, String>("Introspect", &()).await.is_ok()
}

/// If rosecd is running with no configured providers, print a warning to stderr
/// and suggest next steps.  Non-fatal — the caller continues normally (an empty
/// provider list returns empty results, which is correct behaviour).
async fn warn_if_no_providers(conn: &Connection) {
    let Ok(proxy) = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await
    else {
        return;
    };
    let Ok(entries) = proxy
        .call::<_, _, Vec<ProviderEntry>>("ProviderList", &())
        .await
    else {
        return;
    };
    if entries.is_empty() {
        eprintln!("warning: rosecd is running with no configured providers.");
        eprintln!("         Run `rosec provider add <kind>` to add a real provider.");
    }
}

/// Glob search: try `org.rosec.Search.SearchItemsGlob` first when rosecd is running.
///
/// If `is_rosecd` is false (non-rosecd provider), falls back to
/// `SearchItems({})` to retrieve all items, then applies glob matching
/// client-side.  This keeps `rosec search name=John*` working against GNOME
/// Keyring, KWallet, or any other spec-compliant Secret Service daemon.
///
/// When `no_unlock` is true, the lazy-unlock retry is suppressed.
async fn search_with_glob_fallback(
    conn: &Connection,
    attrs: &HashMap<String, String>,
    is_rosecd: bool,
    no_unlock: bool,
) -> Result<(Vec<String>, Vec<String>)> {
    if is_rosecd {
        // Use the rosec Search extension — zero client-side work.
        let search_proxy = zbus::Proxy::new(
            conn,
            "org.freedesktop.secrets",
            "/org/rosec/Search",
            "org.rosec.Search",
        )
        .await?;

        let convert =
            |(u, l): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)| -> (Vec<String>, Vec<String>) {
                (
                    u.into_iter().map(|p| p.to_string()).collect(),
                    l.into_iter().map(|p| p.to_string()).collect(),
                )
            };

        // Mirror the lazy-unlock retry that search_exact uses: if the server
        // returns locked::<id>, prompt the user then retry once.
        match search_proxy.call("SearchItemsGlob", &(attrs,)).await {
            Ok(result) => return Ok(convert(result)),
            Err(ref e) if !no_unlock && try_lazy_unlock(conn, e).await? => {
                return Ok(convert(
                    search_proxy.call("SearchItemsGlob", &(attrs,)).await?,
                ));
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Fallback for non-rosecd providers: fetch all items then filter client-side.
    let (unlocked, locked) = search_exact(conn, &HashMap::new(), no_unlock).await?;

    let mut filtered_unlocked = Vec::new();
    let mut filtered_locked = Vec::new();

    for path in &unlocked {
        if let Ok(summary) = fetch_item_data(conn, path, false).await
            && glob_matches(&summary, attrs)
        {
            filtered_unlocked.push(path.clone());
        }
    }
    for path in &locked {
        if let Ok(summary) = fetch_item_data(conn, path, true).await
            && glob_matches(&summary, attrs)
        {
            filtered_locked.push(path.clone());
        }
    }

    Ok((filtered_unlocked, filtered_locked))
}

/// Returns true if all glob/exact filters in `attrs` match the item summary.
/// The special key `"name"` matches the item label.
fn glob_matches(item: &ItemSummary, attrs: &HashMap<String, String>) -> bool {
    attrs.iter().all(|(key, pattern)| {
        let value = if key == "name" {
            item.label.as_str()
        } else {
            item.attrs
                .get(key.as_str())
                .map(String::as_str)
                .unwrap_or("")
        };
        wildmatch::WildMatch::new(pattern).matches(value)
    })
}

async fn cmd_search(args: SearchArgs) -> Result<()> {
    let format = cli_format_to_output(args.format);
    let show_path = args.show_path;
    let sync = args.sync;
    let no_unlock = args.no_unlock;
    let mut all_attrs: HashMap<String, String> = HashMap::new();

    for filter in &args.filters {
        if let Some((key, value)) = filter.split_once('=') {
            all_attrs.insert(key.to_string(), value.to_string());
        } else {
            bail!("invalid filter: {filter} (expected key=value)");
        }
    }

    if sync && no_unlock {
        bail!("--sync and --no-unlock are mutually exclusive");
    }

    let conn = conn().await?;
    let rosecd = is_rosecd(&conn).await;
    if rosecd {
        warn_if_no_providers(&conn).await;
    }

    // If --sync was requested, ensure the daemon has fresh data first.
    if sync {
        preemptive_sync(&conn).await?;
    }

    let has_globs = all_attrs.values().any(|v| is_glob(v)) || all_attrs.contains_key("name");

    // Strategy:
    //   - Any glob pattern or "name" filter → use org.rosec.Search.SearchItemsGlob
    //     when rosecd is running; otherwise fall back to spec-compliant
    //     SearchItems({}) + client-side glob (works against GNOME Keyring, KWallet, etc.)
    //   - All-exact attrs → always use spec-compliant SearchItems directly.
    let do_search = |conn: &Connection| {
        let conn = conn.clone();
        let all_attrs = all_attrs.clone();
        async move {
            if has_globs {
                search_with_glob_fallback(&conn, &all_attrs, rosecd, no_unlock).await
            } else {
                search_exact(&conn, &all_attrs, no_unlock).await
            }
        }
    };

    let (unlocked, locked) = match do_search(&conn).await {
        Ok(result) => result,
        Err(e) if sync => {
            // Search failed (e.g. all providers locked) — unlock then retry.
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            do_search(&conn).await.map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    // With --sync, trigger unlock whenever any syncable provider is still
    // locked.  Previous logic only unlocked when *all* results were locked or
    // empty, which silently skipped locked providers when at least one unlocked
    // provider already returned results.  The user asked for --sync — honour
    // that by unlocking every syncable provider so the search covers everything.
    let needs_unlock = !no_unlock && sync && any_syncable_providers_locked(&conn).await?;
    let (unlocked, locked) = if needs_unlock {
        trigger_unlock(&conn).await?;
        preemptive_sync(&conn).await?;
        do_search(&conn).await?
    } else {
        (unlocked, locked)
    };

    if unlocked.is_empty() && locked.is_empty() {
        if format != OutputFormat::Json {
            println!("No items found.");
        } else {
            println!("[]");
        }
        return Ok(());
    }

    // Fetch metadata for all result paths.
    let mut items: Vec<ItemSummary> = Vec::new();
    for path in &unlocked {
        let summary = fetch_item_data(&conn, path, false)
            .await
            .unwrap_or_else(|_| ItemSummary {
                label: path.clone(),
                attrs: HashMap::new(),
                path: path.clone(),
                locked: false,
            });
        items.push(summary);
    }
    for path in &locked {
        let summary = fetch_item_data(&conn, path, true)
            .await
            .unwrap_or_else(|_| ItemSummary {
                label: path.clone(),
                attrs: HashMap::new(),
                path: path.clone(),
                locked: true,
            });
        items.push(summary);
    }

    match format {
        OutputFormat::Human | OutputFormat::Table => print_search_table(&items, show_path),
        OutputFormat::Kv => print_search_kv(&items, show_path),
        OutputFormat::Json => print_search_json(&items)?, // JSON always includes path
    }

    Ok(())
}

/// Fetch Label and Attributes for an item into a structured summary.
async fn fetch_item_data(conn: &zbus::Connection, path: &str, locked: bool) -> Result<ItemSummary> {
    let item_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        path,
        "org.freedesktop.Secret.Item",
    )
    .await?;

    let label: String = item_proxy.get_property("Label").await?;
    let attrs: HashMap<String, String> = item_proxy.get_property("Attributes").await?;

    Ok(ItemSummary {
        label,
        attrs,
        path: path.to_string(),
        locked,
    })
}

/// Truncate a string to `max` display chars, appending `…` if cut.
/// Format an epoch timestamp as a human-readable relative time string.
///
/// Returns "never" for 0, otherwise "Xs ago", "Xm ago", "Xh ago", or "Xd ago".
fn format_relative_time(epoch_secs: u64, now_epoch: u64) -> String {
    if epoch_secs == 0 {
        return "never".to_string();
    }
    let delta = now_epoch.saturating_sub(epoch_secs);
    if delta < 60 {
        format!("{delta}s ago")
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86400 {
        format!("{}h ago", delta / 3600)
    } else {
        format!("{}d ago", delta / 86400)
    }
}

/// Build a compact capability string from the D-Bus capability list.
///
/// Each capability maps to a single character:
///   S = Sync, W = Write, s = Ssh, K = KeyWrapping,
///   P = PasswordChange, C = OfflineCache, N = Notifications
fn capability_codes(caps: &[String]) -> String {
    let mut out = String::new();
    for (name, code) in [
        ("Sync", 'S'),
        ("Write", 'W'),
        ("Ssh", 's'),
        ("KeyWrapping", 'K'),
        ("PasswordChange", 'P'),
        ("OfflineCache", 'C'),
        ("Notifications", 'N'),
    ] {
        if caps.iter().any(|c| c == name) {
            out.push(code);
        }
    }
    out
}

fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Cut at a char boundary safely.
        let mut end = max.saturating_sub(1); // 1 char for …
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

/// Detect the terminal width via `TIOCGWINSZ` ioctl, falling back to 120.
fn terminal_width() -> usize {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: ioctl with TIOCGWINSZ on stdout is a standard POSIX operation
    // that writes into a stack-allocated winsize struct.
    let ret = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if ret == 0 && ws.ws_col > 0 {
        ws.ws_col as usize
    } else {
        120
    }
}

/// Column descriptor for adaptive table layout.
struct ColSpec {
    /// Natural width: max(content_width, header_width).
    natural: usize,
    /// Minimum width the column can be shrunk to (header width).
    min: usize,
    /// Allocated width after fitting to terminal.
    allocated: usize,
}

/// Fit columns into `avail` characters.
///
/// Each column starts at its natural (content-driven) width and is never
/// expanded beyond that.  When the total exceeds `avail`, columns are shrunk
/// starting from the **end** of the `cols` slice — so put the highest-priority
/// (last-to-shrink) columns first.
///
/// Returns `true` if everything fit without any truncation.
fn fit_columns(cols: &mut [ColSpec], gap: usize, avail: usize) -> bool {
    let gaps_total = gap * cols.len().saturating_sub(1);

    // Start with natural widths.
    for c in cols.iter_mut() {
        c.allocated = c.natural;
    }

    let total = |cols: &[ColSpec]| -> usize {
        cols.iter().map(|c| c.allocated).sum::<usize>() + gaps_total
    };

    if total(cols) <= avail {
        return true;
    }

    // Shrink from the end (lowest priority) towards the front.
    for i in (0..cols.len()).rev() {
        let over = total(cols).saturating_sub(avail);
        if over == 0 {
            break;
        }
        let can_shrink = cols[i].allocated.saturating_sub(cols[i].min);
        let shrink = can_shrink.min(over);
        cols[i].allocated -= shrink;
    }
    total(cols) <= avail
}

/// Print results as an aligned table.
///
/// Columns: TYPE | PROVIDER | NAME | USERNAME | URI | ID [| PATH]
///
/// Column widths adapt to the terminal width.  When the table is too wide,
/// columns are shrunk in reverse priority order (URI first, then USERNAME,
/// NAME, PROVIDER, ID, TYPE last).
fn print_search_table(items: &[ItemSummary], show_path: bool) {
    const H_TYPE: &str = "TYPE";
    const H_PROV: &str = "PROVIDER";
    const H_NAME: &str = "NAME";
    const H_USER: &str = "USERNAME";
    const H_URI: &str = "URI";
    const H_ID: &str = "ID";
    const GAP: usize = 2; // spaces between columns

    // Natural widths: max(data_length, header_length) per column.
    let nat_type = items
        .iter()
        .map(|i| {
            i.attrs
                .get(rosec_core::ATTR_TYPE)
                .map(String::len)
                .unwrap_or(0)
        })
        .max()
        .unwrap_or(0)
        .max(H_TYPE.len());
    let nat_id = 16_usize.max(H_ID.len()); // always 16 hex chars
    let nat_prov = items
        .iter()
        .map(|i| {
            i.attrs
                .get(rosec_core::ATTR_PROVIDER)
                .map(String::len)
                .unwrap_or(0)
        })
        .max()
        .unwrap_or(0)
        .max(H_PROV.len());
    let nat_name = items
        .iter()
        .map(|i| i.label.len())
        .max()
        .unwrap_or(0)
        .max(H_NAME.len());
    let nat_user = items
        .iter()
        .map(|i| i.attrs.get("username").map(String::len).unwrap_or(0))
        .max()
        .unwrap_or(0)
        .max(H_USER.len());
    let nat_uri = items
        .iter()
        .map(|i| i.attrs.get("uri").map(String::len).unwrap_or(0))
        .max()
        .unwrap_or(0)
        .max(H_URI.len());

    // Priority order (highest first): TYPE, ID, PROVIDER, NAME, USERNAME, URI.
    // Indices into this priority array:
    const P_TYPE: usize = 0;
    const P_ID: usize = 1;
    const P_PROV: usize = 2;
    const P_NAME: usize = 3;
    const P_USER: usize = 4;
    const P_URI: usize = 5;

    let mut cols = [
        ColSpec {
            natural: nat_type,
            min: H_TYPE.len(),
            allocated: 0,
        },
        ColSpec {
            natural: nat_id,
            min: H_ID.len(),
            allocated: 0,
        },
        ColSpec {
            natural: nat_prov,
            min: H_PROV.len(),
            allocated: 0,
        },
        ColSpec {
            natural: nat_name,
            min: H_NAME.len(),
            allocated: 0,
        },
        ColSpec {
            natural: nat_user,
            min: H_USER.len(),
            allocated: 0,
        },
        ColSpec {
            natural: nat_uri,
            min: H_URI.len(),
            allocated: 0,
        },
    ];

    let mut term_w = terminal_width();
    // PATH column (when shown) is not shrinkable — subtract it from budget.
    if show_path {
        // PATH has no max width; reserve header + gap.
        term_w = term_w.saturating_sub(GAP + "PATH".len());
    }

    fit_columns(&mut cols, GAP, term_w);

    let w_type = cols[P_TYPE].allocated;
    let w_id = cols[P_ID].allocated;
    let w_prov = cols[P_PROV].allocated;
    let w_name = cols[P_NAME].allocated;
    let w_user = cols[P_USER].allocated;
    let w_uri = cols[P_URI].allocated;

    // --- Header ---
    if show_path {
        println!(
            "{:<w_type$}  {:<w_prov$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {:<w_id$}  PATH",
            H_TYPE, H_PROV, H_NAME, H_USER, H_URI, H_ID,
        );
    } else {
        println!(
            "{:<w_type$}  {:<w_prov$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {}",
            H_TYPE, H_PROV, H_NAME, H_USER, H_URI, H_ID,
        );
    }

    let sep_w = w_type
        + GAP
        + w_prov
        + GAP
        + w_name
        + GAP
        + w_user
        + GAP
        + w_uri
        + GAP
        + w_id
        + if show_path { GAP + "PATH".len() } else { 0 };
    println!("{}", "-".repeat(sep_w));

    // --- Rows ---
    for item in items {
        let item_type = item
            .attrs
            .get(rosec_core::ATTR_TYPE)
            .map(String::as_str)
            .unwrap_or("");
        let provider = item
            .attrs
            .get(rosec_core::ATTR_PROVIDER)
            .map(String::as_str)
            .unwrap_or("");
        let username = item.attrs.get("username").map(String::as_str).unwrap_or("");
        let uri = item.attrs.get("uri").map(String::as_str).unwrap_or("");

        let t = trunc(item_type, w_type);
        let p = trunc(provider, w_prov);
        let n = trunc(&item.label, w_name);
        let u = trunc(username, w_user);
        let r = trunc(uri, w_uri);
        let id = trunc(item.display_id(), w_id);
        let lock_indicator = if item.locked { " [locked]" } else { "" };

        if show_path {
            println!(
                "{:<w_type$}  {:<w_prov$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {:<w_id$}  {}{}",
                t, p, n, u, r, id, item.path, lock_indicator,
            );
        } else {
            println!(
                "{:<w_type$}  {:<w_prov$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {}{}",
                t, p, n, u, r, id, lock_indicator,
            );
        }
    }
}

/// Print results as key=value pairs (one item block per result).
fn print_search_kv(items: &[ItemSummary], show_path: bool) {
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("label={}", item.label);
        println!("id={}", item.display_id());
        if show_path {
            println!("path={}", item.path);
        }
        if item.locked {
            println!("locked=true");
        }
        // Print all public attributes sorted for determinism.
        let mut sorted_attrs: Vec<_> = item.attrs.iter().collect();
        sorted_attrs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in &sorted_attrs {
            // Skip internal/redundant attrs in kv mode.
            if k.as_str() == "xdg:schema" {
                continue;
            }
            println!("{k}={v}");
        }
    }
}

/// Print results as a JSON array.
fn print_search_json(items: &[ItemSummary]) -> Result<()> {
    let json_items: Vec<serde_json::Value> = items
        .iter()
        .map(|item| {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "label".to_string(),
                serde_json::Value::String(item.label.clone()),
            );
            obj.insert(
                "id".to_string(),
                serde_json::Value::String(item.display_id().to_string()),
            );
            obj.insert(
                "path".to_string(),
                serde_json::Value::String(item.path.clone()),
            );
            obj.insert("locked".to_string(), serde_json::Value::Bool(item.locked));

            let mut attrs_obj = serde_json::Map::new();
            let mut sorted_attrs: Vec<_> = item.attrs.iter().collect();
            sorted_attrs.sort_by_key(|(k, _)| k.as_str());
            for (k, v) in sorted_attrs {
                attrs_obj.insert(k.clone(), serde_json::Value::String(v.clone()));
            }
            obj.insert(
                "attributes".to_string(),
                serde_json::Value::Object(attrs_obj),
            );

            serde_json::Value::Object(obj)
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&json_items)?);
    Ok(())
}

/// Resolve a user-supplied item identifier to a full D-Bus object path.
///
/// Accepts:
/// - A full D-Bus path (starts with `/`)
/// - A 16-char hex hash (the `display_id` shown by `rosec search`) — resolved
///   by searching all items for one whose path ends with `_{hash}`
/// - Any other string is treated as the full last path segment and prepended
///   with the collection prefix (legacy behaviour)
///
/// Returns `(path, is_locked)` where `is_locked` is `true` if the item was
/// found in the `locked` list of `SearchItems`.  For full paths and legacy
/// segments (where we don't call `SearchItems`), `is_locked` is `false`.
async fn resolve_item_path(conn: &Connection, raw: &str) -> Result<(String, bool)> {
    if raw.starts_with('/') {
        return Ok((raw.to_string(), false));
    }

    // Attribute search: key=value (supports globs via SearchItemsGlob).
    //
    // Multiple attributes can be separated by spaces (shell quoting), but the
    // common case is a single `name=My Item` or `name=*API*`.
    //
    // We detect this by looking for '=' that isn't at position 0.
    if let Some(eq_pos) = raw.find('=')
        && eq_pos > 0
    {
        return resolve_item_by_attrs(conn, raw).await;
    }

    // 16-char lowercase hex → look up by hash suffix.
    let is_hash = raw.len() == 16 && raw.chars().all(|c| c.is_ascii_hexdigit());
    if is_hash {
        let proxy = zbus::Proxy::new(
            conn,
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
        )
        .await?;
        let suffix = format!("_{raw}");
        let (unlocked_paths, locked_paths): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = proxy
            .call("SearchItems", &(&HashMap::<String, String>::new(),))
            .await?;
        let unlocked: Vec<String> = unlocked_paths.into_iter().map(|p| p.to_string()).collect();
        let locked: Vec<String> = locked_paths.into_iter().map(|p| p.to_string()).collect();
        // Check unlocked first (preferred).
        for path in &unlocked {
            if path.ends_with(&suffix) {
                return Ok((path.clone(), false));
            }
        }
        // Then check locked list.
        for path in &locked {
            if path.ends_with(&suffix) {
                return Ok((path.clone(), true));
            }
        }
        anyhow::bail!("no item found with ID {raw}");
    }

    // Legacy: treat as full path segment.
    Ok((
        format!("/org/freedesktop/secrets/collection/default/{raw}"),
        false,
    ))
}

/// Resolve an item path from one or more `key=value` attribute filters.
///
/// Uses `SearchItemsGlob` when rosecd is running (supports glob patterns and
/// the virtual `name` attribute); falls back to spec-compliant `SearchItems`
/// for other providers.
///
/// Returns an error if zero or more than one item matches.
async fn resolve_item_by_attrs(conn: &Connection, raw: &str) -> Result<(String, bool)> {
    let mut attrs = HashMap::new();
    // The raw string may be the single positional arg, so it's one key=value.
    // But we also allow the caller to pass multiple space-separated pairs in
    // the future if needed.  For now, treat the entire raw string as one pair
    // since the shell will have already split spaces into separate args.
    if let Some((key, value)) = raw.split_once('=') {
        attrs.insert(key.to_string(), value.to_string());
    } else {
        anyhow::bail!("invalid attribute filter: {raw}  (expected key=value)");
    }

    let rosecd = is_rosecd(conn).await;
    let has_globs = attrs.values().any(|v| is_glob(v)) || attrs.contains_key("name");

    let (unlocked, locked) = if has_globs {
        search_with_glob_fallback(conn, &attrs, rosecd, false).await?
    } else {
        search_exact(conn, &attrs, false).await?
    };

    let total = unlocked.len() + locked.len();
    match total {
        0 => anyhow::bail!("no item found matching {raw}"),
        1 => {
            if let Some(path) = unlocked.into_iter().next() {
                Ok((path, false))
            } else {
                Ok((locked.into_iter().next().expect("locked has 1 item"), true))
            }
        }
        n => {
            let mut msg = format!("{n} items match {raw} — narrow your search:\n");
            for path in unlocked.iter().chain(locked.iter()).take(10) {
                // Extract the short hex ID from the path suffix.
                let id = path.rsplit('_').next().unwrap_or(path);
                msg.push_str(&format!("  {id}  {path}\n"));
            }
            if n > 10 {
                msg.push_str(&format!("  … and {} more\n", n - 10));
            }
            anyhow::bail!("{msg}");
        }
    }
}

async fn cmd_get(args: GetArgs) -> Result<()> {
    let attr = args.attr;
    let sync = args.sync;
    let no_unlock = args.no_unlock;

    if sync && no_unlock {
        bail!("--sync and --no-unlock are mutually exclusive");
    }

    let raw = args.item.as_str();

    let conn = conn().await?;

    // If --sync was requested, ensure the daemon has fresh data before resolving.
    if sync {
        preemptive_sync(&conn).await?;
    }

    let resolve_result = resolve_item_path(&conn, raw).await;

    // Determine the item path and whether unlock is needed.
    // With --sync, if the item wasn't found at all we attempt unlock + re-sync
    // before giving up — the item may live in a provider that hasn't been
    // unlocked yet (so the metadata cache has no knowledge of it).
    // With --no-unlock, skip all unlock attempts.
    let (path, is_locked) = match resolve_result {
        Ok(result) => result,
        Err(e) if sync && !no_unlock => {
            // Item not found — try unlocking, syncing, and re-resolving.
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            resolve_item_path(&conn, raw).await.map_err(|_| e)? // If still not found, return the original error.
        }
        Err(e) => return Err(e),
    };

    // If the item was in the locked partition, trigger the spec Unlock+Prompt
    // flow before attempting to fetch the secret.  With --no-unlock, bail
    // instead of prompting.
    if is_locked {
        if no_unlock {
            bail!("item is locked — use --sync to unlock the provider first");
        }
        trigger_unlock(&conn).await?;
        // Re-sync the just-unlocked providers so the freshly-available items
        // are pulled from the remote and the metadata cache is populated.
        if sync {
            preemptive_sync(&conn).await?;
        }
    }

    // Try once; if provider is locked, prompt for credentials and retry.
    // With --no-unlock, skip the lazy-unlock retry.
    match cmd_get_inner(&conn, &path, attr.as_deref()).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let zbus_err = e.downcast_ref::<zbus::Error>();
            if !no_unlock
                && let Some(ze) = zbus_err
                && try_lazy_unlock(&conn, ze).await?
            {
                cmd_get_inner(&conn, &path, attr.as_deref()).await
            } else {
                Err(e)
            }
        }
    }
}

/// Normalise an `--attr` value that may use dot-index syntax.
///
/// Any attribute with multiple values uses `name.N` notation in the CLI:
/// - `name`   → `"name"`   (bare = index 0, backwards compat)
/// - `name.0` → `"name"`   (explicit index 0 → bare key)
/// - `name.1` → `"name.1"` (index 1 stored as "name.1")
/// - `name.2` → `"name.2"`, …
///
/// This is generic — it works for `uri`, `custom.field`, or any future
/// multi-value attribute without needing an allowlist.
fn normalise_attr_key(attr: &str) -> String {
    if let Some(dot) = attr.rfind('.') {
        let name = &attr[..dot];
        let suffix = &attr[dot + 1..];
        // Only treat as an index if suffix is a pure decimal integer.
        if !name.is_empty()
            && suffix.chars().all(|c| c.is_ascii_digit())
            && let Ok(idx) = suffix.parse::<usize>()
        {
            return if idx == 0 {
                name.to_string()
            } else {
                format!("{name}.{idx}")
            };
        }
    }
    attr.to_string()
}

/// Print only the secret value (or a named attribute) to stdout — pipeable.
async fn cmd_get_inner(conn: &Connection, path: &str, attr: Option<&str>) -> Result<()> {
    use std::io::Write;

    // --attr mode: read from the public Attributes property, no session needed.
    if let Some(attr_name) = attr {
        let resolved = normalise_attr_key(attr_name);
        let item_proxy = zbus::Proxy::new(
            conn,
            "org.freedesktop.secrets",
            path,
            "org.freedesktop.Secret.Item",
        )
        .await?;
        let attrs: HashMap<String, String> = item_proxy.get_property("Attributes").await?;
        match attrs.get(resolved.as_str()) {
            Some(v) => {
                let mut out = std::io::stdout();
                out.write_all(v.as_bytes())?;
                // Attribute values are plain strings — always add newline on TTY,
                // and only if the value doesn't already end with one.
                if std::io::IsTerminal::is_terminal(&out) && !v.ends_with('\n') {
                    out.write_all(b"\n")?;
                }
                return Ok(());
            }
            None => bail!("attribute '{resolved}' not found on this item"),
        }
    }

    // Default: fetch the primary secret via GetSecrets.
    let service_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    let (_, session_path): (OwnedValue, OwnedObjectPath) = service_proxy
        .call("OpenSession", &("plain", zvariant::Value::from("")))
        .await?;

    let item_path = OwnedObjectPath::try_from(path.to_string())
        .map_err(|e| anyhow::anyhow!("invalid item path: {e}"))?;
    let items = vec![&item_path];
    type SecretTuple = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
    let secrets_result: Result<HashMap<OwnedObjectPath, SecretTuple>, zbus::Error> = service_proxy
        .call("GetSecrets", &(items, &session_path))
        .await;

    let _: () = service_proxy
        .call("CloseSession", &(&session_path,))
        .await?;

    match secrets_result {
        Ok(secrets) if secrets.is_empty() => {
            bail!("no secret found for item");
        }
        Ok(secrets) => {
            if let Some((_item_path, (_session, _params, secret_bytes, _content_type))) =
                secrets.into_iter().next()
            {
                let mut out = std::io::stdout();
                out.write_all(&secret_bytes)?;
                // Add a trailing newline on TTY only if the secret itself
                // doesn't already end with one (avoids the double-newline
                // that appears when the stored value has a trailing \n).
                if std::io::IsTerminal::is_terminal(&out) && !secret_bytes.ends_with(b"\n") {
                    out.write_all(b"\n")?;
                }
                return Ok(());
            }
            bail!("no secret found for item");
        }
        Err(zbus::Error::MethodError(_, Some(detail), _))
            if detail.as_str().starts_with("no secret for cipher") =>
        {
            bail!("item has no primary secret");
        }
        Err(e) => Err(e.into()),
    }
}

async fn cmd_inspect(args: InspectArgs) -> Result<()> {
    let all_attrs = args.all_attrs;
    let sync = args.sync;
    let format = cli_format_to_output(args.format);
    let raw = args.item.as_str();

    let conn = conn().await?;

    if sync {
        preemptive_sync(&conn).await?;
    }

    // Resolve the item; if not found and --sync is set, try unlock + re-sync first.
    let (path, is_locked) = match resolve_item_path(&conn, raw).await {
        Ok(result) => result,
        Err(e) => {
            // Item not in cache — trigger unlock (which may populate it) then retry.
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            resolve_item_path(&conn, raw).await.map_err(|_| e)?
        }
    };

    if is_locked {
        trigger_unlock(&conn).await?;
        if sync {
            preemptive_sync(&conn).await?;
        }
    }

    match cmd_inspect_inner(&conn, &path, all_attrs, &format).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let zbus_err = e.downcast_ref::<zbus::Error>();
            if let Some(ze) = zbus_err
                && try_lazy_unlock(&conn, ze).await?
            {
                cmd_inspect_inner(&conn, &path, all_attrs, &format).await
            } else {
                Err(e)
            }
        }
    }
}

/// Print full item metadata (label, attributes) plus the secret value.
///
/// When `all_attrs` is true, also fetches sensitive attribute names via
/// `org.rosec.Secrets.GetSecretAttributeNames` and their values via
/// `GetSecretAttribute`, displaying them alongside the public attributes.
async fn cmd_inspect_inner(
    conn: &Connection,
    path: &str,
    all_attrs: bool,
    format: &OutputFormat,
) -> Result<()> {
    let service_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    let (_, session_path): (OwnedValue, OwnedObjectPath) = service_proxy
        .call("OpenSession", &("plain", zvariant::Value::from("")))
        .await?;

    let item_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        path,
        "org.freedesktop.Secret.Item",
    )
    .await?;

    let label: String = item_proxy.get_property("Label").await?;
    let pub_attrs: HashMap<String, String> = item_proxy.get_property("Attributes").await?;

    // Fetch sensitive attribute names (and optionally values) if requested.
    let secret_attrs: Vec<(String, Zeroizing<Vec<u8>>)> = if all_attrs {
        let secrets_proxy = zbus::Proxy::new(
            conn,
            "org.freedesktop.secrets",
            "/org/rosec/Secrets",
            "org.rosec.Secrets",
        )
        .await?;

        let item_obj_path = OwnedObjectPath::try_from(path.to_string())
            .map_err(|e| anyhow::anyhow!("invalid item path: {e}"))?;

        let names: Vec<String> = secrets_proxy
            .call("GetSecretAttributeNames", &(&item_obj_path,))
            .await?;

        let mut pairs: Vec<(String, Zeroizing<Vec<u8>>)> = Vec::with_capacity(names.len());
        for name in names {
            let bytes: Vec<u8> = secrets_proxy
                .call("GetSecretAttribute", &(&item_obj_path, name.as_str()))
                .await
                .unwrap_or_default();
            pairs.push((name, Zeroizing::new(bytes)));
        }
        pairs
    } else {
        Vec::new()
    };

    // Fetch the primary secret for human/kv (not needed for json as we include
    // sensitive attrs separately).
    let inspect_item_path = OwnedObjectPath::try_from(path.to_string())
        .map_err(|e| anyhow::anyhow!("invalid item path: {e}"))?;
    let items = vec![&inspect_item_path];
    type SecretTuple = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
    let secrets_result: Result<HashMap<OwnedObjectPath, SecretTuple>, zbus::Error> = service_proxy
        .call("GetSecrets", &(items, &session_path))
        .await;

    let _: () = service_proxy
        .call("CloseSession", &(&session_path,))
        .await?;

    match format {
        OutputFormat::Human | OutputFormat::Table => {
            println!("Label:      {label}");
            println!("Path:       {path}");

            // Public attributes.
            if !pub_attrs.is_empty() {
                println!("Attributes (public):");
                let mut sorted: Vec<_> = pub_attrs.iter().collect();
                sorted.sort_by_key(|(k, _)| *k);
                for (k, v) in sorted {
                    println!("  {k}: {v}");
                }
            }

            // Sensitive attributes (--all-attrs).
            if !secret_attrs.is_empty() {
                println!("Attributes (sensitive):");
                for (k, v) in &secret_attrs {
                    let text = String::from_utf8_lossy(v);
                    println!("  {k}: {text}");
                }
            }

            // Primary secret.
            match secrets_result {
                Ok(secrets) if secrets.is_empty() => {
                    println!("Secret:     <none>");
                }
                Ok(secrets) => {
                    for (_item_path, (_session, _params, secret_bytes, content_type)) in secrets {
                        let text = String::from_utf8_lossy(&secret_bytes);
                        if text.is_empty() {
                            println!("Secret:     <empty>");
                        } else {
                            println!("Secret ({content_type}):");
                            println!("  {text}");
                        }
                    }
                }
                Err(zbus::Error::MethodError(_, Some(detail), _))
                    if detail.as_str().starts_with("no secret for cipher") =>
                {
                    println!("Secret:     <not available — this item type has no primary secret>");
                }
                Err(e) => println!("Secret:     <error: {e}>"),
            }
        }

        OutputFormat::Kv => {
            println!("label={label}");
            println!("path={path}");
            let mut sorted_pub: Vec<_> = pub_attrs.iter().collect();
            sorted_pub.sort_by_key(|(k, _)| *k);
            for (k, v) in sorted_pub {
                println!("{k}={v}");
            }
            for (k, v) in &secret_attrs {
                let text = String::from_utf8_lossy(v);
                println!("{k}={text}");
            }
            // Also emit primary secret as `secret=` for completeness.
            if let Ok(secrets) = secrets_result {
                for (_item_path, (_session, _params, secret_bytes, _ct)) in secrets {
                    let text = String::from_utf8_lossy(&secret_bytes);
                    println!("secret={text}");
                }
            }
        }

        OutputFormat::Json => {
            // Build a JSON object with label, path, public_attrs, and (if
            // --all-attrs) sensitive_attrs as a merged or separate sub-object.
            let mut sorted_pub: Vec<_> = pub_attrs.iter().collect();
            sorted_pub.sort_by_key(|(k, _)| *k);

            let pub_obj: serde_json::Map<String, serde_json::Value> = sorted_pub
                .into_iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect();

            let secret_obj: serde_json::Map<String, serde_json::Value> = secret_attrs
                .iter()
                .map(|(k, v)| {
                    let text = String::from_utf8_lossy(v).into_owned();
                    (k.clone(), serde_json::Value::String(text))
                })
                .collect();

            // Primary secret value.
            let primary_secret = match secrets_result {
                Ok(secrets) => {
                    let mut val = serde_json::Value::Null;
                    for (_item_path, (_session, _params, secret_bytes, _ct)) in secrets {
                        val = serde_json::Value::String(
                            String::from_utf8_lossy(&secret_bytes).into_owned(),
                        );
                    }
                    val
                }
                Err(_) => serde_json::Value::Null,
            };

            let mut obj = serde_json::Map::new();
            obj.insert("label".into(), serde_json::Value::String(label));
            obj.insert("path".into(), serde_json::Value::String(path.to_string()));
            obj.insert("attributes".into(), serde_json::Value::Object(pub_obj));
            if all_attrs {
                obj.insert(
                    "sensitive_attributes".into(),
                    serde_json::Value::Object(secret_obj),
                );
            }
            obj.insert("secret".into(), primary_secret);

            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Object(obj))?
            );
        }
    }

    Ok(())
}

async fn cmd_lock() -> Result<()> {
    let conn = conn().await?;

    // Count unlocked providers before locking so we can report how many were locked.
    let mgmt_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;
    let providers: Vec<ProviderEntry> = mgmt_proxy.call("ProviderList", &()).await?;
    let unlocked_count = providers
        .iter()
        .filter(|(_, _, _, locked, ..)| !locked)
        .count();

    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;
    let _: (Vec<OwnedObjectPath>, OwnedObjectPath) = proxy
        .call(
            "Lock",
            &(vec![
                OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default")
                    .expect("static path"),
            ],),
        )
        .await?;

    match unlocked_count {
        0 => println!("Nothing to lock — all providers already locked."),
        n => println!(
            "Locked: 1 collection, {} provider{}.",
            n,
            if n == 1 { "" } else { "s" }
        ),
    }
    Ok(())
}

async fn cmd_unlock() -> Result<()> {
    let conn = conn().await?;

    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let providers: Vec<ProviderEntry> = proxy.call("ProviderList", &()).await?;

    if providers.is_empty() {
        println!("No providers configured. Run `rosec provider add <kind>` to add one.");
        return Ok(());
    }

    // Report already-unlocked providers.
    let any_locked = providers.iter().any(|(_, _, _, locked, ..)| *locked);
    for (id, _, _, is_locked, ..) in &providers {
        if !is_locked {
            println!("'{id}' is already unlocked.");
        }
    }

    if !any_locked {
        return Ok(());
    }

    // Pass the caller's TTY fd to the daemon via D-Bus fd-passing.
    // All credential prompting happens inside rosecd — credentials never
    // appear in any D-Bus message payload.
    //
    // Do NOT wrap this call in a spinner: the daemon writes interactive
    // prompts to the TTY fd while this call is in flight, and the spinner
    // would interleave its \r-overwrite output with those prompts, leaving
    // the cursor in the wrong position.
    let tty_fd = open_tty_owned_fd()?;
    eprintln!("Unlocking…");
    type ResultEntry = (String, bool, String); // (provider_id, success, message)
    let results: Vec<ResultEntry> = proxy.call("UnlockWithTty", &(tty_fd,)).await?;

    for (id, success, _message) in &results {
        if *success {
            println!("'{id}' unlocked.");
        }
        // Failures are already printed inline on the TTY by the daemon
        // as each provider is attempted — no need to repeat them here.
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// rosec config — read/write config.toml
// ---------------------------------------------------------------------------

/// Supported dotted-path config keys and their human description.
///
/// Only settings that are safe to change at runtime (the daemon hot-reloads
/// config.toml) and genuinely useful from the CLI are listed here.
/// Theme colours and prompt binary paths are intentionally excluded —
/// hand-editing TOML is cleaner for those.
static CONFIG_KEYS: &[(&str, &str)] = &[
    (
        "service.refresh_interval_secs",
        "Vault re-sync interval in seconds (0 = disabled)",
    ),
    (
        "service.dedup_strategy",
        "Deduplication strategy: newest | priority",
    ),
    (
        "service.dedup_time_fallback",
        "Tie-break field when strategy=newest: created | none",
    ),
    (
        "autolock.on_logout",
        "Lock vault when the session ends (true | false)",
    ),
    (
        "autolock.on_session_lock",
        "Lock vault when the screen locks (true | false)",
    ),
    (
        "autolock.idle_timeout_minutes",
        "Lock after N minutes of inactivity (0 or omit = disabled)",
    ),
    (
        "autolock.max_unlocked_minutes",
        "Hard cap: lock after N minutes unlocked (0 or omit = disabled)",
    ),
];

fn cmd_config(action: Option<ConfigCommands>) -> Result<()> {
    match action {
        None => cmd_config_show(false),
        Some(ConfigCommands::Show { show_defaults }) => cmd_config_show(show_defaults),
        Some(ConfigCommands::Get { key }) => cmd_config_get(&key),
        Some(ConfigCommands::Set { key, value }) => cmd_config_set(&key, &value),
    }
}

fn cmd_config_show(show_defaults: bool) -> Result<()> {
    let path = config_path();
    if !path.exists() {
        println!("# No config file found at {}", path.display());
        println!("# Showing compiled-in defaults:\n");
        let default_toml = toml::to_string_pretty(&Config::default())
            .unwrap_or_else(|_| "# (serialization error)".to_string());
        println!("{default_toml}");
        return Ok(());
    }

    if show_defaults {
        // Parse with serde defaults applied, then re-serialize to show all fields.
        let cfg = load_config();
        let effective_toml =
            toml::to_string_pretty(&cfg).unwrap_or_else(|_| "# (serialization error)".to_string());
        print!("{effective_toml}");
    } else {
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
        print!("{raw}");
    }
    Ok(())
}

fn cmd_config_get(key: &str) -> Result<()> {
    // Validate the key is in the supported list.
    if !CONFIG_KEYS.iter().any(|(k, _)| *k == key) {
        bail!("unknown config key: {key}\nrun `rosec config --help` to see supported keys");
    }

    let cfg = load_config();
    let value = config_get_value(&cfg, key)?;
    println!("{value}");
    Ok(())
}

/// Read a single dotted-path value from a loaded `Config` as a display string.
fn config_get_value(cfg: &Config, key: &str) -> Result<String> {
    Ok(match key {
        "service.refresh_interval_secs" => cfg
            .service
            .refresh_interval_secs
            .map(|v| v.to_string())
            .unwrap_or_else(|| "60".to_string()),
        "service.dedup_strategy" => format!("{:?}", cfg.service.dedup_strategy).to_lowercase(),
        "service.dedup_time_fallback" => {
            format!("{:?}", cfg.service.dedup_time_fallback).to_lowercase()
        }
        "autolock.on_logout" => cfg.autolock.on_logout.to_string(),
        "autolock.on_session_lock" => cfg.autolock.on_session_lock.to_string(),
        "autolock.idle_timeout_minutes" => cfg
            .autolock
            .idle_timeout_minutes
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".to_string()),
        "autolock.max_unlocked_minutes" => cfg
            .autolock
            .max_unlocked_minutes
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".to_string()),
        other => anyhow::bail!("unhandled key: {other}"),
    })
}

/// Validate a config value before writing it, giving the user a clear error
/// rather than silently writing a value the daemon will reject on reload.
fn validate_config_value(key: &str, value: &str) -> Result<()> {
    match key {
        "service.dedup_strategy" => {
            if !matches!(value, "newest" | "priority") {
                anyhow::bail!("invalid value '{value}': must be 'newest' or 'priority'");
            }
        }
        "service.dedup_time_fallback" => {
            if !matches!(value, "created" | "none") {
                anyhow::bail!("invalid value '{value}': must be 'created' or 'none'");
            }
        }
        "autolock.on_logout" | "autolock.on_session_lock" => {
            if !matches!(value, "true" | "false") {
                anyhow::bail!("invalid value '{value}': must be 'true' or 'false'");
            }
        }
        "service.refresh_interval_secs"
        | "autolock.idle_timeout_minutes"
        | "autolock.max_unlocked_minutes" => {
            value.parse::<u64>().map_err(|_| {
                anyhow::anyhow!("invalid value '{value}': must be a non-negative integer")
            })?;
        }
        _ => {}
    }
    Ok(())
}

fn cmd_config_set(key: &str, value: &str) -> Result<()> {
    // Validate the key is in the supported list.
    if !CONFIG_KEYS.iter().any(|(k, _)| *k == key) {
        bail!("unknown config key: {key}\nrun `rosec config --help` to see supported keys");
    }

    // Validate the value before touching the file.
    validate_config_value(key, value)?;

    let path = config_path();
    config_edit::set_value(&path, key, value)?;

    println!("{key} = {value}");
    Ok(())
}

// ---------------------------------------------------------------------------
// rosec item <subcommand>
// ---------------------------------------------------------------------------

async fn cmd_item(action: Option<ItemCommands>) -> Result<()> {
    let action = action.unwrap_or(ItemCommands::List(ItemListArgs {
        provider: None,
        item_type: None,
        format: Format::Table,
        show_path: false,
        sync: false,
        no_unlock: false,
        filters: Vec::new(),
    }));
    match action {
        ItemCommands::List(args) => cmd_item_list(args).await,
        ItemCommands::Add(args) => cmd_item_add(args).await,
        ItemCommands::Edit(args) => cmd_item_edit(args).await,
        ItemCommands::Delete(args) => cmd_item_delete(args).await,
        ItemCommands::Export(args) => cmd_item_export(args).await,
        ItemCommands::Import(args) => cmd_item_import(args).await,
    }
}

/// `rosec item list` — delegates to the search infrastructure with convenience
/// `--provider` and `--type` filters that get merged into the attribute query.
async fn cmd_item_list(args: ItemListArgs) -> Result<()> {
    let format = cli_format_to_output(args.format);
    let show_path = args.show_path;
    let sync = args.sync;
    let no_unlock = args.no_unlock;
    let mut all_attrs: HashMap<String, String> = HashMap::new();

    if let Some(ref prov) = args.provider {
        all_attrs.insert(rosec_core::ATTR_PROVIDER.to_string(), prov.clone());
    }
    if let Some(ref typ) = args.item_type {
        all_attrs.insert(rosec_core::ATTR_TYPE.to_string(), typ.clone());
    }
    for filter in &args.filters {
        if let Some((key, value)) = filter.split_once('=') {
            all_attrs.insert(key.to_string(), value.to_string());
        } else {
            bail!("invalid filter: {filter} (expected key=value)");
        }
    }

    if sync && no_unlock {
        bail!("--sync and --no-unlock are mutually exclusive");
    }

    let conn = conn().await?;
    let rosecd = is_rosecd(&conn).await;
    if rosecd {
        warn_if_no_providers(&conn).await;
    }

    if sync {
        preemptive_sync(&conn).await?;
    }

    let has_globs = all_attrs.values().any(|v| is_glob(v)) || all_attrs.contains_key("name");

    let do_search = |conn: &Connection| {
        let conn = conn.clone();
        let all_attrs = all_attrs.clone();
        async move {
            if has_globs {
                search_with_glob_fallback(&conn, &all_attrs, rosecd, no_unlock).await
            } else {
                search_exact(&conn, &all_attrs, no_unlock).await
            }
        }
    };

    let (unlocked, locked) = match do_search(&conn).await {
        Ok(result) => result,
        Err(e) if sync => {
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            do_search(&conn).await.map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    let needs_unlock = !no_unlock && sync && any_syncable_providers_locked(&conn).await?;
    let (unlocked, locked) = if needs_unlock {
        trigger_unlock(&conn).await?;
        preemptive_sync(&conn).await?;
        do_search(&conn).await?
    } else {
        (unlocked, locked)
    };

    if unlocked.is_empty() && locked.is_empty() {
        if format != OutputFormat::Json {
            println!("No items found.");
        } else {
            println!("[]");
        }
        return Ok(());
    }

    let mut items: Vec<ItemSummary> = Vec::new();
    for path in &unlocked {
        let summary = fetch_item_data(&conn, path, false)
            .await
            .unwrap_or_else(|_| ItemSummary {
                label: path.clone(),
                attrs: HashMap::new(),
                path: path.clone(),
                locked: false,
            });
        items.push(summary);
    }
    for path in &locked {
        let summary = fetch_item_data(&conn, path, true)
            .await
            .unwrap_or_else(|_| ItemSummary {
                label: path.clone(),
                attrs: HashMap::new(),
                path: path.clone(),
                locked: true,
            });
        items.push(summary);
    }

    match format {
        OutputFormat::Human | OutputFormat::Table => print_search_table(&items, show_path),
        OutputFormat::Kv => print_search_kv(&items, show_path),
        OutputFormat::Json => print_search_json(&items)?,
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// TOML template generation for $EDITOR workflow
// ---------------------------------------------------------------------------

/// Generate an ed25519 SSH key pair and return a pre-populated TOML template.
///
/// The private key PEM is placed in `[secrets].private_key` as a multi-line
/// TOML string.  The public key (OpenSSH format) and fingerprint are placed
/// in `[attributes]`.  The user only needs to fill in the label.
fn generate_ssh_key_template() -> Result<String> {
    use ssh_key::{Algorithm, HashAlg, PrivateKey, rand_core::OsRng};

    let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| anyhow::anyhow!("failed to generate SSH key: {e}"))?;

    let pem = private_key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("failed to encode private key as PEM: {e}"))?;

    let public_key = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("failed to encode public key: {e}"))?;

    let fingerprint = private_key.fingerprint(HashAlg::Sha256);

    let pem_str: &str = &pem;

    let mut out = String::new();
    out.push_str("# rosec item — type: ssh-key (generated ed25519 key)\n");
    out.push_str("# Lines starting with '#' are comments and will be ignored.\n");
    out.push_str("# The private key below was generated fresh — fill in the label.\n\n");

    out.push_str("[item]\n");
    out.push_str("label = \"\"\n");
    out.push_str("type = \"ssh-key\"\n\n");

    out.push_str("[attributes]\n");
    out.push_str(&format!("public_key = {}\n", toml_quote(&public_key)));
    out.push_str(&format!("fingerprint = \"{fingerprint}\"\n\n"));

    out.push_str("[secrets]\n");
    out.push_str(&format!("private_key = \"\"\"\n{pem_str}\"\"\"\n"));
    out.push_str("notes = \"\"\n");

    Ok(out)
}

/// Generate a TOML template for a given item type, suitable for editing in $EDITOR.
///
/// The template has three sections: `[item]`, `[attributes]`, `[secrets]`.
/// Comments explain each field.  Empty string values are placeholders the user
/// fills in; they are stripped on parse (empty secrets are not stored).
fn generate_item_template(item_type: &str) -> String {
    match item_type {
        "login" => "\
# rosec item — type: login
# Lines starting with '#' are comments and will be ignored.
# Empty secret values will not be stored.

[item]
label = \"\"
type = \"login\"

[attributes]
username = \"\"
uri = \"\"

[secrets]
password = \"\"
totp = \"\"
notes = \"\"
"
        .to_string(),

        "ssh-key" => "\
# rosec item — type: ssh-key
# Lines starting with '#' are comments and will be ignored.
# Empty secret values will not be stored.
#
# Paste the PEM-encoded private key as the value of 'private_key' below.
# Multi-line values use triple quotes: private_key = \"\"\"...\"\"\"

[item]
label = \"\"
type = \"ssh-key\"

[attributes]
public_key = \"\"
fingerprint = \"\"

[secrets]
private_key = \"\"
notes = \"\"
"
        .to_string(),

        "note" => "\
# rosec item — type: note
# Lines starting with '#' are comments and will be ignored.
# The note body is stored as a secret.
#
# Multi-line notes use triple quotes: secret = \"\"\"...\"\"\"

[item]
label = \"\"
type = \"note\"

[attributes]

[secrets]
secret = \"\"
"
        .to_string(),

        "card" => "\
# rosec item — type: card
# Lines starting with '#' are comments and will be ignored.
# Empty secret values will not be stored.

[item]
label = \"\"
type = \"card\"

[attributes]
cardholder_name = \"\"
brand = \"\"
exp_month = \"\"
exp_year = \"\"

[secrets]
number = \"\"
security_code = \"\"
notes = \"\"
"
        .to_string(),

        "identity" => "\
# rosec item — type: identity
# Lines starting with '#' are comments and will be ignored.
# Empty secret values will not be stored.

[item]
label = \"\"
type = \"identity\"

[attributes]
title = \"\"
first_name = \"\"
middle_name = \"\"
last_name = \"\"
email = \"\"
phone = \"\"
company = \"\"
address1 = \"\"
address2 = \"\"
address3 = \"\"
city = \"\"
state = \"\"
postal_code = \"\"
country = \"\"

[secrets]
ssn = \"\"
passport_number = \"\"
license_number = \"\"
notes = \"\"
"
        .to_string(),

        // generic (default)
        _ => "\
# rosec item — type: generic
# Lines starting with '#' are comments and will be ignored.
# Empty secret values will not be stored.
#
# Add any key = \"value\" pairs you need under [attributes] or [secrets].

[item]
label = \"\"
type = \"generic\"

[attributes]

[secrets]
secret = \"\"
notes = \"\"
"
        .to_string(),
    }
}

/// Parsed result of an item TOML document.
struct ParsedItem {
    label: String,
    item_type: String,
    attributes: HashMap<String, String>,
    /// Secret name → raw bytes (UTF-8 encoded).
    secrets: HashMap<String, Vec<u8>>,
}

/// Parse a TOML document written by the user in $EDITOR into a `ParsedItem`.
///
/// Expects sections `[item]` (with `label` and `type`), `[attributes]`, and
/// `[secrets]`.  Empty string values in `[secrets]` are silently dropped.
fn parse_item_toml(content: &str) -> Result<ParsedItem> {
    let doc: toml::Value = toml::from_str(content)
        .map_err(|e: toml::de::Error| anyhow::anyhow!("failed to parse TOML: {e}"))?;

    let item_table = doc
        .get("item")
        .and_then(|v| v.as_table())
        .ok_or_else(|| anyhow::anyhow!("[item] section is missing or not a table"))?;

    let label = item_table
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if label.is_empty() {
        bail!("item label is required (set label = \"...\" in [item])");
    }

    let raw_type = item_table
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("generic");

    // Validate and normalize the item type (e.g. "sshkey" → "ssh-key").
    let item_type = raw_type
        .parse::<rosec_core::ItemType>()
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .as_str()
        .to_string();

    let mut attributes = HashMap::new();
    if let Some(attrs_table) = doc.get("attributes").and_then(|v| v.as_table()) {
        for (k, v) in attrs_table {
            let val = match v {
                toml::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if !val.is_empty() {
                attributes.insert(k.clone(), val);
            }
        }
    }

    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();
    if let Some(secrets_table) = doc.get("secrets").and_then(|v| v.as_table()) {
        for (k, v) in secrets_table {
            match v {
                // Plain string → UTF-8 bytes (common case: passwords, TOML, notes).
                toml::Value::String(s) => {
                    if !s.is_empty() {
                        secrets.insert(k.clone(), s.as_bytes().to_vec());
                    }
                }
                // Inline table with `base64` key → decode binary secret.
                toml::Value::Table(tbl) => {
                    if let Some(toml::Value::String(b64)) = tbl.get("base64") {
                        use base64::Engine;
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(b64)
                            .map_err(|e| anyhow::anyhow!("secret \"{k}\": invalid base64: {e}"))?;
                        if !bytes.is_empty() {
                            secrets.insert(k.clone(), bytes);
                        }
                    } else {
                        bail!(
                            "secret \"{k}\": inline table must have a \"base64\" key \
                             (e.g. {{ base64 = \"...\" }})"
                        );
                    }
                }
                other => {
                    // Fallback: stringify non-string scalar values.
                    let val = other.to_string();
                    if !val.is_empty() {
                        secrets.insert(k.clone(), val.into_bytes());
                    }
                }
            }
        }
    }

    Ok(ParsedItem {
        label,
        item_type,
        attributes,
        secrets,
    })
}

/// Determine the editor command.  Checks `$VISUAL`, then `$EDITOR`, then
/// falls back to `vi`.
fn editor_command() -> String {
    std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string())
}

/// Open a temp file in the user's editor and return the edited content.
///
/// The file is created with a `.toml` extension so editors enable syntax
/// highlighting.  Returns `None` if the user quit without saving (content
/// unchanged from the initial template) or if the file is empty.
fn open_editor(initial_content: &str) -> Result<Option<String>> {
    use std::io::Write;

    let dir = tempfile::tempdir()?;
    let file_path = dir.path().join("rosec-item.toml");
    {
        let mut f = std::fs::File::create(&file_path)?;
        f.write_all(initial_content.as_bytes())?;
        f.flush()?;
    }

    let editor = editor_command();
    // Split the editor command on whitespace to support e.g. "code --wait".
    let parts: Vec<&str> = editor.split_whitespace().collect();
    let (cmd, cmd_args) = parts.split_first().ok_or_else(|| {
        anyhow::anyhow!("$EDITOR / $VISUAL is empty; set it to your preferred editor")
    })?;

    let status = std::process::Command::new(cmd)
        .args(cmd_args.iter())
        .arg(&file_path)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to launch editor '{editor}': {e}"))?;

    if !status.success() {
        bail!(
            "editor exited with status {} — item not created",
            status.code().unwrap_or(-1)
        );
    }

    let edited = std::fs::read_to_string(&file_path)?;

    // If the user didn't change anything, treat it as abort.
    if edited.trim() == initial_content.trim() || edited.trim().is_empty() {
        return Ok(None);
    }

    Ok(Some(edited))
}

/// `rosec item add` — create a new item via $EDITOR.
///
/// 1. Parse flags (`--provider`, `--type`, `--generate-ssh-key`)
/// 2. Verify write capability via D-Bus `GetCapabilities`
/// 3. Generate a TOML template for the item type
/// 4. Open `$EDITOR` for the user to fill in
/// 5. Parse the edited TOML
/// 6. Call `CreateItemExtended` on `org.rosec.Items`
/// 7. Print the created item path / ID
async fn cmd_item_add(args: ItemAddArgs) -> Result<()> {
    let provider_id = args.provider.unwrap_or_default();
    let mut item_type = args.item_type;
    let generate_ssh_key = args.generate_ssh_key;

    // Validate item type early.
    item_type
        .parse::<rosec_core::ItemType>()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if generate_ssh_key && item_type != "ssh-key" {
        // Auto-set the type when --generate-ssh-key is used without --type.
        if item_type == "generic" {
            item_type = "ssh-key".to_string();
        } else {
            bail!("--generate-ssh-key can only be used with --type=ssh-key");
        }
    }

    let conn = conn().await?;
    if !is_rosecd(&conn).await {
        bail!("rosec item add requires rosecd (the rosec daemon) to be running");
    }

    // Verify the provider supports Write capability.
    let items_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Items",
        "org.rosec.Items",
    )
    .await?;

    let caps: Vec<String> = items_proxy
        .call("GetCapabilities", &(&provider_id,))
        .await?;
    if !caps.iter().any(|c| c == "Write") {
        if provider_id.is_empty() {
            bail!("no write-capable provider available — add a local vault first");
        } else {
            bail!("provider '{provider_id}' does not support writes");
        }
    }

    // Verify the provider supports the requested item type.
    let supported_types: Vec<String> = items_proxy
        .call("GetSupportedItemTypes", &(&provider_id,))
        .await?;
    if !supported_types.is_empty() && !supported_types.contains(&item_type) {
        bail!(
            "provider does not support item type '{item_type}'\nsupported: {}",
            supported_types.join(", ")
        );
    }

    // Generate the TOML template.
    let template = if generate_ssh_key {
        generate_ssh_key_template()?
    } else {
        generate_item_template(&item_type)
    };

    // Open editor and get the result.
    let edited = open_editor(&template)?;
    let content = match edited {
        Some(c) => c,
        None => {
            println!("No changes — item not created.");
            return Ok(());
        }
    };

    let parsed = parse_item_toml(&content)?;

    if parsed.secrets.is_empty() && parsed.attributes.is_empty() {
        bail!("item has no attributes or secrets — nothing to store");
    }

    // Call CreateItemExtended via D-Bus.
    let item_path: String = items_proxy
        .call(
            "CreateItemExtended",
            &(
                &parsed.label,
                &parsed.item_type,
                &parsed.attributes,
                &parsed.secrets,
                false, // replace
            ),
        )
        .await?;

    // Extract the display ID from the path.
    let display_id = item_path
        .rsplit('/')
        .next()
        .and_then(|seg| seg.rsplit('_').next())
        .unwrap_or(&item_path);

    println!("Created item: {} ({})", parsed.label, display_id);
    Ok(())
}

/// Data fetched from an existing item via D-Bus.
struct FetchedItemData {
    label: String,
    item_type: String,
    pub_attrs: HashMap<String, String>,
    /// Secret name → raw bytes (may not be valid UTF-8).
    secrets: Vec<(String, Vec<u8>)>,
}

/// Fetch a full item's data (label, public attributes, secret names + values)
/// from D-Bus.  Unlike `fetch_item_data` (which returns only public metadata),
/// this also retrieves all secret attributes via the `org.rosec.Secrets`
/// extension interface.
async fn fetch_full_item(conn: &zbus::Connection, item_path: &str) -> Result<FetchedItemData> {
    let item_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        item_path,
        "org.freedesktop.Secret.Item",
    )
    .await?;

    let label: String = item_proxy.get_property("Label").await?;
    let pub_attrs: HashMap<String, String> = item_proxy.get_property("Attributes").await?;

    // Normalize through ItemType so legacy strings like "sshkey" become "ssh-key".
    let item_type = rosec_core::ItemType::from_attributes(&pub_attrs)
        .as_str()
        .to_string();

    // Fetch secret attribute names and values via rosec extension.
    let secrets_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Secrets",
        "org.rosec.Secrets",
    )
    .await?;

    let item_obj_path = OwnedObjectPath::try_from(item_path.to_string())
        .map_err(|e| anyhow::anyhow!("invalid item path: {e}"))?;

    let secret_names: Vec<String> = secrets_proxy
        .call("GetSecretAttributeNames", &(&item_obj_path,))
        .await
        .unwrap_or_default();

    let mut secrets: Vec<(String, Vec<u8>)> = Vec::new();
    for name in &secret_names {
        let bytes: Vec<u8> = secrets_proxy
            .call("GetSecretAttribute", &(&item_obj_path, name.as_str()))
            .await
            .unwrap_or_default();
        secrets.push((name.clone(), bytes));
    }

    Ok(FetchedItemData {
        label,
        item_type,
        pub_attrs,
        secrets,
    })
}

/// Build a TOML document from an existing item's data, suitable for editing.
///
/// The document mirrors the template format: `[item]`, `[attributes]`,
/// `[secrets]`.  Internal/reserved attributes (`rosec:type`, `rosec:provider`,
/// `xdg:schema`) are omitted from `[attributes]` since they are handled by
/// `[item].type` or are read-only.
///
/// Secret values that are valid UTF-8 are emitted as plain TOML strings.
/// Binary (non-UTF-8) values are emitted as inline tables:
///   `key = { base64 = "..." }`
/// so that the import side can distinguish and decode them losslessly.
fn build_item_toml(
    label: &str,
    item_type: &str,
    pub_attrs: &HashMap<String, String>,
    secrets: &[(String, Vec<u8>)],
) -> String {
    use base64::Engine;

    let mut out = String::new();

    out.push_str(&format!("# rosec item — type: {item_type}\n"));
    out.push_str("# Lines starting with '#' are comments and will be ignored.\n");
    out.push_str("# Empty secret values will not be stored.\n");
    out.push_str("# Removing a secret key will leave the existing value unchanged.\n\n");

    // [item] section
    out.push_str("[item]\n");
    out.push_str(&format!("label = {}\n", toml_quote(label)));
    out.push_str(&format!(
        "type = \"{}\"    # generic | login | ssh-key | note | card | identity\n\n",
        item_type
    ));

    // [attributes] section — skip reserved/internal attrs
    out.push_str("[attributes]\n");
    let mut sorted_attrs: Vec<_> = pub_attrs
        .iter()
        .filter(|(k, _)| !k.starts_with("rosec:") && !k.starts_with("xdg:"))
        .collect();
    sorted_attrs.sort_by_key(|(k, _)| k.as_str());
    for (k, v) in &sorted_attrs {
        out.push_str(&format!("{} = {}\n", toml_key(k), toml_quote(v)));
    }
    out.push('\n');

    // [secrets] section
    out.push_str("[secrets]\n");
    for (k, v) in secrets {
        let key = toml_key(k);
        match std::str::from_utf8(v) {
            Ok(text) => {
                // Valid UTF-8: emit as a plain TOML string.
                if text.contains('\n') {
                    out.push_str(&format!("{key} = \"\"\"\n{}\"\"\"\n", toml_escape(text)));
                } else {
                    out.push_str(&format!("{key} = {}\n", toml_quote(text)));
                }
            }
            Err(_) => {
                // Binary data: base64-encode into an inline table.
                let encoded = base64::engine::general_purpose::STANDARD.encode(v);
                out.push_str(&format!("{key} = {{ base64 = \"{}\" }}\n", encoded));
            }
        }
    }

    out
}

/// TOML-safe quoting: wraps in double quotes, escaping backslashes, quotes,
/// and control characters (which are not allowed unescaped in TOML basic
/// strings).
fn toml_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{0008}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            // All other control characters (U+0000..U+001F, U+007F) must use
            // the \uXXXX escape.
            c if c.is_control() => {
                let cp = c as u32;
                if cp <= 0xFFFF {
                    out.push_str(&format!("\\u{cp:04X}"));
                } else {
                    out.push_str(&format!("\\U{cp:08X}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Escape a string for use inside TOML triple-quoted (multi-line basic)
/// strings.  Newlines are preserved, but control characters and backslashes
/// are escaped.
fn toml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push('\n'), // preserved in multi-line strings
            '\u{000C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                let cp = c as u32;
                if cp <= 0xFFFF {
                    out.push_str(&format!("\\u{cp:04X}"));
                } else {
                    out.push_str(&format!("\\U{cp:08X}"));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// TOML-safe key: bare keys may only contain `[A-Za-z0-9_-]`.  Anything else
/// (e.g. dots, colons) must be quoted.
fn toml_key(k: &str) -> String {
    if k.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        k.to_string()
    } else {
        toml_quote(k)
    }
}

/// `rosec item edit` — edit an existing item via $EDITOR.
///
/// 1. Resolve the item path
/// 2. Fetch label, public attributes, secret attribute names + values
/// 3. Build a TOML document
/// 4. Open $EDITOR
/// 5. Parse the edited TOML
/// 6. Call UpdateItem via D-Bus
async fn cmd_item_edit(args: ItemEditArgs) -> Result<()> {
    let sync = args.sync;
    let raw = args.item.as_str();

    let conn = conn().await?;
    if !is_rosecd(&conn).await {
        bail!("rosec item edit requires rosecd (the rosec daemon) to be running");
    }

    if sync {
        preemptive_sync(&conn).await?;
    }

    // Resolve the item path.
    let (path, is_locked) = match resolve_item_path(&conn, raw).await {
        Ok(result) => result,
        Err(e) if sync => {
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            resolve_item_path(&conn, raw).await.map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    if is_locked {
        trigger_unlock(&conn).await?;
        if sync {
            preemptive_sync(&conn).await?;
        }
    }

    // Fetch current item data.
    let fetched = fetch_full_item(&conn, &path).await?;

    // Build the TOML document.
    let toml_content = build_item_toml(
        &fetched.label,
        &fetched.item_type,
        &fetched.pub_attrs,
        &fetched.secrets,
    );

    // Open editor.
    let edited = open_editor(&toml_content)?;
    let content = match edited {
        Some(c) => c,
        None => {
            println!("No changes — item not updated.");
            return Ok(());
        }
    };

    let parsed = parse_item_toml(&content)?;

    // Call UpdateItem via D-Bus.
    let items_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Items",
        "org.rosec.Items",
    )
    .await?;

    let _: () = items_proxy
        .call(
            "UpdateItem",
            &(
                path.as_str(),
                parsed.label.as_str(),
                parsed.item_type.as_str(),
                &parsed.attributes,
                &parsed.secrets,
            ),
        )
        .await?;

    let display_id = path
        .rsplit('/')
        .next()
        .and_then(|seg| seg.rsplit('_').next())
        .unwrap_or(&path);

    println!("Updated item: {} ({})", parsed.label, display_id);
    Ok(())
}

/// `rosec item delete` — delete an item with confirmation.
///
/// 1. Resolve the item path
/// 2. Fetch label for the confirmation prompt
/// 3. Prompt for confirmation (unless `--yes` / `-y`)
/// 4. Call DeleteItem via D-Bus
async fn cmd_item_delete(args: ItemDeleteArgs) -> Result<()> {
    let sync = args.sync;
    let yes = args.yes;
    let raw = args.item.as_str();

    let conn = conn().await?;
    if !is_rosecd(&conn).await {
        bail!("rosec item delete requires rosecd (the rosec daemon) to be running");
    }

    if sync {
        preemptive_sync(&conn).await?;
    }

    // Resolve the item path.
    let (path, is_locked) = match resolve_item_path(&conn, raw).await {
        Ok(result) => result,
        Err(e) if sync => {
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            resolve_item_path(&conn, raw).await.map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    if is_locked {
        trigger_unlock(&conn).await?;
        if sync {
            preemptive_sync(&conn).await?;
        }
    }

    // Fetch the label so we can show a meaningful confirmation.
    let item_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        path.as_str(),
        "org.freedesktop.Secret.Item",
    )
    .await?;

    let label: String = item_proxy
        .get_property("Label")
        .await
        .unwrap_or_else(|_| "<unknown>".to_string());

    let display_id = path
        .rsplit('/')
        .next()
        .and_then(|seg| seg.rsplit('_').next())
        .unwrap_or(&path);

    // Confirmation prompt.
    if !yes {
        eprint!("Delete item '{}' ({})? [y/N] ", label, display_id);
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        let answer = line.trim().to_lowercase();
        if answer != "y" && answer != "yes" {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Call DeleteItem via D-Bus.
    let items_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Items",
        "org.rosec.Items",
    )
    .await?;

    let _: () = items_proxy.call("DeleteItem", &(path.as_str(),)).await?;

    println!("Deleted item: {} ({})", label, display_id);
    Ok(())
}

/// `rosec item export` — export an item as TOML to stdout.
///
/// The output uses the same `[item]`/`[attributes]`/`[secrets]` format as
/// the editor workflow, so it can be piped into `rosec item import` or
/// redirected to a file for backup.
async fn cmd_item_export(args: ItemExportArgs) -> Result<()> {
    let sync = args.sync;
    let raw = args.item.as_str();

    let conn = conn().await?;
    if !is_rosecd(&conn).await {
        bail!("rosec item export requires rosecd (the rosec daemon) to be running");
    }

    if sync {
        preemptive_sync(&conn).await?;
    }

    // Resolve the item path.
    let (path, is_locked) = match resolve_item_path(&conn, raw).await {
        Ok(result) => result,
        Err(e) if sync => {
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            resolve_item_path(&conn, raw).await.map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    if is_locked {
        trigger_unlock(&conn).await?;
        if sync {
            preemptive_sync(&conn).await?;
        }
    }

    // Fetch item data including secrets.
    let fetched = fetch_full_item(&conn, &path).await?;

    // Build TOML and write to stdout.
    let toml_content = build_item_toml(
        &fetched.label,
        &fetched.item_type,
        &fetched.pub_attrs,
        &fetched.secrets,
    );
    print!("{toml_content}");

    Ok(())
}

/// `rosec item import` — import an item from TOML on stdin.
///
/// Reads the same `[item]`/`[attributes]`/`[secrets]` TOML format produced
/// by `rosec item export`.  Creates the item via `CreateItemExtended` on
/// the specified (or default write-capable) provider.
async fn cmd_item_import(args: ItemImportArgs) -> Result<()> {
    let provider_id = args.provider.unwrap_or_default();

    // Read TOML from stdin.
    let mut content = String::new();
    io::stdin().lock().read_to_string(&mut content)?;

    if content.trim().is_empty() {
        bail!("no input on stdin — pipe a TOML document or redirect a file");
    }

    let parsed = parse_item_toml(&content)?;

    if parsed.secrets.is_empty() && parsed.attributes.is_empty() {
        bail!("item has no attributes or secrets — nothing to store");
    }

    let conn = conn().await?;
    if !is_rosecd(&conn).await {
        bail!("rosec item import requires rosecd (the rosec daemon) to be running");
    }

    // Verify the provider supports Write capability.
    let items_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Items",
        "org.rosec.Items",
    )
    .await?;

    let caps: Vec<String> = items_proxy
        .call("GetCapabilities", &(&provider_id,))
        .await?;
    if !caps.iter().any(|c| c == "Write") {
        if provider_id.is_empty() {
            bail!("no write-capable provider available — add a local vault first");
        } else {
            bail!("provider '{provider_id}' does not support writes");
        }
    }

    // Verify the provider supports the item type.
    let supported_types: Vec<String> = items_proxy
        .call("GetSupportedItemTypes", &(&provider_id,))
        .await?;
    if !supported_types.is_empty() && !supported_types.contains(&parsed.item_type) {
        bail!(
            "provider does not support item type '{}'\nsupported: {}",
            parsed.item_type,
            supported_types.join(", ")
        );
    }

    // Call CreateItemExtended via D-Bus.
    let item_path: String = items_proxy
        .call(
            "CreateItemExtended",
            &(
                &parsed.label,
                &parsed.item_type,
                &parsed.attributes,
                &parsed.secrets,
                false, // replace
            ),
        )
        .await?;

    // Extract the display ID from the path.
    let display_id = item_path
        .rsplit('/')
        .next()
        .and_then(|seg| seg.rsplit('_').next())
        .unwrap_or(&item_path);

    // Print to stderr so stdout stays clean for piping.
    eprintln!("Imported item: {} ({})", parsed.label, display_id);
    Ok(())
}
