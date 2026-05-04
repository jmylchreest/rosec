use std::collections::HashMap;
use std::io::{self, BufRead};
use std::path::PathBuf;

use clap::Parser;

use anyhow::{Result, bail};
use zbus::Connection;
use zeroize::Zeroizing;
use zvariant::OwnedObjectPath;

use rosec_core::config::Config;

mod cli;
mod config;
mod enable;
mod get;
mod inspect;
mod item;
mod lock;
mod provider;
mod search;
mod status;
mod sync;
mod totp;
mod unlock;

use cli::*;

/// D-Bus wire type for `org.rosec.Daemon.ProviderList` entries.
///
/// Fields: `(id, name, kind, locked, cached, offline_cache, last_cache_write_epoch, last_sync_epoch, capabilities)`.
pub(crate) type ProviderEntry = (
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
        Commands::Provider { action } => provider::dispatch(action).await,
        Commands::Config { action } => config::dispatch(action),
        Commands::Status => status::run().await,
        Commands::Sync => sync::run().await,
        Commands::Search(args) => search::run(args).await,
        Commands::Item { action } => item::dispatch(action).await,
        Commands::Get(args) => get::run(args).await,
        Commands::Totp(cmd) => totp::dispatch(cmd).await,
        Commands::Inspect(args) => inspect::run(args).await,
        Commands::Lock => lock::run().await,
        Commands::Unlock => unlock::run().await,
        Commands::Enable(args) => enable::cmd_enable(args),
        Commands::Disable(args) => enable::cmd_disable(args),
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Command implementations
// ───────────────────────────────────────────────────────────────────────────

pub(crate) async fn conn() -> Result<Connection> {
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

/// Resolve the config file path from `--config <path>` flag or XDG default.
pub(crate) fn config_path() -> PathBuf {
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

pub(crate) fn load_config() -> Config {
    let path = config_path();
    if !path.exists() {
        return Config::default();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

//
// These functions are used by `cmd_provider_add` to collect non-secret
// configuration values (email address, region, base_url, etc.) that go into
// config.toml.  Credential prompting (passwords, tokens) is handled entirely
// inside `rosecd` via `UnlockWithTty` / `AuthProviderWithTty` — the TTY fd is
// passed via D-Bus fd-passing so credentials never appear in any D-Bus message.

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
pub(crate) async fn try_lazy_unlock(conn: &Connection, err: &zbus::Error) -> Result<bool> {
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
pub(crate) async fn trigger_unlock(conn: &Connection) -> Result<()> {
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

/// Open `/dev/tty` and return it as a `zvariant::OwnedFd` for D-Bus fd-passing.
///
/// The returned `OwnedFd` can be passed directly to `UnlockWithTty` /
/// `AuthProviderWithTty`.  `dbus-monitor` sees only the fd number, never the
/// terminal contents.
pub(crate) fn open_tty_owned_fd() -> Result<zvariant::OwnedFd> {
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
pub(crate) fn password_to_pipe_fd(password: &[u8]) -> Result<zvariant::OwnedFd> {
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
pub(crate) async fn prompt_field(
    label: &str,
    placeholder: &str,
    kind: &str,
) -> Result<Zeroizing<String>> {
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

// (provider subcommand tree moved to rosec/src/provider/)

// (status / sync subcommand moved to rosec/src/{status,sync}.rs)

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
pub(crate) async fn preemptive_sync(conn: &Connection) -> Result<()> {
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
pub(crate) async fn any_syncable_providers_locked(conn: &Connection) -> Result<bool> {
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
pub(crate) enum OutputFormat {
    Human,
    Table,
    Kv,
    Json,
}

/// Convert a clap `Format` enum to the internal `OutputFormat`.
pub(crate) fn cli_format_to_output(f: Format) -> OutputFormat {
    match f {
        Format::Human => OutputFormat::Human,
        Format::Table => OutputFormat::Table,
        Format::Kv => OutputFormat::Kv,
        Format::Json => OutputFormat::Json,
    }
}

/// All data fetched for a single search result item.
pub(crate) struct ItemSummary {
    pub(crate) label: String,
    pub(crate) attrs: HashMap<String, String>,
    pub(crate) path: String,
    pub(crate) locked: bool,
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
pub(crate) fn is_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

/// Spec-compliant exact-match search via `org.freedesktop.Secret.Service.SearchItems`.
/// Handles lazy-unlock automatically unless `no_unlock` is set.
pub(crate) async fn search_exact(
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
pub(crate) async fn is_rosecd(conn: &Connection) -> bool {
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
pub(crate) async fn warn_if_no_providers(conn: &Connection) {
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
pub(crate) async fn search_with_glob_fallback(
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

// (search subcommand moved to rosec/src/search.rs)

/// Fetch Label and Attributes for an item into a structured summary.
pub(crate) async fn fetch_item_data(
    conn: &zbus::Connection,
    path: &str,
    locked: bool,
) -> Result<ItemSummary> {
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
pub(crate) fn format_relative_time(epoch_secs: u64, now_epoch: u64) -> String {
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
pub(crate) fn capability_codes(caps: &[String]) -> String {
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

pub(crate) fn trunc(s: &str, max: usize) -> String {
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
pub(crate) fn terminal_width() -> usize {
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
pub(crate) struct ColSpec {
    /// Natural width: max(content_width, header_width).
    pub(crate) natural: usize,
    /// Minimum width the column can be shrunk to (header width).
    pub(crate) min: usize,
    /// Allocated width after fitting to terminal.
    pub(crate) allocated: usize,
}

/// Fit columns into `avail` characters.
///
/// Each column starts at its natural (content-driven) width and is never
/// expanded beyond that.  When the total exceeds `avail`, columns are shrunk
/// starting from the **end** of the `cols` slice — so put the highest-priority
/// (last-to-shrink) columns first.
///
/// Returns `true` if everything fit without any truncation.
pub(crate) fn fit_columns(cols: &mut [ColSpec], gap: usize, avail: usize) -> bool {
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
pub(crate) fn print_search_table(items: &[ItemSummary], show_path: bool) {
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
pub(crate) fn print_search_kv(items: &[ItemSummary], show_path: bool) {
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
pub(crate) fn print_search_json(items: &[ItemSummary]) -> Result<()> {
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
pub(crate) async fn resolve_item_path(conn: &Connection, raw: &str) -> Result<(String, bool)> {
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

// (get / inspect / lock / unlock subcommands moved to rosec/src/{get,inspect,lock,unlock}.rs)

// (config subcommand tree moved to rosec/src/config/)

// (item subcommand tree moved to rosec/src/item/)
