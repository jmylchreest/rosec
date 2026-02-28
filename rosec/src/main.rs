use std::collections::HashMap;
use std::io::{self, BufRead};
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use anyhow::{Result, bail};
use zbus::Connection;
use zeroize::Zeroizing;
use zvariant::{OwnedObjectPath, OwnedValue};

use rosec_core::VaultBackend as _;
use rosec_core::config::Config;
use rosec_core::config_edit;

#[tokio::main]
async fn main() -> Result<()> {
    // Reset SIGPIPE to default so piping output to `head` etc. exits cleanly
    // instead of panicking with "broken pipe".
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    match cmd {
        // vault / vaults are full aliases for the same subcommand tree
        "vault" | "vaults" => cmd_vault(&args[1..]).await,
        // backend / backends are full aliases for the same subcommand tree
        "backend" | "backends" => cmd_backend(&args[1..]).await,
        "config" => cmd_config(&args[1..]),
        "status" => cmd_status().await,
        "sync" | "refresh" => cmd_sync().await,
        "search" => cmd_search(&args[1..]).await,
        "get" => cmd_get(&args[1..]).await,
        "inspect" => cmd_inspect(&args[1..]).await,
        "lock" => cmd_lock().await,
        "unlock" => cmd_unlock().await,
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}");
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_help() {
    println!(
        "\
rosec - read-only secret service CLI

USAGE:
    rosec <command> [args...]

COMMANDS:
    vault <subcommand>                  Manage local encrypted vaults (alias: vaults)
      list                              List configured vaults and their state
      create [--id <id>] [--path <p>]   Create a new vault (prompts for password)
      attach --path <file> [--id <id>]  Attach an existing vault file to the config
      detach <id>                       Remove a vault from config (file stays on disk)
      destroy <id>                      Remove a vault from config AND delete the file
      add-password <id>                 Add a new unlock password to a vault
      remove-password <id> <entry-id>   Remove a password from a vault
      list-passwords <id>               List unlock passwords for a vault
      auth <id>                         Authenticate/unlock a vault

    backend <subcommand>                Manage external backends (alias: backends)
      list                              List configured backends and their lock state
      auth <id>                         Authenticate/unlock a backend
      add <kind> [options]              Add a backend to the config file
      remove <id>                       Remove a backend from the config file

    config <subcommand>                 Read or modify config.toml
      show                              Print the current effective configuration
      get <key>                         Print the value of one setting (e.g. autolock.idle_timeout_minutes)
      set <key> <value>                 Update a setting in config.toml (daemon hot-reloads automatically)

    status                              Show daemon status
    sync                                Sync vault with remote server (alias: refresh)
    search [-s] [--format=<fmt>] [--show-path] [key=value]...
                                        Search items by attributes (no args = list all)
    get <id>                            Print the secret value only (pipeable)
    inspect <id>                        Show full item detail: label, attributes, secret
    lock                                Lock all backends
    unlock                              Unlock (triggers GUI/TTY prompt)
    help                                Show this help

BACKEND KINDS:
    bitwarden                           Bitwarden Password Manager
    bitwarden-sm                        Bitwarden Secrets Manager

OUTPUT FORMATS (--format):
    table                               Aligned columns: TYPE | NAME | USERNAME | URI | ID  [default]
    kv                                  Key=value pairs, one attribute per line per item
    json                                JSON array of objects (always includes full path)

FLAGS:
    --show-path                         Also print the full D-Bus object path for each item
                                        (useful when calling GetSecret directly via D-Bus/libsecret)

SEARCH FILTERS:
    Pass one or more key=value pairs to filter by public attributes:
      type=login                        Only login items
      username=alice                    Items with username 'alice'
      type=login username=alice         Combine filters (AND)
      uri=github.com                    Items with a matching URI attribute

    Common attribute names: type, username, uri, folder, name

NOTES:
    If a backend is locked when running 'search' or 'get', you will be
    prompted for credentials automatically and the operation retried.

    The 16-char hex ID shown in 'search' output is unique and stable.
    Pass it directly to 'rosec get'.

EXAMPLES:
    rosec vault create                                      # create a new vault (auto ID + path)
    rosec vault create --id work --path ~/vaults/work.vault # custom ID and path
    rosec vault attach --path /mnt/shared/team.vault        # attach an existing vault file
    rosec vault list                                        # show all vaults
    rosec vault auth personal                               # unlock a vault
    rosec vault add-password personal                       # add a second unlock password
    rosec vault remove-password personal <entry-id>         # remove a password
    rosec vault detach work                                 # remove from config (file stays)
    rosec vault destroy old-vault                           # remove from config AND delete file

    rosec backend list
    rosec backend add bitwarden email=you@example.com       # ID auto-generated from email
    rosec backend add bitwarden-sm organization_id=uuid
    rosec backend add bitwarden --id work email=work@corp.com region=eu
    rosec backend auth bitwarden-3f8a1c2d
    rosec backend remove bitwarden-3f8a1c2d
    rosec backends list        # 'backends' is a full alias for 'backend'

    rosec search                                            # list all items
    rosec search type=login                                 # only login items
    rosec search username=alice                             # search by username
    rosec search type=login username=alice                  # combine filters
    rosec search --format=json type=login                   # JSON output (includes path)
    rosec search --format=kv uri=github.com                 # key=value output
    rosec search --show-path type=login                     # table with D-Bus path column
    rosec search -s type=login                             # sync/unlock, then search

    rosec get a1b2c3d4e5f60718                              # print secret value only (pipeable)
    rosec get a1b2c3d4e5f60718 | xclip -sel clip            # copy secret to clipboard

    rosec inspect a1b2c3d4e5f60718                          # full label + attributes + secret
    rosec inspect -s a1b2c3d4e5f60718                       # sync/unlock then inspect
    rosec inspect -s --all-attrs a1b2c3d4e5f60718           # include sensitive attrs (password, totp…)
    rosec inspect --all-attrs --format=json a1b2c3d4e5f60718 # JSON with all attrs
    rosec inspect /org/freedesktop/secrets/collection/default/… # full D-Bus path"
    );
}

fn print_search_help() {
    println!(
        "\
rosec search - search vault items by attribute

USAGE:
    rosec search [flags] [key=value]...

FLAGS:
    -s, --sync          Sync backends before searching; also unlocks if needed
    --format=<fmt>      Output format: table (default), kv, json
    --show-path         Include the full D-Bus object path in output
    --help, -h          Show this help

SEARCH FILTERS:
    Pass one or more key=value pairs to filter by public attributes (AND semantics).
    Glob metacharacters (*, ?, [...]) are accepted.
    The special key 'name' matches the item label.

EXAMPLES:
    rosec search                                    list all items
    rosec search -s                                 sync first, then list all
    rosec search type=login                         only login items
    rosec search username=alice                     items with username 'alice'
    rosec search type=login username=alice          combine filters
    rosec search name=\"GitHub*\"                     glob on item name
    rosec search --format=json type=login           JSON output
    rosec search --format=kv uri=github.com         key=value output
    rosec search --show-path type=login             table with D-Bus path column"
    );
}

fn print_inspect_help() {
    println!(
        "\
rosec inspect - show full item detail

USAGE:
    rosec inspect [flags] <id>

ARGUMENTS:
    <id>                16-char hex item ID or full D-Bus object path

FLAGS:
    -a, --all-attrs     Also fetch and display sensitive attributes (password, totp,
                        notes, card number, custom fields, etc.)
    -s, --sync          Sync backends before inspecting; also unlocks if the item is
                        not yet in the cache (e.g. after a fresh daemon start)
    --format=<fmt>      Output format: human (default), kv, json
    --help, -h          Show this help

OUTPUT FORMATS:
    human               Labelled sections with public and (if --all-attrs) sensitive attrs
    kv                  Flat key=value pairs — one per line, pipe-friendly
    json                JSON object with 'attributes', 'sensitive_attributes', and 'secret'

EXAMPLES:
    rosec inspect a1b2c3d4e5f60718
    rosec inspect -s a1b2c3d4e5f60718
    rosec inspect -s --all-attrs a1b2c3d4e5f60718
    rosec inspect --all-attrs --format=kv a1b2c3d4e5f60718
    rosec inspect --all-attrs --format=json a1b2c3d4e5f60718"
    );
}

fn print_backend_help() {
    println!(
        "\
rosec backend - manage vault backends

USAGE:
    rosec backend <subcommand> [args...]
    rosec backends <subcommand> [args...]   (alias)

SUBCOMMANDS:
    list                      List backends and their lock state
    kinds                     List available backend kinds
    auth <id>                 Authenticate/unlock a backend
    add <kind> [options]      Add a backend to config.toml
    remove <id>               Remove a backend from config.toml

NOTE:
    Device registration (Bitwarden) and first-time token setup (SM) are handled
    automatically during 'auth' when the backend requires them.

OPTIONS for 'add':
    --id <id>                 Override auto-generated ID (default: derived from email/org)
    key=value ...             Backend options (email, region, base_url, etc.)
    --config <path>           Config file to edit (default: ~/.config/rosec/config.toml)"
    );
}

fn cmd_backend_kinds() {
    println!("Available backend kinds:\n");
    for kind in config_edit::KNOWN_KINDS {
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
}

async fn conn() -> Result<Connection> {
    Ok(Connection::session().await?)
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
// These functions are used by `cmd_backend_add` to collect non-secret
// configuration values (email address, region, base_url, etc.) that go into
// config.toml.  Credential prompting (passwords, tokens) is handled entirely
// inside `rosecd` via `UnlockWithTty` / `AuthBackendWithTty` — the TTY fd is
// passed via D-Bus fd-passing so credentials never appear in any D-Bus message.

// ---------------------------------------------------------------------------
// Lazy-unlock: detect "locked::<backend_id>" D-Bus errors and prompt
// ---------------------------------------------------------------------------

/// Extract a `"locked::<backend_id>"` backend ID from a `zbus::Error`, if present.
///
/// The daemon returns `org.freedesktop.DBus.Error.Failed("locked::<id>")` when
/// a backend needs interactive authentication.  This helper parses that sentinel
/// and returns `Some(backend_id)` or `None`.
fn extract_locked_backend(err: &zbus::Error) -> Option<String> {
    if let zbus::Error::MethodError(_, Some(detail), _) = err {
        let msg = detail.as_str();
        if let Some(id) = msg.strip_prefix("locked::") {
            return Some(id.to_string());
        }
    }
    None
}

/// Attempt to interactively unlock a backend after receiving a `"locked::<id>"`
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
/// Returns `Ok(true)` if the backend was successfully unlocked (caller should
/// retry the original operation).  Returns `Ok(false)` if the error was not a
/// locked sentinel (caller should propagate the original error).
async fn try_lazy_unlock(conn: &Connection, err: &zbus::Error) -> Result<bool> {
    // Only trigger for the locked sentinel — not for generic errors.
    if extract_locked_backend(err).is_none() {
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
    // prompt_path == "/" means everything was already unlocked (auto-unlock backends).
    let collection_path =
        OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default".to_string())?;
    let (_, prompt_path): (Vec<OwnedObjectPath>, OwnedObjectPath) = service_proxy
        .call("Unlock", &(vec![collection_path],))
        .await?;
    let prompt_path = prompt_path.to_string();

    if prompt_path == "/" {
        // Already unlocked (auto-unlock backends recovered silently).
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
            let _: Result<bool, _> = daemon_proxy.call("CancelPrompt", &(&prompt_path,)).await;
            bail!("cancelled by user");
        }
    };

    if dismissed {
        bail!("unlock cancelled or failed");
    }

    // Unlock succeeded.  Trigger a cache sync so the retry finds items.
    // Use the daemon proxy for SyncBackend; need to look up which backend unlocked.
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
/// `AuthBackendWithTty`.  `dbus-monitor` sees only the fd number, never the
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

/// Read one line from `fd` with terminal echo disabled.
///
/// Flushes any stale input (via `TCSAFLUSH`), saves the current `termios`,
/// clears `ECHO`/`ECHONL`, reads a line, then restores the original settings.
/// The returned string has the trailing newline stripped.
///
/// The read buffer is `Zeroizing<Vec<u8>>` so the raw bytes are scrubbed on
/// drop — no plain copy of the secret ever lingers on the heap.
#[cfg(unix)]
fn read_hidden(fd: std::os::unix::io::RawFd) -> io::Result<Zeroizing<String>> {
    use std::os::unix::io::FromRawFd as _;

    // Save current termios.
    // SAFETY: fd is valid (we just opened it) and term is properly initialised.
    let orig = unsafe {
        let mut term = std::mem::MaybeUninit::<libc::termios>::uninit();
        if libc::tcgetattr(fd, term.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        term.assume_init()
    };

    let mut noecho = orig;
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

    // Always restore original settings (including echo) before propagating errors.
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };

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
// backend / backends subcommand tree
// ---------------------------------------------------------------------------

async fn cmd_backend(args: &[String]) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    match sub {
        "list" | "ls" => cmd_backend_list().await,
        "auth" => cmd_backend_auth(&args[1..]).await,
        "add" => cmd_backend_add(&args[1..]).await,
        "remove" | "rm" => cmd_backend_remove(&args[1..]).await,
        "kinds" => {
            cmd_backend_kinds();
            Ok(())
        }
        "help" | "--help" | "-h" => {
            print_backend_help();
            Ok(())
        }
        other => {
            eprintln!("unknown backend subcommand: {other}");
            print_backend_help();
            std::process::exit(1);
        }
    }
}

/// `rosec backend list` — show all configured backends with lock state.
async fn cmd_backend_list() -> Result<()> {
    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let entries: Vec<(String, String, String, bool)> = proxy.call("BackendList", &()).await?;

    if entries.is_empty() {
        println!("No backends configured. Run `rosec backend add <kind>` to add one.");
        return Ok(());
    }

    let id_w = entries
        .iter()
        .map(|(id, ..)| id.len())
        .max()
        .unwrap_or(2)
        .max(2);
    let name_w = entries
        .iter()
        .map(|(_, n, ..)| n.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let kind_w = entries
        .iter()
        .map(|(_, _, k, _)| k.len())
        .max()
        .unwrap_or(4)
        .max(4);

    println!(
        "{:<id_w$}  {:<name_w$}  {:<kind_w$}  STATE",
        "ID", "NAME", "KIND",
    );
    println!("{}", "-".repeat(id_w + name_w + kind_w + 14));
    for (id, name, kind, locked) in &entries {
        println!(
            "{:<id_w$}  {:<name_w$}  {:<kind_w$}  {}",
            id,
            name,
            kind,
            if *locked { "locked" } else { "unlocked" },
        );
    }
    Ok(())
}

/// `rosec backend auth <id>` — interactively authenticate a backend.
///
/// Opens `/dev/tty` and passes the fd to `rosecd` via D-Bus fd-passing.
/// All credential prompting happens inside the daemon — credentials never
/// appear in any D-Bus message payload.
async fn cmd_backend_auth(args: &[String]) -> Result<()> {
    let backend_id = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: rosec backend auth <backend-id>"))?;

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
        .call("AuthBackendWithTty", &(backend_id.as_str(), tty_fd))
        .await?;

    println!("Backend '{backend_id}' authenticated.");
    Ok(())
}

/// `rosec backend add <kind> [--id <id>] [key=value ...]`
async fn cmd_backend_add(args: &[String]) -> Result<()> {
    let kind = args.first().ok_or_else(|| {
        anyhow::anyhow!(
            "usage: rosec backend add <kind> [--id <id>] [key=value ...]\nKinds: {}",
            config_edit::KNOWN_KINDS.join(", ")
        )
    })?;

    if !config_edit::KNOWN_KINDS.contains(&kind.as_str()) {
        bail!(
            "unknown backend kind '{kind}'. Known kinds: {}",
            config_edit::KNOWN_KINDS.join(", ")
        );
    }

    // Parse --id <id> and key=value pairs from remaining args.
    let mut custom_id: Option<String> = None;
    let mut options: Vec<(String, String)> = Vec::new();
    let mut i = 1usize;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--id" {
            i += 1;
            custom_id = Some(
                args.get(i)
                    .ok_or_else(|| anyhow::anyhow!("--id requires a value"))?
                    .clone(),
            );
        } else if let Some(id_val) = arg.strip_prefix("--id=") {
            custom_id = Some(id_val.to_string());
        } else if let Some((k, v)) = arg.split_once('=')
            && !k.starts_with("--config")
        {
            options.push((k.to_string(), v.to_string()));
        }
        i += 1;
    }

    // Snapshot the keys already supplied on the command line.
    let supplied: std::collections::HashSet<String> =
        options.iter().map(|(k, _)| k.clone()).collect();

    // Collect required options first — we need them to auto-generate the ID.
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

    // Determine the backend ID: explicit --id wins; otherwise derive from credentials.
    let id = match custom_id {
        Some(ref id) => id.clone(),
        None => derive_backend_id(kind, &options),
    };

    // Prompt for optional options not already supplied.
    let supplied_after_required: std::collections::HashSet<String> =
        options.iter().map(|(k, _)| k.clone()).collect();
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

    let cfg = config_path();
    config_edit::add_backend(&cfg, &id, kind, &options)?;
    println!("Added backend '{id}' (kind: {kind}) to {}", cfg.display());

    // If rosecd is running, wait for it to hot-reload the new backend then
    // immediately kick off the auth flow so the user doesn't have to run
    // `rosec backend auth <id>` manually as a separate step.
    if let Ok(conn) = conn().await {
        if let Ok(proxy) = zbus::Proxy::new(
            &conn,
            "org.freedesktop.secrets",
            "/org/rosec/Daemon",
            "org.rosec.Daemon",
        )
        .await
        {
            // Poll BackendList until the new backend ID appears (hot-reload
            // debounces at 500 ms) or we give up after 3 s.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            let appeared = loop {
                if let Ok(entries) = proxy
                    .call::<_, _, Vec<(String, String, String, bool)>>("BackendList", &())
                    .await
                    && entries.iter().any(|(bid, ..)| bid == &id)
                {
                    break true;
                }
                if std::time::Instant::now() >= deadline {
                    break false;
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            };

            if appeared {
                println!("rosecd picked up the new backend — starting authentication.");
                let tty_fd = open_tty_owned_fd()?;
                let _: () = proxy
                    .call("AuthBackendWithTty", &(id.as_str(), tty_fd))
                    .await?;
                println!("Backend '{id}' authenticated.");
            } else {
                println!("rosecd will hot-reload the config automatically if it is running.");
                println!("Run `rosec backend auth {id}` to authenticate.");
            }
        } else {
            println!("rosecd will hot-reload the config automatically if it is running.");
            println!("Run `rosec backend auth {id}` to authenticate.");
        }
    } else {
        println!("rosecd is not running — start it, then run `rosec backend auth {id}`.");
    }

    Ok(())
}

/// Derive a short, stable backend ID from the credential that identifies the account.
///
/// Format: `{kind}-{first8hexchars of sha256(credential)}`
///
/// - `bitwarden`: hashes the email address
/// - `bitwarden-sm`: hashes the organization_id
/// - anything else: falls back to the kind string itself
fn derive_backend_id(kind: &str, options: &[(String, String)]) -> String {
    let credential_key = match kind {
        "bitwarden" => "email",
        "bitwarden-sm" => "organization_id",
        _ => return kind.to_string(),
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

/// `rosec backend remove <id>`
async fn cmd_backend_remove(args: &[String]) -> Result<()> {
    let id = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: rosec backend remove <id>"))?;
    let cfg = config_path();
    config_edit::remove_backend(&cfg, id)?;
    println!("Removed backend '{id}' from {}", cfg.display());
    println!("rosecd will hot-reload the config automatically if it is running.");
    Ok(())
}

// ---------------------------------------------------------------------------
// vault / vaults subcommand tree
// ---------------------------------------------------------------------------

fn print_vault_help() {
    println!(
        "\
rosec vault - manage local encrypted vaults

USAGE:
    rosec vault <subcommand> [args...]
    rosec vaults <subcommand> [args...]   (alias)

SUBCOMMANDS:
    list                              List configured vaults and their state
    create [--id <id>] [--path <p>] [--collection <c>]
                                      Create a new vault (prompts for password)
    attach --path <file> [--id <id>] [--collection <c>]
                                      Attach an existing vault file to the config
    detach <id>                       Remove vault from config (file stays on disk)
    destroy <id>                      Remove vault from config AND delete the file
    add-password <id> [--label <l>]   Add a new unlock password to a vault
    remove-password <id> <entry-id>   Remove a password from a vault
    list-passwords <id>               List unlock passwords for a vault
    auth <id>                         Authenticate/unlock a vault

OPTIONS:
    --id <id>             Vault identifier (default: derived from path)
    --path <path>         Path to the vault file (default: $XDG_DATA_HOME/rosec/vaults/<id>.vault)
    --collection <name>   Collection label for grouping items
    --label <name>        Label for a password entry (default: user@hostname; must be unique)
    --config <path>       Config file to edit (default: ~/.config/rosec/config.toml)

NOTE:
    Vaults are rosec's local encrypted stores, distinct from external backends
    (Bitwarden, etc.).  Each vault is a single encrypted file on disk supporting
    multiple unlock passwords via key wrapping.

EXAMPLES:
    rosec vault create
    rosec vault create --id work --path ~/vaults/work.vault --collection work
    rosec vault attach --path /mnt/syncthing/shared.vault --id shared
    rosec vault list
    rosec vault auth personal
    rosec vault add-password personal --label pam
    rosec vault list-passwords personal
    rosec vault remove-password personal a1b2c3d4
    rosec vault detach work
    rosec vault destroy old-vault"
    );
}

async fn cmd_vault(args: &[String]) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    match sub {
        "list" | "ls" => cmd_vault_list().await,
        "create" => cmd_vault_create(&args[1..]).await,
        "attach" => cmd_vault_attach(&args[1..]).await,
        "detach" => cmd_vault_detach(&args[1..]).await,
        "destroy" => cmd_vault_destroy(&args[1..]).await,
        "add-password" => cmd_vault_add_password(&args[1..]).await,
        "remove-password" => cmd_vault_remove_password(&args[1..]).await,
        "list-passwords" => cmd_vault_list_passwords(&args[1..]).await,
        "auth" => cmd_vault_auth(&args[1..]).await,
        "help" | "--help" | "-h" => {
            print_vault_help();
            Ok(())
        }
        other => {
            eprintln!("unknown vault subcommand: {other}");
            print_vault_help();
            std::process::exit(1);
        }
    }
}

/// `rosec vault list` — show all configured vaults with lock state.
///
/// If rosecd is running, fetches live lock state from BackendList (filtered to
/// vault-kind entries). Otherwise falls back to listing from config.
async fn cmd_vault_list() -> Result<()> {
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
            .call::<_, _, Vec<(String, String, String, bool)>>("BackendList", &())
            .await
    {
        let vaults: Vec<_> = entries
            .iter()
            .filter(|(_, _, kind, _)| kind == "vault")
            .collect();

        if vaults.is_empty() {
            println!("No vaults configured. Run `rosec vault create` to create one.");
            return Ok(());
        }

        let id_w = vaults
            .iter()
            .map(|(id, ..)| id.len())
            .max()
            .unwrap_or(2)
            .max(2);
        let name_w = vaults
            .iter()
            .map(|(_, n, ..)| n.len())
            .max()
            .unwrap_or(4)
            .max(4);

        println!("{:<id_w$}  {:<name_w$}  STATE", "ID", "NAME");
        println!("{}", "-".repeat(id_w + name_w + 12));
        for (id, name, _, locked) in &vaults {
            println!(
                "{:<id_w$}  {:<name_w$}  {}",
                id,
                name,
                if *locked { "locked" } else { "unlocked" },
            );
        }
        return Ok(());
    }

    // Fallback: read config directly.
    let cfg = load_config();
    if cfg.vault.is_empty() {
        println!("No vaults configured. Run `rosec vault create` to create one.");
        return Ok(());
    }

    let id_w = cfg
        .vault
        .iter()
        .map(|v| v.id.len())
        .max()
        .unwrap_or(2)
        .max(2);
    let path_w = cfg
        .vault
        .iter()
        .map(|v| v.path.len())
        .max()
        .unwrap_or(4)
        .max(4);

    println!("{:<id_w$}  {:<path_w$}  STATE", "ID", "PATH");
    println!("{}", "-".repeat(id_w + path_w + 12));
    for entry in &cfg.vault {
        println!(
            "{:<id_w$}  {:<path_w$}  (daemon not running)",
            entry.id, entry.path,
        );
    }
    Ok(())
}

/// `rosec vault create [--id <id>] [--path <path>] [--collection <c>]`
///
/// Creates a new vault file on disk and adds a `[[vault]]` entry to the config.
/// Prompts for the initial password interactively.
async fn cmd_vault_create(args: &[String]) -> Result<()> {
    let mut custom_id: Option<String> = None;
    let mut custom_path: Option<String> = None;
    let mut collection: Option<String> = None;
    let mut i = 0usize;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--id" => {
                i += 1;
                custom_id = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--id requires a value"))?
                        .clone(),
                );
            }
            a if a.starts_with("--id=") => {
                custom_id = Some(a.trim_start_matches("--id=").to_string());
            }
            "--path" => {
                i += 1;
                custom_path = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--path requires a value"))?
                        .clone(),
                );
            }
            a if a.starts_with("--path=") => {
                custom_path = Some(a.trim_start_matches("--path=").to_string());
            }
            "--collection" => {
                i += 1;
                collection = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--collection requires a value"))?
                        .clone(),
                );
            }
            a if a.starts_with("--collection=") => {
                collection = Some(a.trim_start_matches("--collection=").to_string());
            }
            "--help" | "-h" => {
                print_vault_help();
                return Ok(());
            }
            other => bail!("unexpected argument: {other}"),
        }
        i += 1;
    }

    // Derive ID from path or generate a default.
    let id = match custom_id {
        Some(id) => id,
        None => {
            let v = prompt_field("Vault ID", "personal", "text").await?;
            let s = v.as_str().to_string();
            if s.is_empty() {
                "personal".to_string()
            } else {
                s
            }
        }
    };

    // Derive path from ID or use custom.
    let vault_path = match custom_path {
        Some(p) => p,
        None => default_vault_path(&id),
    };

    // Prompt for the initial vault password.
    let pw = prompt_field("Vault password", "", "password").await?;
    if pw.is_empty() {
        bail!("password cannot be empty");
    }
    let pw_confirm = prompt_field("Confirm password", "", "password").await?;
    if pw.as_str() != pw_confirm.as_str() {
        bail!("passwords do not match");
    }

    // Create the vault file on disk.
    let local_vault = rosec_vault::LocalVault::new(&id, &vault_path);
    local_vault
        .unlock(rosec_core::UnlockInput::Password(Zeroizing::new(
            pw.as_str().to_string(),
        )))
        .await
        .map_err(|e| anyhow::anyhow!("failed to create vault: {e}"))?;

    // Add the vault to config.toml.
    let cfg = config_path();
    config_edit::add_vault(&cfg, &id, &vault_path, collection.as_deref())?;

    println!("Created vault '{id}' at {vault_path}");
    println!("Added to {}", cfg.display());

    // If rosecd is running, wait for hot-reload then trigger auth.
    if let Ok(conn) = conn().await
        && let Ok(proxy) = zbus::Proxy::new(
            &conn,
            "org.freedesktop.secrets",
            "/org/rosec/Daemon",
            "org.rosec.Daemon",
        )
        .await
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let appeared = loop {
            if let Ok(entries) = proxy
                .call::<_, _, Vec<(String, String, String, bool)>>("BackendList", &())
                .await
                && entries.iter().any(|(bid, ..)| bid == &id)
            {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        };

        if appeared {
            println!("rosecd picked up the new vault — starting authentication.");
            let tty_fd = open_tty_owned_fd()?;
            let _: () = proxy
                .call("AuthBackendWithTty", &(id.as_str(), tty_fd))
                .await?;
            println!("Vault '{id}' authenticated.");
        } else {
            println!("rosecd will hot-reload the config automatically if it is running.");
            println!("Run `rosec vault auth {id}` to authenticate.");
        }
    }

    Ok(())
}

/// `rosec vault attach --path <file> [--id <id>] [--collection <c>]`
///
/// Adds an existing vault file to the config without creating it.
async fn cmd_vault_attach(args: &[String]) -> Result<()> {
    let mut custom_id: Option<String> = None;
    let mut vault_path: Option<String> = None;
    let mut collection: Option<String> = None;
    let mut i = 0usize;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--id" => {
                i += 1;
                custom_id = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--id requires a value"))?
                        .clone(),
                );
            }
            a if a.starts_with("--id=") => {
                custom_id = Some(a.trim_start_matches("--id=").to_string());
            }
            "--path" => {
                i += 1;
                vault_path = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--path requires a value"))?
                        .clone(),
                );
            }
            a if a.starts_with("--path=") => {
                vault_path = Some(a.trim_start_matches("--path=").to_string());
            }
            "--collection" => {
                i += 1;
                collection = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--collection requires a value"))?
                        .clone(),
                );
            }
            a if a.starts_with("--collection=") => {
                collection = Some(a.trim_start_matches("--collection=").to_string());
            }
            "--help" | "-h" => {
                print_vault_help();
                return Ok(());
            }
            other => bail!("unexpected argument: {other}"),
        }
        i += 1;
    }

    let vault_path = vault_path.ok_or_else(|| {
        anyhow::anyhow!("--path is required\nusage: rosec vault attach --path <file> [--id <id>]")
    })?;

    // Derive ID from filename if not specified.
    let id = match custom_id {
        Some(id) => id,
        None => derive_vault_id_from_path(&vault_path),
    };

    let cfg = config_path();
    config_edit::add_vault(&cfg, &id, &vault_path, collection.as_deref())?;

    println!("Attached vault '{id}' ({vault_path}) to {}", cfg.display());
    println!("rosecd will hot-reload the config automatically if it is running.");
    println!("Run `rosec vault auth {id}` to authenticate.");
    Ok(())
}

/// `rosec vault detach <id>`
///
/// Removes the vault from the config file but leaves the vault file on disk.
async fn cmd_vault_detach(args: &[String]) -> Result<()> {
    let id = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: rosec vault detach <id>"))?;
    let cfg = config_path();
    config_edit::remove_vault(&cfg, id)?;
    println!("Detached vault '{id}' from {}", cfg.display());
    println!("The vault file was NOT deleted. Use `rosec vault destroy` to also delete the file.");
    println!("rosecd will hot-reload the config automatically if it is running.");
    Ok(())
}

/// `rosec vault destroy <id>`
///
/// Removes the vault from the config AND deletes the vault file from disk.
async fn cmd_vault_destroy(args: &[String]) -> Result<()> {
    let id = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: rosec vault destroy <id>"))?;

    // Look up the path from config before removing the entry.
    let cfg_data = load_config();
    let vault_entry = cfg_data
        .vault
        .iter()
        .find(|v| v.id == *id)
        .ok_or_else(|| anyhow::anyhow!("vault '{id}' not found in config"))?;
    let vault_path = expand_tilde(&vault_entry.path);

    // Confirm destruction.
    let confirm = prompt_field(
        &format!("Destroy vault '{id}' and delete {vault_path}? (yes/no)"),
        "",
        "text",
    )
    .await?;
    if confirm.as_str() != "yes" {
        println!("Cancelled.");
        return Ok(());
    }

    // Remove from config.
    let cfg = config_path();
    config_edit::remove_vault(&cfg, id)?;

    // Delete the vault file.
    match std::fs::remove_file(&vault_path) {
        Ok(()) => println!("Deleted vault file: {vault_path}"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("Vault file already absent: {vault_path}");
        }
        Err(e) => {
            eprintln!("warning: could not delete vault file {vault_path}: {e}");
        }
    }

    println!("Removed vault '{id}' from {}", cfg.display());
    println!("rosecd will hot-reload the config automatically if it is running.");
    Ok(())
}

/// `rosec vault add-password <id> [--label <label>]`
///
/// Add a new unlock password to a vault. The vault must be unlocked (running in
/// rosecd).
async fn cmd_vault_add_password(args: &[String]) -> Result<()> {
    let mut vault_id: Option<&str> = None;
    let mut label: Option<String> = None;
    let mut i = 0usize;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--label" => {
                i += 1;
                label = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--label requires a value"))?
                        .clone(),
                );
            }
            a if a.starts_with("--label=") => {
                label = Some(a.trim_start_matches("--label=").to_string());
            }
            "--help" | "-h" => {
                print_vault_help();
                return Ok(());
            }
            a if a.starts_with('-') => bail!("unknown flag: {a}"),
            a => {
                if vault_id.is_some() {
                    bail!("unexpected argument: {a}");
                }
                vault_id = Some(a);
            }
        }
        i += 1;
    }

    let vault_id = vault_id
        .ok_or_else(|| anyhow::anyhow!("usage: rosec vault add-password <id> [--label <label>]"))?;

    // Default label: user@hostname
    let label = label.unwrap_or_else(default_password_label);

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
        .call(
            "VaultAddPassword",
            &(vault_id, pw.as_bytes().to_vec(), &label),
        )
        .await?;

    println!("Added password entry {entry_id} (label: {label}) to vault '{vault_id}'.");
    Ok(())
}

/// `rosec vault list-passwords <vault-id>`
///
/// List the wrapping entries (unlock passwords) for a vault. The vault must be
/// unlocked. Shows the entry ID and label for each password.
async fn cmd_vault_list_passwords(args: &[String]) -> Result<()> {
    let vault_id = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: rosec vault list-passwords <vault-id>"))?;

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let entries: Vec<(String, String)> = proxy
        .call("VaultListPasswords", &(vault_id.as_str(),))
        .await?;

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

/// `rosec vault remove-password <vault-id> <entry-id>`
///
/// Remove an unlock password from a vault. The vault must be unlocked and must
/// have at least 2 passwords.
async fn cmd_vault_remove_password(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        bail!("usage: rosec vault remove-password <vault-id> <entry-id>");
    }
    let vault_id = &args[0];
    let entry_id = &args[1];

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    // First list passwords to show the user what they're removing.
    let entries: Vec<(String, String)> = proxy
        .call("VaultListPasswords", &(vault_id.as_str(),))
        .await?;

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

    let _: () = proxy
        .call(
            "VaultRemovePassword",
            &(vault_id.as_str(), entry_id.as_str()),
        )
        .await?;

    println!("Removed password entry '{entry_id}' from vault '{vault_id}'.");
    Ok(())
}

/// `rosec vault auth <id>` — interactively authenticate a vault.
///
/// Opens `/dev/tty` and passes the fd to `rosecd` via D-Bus fd-passing.
async fn cmd_vault_auth(args: &[String]) -> Result<()> {
    let vault_id = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: rosec vault auth <vault-id>"))?;

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
        .call("AuthBackendWithTty", &(vault_id.as_str(), tty_fd))
        .await?;

    println!("Vault '{vault_id}' authenticated.");
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
    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let (_, _, _, cache_size, last_sync_epoch, sessions): (String, String, u32, u32, u64, u32) =
        proxy.call("Status", &()).await?;

    // Fetch all backends with type and lock state.
    let backends: Vec<(String, String, String, bool)> = proxy.call("BackendList", &()).await?;

    println!("Backends:");
    for (id, name, kind, locked) in &backends {
        let lock_indicator = if *locked { "locked" } else { "unlocked" };
        println!("  {name} ({id})  [{kind}, {lock_indicator}]");
    }
    println!();
    println!("Cache size:  {cache_size} items");
    if last_sync_epoch > 0 {
        println!("Last sync:   {last_sync_epoch} (epoch secs)");
    } else {
        println!("Last sync:   never");
    }
    println!("Sessions:    {sessions}");
    Ok(())
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

    // Fetch the list of backends so we know which ones to sync.
    let backends: Vec<(String, String, String, bool)> = proxy.call("BackendList", &()).await?;

    for (id, _name, _kind, _locked) in &backends {
        eprint!("Syncing '{id}'...");
        match proxy.call::<_, _, u32>("SyncBackend", &(id,)).await {
            Ok(count) => {
                println!(" {count} items");
            }
            Err(zbus::Error::MethodError(_, Some(detail), _))
                if detail.as_str().starts_with("locked::") =>
            {
                // Daemon says this backend needs credentials first.
                // Pass a TTY fd so the daemon can prompt in-process —
                // credentials never appear in any D-Bus message.
                let backend_id = detail.as_str().trim_start_matches("locked::");
                eprintln!(" locked");
                let tty_fd = open_tty_owned_fd()?;
                let _: () = proxy
                    .call("AuthBackendWithTty", &(backend_id, tty_fd))
                    .await?;
                // Retry sync now that the backend is unlocked.
                eprint!("Syncing '{id}' (retrying)...");
                match proxy.call::<_, _, u32>("SyncBackend", &(id,)).await {
                    Ok(count) => println!(" {count} items"),
                    Err(e) => eprintln!(" failed: {e}"),
                }
            }
            Err(e) => eprintln!(" failed: {e}"),
        }
    }

    Ok(())
}

/// Ensure the daemon's cache is fresh by syncing backends in parallel.
///
/// Checks `DaemonStatus.last_sync_epoch` — if the last sync was more than
/// 60 seconds ago (matching the daemon's internal staleness threshold), calls
/// `SyncBackend` for each unlocked backend concurrently.  If the cache is
/// already fresh, this is a single cheap D-Bus call with no network I/O.
///
/// Locked backends are skipped — the caller handles unlock via the Prompt flow
/// and can call this again afterwards to sync the newly-unlocked backends.
async fn preemptive_sync(conn: &Connection) -> Result<()> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    // Check global staleness: if last_sync_epoch is within 60 s, skip.
    let status: (String, String, u32, u32, u64, u32) = proxy.call("Status", &()).await?;
    let last_sync_epoch = status.4;

    if last_sync_epoch > 0 {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now_epoch.saturating_sub(last_sync_epoch) < 60 {
            return Ok(());
        }
    }

    // Stale or never synced — sync each unlocked backend in parallel.
    let backends: Vec<(String, String, String, bool)> = proxy.call("BackendList", &()).await?;

    let futures: Vec<_> = backends
        .into_iter()
        .filter(|(_, _, _, locked)| !locked)
        .map(|(id, _, _, _)| {
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
                        if let Err(e) = p.call::<_, _, u32>("SyncBackend", &(&id,)).await {
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

/// Returns `true` if the daemon reports at least one locked backend.
///
/// Used by `cmd_search` with `--sync` to distinguish "genuinely no results"
/// from "empty because the metadata cache was never populated" (cold start with
/// all backends locked).
async fn any_backends_locked(conn: &Connection) -> Result<bool> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;
    let backends: Vec<(String, String, String, bool)> = proxy.call("BackendList", &()).await?;
    Ok(backends.iter().any(|(_, _, _, locked)| *locked))
}

/// Output format for `rosec search`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Human,
    Table,
    Kv,
    Json,
}

impl OutputFormat {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "human" => Some(Self::Human),
            "table" => Some(Self::Table),
            "kv" => Some(Self::Kv),
            "json" => Some(Self::Json),
            _ => None,
        }
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
    /// Path segment format: `{backend}_{uuid_sanitised}_{hash:016x}`
    /// The hash is the last `_`-delimited token — always exactly 16 hex chars.
    /// It is derived from `sha256("{backend_id}:{item_id}")[0..8]` so it is
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
/// Handles lazy-unlock automatically.
async fn search_exact(
    conn: &Connection,
    attrs: &HashMap<String, String>,
) -> Result<(Vec<String>, Vec<String>)> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    match proxy.call("SearchItems", &(attrs,)).await {
        Ok(result) => Ok(result),
        Err(ref e) if try_lazy_unlock(conn, e).await? => {
            Ok(proxy.call("SearchItems", &(attrs,)).await?)
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

/// If rosecd is running with no configured backends, print a warning to stderr
/// and suggest next steps.  Non-fatal — the caller continues normally (an empty
/// backend list returns empty results, which is correct behaviour).
async fn warn_if_no_backends(conn: &Connection) {
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
        .call::<_, _, Vec<(String, String, String, bool)>>("BackendList", &())
        .await
    else {
        return;
    };
    if entries.is_empty() {
        eprintln!("warning: rosecd is running with no configured backends.");
        eprintln!("         Run `rosec backend add <kind>` to add a real backend.");
    }
}

/// Glob search: try `org.rosec.Search.SearchItemsGlob` first when rosecd is running.
///
/// If `is_rosecd` is false (non-rosecd provider), falls back to
/// `SearchItems({})` to retrieve all items, then applies glob matching
/// client-side.  This keeps `rosec search name=John*` working against GNOME
/// Keyring, KWallet, or any other spec-compliant Secret Service daemon.
async fn search_with_glob_fallback(
    conn: &Connection,
    attrs: &HashMap<String, String>,
    is_rosecd: bool,
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
        // Mirror the lazy-unlock retry that search_exact uses: if the server
        // returns locked::<id>, prompt the user then retry once.
        match search_proxy.call("SearchItemsGlob", &(attrs,)).await {
            Ok(result) => return Ok(result),
            Err(ref e) if try_lazy_unlock(conn, e).await? => {
                return Ok(search_proxy.call("SearchItemsGlob", &(attrs,)).await?);
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Fallback for non-rosecd providers: fetch all items then filter client-side.
    let (unlocked, locked) = search_exact(conn, &HashMap::new()).await?;

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

async fn cmd_search(args: &[String]) -> Result<()> {
    // Parse --format flag, --show-path flag, --sync flag, and k=v filters.
    let mut format = OutputFormat::Table;
    let mut show_path = false;
    let mut sync = false;
    let mut all_attrs: HashMap<String, String> = HashMap::new();

    for arg in args {
        if let Some(fmt_str) = arg.strip_prefix("--format=") {
            match OutputFormat::parse(fmt_str) {
                Some(f) => format = f,
                None => {
                    eprintln!("unknown format '{fmt_str}': use table, kv, or json");
                    std::process::exit(1);
                }
            }
        } else if arg == "--format" {
            eprintln!("--format requires a value: --format=table|kv|json");
            std::process::exit(1);
        } else if arg == "--show-path" {
            show_path = true;
        } else if arg == "--sync" || arg == "-s" {
            sync = true;
        } else if arg == "--help" || arg == "-h" {
            print_search_help();
            return Ok(());
        } else if let Some((key, value)) = arg.split_once('=') {
            all_attrs.insert(key.to_string(), value.to_string());
        } else {
            eprintln!("invalid argument: {arg}");
            std::process::exit(1);
        }
    }

    let conn = conn().await?;
    let rosecd = is_rosecd(&conn).await;
    if rosecd {
        warn_if_no_backends(&conn).await;
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
                search_with_glob_fallback(&conn, &all_attrs, rosecd).await
            } else {
                search_exact(&conn, &all_attrs).await
            }
        }
    };

    let (unlocked, locked) = match do_search(&conn).await {
        Ok(result) => result,
        Err(e) if sync => {
            // Search failed (e.g. all backends locked) — unlock then retry.
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            do_search(&conn).await.map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    // With --sync, trigger unlock and retry when:
    //   (a) results are all locked (items exist but collection is locked), OR
    //   (b) both lists are empty AND the daemon has locked backends — the
    //       metadata cache is cold (never synced) because all backends started
    //       locked and preemptive_sync skipped them.
    let needs_unlock = sync
        && ((!locked.is_empty() && unlocked.is_empty())
            || (unlocked.is_empty() && locked.is_empty() && any_backends_locked(&conn).await?));
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

/// Print results as an aligned table.
///
/// Columns: TYPE | NAME | USERNAME | URI | ID [| PATH]
fn print_search_table(items: &[ItemSummary], show_path: bool) {
    const H_TYPE: &str = "TYPE";
    const H_NAME: &str = "NAME";
    const H_USER: &str = "USERNAME";
    const H_URI: &str = "URI";
    const H_ID: &str = "ID";

    // Hard caps keep the table usable on a standard 120-column terminal.
    const MAX_TYPE: usize = 10;
    const MAX_NAME: usize = 30;
    const MAX_USER: usize = 30;
    const MAX_URI: usize = 45;
    const W_ID: usize = 16; // always exactly 16 hex chars

    let w_type = items
        .iter()
        .map(|i| {
            i.attrs
                .get("type")
                .map(String::len)
                .unwrap_or(0)
                .min(MAX_TYPE)
        })
        .max()
        .unwrap_or(0)
        .max(H_TYPE.len());
    let w_name = items
        .iter()
        .map(|i| i.label.len().min(MAX_NAME))
        .max()
        .unwrap_or(0)
        .max(H_NAME.len());
    let w_user = items
        .iter()
        .map(|i| {
            i.attrs
                .get("username")
                .map(String::len)
                .unwrap_or(0)
                .min(MAX_USER)
        })
        .max()
        .unwrap_or(0)
        .max(H_USER.len());
    let w_uri = items
        .iter()
        .map(|i| {
            i.attrs
                .get("uri")
                .map(String::len)
                .unwrap_or(0)
                .min(MAX_URI)
        })
        .max()
        .unwrap_or(0)
        .max(H_URI.len());

    // Separator width: columns + 2-char gaps between each pair + ID column.
    // The ID header text is 2 chars ("ID") but data is always 16 hex chars.
    let w_id_col = W_ID.max(H_ID.len());
    let sep_w = w_type
        + 2
        + w_name
        + 2
        + w_user
        + 2
        + w_uri
        + 2
        + w_id_col
        + if show_path { 2 + "PATH".len() } else { 0 };

    if show_path {
        println!(
            "{:<w_type$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {:<w_id_col$}  PATH",
            H_TYPE, H_NAME, H_USER, H_URI, H_ID,
        );
    } else {
        println!(
            "{:<w_type$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {}",
            H_TYPE, H_NAME, H_USER, H_URI, H_ID,
        );
    }
    println!("{}", "-".repeat(sep_w));

    for item in items {
        let item_type = item.attrs.get("type").map(String::as_str).unwrap_or("");
        let username = item.attrs.get("username").map(String::as_str).unwrap_or("");
        let uri = item.attrs.get("uri").map(String::as_str).unwrap_or("");

        let t = trunc(item_type, MAX_TYPE);
        let n = trunc(&item.label, MAX_NAME);
        let u = trunc(username, MAX_USER);
        let r = trunc(uri, MAX_URI);
        let lock_indicator = if item.locked { " [locked]" } else { "" };

        if show_path {
            println!(
                "{:<w_type$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {:<w_id_col$}  {}{}",
                t,
                n,
                u,
                r,
                item.display_id(),
                item.path,
                lock_indicator,
            );
        } else {
            println!(
                "{:<w_type$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {}{}",
                t,
                n,
                u,
                r,
                item.display_id(),
                lock_indicator,
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
            if matches!(k.as_str(), "backend_id" | "xdg:schema") {
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
        let (unlocked, locked): (Vec<String>, Vec<String>) = proxy
            .call("SearchItems", &(&HashMap::<String, String>::new(),))
            .await?;
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
        search_with_glob_fallback(conn, &attrs, rosecd).await?
    } else {
        search_exact(conn, &attrs).await?
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

async fn cmd_get(args: &[String]) -> Result<()> {
    // Parse flags: --help / -h, --attr <name> / --attr=<name>, --sync
    let mut attr: Option<String> = None;
    let mut sync = false;
    let mut id: Option<&str> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_get_help();
                return Ok(());
            }
            "--sync" | "-s" => {
                sync = true;
            }
            "--attr" => {
                i += 1;
                attr = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--attr requires a value"))?
                        .clone(),
                );
            }
            a if a.starts_with("--attr=") => {
                attr = Some(a.trim_start_matches("--attr=").to_string());
            }
            a if a.starts_with('-') => {
                bail!("unknown flag: {a}  (try `rosec get --help`)");
            }
            a => {
                if id.is_some() {
                    bail!("unexpected argument: {a}  (try `rosec get --help`)");
                }
                id = Some(a);
            }
        }
        i += 1;
    }

    let raw =
        id.ok_or_else(|| anyhow::anyhow!("missing item path or ID  (try `rosec get --help`)"))?;

    let conn = conn().await?;

    // If --sync was requested, ensure the daemon has fresh data before resolving.
    if sync {
        preemptive_sync(&conn).await?;
    }

    let resolve_result = resolve_item_path(&conn, raw).await;

    // Determine the item path and whether unlock is needed.
    // With --sync, if the item wasn't found at all we attempt unlock + re-sync
    // before giving up — the item may live in a backend that hasn't been
    // unlocked yet (so the metadata cache has no knowledge of it).
    let (path, is_locked) = match resolve_result {
        Ok(result) => result,
        Err(e) if sync => {
            // Item not found — try unlocking, syncing, and re-resolving.
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            resolve_item_path(&conn, raw).await.map_err(|_| e)? // If still not found, return the original error.
        }
        Err(e) => return Err(e),
    };

    // If the item was in the locked partition, trigger the spec Unlock+Prompt
    // flow before attempting to fetch the secret.
    if is_locked {
        trigger_unlock(&conn).await?;
        // Re-sync the just-unlocked backends so the freshly-available items
        // are pulled from the remote and the metadata cache is populated.
        if sync {
            preemptive_sync(&conn).await?;
        }
    }

    // Try once; if backend is locked, prompt for credentials and retry.
    match cmd_get_inner(&conn, &path, attr.as_deref()).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let zbus_err = e.downcast_ref::<zbus::Error>();
            if let Some(ze) = zbus_err
                && try_lazy_unlock(&conn, ze).await?
            {
                cmd_get_inner(&conn, &path, attr.as_deref()).await
            } else {
                Err(e)
            }
        }
    }
}

fn print_get_help() {
    println!(
        "\
rosec get - print a secret value

USAGE:
    rosec get [--sync] [--attr <name>] <item>

ARGUMENTS:
    <item>          One of:
                      16-char hex item ID       a1b2c3d4e5f60718
                      D-Bus object path         /org/freedesktop/secrets/…
                      Attribute filter           name=MY_API_KEY
                    Attribute filters use key=value syntax.  Glob patterns
                    are supported (name=*prod*, uri=*.example.com).
                    Exactly one item must match.

FLAGS:
    -s, --sync      Sync backends before fetching if the cache is stale (>60 s).
                    Skips the network call when data is already fresh.
    --attr <name>   Print the named public attribute instead of the primary secret
                    (e.g. username, uri, folder, sm.project).
                    Use `rosec inspect <id>` to see all available attributes.
    -h, --help      Show this help

EXAMPLES:
    rosec get a1b2c3d4e5f60718                    # by hex ID
    rosec get name=MY_API_KEY                     # by exact name
    rosec get 'name=*prod*'                       # by name glob
    rosec get uri=github.com                      # by URI attribute
    rosec get --sync name=MY_API_KEY              # sync first, then fetch
    rosec get a1b2c3d4e5f60718 | xclip -sel clip  # pipe to clipboard
    rosec get --attr username name=MY_API_KEY     # print username attribute"
    );
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

    let (_, session_path): (OwnedValue, String) = service_proxy
        .call("OpenSession", &("plain", zvariant::Value::from("")))
        .await?;

    let items = vec![path.to_string()];
    let secrets_result: Result<HashMap<String, OwnedValue>, zbus::Error> = service_proxy
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
            if let Some((_item_path, value)) = secrets.into_iter().next() {
                match <(OwnedObjectPath, Vec<u8>, Vec<u8>, String)>::try_from(value) {
                    Ok((_session, _params, secret_bytes, _content_type)) => {
                        let mut out = std::io::stdout();
                        out.write_all(&secret_bytes)?;
                        // Add a trailing newline on TTY only if the secret itself
                        // doesn't already end with one (avoids the double-newline
                        // that appears when the stored value has a trailing \n).
                        if std::io::IsTerminal::is_terminal(&out) && !secret_bytes.ends_with(b"\n")
                        {
                            out.write_all(b"\n")?;
                        }
                        return Ok(());
                    }
                    Err(_) => bail!("could not decode secret value"),
                }
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

async fn cmd_inspect(args: &[String]) -> Result<()> {
    let mut all_attrs = false;
    let mut sync = false;
    let mut format = OutputFormat::Human;
    let mut raw: Option<&str> = None;

    for arg in args {
        match arg.as_str() {
            "--all-attrs" | "-a" => all_attrs = true,
            "--sync" | "-s" => sync = true,
            s if s.starts_with("--format=") => {
                let fmt_str = &s["--format=".len()..];
                match OutputFormat::parse(fmt_str) {
                    Some(f) => format = f,
                    None => {
                        eprintln!("unknown format '{fmt_str}': use human, kv, or json");
                        std::process::exit(1);
                    }
                }
            }
            "--format" => {
                eprintln!("--format requires a value: --format=human|kv|json");
                std::process::exit(1);
            }
            "--help" | "-h" => {
                print_inspect_help();
                return Ok(());
            }
            s if raw.is_none() => raw = Some(s),
            s => {
                eprintln!("unexpected argument: {s}");
                std::process::exit(1);
            }
        }
    }

    let raw = raw.ok_or_else(|| anyhow::anyhow!("missing item path or ID"))?;

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

    let (_, session_path): (OwnedValue, String) = service_proxy
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

        let names: Vec<String> = secrets_proxy
            .call("GetSecretAttributeNames", &(path,))
            .await?;

        let mut pairs: Vec<(String, Zeroizing<Vec<u8>>)> = Vec::with_capacity(names.len());
        for name in names {
            let bytes: Vec<u8> = secrets_proxy
                .call("GetSecretAttribute", &(path, name.as_str()))
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
    let items = vec![path.to_string()];
    let secrets_result: Result<HashMap<String, OwnedValue>, zbus::Error> = service_proxy
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
                    for (_item_path, value) in secrets {
                        match <(OwnedObjectPath, Vec<u8>, Vec<u8>, String)>::try_from(value) {
                            Ok((_session, _params, secret_bytes, content_type)) => {
                                let text = String::from_utf8_lossy(&secret_bytes);
                                if text.is_empty() {
                                    println!("Secret:     <empty>");
                                } else {
                                    println!("Secret ({content_type}):");
                                    println!("  {text}");
                                }
                            }
                            Err(_) => println!("Secret:     <could not decode>"),
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
                for (_item_path, value) in secrets {
                    if let Ok((_session, _params, secret_bytes, _ct)) =
                        <(OwnedObjectPath, Vec<u8>, Vec<u8>, String)>::try_from(value)
                    {
                        let text = String::from_utf8_lossy(&secret_bytes);
                        println!("secret={text}");
                    }
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
                    for (_item_path, value) in secrets {
                        if let Ok((_session, _params, secret_bytes, _ct)) =
                            <(OwnedObjectPath, Vec<u8>, Vec<u8>, String)>::try_from(value)
                        {
                            val = serde_json::Value::String(
                                String::from_utf8_lossy(&secret_bytes).into_owned(),
                            );
                        }
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

    // Count unlocked backends before locking so we can report how many were locked.
    let mgmt_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;
    let backends: Vec<(String, String, String, bool)> = mgmt_proxy.call("BackendList", &()).await?;
    let unlocked_count = backends.iter().filter(|(_, _, _, locked)| !locked).count();

    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;
    let _: (Vec<String>, String) = proxy
        .call(
            "Lock",
            &(vec!["/org/freedesktop/secrets/collection/default"],),
        )
        .await?;

    match unlocked_count {
        0 => println!("Nothing to lock — all backends already locked."),
        n => println!(
            "Locked: 1 collection, {} backend{}.",
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

    let backends: Vec<(String, String, String, bool)> = proxy.call("BackendList", &()).await?;

    if backends.is_empty() {
        println!("No backends configured. Run `rosec backend add <kind>` to add one.");
        return Ok(());
    }

    // Report already-unlocked backends.
    let any_locked = backends.iter().any(|(_, _, _, locked)| *locked);
    for (id, _, _, is_locked) in &backends {
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
    type ResultEntry = (String, bool, String); // (backend_id, success, message)
    let results: Vec<ResultEntry> = proxy.call("UnlockWithTty", &(tty_fd,)).await?;

    for (id, success, message) in &results {
        if *success {
            println!("'{id}' unlocked.");
        } else {
            eprintln!("'{id}' failed: {message}");
        }
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

fn print_config_help() {
    println!(
        "\
rosec config - read or modify config.toml

USAGE:
    rosec config show
    rosec config get <key>
    rosec config set <key> <value>

SUBCOMMANDS:
    show            Print the current effective configuration as TOML
    get <key>       Print the current value of a single setting
    set <key> <value>
                    Update a setting.  The daemon hot-reloads config.toml
                    automatically — no restart required.

SETTABLE KEYS:"
    );
    for (key, desc) in CONFIG_KEYS {
        println!("    {key:<40}  {desc}");
    }
    println!(
        "
EXAMPLES:
    rosec config show
    rosec config get autolock.idle_timeout_minutes
    rosec config set autolock.idle_timeout_minutes 30
    rosec config set autolock.on_session_lock false
    rosec config set service.refresh_interval_secs 120"
    );
}

fn cmd_config(args: &[String]) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("help");
    match sub {
        "show" => cmd_config_show(),
        "get" => {
            let key = args
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("missing key  (try `rosec config --help`)"))?;
            cmd_config_get(key)
        }
        "set" => {
            let key = args
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("missing key  (try `rosec config --help`)"))?;
            let value = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("missing value  (try `rosec config --help`)"))?;
            cmd_config_set(key, value)
        }
        "help" | "--help" | "-h" => {
            print_config_help();
            Ok(())
        }
        other => {
            eprintln!("unknown config subcommand: {other}");
            print_config_help();
            std::process::exit(1);
        }
    }
}

fn cmd_config_show() -> Result<()> {
    let path = config_path();
    if !path.exists() {
        println!("# No config file found at {}", path.display());
        println!("# Showing compiled-in defaults:\n");
        let default_toml = toml::to_string_pretty(&Config::default())
            .unwrap_or_else(|_| "# (serialization error)".to_string());
        println!("{default_toml}");
        return Ok(());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    print!("{raw}");
    Ok(())
}

fn cmd_config_get(key: &str) -> Result<()> {
    // Validate the key is in the supported list.
    if !CONFIG_KEYS.iter().any(|(k, _)| *k == key) {
        eprintln!("unknown config key: {key}");
        eprintln!("run `rosec config --help` to see supported keys");
        std::process::exit(1);
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
        eprintln!("unknown config key: {key}");
        eprintln!("run `rosec config --help` to see supported keys");
        std::process::exit(1);
    }

    // Validate the value before touching the file.
    validate_config_value(key, value)?;

    let path = config_path();
    config_edit::set_value(&path, key, value)?;

    println!("{key} = {value}");
    Ok(())
}
