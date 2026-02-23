use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::Stdio;

use sha2::{Digest, Sha256};
use serde::Serialize;

use anyhow::{Result, bail};
use zbus::Connection;
use zeroize::Zeroizing;
use zvariant::{OwnedObjectPath, OwnedValue};

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
        // backend / backends are full aliases for the same subcommand tree
        "backend" | "backends" => cmd_backend(&args[1..]).await,
        "status" => cmd_status().await,
        "sync" | "refresh" => cmd_sync().await,
        "search" => cmd_search(&args[1..]).await,
        "get" => cmd_get(&args[1..]).await,
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
    backend <subcommand>                Manage backends (alias: backends)
      list                              List configured backends and their lock state
      auth <id>                         Authenticate/unlock a backend
      add <kind> [options]              Add a backend to the config file
      remove <id>                       Remove a backend from the config file

    status                              Show daemon status
    sync                                Sync vault with remote server (alias: refresh)
    search [--format=<fmt>] [--show-path] [key=value]...
                                        Search items by attributes (no args = list all)
    get <id>                            Get a secret by item ID or full D-Bus path
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
    rosec get a1b2c3d4e5f60718                              # 16-char hex ID from search
    rosec get /org/freedesktop/secrets/collection/default/… # full D-Bus path"
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

async fn conn() -> Result<Connection> {
    Ok(Connection::session().await?)
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
// Prompt helpers (client-side credential collection)
// ---------------------------------------------------------------------------

/// JSON types matching the rosec-prompt wire protocol.
#[derive(Serialize)]
struct PromptRequest<'a> {
    #[serde(rename = "t")]  title:         &'a str,
    #[serde(rename = "m")]  message:       &'a str,
    #[serde(rename = "h")]  hint:          &'a str,
    backend:                               &'a str,
    confirm_label:                         &'a str,
    cancel_label:                          &'a str,
    fields:                                Vec<PromptField<'a>>,
    theme:                                 PromptTheme<'a>,
}

#[derive(Serialize, Clone)]
struct PromptField<'a> {
    id:          &'a str,
    label:       &'a str,
    kind:        &'a str,
    placeholder: &'a str,
}

#[derive(Serialize)]
struct PromptTheme<'a> {
    #[serde(rename = "bg")]   background:         &'a str,
    #[serde(rename = "fg")]   foreground:         &'a str,
    #[serde(rename = "bdr")]  border_color:       &'a str,
    #[serde(rename = "bw")]   border_width:       u16,
    #[serde(rename = "font")] font_family:        &'a str,
    #[serde(rename = "lc")]   label_color:        &'a str,
    #[serde(rename = "ac")]   accent_color:       &'a str,
    #[serde(rename = "ybg")]  confirm_background: &'a str,
    #[serde(rename = "yt")]   confirm_text:       &'a str,
    #[serde(rename = "nbg")]  cancel_background:  &'a str,
    #[serde(rename = "nt")]   cancel_text:        &'a str,
    #[serde(rename = "ibg")]  input_background:   &'a str,
    #[serde(rename = "it")]   input_text:         &'a str,
    #[serde(rename = "size")] font_size:          u16,
}

/// Resolve the path to the named binary, checking sibling of current exe first
/// (handles cargo dev builds in target/debug/ and same-directory installs).
fn resolve_binary(name: &str) -> String {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    name.to_string()
}

/// Collect credentials for `backend_id` using the configured prompt program
/// (or TTY fallback), then call `AuthBackend` over D-Bus.
///
/// `field_descs` is the list returned by `GetAuthFields`.
/// Returns `Ok(())` if the backend was successfully authenticated.
async fn prompt_and_auth(
    backend_id: &str,
    backend_name: &str,
    field_descs: &[(String, String, String, String, bool)],
    proxy: &zbus::Proxy<'_>,
    config: &Config,
) -> Result<()> {
    let theme = &config.prompt.theme;

    let fields: Vec<PromptField<'_>> = field_descs
        .iter()
        .map(|(id, label, kind, placeholder, _)| PromptField {
            id: id.as_str(),
            label: label.as_str(),
            kind: kind.as_str(),
            placeholder: placeholder.as_str(),
        })
        .collect();

    // Title uses the backend ID (short, stable identifier).
    // The human-readable name (which may contain PII such as an email address)
    // is shown in the tooltip (hint) so it is discoverable on hover but does
    // not occupy visible space or leak into the main window text.
    let display_name = if backend_name.is_empty() { backend_id } else { backend_name };
    let hint = if backend_name.is_empty() || backend_name == backend_id {
        String::new()
    } else {
        backend_name.to_string()
    };
    let request = PromptRequest {
        title:             &format!("Unlock {backend_id}"),
        message:           "",
        hint:              &hint,
        backend:           backend_id,
        confirm_label:     "Unlock",
        cancel_label:      "Cancel",
        fields:            fields.clone(),
        theme: PromptTheme {
            background:         &theme.background,
            foreground:         &theme.foreground,
            border_color:       &theme.border_color,
            border_width:       theme.border_width,
            font_family:        &theme.font_family,
            label_color:        &theme.label_color,
            accent_color:       &theme.accent_color,
            confirm_background: &theme.confirm_background,
            confirm_text:       &theme.confirm_text,
            cancel_background:  &theme.cancel_background,
            cancel_text:        &theme.cancel_text,
            input_background:   &theme.input_background,
            input_text:         &theme.input_text,
            font_size:          theme.font_size,
        },
    };

    let json = serde_json::to_string(&request)?;

    // Determine the prompt program path.
    let has_display = std::env::var_os("WAYLAND_DISPLAY").is_some()
        || std::env::var_os("DISPLAY").is_some();

    let collected: HashMap<String, Zeroizing<String>> = if has_display {
        let program = match config.prompt.backend.as_str() {
            "builtin" | "" => resolve_binary("rosec-prompt"),
            custom => custom.to_string(),
        };

        let spawn_result = std::process::Command::new(&program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn();

        match spawn_result {
            Ok(mut child) => {
                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(json.as_bytes())?;
                }
                let output = child.wait_with_output()?;
                if !output.status.success() {
                    bail!("prompt cancelled");
                }
                let raw: HashMap<String, String> =
                    serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim())?;
                raw.into_iter().map(|(k, v)| (k, Zeroizing::new(v))).collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
                   || e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                // GUI binary not available — fall through to TTY
                collect_tty(display_name, &fields).await?
            }
            Err(e) => bail!("failed to launch prompt: {e}"),
        }
    } else {
        collect_tty(display_name, &fields).await?
    };

    // Call AuthBackend with the collected values.
    let mut string_map: HashMap<String, String> = collected
        .into_iter()
        .map(|(k, v)| (k, v.as_str().to_string()))
        .collect();

    let result: Result<bool, zbus::Error> =
        proxy.call("AuthBackend", &(backend_id, &string_map)).await;

    // Zero the map values now that they've been sent.
    for v in string_map.values_mut() {
        unsafe { v.as_bytes_mut().iter_mut().for_each(|b| *b = 0) };
    }

    let needs_registration = matches!(
        &result,
        Err(zbus::Error::MethodError(_, Some(detail), _)) if detail.as_str() == "registration_required"
    );

    if needs_registration {
        type FieldDesc = (String, String, String, String, bool);
        let (instructions, reg_field_descs): (String, Vec<FieldDesc>) =
            proxy.call("GetRegistrationInfo", &(backend_id,)).await?;

        eprintln!();
        eprintln!("{instructions}");
        eprintln!();

        // Re-collect all fields including registration fields via TTY
        // (registration flow is always interactive/text-based).
        let mut all_fields = field_descs.to_vec();
        all_fields.extend(reg_field_descs);
        let reg_fields: Vec<PromptField<'_>> = all_fields
            .iter()
            .map(|(id, label, kind, placeholder, _)| PromptField {
                id: id.as_str(),
                label: label.as_str(),
                kind: kind.as_str(),
                placeholder: placeholder.as_str(),
            })
            .collect();
        let mut reg_map: HashMap<String, String> = collect_tty(display_name, &reg_fields)
            .await?
            .into_iter()
            .map(|(k, v)| (k, v.as_str().to_string()))
            .collect();

        let _ok: bool = proxy.call("AuthBackend", &(backend_id, &reg_map)).await?;
        for v in reg_map.values_mut() {
            unsafe { v.as_bytes_mut().iter_mut().for_each(|b| *b = 0) };
        }
    } else {
        result?;
    }

    Ok(())
}

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
/// Returns `Ok(true)` if the backend was successfully unlocked (caller should
/// retry the original operation).  Returns `Ok(false)` if the error was not a
/// locked sentinel (caller should propagate the original error).
async fn try_lazy_unlock(conn: &Connection, err: &zbus::Error) -> Result<bool> {
    let backend_id = match extract_locked_backend(err) {
        Some(id) => id,
        None => return Ok(false),
    };

    let config = load_config();
    let daemon_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    // Look up the backend's display name for the prompt.
    let backends: Vec<(String, String, String, bool)> =
        daemon_proxy.call("BackendList", &()).await?;
    let display_name = backends
        .iter()
        .find(|(id, _, _, _)| id == &backend_id)
        .map(|(_, name, _, _)| name.as_str())
        .unwrap_or(&backend_id);

    let field_descs: Vec<(String, String, String, String, bool)> =
        daemon_proxy.call("GetAuthFields", &(&backend_id,)).await?;

    prompt_and_auth(&backend_id, display_name, &field_descs, &daemon_proxy, &config).await?;

    Ok(true)
}

/// Collect credentials via TTY for the given fields.
async fn collect_tty(
    display_name: &str,
    fields: &[PromptField<'_>],
) -> Result<HashMap<String, Zeroizing<String>>> {
    eprintln!();
    eprintln!("=== Unlock {display_name} ===");
    eprintln!();
    let mut map = HashMap::new();
    for f in fields {
        let v = prompt_field(f.label, f.placeholder, f.kind).await?;
        map.insert(f.id.to_string(), v);
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Secure field collection
// ---------------------------------------------------------------------------

/// Read one line from `fd` with terminal echo disabled.
///
/// Flushes any stale input (via `TCSAFLUSH`), saves the current `termios`,
/// clears `ECHO`/`ECHONL`, reads a line, then restores the original settings.
/// The returned string has the trailing newline stripped.
#[cfg(unix)]
fn read_hidden(fd: std::os::unix::io::RawFd) -> io::Result<String> {
    use std::io::BufRead as _;
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

    // Read one line from the same fd.
    let mut line = String::new();
    let result = {
        // SAFETY: we borrow the fd for reading; ManuallyDrop prevents double-close
        // since the original `tty: File` in the caller still owns the fd.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let file = std::mem::ManuallyDrop::new(file);
        let mut reader = io::BufReader::new(&*file);
        reader.read_line(&mut line)
    };

    // Always restore original settings (including echo) before propagating errors.
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };

    // Print a newline since ECHO is off (the user's Enter was not echoed).
    let _ = unsafe {
        libc::write(
            fd,
            b"\n".as_ptr().cast(),
            1,
        )
    };

    result?;
    Ok(line
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string())
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
                let value = read_hidden(fd)?;
                Ok(Zeroizing::new(value))
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
        "list" | "ls"            => cmd_backend_list().await,
        "auth"                   => cmd_backend_auth(&args[1..]).await,
        "add"                    => cmd_backend_add(&args[1..]).await,
        "remove" | "rm"          => cmd_backend_remove(&args[1..]).await,
        "help" | "--help" | "-h" => { print_backend_help(); Ok(()) }
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

    let entries: Vec<(String, String, String, bool)> =
        proxy.call("BackendList", &()).await?;

    if entries.is_empty() {
        println!("No backends configured.");
        return Ok(());
    }

    let id_w   = entries.iter().map(|(id, ..)| id.len()).max().unwrap_or(2).max(2);
    let name_w = entries.iter().map(|(_, n, ..)| n.len()).max().unwrap_or(4).max(4);
    let kind_w = entries.iter().map(|(_, _, k, _)| k.len()).max().unwrap_or(4).max(4);

    println!(
        "{:<id_w$}  {:<name_w$}  {:<kind_w$}  STATE",
        "ID", "NAME", "KIND",
    );
    println!("{}", "-".repeat(id_w + name_w + kind_w + 14));
    for (id, name, kind, locked) in &entries {
        println!(
            "{:<id_w$}  {:<name_w$}  {:<kind_w$}  {}",
            id, name, kind,
            if *locked { "locked" } else { "unlocked" },
        );
    }
    Ok(())
}

/// `rosec backend auth <id>` — interactively authenticate a backend.
///
/// Normal flow:
///   1. `GetAuthFields` → prompt each field (always includes the password field first)
///   2. `AuthBackend` with all collected values
///
/// Registration flow (first-time device / new token):
///   If `AuthBackend` returns a D-Bus error whose message is `"registration_required"`:
///   3. `GetRegistrationInfo` → display instructions, prompt extra fields
///   4. Retry `AuthBackend` with password + registration fields combined
async fn cmd_backend_auth(args: &[String]) -> Result<()> {
    let backend_id = args.first().ok_or_else(|| {
        anyhow::anyhow!("usage: rosec backend auth <backend-id>")
    })?;

    let conn = conn().await?;
    let config = load_config();
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    // Resolve the friendly backend name from BackendList.
    let backends: Vec<(String, String, String, bool)> =
        proxy.call("BackendList", &()).await?;
    let backend_name = backends
        .iter()
        .find(|(id, _, _, _)| id == backend_id)
        .map(|(_, name, _, _)| name.as_str())
        .unwrap_or("");

    let field_descs: Vec<(String, String, String, String, bool)> =
        proxy.call("GetAuthFields", &(backend_id,)).await?;

    prompt_and_auth(backend_id, backend_name, &field_descs, &proxy, &config).await?;

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
            let field_kind = if *key == "access_token" || key.contains("secret") || key.contains("password") {
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
            ).await?;
            let s = v.as_str().to_string();
            if !s.is_empty() {
                options.push((key.to_string(), s));
            }
        }
    }

    let cfg = config_path();
    config_edit::add_backend(&cfg, &id, kind, &options)?;
    println!("Added backend '{id}' (kind: {kind}) to {}", cfg.display());
    println!("rosecd will hot-reload the config automatically if it is running.");
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
    let short = format!("{:08x}", u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]));
    format!("{kind}-{short}")
}

/// `rosec backend remove <id>`
async fn cmd_backend_remove(args: &[String]) -> Result<()> {
    let id = args.first().ok_or_else(|| {
        anyhow::anyhow!("usage: rosec backend remove <id>")
    })?;
    let cfg = config_path();
    config_edit::remove_backend(&cfg, id)?;
    println!("Removed backend '{id}' from {}", cfg.display());
    println!("rosecd will hot-reload the config automatically if it is running.");
    Ok(())
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

    let (_, _, _, cache_size, last_sync_epoch, sessions): (
        String, String, u32, u32, u64, u32,
    ) = proxy.call("Status", &()).await?;

    // Fetch all backends with type and lock state.
    let backends: Vec<(String, String, String, bool)> =
        proxy.call("BackendList", &()).await?;

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

    let config = load_config();

    // Fetch the list of backends so we know which ones to sync.
    let backends: Vec<(String, String, String, bool)> =
        proxy.call("BackendList", &()).await?;

    for (id, name, _kind, _locked) in &backends {
        eprint!("Syncing '{id}'...");
        match proxy.call::<_, _, u32>("SyncBackend", &(id,)).await {
            Ok(count) => {
                println!(" {count} items");
            }
            Err(zbus::Error::MethodError(_, Some(detail), _))
                if detail.as_str().starts_with("locked::") =>
            {
                // Daemon says this backend needs credentials first.
                let backend_id = detail.as_str().trim_start_matches("locked::");
                eprintln!(" locked");
                let field_descs: Vec<(String, String, String, String, bool)> =
                    proxy.call("GetAuthFields", &(backend_id,)).await?;
                prompt_and_auth(backend_id, name, &field_descs, &proxy, &config).await?;
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

/// Output format for `rosec search`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Table,
    Kv,
    Json,
}

impl OutputFormat {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "table" => Some(Self::Table),
            "kv"    => Some(Self::Kv),
            "json"  => Some(Self::Json),
            _       => None,
        }
    }
}

/// All data fetched for a single search result item.
struct ItemSummary {
    label:   String,
    attrs:   HashMap<String, String>,
    path:    String,
    locked:  bool,
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
        return Ok(search_proxy.call("SearchItemsGlob", &(attrs,)).await?);
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
            item.attrs.get(key.as_str()).map(String::as_str).unwrap_or("")
        };
        wildmatch::WildMatch::new(pattern).matches(value)
    })
}

async fn cmd_search(args: &[String]) -> Result<()> {
    // Parse --format flag, --show-path flag, and k=v attribute filters from args.
    let mut format = OutputFormat::Table;
    let mut show_path = false;
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
        } else if let Some((key, value)) = arg.split_once('=') {
            all_attrs.insert(key.to_string(), value.to_string());
        } else {
            eprintln!("invalid argument: {arg}");
            std::process::exit(1);
        }
    }

    let conn = conn().await?;
    let rosecd = is_rosecd(&conn).await;
    let has_globs = all_attrs.values().any(|v| is_glob(v))
        || all_attrs.contains_key("name");

    // Strategy:
    //   - Any glob pattern or "name" filter → use org.rosec.Search.SearchItemsGlob
    //     when rosecd is running; otherwise fall back to spec-compliant
    //     SearchItems({}) + client-side glob (works against GNOME Keyring, KWallet, etc.)
    //   - All-exact attrs → always use spec-compliant SearchItems directly.
    let (unlocked, locked) = if has_globs {
        search_with_glob_fallback(&conn, &all_attrs, rosecd).await?
    } else {
        search_exact(&conn, &all_attrs).await?
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
        let summary = fetch_item_data(&conn, path, false).await
            .unwrap_or_else(|_| ItemSummary {
                label:  path.clone(),
                attrs:  HashMap::new(),
                path:   path.clone(),
                locked: false,
            });
        items.push(summary);
    }
    for path in &locked {
        let summary = fetch_item_data(&conn, path, true).await
            .unwrap_or_else(|_| ItemSummary {
                label:  path.clone(),
                attrs:  HashMap::new(),
                path:   path.clone(),
                locked: true,
            });
        items.push(summary);
    }

    match format {
        OutputFormat::Table => print_search_table(&items, show_path),
        OutputFormat::Kv    => print_search_kv(&items, show_path),
        OutputFormat::Json  => print_search_json(&items)?,  // JSON always includes path
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

    Ok(ItemSummary { label, attrs, path: path.to_string(), locked })
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
    const H_TYPE:  &str = "TYPE";
    const H_NAME:  &str = "NAME";
    const H_USER:  &str = "USERNAME";
    const H_URI:   &str = "URI";
    const H_ID:    &str = "ID";

    // Hard caps keep the table usable on a standard 120-column terminal.
    const MAX_TYPE: usize = 10;
    const MAX_NAME: usize = 30;
    const MAX_USER: usize = 30;
    const MAX_URI:  usize = 45;
    const W_ID:     usize = 16; // always exactly 16 hex chars

    let w_type = items.iter()
        .map(|i| i.attrs.get("type").map(String::len).unwrap_or(0).min(MAX_TYPE))
        .max().unwrap_or(0)
        .max(H_TYPE.len());
    let w_name = items.iter()
        .map(|i| i.label.len().min(MAX_NAME))
        .max().unwrap_or(0)
        .max(H_NAME.len());
    let w_user = items.iter()
        .map(|i| i.attrs.get("username").map(String::len).unwrap_or(0).min(MAX_USER))
        .max().unwrap_or(0)
        .max(H_USER.len());
    let w_uri = items.iter()
        .map(|i| i.attrs.get("uri").map(String::len).unwrap_or(0).min(MAX_URI))
        .max().unwrap_or(0)
        .max(H_URI.len());

    // Separator width: columns + 2-char gaps between each pair + ID column.
    // The ID header text is 2 chars ("ID") but data is always 16 hex chars.
    let w_id_col = W_ID.max(H_ID.len());
    let sep_w = w_type + 2 + w_name + 2 + w_user + 2 + w_uri + 2 + w_id_col
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
        let username  = item.attrs.get("username").map(String::as_str).unwrap_or("");
        let uri       = item.attrs.get("uri").map(String::as_str).unwrap_or("");

        let t = trunc(item_type, MAX_TYPE);
        let n = trunc(&item.label, MAX_NAME);
        let u = trunc(username, MAX_USER);
        let r = trunc(uri, MAX_URI);
        let lock_indicator = if item.locked { " [locked]" } else { "" };

        if show_path {
            println!(
                "{:<w_type$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {:<w_id_col$}  {}{}",
                t, n, u, r, item.display_id(), item.path, lock_indicator,
            );
        } else {
            println!(
                "{:<w_type$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {}{}",
                t, n, u, r, item.display_id(), lock_indicator,
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
    let json_items: Vec<serde_json::Value> = items.iter().map(|item| {
        let mut obj = serde_json::Map::new();
        obj.insert("label".to_string(),    serde_json::Value::String(item.label.clone()));
        obj.insert("id".to_string(),       serde_json::Value::String(item.display_id().to_string()));
        obj.insert("path".to_string(),     serde_json::Value::String(item.path.clone()));
        obj.insert("locked".to_string(),   serde_json::Value::Bool(item.locked));

        let mut attrs_obj = serde_json::Map::new();
        let mut sorted_attrs: Vec<_> = item.attrs.iter().collect();
        sorted_attrs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in sorted_attrs {
            attrs_obj.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
        obj.insert("attributes".to_string(), serde_json::Value::Object(attrs_obj));

        serde_json::Value::Object(obj)
    }).collect();

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
async fn resolve_item_path(conn: &Connection, raw: &str) -> Result<String> {
    if raw.starts_with('/') {
        return Ok(raw.to_string());
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
        let (unlocked, locked): (Vec<String>, Vec<String>) =
            proxy.call("SearchItems", &(&HashMap::<String, String>::new(),)).await?;
        let all = unlocked.into_iter().chain(locked);
        for path in all {
            if path.ends_with(&suffix) {
                return Ok(path);
            }
        }
        anyhow::bail!("no item found with ID {raw}");
    }

    // Legacy: treat as full path segment.
    Ok(format!("/org/freedesktop/secrets/collection/default/{raw}"))
}

async fn cmd_get(args: &[String]) -> Result<()> {
    let raw = args.first().ok_or_else(|| anyhow::anyhow!("missing item path or ID"))?;

    let conn = conn().await?;
    let path = resolve_item_path(&conn, raw).await?;

    // Try once; if backend is locked, prompt for credentials and retry.
    match cmd_get_inner(&conn, &path).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Check if the underlying cause is a zbus locked:: sentinel.
            let zbus_err = e.downcast_ref::<zbus::Error>();
            if let Some(ze) = zbus_err
                && try_lazy_unlock(&conn, ze).await?
            {
                cmd_get_inner(&conn, &path).await
            } else {
                Err(e)
            }
        }
    }
}

async fn cmd_get_inner(conn: &Connection, path: &str) -> Result<()> {
    // Open a plain session
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

    // Fetch item metadata.
    let item_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        path,
        "org.freedesktop.Secret.Item",
    )
    .await?;

    let label: String = item_proxy.get_property("Label").await?;
    let attrs: HashMap<String, String> = item_proxy.get_property("Attributes").await?;

    println!("Label: {label}");
    if !attrs.is_empty() {
        println!("Attributes:");
        let mut sorted: Vec<_> = attrs.iter().collect();
        sorted.sort_by_key(|(k, _)| *k);
        for (k, v) in sorted {
            println!("  {k}: {v}");
        }
    }

    // GetSecrets — may fail for items without a primary secret (cards,
    // identities, secure notes without content).  In that case we still show
    // the metadata we already fetched above.
    let items = vec![path.to_string()];
    let secrets_result: Result<HashMap<String, OwnedValue>, zbus::Error> = service_proxy
        .call("GetSecrets", &(items, &session_path))
        .await;

    match secrets_result {
        Ok(secrets) if secrets.is_empty() => {
            println!("Secret: <none>");
        }
        Ok(secrets) => {
            for (_item_path, value) in secrets {
                match <(OwnedObjectPath, Vec<u8>, Vec<u8>, String)>::try_from(value) {
                    Ok((_session, _params, secret_bytes, content_type)) => {
                        let text = String::from_utf8_lossy(&secret_bytes);
                        if text.is_empty() {
                            println!("Secret: <empty>");
                        } else {
                            println!("Secret ({content_type}): {text}");
                        }
                    }
                    Err(_) => {
                        println!("Secret: <could not decode>");
                    }
                }
            }
        }
        Err(zbus::Error::MethodError(_, Some(detail), _))
            if detail.as_str().starts_with("no secret for cipher") =>
        {
            println!("Secret: <not available — this item type has no primary secret>");
        }
        Err(e) => {
            println!("Secret: <error: {e}>");
        }
    }

    // Close the session
    let _: () = service_proxy
        .call("CloseSession", &(&session_path,))
        .await?;

    Ok(())
}

async fn cmd_lock() -> Result<()> {
    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    let (locked, _prompt): (Vec<String>, String) = proxy
        .call("Lock", &(vec!["/org/freedesktop/secrets/collection/default"],))
        .await?;

    if locked.is_empty() {
        println!("Lock requested (may require prompt).");
    } else {
        println!("Locked: {} objects", locked.len());
    }
    Ok(())
}

async fn cmd_unlock() -> Result<()> {
    let conn = conn().await?;
    let config = load_config();

    // Use the rosec Daemon interface — it gives us the locked::<id> signal
    // and access to GetAuthFields / AuthBackend on the same proxy.
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let backends: Vec<(String, String, String, bool)> =
        proxy.call("BackendList", &()).await?;

    let mut any_unlocked = false;
    for (id, name, _kind, locked) in &backends {
        if !locked {
            println!("'{id}' is already unlocked.");
            any_unlocked = true;
            continue;
        }
        let field_descs: Vec<(String, String, String, String, bool)> =
            proxy.call("GetAuthFields", &(id,)).await?;
        prompt_and_auth(id, name, &field_descs, &proxy, &config).await?;
        println!("'{id}' unlocked.");
        any_unlocked = true;
    }

    if !any_unlocked {
        println!("No backends configured.");
    }
    Ok(())
}

