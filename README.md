# rosec

A [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/) daemon with pluggable backends, Bitwarden integration, and SSH agent support.

**Status:** MVP — D-Bus Secret Service is implemented and the Bitwarden backend is functional.

## What it does

`rosecd` replaces `gnome-keyring-daemon` as the D-Bus Secret Service provider. Any application that uses `libsecret` (GNOME Keyring API) will transparently read secrets from your Bitwarden vault without storing them on disk.

**Multi-backend, multi-instance:** rosec supports multiple backends simultaneously — multiple Bitwarden accounts, Bitwarden Secrets Manager projects, a local encrypted file store, and can be extended to other providers. Each backend is independently locked/unlocked and contributes items to a unified namespace.

**SSH agent + FUSE:** SSH keys in your vault are exposed via a built-in agent (`$XDG_RUNTIME_DIR/rosec/agent.sock`) and a FUSE filesystem (`$XDG_RUNTIME_DIR/rosec/ssh/`). The FUSE mount includes auto-generated SSH config snippets, so hosts mapped via `custom.ssh_host` fields get working `Host` blocks automatically.

**Write support:** Bitwarden backends are read-only (vault changes must be made via the Bitwarden clients), but local vaults (`rosec-vault`) provide encrypted storage for machine-local secrets like session tokens and application credentials.

## Install

### From source

```bash
cargo build --release --workspace
sudo install -m755 target/release/rosecd /usr/local/bin/
sudo install -m755 target/release/rosec  /usr/local/bin/

# Optional: PAM auto-unlock hook
sudo install -Dm755 target/release/rosec-pam-unlock /usr/lib/rosec/rosec-pam-unlock
```

### systemd + D-Bus activation (recommended)

```bash
# systemd user unit
cp contrib/systemd/rosecd.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now rosecd

# D-Bus activation (delegate to systemd, mask gnome-keyring)
mkdir -p ~/.local/share/dbus-1/services
cp contrib/dbus/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/
cp contrib/dbus/org.gnome.keyring.service       ~/.local/share/dbus-1/services/
```

See [FUTURE.md](FUTURE.md) for the full activation guide, non-systemd setups, and gnome-keyring race condition details.

## Quick Start

```bash
# 1. Add a Bitwarden backend (prompts for email; authenticates immediately if rosecd is running)
rosec backend add bitwarden

# 2. If rosecd was not running when you added the backend, authenticate now
rosec backend auth <backend-id>

# 3. Check status
rosec backend list

# 4. Search and retrieve secrets
rosec search username=admin
rosec search name="GitHub*"
rosec get name=MY_API_KEY
```

### PAM auto-unlock (optional)

Automatically unlock vaults at login by adding one line to your PAM config
(e.g. `/etc/pam.d/system-login`), after `pam_unix.so`:

```text
auth  optional  pam_exec.so  expose_authtok quiet /usr/lib/rosec/rosec-pam-unlock
```

If your login password differs from your vault master password, add it as a
second wrapping entry first: `rosec vault add-password <vault-id> --label pam`.
See [PAM Auto-Unlock](#pam-auto-unlock) for the full setup guide.

### SSH agent usage

```bash
# Add to ~/.ssh/config (one-time setup)
Include /run/user/1000/rosec/ssh/config.d/*

# Set SSH_AUTH_SOCK for the rosec agent
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rosec/agent.sock"

# List loaded keys
ssh-add -l

# SSH to a host with auto-generated config
ssh my-server.example.com
```

Tag SSH key items in Bitwarden with a `custom.ssh_host` field (value: hostname or pattern) to generate SSH config snippets automatically. See [docs/ssh-agent.md](docs/ssh-agent.md) for details.

## Configuration

Config file: `$XDG_CONFIG_HOME/rosec/config.toml` (default: `~/.config/rosec/config.toml`)

```toml
[service]
refresh_interval_secs = 60   # vault re-sync interval (default: 60)
# pam_helper_paths = ["/usr/lib/rosec/rosec-pam-unlock", "/usr/libexec/rosec-pam-unlock"]

# Global autolock defaults (KWallet/GNOME Keyring-like behaviour).
# Backends stay unlocked for the session, lock only on logout.
[autolock]
on_logout = true
on_session_lock = false      # true to lock on screen lock
# idle_timeout_minutes = 15  # uncomment to enable idle lock
# max_unlocked_minutes = 240 # uncomment to enable hard cap

[prompt]
backend = "builtin"          # "builtin" or path to external prompter binary

[[backend]]
id = "bitwarden"
type = "bitwarden"

[backend.options]
email = "user@example.com"
# base_url = "https://your-vaultwarden.example.com"  # omit for official cloud

# Per-backend autolock overrides (optional — omit to use global defaults):
# [backend.autolock]
# idle_timeout_minutes = 5   # stricter timeout for this backend
# on_session_lock = true     # lock this backend on screen lock
```

Full reference: [docs/configuration.md](docs/configuration.md)

## Local Vaults

For machine-local secrets (application tokens, session credentials, development API keys), create a local vault:

```bash
rosec vault create local
```

Or add a vault section to your config:

```toml
[[vault]]
id = "local"
path = "~/.local/share/rosec/vaults/local.vault"
```

Local vaults store secrets in an encrypted file at the specified path. They're unlocked with a master password (derived via PBKDF2, encrypted with AES-256-CBC) and support full CRUD operations via the D-Bus Secret Service API. Key wrapping allows multiple passwords to unlock the same vault, enabling PAM auto-unlock with a different password than the master password.

### Vault management

```bash
# Create a new vault (interactive — prompts for master password)
rosec vault create
rosec vault create --id work --path ~/vaults/work.vault

# Attach an existing vault file (e.g. shared via Syncthing)
rosec vault attach --path /mnt/shared/team.vault --id shared

# List all vaults and their lock state
rosec vault list

# Detach a vault from config (file is preserved on disk)
rosec vault detach work

# Destroy a vault — removes from config AND deletes the file
rosec vault destroy old-vault
```

### Multiple passwords (key wrapping)

Each vault can have multiple unlock passwords. This is essential for PAM auto-unlock when your login password differs from the vault master password.

```bash
# Add a second password to the "personal" vault (prompts interactively)
rosec vault add-password personal --label pam

# List wrapping entries to see entry IDs
rosec vault list

# Remove a password by entry ID
rosec vault remove-password personal a1b2c3d4
```

The vault data key is randomly generated and encrypted ("wrapped") by each password. Adding or removing a password only changes the wrapping entries — vault data is never re-encrypted.

**When to use:**
- Application session tokens that don't belong in Bitwarden
- Development credentials and test API keys
- Machine-specific secrets that shouldn't sync across devices
- Temporary or frequently-changed credentials

**Write routing:** When multiple backends are configured, the `service.write_backend` option controls which backend receives `CreateItem` calls on the virtual "default" collection:

```toml
[service]
write_backend = "local"  # default if a "local" vault exists
```

## PAM Auto-Unlock

`rosec-pam-unlock` is a `pam_exec` hook that automatically unlocks your rosec vaults when you log in. Your login password is read from PAM's stdin and passed to the rosec daemon via a Unix pipe fd — it never appears in any D-Bus message payload, so it is invisible to `dbus-monitor`.

### How it works

1. PAM calls `rosec-pam-unlock` with your login password on stdin (`expose_authtok`)
2. The binary connects to the D-Bus session bus and lists all locked vault backends
3. For each locked vault, it creates a Unix pipe, writes the password to the write end, and passes the read-end fd to the daemon via `AuthBackendFromPipe` (D-Bus fd-passing / SCM_RIGHTS)
4. The daemon reads the password from the pipe, attempts to unwrap the vault key, and unlocks the vault if a matching wrapping entry exists
5. Vaults without a matching password are silently skipped — this never blocks login

### Setup

**1. Install the binary:**

```bash
sudo install -m755 target/release/rosec-pam-unlock /usr/lib/rosec/rosec-pam-unlock
```

**2. Add a PAM-specific password to your vault:**

If your login password differs from your vault master password, add it as a second wrapping entry:

```bash
# Add your login password as a second unlock password
rosec vault add-password personal --label pam
# Enter your login password when prompted
```

If your login password is already your vault master password, skip this step.

**3. Configure PAM:**

Add to your login PAM config (e.g. `/etc/pam.d/system-login` or `/etc/pam.d/login`):

```text
auth  optional  pam_exec.so  expose_authtok quiet /usr/lib/rosec/rosec-pam-unlock
```

Place it after `pam_unix.so` (or your primary auth module) so the password is available.

For display managers (SDDM, GDM, etc.), add to their respective PAM config:

```text
# /etc/pam.d/sddm (or gdm-password, lightdm, etc.)
auth  optional  pam_exec.so  expose_authtok quiet /usr/lib/rosec/rosec-pam-unlock
```

**4. (Optional) Configure allowed helper paths:**

The daemon verifies that `AuthBackendFromPipe` is only called by the PAM helper binary. It checks the caller's `/proc/<pid>/exe` against a list of allowed paths. The default covers standard FHS install locations:

```toml
[service]
pam_helper_paths = [
    "/usr/lib/rosec/rosec-pam-unlock",
    "/usr/libexec/rosec-pam-unlock",
]
```

Override this if you install to a non-standard location or want to test during development:

```toml
[service]
pam_helper_paths = ["/home/you/rosec/target/debug/rosec-pam-unlock"]
```

### Security properties

- **Caller-restricted:** The `AuthBackendFromPipe` D-Bus method only accepts calls from the PAM helper binary. The daemon resolves the caller's PID via `GetConnectionCredentials` and verifies `/proc/<pid>/exe` against `pam_helper_paths`. Arbitrary processes cannot pipe passwords to the daemon.
- **Password never on D-Bus wire:** The password is sent via Unix pipe fd-passing (SCM_RIGHTS), not as a D-Bus string argument. It cannot be intercepted by `dbus-monitor` or `busctl monitor`.
- **Zeroized after use:** The password buffer is zeroized in both the PAM binary and the daemon after each unlock attempt.
- **Never blocks login:** The module is configured as `optional` and exits with `PAM_IGNORE` on any failure.
- **No logging of secrets:** No sensitive data is ever written to stdout, stderr, or syslog.
- **Session bus scope:** Communication happens on the per-user session bus, not the system bus.

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all
```

A `Justfile` is provided for common tasks (`just build`, `just test`, `just lint`, `just release-patch`, etc.).

## FAQ

### `gnome-keyring-daemon` keeps stealing `org.freedesktop.secrets`

```bash
# Mask systemd units
systemctl --user mask gnome-keyring-daemon.service gnome-keyring-daemon.socket

# Override D-Bus activation
mkdir -p ~/.local/share/dbus-1/services
cp /usr/share/dbus-1/services/org.freedesktop.secrets.service \
   ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
sed -i 's|Exec=.*|Exec=/bin/false|' \
   ~/.local/share/dbus-1/services/org.freedesktop.secrets.service

# Reload and kill the running instance
systemctl --user reload dbus
pkill gnome-keyring-daemon
```

User-level files in `~/.local/share/dbus-1/services/` take precedence over system ones per the D-Bus spec. See [FUTURE.md](FUTURE.md) for the recommended approach using the contrib D-Bus activation files.

### How do I update my Bitwarden master password?

The master password is never stored. After changing it in the Bitwarden web vault, simply run `rosec backend auth <id>` at the next unlock and enter the new password.

### How do I rotate my Bitwarden Secrets Manager access token?

Run `rosec backend auth <id>`. Enter your key encryption password, then paste the new access token when prompted. Leaving the token field blank re-uses the stored token.

### SSH agent fails with "Transport endpoint is not connected"

If `rosecd` was killed or crashed, a stale FUSE mount may be left behind. `rosecd` automatically cleans up stale mounts on startup, so simply restarting it should work.

If automatic cleanup fails, unmount manually:

```bash
fusermount3 -uz "$XDG_RUNTIME_DIR/rosec/ssh"
```

## Prior Art

- [`secretsd`](https://github.com/grawity/secretsd) — Generic Secret Service backend
- [`oo7`](https://github.com/bilelmoussaoui/oo7) — Pure Rust Secret Service client
- [`pass-secret-service`](https://github.com/mdellweg/pass_secret_service) — Secret Service backed by pass

## License

MIT
