# rosec

A read-only [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/) daemon with pluggable backends and Bitwarden integration.

**Status:** MVP — D-Bus Secret Service is implemented and the Bitwarden backend is functional.

## What it does

`rosecd` replaces `gnome-keyring-daemon` as the D-Bus Secret Service provider. Any application that uses `libsecret` (GNOME Keyring API) will transparently read secrets from your Bitwarden vault without storing them on disk.

**Multi-backend, multi-instance:** rosec supports multiple backends simultaneously — multiple Bitwarden accounts, Bitwarden Secrets Manager projects, and can be extended to other providers. Each backend is independently locked/unlocked and contributes items to a unified namespace.

**SSH agent + FUSE:** SSH keys in your vault are exposed via a built-in agent (`$XDG_RUNTIME_DIR/rosec/agent.sock`) and a FUSE filesystem (`$XDG_RUNTIME_DIR/rosec/ssh/`). The FUSE mount includes auto-generated SSH config snippets, so hosts mapped via `custom.ssh_host` fields get working `Host` blocks automatically.

All write operations return `NotSupported` — rosec is intentionally read-only.

## Install

### From source

```bash
cargo build --release --workspace
sudo install -m755 target/release/rosecd /usr/local/bin/
sudo install -m755 target/release/rosec  /usr/local/bin/
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

[autolock]
on_logout = true
on_session_lock = true
idle_timeout_minutes = 15    # lock after idle (0 = disabled)
max_unlocked_minutes = 240   # hard cap (0 = disabled)

[prompt]
backend = "builtin"          # "builtin" or path to external prompter binary

[[backend]]
id = "bitwarden"
type = "bitwarden"

[backend.options]
email = "user@example.com"
# base_url = "https://your-vaultwarden.example.com"  # omit for official cloud
```

Full reference: [docs/configuration.md](docs/configuration.md)

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
