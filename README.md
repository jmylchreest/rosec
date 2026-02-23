# rosec

A read-only `org.freedesktop.secrets` (Secret Service) daemon with pluggable backends and Bitwarden integration.

## Features

- **Read-only**: Exposes secrets via the standard D-Bus Secret Service API; all write operations return `NotSupported`
- **Bitwarden backend**: Direct Bitwarden API client (compatible with official servers and Vaultwarden)
- **Multi-backend fallthrough**: Deduplicates secrets across backends (newest wins)
- **Secure prompting**: Built-in iced GUI with RGBA theming, or external prompter support
- **Wayland-first**: Designed for Wayland compositors (Hyprland, Sway, etc.)
- **Idiomatic Rust 1.93+**: Zero clippy warnings, minimal dependencies
- **systemd integration**: Ships with a user service unit

## Project Structure

```
rosec/
├── rosec-core/           # Core library (traits, types, config, dedup, router)
├── rosec-bitwarden/      # Bitwarden API client + VaultBackend implementation
├── rosec-secret-service/ # D-Bus Secret Service implementation
├── rosec-prompt/         # Standalone iced prompter GUI
├── rosecd/               # Daemon binary
├── rosec/                # CLI binary
└── contrib/systemd/      # systemd user service unit
```

## Status

**MVP.** D-Bus Secret Service is implemented and the Bitwarden backend is functional. The daemon starts locked and requires an unlock prompt (master password) before serving secrets.

## Quick Start

1. Copy and edit the example config:
   ```bash
   mkdir -p ~/.config/rosec
   cp examples/config.toml ~/.config/rosec/config.toml
   # Edit email in the [[backend]] section
   ```

2. Build:
   ```bash
   cargo build --release --workspace
   ```

3. Run the daemon:
   ```bash
   cargo run --release --bin rosecd
   ```

4. Use the CLI:
   ```bash
   # Show daemon status
   rosec status

   # Force vault re-sync
   rosec refresh

   # Search items by attributes
   rosec search username=admin

   # Get a secret by item path
   rosec get /org/freedesktop/secrets/item/bitwarden/my-login_abc123
   ```

5. (Optional) Install the systemd user service:
   ```bash
   cp contrib/systemd/rosecd.service ~/.config/systemd/user/
   systemctl --user daemon-reload
   systemctl --user enable --now rosecd
   ```

## Configuration

Configuration is loaded from `$XDG_CONFIG_HOME/rosec/config.toml` (default: `~/.config/rosec/config.toml`).

### Example

```toml
[service]
dedup_strategy = "newest"
dedup_time_fallback = "created"
refresh_interval_secs = 60

[autolock]
on_logout = true
on_session_lock = true
idle_timeout_minutes = 15
max_unlocked_minutes = 240

[prompt]
backend = "builtin"

[prompt.theme]
bg = "#1e1e2ecc"
fg = "#cdd6f4ff"
lc = "#a6adc8ff"
ac = "#7aa2f7ff"
ibg = "#181825ff"
it = "#cdd6f4ff"
bd = "#89b4faff"
bw = 2
font = "monospace"
size = 14

[[backend]]
id = "bitwarden"
type = "bitwarden"

[backend.options]
email = "user@example.com"
# base_url = "https://vault.bitwarden.com"  # omit for official US cloud
# base_url = "https://your-vaultwarden.example.com"  # for self-hosted
```

### Theme Aliases

| Field | Aliases | Description |
|-------|---------|-------------|
| `background` | `bg` | Main background color |
| `foreground` | `fg` | Main text color |
| `label_color` | `lc` | Secondary/hint text color |
| `accent_color` | `ac` | Accent color (inputs, buttons) |
| `border_color` | `bd`, `bdr` | Border color |
| `border_width` | `bw` | Border width in pixels |
| `font_family` | `font` | Font family |
| `font_size` | `size` | Font size in pixels |
| `input_background` | `ibg` | Password input background |
| `input_text` | `it` | Password input text color |
| `confirm_background` | `ybg` | Unlock button background |
| `confirm_text` | `yt` | Unlock button text |
| `cancel_background` | `nbg` | Cancel button background |
| `cancel_text` | `nt` | Cancel button text |

Colors support RGBA hex format: `#RRGGBBAA` or `#RRGGBB`.

## Prompter Templating

External prompters support template arguments:

```toml
[prompt]
backend = "/usr/bin/rosec-prompt"
args = [
  "--hint=Backend: {{backend}}",
  "--title={{title}}",
  "--message={{message}}"
]
```

Available template fields: `{{title}}`, `{{message}}`, `{{hint}}`, `{{backend}}`

## D-Bus Interface

rosec implements the standard [Secret Service API](https://specifications.freedesktop.org/secret-service/):

| Interface | Path | Description |
|-----------|------|-------------|
| `org.freedesktop.Secret.Service` | `/org/freedesktop/secrets` | Main service (SearchItems, GetSecrets, OpenSession) |
| `org.freedesktop.Secret.Collection` | `/org/freedesktop/secrets/collection/default` | Default collection (SearchItems) |
| `org.freedesktop.Secret.Item` | `/org/freedesktop/secrets/item/{backend}/{id}` | Individual items (GetSecret, Label, Attributes) |
| `org.freedesktop.Secret.Session` | `/org/freedesktop/secrets/session/{id}` | Encryption sessions (plain algorithm only) |
| `org.freedesktop.Secret.Prompt` | `/org/freedesktop/secrets/prompt/*` | User prompts |

All write operations (`CreateItem`, `CreateCollection`, `Delete`, `SetSecret`) return `NotSupported`.

DH session crypto is explicitly deferred; only the `plain` algorithm is supported for MVP.

### Custom Interface: `org.rosec.Daemon`

Available at `/org/rosec/Daemon`:

| Method | Returns | Description |
|--------|---------|-------------|
| `Status()` | `(ssutu)` | Backend ID, name, cache size, last refresh epoch, active sessions |
| `Refresh()` | `u` | Force re-sync, returns item count |
| `BackendInfo()` | `(ss)` | Backend ID and name |

## Bitwarden Backend

The Bitwarden backend (`rosec-bitwarden`) implements a direct Bitwarden API client, compatible with both official Bitwarden servers and Vaultwarden. It does not depend on the official Bitwarden SDK.

### Authentication Flow

1. Daemon starts locked
2. On first D-Bus access requiring secrets, the prompt launcher asks for the master password
3. The backend performs: prelogin -> key derivation (PBKDF2 or Argon2id) -> login -> sync
4. Vault items are decrypted in-memory and cached
5. Background refresh re-syncs periodically (configurable via `refresh_interval_secs`)

### Item Attributes

Vault items are exposed with these D-Bus attributes:

| Attribute | Source |
|-----------|--------|
| `type` | Cipher type: `login`, `note`, `card`, `identity`, `sshkey` |
| `folder` | Decrypted folder name |
| `username` | Login username (logins only) |
| `uri` | First login URI (logins only) |
| `org_id` | Organization ID (org items only) |
| Custom fields | Text-type custom fields are exposed as attributes |

### Primary Secret

The "secret" returned by `GetSecret` depends on the cipher type:

| Type | Secret |
|------|--------|
| Login | Password |
| Secure Note | Notes content |
| Card | Card number |
| Identity / SSH Key | Notes content |

## Development

```bash
# Run all tests
cargo test --workspace

# Run clippy (must pass with zero warnings)
cargo clippy --workspace -- -D warnings

# Format code
cargo fmt --all

# Build all crates
cargo build --workspace
```

## Prior Art

- [`secretsd`](https://github.com/grawity/secretsd) — Generic Secret Service backend
- [`oo7`](https://github.com/bilelmoussaoui/oo7) — Pure Rust Secret Service client
- [`pass-secret-service`](https://github.com/mdellweg/pass_secret_service) — Secret Service backed by pass

## License

MIT
