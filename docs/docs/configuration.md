# rosec — Configuration Reference

Config file: `$XDG_CONFIG_HOME/rosec/config.toml` (default: `~/.config/rosec/config.toml`)

## Editing from the CLI

Read or change individual settings without opening the file — the daemon
hot-reloads on `set`:

```bash
rosec config show                                 # print the resolved config
rosec config get autolock.idle_timeout_minutes    # read one dotted key
rosec config set service.refresh_interval_secs 120
```

The reference below documents every key.

---

## `[service]`

Controls vault caching and deduplication behaviour.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dedup_strategy` | string | `"newest"` | How to resolve duplicate items across providers. See [Deduplication](#deduplication). |
| `dedup_time_fallback` | string | `"created"` | Timestamp field used when `dedup_strategy = "newest"`. `"created"` or `"none"`. |
| `refresh_interval_secs` | integer | `60` | How often (seconds) to re-sync each provider. Set to `0` to disable periodic refresh. |
| `ssh_fuse` | bool | `true` | Mount the SSH FUSE filesystem at `$XDG_RUNTIME_DIR/rosec/ssh/`. Set to `false` to disable. See [ssh-agent.md](ssh-agent.md). |
| `totp_fuse` | bool | `true` | Mount the TOTP FUSE filesystem at `$XDG_RUNTIME_DIR/rosec/totp/`. Set to `false` to disable. |
| `fido2` | bool | `false` | Serve stored passkeys to browsers as a virtual security key. Requires the `rosec-uhid` broker; off by default. See [FIDO2 passkeys](fido2-passkeys.md). |
| `wasm_prefer` | string | `"user"` | Which copy wins when a WASM provider kind exists in both the system and user provider directories: `"user"`, `"system"`, or `"newest"`. |
| `wasm_verify` | string | `"required"` | Signature verification for WASM provider plugins: `"required"` or `"disabled"` (local plugin development only). |
| `wasm_trusted_key` | array of tables | `[]` | Additional trust anchors for WASM plugin signatures. See [Trusted plugin signing keys](#trusted-plugin-signing-keys). |

### Trusted plugin signing keys

By default a WASM plugin only loads when its bundle is signed by a rosec
release key embedded in the binary. To run a plugin signed by a third party
(e.g. a partner shipping their own provider) *without* the global off-switch of
`wasm_verify = "disabled"`, add the author's minisign public key as a trust
anchor:

```toml
[[service.wasm_trusted_key]]
key   = "RWQ..."          # base64 minisign public key (second line of the .pub file)
name  = "acme-corp"       # label shown in logs and `rosec provider validate`
kinds = ["acme-vault"]    # optional: kinds this key may vouch for (empty = any)
```

Scoping `kinds` limits the blast radius of the extended trust: the key is only
consulted for plugins whose signed policy declares one of the listed kinds.
rosecd logs a `warn!` at startup whenever a plugin loads on the strength of a
user-trusted key rather than a release key, and
`rosec provider validate <kind>` shows the same provenance.

### Deduplication

When multiple providers return an item with the same label or attributes, rosec
picks one winner according to `dedup_strategy`:

| Value | Behaviour |
|-------|-----------|
| `"newest"` | Keep the item with the most recent modification time. Falls back to `dedup_time_fallback` if modification time is unavailable. |
| `"priority"` | Keep the item from the provider listed first in `config.toml`. |
| `"none"` | Expose all copies; clients see duplicates. |

---

## `[autolock]`

Controls when the daemon locks providers automatically. These are **global
defaults** — individual providers can override any field via
`[provider.autolock]` (see below).

The defaults mirror KWallet/GNOME Keyring behaviour: providers stay unlocked for
the session duration and lock only on logout.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `on_logout` | bool | `true` | Lock when the user session ends (logind `SessionRemoved`). |
| `on_session_lock` | bool | `false` | Lock when the screen is locked (logind `Lock` signal). |
| `idle_timeout_minutes` | integer or omitted | _(none)_ | Lock after this many minutes of D-Bus inactivity. Omit or set to `0` to disable. |
| `max_unlocked_minutes` | integer or omitted | _(none)_ | Hard upper limit on how long a provider stays unlocked. Omit or set to `0` to disable. |

> **Note:** `PrepareForSleep` (suspend/hibernate) always locks all providers
> regardless of config — this is not configurable.

---

## `[prompt]`

Controls the unlock prompt shown when a secret is requested and the vault is locked.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `backend` | string | `"builtin"` | `"builtin"` uses the bundled `rosec-prompt` GUI. Any other value is treated as a path to an external prompter binary. |
| `args` | array of strings | `[]` | Arguments passed to an external prompter. Supports template placeholders. |

### External prompter

When `backend` is a binary path, rosec spawns it as a subprocess, passes the
prompt request via stdin as JSON, and reads the response from stdout.

Template placeholders in `args`:

| Placeholder | Value |
|-------------|-------|
| `{{title}}` | Prompt window title |
| `{{message}}` | Human-readable description |
| `{{hint}}` | Short context hint (e.g. provider name) |
| `{{backend}}` | Provider ID (template variable name kept for back-compat with custom prompters) |

Example:

```toml
[prompt]
backend = "/usr/bin/my-prompter"
args = [
  "--title={{title}}",
  "--message={{message}}",
  "--hint=Backend: {{backend}}",
]
```

### `[prompt.theme]`

Theming for the built-in `rosec-prompt` GUI. All color values accept `#RRGGBBAA`
or `#RRGGBB` hex format (alpha defaults to `ff` if omitted).

| Field | Short alias(es) | Default | Description |
|-------|-----------------|---------|-------------|
| `background` | `bg` | `#1e1e2eff` | Window background |
| `foreground` | `fg` | `#cdd6f4ff` | Primary text |
| `label_color` | `lc` | `#a6adc8ff` | Secondary / hint text |
| `accent_color` | `ac` | `#7aa2f7ff` | Accent color (focus rings, highlights) |
| `input_background` | `ibg` | `#181825ff` | Password field background |
| `input_text` | `it` | `#cdd6f4ff` | Password field text |
| `border_color` | `bd`, `bdr` | `#89b4faff` | Window border |
| `border_width` | `bw` | `2` | Border width in pixels |
| `font_family` | `font` | `"monospace"` | Font family name |
| `font_size` | `size` | `14` | Font size in pixels |
| `confirm_background` | `ybg` | _(accent)_ | Unlock button background (empty = use accent) |
| `confirm_text` | `yt` | _(foreground)_ | Unlock button text (empty = use foreground) |
| `cancel_background` | `nbg` | _(accent)_ | Cancel button background (empty = use accent) |
| `cancel_text` | `nt` | _(foreground)_ | Cancel button text (empty = use foreground) |

Example (Catppuccin Mocha palette):

```toml
[prompt.theme]
bg   = "#1e1e2ecc"
fg   = "#cdd6f4ff"
lc   = "#a6adc8ff"
ac   = "#7aa2f7ff"
ibg  = "#181825ff"
it   = "#cdd6f4ff"
bd   = "#89b4faff"
bw   = 2
font = "monospace"
size = 14
```

---

## `[[provider]]`

Each `[[provider]]` section registers one secrets source. Multiple providers can
be listed; items are deduplicated across them (see [Deduplication](#deduplication)).

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `id` | string | yes | Unique identifier for this provider. Used in D-Bus paths and CLI commands. |
| `kind` | string | yes | Provider type. Currently: `"local"`, `"bitwarden"`, `"bitwarden-sm"`, `"gnome-keyring"`, `"keepassxc-file"`. |
| `path` | string | sometimes | Path to the on-disk file backing this provider. Required for `local` (vault file) and `keepassxc-file` (kdbx file). `~/` is expanded to `$HOME`. |
| `collection` | string | no | Stamp a `collection` attribute onto every item from this provider. Useful for grouping in multi-provider setups. |
| `return_attr` | array of strings | no | Ordered list of glob patterns selecting which sensitive attribute to return via `GetSecret`. First match wins. Default: `["password", "number", "private_key", "notes"]`. |
| `match_attr` | array of strings | no | Glob patterns controlling which attributes participate in `SearchItems` filtering. Reserved for future use. |
| `tls_mode` | string | no | TLS certificate verification for plugin HTTP requests. `"bundled"` (default): Mozilla root certs only. `"system"`: use the OS trust store (for self-signed / private CA certs). |
| `tls_mode_probe` | string | no | TLS certificate verification for readiness probes. Inherits from `tls_mode` if not set. `"disabled"`: skip TLS verification. `"system"`: OS trust store. `"bundled"`: Mozilla root certs. |
| `offline_cache` | bool | no | Enable encrypted offline cache export/restore for providers that declare the `OfflineCache` capability. Default: `true`. |
| `unlock_timeout_secs` | integer | no | Maximum seconds to wait for this provider's unlock (readiness probes + authentication) during the parallel multi-provider unlock flow. If exceeded, the attempt is cancelled without blocking other providers. Default: `30`. |

### `[provider.autolock]` — Per-provider autolock overrides

Each provider can have its own `[provider.autolock]` sub-table. Fields not
specified inherit from the global `[autolock]` section. This lets you, for
example, keep a work provider locked more aggressively while leaving your
personal provider unlocked for the session.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `on_logout` | bool | _(inherit)_ | Override the global `on_logout` for this provider. |
| `on_session_lock` | bool | _(inherit)_ | Override the global `on_session_lock` for this provider. |
| `idle_timeout_minutes` | integer | _(inherit)_ | Override the global idle timeout. `0` explicitly disables. |
| `max_unlocked_minutes` | integer | _(inherit)_ | Override the global max-unlocked timeout. `0` explicitly disables. |

Example:

```toml
[[provider]]
id   = "work"
kind = "bitwarden"

[provider.options]
email = "work@example.com"

[provider.autolock]
idle_timeout_minutes = 5
on_session_lock      = true
```

### `[provider.options]` — Local vault (`kind = "local"`)

| Key | Required | Description |
|-----|----------|-------------|
| `path` | no | Vault file path. Defaults to `~/.local/share/rosec/providers/<id>.vault`. May also be set as the top-level `path` field on `[[provider]]`. |

See [providers/local.md](providers/local.md).

### `[provider.options]` — Bitwarden Personal Vault (`kind = "bitwarden"`)

| Key | Required | Description |
|-----|----------|-------------|
| `email` | yes | Bitwarden account email address. |
| `base_url` | no | Server URL. Omit for official US cloud (`https://vault.bitwarden.com`). Set to your Vaultwarden instance for self-hosted. |

### `[provider.options]` — Bitwarden Secrets Manager (`kind = "bitwarden-sm"`)

Available when the `bitwarden-sm` feature is compiled in.

| Key | Required | Description |
|-----|----------|-------------|
| `access_token` | yes | Machine account access token from the SM web vault. |
| `organization_id` | yes | Organization UUID. |
| `server_url` | no | SM API base URL. Omit for official cloud. |

### `[provider.options]` — GNOME Keyring (`kind = "gnome-keyring"`)

Read-only access to existing `~/.local/share/keyrings/*.keyring` files. No required options; the plugin scans the standard keyring directory at unlock time.

### `[provider.options]` — KeePassXC file (`kind = "keepassxc-file"`) *— experimental*

Reads a KeePassXC `.kdbx` (KDBX 4) directly from disk. Read-only. See [providers/keepassxc-file.md](providers/keepassxc-file.md) for a full setup guide including TOTP and SSH key conventions.

| Key | Required | Description |
|-----|----------|-------------|
| `path` | yes | Absolute or `~/`-prefixed path to the `.kdbx` database. |
| `key_file` | no | Path to a key file used as a second factor. When set, master password becomes optional (KeePassXC permits key-file-only authentication). |

---

## Legacy `[[vault]]` and `[[backend]]` sections

Earlier rosec releases used `[[vault]]` for local encrypted vaults and `[[backend]]` for remote sources. These names are **no longer recognised** — the only section the daemon parses is `[[provider]]`. If you have an old configuration, replace `[[backend]]` with `[[provider]]`, `[[vault]]` with `[[provider]] kind = "local"`, and rename `type = ` to `kind = `.

---

## Full example

```toml
[service]
dedup_strategy        = "newest"
dedup_time_fallback   = "created"
refresh_interval_secs = 60
ssh_fuse              = true
totp_fuse             = true
fido2                 = false


# Global defaults — providers stay unlocked for the session, lock on logout.
[autolock]
on_logout             = true
on_session_lock       = false
# idle_timeout_minutes  = 15   # uncomment to enable
# max_unlocked_minutes  = 240  # uncomment to enable

[prompt]
backend = "builtin"

[prompt.theme]
bg   = "#1e1e2ecc"
fg   = "#cdd6f4ff"
lc   = "#a6adc8ff"
ac   = "#7aa2f7ff"
ibg  = "#181825ff"
it   = "#cdd6f4ff"
bd   = "#89b4faff"
bw   = 2
font = "monospace"
size = 14

# Local encrypted vault — fully writable, offline-only.
[[provider]]
id   = "local"
kind = "local"
path = "~/.local/share/rosec/vaults/local.vault"

# Personal Bitwarden vault — uses global autolock defaults.
[[provider]]
id   = "personal"
kind = "bitwarden"

[provider.options]
email    = "user@example.com"
# base_url = "https://your-vaultwarden.example.com"

# Work Secrets Manager org (bitwarden-sm feature required).
# Stricter autolock: 5-minute idle, lock on screen lock.
[[provider]]
id         = "work-sm"
kind       = "bitwarden-sm"
collection = "work"

[provider.options]
access_token    = "0.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.secret:key"
organization_id = "00000000-0000-0000-0000-000000000000"

[provider.autolock]
idle_timeout_minutes = 5
on_session_lock      = true

# KeePassXC kdbx (read-only, experimental).
[[provider]]
id   = "kp-personal"
kind = "keepassxc-file"
path = "~/Passwords.kdbx"

[provider.options]
# key_file = "~/Passwords.keyx"
```
