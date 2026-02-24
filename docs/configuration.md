# rosec — Configuration Reference

Config file: `$XDG_CONFIG_HOME/rosec/config.toml` (default: `~/.config/rosec/config.toml`)

---

## `[service]`

Controls vault caching and deduplication behaviour.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dedup_strategy` | string | `"newest"` | How to resolve duplicate items across backends. See [Deduplication](#deduplication). |
| `dedup_time_fallback` | string | `"created"` | Timestamp field used when `dedup_strategy = "newest"`. `"created"` or `"none"`. |
| `refresh_interval_secs` | integer | `60` | How often (seconds) to re-sync each backend. Set to `0` to disable periodic refresh. |

### Deduplication

When multiple backends return an item with the same label or attributes, rosec
picks one winner according to `dedup_strategy`:

| Value | Behaviour |
|-------|-----------|
| `"newest"` | Keep the item with the most recent modification time. Falls back to `dedup_time_fallback` if modification time is unavailable. |
| `"priority"` | Keep the item from the backend listed first in `config.toml`. |
| `"none"` | Expose all copies; clients see duplicates. |

---

## `[autolock]`

Controls when the daemon locks the vault automatically.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `on_logout` | bool | `true` | Lock when the user session ends. |
| `on_session_lock` | bool | `true` | Lock when the screen is locked (logind `LockedHint`). |
| `idle_timeout_minutes` | integer or `null` | `15` | Lock after this many minutes of inactivity. `null` or `0` disables. |
| `max_unlocked_minutes` | integer or `null` | `240` | Hard upper limit on how long the vault stays unlocked. `null` or `0` disables. |

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
| `{{hint}}` | Short context hint (e.g. backend name) |
| `{{backend}}` | Backend ID |

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

## `[[backend]]`

Each `[[backend]]` section registers one secrets source. Multiple backends can
be listed; items are deduplicated across them (see [Deduplication](#deduplication)).

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `id` | string | yes | Unique identifier for this backend. Used in D-Bus paths and CLI commands. |
| `type` | string | yes | Backend type. Currently: `"bitwarden"`, `"bitwarden-sm"`. |
| `collection` | string | no | Stamp a `collection` attribute onto every item from this backend. Useful for grouping in multi-backend setups. |
| `return_attr` | array of strings | no | Ordered list of glob patterns selecting which sensitive attribute to return via `GetSecret`. First match wins. Default: `["password", "number", "private_key", "notes"]`. |
| `match_attr` | array of strings | no | Glob patterns controlling which attributes participate in `SearchItems` filtering. Reserved for future use. |

### `[backend.options]` — Bitwarden Personal Vault (`type = "bitwarden"`)

| Key | Required | Description |
|-----|----------|-------------|
| `email` | yes | Bitwarden account email address. |
| `base_url` | no | Server URL. Omit for official US cloud (`https://vault.bitwarden.com`). Set to your Vaultwarden instance for self-hosted. |

### `[backend.options]` — Bitwarden Secrets Manager (`type = "bitwarden-sm"`)

Available when the `bitwarden-sm` feature is compiled in.

| Key | Required | Description |
|-----|----------|-------------|
| `access_token` | yes | Machine account access token from the SM web vault. |
| `organization_id` | yes | Organization UUID. |
| `server_url` | no | SM API base URL. Omit for official cloud. |

---

## Full example

```toml
[service]
dedup_strategy        = "newest"
dedup_time_fallback   = "created"
refresh_interval_secs = 60

[autolock]
on_logout             = true
on_session_lock       = true
idle_timeout_minutes  = 15
max_unlocked_minutes  = 240

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

# Personal vault
[[backend]]
id   = "personal"
type = "bitwarden"

[backend.options]
email    = "user@example.com"
# base_url = "https://your-vaultwarden.example.com"

# Work Secrets Manager org (bitwarden-sm feature required)
[[backend]]
id         = "work-sm"
type       = "bitwarden-sm"
collection = "work"

[backend.options]
access_token    = "0.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.secret:key"
organization_id = "00000000-0000-0000-0000-000000000000"
```
