# CLI Reference

## Provider List

```bash
rosec provider list
```

Shows all configured providers with their status. The output includes a **CAPS** column showing a compact code for each provider's capabilities.

### Capability Codes

Each letter represents one capability the provider supports:

| Code | Capability | Description |
|:----:|---|---|
| `S` | Sync | Can sync with a remote source |
| `W` | Write | Supports creating, updating, and deleting items |
| `s` | Ssh | Exposes SSH keys to the built-in agent |
| `K` | KeyWrapping | Supports multiple unlock passwords |
| `P` | PasswordChange | Supports changing the unlock password |
| `C` | OfflineCache | Supports offline cache for use without network |
| `N` | Notifications | Supports real-time push notifications from the remote |
| _(none)_ | Totp | Stores TOTP seeds; enables `rosec totp` and TOTP FUSE filesystem |

`Totp` is not currently assigned a display code and does not appear in the CAPS column.

### Example

```
ID              NAME             KIND           CAPS     STATE     LAST SYNC
─────────────────────────────────────────────────────────────────────────────
local           My Vault         local          WsKP     unlocked  never
bitwarden       Bitwarden        bitwarden-pm   SsCN     unlocked  2m ago
gnome-keyring   GNOME Keyring    gnome-keyring           unlocked
```

- `WsKP` — local vault: write, SSH, key wrapping, password change
- `SsCN` — Bitwarden PM: sync, SSH, offline cache, notifications
- *(empty)* — gnome-keyring: read-only, no optional capabilities

The CAPS column also appears in `rosec status`.

See [docs/providers/capabilities.md](providers/capabilities.md) for which capabilities each provider type supports and what they mean in practice.

## Search

```bash
rosec search [key=value ...] [-s|--sync] [--format=table|kv|json|human]
```

Search for items across all providers. Attribute filters are `key=value` pairs; glob patterns (`*`, `?`, `[`) in values trigger glob matching.

The `-s` / `--sync` flag syncs all providers that support `Sync` before searching. Providers without the `Sync` capability are skipped silently.

To find all items that have a TOTP seed:

```bash
rosec search rosec:totp=true
```

Items with a TOTP seed have the public attribute `rosec:totp=true` stamped automatically by the daemon. This attribute can be used as a search filter by any client that calls `SearchItems({"rosec:totp": "true"})`.

## Sync

```bash
rosec sync
```

Triggers a sync on all providers that declare the `Sync` capability. Providers without it (e.g. `local`, `gnome-keyring`) are skipped.

## TOTP

```bash
rosec totp [--stdout] <item>
rosec totp get [--stdout] [-s|--sync] <item>
rosec totp add [--qr] <item>
```

`<item>` accepts the same identifiers as `rosec get`: a 16-character hex ID, a `key=value` attribute filter, or a full D-Bus object path.

### Getting a TOTP code

```bash
# Show code in GUI popup with clipboard (default)
rosec totp name=GitHub

# Print code to stdout (for scripting)
rosec totp --stdout name=GitHub

# Explicit get subcommand — same behaviour as bare `rosec totp`
rosec totp get a1b2c3d4e5f60718

# Sync providers first, then get code
rosec totp get --sync name=GitHub
```

The GUI popup displays the current code and copies it to the clipboard automatically. The code refreshes every 30 seconds (or the period configured in the TOTP seed).

### Adding a TOTP seed

```bash
# Add via hidden prompt (accepts an otpauth:// URI or raw base32 secret)
rosec totp add name=GitHub

# Add via QR scanner overlay
rosec totp add --qr name=GitHub
```

After entering the seed, the CLI generates a test code and asks you to confirm it matches your authenticator before saving. The seed is stored in the item's `totp` secret attribute.

### Reading codes from the FUSE filesystem

When `totp_fuse = true` (the default), TOTP codes are available as files under `$XDG_RUNTIME_DIR/rosec/totp/`:

```
totp/
├── by-name/<item-label>.code    # current code + newline
└── by-id/<hex-id>.code          # same, addressed by item hex ID
```

Each `.code` file generates the current code dynamically on every `read()`. The files disappear when the provider is locked. This makes it straightforward to use TOTP codes in scripts:

```bash
cat "$XDG_RUNTIME_DIR/rosec/totp/by-name/GitHub.code"
```

### D-Bus API

`GetTotpCode(item_path)` on the `org.rosec.Secrets` interface returns a `(code: String, seconds_remaining: u32)` tuple — the current code and how many seconds remain before it rotates.
