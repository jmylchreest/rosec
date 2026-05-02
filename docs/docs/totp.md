# TOTP

`rosecd` extracts time-based one-time-password (TOTP) seeds from any provider that declares the `Totp` capability and exposes the live codes through three interfaces: a CLI command, a FUSE filesystem, and a D-Bus method. The seed itself is stored as a `totp` secret on the item; `rosecd` computes the current code on demand and never persists the rotated value.

## How items become TOTP-bearing

An item participates in TOTP discovery if it has both:

- a `totp` secret containing either a base32 seed or an `otpauth://totp/...` URI, and
- the public attribute `rosec:totp=true`.

The daemon stamps `rosec:totp=true` automatically whenever an item gains a `totp` secret, so in practice you only need to add the seed — the attribute follows. WASM provider plugins are responsible for stamping the attribute themselves; the local vault does it host-side.

To list TOTP-bearing items:

```bash
rosec search rosec:totp=true
```

## CLI

```bash
rosec totp [--stdout] <item>
rosec totp get [--stdout] [-s|--sync] <item>
rosec totp add [--qr] <item>
```

`<item>` accepts the same identifiers as `rosec get`: a 16-character hex ID, a `key=value` attribute filter, or a full D-Bus object path.

### Getting a code

```bash
# GUI popup with clipboard (default)
rosec totp name=GitHub

# Print to stdout (for scripting)
rosec totp --stdout name=GitHub

# Explicit get subcommand — same as bare `rosec totp`
rosec totp get a1b2c3d4e5f60718

# Sync providers first, then get the code
rosec totp get --sync name=GitHub
```

The GUI popup shows the current code and copies it to the clipboard. It refreshes every 30 s (or the period configured in the TOTP seed).

### Adding a seed

```bash
# Hidden prompt — accepts an otpauth:// URI or raw base32 secret
rosec totp add name=GitHub

# QR scanner overlay
rosec totp add --qr name=GitHub
```

After entering the seed, the CLI generates a test code and asks you to confirm it matches your authenticator before saving.

## FUSE filesystem

When `totp_fuse = true` in `[service]` (the default), `rosecd` mounts a virtual filesystem at `$XDG_RUNTIME_DIR/rosec/totp/`:

```
totp/
├── by-name/<item-label>.code    # current code + newline
└── by-id/<hex-id>.code          # same, addressed by item hex ID
```

Each `.code` file regenerates the current code on every `read()`. Files disappear when the underlying provider is locked. This makes scripting trivial:

```bash
cat "$XDG_RUNTIME_DIR/rosec/totp/by-name/github.code"
```

The mount is read-only and entirely in-memory — the seed never hits disk via this path. Disable in `config.toml`:

```toml
[service]
totp_fuse = false
```

## D-Bus

`GetTotpCode(item_path)` on the `org.rosec.Secrets` interface returns `(code: String, seconds_remaining: u32)` — the current code plus how many seconds remain before it rotates. Useful for building integrations without scraping the FUSE mount.
