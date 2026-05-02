# Bitwarden Password Manager Provider

The `bitwarden` provider connects rosec to a Bitwarden (or Vaultwarden) account. Items in your vault are available read-only via the D-Bus Secret Service API. SSH keys are loaded into the built-in SSH agent automatically.

## Requirements

- A Bitwarden account (bitwarden.com, or a self-hosted Vaultwarden instance)
- `rosecd` running

## Adding a Bitwarden provider

```bash
rosec provider add bitwarden
```

You will be prompted for:

1. **Email address** — your Bitwarden account email
2. **Base URL** (optional) — leave blank for bitwarden.com; set for Vaultwarden or other self-hosted instances
3. **Master password** — used to decrypt your vault; never stored on disk

On first use, device registration is required. rosec registers itself as a device in your Bitwarden account (visible under Account Settings → Security → Devices). You may be asked to approve the login via email or your two-factor method.

To use a custom ID:

```bash
rosec provider add bitwarden --id personal
rosec provider add bitwarden --id work
```

## Config

```toml
[[provider]]
id   = "bitwarden"
kind = "bitwarden"
# tls_mode = "system"   # use OS trust store (for self-signed / private CA certs)

[provider.options]
email    = "user@example.com"
# base_url = "https://vaultwarden.example.com"   # omit for bitwarden.com
```

> **Self-hosted with a private CA?** If your Vaultwarden instance uses a
> certificate signed by a private CA, set `tls_mode = "system"` and make sure
> the CA is installed in your OS trust store. A bare self-signed certificate
> will not work — you need a proper CA that signs a leaf server certificate
> (otherwise TLS verification fails with `CaUsedAsEndEntity`). See the
> [FAQ](../../README.md#faq) for details and certificate generation instructions.

## Authenticating

```bash
# Normal unlock (prompts for master password)
rosec provider auth bitwarden

# Re-register the device (e.g. after rotating API credentials)
rosec provider auth bitwarden --force
```

## Syncing

The provider syncs automatically on a configurable interval. To trigger a sync immediately:

```bash
rosec sync
```

## Accessing items

All Bitwarden items are available through the standard D-Bus Secret Service API. Use `rosec` to search and retrieve:

```bash
# List all items
rosec search

# Filter by type or attribute
rosec search type=login
rosec search username=alice
rosec search uri=github.com

# Retrieve a secret value (pipeable)
rosec get name="GitHub token"

# Inspect all attributes for an item
rosec inspect <item-id>
```

## Attribute model

rosec exposes Bitwarden fields as flat attributes:

| Attribute | Value |
|---|---|
| `type` | `login`, `card`, `identity`, `note` |
| `username` | Login username |
| `uri` | Primary URI |
| `totp` | TOTP seed (sensitive) |
| `number` | Card number (sensitive) |
| `custom.<name>` | Custom fields |

Custom fields are prefixed with `custom.` to avoid collision with built-in names. Sensitive attributes (password, TOTP, card number, notes) are never exposed in D-Bus `Attributes` — they are only retrievable via `GetSecret`.

## SSH keys

SSH keys stored as Bitwarden items (type: SSH key, or login items with SSH key fields) are loaded automatically into the built-in agent. Tag items with a `custom.ssh_host` field to generate `~/.ssh/config` snippets. See [docs/ssh-agent.md](../ssh-agent.md).

## Two-factor authentication

When your Bitwarden account has two-factor authentication enabled, rosec will
detect the 2FA challenge during unlock and prompt you on the terminal.

### Supported methods

| Method | Bitwarden code | How it works in rosec |
|--------|:--------------:|------|
| **Authenticator app (TOTP)** | 0 | Prompts for a 6-digit code from your authenticator app |
| **Email** | 1 | Prompts for the code sent to your account email |
| **YubiKey OTP** | 3 | Touch your YubiKey; the OTP is typed directly into the terminal |
| **Duo (passcode)** | 2, 6 | Prompts for a Duo bypass code or passcode |

If multiple methods are available, rosec shows a numbered list and lets you choose.

### Not yet supported

| Method | Notes |
|--------|-------|
| **FIDO2 / WebAuthn** | Requires host-side hardware key access; deferred (see FUTURE.md) |
| **Duo push / call** | Requires browser redirect; only passcode mode is supported |
| **Remember token** | 30-day remember-me token caching is planned |

### Example

```
Master Password: ********
Two-factor authentication required.
Available methods:
  [1] Authenticator app (TOTP)
  [2] Email code
Choose method: 1

Authenticator app (TOTP): 123456
vault unlocked: ciphers=42
```

## Multiple accounts

Add a second provider with a different ID:

```bash
rosec provider add bitwarden --id work
```

Items from both accounts appear in the unified namespace. Use `rosec search` to filter by provider if needed.

## Vaultwarden / self-hosted

Set `base_url` to your instance URL:

```bash
rosec provider add bitwarden base_url=https://vaultwarden.example.com
```

Or in config:

```toml
[provider.options]
email    = "user@example.com"
base_url = "https://vaultwarden.example.com"
```

## Security notes

- The master password is used to decrypt the vault key locally and is never transmitted to the server
- The vault key and decrypted items are held in memory only while the provider is unlocked
- All memory containing key material or decrypted secrets is zeroized on lock or shutdown
- Device registration credentials are stored encrypted on disk, wrapped by the master password
