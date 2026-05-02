# Bitwarden Secrets Manager Provider

The `bitwarden-sm` provider connects rosec to a [Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/) project using a machine account access token. It is designed for server or CI/CD use cases where secrets need to be available to automated processes without a human entering a master password interactively.

> **License note:** The Bitwarden Secrets Manager SDK used by this provider is distributed under the [Bitwarden SDK License Agreement](https://github.com/bitwarden/sdk/blob/main/LICENSE), which is not OSI-approved. The SM provider is shipped as a separate WASM plugin (`rosec_bitwarden_sm.wasm`) and can be excluded at package time.

## Requirements

- A Bitwarden Secrets Manager account with at least one project
- A machine account with an access token scoped to the desired project(s)
- The SM WASM plugin installed (see [Install](#install))

## Install

The SM provider is a WASM plugin. Copy it to the user provider directory:

```bash
cp rosec_bitwarden_sm.wasm ~/.local/share/rosec/providers/
```

Or to the system-wide directory for all users:

```bash
sudo cp rosec_bitwarden_sm.wasm /usr/lib/rosec/providers/
```

Verify it is discovered:

```bash
rosec provider kinds
# bitwarden-sm    Bitwarden Secrets Manager
```

## Adding a Bitwarden SM provider

```bash
rosec provider add bitwarden-sm
```

You will be prompted for:

1. **Key encryption password** — used to encrypt the access token at rest; stored locally, never sent to Bitwarden
2. **Access token** — a Bitwarden SM machine account access token (format: `<id>.<secret>`)

The access token is encrypted with the key encryption password and stored at `~/.local/share/rosec/providers/<id>.smcred`. It is decrypted only when the provider unlocks.

## Config

```toml
[[provider]]
id   = "my-sm-project"
kind = "bitwarden-sm"

[provider.options]
# base_url = "https://vault.bitwarden.eu"   # omit for bitwarden.com US
```

## Authenticating

```bash
# Unlock (prompts for key encryption password)
rosec provider auth my-sm-project

# Re-register with a new access token (e.g. after rotation)
rosec provider auth my-sm-project --force
```

When `--force` is used, you are prompted for both the key encryption password and a new access token. Leaving the token field blank re-uses the stored token (useful for changing only the key encryption password).

## Unlock flow

SM providers always require an interactive passphrase — there is no auto-unlock path without PAM. The passphrase is used to derive the decryption key for the stored access token; it is never stored.

SM providers participate in the opportunistic unlock sweep: if you unlock one SM provider, rosec tries the same passphrase against other locked SM providers.

## Accessing secrets

SM secrets appear in the unified namespace alongside items from other providers:

```bash
rosec search
rosec get name="DATABASE_URL"
```

## Attribute model

| Attribute | Value |
|---|---|
| `type` | `secret` |
| `name` | Secret name |
| `project` | Bitwarden SM project name |
| `custom.<key>` | Secret metadata fields |

Secret values are never exposed in D-Bus `Attributes` — only via `GetSecret`.

## Rotating the access token

```bash
rosec provider auth <id> --force
```

Enter the key encryption password, then paste the new access token. The stored credentials are re-encrypted with the same password.

## Rotating the key encryption password

```bash
rosec provider change-password <id>
```

Enter the current key encryption password, then the new one. The stored access token is re-encrypted without ever being decrypted to disk.

## Multiple SM projects

Add a provider for each project with a distinct ID:

```bash
rosec provider add bitwarden-sm --id infra-secrets
rosec provider add bitwarden-sm --id app-secrets
```

## Security notes

- The access token is stored encrypted on disk, wrapped by the key encryption password
- HKDF (HMAC-SHA256) is used to derive the AES encryption key from the passphrase and a machine-specific secret
- The passphrase is never stored — a wrong passphrase produces a wrong key and decryption fails
- All memory holding the passphrase or access token is zeroized after use
- The access token is never transmitted in a D-Bus message; it is read from the encrypted file inside the daemon process
