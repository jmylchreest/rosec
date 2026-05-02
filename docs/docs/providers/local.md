# Local Vault Provider

The `local` provider stores secrets in an AES-256-CBC encrypted file on disk. It is the only provider with full write support — items can be created, updated, and deleted via the D-Bus Secret Service API or via `libsecret`-compatible applications.

## When to use

- Application session tokens and API keys that don't belong in a remote vault
- Machine-specific secrets that shouldn't sync across devices
- Development credentials and test keys
- Any secret you want available offline and under your direct control

## Adding a local vault

```bash
rosec provider add local
```

You will be prompted for a master password. Because the vault file does not yet exist, you must confirm the password before it is created.

To use a custom ID or path:

```bash
rosec provider add local --id work --path ~/vaults/work.vault
```

The default path is `~/.local/share/rosec/providers/<id>.vault`.

## Attaching an existing vault

If you already have a vault file (e.g. shared via Syncthing or rsync):

```bash
rosec provider attach --path /path/to/file.vault --id shared
rosec provider auth shared
```

## Config

```toml
[[provider]]
id   = "local"
kind = "local"

[provider.options]
path = "~/.local/share/rosec/providers/local.vault"
```

`path` defaults to `~/.local/share/rosec/providers/<id>.vault` if omitted.

## Key wrapping

The vault data is encrypted with a randomly-generated vault key. That key is then "wrapped" (encrypted) by one or more unlock passwords. This means:

- Multiple passwords can unlock the same vault (useful for PAM auto-unlock)
- Adding or removing a password only changes the wrapping layer — vault data is never re-encrypted
- Changing the master password does not require re-encrypting any items

```bash
# Add an unlock password (e.g. your PAM login password)
rosec provider add-password local --label pam

# List wrapping entries
rosec provider list-passwords local

# Remove a wrapping entry by ID
rosec provider remove-password local <entry-id>

# Replace an existing wrapping entry with a new password
rosec provider change-password local
```

## PAM auto-unlock

To unlock this vault automatically at login, add a wrapping entry whose password matches your login password:

```bash
rosec provider add-password local --label pam
# Enter your LOGIN password (not the vault master password)
```

Then configure PAM — see the [PAM auto-unlock section in the README](../../README.md#pam-auto-unlock).

If your login password and vault master password are the same, no extra wrapping entry is needed.

## Write routing

When multiple providers are configured, `rosecd` needs to know which one to use for `CreateItem` calls (e.g. from password managers saving new entries). Set `write_provider` in `config.toml`:

```toml
[service]
write_provider = "local"
```

If a provider with id `"local"` exists and `write_provider` is not set, it is used automatically.

## Cryptography

| Parameter | Value |
|---|---|
| Data encryption | AES-256-CBC |
| Key derivation (unlock) | PBKDF2-HMAC-SHA256, 600 000 iterations |
| Key wrapping | PBKDF2-HMAC-SHA256 → AES-256-CBC wrap of vault key |
| MAC | HMAC-SHA256, HKDF-derived key (`salt = b"rosec-vault-mac-v1"`) |
| Vault key | 32 bytes, `rand::rng().fill_bytes()` |
| IV | 16 bytes random per encryption |

The vault file is JSON and stores only ciphertext, HMAC, and the wrapping entries (which contain only the wrapped vault key, KDF parameters, and a label). No plaintext secrets, no master password hash, and no plaintext vault key are ever written to disk.

## Vault file format

```json
{
  "version": 1,
  "wrapping_entries": [
    {
      "id": "a1b2c3d4...",
      "label": "master",
      "kdf": { "algorithm": "pbkdf2-sha256", "iterations": 600000, "salt": "..." },
      "wrapped_key": "..."
    }
  ],
  "iv": "...",
  "ciphertext": "...",
  "hmac": "..."
}
```

## Removing a vault

```bash
# Remove from config and delete the vault file
rosec provider remove local

# Remove from config but keep the file on disk
rosec provider detach local
```
