# Provider Capabilities

Each provider declares a set of capabilities — the optional pieces of functionality it supports beyond the bare Secret Service contract. The CLI shows these as compact single-letter codes in the **CAPS** column of `rosec provider list` and `rosec status`.

## Capability reference

| Code | Capability | Description |
|:----:|---|---|
| `S` | Sync | Provider can sync with a remote source. Enables `rosec sync` and the `-s` flag on `rosec search`. |
| `W` | Write | Provider supports creating, updating, and deleting items via D-Bus `CreateItem` / `Delete`. Required for `rosec item add`, `rosec item edit`, `rosec item import`, and `rosec item delete`. |
| `s` | Ssh | Provider exposes SSH keys to the built-in SSH agent. Keys are loaded automatically on unlock. See [SSH agent integration](../ssh-agent.md). |
| `K` | KeyWrapping | Provider supports key wrapping — multiple passwords can unlock the same vault. Enables `rosec provider add-password`, `remove-password`, and `list-passwords`. |
| `P` | PasswordChange | Provider supports changing the unlock password via `rosec provider change-password`. |
| `C` | OfflineCache | Provider supports offline cache export/restore. Previously synced data is available after reboot without network access. Requires both the provider capability and host-side `offline_cache = true` in config. |
| `N` | Notifications | Provider supports real-time push notifications via a WebSocket connection managed by the host. Enables immediate sync on remote vault changes. |
| `F` | Fido2 | Provider stores FIDO2/WebAuthn credentials (passkeys). rosec can serve these to browsers as a virtual security key. See [FIDO2 passkeys](../fido2-passkeys.md). |
| _(none)_ | Totp | Provider stores TOTP seeds. Items expose `rosec:totp=true` and can be read via `rosec totp get` or the TOTP FUSE filesystem. |

> **Note:** `Totp` is not currently assigned a single-letter display code and does not appear in the **CAPS** column of `rosec provider list`.

## Matrix

|                | `local` | `bitwarden` | `bitwarden-sm` | `gnome-keyring` | `keepassxc-file` *(experimental)* |
|----------------|:-------:|:-----------:|:--------------:|:---------------:|:---------------------------------:|
| **CAPS code**  | `WsKPF` | `SsCNF`     | `S`            | *(empty)*       | `SsF`                             |
| Sync           | --      | yes         | yes            | --              | yes                               |
| Write          | yes     | --          | --             | --              | --                                |
| Ssh            | yes     | yes         | --             | --              | yes                               |
| Fido2          | yes     | yes         | --             | --              | yes                               |
| KeyWrapping    | yes     | --          | --             | --              | --                                |
| PasswordChange | yes     | --          | --             | --              | --                                |
| OfflineCache   | --      | yes         | --             | --              | --                                |
| Notifications  | --      | yes         | --             | --              | --                                |
| Totp           | yes     | yes         | --             | --              | yes                               |

## Notes by provider

**[Local Vault](./local) (`local`)** — Fully writable, offline-only. Multiple unlock passwords via key wrapping (used for PAM auto-unlock when the login password differs from the master password). No sync because all data is local.

**[Bitwarden Password Manager](./bitwarden) (`bitwarden`)** — Read-only access to a Bitwarden / Vaultwarden account. Syncs from the API on a configurable interval and supports push notifications for immediate updates. SSH keys, TOTP seeds, passkeys, and offline cache all surface through the standard rosec interfaces.

**[Bitwarden Secrets Manager](./bitwarden-sm) (`bitwarden-sm`)** — Machine-to-machine provider for CI/CD and server use cases. Syncs secrets from a Bitwarden SM project using an access token. Password change for the key encryption password is handled host-side by the WASM runtime, not as a provider capability.

**GNOME Keyring (`gnome-keyring`)** — Read-only access to existing `~/.local/share/keyrings/*.keyring` files. No optional capabilities — items are loaded once at unlock time. Intended as a migration bridge: access old GNOME Keyring items while running rosec as the Secret Service daemon.

**[KeePassXC (file)](./keepassxc-file) (`keepassxc-file`)** *(experimental)* — Reads a KeePassXC `.kdbx` database directly from disk (KDBX 4). Decrypts in-memory; never writes back. The host's filesystem watcher (`host_watch`) re-decrypts automatically when KeePassXC saves the file. SSH keys stored via KeePassXC's built-in SSH-agent integration (binary attachment + `KeeAgent.settings`) are surfaced to the rosec SSH agent and FUSE, and passkeys stored via KeePassXC's passkey support are served through the [FIDO2 frontend](../fido2-passkeys.md).
