---
sidebar_position: 99
---

# FAQ

## Is this a drop-in replacement for GNOME Keyring?

For the Secret Service API, yes. Applications using `libsecret`, `secret-tool`, or talking to `org.freedesktop.secrets` directly will work unchanged. `rosec enable` writes the systemd / D-Bus activation files needed to take over the bus name from `gnome-keyring-daemon` and masks the upstream service so it doesn't fight you on login.

The PKCS#11 store and the Secrets-PIN-Entry agent that `gnome-keyring-daemon` ships are **not** implemented — if you depend on those, keep gnome-keyring around alongside.

If you have existing `~/.local/share/keyrings/*.keyring` files, the `gnome-keyring` provider mounts them read-only inside rosec so you can migrate without retyping every secret. See [Providers → GNOME Keyring](./providers/capabilities).

## Why does `gnome-keyring-daemon` keep stealing the bus name back?

Several distros ship XDG autostart entries that launch gnome-keyring before user services come up. `rosec enable` masks the autostart files (`~/.config/autostart/gnome-keyring-*.desktop` set to `Hidden=true`) and the D-Bus activation file. If something keeps re-creating these (e.g. a desktop environment update), rerun `rosec enable --force`. Full diagnosis in [Troubleshooting](./troubleshooting).

## How is the master password stored?

It isn't. The local vault derives an AES-256 key from the password via PBKDF2-SHA256 with a per-vault salt; only the wrapped key (and an HMAC) lives on disk. Unlocking re-derives the key in memory; locking zeroes it. The same password can wrap multiple key slots (the basis of the PAM-unlock flow) but the password itself never hits the filesystem.

For WASM providers, the password is held in the guest's WASM linear memory between `unlock()` and `lock()` so file-watch hot-reload can re-decrypt without re-prompting; the WASM sandbox is process-isolated and the entire `AuthState` is zeroized on `lock`.

## Where do SSH keys come from?

Three discovery paths, all transparent — rosec doesn't care which provider an item lives in:

1. **Native SSH-key items** — Bitwarden's first-class SSH Key item type, or the local vault's `--generate-ssh-key` flow.
2. **PEM scan** — `notes`, `password`, and any hidden custom field is scanned for `-----BEGIN ... PRIVATE KEY-----` blocks. So you can keep keys as Secure Notes if you want.
3. **KeePassXC SSH Agent integration** — entries with a `KeeAgent.settings` attachment + an embedded private-key attachment. Encrypted keys are decrypted with the entry's *Password* field. See [providers/keepassxc-file](./providers/keepassxc-file#ssh-keys).

Once discovered, keys are exposed through the rosec SSH agent at `$XDG_RUNTIME_DIR/rosec/ssh/agent.sock` and the `ssh/keys/by-name/`, `by-fingerprint/`, `by-host/` FUSE views.

## Can I write my own provider?

Yes — providers other than `local` are Extism WASM guests. You implement a small set of `plugin_fn` exports and the daemon does the rest (D-Bus surface, prompting, locking, sync, SSH agent integration). See `notes/internal/wasm-provider-guide.md` in the repo for the function contract and host-import reference.

## Why two FUSE mounts and not just one?

`$XDG_RUNTIME_DIR/rosec/ssh/` and `$XDG_RUNTIME_DIR/rosec/totp/` have different lifetimes and different access patterns:

- The **SSH agent** mount carries public keys and a generated `~/.ssh/config` snippet. It's static between syncs.
- The **TOTP mount** carries live, time-varying codes — every `read()` recomputes the current code from the seed. Putting these under the same tree would mean the TOTP filesystem invalidates the kernel cache continuously, which would force re-stat of every SSH entry too.

Both mounts are gated by `[service]` flags (`ssh_fuse = true`, `totp_fuse = true`); set either to `false` to disable.

## What's the threat model?

- **Trusted:** the local user account, `rosecd`'s own process, and any process that can read your `~/.config/rosec` or `$XDG_RUNTIME_DIR/rosec` (which is your account already).
- **Sandboxed:** WASM provider plugins. They can only touch host paths they were granted via the per-provider allow-list; network access is per-provider via `allowed_hosts`. They can't escape into the host filesystem or talk to D-Bus directly.
- **Out of scope:** root, kernel, hardware. If your machine is compromised at that level, no userspace daemon helps.

## Does rosec sync?

The daemon doesn't sync between machines — it's a local daemon. Individual providers may sync from their own remote source (Bitwarden does, KeePassXC reloads from the kdbx file on save, gnome-keyring is read-only). For multi-machine "same vault everywhere" use-cases, the cleanest path is a sync'd Bitwarden account, or a kdbx file under Syncthing.
