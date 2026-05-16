# rosec

A [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/latest/) daemon for Linux — a multi-provider replacement for GNOME Keyring's Secret Service implementation. Any application that uses `libsecret`, `secret-tool`, or talks directly to `org.freedesktop.secrets` reads secrets from your configured providers transparently. No code changes required.

📖 **Documentation:** [jmylchreest.github.io/rosec](https://jmylchreest.github.io/rosec)

## What it does

| | |
|---|---|
| **Multi-provider** | Local encrypted vault, Bitwarden Password Manager, Bitwarden Secrets Manager, KeePassXC `.kdbx` files, read-only GNOME Keyring (for migration). All visible as one unified collection on the bus. |
| **SSH agent** | SSH keys stored in any provider auto-populate a built-in agent at `$XDG_RUNTIME_DIR/rosec/ssh/agent.sock` — no manual `ssh-add`. Optional FUSE filesystem exposes public keys + an auto-generated `~/.ssh/config` snippet. |
| **TOTP** | Items with a TOTP seed appear as live files under `$XDG_RUNTIME_DIR/rosec/totp/`. `cat` for the current code. |
| **PAM unlock** | Log in once, vaults unlock automatically using your login password. |
| **XDG Portal** | Sandboxed apps (Flatpak, Snap) get per-app secrets via the `org.freedesktop.impl.portal.Secret` backend. |
| **Sandboxed plugins** | Non-built-in providers run as Extism WASM guests with per-file allow-listing. The plugin can't read anything you didn't authorise. |

## Install

### Arch Linux (AUR)

```bash
yay -S rosec-bin                              # daemon, CLI, PAM helper
yay -S rosec-provider-bitwarden-pm-bin        # optional providers — install only what you need
yay -S rosec-provider-bitwarden-sm-bin
yay -S rosec-provider-gnome-keyring-bin
yay -S rosec-provider-keepassxc-file-bin      # experimental
```

### Build from source

```bash
git clone https://github.com/jmylchreest/rosec
cd rosec
just install        # builds + installs to ~/.local/bin and ~/.local/share/rosec/providers
```

(`just build-release` and `just build-wasm` are available individually.)

### Enable as the Secret Service daemon

```bash
rosec enable        # writes systemd / D-Bus activation files, masks gnome-keyring-daemon
systemctl --user start rosecd
```

Full installation guide, including PAM and display-manager setup, lives at the [docs site](https://jmylchreest.github.io/rosec/installation).

## How it feels in practice

```bash
# Add a provider, unlock it
rosec provider add local
rosec unlock

# Use it from any libsecret-aware tool
rosec item add --provider local --label "GitHub" --attr username=alice --secret 'hunter2'
secret-tool lookup label "GitHub"             # → hunter2
```

### SSH agent

Any SSH key in any provider — first-class SSH-key items, PEM blobs in notes, KeePassXC's KeeAgent attachment integration — gets registered automatically:

```bash
$ export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rosec/ssh/agent.sock"
$ ssh-add -l
256 SHA256:zBO1FdFfWhPfGfAJJMEPS2aog5C1b/06o7h0m2t1W/o rosec-kpxc-test (ED25519)
3072 SHA256:GDyUpSY2eyXYHCkUeADBhoWn/LWLvM3GI8cO8DQBI7k jmylchreest-github (RSA)

$ ssh git@github.com         # signs with the matching key, no `ssh-add` needed
```

Public keys + a generated SSH config are also exposed via FUSE so you can drop the agent socket into existing tooling:

```text
$XDG_RUNTIME_DIR/rosec/ssh/
├── agent.sock                    # SSH agent socket — point SSH_AUTH_SOCK here
├── keys/
│   ├── by-name/<item>.pub        # public key per vault item
│   ├── by-fingerprint/<sha256>.pub
│   └── by-host/<host>.pub        # one per ssh_host attribute
└── config.d/<provider>-<item>.conf  # ssh config snippet — `Host <pattern>` blocks pointing at agent.sock
```

Add `Include $XDG_RUNTIME_DIR/rosec/ssh/config.d/*` near the top of your `~/.ssh/config` and any item with an `ssh_host` attribute auto-routes through rosec.

### TOTP

```bash
$ ls "$XDG_RUNTIME_DIR/rosec/totp/by-name/"
github  gitlab  github_signing

$ cat "$XDG_RUNTIME_DIR/rosec/totp/by-name/github"
384295        # ← live, recomputed on every read
```

Or via the CLI: `rosec totp get github`.

## FAQ

A handful of greatest hits — the [FAQ on the docs site](https://jmylchreest.github.io/rosec/faq) has the full set.

**Is this a drop-in for GNOME Keyring?** For the Secret Service API, yes. PKCS#11 and the gnome-keyring SSH agent are not implemented; if you depend on those keep gnome-keyring around alongside.

**Does the daemon sync between machines?** No — rosec is a local daemon. Sync happens within individual providers (Bitwarden API, KeePassXC kdbx via Syncthing, etc.).

**How is the master password stored?** It isn't — only a wrapped key. PBKDF2-SHA256 with a per-vault salt, AES-256 wrap. Unlocking re-derives in memory; locking zeroes it.

**Can I write a custom provider?** Yes — providers other than `local` are Extism WASM guests. See the [WASM Provider Guide](https://jmylchreest.github.io/rosec/developers/wasm-provider-guide).

**`gnome-keyring-daemon` keeps grabbing the bus name back.** Run `rosec enable --force` to rewrite the autostart and D-Bus mask files, then re-login. Full diagnosis on the [troubleshooting page](https://jmylchreest.github.io/rosec/troubleshooting).

**Chromium / Vivaldi / Brave says "Encrypted keystore changed".** Cross-provider duplicate; dedup served the wrong copy. Find the right value with `rosec search --no-dedup --provider <id> application=chrome`, then replant it with `rosec item import --force --provider local` (piping the TOML). Full walk-through on the [troubleshooting page](https://jmylchreest.github.io/rosec/troubleshooting).

## Status

Active development. The `local`, `bitwarden`, `bitwarden-sm`, and `gnome-keyring` providers are stable. The `keepassxc-file` provider is **experimental** — interfaces and on-disk caching may change between releases.

## Licence

[MIT](LICENSE).
