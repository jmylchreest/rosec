# rosec

rosec integrates multiple secret backends into one secure desktop experience on Linux. Configure providers once and a single systemd user service serves them everywhere your system already looks: the [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/latest/) Secret Service, an SSH agent, live TOTP files, FIDO2/WebAuthn passkeys, and PAM unlock at login. No application changes required.

📖 **Documentation:** [jmylchreest.github.io/rosec](https://jmylchreest.github.io/rosec)

## Features

| | |
|---|---|
| **Providers** | Local encrypted vault, Bitwarden Password Manager, Bitwarden Secrets Manager, KeePassXC `.kdbx` files, read-only GNOME Keyring (for migration). All appear as one unified collection. |
| **Secret Service** | Drop-in `org.freedesktop.secrets` implementation, replacing GNOME Keyring's. Works with `libsecret`, `secret-tool`, and anything that talks to the bus directly. |
| **SSH agent** | Keys from any provider auto-populate a built-in agent at `$XDG_RUNTIME_DIR/rosec/ssh/agent.sock`, no manual `ssh-add`. Optional FUSE tree exposes public keys and generated `~/.ssh/config` snippets. |
| **TOTP** | Items with a TOTP seed appear as live files under `$XDG_RUNTIME_DIR/rosec/totp/`. `cat` for the current code. |
| **FIDO2 passkeys** | Opt-in virtual security key. Unmodified browsers register and sign in with passkeys held in any provider. Requires the optional `rosec-uhid` broker. |
| **PAM unlock** | Log in once; vaults unlock automatically with your login password. |
| **XDG Portal** | Sandboxed apps (Flatpak, Snap) get per-app secrets via the `org.freedesktop.impl.portal.Secret` backend. |
| **Sandboxed plugins** | Non-built-in providers run as Extism WASM guests with per-file allow-listing. A plugin cannot read anything you did not authorise. |

## Install

### Arch Linux (AUR)

```bash
yay -S rosec-bin                              # daemon, CLI, PAM helper

yay -S rosec-provider-bitwarden-pm-bin        # optional providers, install only what you need
yay -S rosec-provider-bitwarden-sm-bin
yay -S rosec-provider-gnome-keyring-bin
yay -S rosec-provider-keepassxc-file-bin      # experimental

yay -S rosec-uhid-bin                         # optional privileged broker for FIDO2 passkeys
sudo systemctl enable --now rosec-uhid.socket # only needed with rosec-uhid-bin
```

### Build from source

```bash
git clone https://github.com/jmylchreest/rosec
cd rosec
just install        # builds + installs to ~/.local/bin and ~/.local/share/rosec/providers
```

(`just build-release` and `just build-wasm` are available individually.)

The optional [FIDO2 passkey](https://jmylchreest.github.io/rosec/fido2-passkeys) broker (`rosec-uhid`) is a privileged system service and is not covered by `just install`. Install it from `contrib/uhid/` following the [installation guide](https://jmylchreest.github.io/rosec/installation#fido2).

### Enable

```bash
rosec enable        # writes systemd / D-Bus activation files, masks gnome-keyring-daemon
systemctl --user start rosecd
```

Full installation guide, including PAM and display-manager setup: [docs site](https://jmylchreest.github.io/rosec/installation).

## Quick start

```bash
# Add a provider, unlock it
rosec provider add local
rosec unlock

# Use it from any libsecret-aware tool
rosec item add --provider local --label "GitHub" --attr username=alice --secret 'hunter2'
secret-tool lookup label "GitHub"             # prints: hunter2
```

### SSH agent

SSH keys from any provider (first-class SSH-key items, PEM blobs in notes, KeePassXC KeeAgent attachments) register automatically:

```bash
$ export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rosec/ssh/agent.sock"
$ ssh-add -l
256 SHA256:zBO1FdFfWhPfGfAJJMEPS2aog5C1b/06o7h0m2t1W/o rosec-kpxc-test (ED25519)
3072 SHA256:GDyUpSY2eyXYHCkUeADBhoWn/LWLvM3GI8cO8DQBI7k jmylchreest-github (RSA)

$ ssh git@github.com         # signs with the matching key, no ssh-add needed
```

Public keys and a generated SSH config are also exposed via FUSE:

```text
$XDG_RUNTIME_DIR/rosec/ssh/
├── agent.sock                    # SSH agent socket, point SSH_AUTH_SOCK here
├── keys/
│   ├── by-name/<item>.pub        # public key per vault item
│   ├── by-fingerprint/<sha256>.pub
│   └── by-host/<host>.pub        # one per ssh_host attribute
├── config.d/<provider>-<item>.conf  # ssh config snippet, `Host <pattern>` blocks pointing at agent.sock
└── allowed_signers               # one line per (principal × key) for items
                                  # tagged with `custom.ssh_signing_principal`
```

Add `Include $XDG_RUNTIME_DIR/rosec/ssh/config.d/*` near the top of `~/.ssh/config` and any item with an `ssh_host` attribute routes through rosec.

For git commit verification, tag a key with `custom.ssh_signing_principal=you@example.com` and point `git config gpg.ssh.allowedSignersFile` at the FUSE `allowed_signers` file. Locking rosec or removing the tag revokes trust. Details in the [SSH agent docs](https://jmylchreest.github.io/rosec/ssh-agent#git-signature-verification-allowed_signers).

### TOTP

```bash
$ ls "$XDG_RUNTIME_DIR/rosec/totp/by-name/"
github  gitlab  github_signing

$ cat "$XDG_RUNTIME_DIR/rosec/totp/by-name/github"
384295        # live, recomputed on every read
```

Or via the CLI: `rosec totp get github`.

## FAQ

Full set on the [docs FAQ](https://jmylchreest.github.io/rosec/faq).

**Is this a drop-in for GNOME Keyring?** For the Secret Service API, yes. rosec also ships its own SSH agent, so `rosec enable` masks gnome-keyring's SSH autostart too. The one component it does not provide is the **PKCS#11** module (certificate / crypto-token storage); keep gnome-keyring installed for that if you depend on it.

**Does the daemon sync between machines?** No. rosec is a local daemon; sync happens within individual providers (Bitwarden API, KeePassXC kdbx via Syncthing, etc.).

**How is the master password stored?** It isn't; only a wrapped key is stored. PBKDF2-SHA256 with a per-vault salt, AES-256 key wrap. Unlocking re-derives the key in memory; locking zeroes it.

**Can I write a custom provider?** Yes. Providers other than `local` are Extism WASM guests. See the [WASM Provider Guide](https://jmylchreest.github.io/rosec/developers/wasm-provider-guide).

**`gnome-keyring-daemon` keeps grabbing the bus name back.** Run `rosec enable --force` to rewrite the autostart and D-Bus mask files, then re-login. Full diagnosis on the [troubleshooting page](https://jmylchreest.github.io/rosec/troubleshooting).

**Chromium / Vivaldi / Brave says "Encrypted keystore changed".** Cross-provider duplicate; dedup served the wrong copy. Find the right value with `rosec search --no-dedup --provider <id> application=chrome`, then replant it with `rosec item import --force --provider local` (piping the TOML). Full walk-through on the [troubleshooting page](https://jmylchreest.github.io/rosec/troubleshooting).

**Can git verify signed commits against rosec?** Yes. Tag the signing key item with `custom.ssh_signing_principal=you@example.com` and set `git config gpg.ssh.allowedSignersFile "$XDG_RUNTIME_DIR/rosec/ssh/allowed_signers"`. rosec synthesises the file from every tagged key; locking the daemon revokes trust automatically.

## Status

Active development. The `local`, `bitwarden`, `bitwarden-sm`, and `gnome-keyring` providers are stable. The `keepassxc-file` provider is **experimental**; interfaces and on-disk caching may change between releases.

## Licence

[MIT](LICENSE).
