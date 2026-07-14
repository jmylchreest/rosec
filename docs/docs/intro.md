---
slug: /
sidebar_position: 1
---

# Introduction

**rosec** integrates multiple secret backends into one secure desktop experience on Linux. A single systemd user service exposes secrets from a local encrypted vault, a Bitwarden account, a KeePassXC `.kdbx` file, and read-only legacy GNOME Keyring stores.

It serves them through the interfaces your system already uses: the [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/latest/) D-Bus API (the same one applications use to talk to GNOME Keyring or KWallet), an SSH agent, live TOTP files via FUSE, FIDO2/WebAuthn passkeys, and PAM unlock at login. `ssh`, `oathtool`, browsers, scripts, and editors consume them with no rosec-specific glue.

## Why rosec

- **One daemon, many sources.** Items are deduplicated across providers; applications calling `libsecret` see a single unified collection.
- **Stays out of the way.** Drop-in for GNOME Keyring; `rosec enable` writes the same systemd / D-Bus activation files Keyring would, masking the upstream service.
- **Useful without writing code.** SSH keys discovered in any provider auto-populate the bundled SSH agent; TOTP seeds appear as live files under `$XDG_RUNTIME_DIR/rosec/totp/`. PAM unlock means your master password is the same as your login.
- **Sandboxed plugins.** Non-built-in providers (Bitwarden, KeePassXC, gnome-keyring) run as Extism WASM guests with per-file allow-listing. The daemon hosts the network/filesystem capabilities they need; the plugin can't touch anything you didn't authorise.
- **Sandboxed apps too.** rosec implements the XDG Secret portal, so Flatpak apps retrieve their secrets from your providers. See [Flatpak app secrets](./portal).

## Status

Active development. Versioned releases live on [GitHub Releases](https://github.com/jmylchreest/rosec/releases). The `local`, `bitwarden`, `bitwarden-sm`, and `gnome-keyring` providers are stable. The `keepassxc-file` provider is marked **experimental**; interfaces, on-disk caching, and behaviour may change without notice between releases.

## Where to next

- **[Installation](./installation)**: distro packages, build from source, enable as the system Secret Service.
- **[Quickstart](./quickstart)**: five-minute walkthrough from install to `secret-tool`.
- **[Configuration](./configuration)**: full reference for `~/.config/rosec/config.toml`.
- **[Providers](./providers/capabilities)**: capability matrix and per-provider setup.
- **[FAQ](./faq)**: common questions and gotchas.
