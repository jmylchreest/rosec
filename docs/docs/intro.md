---
slug: /
sidebar_position: 1
---

# Introduction

**rosec** is a Linux Secret Service daemon. It implements the [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/latest/) D-Bus API — the same one applications use to talk to GNOME Keyring or KWallet — but with a multi-provider model: a single rosec daemon can simultaneously expose secrets from a local encrypted vault, a Bitwarden account, a KeePassXC `.kdbx` file, and read-only legacy GNOME Keyring stores.

It also bundles two FUSE filesystems and an SSH agent, so secrets stored in any provider can be consumed by `ssh`, `oathtool`, scripts, and editors with no rosec-specific glue.

## Why rosec

- **One daemon, many sources.** Items are deduplicated across providers; applications calling `libsecret` see a single unified collection.
- **Stays out of the way.** Drop-in for GNOME Keyring; `rosec enable` writes the same systemd / D-Bus activation files Keyring would, masking the upstream service.
- **Useful without writing code.** SSH keys discovered in any provider auto-populate the bundled SSH agent; TOTP seeds appear as live files under `$XDG_RUNTIME_DIR/rosec/totp/`. PAM unlock means your master password is the same as your login.
- **Sandboxed plugins.** Non-built-in providers (Bitwarden, KeePassXC, gnome-keyring) run as Extism WASM guests with per-file allow-listing — the daemon hosts the network/filesystem capabilities they need; the plugin can't touch anything you didn't authorise.

## Status

Active development. Versioned releases live on [GitHub Releases](https://github.com/jmylchreest/rosec/releases). The `local`, `bitwarden`, `bitwarden-sm`, and `gnome-keyring` providers are stable. The `keepassxc-file` provider is marked **experimental** — interfaces, on-disk caching, and behaviour may change without notice between releases.

## Where to next

- **[Installation](./installation)** — distro packages, build from source, enable as the system Secret Service.
- **[Quickstart](./quickstart)** — five-minute walkthrough: install → unlock a vault → use it from `secret-tool`.
- **[Configuration](./configuration)** — full reference for `~/.config/rosec/config.toml`.
- **[Providers](./providers/capabilities)** — capability matrix and per-provider setup.
- **[FAQ](./faq)** — common questions and gotchas.
