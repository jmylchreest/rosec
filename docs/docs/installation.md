---
sidebar_position: 2
---

# Installation

## Arch Linux (AUR)

```bash
# Pre-built binary release (recommended)
yay -S rosec-bin

# Optional providers (each a separate package — install only what you need)
yay -S rosec-provider-bitwarden-pm-bin
yay -S rosec-provider-bitwarden-sm-bin
yay -S rosec-provider-gnome-keyring-bin
yay -S rosec-provider-keepassxc-file-bin    # experimental
```

Source-build alternative: `rosec` (bundles all providers, requires Rust toolchain) or `rosec-git` (latest `main`).

## Build from source

Requires Rust 1.85+ (for edition 2024) and a `wasm32-wasip1` target for the WASM provider crates.

```bash
git clone https://github.com/jmylchreest/rosec
cd rosec
rustup target add wasm32-wasip1

# Native binaries: rosec, rosecd, rosec-prompt, rosec-pam-unlock
cargo build --release --bin rosec --bin rosecd --bin rosec-prompt --bin rosec-pam-unlock

# WASM provider plugins (out-of-workspace crates)
cargo build --target wasm32-wasip1 --release --manifest-path rosec-bitwarden-pm/Cargo.toml
cargo build --target wasm32-wasip1 --release --manifest-path rosec-bitwarden-sm/Cargo.toml
cargo build --target wasm32-wasip1 --release --manifest-path rosec-gnome-keyring/Cargo.toml
cargo build --target wasm32-wasip1 --release --manifest-path rosec-keepassxc-file/Cargo.toml
```

Or use the bundled Justfile:

```bash
just build-release    # all native binaries
just build-wasm       # all WASM providers
just install          # install to ~/.local/bin and ~/.local/share/rosec/providers
```

## Enable as the Secret Service daemon

Once installed, `rosec enable` writes the systemd user units and D-Bus activation files that make rosec the implementation of `org.freedesktop.secrets` for your session. It also masks `gnome-keyring-daemon` so the two don't fight over the bus name.

```bash
rosec enable
systemctl --user start rosecd

# Confirm it's the active Secret Service
busctl --user list | grep secrets
```

If `gnome-keyring-daemon` keeps grabbing the bus name on login, rerun `rosec enable --force` and check the [Troubleshooting guide](./troubleshooting).

## Add your first provider

```bash
# Local encrypted vault — fully writable, offline-only
rosec provider add local

# Or an existing remote source
rosec provider add bitwarden       # prompts for email + master password
rosec provider add keepassxc-file path=~/Passwords.kdbx
```

Then unlock it:

```bash
rosec unlock                   # all configured providers
rosec provider auth <id>       # one specific provider
```

## FIDO2 / WebAuthn support {#fido2}

Optional. Install this only if you want rosec to serve your passkeys to
browsers as a virtual security key. See [FIDO2 passkeys](fido2-passkeys) for
what it does and how to use it.

It needs one extra system service, the **`rosec-uhid` broker**. `/dev/uhid`
(the kernel's virtual-HID facility) is root-only, so a tiny privileged broker
creates the device and hands it to your unprivileged daemon — rosecd itself
never runs as root. The broker ships with the release under `contrib/uhid/`:

```bash
# From the contrib/uhid/ directory (packages install these for you)
sudo install -Dm755 rosec-uhid        /usr/bin/rosec-uhid
sudo install -Dm644 rosec-uhid.socket /usr/lib/systemd/system/rosec-uhid.socket
sudo install -Dm644 rosec-uhid.service /usr/lib/systemd/system/rosec-uhid.service
sudo systemctl enable --now rosec-uhid.socket
```

Then enable the frontend for your session — set `fido2 = true` under
`[service]` in your [configuration](configuration) and restart the daemon:

```bash
systemctl --user restart rosecd
```

The `uhid` kernel module is loaded on demand. This is a per-user desktop
feature; do not enable it on shared multi-user servers.

## What runs where

| Component | Path | Role |
|-----------|------|------|
| `rosecd` | `/usr/bin/rosecd` | The daemon. Hosts D-Bus, SSH agent, FUSE mounts. Long-lived systemd user service. |
| `rosec` | `/usr/bin/rosec` | CLI for managing providers, items, locking. |
| `rosec-prompt` | `/usr/bin/rosec-prompt` | The default GUI prompter binary the daemon spawns when it needs a password. |
| `rosec-uhid` | `/usr/bin/rosec-uhid` | Optional privileged broker for [FIDO2 passkeys](fido2-passkeys). Socket-activated system service; creates the virtual security-key device and exits. |
| `rosec-pam-unlock` | `/usr/lib/rosec/rosec-pam-unlock` | PAM helper; unlocks providers using your login password. |
| `pam_rosec.so` | `/usr/lib/security/pam_rosec.so` | The PAM module that captures the login password and forks `rosec-pam-unlock`. |
| Provider WASM | `/usr/lib/rosec/providers/*.wasm` | Sandboxed guest plugins. Each `.wasm` carries a `.wasm.minisig` signature checked by the host on load. |

User-local installs put binaries under `~/.local/bin/` and provider WASM under `~/.local/share/rosec/providers/`.
