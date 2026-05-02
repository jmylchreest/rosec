---
sidebar_position: 3
---

# Quickstart

A five-minute end-to-end walkthrough — install, unlock a local vault, use it from a standard libsecret tool. Assumes you've completed [installation](./installation) and `rosec enable`.

## 1. Create a local vault

```bash
rosec provider add local
# ... prompts for a master password (twice), creates the file at
# ~/.local/share/rosec/providers/local.vault
```

## 2. Unlock it

```bash
rosec unlock
# Master Password [Enter your master password]: ******
#   local: unlocked
```

## 3. Add an item

```bash
rosec item add \
    --provider local \
    --label "Personal email" \
    --attr username=alice \
    --attr uri=mail.example.com \
    --secret "hunter2"
```

## 4. Read it back

The whole point — your data is now reachable from any libsecret-aware program:

```bash
# Search by attribute, get the secret
secret-tool lookup uri mail.example.com
# hunter2

# Or via the rosec CLI
rosec search uri=mail.example.com
rosec inspect <id>
```

## 5. Pull SSH keys into your agent

If you stored an OpenSSH private key (in any provider — `local`, `bitwarden`, `keepassxc-file`), it's already in the rosec SSH agent:

```bash
SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rosec/ssh/agent.sock" ssh-add -l
```

Make rosec your default agent for the session by exporting `SSH_AUTH_SOCK`, or per the [SSH agent integration guide](./ssh-agent).

## 6. Pull TOTP codes

Items with a `totp` secret automatically appear under a FUSE mount:

```bash
ls "$XDG_RUNTIME_DIR/rosec/totp/by-name/"
cat "$XDG_RUNTIME_DIR/rosec/totp/by-name/personal_email"
# 384295
```

The file content is the live TOTP code — re-read it whenever you need a fresh code.

## What's next

- **[CLI reference](./cli)** — every `rosec` command.
- **[Configuration](./configuration)** — `config.toml` for the daemon, autolock policies, prompt theming.
- **[Providers](./providers/capabilities)** — connect to Bitwarden, KeePassXC, or migrate from GNOME Keyring.
- **[PAM unlock](./pam)** — auto-unlock on login.
