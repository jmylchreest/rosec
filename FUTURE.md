# rosec — Future Work & Integration Notes

Design notes, planned features, and integration guidance.

---

## Replacing gnome-keyring-daemon (drop-in activation)

### Background

gnome-keyring-daemon is commonly started via one of three mechanisms:

1. **D-Bus auto-activation** — the session bus starts it on first access to
   `org.freedesktop.secrets` (via `/usr/share/dbus-1/services/org.freedesktop.secrets.service`).
2. **XDG autostart** — `gnome-keyring-secrets.desktop` in `/etc/xdg/autostart/`
   starts it at login for GNOME-family desktops.
3. **Compositor `exec-once`** — explicit launch in e.g. `hyprland.conf`:
   `exec-once = eval $(gnome-keyring-daemon --start --components=secrets,ssh,pkcs11)`

For a compositor like Hyprland that is not a GNOME session, typically only (1)
and (3) are active.  rosecd replaces both.

### How D-Bus auto-activation works

When any process calls a D-Bus method on a name that is not currently owned
(e.g. `org.freedesktop.secrets`), the bus daemon looks up
`/usr/share/dbus-1/services/<name>.service` and launches the `Exec=` binary.
The launched process must claim the bus name within a timeout or the activation
fails.

User-level service files in `~/.local/share/dbus-1/services/` take precedence
over system-level files in `/usr/share/dbus-1/services/`.  This is the
mechanism used to override or mask system entries without root access.

### Activation via systemd (recommended)

The contrib files ship everything needed:

```
contrib/
  dbus/
    org.freedesktop.secrets.service   # D-Bus activation → delegates to systemd
    org.gnome.keyring.service          # Masks gnome-keyring auto-activation
  systemd/
    rosecd.service                     # systemd user unit
  autostart/
    rosecd.desktop                     # XDG autostart fallback (non-systemd)
```

**Install steps:**

```bash
# 1. Install the binary (or adjust paths below to ~/.cargo/bin/rosecd)
sudo install -m755 target/release/rosecd /usr/local/bin/rosecd

# 2. D-Bus activation file — tells the bus to start rosecd via systemd
mkdir -p ~/.local/share/dbus-1/services
cp contrib/dbus/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/

# 3. Mask gnome-keyring so it cannot auto-activate and race with rosecd
cp contrib/dbus/org.gnome.keyring.service ~/.local/share/dbus-1/services/

# 4. systemd user unit
mkdir -p ~/.config/systemd/user
cp contrib/systemd/rosecd.service ~/.config/systemd/user/
# Edit ExecStart path if needed (default: %h/.cargo/bin/rosecd)
systemctl --user daemon-reload
systemctl --user enable rosecd   # start at login
systemctl --user start rosecd    # start now
```

With `Type=dbus` and `BusName=org.freedesktop.secrets` in the systemd unit,
systemd knows the service is ready once the bus name is claimed.  The D-Bus
activation file's `SystemdService=rosecd.service` line means the bus daemon
delegates to systemd rather than exec-ing rosecd directly — so systemd handles
restarts, logging, and sandboxing.

**Remove the compositor `exec-once` line** — systemd + D-Bus activation is
sufficient and more robust (handles restarts, correct ordering).

### Activation without systemd (XDG autostart)

For setups without systemd user sessions (e.g. openrc, runit):

```bash
mkdir -p ~/.config/autostart
cp contrib/autostart/rosecd.desktop ~/.config/autostart/

# Still mask gnome-keyring D-Bus activation
mkdir -p ~/.local/share/dbus-1/services
cp contrib/dbus/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/
cp contrib/dbus/org.gnome.keyring.service ~/.local/share/dbus-1/services/
```

The `.desktop` file has `NotShowIn=GNOME;Unity;MATE;Cinnamon;` so it only
activates on compositors that don't already manage gnome-keyring themselves
(Hyprland, Sway, river, etc.).  Remove that line if you want it unconditional.

Alternatively, add to `hyprland.conf`:
```ini
exec-once = rosecd
```
No `eval $(...)` is needed — rosecd does not print env vars to stdout (unlike
gnome-keyring-daemon, which prints `SSH_AUTH_SOCK` etc.).  libsecret-based apps
find the daemon purely by D-Bus name.

### Why gnome-keyring can win the race

Even with rosecd running, gnome-keyring can grab `org.freedesktop.secrets` if:

- It starts first (e.g. via PAM — `pam_gnome_keyring.so` in `/etc/pam.d/`)
- Its D-Bus service file is read before rosecd claims the name

Check for PAM activation:
```bash
grep -r "gnome.keyring\|gnome-keyring" /etc/pam.d/
```

If found, either remove the PAM module or ensure rosecd is started earlier
(systemd `After=` ordering or PAM replacement with `pam_exec.so`).

Check for conflicting system D-Bus service files:
```bash
ls /usr/share/dbus-1/services/ | grep -E "secrets|keyring"
# User files in ~/.local/share/dbus-1/services/ take precedence over these,
# so the masking files above are sufficient without root access.
```

### Verifying rosecd owns the name

```bash
# Confirm rosecd is the current owner
gdbus call --session \
  --dest org.freedesktop.DBus \
  --object-path /org/freedesktop/DBus \
  --method org.freedesktop.DBus.GetNameOwner \
  org.freedesktop.secrets

# Check which process owns it
rosec status
```

---

## SSH Agent (`rosec-ssh-agent`)

### Motivation

`rosecd` already owns the secrets daemon role that gnome-keyring-daemon fills.
gnome-keyring also provides an SSH agent (`SSH_AUTH_SOCK`), so dropping it
entirely requires a replacement.  Rather than delegating to a separate
`ssh-agent` process (which has no awareness of the vault), rosecd can provide a
smarter agent that draws SSH keys directly from the vault and applies
policy-based key selection.

### Security model

The SSH agent protocol (`$SSH_AUTH_SOCK`, a Unix domain socket) exposes private
key material to any process that can connect to the socket.  A naive
implementation that loads all keys from the vault on unlock would replicate the
main risk of gnome-keyring: an attacker with code execution can enumerate and
exfiltrate all SSH private keys.

Mitigations to implement:

- **Socket permissions**: the socket must be `chmod 600`, owner = session user,
  placed under `$XDG_RUNTIME_DIR/rosec/ssh-agent.sock` (mode 0700 directory).
- **Per-key confirm flag**: support the `SSH_AGENT_CONSTRAIN_CONFIRM` constraint
  — any `sign` request for a key marked `confirm` triggers a GUI prompt before
  use, matching `ssh-add -c` semantics.  This prevents silent exfiltration.
- **Per-key lifetime constraints**: support `SSH_AGENT_CONSTRAIN_LIFETIME` to
  auto-remove keys after N seconds of being loaded, matching `ssh-add -t`.
- **Key material zeroization**: private key bytes must be held in
  `Zeroizing<Vec<u8>>` and never copied into plain `Vec<u8>` or `String`.
  Keys are dropped (and zeroized) on vault lock.
- **No persistent key storage**: keys are never written to disk by the agent;
  they live only in memory while the vault is unlocked.
- **Audit log**: every `sign` request should be logged (key fingerprint,
  requesting peer PID via `SO_PEERCRED`, timestamp) at `tracing::info` level
  so users can audit what used which key.

### Smart key selection (solving "too many keys")

The standard SSH agent presents all loaded keys to the server in sequence.
OpenSSH will abort with `Too many authentication failures` (default
`MaxAuthTries = 6`) before reaching the right key if many are loaded.

#### Proposed approach: URI-based key filtering

Each SSH key item in the vault carries a `uri` attribute (the login URI field,
or a custom field named `ssh_host`).  The agent can match the target hostname
from the SSH connection against vault item attributes before deciding which keys
to offer:

1. Client sends `SSH_AGENTC_SIGN_REQUEST` with a public key.
2. Agent checks whether the key's vault item has a `uri` / `ssh_host` attribute.
3. If present, the key is only offered to hosts that match the pattern.
4. Keys with no host restriction are offered last (fallback pool).

This is analogous to `~/.ssh/config`'s `IdentityFile` per-host, but
driven automatically from vault metadata.

#### Config knobs (under `[ssh_agent]` in `config.toml`)

```toml
[ssh_agent]
# Enable the SSH agent.  Default: false.
enabled = true

# Path for the Unix domain socket.
# Default: $XDG_RUNTIME_DIR/rosec/ssh-agent.sock
# socket = "/run/user/1000/rosec/ssh-agent.sock"

# Maximum number of keys to offer per connection attempt.
# Prevents MaxAuthTries failures when many keys are stored.
# Default: 5
max_keys_per_host = 5

# If true, require a GUI confirmation prompt for every sign() call.
# Equivalent to ssh-add -c for all keys.
# Per-key override via vault item custom field: confirm = "true"
confirm_all = false

# Auto-remove keys from the agent N seconds after vault unlock.
# 0 = no lifetime limit.  Equivalent to ssh-add -t.
# Per-key override via vault item custom field: lifetime_secs = "3600"
key_lifetime_secs = 0
```

### Vault item convention for SSH keys

Bitwarden's SSH Key cipher type (`CipherType::SshKey`) maps naturally:

| Vault field        | Agent use                                      |
|--------------------|------------------------------------------------|
| Private Key        | Loaded into agent on unlock                    |
| Public Key         | Used for key fingerprint / identity matching   |
| Fingerprint        | Displayed in confirm prompts and audit log     |
| Login URI / `ssh_host` custom field | Host pattern for smart selection |
| `confirm` custom field (text, "true") | Per-key confirm constraint  |
| `lifetime_secs` custom field (text, integer) | Per-key lifetime       |

Login-type items with a URI of `ssh://hostname` and a password that is a
PEM private key should also be supported for users who store SSH keys as
login items rather than the dedicated SSH Key type.

### Implementation sketch

A new workspace crate `rosec-ssh-agent` would:

1. Implement the SSH agent protocol (parse/serialise `ssh-agent` wire format,
   defined in `draft-miller-ssh-agent`).
2. Expose a `SshAgentBackend` that holds the loaded keys (drawn from the
   `VaultBackend` trait on unlock).
3. Bind a Unix socket under `$XDG_RUNTIME_DIR/rosec/` and `accept()` in a
   `tokio` task per connection.
4. On `LIST_IDENTITIES`: return keys filtered/ordered by host-match policy.
5. On `SIGN_REQUEST`: check confirm constraint → optional prompt → sign →
   return signature.  Log the event.
6. On vault lock: drop all `Zeroizing<>` key material, close the socket.

`rosecd` would spawn the agent task when `[ssh_agent] enabled = true` and
export `SSH_AUTH_SOCK` to child processes — but since `rosecd` is launched by
the compositor (not a shell), this env var needs to reach the rest of the
session.  Options:
- Write it to `$XDG_RUNTIME_DIR/rosec/env` and source it from shell init.
- Register it via `systemd --user set-environment SSH_AUTH_SOCK=...`.
- Emit `export SSH_AUTH_SOCK=...` to stdout so `eval $(rosecd)` works
  (matching gnome-keyring-daemon's interface).

### PKCS#11 / hardware token support

PKCS#11 is the standard C API for hardware cryptographic tokens (YubiKey,
smartcard, HSM).  When an SSH private key lives on hardware, the token performs
the signing operation internally — the raw key bytes never leave the device.

gnome-keyring's `--components=pkcs11` exposes a *software* PKCS#11 token that
bridges this interface for apps that expect it.  For the SSH agent specifically,
`ssh` can load a PKCS#11 module directly (`PKCS11Provider` in `~/.ssh/config`)
to use a hardware token without any agent involvement.

For rosecd, PKCS#11 matters in two ways:

1. **Hardware-backed SSH keys via the agent**: if a user's SSH key lives on a
   YubiKey rather than in Bitwarden, the agent needs to forward sign requests to
   the token's PKCS#11 interface.  The key selection policy (which token slot
   maps to which host) could be stored as vault metadata, giving rosecd the same
   host-filtering benefit for hardware keys.

2. **Software PKCS#11 token (lower priority)**: some apps (notably older GNOME
   apps and some browsers) expect a PKCS#11 token for certificate/key storage
   rather than the Secret Service API.  This is largely obsolete for the use
   cases rosecd targets.

Hardware token support for the SSH agent is worth implementing as a follow-on.
The relevant Rust crate is [`cryptoki`](https://crates.io/crates/cryptoki)
(Apache-2.0), the idiomatic PKCS#11 binding.  The signing path would be:
`sign_request → look up host policy in vault → identify token slot → cryptoki
sign → return signature`, with the private key never touching rosecd's memory.

### Relevant crates to evaluate

- [`ssh-agent-lib`](https://crates.io/crates/ssh-agent-lib) — async SSH agent
  protocol implementation (MIT).  Evaluating whether it covers the constraint
  extensions.
- [`ssh-key`](https://crates.io/crates/ssh-key) — pure Rust SSH key parsing and
  signing (Apache-2.0/MIT).  Already used transitively via some deps; worth
  depending on directly.
- [`russh`](https://crates.io/crates/russh) — full SSH implementation; likely
  too heavy for just the agent protocol.

### Open questions

- Should `rosec-ssh-agent` be gated behind a feature flag like `bitwarden-sm`,
  given it pulls in additional crypto deps?  Likely yes.
- How to handle ECDSA / Ed25519 / RSA signing without pulling in OpenSSL?
  `ssh-key` + `p256`/`ed25519-dalek`/`rsa` should cover this with pure Rust.
- Confirm prompt UX: reuse `rosec-prompt` (iced GUI) or a simpler
  notification-style dialog?  The latter is less intrusive for frequent
  operations.
