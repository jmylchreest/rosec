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

---

## WASM backend host (`rosec-wasm`)

### Motivation

Several password managers (1Password, Proton Pass, Dashlane, etc.) either have
official Go SDKs or are best reached by community Go libraries.  Rather than
writing a bespoke Rust HTTP+crypto client for every provider, a WASM plugin host
would let backends be written in **any language that compiles to WASM** — Go
(via TinyGo), Rust, Python, or C — and loaded at runtime as sandboxed modules.

This gives rosec a general-purpose extension mechanism:

- Third-party backends without modifying the rosec source tree.
- Backend logic written in Go (e.g. wrapping the official 1Password Go SDK or
  the Proton Pass Go library) compiled to `.wasm` and dropped into a directory.
- Tight sandboxing: the WASM module cannot access the filesystem, network, or
  process memory beyond what the host explicitly grants through capabilities.
- ABI stability: the WIT interface between host and guest is versioned and
  language-agnostic.

### Two viable embedding approaches

#### Option A — WASI Component Model + wasmtime (recommended)

The [WebAssembly Component Model](https://component-model.bytecodealliance.org/)
(WASI Preview 2 / `wasip2`) is the emerging standard for polyglot WASM plugins.
Interfaces are defined in **WIT** (WASM Interface Type), and `wit-bindgen`
generates host and guest bindings automatically.

**How it works:**

1. Define a `vault-backend` WIT world in `rosec-wasm/wit/vault-backend.wit`:

```wit
package rosec:vault-backend@0.1.0;

world vault-backend {
    /// Called once with the raw TOML options table for this backend entry.
    export init: func(options: list<tuple<string, string>>) -> result<_, string>;

    /// Return current lock state.
    export is-locked: func() -> bool;

    /// Unlock with a password or token.
    export unlock: func(credential: string) -> result<_, string>;

    /// Lock and clear in-memory secrets.
    export lock: func();

    /// Return all vault items as a flat JSON array.
    export list-items: func() -> result<string, string>;

    /// Sync from the remote source.
    export sync: func() -> result<_, string>;
}
```

2. The host (`rosec-wasm`) embeds `wasmtime` and, on startup, instantiates each
   `.wasm` file found in the configured plugin directory.  Each instantiated
   component becomes a `VaultBackend` adaptor.

3. A Go backend author writes a TinyGo program, imports `wit-bindgen`-generated
   Go bindings, implements the exported functions, and compiles:

```bash
tinygo build -target=wasip2 -o 1password.wasm ./cmd/1password-plugin/
```

The resulting `.wasm` is placed in `~/.config/rosec/plugins/` and referenced
from `config.toml`:

```toml
[[backend]]
id   = "1password"
type = "wasm"

[backend.options]
plugin = "~/.config/rosec/plugins/1password.wasm"
connect_url = "https://op-connect.internal:8080"
token       = "..."     # stored encrypted by the host
```

**Go/TinyGo status (Feb 2026):**
TinyGo v0.34+ supports the `wasip2` target and the Component Model natively
(via `wasm-tools` component wrapping).  Standard Go (`GOOS=wasip1`) targets
WASI Preview 1 (core modules, not components); `GOOS=wasip2` is tracked in
[golang/go#65333](https://github.com/golang/go/issues/65333) and not yet
shipped.  TinyGo is therefore the recommended Go compiler for guest plugins
today; it supports most of the standard library needed for HTTP clients.

**Rust crates needed (host):**

| Crate | Role | License |
|---|---|---|
| `wasmtime` | WASM/WASI runtime + Component Model embedding | Apache-2.0 |
| `wasmtime-wasi` | WASI Preview 2 host implementation | Apache-2.0 |
| `wit-bindgen` | Generate Rust host bindings from WIT | Apache-2.0/MIT |

**Security properties:**
- The WASM sandbox prevents the plugin from reading `/proc`, opening arbitrary
  file descriptors, or forking processes.
- Network access is capability-gated: the host can grant the plugin a pre-opened
  `wasi:http/outgoing-handler` (HTTP client only, no raw sockets).
- Filesystem access: the host grants only an explicit pre-opened directory (for
  token cache), nothing else.
- Secrets returned from the guest (`list-items`) are JSON strings in guest
  memory; the host copies them out and then zeroizes the host-side buffer after
  parsing, before storing in `Zeroizing<Vec<u8>>`.

#### Option B — Extism (simpler, less formal)

[Extism](https://extism.org) is a higher-level plugin framework built on
Wasmtime.  It provides a unified host SDK and per-language PDKs (Plug-in
Development Kits) with a simple `input → output` call model.

**Advantages over raw Component Model:**
- Simpler API: no WIT file, no `wit-bindgen` step.
- Go PDK (`extism/go-pdk`) compiles via TinyGo to a working `.wasm` today.
- Host SDK (`extism` Rust crate) is a single dependency with an ergonomic API.
- Good documentation and a larger community of plugin authors.

**Disadvantages:**
- Uses a custom ABI (not the standard Component Model) — interoperability with
  non-Extism hosts is zero.
- Extism's data model is byte-buffer–based; structured types must be
  JSON-serialised manually (no generated type bindings).
- Less capability-granular than WASI Preview 2 — HTTP is allowed or not, rather
  than per-origin.

**Sketch:**

```rust
// Host (rosec-wasm/src/extism_backend.rs)
use extism::{Plugin, Manifest, Wasm};

let wasm = Wasm::file("~/.config/rosec/plugins/1password.wasm");
let manifest = Manifest::new([wasm]).with_allowed_host("op-connect.internal");
let mut plugin = Plugin::new(&manifest, [], true)?;

let items_json: String = plugin.call("list_items", options_json)?;
```

```go
// Guest (Go / TinyGo, compiled with extism/go-pdk)
package main

import (
    "github.com/extism/go-pdk"
    "encoding/json"
)

//go:export list_items
func listItems() int32 {
    cfg := pdk.GetConfig("connect_url")
    // ... fetch and decrypt items from 1Password Connect ...
    out, _ := json.Marshal(items)
    pdk.OutputString(string(out))
    return 0
}
func main() {}
```

### Recommended path

Start with **Extism** (Option B) to prove the concept quickly — the Go PDK
works today with TinyGo and the Rust host SDK is mature.  Migrate to the
**Component Model** (Option A) once `GOOS=wasip2` lands in standard Go (likely
Go 1.25–1.26) and the toolchain stabilises, giving a formally typed interface
and standard WASI capability model.

### Config sketch

```toml
[[backend]]
id   = "1password-wasm"
type = "wasm"

[backend.options]
# Path to the compiled .wasm plugin.  Relative paths are resolved from
# $XDG_CONFIG_HOME/rosec/plugins/.
plugin = "1password.wasm"

# All remaining options are forwarded to the plugin's init() call as a
# flat string→string map.  The plugin is responsible for interpreting them.
connect_url = "https://op-connect.internal:8080"
# token is stored encrypted by the host using the same credential store
# as the bitwarden backend; the plugin receives the decrypted value.
token       = "eyJ..."
```

### Security considerations

- **Plugin provenance**: plugins are unsigned arbitrary code.  The host must
  warn loudly if a plugin path is world-writable.  A future `plugin_sha256`
  config field could pin expected content hashes.
- **Secret exposure**: the host decrypts stored credentials before passing them
  to the plugin's `init()` call.  The decrypted bytes live in the host's
  address space only long enough to copy into WASM linear memory, then are
  zeroized.  The plugin itself never has access to the host's key material.
- **No `wasi:filesystem` for plugins**: plugins receive only a virtual temp
  directory and the specific HTTP hosts they declare.  They cannot read
  `~/.config/rosec/` or the host's secret store.
- **Output sanitisation**: JSON returned by the plugin is parsed by the host
  before being stored in the vault cache.  Malformed output returns an error;
  it does not crash the daemon.

### Relevant crates

| Crate | Purpose | License |
|---|---|---|
| `wasmtime` | WASI Component Model runtime | Apache-2.0 |
| `wasmtime-wasi` | WASI host implementation | Apache-2.0 |
| `extism` | Higher-level plugin host (Option B) | BSD-3 |
| `wit-bindgen` | WIT → Rust binding codegen (Option A) | Apache-2.0/MIT |

---

## 1Password backend (`rosec-1password`)

### Motivation

[1Password](https://1password.com) is one of the most widely used password
managers, particularly in team and enterprise contexts.  Adding a rosec backend
for it would let users access 1Password secrets through the standard Secret
Service API alongside Bitwarden or other backends.

Two integration paths exist, with very different trade-offs:

### Option A — 1Password Connect (recommended first target)

1Password Connect is a self-hosted REST server that exposes vault contents over
a simple, fully-documented HTTP API authenticated with a static bearer token.

**Requirements:**
- A 1Password Teams or Business plan (Connect is not available on Personal).
- A Connect server deployed on your own infrastructure (Docker image provided
  by 1Password).
- A Connect server access token scoped to the vaults you want to expose.

**Authentication:**
All requests carry an `Authorization: Bearer <token>` header.  There is no
session negotiation, no SRP, no KDF — the token is static and issued from the
1Password web portal.  The token is stored encrypted at rest (same pattern as
`rosec-bitwarden`'s OAuth credential store).

**Key API endpoints:**

| Endpoint | Purpose |
|---|---|
| `GET /v1/vaults` | List accessible vaults |
| `GET /v1/vaults/{vaultId}/items` | List items in a vault |
| `GET /v1/vaults/{vaultId}/items/{itemId}` | Fetch a single item (with fields) |
| `GET /v1/vaults/{vaultId}/items?filter=title eq "..."` | Server-side search |

The response schema is a well-documented JSON format.  Items have typed fields
(username, password, TOTP, URL, custom, etc.) that map cleanly onto the rosec
attribute model.

**Why this path is attractive:**
- The API is stable, publicly documented, and versioned.
- No proprietary binary is required.
- Pure HTTP — reqwest already a workspace dep, no new crypto.
- A Rust crate exists: [`connect-1password`](https://crates.io/crates/connect-1password)
  (Apache-2.0/MIT), though the implementation is simple enough to do directly
  from the published OpenAPI spec.
- `can_auto_unlock()` returns `true` — the bearer token IS the credential; no
  master-password prompt is needed.

**Limitations:**
- Requires a 1Password Business/Teams plan and self-hosted Connect server.
- Not usable for personal 1Password accounts on the cloud.
- Items are transmitted decrypted by the Connect server — the security boundary
  is the Connect server itself, not end-to-end encryption.

### Option B — Service Accounts / SDK (personal cloud accounts)

1Password Service Accounts are JWT-based machine credentials that authenticate
directly against the 1Password cloud.  The official 1Password SDKs (Go, JS,
Python) are thin wrappers around a proprietary core library (`libop_uniffi_core`)
that handles the end-to-end encrypted vault protocol client-side.

A community crate [`corteq-onepassword`](https://crates.io/crates/corteq-onepassword)
provides FFI bindings to this core library for Rust.  However:

- The underlying `libop_uniffi_core` is **proprietary** (1Password's own
  license, similar situation to Bitwarden's SM SDK).
- It ships as a pre-built binary (`libop_uniffi_core.so`) that must be linked
  at runtime — not a pure Rust solution.
- The license terms for redistribution and use in open-source projects are
  unclear.

For these reasons, Option B would follow the same pattern as `rosec-bitwarden-sm`:
a separate workspace crate (`rosec-1password-sa`) gated behind a feature flag,
with its own license declaration, letting packagers exclude it cleanly.

### Implementation plan (Option A first)

1. New workspace crate `rosec-1password` (MIT, no feature gate needed — pure HTTP).
2. `OnePasswordConfig` with `id`, `connect_url`, `token` (stored encrypted).
3. `OnePasswordBackend` implementing `VaultBackend`:
   - `can_auto_unlock() = true` (token-based, no interactive prompt).
   - `unlock()` validates the token against `GET /v1/vaults` and caches the
     vault list.
   - `sync()` re-fetches vault item lists.
   - `get_secret()` fetches the item and returns the primary secret field
     (password, or first secret-type field).
4. Field → attribute mapping:
   - `type` = item category (login, password, creditCard, identity, etc.)
   - `username`, `password`, `totp`, `uri` — standard Login fields
   - `custom.<field_label>` — custom fields (concealed → sensitive, text → public)
   - `notes` — always sensitive

### Relevant crates

- [`connect-1password`](https://crates.io/crates/connect-1password) — Rust
  Connect SDK (Apache-2.0/MIT); evaluating for reuse vs direct reqwest calls.
- [`corteq-onepassword`](https://crates.io/crates/corteq-onepassword) — FFI
  wrapper for the official SDK core (Option B only; proprietary core dep).
- [`reqwest`](https://crates.io/crates/reqwest) — already a workspace dep.

### Open questions

- Should `rosec-1password` support both Connect and Service Accounts in a single
  crate (distinguished by `type = "1password-connect"` vs `"1password-sa"`)?
  Probably yes for user clarity, but Option B needs a separate crate for the
  license isolation.
- Does 1Password Connect support a change-notification mechanism (webhooks or
  SSE) similar to Bitwarden's SignalR hub?  If so, a `notifications.rs` task
  could provide real-time sync.  Otherwise polling is sufficient given the
  Connect use case (infrastructure automation rather than interactive desktop
  use).

---

## Proton Pass backend (`rosec-proton-pass`)

### Motivation

[Proton Pass](https://proton.me/pass) is a privacy-focused password manager
from the team behind ProtonMail.  It stores vaults end-to-end encrypted on
Proton's servers and offers apps for all major platforms.  Adding it as a
rosec backend would let users who choose Proton's ecosystem access their
secrets through the standard Secret Service API — the same way the Bitwarden
backend works today.

### Authentication model

Proton Pass uses Proton's SRP-based authentication (Secure Remote Password
with an extra client-proof step).  The client derives a session key from the
user's password using PBKDF2 (or Argon2id on newer accounts), then exchanges
proofs with the identity server to obtain an access token.  Two-factor
authentication (TOTP or hardware key) is supported at this step.

The session token is short-lived.  The client must refresh it using a refresh
token, or re-authenticate when the session expires.  The device must be
registered (similar to Bitwarden's device verification flow) before it can
receive an access token.

### Vault encryption

Vault data is doubly encrypted:

1. **Address key**: derived from the primary key material, used to decrypt the
   vault "share" keys.
2. **Item keys**: per-item symmetric keys encrypted with the share key.  All
   cipher text uses PGP (OpenPGP message format) with the item key.

This means the Rust implementation needs:
- SRP proof computation (PBKDF2 / Argon2 + modular exponentiation)
- OpenPGP decryption for item content (the
  [`pgp`](https://crates.io/crates/pgp) crate, MIT)
- AES-GCM / AES-CBC for the inner share-key layer

The `rosec-proton-pass` crate would mirror the structure of `rosec-bitwarden`:
separate modules for the HTTP client, crypto, vault state, and
`VaultBackend` implementation.

### API surface

Proton Pass does not publish an official API specification, but the protocol
is partially documented by reverse engineering and community projects (notably
[pass-rust-core](https://github.com/ProtonMail/pass-rust-core) and the
[gopass-bridge](https://github.com/nicholasgasior/gopass-bridge) project).
The key endpoints are:

| Endpoint | Purpose |
|---|---|
| `POST /auth/v4/info` | SRP server challenge |
| `POST /auth/v4` | SRP proof exchange → access + refresh tokens |
| `GET /pass/v1/share` | List vault shares |
| `GET /pass/v1/share/{shareId}/item` | List encrypted items in a share |
| `GET /core/v4/keys` | Fetch user key material |

### Implementation considerations

- **License**: The `rosec-proton-pass` crate would be MIT-licensed (matching
  the rest of rosec).  The SRP and OpenPGP implementations it uses are all
  OSI-approved.  No proprietary SDK is required.
- **Feature flag**: gate behind `proton-pass` feature, same pattern as
  `bitwarden-sm`, so users who do not use Proton Pass incur no extra
  dependencies.
- **Credentials storage**: the session access/refresh token pair should be
  stored encrypted at rest using the same `oauth_cred` pattern used by the
  Bitwarden backend (derive a storage key from the master password, then
  HMAC-authenticated AES-CBC).
- **SRP crate**: [`srp`](https://crates.io/crates/srp) (MIT/Apache-2) handles
  the SRP proof computation; Proton uses a custom group (2048-bit MODP).
- **Two-factor**: TOTP tokens can be submitted as an additional field in the
  auth flow, using the same `TwoFactorSubmission` pattern as Bitwarden.
- **Read-only**: rosec is read-only; write operations (creating/updating items)
  are out of scope.

### Relevant crates

- [`pgp`](https://crates.io/crates/pgp) — pure Rust OpenPGP (MIT)
- [`srp`](https://crates.io/crates/srp) — SRP-6a implementation (MIT/Apache-2)
- [`aes-gcm`](https://crates.io/crates/aes-gcm) — AES-GCM (MIT/Apache-2)
- [`reqwest`](https://crates.io/crates/reqwest) — already a workspace dep

### Open questions

- Proton's API is not versioned in a stable, public way — the implementation
  would need to track API changes.  Community projects like
  [pass-rust-core](https://github.com/ProtonMail/pass-rust-core) are the
  primary reference.
- Does Proton Pass have a device-registration step analogous to Bitwarden's
  personal API key flow?  If so, the `RegistrationInfo` trait method covers it.
- Real-time sync: Proton Pass uses Server-Sent Events (SSE) rather than
  SignalR.  A similar `notifications.rs` task could listen on the SSE stream
  and call `try_sync_backend` on events.

---

## Real-time vault sync (SignalR / WebSocket)

### Background

rosec currently polls on a fixed `refresh_interval_secs` timer (default 60 s).
Bitwarden non-mobile clients use a persistent SignalR WebSocket connection to
`/notifications/hub` on the server.  The server pushes a lightweight
"something changed" notification; the client responds by calling `/api/sync` to
fetch the actual data.  This provides near-instant propagation of vault changes
without constant polling.

The flow:

1. Client establishes a WebSocket to `wss://<server>/notifications/hub`.
2. Server sends a SignalR handshake, then `SyncCipherUpdated` / `SyncVault` /
   `LogOut` messages as events occur.
3. On any sync notification the client calls `GET /api/sync` to refresh.
4. The WebSocket is kept alive with SignalR ping frames; the client reconnects
   on disconnect.

Vaultwarden supports the same protocol; the official Bitwarden cloud uses it
exclusively for non-mobile clients.

### Why it matters for rosec

With a 60 s poll interval, a password changed in the Bitwarden web vault takes
up to a minute to appear in rosec.  Applications that cache the secret (e.g.
`pass`, shell scripts) may use a stale value even longer.  Real-time sync
closes this window immediately.

### Implementation notes

- No mature Rust SignalR client crate exists.  The protocol is simple enough to
  implement directly: HTTP upgrade to WebSocket, send the SignalR handshake JSON
  (`{"protocol":"json","version":1}`), then read newline-delimited JSON frames.
  The [`tokio-tungstenite`](https://crates.io/crates/tokio-tungstenite) crate
  handles the WebSocket layer.
- Access token refresh must be wired into the WebSocket reconnect path: if the
  session token expires the server closes the connection, and the client must
  re-authenticate before reconnecting.
- The existing `refresh_interval_secs` timer becomes a fallback for servers
  that do not support SignalR (uncommon self-hosted deployments).
- On a `LogOut` notification the daemon should lock the vault immediately,
  matching the behaviour of the official client.

### Config sketch

No new top-level section is needed.  The feature is per-backend:

```toml
[[backend]]
id   = "bitwarden"
type = "bitwarden"

[backend.options]
email           = "user@example.com"
realtime_sync   = true   # default: true when server supports it
```

Disabling is useful if the WebSocket connection causes issues (e.g. aggressive
corporate proxies that terminate long-lived connections).

### Relevant crates

- [`tokio-tungstenite`](https://crates.io/crates/tokio-tungstenite) — async
  WebSocket client (MIT).  Already in the broader Rust ecosystem; lightweight.
- No SignalR crate is needed — the subset used by Bitwarden is simple enough to
  parse directly from newline-delimited JSON frames.

---

## Headless / container mode (private D-Bus socket)

### Background

`rosecd` currently requires a D-Bus session bus (`DBUS_SESSION_BUS_ADDRESS`).
In containers, SSH sessions, and CI environments there is often no session bus,
making the daemon unusable in those contexts.

gnome-keyring-daemon solves a related problem via
`/run/user/<uid>/keyring/control` — a Unix domain socket it listens on directly,
advertised to clients via `GNOME_KEYRING_CONTROL`.  This lets gnome-keyring work
without a session bus, but at the cost of a bespoke, non-standard protocol that
no other Secret Service implementation supports.

### Proposed approach

Rather than a gnome-keyring-style private protocol socket, rosecd should expose
the **same `org.freedesktop.secrets` D-Bus interface** over a private Unix socket
bus.  Clients connect by setting `DBUS_SESSION_BUS_ADDRESS=unix:path=<socket>`,
which is the standard mechanism — no client changes required.

```
rosecd --socket /run/user/1000/rosec/bus
export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/rosec/bus
rosec search name=github
```

### Implementation notes

- zbus supports this via `ConnectionBuilder::unix_listener(listener)` —
  `rosecd` would call `tokio::net::UnixListener::bind(path)` and pass it to
  `ConnectionBuilder` instead of `Connection::session()`.
- The socket path defaults to `$XDG_RUNTIME_DIR/rosec/bus`; configurable via
  `--socket` flag or `ROSEC_SOCKET` env var.
- When `--socket` is given, rosecd skips claiming `org.freedesktop.secrets` on
  the session bus (there may not be one) and instead acts as the bus itself.
- `rosec` CLI would auto-detect the socket via `ROSEC_SOCKET` /
  `XDG_RUNTIME_DIR/rosec/bus` before falling back to the session bus, so
  `eval $(rosecd --socket ...)` shell integration works naturally.
- This is the correct path for containers: no new IPC surface, same protocol,
  existing Secret Service clients work unmodified.

### Why not the gnome-keyring control socket approach

- `GNOME_KEYRING_CONTROL` is a gnome-keyring private protocol — not the Secret
  Service spec.  No other implementation supports it.
- Exposing a raw socket with a bespoke framing would require maintaining a
  second protocol implementation in perpetuity.
- A private D-Bus socket is strictly superior: same protocol, zero extra code
  beyond `ConnectionBuilder::unix_listener`, and fully interoperable with any
  conforming Secret Service client.
