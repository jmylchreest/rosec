# rosec — Future Work & Integration Notes

Design notes, planned features, and integration guidance.

---

## XDG Desktop Portal Secret backend (`org.freedesktop.impl.portal.Secret`)

### Background

The [XDG Desktop Portal](https://flatpak.github.io/xdg-desktop-portal/) is a
D-Bus framework that lets sandboxed apps (Flatpak, Snap) access host services
through portal interfaces.  The `org.freedesktop.portal.Secret` portal
(frontend) delegates to an implementation backend
(`org.freedesktop.impl.portal.Secret`) to retrieve a per-application master
secret that apps use to derive their own encryption keys.

The portal interface has exactly one method:

```xml
org.freedesktop.impl.portal.Secret.RetrieveSecret(
    IN  handle      ObjectPath,
    IN  app_id      String,
    IN  fd          UnixFD,
    IN  options     Dict<String, Variant>,
    OUT response    UInt32,
    OUT results     Dict<String, Variant>
)
```

The implementation writes a stable, per-`app_id` secret to the passed file
descriptor.  The app never learns the master vault password — it only receives
a derived key unique to its `app_id`.

### Why rosec should implement this

- **Flatpak apps** (e.g. GNOME Secrets, Firefox Flatpak) use this portal to
  bootstrap their encrypted storage.  Without a portal backend, these apps
  either fall back to plaintext or fail to initialize their secret stores.
- gnome-keyring-daemon provides this via `oo7-portal` (a separate binary).
  Dropping gnome-keyring without replacing the portal backend breaks Flatpak
  apps that depend on it.
- The implementation is trivial: derive a stable per-app secret (e.g.
  `HKDF(vault_key, app_id)`) and write it to the file descriptor.  oo7's
  implementation is ~100 lines.
- `cargo:libsecret` (Cargo's built-in credential helper) already talks to
  `org.freedesktop.secrets` directly, so the portal is NOT needed for Cargo.
  This is specifically for sandboxed Flatpak/Snap apps.

### Implementation sketch

1. A new D-Bus interface `org.freedesktop.impl.portal.Secret` registered on
   the session bus (same `rosecd` process, or a small companion binary
   activated via D-Bus).
2. On `RetrieveSecret`: check that the vault is unlocked, derive
   `HKDF-SHA256(vault_key, info=app_id)` → 64-byte secret, write to `fd`.
3. Ship a `.portal` file so `xdg-desktop-portal` discovers rosec as the
   Secret portal backend:
   ```ini
   [portal]
   DBusName=org.freedesktop.secrets
   Interfaces=org.freedesktop.impl.portal.Secret
   ```

### Effort estimate

Low — single method, no complex state.  The HKDF derivation and fd write are
straightforward.  Main work is D-Bus activation plumbing and integration
testing with a Flatpak app.

### Status

- **Not started** — requested in [#6](https://github.com/jmylchreest/rosec/issues/6)
  (Flatpak Evolution cannot authenticate).

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
secret-tool search name github   # standard clients work unmodified
```

### Why not raw zbus peer-to-peer

The original plan assumed `ConnectionBuilder::unix_listener(listener)` exists in
zbus — it does not.  The actual API is `Builder::unix_stream(stream)`, which
takes a single already-connected stream.  In p2p mode each `accept()`ed client
gets its own `Connection` with its own `ObjectServer`; there is no shared bus.

Standard Secret Service clients (`secret-tool`, `libsecret`, `seahorse`) call
bus-level operations on connect: `Hello()`, `RequestName()`,
`GetNameOwner("org.freedesktop.secrets")`.  These operations only exist in a bus
broker — p2p connections have no name registry, no signal routing, and no match
rules.

Additionally, `ServiceState` stores a single `self.conn` and uses it to
dynamically register/deregister `SecretItem` D-Bus objects
(`rosec-secret-service/src/state.rs`).  This design requires a single bus
connection, not per-client p2p connections.

### Chosen approach: embedded busd

[`busd`](https://crates.io/crates/busd) (MIT license) is a D-Bus bus broker
written by the zbus author (zeenix).  It exposes a library API:

```rust
let bus = busd::bus::Bus::for_address(Some("unix:path=/run/user/1000/rosec/bus"))?;
bus.run().await?;  // accept loop — handles multi-client multiplexing
```

busd provides everything a real bus broker needs: multi-client multiplexing,
name registry (`Hello()`, `RequestName()`), signal routing/broadcasting, and
match rules.  It has 583 commits and is actively maintained.  6 of its 7 unique
dependencies are already in our `Cargo.lock` as transitive deps of zbus — only
`xdg-home` would be new.

**Architecture when `--socket` is given:**

```
┌───────────────────────────────────┐
│           rosecd process          │
│                                   │
│  ┌─────────────────────────────┐  │
│  │  busd::bus::Bus (tokio task)│  │
│  │  listening on /run/.../bus  │  │
│  └────────────┬────────────────┘  │
│               │ unix socket       │
│  ┌────────────▼────────────────┐  │
│  │  Connection::session()      │  │
│  │  (DBUS_SESSION_BUS_ADDRESS  │  │
│  │   = unix:path=.../bus)      │  │
│  └────────────┬────────────────┘  │
│               │                   │
│  ┌────────────▼────────────────┐  │
│  │  register_objects_with_     │  │
│  │  full_config() — unchanged  │  │
│  └─────────────────────────────┘  │
└───────────────────────────────────┘
         ▲            ▲
         │            │
    secret-tool    libsecret app
    (unmodified)   (unmodified)
```

**Zero changes to existing service code.** The daemon spawns busd in-process on
the private socket, sets `DBUS_SESSION_BUS_ADDRESS` to point to it, then
connects via `Connection::session()` as normal.  The same
`register_objects_with_full_config()`, same `ObjectServer`, same dynamic item
registration all work unchanged.

### Implementation details

- **Cargo feature:** `private-socket` in the `rosecd` crate, adding `busd` as
  an optional dependency.  Disabled by default — no impact on the normal
  session bus path.
- **Socket path:** defaults to `$XDG_RUNTIME_DIR/rosec/bus`; configurable via
  `--socket <path>` flag or `ROSEC_SOCKET` env var.
- **CLI auto-detection:** `rosec` CLI checks `ROSEC_SOCKET` env var, then
  `$XDG_RUNTIME_DIR/rosec/bus` (if the file exists), before falling back to
  the session bus.  This makes `eval $(rosecd --socket ...)` shell integration
  work naturally.
- **Logind watcher:** skipped in private socket mode — no system bus is
  available.  Lock-on-sleep would rely on idle timeouts instead.
- **Permissions:** the socket file is created with mode `0o600` and placed under
  the user's `XDG_RUNTIME_DIR` (which is itself `0o700`).

### Implementation phases

1. Add `--socket` flag to `rosecd` and embedded busd startup behind
   `private-socket` feature.
2. CLI auto-detection of `ROSEC_SOCKET` / `XDG_RUNTIME_DIR/rosec/bus`.
3. Config file `socket_path` option in `[daemon]` section.
4. Systemd integration documentation (`rosecd.socket` activation example).

### Why not the gnome-keyring control socket approach

- `GNOME_KEYRING_CONTROL` is a gnome-keyring private protocol — not the Secret
  Service spec.  No other implementation supports it.
- Exposing a raw socket with a bespoke framing would require maintaining a
  second protocol implementation in perpetuity.
- A private D-Bus socket via embedded busd is strictly superior: same protocol,
  zero changes to service code, and fully interoperable with any conforming
  Secret Service client.

---

## WebAuthn / FIDO2 / Passkey Two-Factor Authentication

### Background

rosec supports text-prompt 2FA methods (TOTP, email, YubiKey OTP, Duo
passcode) via the generic `TwoFactorMethod` protocol.  Each text-prompt
method works identically from the host's perspective: prompt a string on the
TTY, send it to the guest.

WebAuthn / FIDO2 (Bitwarden provider code 4) is fundamentally different.  It
requires a **host-mediated ceremony** where:

1. The guest returns a JSON challenge (from `TwoFactorProviders2`) containing
   `rpId`, `challenge`, `allowCredentials`, `userVerification`, etc.
2. The **host** communicates with a hardware authenticator (USB HID / NFC /
   BLE) to perform a `navigator.credentials.get()` equivalent.
3. The host sends the signed assertion response back to the guest.
4. The guest includes the assertion in the Bitwarden login request.

This cannot happen inside the WASM sandbox — the guest has no hardware access.

### Protocol support (already in place)

The `TwoFactorMethod` protocol type includes:

- `prompt_kind: "fido2"` — signals to the host that this is a host-mediated
  method, not a text prompt.
- `challenge: Option<String>` — carries the JSON challenge data from the
  server (currently `None` because the PM guest doesn't yet extract
  `TwoFactorProviders2` challenge data for WebAuthn).

The host (`unlock.rs`) currently filters to `prompt_kind == "text"` methods
only.  If only `fido2` methods are available, it returns an error:
"provider requires 2FA but no supported methods available".

### Implementation plan

#### Phase 1: Guest extracts WebAuthn challenge

- Deserialize `TwoFactorProviders2` in `rosec-bitwarden-pm/src/api.rs`
  (currently only `TwoFactorProviders` — the flat `Vec<u8>` — is parsed).
- For provider code 4, extract the `Challenges` array and serialize it as
  JSON into `TwoFactorMethod { challenge: Some(json_str), .. }`.
- The guest must also accept the assertion response back via `auth_fields`
  and format it into the `twoFactorToken` form parameter expected by the
  Bitwarden identity endpoint.

#### Phase 2: Host FIDO2 client

- Add a new crate `rosec-fido2` (or a module in `rosec-secret-service`)
  that wraps `libfido2` or the `ctap-hid-fido2` Rust crate.
- The host detects `prompt_kind == "fido2"`, parses the challenge JSON,
  performs the authenticator assertion, and puts the response into
  `auth_fields` (e.g. `__2fa_fido2_response`).
- Requires access to `/dev/hidraw*` — user must be in the `fido` group
  or have appropriate udev rules.

#### Phase 3: Passkey / discoverable credentials

- Some Bitwarden accounts may use passkeys (resident/discoverable
  credentials) for passwordless login.  This is a separate Bitwarden API
  flow (`grant_type: "webauthn"` rather than `"password"`).
- This would require a new `UnlockInput` variant or a separate
  `Provider::unlock_passkey()` method.
- Deferred until WebAuthn 2FA works, since the FIDO2 infrastructure is a
  prerequisite.
- Note: this is *consuming* a passkey to unlock a Bitwarden vault,
  distinct from *serving* passkeys to other apps via WebAuthn.  The
  latter is covered separately in
  [credentialsd integration](#credentialsd-integration--rosec-as-a-passkey-provider).

#### Platform considerations

| Platform | FIDO2 access | Notes |
|----------|-------------|-------|
| Linux | `libfido2` / `ctap-hid-fido2` via `/dev/hidraw*` | Needs udev rules or `fido` group |
| macOS | `libfido2` or Security.framework | Different transport |
| Windows | Windows Hello / WebAuthn API | Completely different surface |

For the initial implementation, Linux-only via `libfido2` is sufficient.

### Duo push / browser redirect

Full Duo push (provider 2/6) faces a similar problem: the Duo handshake
requires a browser redirect and callback.  The approach would be:

1. Guest extracts `Host`, `Signature`, `AuthUrl` from `TwoFactorProviders2`.
2. Host opens the URL via `xdg-open` (or equivalent).
3. Host polls or listens for the Duo callback to complete.
4. Host extracts the Duo auth token and sends it back to the guest.

This shares infrastructure with the "browser_redirect" `prompt_kind`.
Currently, only Duo passcode (plain text) is supported.

### Status

- Protocol types: **done** (`TwoFactorMethod.prompt_kind`, `.challenge`)
- Guest challenge extraction: **not started**
- Host FIDO2 client: **not started**
- Duo browser redirect: **not started**

---

## credentialsd integration — rosec as a passkey provider

### Background

[credentialsd](https://github.com/linux-credentials/credentialsd) is an
emerging Linux Credential Manager API that defines a D-Bus surface for
WebAuthn ceremonies on the desktop.  It is the missing equivalent of
macOS's Authentication Services / Windows Hello — a system-level entry
point that browsers and native apps can call to perform
`navigator.credentials.create()` and `navigator.credentials.get()`,
delegating actual credential handling to a separate daemon and UI.

The project explicitly intends to be standardised as an XDG portal:

> "I intend to convert the API into a portal spec, making it fit normal
> D-Bus/portal patterns." (GOALS.md)

And it explicitly carves out space for password/passkey managers to
plug in:

> "Provide a uniform interface for third-party credential providers
> (password/passkey managers like GNOME Secrets, Bitwarden, Keepass,
> LastPass, etc.) to hook into." (GOALS.md)

That hook is where rosec belongs.

### D-Bus surface (current shape)

`xyz.iinuwa.credentialsd.Credentials1` exposes three methods:

| Method | Signature | WebAuthn equivalent |
|---|---|---|
| `CreateCredential` | `((s, a{sv})) → a{sv}` | `navigator.credentials.create()` |
| `GetCredential` | `((s, a{sv})) → a{sv}` | `navigator.credentials.get()` |
| `GetClientCapabilities` | `() → a{sv}` | capability discovery |

The `(s, a{sv})` request shape carries `(origin, options)` where
`options` is the WebAuthn options dict serialised to D-Bus variants.
This is a thin transport for the existing W3C spec — not a new
protocol.

### Architecture

credentialsd splits the work across three processes:

- **credentialsd daemon** (Gateway + Flow Controller) — receives the
  request, drives the ceremony, calls authenticator backends.
- **credentialsd-ui** — separate UI process subscribed to flow events.
  GTK4 reference; replaceable per desktop environment.
- **Browser web extension** — overrides `navigator.credentials.*` and
  forwards to D-Bus.

Authenticator I/O is delegated to
[`libwebauthn`](https://github.com/linux-credentials/libwebauthn)
(USB + hybrid/QR transports today).  Resident-credential storage is
not yet specified — that is the gap rosec would fill.

### Why rosec should integrate

- **Right-shaped interface**: passkey private keys belong in a vault,
  not in `org.freedesktop.secrets.GetSecret()`.  WebAuthn is a signing
  ceremony, not an extractable secret.  credentialsd's interface is
  challenge-in / assertion-out, which matches what the vault should
  expose.
- **Reuses rosec's existing storage**: a local rosec vault already has
  PBKDF2 + AES-256-CBC + HMAC-SHA256 wrapping, autolock, multi-password
  unlock, and atomic on-disk persistence.  These are exactly the
  primitives a passkey store needs.
- **Multi-provider fan-out**: rosec already routes lookups across
  several backends (Bitwarden, local vault, others).  When credentialsd
  asks "do you have a credential for `rpId=example.com`?", rosec can
  answer across every backend that holds passkeys, not just one.
- **No browser-extension churn**: the browser side talks to
  credentialsd; rosec only needs to implement the
  third-party-provider hook on the daemon side.

### Implementation sketch

#### Phase 1: Track upstream

The third-party-provider interface is not stable yet.  No protocol
implementation work makes sense until credentialsd publishes a draft
provider API.  Until then:

- Watch the credentialsd repo for a `provider.rs` / `xml`
  introspection file in the `doc/` tree.
- Engage on the spec discussion (open issue / RFC threads) so rosec's
  storage shape (multi-vault, lazy unlock, autolock, key-wrapping)
  gets considered when the provider API is designed.

#### Phase 2: Passkey storage in rosec-vault

Add a new item type `passkey` to `LocalVault`:

```rust
// rosec-core/src/lib.rs (ItemType variant)
ItemType::Passkey

// rosec-vault stores per-passkey:
//   - rpId (plaintext attribute)
//   - userId, userHandle (plaintext attributes)
//   - credentialId (plaintext attribute, used as lookup key)
//   - publicKey (plaintext, served back during create)
//   - privateKey (encrypted via vault master key, never returned)
//   - signCounter (encrypted, incremented per assertion)
```

The private key never leaves the vault: signing happens inside
`rosec-vault` and only the assertion bytes flow back out.  This is the
same shape `Provider::sign_ssh()` already follows for SSH keys.

#### Phase 3: Implement the credentialsd provider hook

Once credentialsd's third-party-provider API stabilises, add a small
`rosec-credentialsd` binary (or rosecd module behind a cargo feature)
that:

1. Registers as a credentialsd provider over D-Bus.
2. On `CreateCredential`: receives the rpId and PublicKeyCredentialCreationOptions,
   asks the user (via rosec-prompt) which backend should host the new
   passkey, generates a keypair inside `rosec-vault`, and returns the
   public key + credentialId.
3. On `GetCredential`: receives the rpId and a list of allowed
   credentialIds, looks up matching passkeys across backends, asks the
   user to confirm (rosec-prompt with rpId + user label), and returns
   the signed assertion.
4. On lock / autolock: the passkeys are inaccessible until the vault
   is re-unlocked.  credentialsd already understands "authenticator
   unavailable" responses, so this maps cleanly.

#### Phase 4: Browser ergonomics

credentialsd's browser web extension handles
`navigator.credentials.*` interception, so no per-browser work is
needed.  rosec just needs to ensure its prompt UI surfaces enough
context (rpId, requesting app name) for the user to make a sensible
allow/deny decision.

### What this is *not*

- **Not a Secret Service `org.freedesktop.secrets` extension.**  Items
  with extractable secrets via `GetSecret()` are the wrong shape for
  passkeys.  Adding a `type=passkey` item that returns the private
  key bytes would break the WebAuthn security model.
- **Not a wrapper around `passkeyd`**.  credentialsd's scope is
  broader (full ceremony, hybrid transport, browser shim, portal
  spec); passkeyd is a simpler passkey daemon with no spec ambitions.
  If rosec adopts credentialsd's provider hook, passkeyd is
  unnecessary as a dependency.
- **Not the same thing as `Bitwarden passkey-based unlock`**.  The
  WebAuthn 2FA section above covers using a passkey to unlock a
  *Bitwarden vault*.  This section covers serving passkeys from
  rosec's own vault to *other apps* via credentialsd.  The two share
  no code paths — one consumes WebAuthn, the other produces it.

### Effort estimate

- Phase 1 (track + engage): ongoing, low effort, mostly issue
  participation.
- Phase 2 (vault storage): ~1–2 weeks.  Requires `ItemType::Passkey`,
  wrapping the existing storage primitives, exposing a sign-with-key
  interface on the `Provider` trait, and tests.
- Phase 3 (provider hook): unknown until credentialsd's API
  stabilises, but the actual ceremony orchestration is a few hundred
  lines on top of phase 2.
- Phase 4: minimal — UI polish in `rosec-prompt`.

### Status

- credentialsd third-party-provider API: **draft / not yet stable** upstream
- rosec-vault passkey storage: **not started**
- rosec-credentialsd integration: **blocked on upstream**
- Tracking issue: TBD (open one once Phase 1 begins)

### Reference

- Upstream repo: <https://github.com/linux-credentials/credentialsd>
- libwebauthn (authenticator I/O): <https://github.com/linux-credentials/libwebauthn>
- D-Bus introspection: `doc/xyz.iinuwa.credentialsd.Credentials.xml`
  in the credentialsd repo
- ARCHITECTURE.md and GOALS.md in the credentialsd repo

---

## Cross-Platform Support

### Overview

rosec's architecture separates cleanly into platform-agnostic crates and
platform-specific ones.  The goal is not to port the entire stack to every OS,
but to ensure the core crates compile everywhere and platform-specific
functionality is properly gated behind `cfg` attributes.

### D-Bus dependency audit

| Crate | D-Bus? | Cross-platform? | Notes |
|-------|--------|-----------------|-------|
| `rosec-core` | No | Yes | Pure Rust, config/crypto/types |
| `rosec-vault` | No | Yes | Local encrypted storage |
| `rosec-wasm` | No | Yes | Extism host, provider trait bridge |
| WASM guests (bitwarden-pm, bitwarden-sm) | No | Yes | Pure Rust, compile to wasm32-wasi |
| `rosec-ssh-agent` | No | Mostly | Unix sockets need `cfg` gating |
| `rosec-fuse` | No | Linux-only | FUSE is Linux/macOS (macFUSE) |
| `rosec-prompt` | No | Mostly | Wayland-specific structs need gating |
| `rosec-secret-service` | **Yes** | Linux-only | Core D-Bus interface |
| `rosecd` | **Yes** | Linux-only | Daemon, logind integration |
| `rosec` (CLI) | **Yes** | Linux-only | D-Bus client connection |
| `rosec-pam` | No | Linux-only | PAM is Linux-specific |

### Compilation blockers

These are specific locations where ungated platform-specific code prevents
compilation on non-Linux targets.  All are fixable with `cfg` gates and
fallbacks.

| File | Line(s) | Issue | Fix |
|------|---------|-------|-----|
| `rosec-core/src/config_edit.rs` | 297 | Ungated `use std::os::unix::fs::OpenOptionsExt` + `.mode(0o600)` | `#[cfg(unix)]` gate; non-unix: rely on parent dir permissions |
| `rosec-prompt/src/main.rs` | 310, 374-377 | Ungated `PlatformSpecific { application_id, override_redirect }` (Wayland/X11) | `#[cfg(target_os = "linux")]` gate; other platforms: omit or use platform equivalent |
| `rosecd/src/bootstrap.rs` | 31-41 | `prctl` gated `#[cfg(unix)]` but `prctl` is Linux-only | Change to `#[cfg(target_os = "linux")]` |
| `rosec/src/main.rs` | 625 | `read_hidden()` is `#[cfg(unix)]` with no `#[cfg(not(unix))]` fallback | Add Windows fallback using `windows-sys` console mode APIs |
| `rosec-secret-service/src/daemon/management.rs` | 715-726 | `libc::pipe2` — Linux/Unix-specific, no cfg gate | Gate behind `#[cfg(unix)]`; alternative: `std::os::unix::net::UnixStream::pair()` |
| `rosec-secret-service/src/daemon/management.rs` | 390-400 | `/proc/<pid>/exe` readlink — Linux-only | `#[cfg(target_os = "linux")]`; macOS: `proc_pidpath`; others: skip |
| `rosecd/src/main.rs` | 374-405 | `/proc/<pid>/comm` read — Linux-only | `#[cfg(target_os = "linux")]` |
| `rosec-ssh-agent/src/session.rs` | 4, 32, 35 | Ungated `UnixListener`, `PermissionsExt`, `from_mode(0o600)` | `#[cfg(unix)]` + `#[cfg(windows)]` named pipe alternative |

### D-Bus connection sites

All current D-Bus connections use `Connection::session()` or
`Connection::system()`.  These are the sites that would need abstraction for
any non-D-Bus transport:

| File | Line | Bus | Purpose |
|------|------|-----|---------|
| `rosecd/src/main.rs` | 88 | session | Main daemon connection |
| `rosecd/src/main.rs` | 458 | system | logind sleep/lock watcher |
| `rosec-secret-service/src/state.rs` | 2211, 2344 | session | ServiceState operations |
| `rosec-secret-service/src/item.rs` | 304 | session | SecretItem registration |
| `rosec/src/main.rs` | 313 | session | CLI client |
| `rosec-pam/src/main.rs` | 135 | session | PAM unlock module |

### Platform abstractions needed

#### Directory and path handling

Use the [`directories`](https://crates.io/crates/directories) crate (or
`dirs`) for cross-platform config/data/runtime paths:

| Purpose | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Config | `~/.config/rosec` | `~/Library/Application Support/rosec` | `%APPDATA%\rosec` |
| Data | `~/.local/share/rosec` | `~/Library/Application Support/rosec` | `%LOCALAPPDATA%\rosec` |
| Runtime | `$XDG_RUNTIME_DIR/rosec` | `$TMPDIR/rosec-<uid>` | Named pipes / temp |

#### Process introspection (`/proc` abstraction)

Two call sites read from `/proc`: peer exe path (`/proc/<pid>/exe`) for
D-Bus caller verification, and peer comm (`/proc/<pid>/comm`) for logging.
These are Linux-specific:

- **macOS:** `proc_pidpath()` from `libproc` for exe path.
- **Windows/other:** Skip caller verification or use platform-specific
  alternatives.
- Wrap in a `rosec_core::platform::peer_exe_path(pid) -> Option<PathBuf>`
  abstraction.

#### File permissions

`OpenOptionsExt::mode(0o600)` and `PermissionsExt::from_mode(0o600)` are
Unix-only.  On non-Unix platforms:

- Rely on the parent directory's permissions (user-only access).
- On Windows, use ACLs via `windows-sys` or accept default user-only
  permissions on `%LOCALAPPDATA%` paths.

### SSH agent cross-platform support

#### Current state

`rosec-ssh-agent` uses `ssh-agent-lib` v0.5.1 which has first-class Windows
named pipe support via `NamedPipeListener`.

#### Linux (current)

```rust
listen(UnixListener::bind(socket_path)?, agent).await?;
```

Plus optional FUSE mount for per-key `.pub` files in `~/.ssh/rosec/`.

#### Windows / WSL2

```rust
listen(NamedPipeListener::bind(r"\\.\pipe\rosec-agent")?, agent).await?;
```

Windows OpenSSH reads `SSH_AUTH_SOCK` but also supports named pipes natively.
WSL2 can bridge to Windows named pipes via `socat` or `npiperelay`.

#### Cross-platform SSH key export

`rosec ssh export <dir>` writes `.pub` files to a directory on disk.  This
works on all platforms and is the primary non-agent path for making SSH
public keys available.  FUSE remains a Linux-only convenience feature, gated
behind `#[cfg(target_os = "linux")]` (or a cargo feature).

### Lock / sleep event sources

| Platform | Events | Mechanism |
|----------|--------|-----------|
| Linux | Sleep, screen lock, session end | logind D-Bus: `PrepareForSleep`, `Lock`, `SessionRemoved` (implemented) |
| macOS | Sleep, screen lock | `NSWorkspace.willSleepNotification`, `com.apple.screenIsLocked` via `objc2` |
| Windows (native) | Sleep, session lock | `WM_POWERBROADCAST`, `WTS_SESSION_LOCK` via `windows-sys` |
| WSL2 | None | VM freezes silently; no events available. Rely on idle timeouts. |

For macOS, the event watcher would use Objective-C bridge crates (`objc2`,
`block2`) to subscribe to `NSDistributedNotificationCenter`.  This is a
separate `rosec-events-macos` crate or a `#[cfg(target_os = "macos")]` module
within `rosecd`.

### Phased implementation roadmap

#### Phase 1: Compilation fixes (no new features)

Fix all `cfg` gate issues from the compilation blockers table above.  Goal:
`cargo check --target x86_64-apple-darwin` and
`cargo check --target x86_64-pc-windows-msvc` pass for the core crates
(`rosec-core`, `rosec-vault`, `rosec-wasm`, WASM guests).

Estimated scope: ~8 targeted `cfg` additions, no architectural changes.

#### Phase 2: Platform abstraction layer

- Introduce `rosec-core::platform` module with cross-platform helpers:
  `config_dir()`, `data_dir()`, `runtime_dir()`, `peer_exe_path(pid)`,
  `set_file_permissions(path, user_only: bool)`.
- Migrate existing hardcoded paths to use these helpers.
- Add `directories` crate dependency.

#### Phase 3: Private socket mode (embedded busd)

See "Headless / container mode" section above.  This is a Linux feature but
the architecture (embedded bus broker) could theoretically work on macOS too,
since busd and zbus are cross-platform.

#### Phase 4: SSH agent cross-platform

- Gate `UnixListener` path behind `#[cfg(unix)]`.
- Add `#[cfg(windows)]` path using `NamedPipeListener`.
- Gate FUSE behind `#[cfg(target_os = "linux")]` cargo feature.
- `rosec ssh export` works everywhere already (writes files to disk).

#### Phase 5: macOS polish

- macOS sleep/lock event watcher (Objective-C bridge).
- macOS keychain integration as a potential provider (read-only bridge to
  Keychain items).
- macOS-specific prompt backend (if `rosec-prompt`'s current approach
  doesn't work with macOS window management).
- Code signing / notarization for distribution.

### Status

- Compilation audit: **done** (blockers identified above)
- D-Bus dependency map: **done**
- Platform abstraction design: **done** (documented above)
- Phase 1 implementation: **not started**
- Phase 2 implementation: **not started**
- Phase 3 implementation: **not started** (depends on busd evaluation)
- Phase 4 implementation: **not started**
- Phase 5 implementation: **not started**

---

## Daemon-level credential store

### Overview

Enable all providers to benefit from key-wrapping without modifying each
provider.  A daemon-level credential store wraps per-provider unlock
passwords behind its own set of wrapping entries.  When the user types a
password during unlock, the daemon tries it against the store's wrapping
entries; on match, stored provider passwords are auto-supplied — zero extra
prompts.

Registration fields (access tokens, client IDs) are already persisted by
the WASM credential system at `$XDG_DATA_HOME/rosec/oauth/<provider-id>.toml`,
encrypted with `HKDF(password + provider_id)`.  The credential store only
stores the **password** for each provider.  Once the correct password is
supplied, the existing `wasm_cred::load()` flow handles registration fields.

Addresses: [#8](https://github.com/jmylchreest/rosec/issues/8)

### Motivation

Today the `unlock_with_tty()` opportunistic sweep tries the same password
against all locked providers.  This works when providers share a password
but silently fails when they differ.  Users want a single credential action
to unlock everything — even when their Bitwarden master password differs
from their local vault password.

The credential store solves this by mapping:
store wrapping password → per-provider passwords.

### Data model

#### Store file

```
Stored at: $XDG_DATA_HOME/rosec/credential-store.json
Permissions: 0600
```

```json
{
  "version": 1,
  "wrapping_entries": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "label": "master",
      "kdf": { "salt": "base64...", "iterations": 600000 },
      "wrapped_store_key": "base64(IV || AES-256-CBC(store_key))",
      "wrapped_key_hmac": "base64(HMAC-SHA256)"
    }
  ],
  "credentials": {
    "bitwarden": {
      "iv_b64": "...",
      "ciphertext_b64": "...",
      "mac_b64": "..."
    }
  }
}
```

- **store_key**: Random 32-byte key (analogous to LocalVault's vault_key).
- **wrapping_entries**: Each wraps the store_key with a different password
  via PBKDF2 + AES-256-CBC + HMAC-SHA256 (same crypto pattern as
  `rosec-vault/src/crypto.rs`).  Multiple entries allow unlocking with any
  of several passwords.
- **credentials**: Per-provider password blobs encrypted with a
  `StorageKey` derived from the store_key via HKDF, using
  `rosec_core::credential::encrypt/decrypt`.

#### Key hierarchy

```
User password
    │
    ├── PBKDF2(password, kdf_params) ──► wrapping_key
    │       │
    │       └── AES-256-CBC decrypt ──► store_key (32 bytes)
    │                                       │
    │                                       ├── HKDF(store_key, info="rosec-cred-store-v1")
    │                                       │       │
    │                                       │       └── StorageKey (64 bytes: 32 enc + 32 mac)
    │                                       │               │
    │                                       │               ├── AES-256-CBC decrypt ──► provider "bw" password
    │                                       │               ├── AES-256-CBC decrypt ──► provider "sm" password
    │                                       │               └── ...
    │                                       │
    │                                       └── HKDF(store_key, info="mac key")
    │                                               │
    │                                               └── HMAC verify wrapping entry
    │
    └── (may also directly unlock a LocalVault via its own wrapping entries)
```

Adding/removing a wrapping password is O(1) — re-wrap the store_key, not
re-encrypt every credential.

### Configuration

```toml
# Global toggle (default: false)
[credential_store]
enabled = true

# Per-provider opt-in (default: false)
[[provider]]
id = "bw"
kind = "bitwarden-pm"
stored_credentials = true

[provider.options]
email = "user@example.com"
```

Default behaviour (no `[credential_store]` section, no `stored_credentials`
flags) is identical to today — no credential store operations occur.

### Data flow

#### Storing credentials (CLI)

```
1. User runs: rosec credential store <provider-id>
2. CLI shows security warning, prompts for confirmation
3. CLI prompts for store wrapping password
4. CLI prompts for the provider's unlock password
5. Daemon unlocks store (try wrapping entries with store password)
   - If store file doesn't exist: create it (generate store_key,
     wrap with supplied password, label "master")
6. Daemon encrypts provider password with store_key-derived StorageKey
7. Daemon saves credential-store.json (atomic write-then-rename, 0600)
```

#### Unlock flow (modified `unlock_with_tty`)

```
1. User types password (existing prompt — no change)
2. Try password against credential store wrapping entries
   (fast HMAC check per entry, same as LocalVault)
   - Match → store_key decrypted, store is "open"
   - No match → store stays closed, continue as today
3. For each locked provider where:
     - stored_credentials = true in config
     - store is open
     - store has an entry for this provider ID
   → Decrypt stored provider password
   → Call try_auth_provider() with that password
     - Success → mark unlocked, sync, done
     - TwoFactorRequired → add to need_2fa list (password prefilled)
     - RegistrationRequired → add to need_registration list (password prefilled)
     - AuthFailed → fall through to normal flow (stored password may be stale)
   → Remove successfully-handled providers from the locked list
4. Remaining locked providers → existing flow:
   - Same password tried against each (opportunistic sweep)
   - Individual prompts for failures
```

The store attempt is inserted after password collection (line ~141 of
`unlock.rs`) and before the provider-by-provider loop.  No additional
prompts.

#### Lock

```
1. mark_locked() called (existing path)
2. Store key zeroized (credential store closed)
3. Store file remains on disk (encrypted at rest)
4. Next unlock requires re-entering a wrapping password
```

#### Single-provider unlock (`AuthProviderWithTty`)

Same pattern: after collecting the password, try credential store before
calling `try_auth_provider()`.  If the store has a different password
for this specific provider, use it.

### Interfaces

#### New config types

```rust
// rosec-core/src/config.rs

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialStoreConfig {
    /// Master switch.  Default `false` — no credential store operations
    /// occur unless explicitly enabled.
    #[serde(default)]
    pub enabled: bool,
}

// Added to ProviderEntry:
/// Opt-in: store this provider's unlock password in the daemon
/// credential store.  Default `false`.
#[serde(default)]
pub stored_credentials: bool,
```

#### New module: `rosec-core/src/credential_store.rs`

```rust
/// On-disk format.
#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialStoreFile {
    pub version: u32,
    pub wrapping_entries: Vec<StoreWrappingEntry>,
    pub credentials: HashMap<String, EncryptedFields>,
}

/// A wrapping entry protecting the store key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreWrappingEntry {
    pub id: String,
    pub label: Option<String>,
    pub kdf: KdfParams,
    pub wrapped_store_key: String,
    pub wrapped_key_hmac: String,
}

/// In-memory unlocked state.  Zeroized on drop.
pub struct UnlockedCredentialStore {
    store_key: Zeroizing<[u8; 32]>,
    file: CredentialStoreFile,
    path: PathBuf,
}

impl UnlockedCredentialStore {
    /// Try to unlock the store with a password.
    /// Returns None if no wrapping entry matches (fast HMAC rejection).
    pub fn try_open(path: &Path, password: &[u8]) -> Result<Option<Self>>;

    /// Create a new store file with one wrapping entry.
    pub fn create(path: &Path, password: &[u8], label: String) -> Result<Self>;

    /// Decrypt a stored provider password.
    pub fn get_password(&self, provider_id: &str) -> Option<Zeroizing<String>>;

    /// Encrypt and store a provider password.
    pub fn store_password(&mut self, provider_id: &str, password: &str) -> Result<()>;

    /// Remove a stored provider password.
    pub fn remove_password(&mut self, provider_id: &str) -> bool;

    /// List provider IDs with stored passwords.
    pub fn list_providers(&self) -> Vec<&str>;

    /// Add a new wrapping entry (new password that can open the store).
    pub fn add_wrapping_password(&mut self, password: &[u8], label: String) -> Result<String>;

    /// Remove a wrapping entry by ID.  Refuses to remove the last one.
    pub fn remove_wrapping_password(&mut self, entry_id: &str) -> Result<bool>;

    /// List wrapping entries (id, label).
    pub fn list_wrapping_passwords(&self) -> Vec<(&str, Option<&str>)>;

    /// Persist to disk (atomic write-then-rename, mode 0600).
    pub fn save(&self) -> Result<()>;
}
```

#### Crypto functions (in `credential_store.rs`)

```rust
/// Generate a random 32-byte store key.
fn generate_store_key() -> Zeroizing<[u8; 32]>;

/// Wrap the store key with a password.
///
/// 1. Generate random KDF params (salt + iterations)
/// 2. derive_key(password, kdf_params) → wrapping_key  (PBKDF2-SHA256)
/// 3. derive_mac_key(wrapping_key) → mac_key  (HKDF, salt = "rosec-cred-store-mac-v1")
/// 4. AES-256-CBC(store_key, wrapping_key) → wrapped bytes
/// 5. HMAC-SHA256(wrapped_bytes, mac_key) → hmac
/// 6. Return StoreWrappingEntry
fn wrap_store_key(store_key: &[u8; 32], password: &[u8], label: String)
    -> Result<StoreWrappingEntry>;

/// Unwrap the store key.  Returns None on wrong password (HMAC mismatch).
fn unwrap_store_key(entry: &StoreWrappingEntry, password: &[u8])
    -> Result<Option<Zeroizing<[u8; 32]>>>;

/// Derive a StorageKey from the store key for encrypting provider passwords.
fn derive_credential_key(store_key: &[u8; 32]) -> Result<StorageKey>;
```

#### ServiceState changes

```rust
// rosec-secret-service/src/state.rs

pub struct ServiceState {
    // ... existing fields ...

    /// Unlocked credential store (in-memory, zeroized on lock).
    credential_store: Mutex<Option<UnlockedCredentialStore>>,
}

impl ServiceState {
    /// Try to unlock the credential store with a password.
    /// Returns true if the store was unlocked.
    pub async fn try_unlock_credential_store(&self, password: &str) -> bool;

    /// Get a stored provider password (if store is unlocked and has one).
    pub async fn get_stored_password(&self, provider_id: &str) -> Option<Zeroizing<String>>;

    /// Store a provider password (store must be unlocked).
    pub async fn store_credential(&self, provider_id: &str, password: &str) -> Result<()>;

    /// Remove a stored provider credential.
    pub async fn remove_credential(&self, provider_id: &str) -> Result<bool>;

    /// List provider IDs with stored credentials.
    pub async fn list_stored_credentials(&self) -> Vec<String>;
}
```

#### D-Bus methods

| Method | Parameters | Returns | Notes |
|--------|-----------|---------|-------|
| `StoreProviderCredential` | `provider_id`, `store_pw_fd`, `provider_pw_fd` | `()` | fd-passing |
| `RemoveProviderCredential` | `provider_id` | `bool` | |
| `ListStoredProviderCredentials` | | `Vec<String>` | provider IDs |
| `AddStorePassword` | `password_fd`, `label` | `String` | returns entry ID |
| `RemoveStorePassword` | `entry_id` | `bool` | refuses last entry |
| `ListStorePasswords` | | `Vec<(String, String)>` | (id, label) |

#### CLI commands

```
rosec credential store <provider-id>         Store a provider's unlock password
rosec credential remove <provider-id>        Remove a stored provider password
rosec credential list                        List providers with stored passwords

rosec credential add-password [--label]      Add a wrapping password to the store
rosec credential remove-password <entry-id>  Remove a wrapping password
rosec credential list-passwords              List store wrapping entries
```

### Key decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Store scope | Password only | Registration fields already handled by `wasm_cred` system. The store fills the one gap: different passwords across providers. |
| Wrapping model | Multi-entry (like LocalVault) | Any of several passwords can open the store. Supports use cases like "laptop password" + "YubiKey-derived password" (future). Adding/removing entries is O(1). |
| Store unlock trigger | Tried automatically with user's password | No extra prompt. The password typed for provider unlock is opportunistically tried against store wrapping entries. Silent no-op if it doesn't match. |
| Separate from LocalVault | Yes — independent store file | The repo owner flagged that storing credentials *in* another provider is "giving away your master password to a potentially less secure vault." The daemon credential store is owned by the daemon, not by any provider. |
| Crypto | Same primitives as LocalVault | PBKDF2 + AES-256-CBC + HMAC-SHA256, with store-specific HKDF domain separation (`rosec-cred-store-mac-v1`). Proven pattern, no new dependencies. |
| Config model | Opt-in, normal naming | `stored_credentials = true` per provider + `[credential_store] enabled = true` globally. Security warning shown at CLI store time. |
| Stale password handling | Fall through to normal flow | If a stored password fails `AuthFailed`, the provider is left in the `locked` list for the normal prompt flow. No automatic deletion of stored credentials on failure (the user may have just changed their password externally). |

### Interaction with existing systems

#### WASM credential storage (`wasm_cred`)

The credential store supplies the *password* to `try_auth_provider()`.
Inside the WASM provider's `unlock()`, this password is used to
`wasm_cred::load()` registration fields (access tokens, client secrets)
from `$XDG_DATA_HOME/rosec/oauth/<provider-id>.toml`.  No changes to
`wasm_cred.rs` or `credential.rs` needed.

#### Opportunistic sweep

The credential store runs *before* the sweep.  Providers unlocked by
stored credentials are removed from the `locked` list before the sweep
runs.  The sweep still handles any remaining providers.

#### PAM module

`pam-rosec-unlock` passes the login password via pipe.  This password
will also be tried against the credential store wrapping entries — if the
user adds their login password as a store wrapping entry, PAM login
unlocks all stored-credential providers automatically.

#### Autolock

`mark_locked()` clears the credential store from memory (`store_key`
zeroized).  Re-unlock after autolock requires re-entering a wrapping
password, same as re-entering the vault password today.

### Acceptance criteria

#### Core store mechanics
- [ ] `CredentialStoreFile` format with version, wrapping_entries, credentials
- [ ] `generate_store_key()` produces random 32-byte key
- [ ] `wrap_store_key()` / `unwrap_store_key()` with HMAC-first fast rejection
- [ ] Multiple wrapping entries supported (add, remove, list)
- [ ] Cannot remove last wrapping entry
- [ ] Provider passwords encrypted/decrypted via `credential::encrypt/decrypt`
- [ ] Store file uses atomic write-then-rename, mode 0600

#### Config
- [ ] `[credential_store]` section with `enabled` flag (default false)
- [ ] `stored_credentials` per-provider flag (default false)
- [ ] Default config (no credential_store section) behaves identically to today

#### Unlock integration
- [ ] Store wrapping entries tried with user's password during `unlock_with_tty()`
- [ ] Stored passwords auto-supplied to providers with `stored_credentials = true`
- [ ] Providers with 2FA: password supplied, 2FA still prompted interactively
- [ ] Providers with registration: password supplied, `wasm_cred` handles the rest
- [ ] Failed stored password: provider falls through to normal prompt flow
- [ ] Store locked on `mark_locked()`, store_key zeroized

#### CLI
- [ ] `rosec credential store` with security warning + confirmation
- [ ] `rosec credential remove`, `list`
- [ ] `rosec credential add-password`, `remove-password`, `list-passwords`
- [ ] All passwords via fd-passing (never on D-Bus wire)

### Security considerations

1. **No password storage without opt-in**: Both `[credential_store] enabled = true`
   and per-provider `stored_credentials = true` are required. Default behaviour
   is unchanged.

2. **Password-protected at rest**: Store key is wrapped with PBKDF2-derived
   keys. Provider passwords are encrypted with store_key-derived keys. The
   store file is meaningless without a wrapping password.

3. **Zeroization**: All key material uses `Zeroizing<>` wrappers.  Store key
   is scrubbed on lock.  Provider passwords are scrubbed after being passed
   to `try_auth_provider()`.

4. **No credentials on D-Bus**: All password parameters use fd-passing
   (SCM_RIGHTS), consistent with existing unlock methods.

5. **Atomic persistence**: Write-then-rename prevents partial writes.
   File mode 0600 restricts access to the owning user.

6. **Security warning**: CLI displays a clear warning when first storing
   credentials, explaining that anyone who knows a store wrapping password
   can access the provider's credentials.

7. **Stale credentials**: Failed stored passwords do NOT auto-delete.  The
   user may have mistyped their store password or changed their provider
   password externally.  Manual `rosec credential remove` is required.

### Files to create/modify

#### New files
- `rosec-core/src/credential_store.rs` — core store module (data types, crypto, file I/O)

#### Modified files
- `rosec-core/src/config.rs` — `CredentialStoreConfig`, `stored_credentials` field
- `rosec-core/src/lib.rs` — re-export `credential_store` module
- `rosec-secret-service/src/state.rs` — `credential_store` field, methods, `mark_locked()` integration
- `rosec-secret-service/src/unlock.rs` — insert store unlock + auto-supply into `unlock_with_tty()`
- `rosec-secret-service/src/daemon/management.rs` — new D-Bus methods
- `rosec/src/cli.rs` — `CredentialCommands` subcommand group
- `rosec/src/main.rs` — CLI handlers

#### Reused (no changes needed)
- `rosec-core/src/credential.rs` — `encrypt()`, `decrypt()`, `StorageKey`
- `rosec-core/src/oauth.rs` — file I/O patterns
- `rosec-wasm/src/wasm_cred.rs` — registration field storage (unchanged)
- `rosec-vault/src/crypto.rs` — pattern reference for PBKDF2 + AES-256-CBC + HMAC

### Out of scope

- **FIDO2 / TPM wrapping entry types**: The wrapping entry model supports
  a future `method` discriminant (currently always `"password"`), but
  non-password mechanisms are a separate feature.
- **systemd-creds integration**: Could inject a store wrapping password at
  service start.  Compatible with this design but not part of initial work.
- **Provider dependency chains**: The credential store is simpler and more
  general — no need for explicit provider ordering or dependency declarations.
- **Storing registration fields**: Already handled by `wasm_cred`.

### Status

- **Not started** — design only.  Tracked in [#8](https://github.com/jmylchreest/rosec/issues/8).

---

## Provider trait: split `create_item(replace)` into `insert_item` / `replace_item`

### Background

`Provider::create_item(item: NewItem, replace: bool) -> Result<String>` does
two distinct jobs: when `replace=false` it inserts and reports `AlreadyExists`
on attribute collision; when `replace=true` it scans the provider's storage
for a matching item and either updates that item or inserts a new one.

The find-by-attributes step inside the provider was the right design when the
provider was the only thing that knew its own storage.  After the
service-layer routing change (`ServiceState::find_writable_match`), the
service already picks the writable provider that owns the matching item using
the metadata cache — i.e. the same view `SearchItems` exposes.  The provider's
internal scan now duplicates that work and can disagree on edge cases (cache
drift, provider-internal-only attributes, type-stamp differences).

### Proposed shape

```rust
async fn insert_item(&self, item: NewItem) -> Result<String, ProviderError>;
// Always inserts. AlreadyExists is no longer the provider's responsibility —
// it's enforced at the service layer based on `find_writable_match`.

async fn replace_item(&self, id: &str, item: NewItem) -> Result<(), ProviderError>;
// Updates the item with the given id, replacing label/attributes/secrets.
// NotFound → caller falls back to insert.
```

Service-layer flow becomes:

1. `find_writable_match(&attrs)` → `Option<(provider, existing_id)>`
   (today returns just `provider`; would re-add the id).
2. `Some((p, id))`: if the caller passed `replace`, `p.replace_item(&id, item)`;
   else return `AlreadyExists`.
3. `None`: `write_provider().insert_item(item)`.

### Why this is worth doing

- **Single source of truth for matching.**  Today the predicate runs in two
  places; after the patch they agree, but agreement is enforced by convention
  rather than by the type system.  Splitting the trait makes "discovery" the
  service's job and "atomic write" the provider's job — no overlap.
- **Provider impls shrink.**  Each provider drops its find-by-attrs branch.
  For the WASM providers this is a non-trivial simplification.
- **Concurrency story improves.**  When the service routes by id, races
  between concurrent CreateItems become "two inserts at different ids" rather
  than "two inserts that race on attribute matching", which is easier to
  reason about and easier to deduplicate at the next cache rebuild.

### Cost

- **Provider trait change**: every impl must be updated.  Affected:
  - `rosec-vault/src/provider.rs`
  - The default impl in `rosec-core/src/lib.rs`
  - Test mocks in `rosec-secret-service/src/portal.rs` and
    `rosec-core/src/lib.rs`
- **WASM ABI break**: `rosec-bitwarden-pm`, `rosec-bitwarden-sm`,
  `rosec-gnome-keyring`, `rosec-keepassxc-file` all expose `create_item` as a
  guest export.  Splitting on the host means changing the guest contract too.
  The host needs version detection so older `.wasm` plugins keep working until
  rebuilt.
- **Deferred CreateItem**: `rosec-secret-service/src/prompt.rs` carries
  `PendingOperation::CreateItem { provider_id, item, replace }`.  The deferred
  variant needs to switch to `insert_item` / `replace_item` plumbing too.
- **Daemon extension surface**: `org.rosec.Items.CreateItemExtended`
  (`rosec-secret-service/src/daemon/items.rs`) takes `replace: bool` on the
  wire — the wire shape can stay the same; the implementation just routes
  differently internally.

### When to do it

After the WASM plugin distribution allows a coordinated rebuild — i.e. when
there is a release that bumps all of: `rosec_bitwarden_pm.wasm`,
`rosec_bitwarden_sm.wasm`, `rosec_gnome_keyring.wasm`,
`rosec_keepassxc_file.wasm`, plus the host.  Until then the current
single-method trait keeps backward compatibility with shipped plugins.

### Status

- **Not started** — design only.  Captured here so the routing fix's
  layering implications don't get forgotten.
