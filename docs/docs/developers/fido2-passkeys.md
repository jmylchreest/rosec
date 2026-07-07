---
sidebar_position: 6
title: FIDO2 passkeys
---

# FIDO2 passkeys

Status, tracked in [#13](https://github.com/jmylchreest/rosec/issues/13):

- **Phase 1 (done)** — credential model, `Capability::Fido2`, the three
  storage mappings, the local-vault write path (`makeCredential` storage),
  and `rosec-prompt`'s selection UI.
- **Phase 2 (in progress)** — the `rosec-uhid` frontend. Landed so far: the
  privileged broker (device creation, per-uid hidraw chown, `SCM_RIGHTS`
  fd-passing), the `/dev/uhid` codec with the hard-coded FIDO descriptor,
  CTAPHID transport framing, and the system unit. **Remaining**: the CTAP2
  command/ceremony engine (`getInfo`/`getAssertion`/`makeCredential`
  signing wired to the registry), which needs root + a real browser to
  verify end to end.
- **Phase 3 (future)** — the credentialsd provider bridge, once their
  upstream provider API exists.

## Architecture: storage is a provider concern, serving is a frontend

Passkeys follow the same seam as SSH keys: providers **store** credentials
and expose them through a capability; host-side **frontends** perform the
protocol ceremonies, the way `rosec-ssh-agent` signs with keys the
providers store. No WASM plugin ever implements WebAuthn itself.

```
                         ┌──────────────────────────────┐
  browsers / apps ──────▶│ frontend A: credentialsd     │
                         │   provider bridge (D-Bus)    │──┐
                         └──────────────────────────────┘  │   Fido2 registry +
                         ┌──────────────────────────────┐  ├─▶ ceremony engine ──▶ providers
  browsers (unmodified)─▶│ frontend B: virtual CTAP2    │──┘   (rosecd)             (storage)
                         │   authenticator (/dev/uhid)  │
                         └──────────────────────────────┘
```

The pieces:

- **`Capability::Fido2`** — providers declaring it implement
  `list_fido2_credentials()` (metadata for discovery/selection: rpId, user
  handle, algorithm, …) and `get_fido2_key(item_id, credential_id)` (PEM
  PKCS#8 private key, fetched only at ceremony time, zeroized after use).
- **Passkey registry** (future) — a rosecd-side index of the passkeys held
  by unlocked providers, consumed by both frontends so neither talks to
  providers directly. It is rebuilt whenever a provider unlocks or reports a
  changed sync, and cleared on lock — the same discipline the SSH and TOTP
  managers use. It never serves a stale snapshot: each rebuild re-reads the
  current set of passkey-capable providers and re-queries their credentials,
  so an unlock or sync is always reflected.
- **Ceremony engine** (future) — one implementation of
  `authenticatorGetAssertion` / `authenticatorMakeCredential`:
  authenticatorData assembly, client-data hashing, ES256/EdDSA/RS256
  signing, attestation `"none"`. User presence/verification goes through
  `rosec-prompt`, like SSH `require_confirm`. Synced-passkey counter
  semantics: a stored counter of `0` stays `0` (Bitwarden and KeePassXC
  both do this; RPs treat zero counters as "counter not supported").

### Multiple matching credentials

When a `getAssertion` matches more than one credential (an `allowList` with
several, or a discoverable-credential request against a vault holding
multiple passkeys for the RP), rosec follows the platform-authenticator
pattern rather than the CTAP `getNextAssertion` paging dance: it presents
its **own** account chooser and returns a single assertion
(`numberOfCredentials = 1`). Choosing an account *is* the user
presence/verification gesture.

The chooser is `rosec-prompt`'s **selection mode** (implemented now):
`{"select": {"options": [{id, primary, secondary}]}}` renders a scrollable
single-select list (GUI: iced, keyboard + click, Enter/Esc; no-display
fallback: a numbered TTY menu reading `/dev/tty`), emitting
`{"selected": "<id>"}`. The engine passes `primary = user@rpId` and
`secondary = source provider`, using the returned id as the credential
handle to sign with. Cancel (exit 1) maps to CTAP2 `0x27`
(operation denied); zero matches to `0x2b` (no credentials). The same
selection prompt is reusable for other "which of these?" flows such as
multiple matching SSH keys.

### No matching credential — stay silent

The virtual authenticator is always present, so it is queried on *every*
`getAssertion`, including sites where the user has no rosec passkey. When
nothing matches — an empty `allowList` discoverable request with no resident
credential for the RP, or an `allowList` containing none of rosec's
credential IDs — the engine returns `CTAP2_ERR_NO_CREDENTIALS` (`0x2b`)
**without showing a prompt**. Prompting on every no-match would make routine
logins unusable and leak activity. rosec-prompt appears only when there is a
real credential to confirm.

### Creating a passkey — registration

`makeCredential` (`navigator.credentials.create()`) is user-initiated, not
something rosec pushes: the browser shows its own authenticator picker, and
rosec is invoked only if the user selects it there. Having zero existing
passkeys is the normal starting state and blocks nothing.

A created credential needs a provider that can both **write** and **store
passkeys**. The configured write provider is used when it qualifies,
otherwise the first provider in config order that does. Today that is the
**local vault** only; the Bitwarden and KeePassXC providers expose passkeys
for reading but rosec does not write passkeys back to them, so they are
never chosen as registration targets. When no writable passkey store is
available, `makeCredential` fails cleanly rather than hanging the browser.
rosec also honours `excludeCredentials`: if it already holds a credential
the relying party lists there, registration is refused
(`CTAP2_ERR_CREDENTIAL_EXCLUDED`).

Symmetrically, the read side (`getAssertion` and registry building) draws
only from passkey-capable providers, so a
ceremony never queries a provider that can't hold passkeys. Both selectors
build on the generic capability-set routing in `rosec_core`
(`supports_all` / `require_all`).

### Normalisation at the rosec boundary

| Field | Canonical form | Bitwarden native | KeePassXC native |
|---|---|---|---|
| private key | PEM PKCS#8 | base64url PKCS#8 DER (plugin wraps) | PEM PKCS#8 (pass-through) |
| credential ID | base64url raw bytes, unpadded | GUID string (plugin converts, RFC 4122 order) | base64 string (padding stripped) |
| algorithm | COSE id (`-7` ES256, `-8` EdDSA, `-257` RS256) | always ES256 | sniffed from the key's PKCS#8 OID |
| user handle | base64url, unpadded | pass-through | pass-through |

## Backend mappings (phase 1, implemented)

- **bitwarden-pm** — parses the `fido2Credentials` array on login ciphers
  (every field vault-encrypted; decrypted alongside the login, key material
  in `Zeroizing`). Credentials with non-ES256 algorithms are skipped with a
  debug log — Bitwarden only creates ECDSA/P-256 keys.
- **keepassxc-file** — reads the `KPEX_PASSKEY_*` protected attributes
  KeePassXC has written since 2.7.7 (`_RELYING_PARTY`, `_CREDENTIAL_ID`,
  `_PRIVATE_KEY_PEM`, `_USER_HANDLE`, `_USERNAME`).
- **local vault** — any item with the `fido2_rp_id` attribute and a
  `fido2_private_key` secret (see `rosec-vault/src/fido2.rs` for the full
  attribute table). This makes rosec itself a passkey store, not just a
  bridge to external managers.

### Is local-vault passkey storage secure?

Yes, with the same posture as everything else in the vault — a passkey
private key is not materially different from the SSH private keys and
passwords the local vault already protects:

- At rest it lives in the `secrets` map, encrypted under the vault key
  (AES-256, key-wrapped per unlock password); attributes (rpId, username)
  are metadata with the same at-rest protection as other item attributes.
- In memory it is `Zeroizing`-wrapped, `Debug`-redacted, and only leaves
  the provider through `get_fido2_key` at ceremony time.
- What it is **not**: hardware-bound. Like every software password manager
  (Bitwarden, 1Password, KeePassXC), the key is extractable by anything
  that can read the unlocked vault's memory. Relying parties that require
  hardware-backed attestation will not accept software authenticators
  regardless of which manager stores them — we sign with attestation
  `"none"`, the industry norm for synced passkeys.

## Frontends (phase 2, designed)

### A. credentialsd provider bridge — the strategic path

[credentialsd](https://github.com/linux-credentials/credentialsd) is the
emerging D-Bus WebAuthn mediator for Linux (SUSE-sponsored, xdg-desktop-portal
integration in review). Its third-party provider API — the interface rosec
would register against — **does not exist yet**; the design is tracked in
[credentialsd#26](https://github.com/linux-credentials/credentialsd/issues/26)
and sketches an Android-like model: providers register over D-Bus, answer
credential-matching queries, run their own unlock UI, and return the
credential. When that lands, rosec registers as a provider: credentialsd
owns browser wiring and the account-selection UI; rosec answers matching
queries from the registry and performs signing via the ceremony engine,
prompting through `rosec-prompt` for unlock/UV.

### B. Virtual CTAP2 authenticator over uhid — works with today's browsers

A `rosec-fido` frontend can present a **virtual FIDO2 HID device** so
*unmodified* Firefox (114+) and Chromium use rosec as a security key.

**This is not a filesystem mount.** rosec's FUSE frontends work because SSH
public keys and TOTP codes are file-shaped; CTAP2 is not — it is a
64-byte-report HID protocol (CTAPHID framing carrying CBOR) that browsers
speak directly to `/dev/hidraw*` device nodes. The kernel facility for
creating such a device from userspace is **`/dev/uhid`** (virtual HID), a
character device, not a mount point. The flow:

1. `rosec-fido` opens `/dev/uhid` and creates a HID device declaring the
   FIDO usage page (`0xF1D0`).
2. The kernel materialises `/dev/hidrawN`. The node must be owned by the
   requesting user at `0600` (see *Multi-user safety* below) — **not** left
   to the generic `fido_id` uaccess tag, which is active-seat-scoped and
   wrong for a virtual device.
3. Browsers enumerate it like a USB key; rosec answers `CTAPHID_INIT`,
   `authenticatorGetInfo`, `authenticatorMakeCredential`,
   `authenticatorGetAssertion` from the registry + ceremony engine, with
   `rosec-prompt` supplying user presence/verification (reported as
   `uv = true`, the platform-authenticator pattern).

### Multi-user safety — do NOT rely on the blanket `fido_id` uaccess tag

The stock `fido_id` + `70-uaccess` rule grants the `/dev/hidrawN` node to
the **active seat session**, not to a specific user — the model assumes a
physical device on a seat. A virtual uhid device has no seat binding, so on
a multi-user box (fast user-switching, multi-seat) that ACL can expose one
user's authenticator node to whoever is currently active. They still can't
complete an assertion — CTAP flows to the fd the owner's rosecd holds, so
the prompt fires on the *owner's* session and dies without their
confirmation — but enumeration/initiation by another local user is not an
acceptable property.

The device node must therefore be owned by the **requesting uid at mode
`0600`**, not left to the generic uaccess tag: either a dedicated udev rule
keyed on rosec's vendor/product string chowns it, or the broker chowns it
after `UHID_CREATE2` (it knows the caller's uid from `SO_PEERCRED`).
Remote/SSH users have no active seat and cannot open the node regardless;
only concurrent *local* sessions are in scope. This frontend is a desktop
feature and should be opt-in per user, not enabled system-wide on shared
servers.

### Broker trust model — uid, not binary identity

The caller's identity comes from `SO_PEERCRED` on the broker's Unix socket:
the kernel stamps the connecting process's real uid, which cannot be
spoofed and is never taken from the request body (the request carries no
uid and no descriptor). Activation is systemd socket activation — the
user's rosecd connects to `/run/rosec/uhid.sock`, systemd spawns the
broker, it serves one request and exits.

Be clear about what this does **not** restrict: the broker authenticates by
**uid, not by binary**. Any process running as user X can connect and
receive a FIDO device chowned to X. Binary-level restriction is not
robustly achievable over Unix sockets — `SO_PEERCRED` yields uid/pid/gid but
not a trustworthy executable identity, and `/proc/PID/exe` is raceable — and
it is not a hard boundary anyway, because same-uid processes already share a
trust domain. The device is hard-coded FIDO-only, is chowned to X, and all
CTAP logic runs in X's own daemon, so a process as X obtaining a FIDO device
for X is not a privilege escalation (X could not otherwise get one, since
`/dev/uhid` is root-only, but the capability it gains is confined to X's own
session).

The residual concern is a rogue same-uid process claiming X's device slot
and presenting a *rogue* authenticator to X's browsers. Mitigations, in
order: one-device-per-uid (implemented); **rosecd claims the device at
startup** so it wins the slot first-come; optionally an `SO_PEERSEC`
SELinux-label check where MAC is deployed. Socket permissions can restrict
*which uids may connect at all* but cannot distinguish binaries within a
uid.

### The check in the other direction — rosecd verifies the broker

The broker authenticating the client is only half of it. Because the
rendezvous socket is a shared, world-connectable system path, rosecd must
also verify **the thing it connected to is the real broker** before trusting
what it receives — otherwise a process that squatted the socket path could
hand rosecd a descriptor to a device *it* controls and drive rosecd as a
signing oracle (feeding it assertions for a target relying party and
capturing the signatures). Two checks close this, both required in the
client (`rosec-uhid`'s `client` module) that rosecd uses:

- **The broker peer must be uid 0.** `SO_PEERCRED` on rosecd's side yields
  the *server's* uid; the real broker is a root system service, so a non-root
  peer at that path is an imposter and rosecd refuses.
- **The received fd must be the uhid device.** rosecd `fstat`s the passed
  descriptor and confirms it is a character device whose device number
  matches `/dev/uhid`, rejecting any other fd a squatter might send.

The path itself is kept squat-proof by owning `/run/rosec` as `root:root`
`0755` (declared `RuntimeDirectory=rosec` on the socket unit), so an
unprivileged process cannot unlink and re-bind the socket in the first place;
the two client-side checks are defence-in-depth on top of that.

### Device lifecycle — idempotency and cleanup

The passed fd is the ownership token, which makes the lifecycle
self-cleaning:

- **Singleton per rosecd**: rosecd holds the device fd for its lifetime and
  treats it as a singleton. It already single-instances via its D-Bus name
  lock, so it never opens two.
- **Already-exists = double-start only**: the broker enforces
  one-device-per-uid (keyed on `SO_PEERCRED`), refusing or returning the
  existing device rather than stacking a second authenticator for the same
  user. There is no *stale* node to reconcile — see cleanup.
- **Cleanup is automatic on every exit path**. Closing the fd destroys the
  uhid device, and the kernel closes the fd when the process dies. So:
  normal shutdown sends `UHID_DESTROY` then closes (device gone
  immediately); a crash/`SIGKILL` closes the fd as the process dies →
  kernel destroys the device (**a badly-dying daemon cannot leak a virtual
  FIDO device** — the key safety property). The broker holds nothing after
  fd-passing, so it has no cleanup responsibility and no persistent
  privileged state.
- **Lock / logout**: on vault lock or session end, destroy the device
  (default — no authenticator present while locked, browser sees the key
  unplugged) rather than leaving it to fail every ceremony against a locked
  provider. This matches rosec's autolock model.

"User level" is achievable, with one caveat: `/dev/uhid` itself is
root-only by default — deliberately, because uhid can create *any* HID
device, including virtual keyboards (an input-injection primitive). Two
ways to cross that boundary without running rosecd as root:

- **udev `uaccess` rule** on `/dev/uhid` (the `/dev/kvm` mechanism) —
  zero moving parts, but it hands every process in the active session the
  ability to create arbitrary HID devices, widening the input-injection
  surface beyond rosec.
- **Privileged broker (preferred)** — a tiny socket-activated system
  service (`rosec-uhid`) opens `/dev/uhid` as root, creates a
  device whose HID descriptor is hard-coded to the FIDO usage page
  (`0xF1D0`), passes the fd to the user's rosecd via `SCM_RIGHTS`, and
  exits. The broker physically cannot be asked to create a keyboard, and
  after fd-passing all CTAP traffic runs unprivileged. This is the
  softu2f split, and it matches rosec's least-privilege posture.

After creation everything runs as the user.
Known limitations: Flatpak/Snap-confined browsers need device access;
attestation-enforcing RPs (e.g. Entra ID) reject software authenticators.

Component split — the broker is privileged but trivial; all protocol
logic is unprivileged:

| | `rosec-uhid` (system service) | fido2 frontend (in rosecd) |
|---|---|---|
| privilege | root, socket-activated, exits after fd-passing | user |
| does | `SO_PEERCRED` caller check → open `/dev/uhid` → `UHID_CREATE2` with a hard-coded FIDO-only descriptor → pass fd via `SCM_RIGHTS` | event loop on the fd: `UHID_OUTPUT` in, `UHID_INPUT2` out |
| protocol | none | CTAPHID framing (INIT, fragmentation, KEEPALIVE `UPNEEDED` while a prompt is up) + CTAP2 CBOR commands |
| CTAP2 surface | — | `getInfo` (`rk=true`, `uv=true`), `getAssertion`/`getNextAssertion` (registry lookup → rosec-prompt UP/UV → `get_fido2_key` → sign → zeroize), `makeCredential` (stores into a writable `Fido2` provider — the local vault) |
| lifetime | milliseconds | session; closing the fd destroys the device |

Useful crates surveyed for phase 2:

- **`passkey-rs`** (1Password: `passkey-authenticator`, `passkey-types`) —
  a maintained software-authenticator implementation with WebAuthn/CTAP2
  types; the strongest candidate to base the ceremony engine on.
- **`webauthn-authenticator-rs`** (kanidm workspace) — authenticator-side
  implementation including a SoftToken; good prior art, and its sibling
  **`webauthn-rs`** (RP side) is ideal *in tests* to verify our assertions
  the way a relying party would.
- **`authenticator`** (Mozilla's authenticator-rs) — the *client* side of
  CTAP (what browsers use to talk **to** tokens); useful only if rosec ever
  mediates hardware keys, not for serving credentials.
- **`uhid-virt`** — thin wrapper over `/dev/uhid` for frontend B's device
  plumbing.

## Code surface (phase 1)

- `rosec-core` — `Capability::Fido2`, `Fido2CredentialMeta`,
  `Fido2KeyMaterial`, `Provider::{list_fido2_credentials, get_fido2_key}`.
- `rosec-wasm` — guest protocol (`list_fido2_credentials`/`get_fido2_key`
  exports, `WasmFido2CredentialMeta` wire struct) and host glue.
- `rosec-vault/src/fido2.rs`, `rosec-bitwarden-pm`, `rosec-keepassxc-file`
  — the three storage mappings.
