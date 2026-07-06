---
sidebar_position: 6
title: FIDO2 passkeys
---

# FIDO2 passkeys

Status: **phase 1 implemented** — the credential model, provider capability,
and backend mappings. WebAuthn *serving* (frontends that browsers and apps
talk to) is designed here but not yet built. Tracked in
[#13](https://github.com/jmylchreest/rosec/issues/13).

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
- **Fido2 registry** (future) — rosecd-side index of credentials across
  unlocked providers, rebuilt on unlock/sync, mirroring how the SSH agent's
  keystore works. Both frontends consume it; neither touches providers
  directly.
- **Ceremony engine** (future) — one implementation of
  `authenticatorGetAssertion` / `authenticatorMakeCredential`:
  authenticatorData assembly, client-data hashing, ES256/EdDSA/RS256
  signing, attestation `"none"`. User presence/verification goes through
  `rosec-prompt`, like SSH `require_confirm`. Synced-passkey counter
  semantics: a stored counter of `0` stays `0` (Bitwarden and KeePassXC
  both do this; RPs treat zero counters as "counter not supported").

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
2. The kernel materialises `/dev/hidrawN`; systemd's `fido_id` rule tags
   FIDO-usage-page devices with `uaccess` automatically, so the active
   session's browsers can open it — no rosec-specific udev rule needed for
   the *hidraw* side.
3. Browsers enumerate it like a USB key; rosec answers `CTAPHID_INIT`,
   `authenticatorGetInfo`, `authenticatorMakeCredential`,
   `authenticatorGetAssertion` from the registry + ceremony engine, with
   `rosec-prompt` supplying user presence/verification (reported as
   `uv = true`, the platform-authenticator pattern).

"User level" is achievable, with one caveat: `/dev/uhid` itself is
root-only by default, so packaging ships a udev rule granting `uaccess` to
`/dev/uhid` (the same mechanism used for `/dev/kvm` and friends), or a
small privileged helper creates the device and hands the fd to the user
daemon (the softu2f split). After creation everything runs as the user.
Known limitations: Flatpak/Snap-confined browsers need device access;
attestation-enforcing RPs (e.g. Entra ID) reject software authenticators.

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
