Proton Pass WASM feasibility spike
================================

Read-only, GPL-3.0-or-later. Not a production provider. Not installed or wired into
rosec's provider registry or release packaging. The local vault remains writable;
external provider writes and password changes deliberately return NotSupported.

What this proves
----------------
Proton's actual GPL item schema/generated decoder and adapted PAT/AES-GCM logic
compile into an Extism wasm32-wasip1 guest. No browser JavaScript, subprocess or
native Proton library is required by this guest. We reuse selected upstream parts,
not the entire pass SDK. UPSTREAM.txt records exact sources and modifications.

The probe loads the actual WASM using Extism 1.30.0, matching this rosec checkout.
Its loopback HTTP server supplies synthetic Proton response envelopes and encrypted
share -> item -> content keys. The guest performs actual HTTP requests and decryption.
Tests check TOTP against RFC 6238 through rosec-core, public/secret separation,
read-only methods, successful resync, tamper rejection, simulated authorization
revocation, and denial of secret access after lock. This is not a full daemon,
D-Bus, FUSE, SSH-agent or WebAuthn end-to-end test.

Build and run from the repository root
--------------------------------------
  cargo build --manifest-path rosec-protonpass/Cargo.toml --locked --target wasm32-wasip1 --release
  cargo test --manifest-path rosec-protonpass/Cargo.toml --locked
  cargo run --manifest-path rosec-protonpass/Cargo.toml --locked --example probe
  cargo clippy --manifest-path rosec-protonpass/Cargo.toml --locked --target wasm32-wasip1 -- -D warnings
  cargo clippy --manifest-path rosec-protonpass/Cargo.toml --locked --all-targets -- -D warnings

The probe expects the guest at this crate's target/wasm32-wasip1/release path.
Build the guest without overriding CARGO_TARGET_DIR; the native harness can use
a shared target directory. The fixture probe requires a loopback socket.

Optional live test
------------------
The probe's --live mode reads a PAT from standard input, never an argument. Pipe
it directly from a secret manager; do not paste credentials into shell history.
It performs PAT login, full sync of direct vault/root supported items, metadata
counting and local lock. It does not write items. It does not currently revoke
the remote PAT session; use a short-lived test-only PAT and revoke it afterwards.
Only pass a PAT scoped to a dedicated synthetic test vault. Output contains counts,
not item names, usernames, passwords, seeds or tokens. API failures are redacted.

Live account attempt on 2026-10-10
--------------------------------
The official checksum-verified pass-cli 2.4.2 successfully authenticated with the
user-authorized account credentials and TOTP obtained privately from rosec.
It then refused access with "Your account is not yet allowed to use our CLI".
The upstream eligibility guard logs out on that path. No account upgrade, vault,
item or PAT was created. Temporary encrypted session storage was removed; its
encryption key existed only in the probe process. No credentials or live responses
are saved in this worktree. Live guest vault interoperability is therefore unproven.

Limitations and next implementation steps
-----------------------------------------
- The ephemeral auth_fields PAT must be supplied for each unlock. The nonempty
  local passphrase is only a harness requirement, not verified or used to encrypt
  credentials. Production must use rosec's established passphrase-wrapped credential
  storage; this guest must not be installed as a normal user provider yet.
- Only direct vault shares and root login/note/SSH item payloads are decoded.
  Only Sync and Totp are advertised. SSH key fields can be retrieved as secrets,
  but SSH-agent enumeration and passkey operations are not implemented in this spike.
- Implement folders, all mapped item/custom field types, multiple TOTP fields,
  SSH/passkey adapters, metadata/offline cache and session refresh for first release.
- Protobuf/JSON temporary secret allocations and HTTP header copies require further
  zeroization review. Stored secret values and decryption buffers use Zeroizing.
- Sync is full and bounded, not event-cursor based. Any sync error currently clears
  the snapshot and locks. Production must distinguish outages from confirmed revocation.
- Audit HTTP response limits before allocation, request timeouts, app identification,
  session cleanup, endpoint policy, capability manifests and all host integration paths.
- Guest Cargo metadata declares only permissive dependency licences plus this GPL
  crate; no missing declarations were found. This is not a full source/notice audit
  or legal clearance for the combined host and plugin distribution.

The read-only first-release feature plan remains intact. This directory is a
feasibility checkpoint, not completion of that feature plan.
