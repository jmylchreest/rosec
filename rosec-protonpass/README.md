# Proton Pass provider

This GPL-3.0-or-later Extism WASI guest reads Proton Pass directly through its API.
The official Proton CLI is used to provision test data and PATs, not by the guest
at runtime. The crate is standalone and ships as a separate GPL WASM provider, with matching
source and third-party notices.

**Experimental provider.** Local release checks pass, but the provider retains
its experimental status.
The
[security/performance review](SECURITY-REVIEW.md) records fixes, measurements and
operational boundaries. The [provider guide](../docs/docs/providers/protonpass.md)
explains capabilities, authentication and field mappings.

## Build and test

Run these commands from the repository root. Rust with the `wasm32-wasip1` target
and Rust 1.96 or newer for the native host are required. The fixture feature is off by default and must not be distributed.

```sh
# Production endpoint restrictions; distinct output avoids confusing test builds.
cargo build --manifest-path rosec-protonpass/Cargo.toml --locked --release \
  --target wasm32-wasip1 --target-dir rosec-protonpass/target/production

PROTONPASS_WASM=rosec-protonpass/target/production/wasm32-wasip1/release/rosec_protonpass.wasm \
  cargo run --manifest-path rosec-protonpass/Cargo.toml --locked --example probe -- --check-production

# Local synthetic HTTP fixtures only.
cargo build --manifest-path rosec-protonpass/Cargo.toml --locked --release \
  --target wasm32-wasip1 --features test-http
cargo test --manifest-path rosec-protonpass/Cargo.toml --locked
cargo test --manifest-path rosec-protonpass/Cargo.toml --locked --all-features
cargo run --manifest-path rosec-protonpass/Cargo.toml --locked --example probe
cargo run --manifest-path rosec-protonpass/Cargo.toml --locked --example probe -- --bench
cargo clippy --manifest-path rosec-protonpass/Cargo.toml --locked --all-targets -- -D warnings
cargo clippy --manifest-path rosec-protonpass/Cargo.toml --locked \
  --target wasm32-wasip1 --all-features -- -D warnings
```

The probe loads `rosec-protonpass/target/wasm32-wasip1/release/rosec_protonpass.wasm`.
Set `PROTONPASS_WASM` to override the guest path when using a separate target directory. Native tests/probes may use
`CARGO_TARGET_DIR` to reuse a host build directory. The local server requires a
loopback socket. Tests cover authenticated decryption, TOTP, mappings, malformed
authentication, failed reauthentication, rejected endpoints, duplicate IDs, page
and share limits, sync changes/deletion, revocation, locking and read-only stubs.
The benchmark uses 1,000 synthetic items across ten pages and makes no Proton calls.

## User setup

The [provider guide](../docs/docs/providers/protonpass.md#obtain-a-personal-access-token)
walks through web/CLI PAT creation, viewer vault grants, rosec registration, normal
unlock and renewal/revocation. Account credentials are only used with Proton;
rosec receives a normal PAT and a separate local passphrase.

## Isolated live development

Use only a short-lived PAT with viewer access to a dedicated synthetic vault.
The account must be eligible for official CLI/PAT use. This was verified after
an account subscription upgrade; this repository does not define Proton's plans.
Never put the PAT or account password in command arguments, config, git, logs or
shell history. Supply the PAT through the prompt or the probe's standard input.

For a daemon test, build without `test-http`; copy the resulting `.wasm` and
`rosec_protonpass.wasm.policy.toml` together into an isolated
`$XDG_DATA_HOME/rosec/providers/` directory. Give that daemon separate XDG config,
data and runtime directories and use `rosecd --socket PATH --no-migrate --config FILE`.
Point test CLI calls at that socket using `ROSEC_SOCKET`. The relevant config is:

```toml
[service]
# Only in this isolated development config, for the locally built unsigned guest.
wasm_verify = "disabled"
ssh_fuse = false
totp_fuse = false
fido2 = false

[[provider]]
id = "proton-demo"
kind = "protonpass"
offline_cache = false
```

Authenticate with `rosec provider auth proton-demo` from a terminal, then use
`rosec sync`, `rosec search`, `rosec inspect --all-attrs ID`, `rosec get ID` and
`rosec totp get --stdout ID`. `rosec get --attr NAME` reads public attributes;
use `inspect --all-attrs` for named sensitive fields.

The PAT is a secret-kind **registration** field, separate from the local passphrase.
The host stores it with Argon2id (64 MiB, three passes), a random salt, installation
key and provider binding. Subsequent unlocks need only that local passphrase;
a wrong passphrase cannot decrypt the saved PAT and does not delete it. Legacy
host credential records migrate after successful decryption. Keep the installation's
`rosec/machine-key` with its encrypted credential backups; losing either the local
passphrase or installation key requires re-registering a PAT. `rosec provider auth`
replaces the registration, so possession of a valid PAT lets you choose a new local
passphrase. It does not change the Proton account password.

Host tests cover restart, wrong-password rejection, replacement and legacy migration.
The guest itself accepts a nonempty local passphrase with an explicitly supplied PAT;
the host is responsible for local credential protection. Synthetic and isolated live tests cover these flows; see the review for evidence.

Revoke the PAT, log out of temporary CLI sessions, stop the isolated daemon and
remove its temporary data after testing. Keep signature verification enabled in
the regular daemon.

## Runtime boundaries

- Capabilities are `Sync`, `Totp`, `Ssh`, `Fido2` and `OfflineCache`; writes and
  password changes always return `not_supported`. SSH signing requires confirmation.
  Existing ES256/Ed25519 synced passkeys are supported; new passkey creation and
  nonzero signature counters are not supported by this read-only provider.
- Production requests use `https://pass-api.proton.me` only. The sidecar allows
  that hostname and no guest filesystem access. The rosec host disables redirects.
- A sync accepts at most 32 shares, 128 keys per share, 100 revisions per page,
  100 item pages per share, 10,000 active items and 32 MiB of decrypted content.
  Each encoded encrypted field is limited to 2 MiB and each item protobuf to 1 MiB.
  Responses over 8 MiB are rejected before an additional guest copy. The host
  enforces the same 8 MiB limit for Proton and a 256 MiB guest memory limit.
  Guest execution is capped at 60 seconds; callers wait at most 65 seconds. Each
  blocking HTTP operation has a 10-second maximum within that execution budget.
- Exceeding a limit rejects the entire sync. Any sync failure clears the snapshot
  and locks; the guest never presents a partially updated vault as complete.
- Rust guest allocations are wiped before free/reallocation, including parser
  failure paths and unknown protobuf fields. AES-GCM cleanup features are enabled.
  Authentication input, HTTP buffers owned by rosec and guest result memory are
  scrubbed. This does not prove erasure of upstream HTTP/TLS/parser internals,
  compiler temporaries, stack/register copies, swap or crash dumps.
- Cancellation, timeout, trap and lock invalidate pending calls and discard the
  guest instance before later work can access its state. Failed recreation stops
  the worker. A saturated queue returns `unavailable` without blocking Tokio.
- Full sync drops the old snapshot before constructing a replacement. Network
  failures report `unavailable`; permission/revocation failures report `auth_failed`.
  Both leave the provider locked. A later offline unlock may restore a valid
  host-encrypted cache; cached data is explicitly unconfirmed.
- An expired access token gets one refresh attempt; 403 permission denials do not.
  Normal lock/re-authentication attempts to revoke only this API session before
  discarding its tokens. Network failure, timeout or active-call cancellation can
  prevent remote logout; local lock still completes or invalidates the instance.
  The PAT remains registered for later unlock and is not remotely revoked by lock.
- Full sync is serial. There is no incremental event cursor or
  background notification. Revocation is detected on the next API call, not pushed.

## Licensing

The guest is GPL-3.0-or-later, including selected Proton code and unchanged generated
protobuf files. [UPSTREAM.txt](UPSTREAM.txt) records exact commits, hashes and
modifications; [LICENSE](LICENSE) contains the licence. `Cargo.lock` pins dependencies.
See [DISTRIBUTION.md](DISTRIBUTION.md) for licence review, dependency notices,
corresponding-source packaging and rebuild instructions.
