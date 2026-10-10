# Proton Pass provider spike

This GPL-3.0-or-later Extism WASI guest reads Proton Pass directly through its API.
The official Proton CLI is used to provision test data and PATs, not by the guest
at runtime. The crate is standalone and is not part of release packaging.

**Status: experimental and not approved for production.** The
[security/performance review](SECURITY-REVIEW.md) records fixes, measurements and
remaining release blockers. The [provider guide](../docs/docs/providers/protonpass.md)
explains capabilities, authentication and field mappings.

## Build and test

Run these commands from the repository root. Rust with the `wasm32-wasip1` target
is required. The fixture feature is off by default and must not be distributed.

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
Do not override the fixture guest's target directory. Native tests/probes may use
`CARGO_TARGET_DIR` to reuse a host build directory. The local server requires a
loopback socket. Tests cover authenticated decryption, TOTP, mappings, malformed
authentication, failed reauthentication, rejected endpoints, duplicate IDs, page
and share limits, sync changes/deletion, revocation, locking and read-only stubs.
The benchmark uses 1,000 synthetic items across ten pages and makes no Proton calls.

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
use `inspect --all-attrs` for named sensitive fields. The PAT is a secret-kind
additional auth field; the local password remains a separate prompt field.

The guest only requires a nonempty local passphrase. It does not independently
validate that passphrase. The host can wrap registration credentials, but this
provider's restart, wrong-password, rotation and recovery behavior is not yet
validated. Do not deploy it as a normal credential store on that basis.

Revoke the PAT, log out of temporary CLI sessions, stop the isolated daemon and
remove its temporary data after testing. Keep signature verification enabled in
the regular daemon. The [earlier live transcript](LIVE-DEMO.txt) records successful
reads of all eight CLI-created native types; it predates this hardening pass.
This pass used synthetic fixtures and did not access the user's Proton account.

## Runtime boundaries

- Capabilities are `Sync` and `Totp`; writes and password changes always return
  `not_supported`. SSH keys are readable attributes, not agent/signing support.
- Production requests use `https://pass-api.proton.me` only. The sidecar allows
  that hostname and no guest filesystem access. The rosec host disables redirects.
- A sync accepts at most 32 shares, 128 keys per share, 100 revisions per page,
  100 item pages per share, 10,000 active items and 32 MiB of decrypted content.
  Each encoded encrypted field is limited to 2 MiB and each item protobuf to 1 MiB.
  Responses over 8 MiB are rejected before an additional guest copy. The host
  has its own 50 MiB HTTP limit and 256 MiB guest memory limit.
- Exceeding a limit rejects the entire sync. Any sync failure clears the snapshot
  and locks; the guest never presents a partially updated vault as complete.
- Stored secrets, parsed session JSON and known protobuf secret fields are scrubbed
  on drop. HTTP response memory is scrubbed before release. Parser failure paths,
  generated unknown fields and host/PDK serialization copies still need review.
- Full sync is serial. It fetches keys and all item pages each time; there is no
  event cursor, refresh-token lifecycle, offline cache or background notification.

## Licensing

The guest is GPL-3.0-or-later, including selected Proton code and unchanged generated
protobuf files. [UPSTREAM.txt](UPSTREAM.txt) records exact commits, hashes and
modifications; [LICENSE](LICENSE) contains the licence. `Cargo.lock` pins dependencies.
A combined host/plugin distribution and corresponding-source/notice review remains
required. This spike does not establish that WASM creates a legal licence boundary.
