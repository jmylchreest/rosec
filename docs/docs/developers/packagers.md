---
title: Packagers
sidebar_label: Packagers
---

# Packagers

Use the same rosec source revision for the daemon, CLI, optional helpers, and WASM providers. The provider ABI is tied to the host release. Check the workspace's `rust-version` and build from the committed lockfiles. The [installation guide](../installation.md) covers build prerequisites and runtime dependencies.

## Native binaries and integration

- Ship `rosec` and `rosecd` together. Ship `rosec-prompt` for graphical credential prompts and confirmations.
- For desktop activation, use the installed daemon path in the user service and D-Bus activation files. Keep the Secret Service and portal names aligned with their service definitions. [Activation templates](https://github.com/jmylchreest/rosec/tree/main/rosec/src/enable/templates)
- For PAM, build `contrib/pam/pam_rosec.so` with the target system's PAM headers. Set the Makefile's `ROSEC_PAM_UNLOCK_PATH` to the **final installed** path of `rosec-pam-unlock`. Install the PAM module and an optional PAM configuration snippet according to your distro's conventions. [PAM installation and configuration](../pam.md)
- The optional UHID broker is a separate system component. Package its socket and service together and keep its version aligned with `rosecd`. Upgrade and restart both together because they share a broker protocol. [FIDO2 setup](../fido2-passkeys.md)
- Install shell completions and license files in your distro's standard directories. The AUR recipes show source, Git, and prebuilt layouts. [AUR recipes](https://github.com/jmylchreest/rosec/tree/main/contrib/aur)

### PAM upgrade compatibility

**Potentially breaking for split or custom packages.** PAM verifies the running daemon against a root-owned executable in a trusted installation. The helper checks `/usr/bin/rosecd` and `bin/rosecd` under its own installation prefix when the helper is itself in `bin`, `lib/rosec`, or `libexec/rosec`. This supports the AUR layout and a shared output such as `/nix/store/<output>/libexec/rosec/rosec-pam-unlock` with `/nix/store/<output>/bin/rosecd`.

When the helper and daemon live in separate prefixes, set `ROSEC_PAM_DAEMON_PATH` while building the helper. It replaces the defaults and accepts one absolute path or a comma-separated list of absolute paths. Use final paths in the installed system and keep the executable and its installation path protected from user modification.

```sh
ROSEC_PAM_DAEMON_PATH=/opt/rosec/bin/rosecd,/usr/bin/rosecd \
  cargo build --release --locked -p rosec-pam
```

`ROSEC_PAM_UNLOCK_PATH` selects the helper that the native PAM module launches. `ROSEC_PAM_DAEMON_PATH` selects which daemon executables the Rust helper trusts. If the running daemon cannot be verified, login proceeds and automatic vault unlock or password synchronization may require manual recovery.

## WASM provider packages

Build each selected provider from its crate directory with `cargo build --release --locked --target wasm32-wasip1`. Keep production builds free of fixture features such as Proton Pass's `test-http`. Keep native compiler and linker flags out of WASM builds. Install each provider's `.wasm` and matching `.wasm.policy.toml` side by side. The conventional system directory is `/usr/lib/rosec/providers`. A store-based package should declare the exact provider paths when building the host with [packaged provider trust](#source-built-providers).

### Repackaging upstream releases

Ship the released WASM, policy, and `.wasm.minisig` together. The signature covers the exact WASM and policy bytes. Verify the bundles with `rosec-package-wasm verify` against the embedded release keys before installation. Verify published archive checksums as part of package intake.

### Source-built providers

The **`rosec-git` AUR recipe uses embedded package hashes**. It builds the WASM providers first, generates a manifest from the final WASM and policy bytes and their final install paths, and builds the native host with `ROSEC_PACKAGED_PROVIDERS` pointing to that manifest.

```sh
python3 contrib/packaged-providers.py \
  --bundle build/example.wasm example.wasm.policy.toml \
  /usr/lib/rosec/providers/example.wasm > packaged-providers.json
ROSEC_PACKAGED_PROVIDERS="$PWD/packaged-providers.json" \
  cargo build --release --locked --bin rosecd --bin rosec
```

A match requires both hashes and the exact installed path. Preserve the matched bytes through packaging and rebuild the host when a provider, policy, or installation path changes. A package store can supply its exact output paths in the manifest. Keep the manifest under the packager's control. [Manifest format and source packaging examples](https://github.com/jmylchreest/rosec/blob/main/contrib/packaged-providers.md)

### Distributor-managed signing

If your host and providers need independent updates, sign your bundles with a distributor-controlled Minisign key. Build `rosec-package-wasm` from `rosec-tools` and use it to generate a keypair, sign the final bundle, and verify it with the public key. Distribute the public key through a trusted config fragment and explicitly include it in the user's configuration as `[[service.wasm_trusted_key]]`. Scope the key to the provider kinds it should sign. Protect the private key in the signing environment and keep it out of packages and derivations. [Signing commands and trust configuration](./wasm-provider-guide.md#packaging-signing-and-distribution)

For Proton Pass, include the license notices and make corresponding source available when distributing binaries. The release workflow and `contrib/package-protonpass.py` show how rosec prepares and verifies these materials. Review each provider's separate license before selecting your package set. [Release workflow](https://github.com/jmylchreest/rosec/blob/main/.github/workflows/release.yml)

## Package verification

Test a clean install with the actual packaged paths. Check that the intended daemon owns the Secret Service name, that each selected provider appears in `rosec provider list`, and that the journal identifies the expected trust source. If shipping PAM, test login unlock and password-change sync with a disposable local vault. If shipping UHID, confirm the broker and daemon start together and expose the expected per-user authenticator.
