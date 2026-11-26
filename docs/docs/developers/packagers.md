---
title: Packagers
sidebar_label: Packagers
---

# Packagers

Most distributions start with `rosec` and `rosecd`, then decide which providers and desktop integrations to offer. `rosec-prompt` adds graphical prompts. PAM auto-unlock and the FIDO2 broker are optional and have their own system integration. The native components and WASM providers are built from the same source revision because the provider ABI follows the host release. The workspace's `rust-version` and committed lockfiles are the starting point for a reproducible build. [Build prerequisites and runtime dependencies](../installation.md)

The CLI's `rosec enable` command can generate the user service, D-Bus activation files, and portal registration. A package can ship its own versions of those files with the installed daemon path filled in. The AUR recipes are working examples of how the binaries, activation files, shell completions, and licenses fit together. The optional UHID package ships its own system socket and service. It shares a protocol with `rosecd`, so a package upgrade needs to restart both together. [Activation templates](https://github.com/jmylchreest/rosec/tree/main/rosec/src/enable/templates) · [AUR recipes](https://github.com/jmylchreest/rosec/tree/main/contrib/aur) · [FIDO2 setup](../fido2-passkeys.md)

## PAM and custom install paths

For a conventional package, the PAM module is built against the distro's PAM headers and installed in its PAM module directory. The module starts the helper at the path configured by its Makefile's `ROSEC_PAM_UNLOCK_PATH`. The helper in turn verifies that the running daemon matches an executable from a trusted system installation. `rosecd` still runs as the signed-in user. [PAM setup](../pam.md)

**An upgrade can affect packages that split the helper and daemon across prefixes.** The helper looks for `/usr/bin/rosecd` and for `bin/rosecd` in its own installation prefix. For example, the community Nix package puts the helper in `libexec/rosec` and the daemon in `bin` under the same store output. Both paths resolve without a packaging override. Helpers under `bin` or `lib/rosec` are also supported.

If your layout puts the daemon elsewhere, `ROSEC_PAM_DAEMON_PATH` is the build-time override for the Rust helper. It replaces the default list. For example, a package that supports two daemon locations can build the helper with:

```sh
ROSEC_PAM_DAEMON_PATH=/opt/rosec/bin/rosecd,/usr/bin/rosecd \
  cargo build --release --locked -p rosec-pam
```

These paths refer to the installed system, outside the staging directory. An entry beginning with `@ORIGIN@/` is resolved from the directory containing the installed PAM helper. Only a root-owned daemon in a trusted installation qualifies. If the helper cannot verify it, OS login continues. The user can unlock the vault manually and may need to update its unlock password separately.

## How provider packages establish trust

A provider ships as a WASM file and its matching policy sidecar. The usual system location is `/usr/lib/rosec/providers`. If you build providers yourself, each has its own locked Cargo build for `wasm32-wasip1`. For example, the Git AUR recipe clears native compiler and linker flags for those builds and leaves fixture features such as Proton Pass's `test-http` off. [WASM policy format](./wasm-policy-sidecar.md)

**Repackaging an upstream release.** The release bundles already contain a Minisign signature covering the exact WASM and policy bytes. The archive checksums help verify downloads, and `rosec-package-wasm verify` checks the bundles against rosec's embedded release keys. The three bundle files travel together into the package.

**Building the host and providers together.** This is how `rosec-git` works. It builds the providers first, then records the SHA-256 hashes of each WASM file and policy alongside the final install path. `ROSEC_PACKAGED_PROVIDERS` tells the host build where to find that manifest. The host can then trust those exact packages without a distributor signing key. A package store can use its output paths in the same way.

```sh
python3 contrib/packaged-providers.py \
  --bundle build/example.wasm example.wasm.policy.toml \
  /usr/lib/rosec/providers/example.wasm > packaged-providers.json
ROSEC_PACKAGED_PROVIDERS="$PWD/packaged-providers.json" \
  cargo build --release --locked --bin rosecd --bin rosec
```

The manifest describes the final bytes after any packaging transformations. A provider rebuilt with different bytes, or moved to a different path, needs a corresponding host rebuild to use this trust mechanism. [Manifest format and more examples](https://github.com/jmylchreest/rosec/blob/main/contrib/packaged-providers.md)

**Shipping independently updated provider packages.** A distributor-managed Minisign key lets you sign each provider release separately. The `rosec-package-wasm` tool generates keys and signs and verifies bundles. The private key stays in the signing environment. The public key goes in a config fragment that the user explicitly includes under `[[service.wasm_trusted_key]]`, optionally scoped to the provider kinds it signs. [Signing commands and trust configuration](./wasm-provider-guide.md#packaging-signing-and-distribution)

Provider licenses can differ from the host's. For Proton Pass, the release workflow uses `contrib/package-protonpass.py` to prepare notices and corresponding source for binary distribution and checks that the source rebuilds offline. [Release workflow](https://github.com/jmylchreest/rosec/blob/main/.github/workflows/release.yml)

## Trying the finished package

A clean install catches the issues that a build tree can hide. Once the desktop session starts, `rosec provider list` should show the providers you shipped, and the journal should identify the expected trust source. A disposable vault lets you try both PAM login unlock and password-change sync using the package's actual paths. If you ship UHID, start the packaged broker and daemon together and check that the per-user authenticator appears.
