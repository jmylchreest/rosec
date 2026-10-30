# Nix packaging checks

The root flake builds the current checkout, including all five WASM providers.
It pins nixpkgs in `flake.lock`; it does not merely build the released `pkgs.rosec`.
The package recipe follows nixpkgs' Rust/WASI packaging approach, and the VM
check reuses Mikilio's upstream `nixos/tests/rosec.nix` with our package substituted.

On Linux with Nix installed:

```sh
nix build -L .#checks.x86_64-linux.providers
nix build -L .#checks.x86_64-linux.nixos
```

The first command builds native binaries and providers, runs native Cargo tests,
executes provider discovery/manifest probing, checks package authenticity, and
rejects an identical unsigned provider copied into the user's provider directory.
The second boots a disposable NixOS VM to check D-Bus activation, the portal,
PAM configuration and login unlock. It needs KVM. The upstream PAM test is marked
broken on aarch64, so the flake exposes that VM check only on x86_64.

For a machine without Nix, use Docker or Podman. From a clean checkout (including
the new flake files):

```sh
docker run --rm -v "$PWD:/src:ro" -w /src nixos/nix:2.28.5 \
  nix --extra-experimental-features 'nix-command flakes' \
  build -L --no-link .#checks.x86_64-linux.providers
```

The Nix image disables build sandboxing by default. Container runs are useful
for reproduction; the Ubuntu CI job installs Nix with sandboxing and runs the VM
test with KVM. A source tree containing ignored sockets or large build trees
should be copied to a clean staging directory first. Never mount personal vaults
or your desktop session bus for these tests.

CI checks the locked dependency set on PRs and main. A separate scheduled/manual
job tests current nixos-unstable without updating the committed lock. Initial
builds are substantial (Wasmtime, native GUI dependencies, five WASM guests);
subsequent local builds can reuse the Nix store. No signing secrets are needed.

## Trust for source-built packages

Nix-built WASM bytes are not authenticated by upstream's release signatures.
Generating a public/shared signing key in a derivation would not authenticate
the publisher, and putting a private release key in a derivation is unsafe.

Instead, the provider derivations run first. `contrib/packaged-providers.py`
hashes their final WASM and policy bytes and records their exact install paths.
`ROSEC_PACKAGED_PROVIDERS` points to this JSON **at host compile time**. The Rust
build script embeds it in the host; there is no runtime manifest or environment
variable that can add trusted providers. The store paths are retained in the
host closure. Nix authenticates substituted packages using its own cache trust;
local builds derive trust from the selected source and build inputs.

The same mechanism is used by `contrib/aur/PKGBUILD-git`, with `/usr/lib/rosec/providers`
install paths. That package builds providers before the host. Neither recipe
requires `wasm_verify = "disabled"`. Users who previously set that workaround
should remove it to restore verification for other providers.

This trust is deliberately narrow:

- Both WASM and policy hashes must match before any WASM executes.
- A mismatch at an embedded path fails closed, even if a signature is present.
- A copy at another path receives no package trust and needs a valid signature.
- Other files in the same directory or elsewhere in `/nix/store` gain no trust.
- Policy validation, manifest-kind checks and runtime sandboxing still apply.
- Normal builds without the manifest keep the existing signature-only default.

This delegates authenticity to whoever supplies the host package. It does not
claim the source-built provider was signed by upstream, defend against an attacker
who can replace the host, or independently audit a distro's build inputs. The
validation command and daemon log identify package hashes as the trust source.

Build the host and providers together, and do not strip, rewrite or optimise a
provider or policy after hashing. Updating providers requires rebuilding the host.
For NixOS, changing the selected provider set therefore changes the host derivation.
The existing signed-release workflow and third-party signing keys remain supported.

Example for another packager:

```sh
python3 contrib/packaged-providers.py \
  --bundle build/example.wasm example.wasm.policy.toml \
    /usr/lib/rosec/providers/example.wasm > packaged-providers.json
ROSEC_PACKAGED_PROVIDERS="$PWD/packaged-providers.json" cargo build --release --locked
```

The manifest is an array of objects with `path`, `wasm_sha256`, and
`policy_sha256` (lowercase SHA-256 hex). It contains no secrets. A distributor must
generate it from the artifacts they actually intend to ship, not download it from
an untrusted provider as an additional authority.
