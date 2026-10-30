# Trust for source-built packages

Locally built WASM bytes are not authenticated by upstream's release signatures.
Generating a public/shared signing key in a derivation would not authenticate
the publisher, and putting a private release key in a derivation is unsafe.

Instead, build the providers first. `contrib/packaged-providers.py`
hashes their final WASM and policy bytes and records their exact install paths.
`ROSEC_PACKAGED_PROVIDERS` points to this JSON **at host compile time**. The Rust
build script embeds it in the host; there is no runtime manifest or environment
variable that can add trusted providers. The store paths are retained in the
host closure. Nix authenticates substituted packages using its own cache trust;
local builds derive trust from the selected source and build inputs.

The `contrib/aur/PKGBUILD-git` recipe uses this mechanism with
`/usr/lib/rosec/providers` install paths. It builds providers before the host
and does not require `wasm_verify = "disabled"`. Users who previously set that workaround
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
