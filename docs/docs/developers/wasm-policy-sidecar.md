---
sidebar_position: 5
title: WASM policy sidecar (proposal)
---

# WASM policy sidecar — design proposal

Status: **proposal — not implemented**.

## Problem

A signed WASM provider currently self-declares its sandbox policy: the host
calls the guest's `plugin_manifest()` function, reads the
`default_allowed_hosts` field, and uses that as the host network allow-list.
The host also has a small kind-string-keyed gate for filesystem preopens
(e.g. only `kind == "keepassxc-file"` triggers per-file preopens), but the
network surface is entirely guest-declared.

This means **the prisoner picks the prison's keys**. A signed `.wasm` whose
signing key is compromised — or whose author over-broadens
`default_allowed_hosts` — gets data exfiltration paths the user never
explicitly authorised. The mitigation today is "trust the WASM author",
which is exactly the trust we want to *avoid* when sandboxing.

A second problem: `plugin_manifest()` is itself unsigned in any meaningful
sense. The signature attests the bytes of the `.wasm` file. A guest can
return any value from `plugin_manifest()` it likes, and the host believes
it as long as the byte signature checks out. There's no *separate* policy
attestation.

## Proposed solution

Ship a signed policy sidecar `.policy.toml` next to each `.wasm`. The
host loads policy from the sidecar, treats `plugin_manifest()` as
informational only for security-bearing fields, and signs both files
together so substitution is detected.

### File layout

```
provider-name.wasm
provider-name.wasm.policy.toml
provider-name.wasm.minisig          # signs (BLAKE3(wasm) || BLAKE3(policy))
```

### Policy schema

```toml
schema_version = 1
kind = "bitwarden-pm"
name = "Bitwarden Password Manager"
version = "1.4.0"

# Host-enforced ceiling. Manifest's default_allowed_hosts becomes a hint only.
[network]
allowed_hosts = ["*.bitwarden.com", "*.bitwarden.eu"]

# Path templates resolve against the user's option values at provider construction.
# Templates: $option:<key>, $home, $xdg_data_home, $xdg_config_home.
# Templates that resolve outside an allow-listed prefix are rejected.
[[filesystem.preopens]]
host_template = "$home/.local/share/keyrings"
guest_path = "/keyrings"
mode = "ro"          # "ro" or "rw"

[[filesystem.allowed_files]]
host_template = "$option:path"
mode = "ro"

[[filesystem.allowed_files]]
host_template = "$option:key_file"
mode = "ro"
optional = true      # missing option is accepted

[options]
required = ["path"]
optional = ["key_file"]
```

### Signature scheme

```
sigdata = blake3(wasm_bytes) || blake3(policy_bytes) || schema_version_byte
sig     = minisign(signing_key, sigdata)
```

Substituting either file invalidates the signature. A single `.minisig`
covers both, simplifying distribution.

### Trust flow

1. `discovery::scan_plugins` reads `.policy.toml` first, falling back per
   the rules below.
2. `verify_plugin_and_policy(wasm_path, policy_path)` computes the combined
   hash and verifies the minisign signature.
3. `DiscoveredPlugin` gains `policy: PluginPolicy`.
4. `compute_wasi_allowed_paths` / `compute_allowed_files` in
   `rosecd/src/main.rs` are replaced by `policy.resolve(&user_options) ->
   ResolvedPolicy`. The `kind == "..."` hardcoded gate goes away.
5. `WasmProviderConfig.allowed_hosts` becomes the **intersection** of
   `policy.network.allowed_hosts` and any `allowed_hosts` the user set in
   their config. Users can narrow but not widen.
6. `plugin_manifest()` is downgraded to informational. It can still
   declare `attribute_descriptors`, `auth_fields`, etc., but the
   `default_allowed_hosts` field is dropped from the trust path (kept for
   one cycle as a deprecation log).

### Fallback behaviour

| `wasm_verify` | `.policy.toml` present | result |
|---|---|---|
| `required` (default) | yes | verify signature; load with policy |
| `required` (default) | no | **reject** with "plugin missing required policy file" |
| `disabled` (dev) | yes | load with policy, signature ignored |
| `disabled` (dev) | no | load with **empty** allow-lists (no network, no FS); guest fails at first `host_*` call with a clear error |

## Open questions

These need agreement before implementation:

### 1. User overrides — full mental model

The audit prompt that triggered this proposal asked specifically about
how user config overrides interact with the policy. The current sketch
says "user can narrow but not widen" `allowed_hosts`, but several edge
cases need decisions:

- **Filesystem preopens.** Can the user add a `[[filesystem.preopens]]`
  entry beyond the policy? Probably no — that's widening, same logic as
  network. But what about reducing? A user might want to deny the
  `keyring_dir` preopen for a provider they don't actually use.
- **Filesystem allowed_files.** The policy says
  `host_template = "$option:path"`. The user supplies the option `path`.
  If the user sets `path = "/etc/shadow"`, the policy template resolves
  to `/etc/shadow` and the provider gets read access. Is that the user's
  prerogative (they chose the path) or a footgun (the provider was meant
  for `*.kdbx`)? Probably we need a `host_template_must_match = "*.kdbx"`
  refinement.
- **Network override via local proxy.** A user might want all
  `*.bitwarden.com` traffic to go via a corporate proxy on
  `proxy.corp.local`. That's *adding* a host (proxy) but logically
  narrowing the ultimate destination. How is this expressed?
- **Required options policy.** If policy says
  `required = ["path"]` but the user omits `path` from their config,
  what happens? Probably refuse-to-load with a clear error pointing at
  the policy file. Symmetric for unknown options the user supplies that
  the policy doesn't list.
- **Schema upgrades.** When policy `schema_version = 2` ships with a new
  field, how does an older `rosecd` (still on schema 1) treat it? Reject
  the plugin? Ignore unknown fields with a warning? Fail loudly to
  prompt upgrade? (Probably: fail loudly. Security policies must not be
  silently ignored.)

### 2. Migration path

Existing signed WASM plugins (no policy sidecar yet) must continue to
load somehow during the transition. Options:

- **Hard cutover.** Set a release boundary: rosecd 0.1.0 requires policy
  sidecars universally. All providers re-issued.
- **Soft migration.** rosecd 0.0.x trusts `plugin_manifest()` if no
  sidecar is present, with a `warn!` log on every load. Drop the trust
  in 0.1.0.
- **Per-plugin grandfather list.** Hard-coded `kind` allow-list of
  legacy providers that still trust the manifest. Removed in 0.1.0.

Soft migration is friendliest but extends the vulnerability window.
Hard cutover is cleaner but requires re-signing every provider.

### 3. Policy authoring tooling

A `tools/rosec-package-wasm` CLI is needed:

```
rosec-package-wasm \
  --wasm bitwarden-pm.wasm \
  --policy bitwarden-pm.policy.toml \
  --signing-key /path/to/minisign.key \
  --output-sig bitwarden-pm.wasm.minisig
```

Validates the policy schema, computes the combined hash, signs.

A `rosec-validate-plugin` command for users:

```
rosec-validate-plugin /usr/lib/rosec/providers/bitwarden-pm.wasm
# Verifies signature, prints policy summary, checks template resolution
# against the current user config.
```

### 4. Default-deny vs explicit-deny

The current sketch says missing-policy in `wasm_verify=disabled` mode →
"empty allow-lists". An alternative: missing-policy → refuse to load
even in dev mode, requiring `wasm_verify = "disabled-and-trust-manifest"`
as an explicit fourth option. More steps but harder to misuse.

## Code surface

- new `rosec-wasm/src/policy.rs` (~250 lines: parse, validate, resolve
  templates, signature verification helper)
- `discovery.rs`: extend `VerifyOutcome` and `verify_plugin`; add
  `policy: PluginPolicy` to `DiscoveredPlugin`
- `rosecd/src/main.rs`: replace `compute_wasi_allowed_paths` /
  `compute_allowed_files` with `policy.resolve(&user_options)`;
  intersect `allowed_hosts`
- `rosec-wasm/src/provider.rs`: stop reading manifest's
  `default_allowed_hosts` for trust; treat as informational
- new `tools/rosec-package-wasm` (~80 lines) for plugin authors
- new `tools/rosec-validate-plugin` (~60 lines) for users
- documentation: replace "WASM author declares allowed_hosts" examples
  with "policy sidecar" examples in `wasm-provider-guide.md`

## Threat model — what this fixes vs. doesn't

**Fixes:**
- Compromised signing key still requires re-signing both files; if the
  attacker only obtained the WASM signing capability and not the
  policy, they cannot widen the network allow-list.
- A bug or oversight in `plugin_manifest()` returning over-broad
  `default_allowed_hosts` no longer affects trust.
- The brittle `kind == "keepassxc-file"` hardcoded gate in
  `compute_wasi_allowed_paths` becomes an explicit policy declaration
  per-plugin.

**Does not fix:**
- A compromised signing key with full access to both wasm and policy
  files — the attacker can sign anything they want. That's the
  irreducible trust root.
- Bugs in the host's network enforcement (`host_http`, redirect
  following). The policy is the host's input, not the host's
  enforcement code.
- Provider-side data exfiltration via legitimate channels (e.g. a
  bitwarden provider exfiltrating to bitwarden.com itself).
