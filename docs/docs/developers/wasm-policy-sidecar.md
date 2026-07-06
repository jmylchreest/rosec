---
sidebar_position: 5
title: WASM policy sidecar
---

# WASM policy sidecar

Status: **implemented**, including the plugin-author/user CLI tooling
(`rosec-package-wasm`, `rosec provider validate`) from
[#22](https://github.com/jmylchreest/rosec/issues/22) — see
[Tooling](#tooling) below.

## Problem

A signed WASM provider currently self-declares its sandbox policy: the host
calls the guest's `plugin_manifest()` function, reads the
`default_allowed_hosts` field, and uses that as the host network allow-list.
The host also has a small kind-string-keyed gate for filesystem preopens
(e.g. only `kind == "keepassxc-file"` triggers per-file preopens), but the
network surface is entirely guest-declared.

This means **the prisoner picks the prison's keys**. A signed `.wasm` whose
signing key is compromised — or whose author over-broadens
`default_allowed_hosts` — gets data-exfiltration paths the user never
explicitly authorised.

A second problem: `plugin_manifest()` is itself unsigned in any meaningful
sense. The signature attests the bytes of the `.wasm` file. A guest can
return any value from `plugin_manifest()` it likes, and the host believes
it as long as the byte signature checks out. There's no *separate* policy
attestation.

## Solution

Ship a signed policy sidecar `.policy.toml` alongside each `.wasm`. The
host loads policy from the sidecar, signs both files together so
substitution is detected, and stops trusting `plugin_manifest()` for
security-bearing fields.

### Trust model

The user is the security principal. The policy is the **plugin author's
claim** about what the plugin needs; the user can always extend it
(adding hosts) and may also replace it outright (narrowing). The policy
matters for two reasons:

1. **Auditability.** The user can `cat foo.wasm.policy.toml` to see what
   a plugin asks for *before* loading it. This is far better than
   reverse-engineering `plugin_manifest()` from WASM bytes.
2. **Tamper detection.** The combined signature ensures the policy text
   you read is the policy text the host enforces; substituting either
   `.wasm` or `.policy.toml` invalidates the signature.

### File layout

```
provider-name.wasm
provider-name.wasm.policy.toml
provider-name.wasm.minisig          # signs (wasm_bytes || policy_bytes)
```

All three files **must** live in the same directory. Distributions ship
them together; the user can drop a third-party plugin trio into
`$XDG_DATA_HOME/rosec/providers/` and the daemon picks it up at next
scan. There are no separate override directories — user-level
customisation goes through `rosec.toml` (see below).

### Policy schema

```toml
schema_version = 1
kind = "bitwarden-pm"
name = "Bitwarden Password Manager"
version = "1.4.0"

# Plugin-author baseline. The user's effective set is policy ∪ user.additional_hosts,
# OR user.allowed_hosts ∪ user.additional_hosts when the user replaces the policy.
[network]
allowed_hosts = ["*.bitwarden.com", "*.bitwarden.eu"]

# Path templates resolve against the user's option values at provider construction.
# Templates: $option:<key>, $home, $xdg_data_home, $xdg_config_home.
[[filesystem.preopens]]
host_template = "$home/.local/share/keyrings"
guest_path    = "/keyrings"
mode          = "ro"           # "ro" or "rw"

[[filesystem.allowed_files]]
host_template = "$option:path"
mode          = "ro"

[[filesystem.allowed_files]]
host_template = "$option:key_file"
mode          = "ro"
optional      = true           # missing option is accepted

[options]
required = ["path"]            # user MUST set these
optional = ["key_file"]        # user MAY set these

# Optional: defaults for optional options. The daemon injects these into
# the user's option map for any key the user hasn't supplied, before
# template resolution and before forwarding to the guest. Defaults may
# reference $home / $xdg_data_home / $xdg_config_home (but not $option:
# to avoid resolution cycles).
#
# Important: a host_template that references a defaulted option (e.g.
# $option:keyring_dir) will resolve to the default value, so the default
# location is auto-allowed without any special-case in the daemon.
[options.defaults]
# example — the gnome-keyring policy uses:
#   keyring_dir = "$home/.local/share/keyrings"
```

### Signature scheme

```
sigdata = wasm_bytes || policy_bytes
sig     = minisign(signing_key, sigdata)
```

The `.minisig` covers the raw concatenation of both files; minisign
hashes the input internally (BLAKE2b), so a separate pre-hash stage
buys nothing. The schema version is part of `policy_bytes` (it lives
in the TOML body), so substituting a different version invalidates
the signature without needing a separate version byte. A single
`.minisig` covers both files, simplifying distribution.

### User overrides (via `rosec.toml`)

```toml
[provider.my-bitwarden]
kind   = "bitwarden-pm"
# ... required and optional plugin options live here ...
server_url = "https://bitwarden.example.com"

# Override knobs:
#   allowed_hosts     — REPLACES policy.network.allowed_hosts
#   additional_hosts  — EXTENDS the effective set, always
#
# Effective set = (allowed_hosts ?? policy.allowed_hosts) ∪ additional_hosts.
allowed_hosts    = ["api.bitwarden.com"]    # narrows from policy
additional_hosts = ["proxy.corp.local"]      # always-extending
```

| User config | Effective `allowed_hosts` |
|---|---|
| (nothing set) | `policy.allowed_hosts` |
| `additional_hosts = [X]` | `policy.allowed_hosts ∪ {X}` |
| `allowed_hosts = [Y]` | `{Y}` (policy replaced; loud `warn!` at startup) |
| `allowed_hosts = [Y]` + `additional_hosts = [X]` | `{Y, X}` |

When the user replaces the policy via `allowed_hosts`, rosecd logs a
single `warn!` at startup so it's auditable. `additional_hosts` is
informational at `info!`.

There is no equivalent for filesystem preopens or `allowed_files` — those
follow the policy as declared. Users who don't want a plugin's filesystem
access don't enable the plugin.

### Trust flow

1. `discovery::scan_plugins` reads the sidecar `.policy.toml` and the
   sibling `.minisig`.
2. `verify_plugin` concatenates `(wasm_bytes || policy_bytes)` and asks
   minisign to verify the signature against the embedded
   `WASM_SIGNING_PUBKEY`.
3. `DiscoveredPlugin` carries `policy: PluginPolicy` (always present —
   no `Option`; both verify modes require the sidecar).
4. The kind-string gates in `rosecd/src/main.rs` are gone. Filesystem
   preopens and per-file allow-lists are produced exclusively by
   `policy.resolve(&user_options) -> ResolvedPolicy`.
5. `WasmProviderConfig.allowed_hosts` is the effective set per the table
   above (`policy.network.allowed_hosts` ∪ user overrides).
6. `plugin_manifest()` is informational only. Plugins can still declare
   `attribute_descriptors`, `auth_fields`, `id_derivation_key`, etc.,
   but `default_allowed_hosts` is no longer consulted by the host.

### Fallback behaviour

The `.policy.toml` sidecar is **always required**. `wasm_verify =
"disabled"` only bypasses the cryptographic signature check; it does
not skip the policy. There is no manifest-declared fallback path —
historic kind-string gates have been removed.

| `wasm_verify` | sidecar present | `.minisig` present | result |
|---|---|---|---|
| `required` (default) | yes | yes | verify combined signature; load with policy |
| `required` (default) | yes | no | reject (`"signature file not found"`) |
| `required` (default) | no | — | reject (`"policy file not found"`) |
| `disabled` (dev) | yes | — | load with policy, signature ignored, `warn!` loudly |
| `disabled` (dev) | no | — | reject (`"policy file not found"` — disabled skips the signature check, not the policy) |

### Required and unknown options

- **Missing required option** — refuse to load with
  `"provider 'X' (kind Y) requires option 'Z' per policy"`, pointing at
  the policy file.
- **Unknown user option** — `warn!` once at startup
  (`"unknown option 'foo' for kind X, ignored"`) and continue. Lenient
  mode: typos are common; the security cost of an ignored option is zero.
- **Optional option with a `[options.defaults]` entry** — daemon injects
  the resolved default for any key the user hasn't supplied. The default
  is then visible to both `[[filesystem.preopens]]` / `[[filesystem.allowed_files]]`
  template resolution AND to the plugin via the option map. Default
  templates may use `$home`, `$xdg_data_home`, `$xdg_config_home`;
  `$option:` refs are rejected to prevent resolution cycles.

### Schema versioning

Plugin policy ships `schema_version = N`; this rosecd understands schema
versions ≤ M.

| Policy schema | rosecd knowledge | result |
|---|---|---|
| N ≤ M | recognised | load |
| N > M | future schema | refuse to load with `"upgrade rosec to load this plugin (policy schema N, daemon supports up to M)"` |

Security policies must not be silently ignored. Hard refuse on
forward-incompatible policies; users get a clear "upgrade rosec"
message rather than a silently-relaxed sandbox.

### Migration

**Hard cutover.** All in-tree providers (bitwarden-pm, bitwarden-sm,
keepassxc-file, gnome-keyring) ship a `*.wasm.policy.toml` alongside
their `.wasm` and the combined `.minisig`. Third-party plugins must
re-issue with a sidecar to remain loadable.

The user base is small enough that the disruption cost is low and the
"soft migration with deprecation warning" path would extend the
vulnerability window for too little gain.

## Code surface (as implemented)

- `rosec-wasm/src/policy.rs` — schema, parse, schema-version refusal,
  `[options.defaults]` injection, template resolver, signature input
  builder.
- `rosec-wasm/src/discovery.rs` — sidecar mandatory in both verify
  modes; `DiscoveredPlugin.policy: PluginPolicy` (non-optional);
  `VerifyOutcome::{Verified, NotVerified, Rejected}`.
- `rosecd/src/main.rs` — `build_single_provider` runs
  `policy.apply_defaults` → `report_unknown_options` →
  `policy.resolve` to populate `WasmProviderConfig.allowed_paths` /
  `allowed_files`; computes effective `allowed_hosts` from
  policy + user `allowed_hosts` / `additional_hosts`. No kind-string
  gates remain.
- `rosec-core/src/config.rs` — per-provider
  `allowed_hosts: Option<Vec<String>>` and
  `additional_hosts: Vec<String>` fields.
- In-tree provider crates ship `*.wasm.policy.toml` files.
- `rosec-tools/` — the `rosec-package-wasm` binary (keygen, sign,
  verify); shares `PluginBundle` and the policy schema validator with
  the daemon's discovery path.
- `rosec/src/provider/validate.rs` — `rosec provider validate`, the
  user-side audit/dry-run command.
- `Justfile` `sign-wasm` recipe delegates to `rosec-package-wasm` and
  stages `dist/providers/{stem}.wasm{,.policy.toml,.minisig}` for local
  testing of the `wasm_verify = "required"` path.

## Tooling

### `rosec-package-wasm` (plugin authors)

Built from the `rosec-tools` crate (`cargo build -p rosec-tools`).
Replaces the ad-hoc rsign invocation for downstream plugin authors —
the policy schema is validated *before* anything is signed, so a typo'd
sidecar fails at packaging time rather than at every user's daemon
startup.

```console
# One-time: generate a signing keypair (use --no-password for a key
# destined for a CI secret, like 'rsign generate -W')
$ rosec-package-wasm keygen --output-dir ~/keys

# Bundle + sign: validates foo.wasm.policy.toml, signs
# (wasm_bytes || policy_bytes), emits foo.wasm.minisig
$ rosec-package-wasm sign --key ~/keys/rosec-wasm-signing.key foo.wasm

# Stage a release layout (copies .wasm + .policy.toml, signs there)
$ rosec-package-wasm sign --key ~/keys/rosec-wasm-signing.key \
    --output-dir dist/providers foo.wasm

# Check bundles (defaults to the embedded rosec release key)
$ rosec-package-wasm verify --pubkey ~/keys/rosec-wasm-signing.pub dist/providers/
```

Key rotation is the same `sign` command pointed at existing artefacts —
signing never rebuilds the `.wasm`:

```console
$ rosec-package-wasm sign --key ~/keys/new-signing.key dist/providers/
```

Non-interactive signing reads the key from the `WASM_SIGNING_KEY` env
var (the *contents* of the secret-key file, same contract as the CI
secret) and the password from `WASM_SIGNING_KEY_PASSWORD` (empty or
unset with `--no-password` for passwordless keys).

### `rosec provider validate` (users)

One command that answers "is this plugin's signature good, what does it
*claim* to need, and what will the sandbox *actually* be with my
config?":

```console
$ rosec provider validate                    # every discovered plugin
$ rosec provider validate keepassxc-file     # one kind
$ rosec provider validate --wasm ./foo.wasm  # a file, before installing it
```

For each plugin it prints:

- **signature** — verified against the embedded `WASM_SIGNING_PUBKEY`
  (with a note when `wasm_verify = "disabled"` means the daemon would
  load it anyway);
- **the policy claim** — `allowed_hosts`, preopens, `allowed_files`,
  required/optional options and defaults, as signed by the author;
- **a dry-run per configured provider** — templates resolved against
  the options in your `rosec.toml` (so `$option:...`/`$home` become real
  paths), the effective `allowed_hosts` with per-host provenance, and
  the same replace/extend/unknown-option warnings rosecd logs at
  startup. The computation is shared with the daemon
  (`rosec_wasm::policy::effective_allowed_hosts`), not re-implemented.

Exit status is non-zero when a signature fails or a configured provider
can't resolve the policy (e.g. missing required options), so it can
gate scripts.

## Threat model

**What the sidecar fixes:**

- ✅ The brittle `kind == "..."` hardcoded gates that previously lived
  in `rosecd/src/main.rs` for filesystem preopens and per-file
  scoping are gone — replaced entirely by `policy.resolve()`.
- ✅ `plugin_manifest()` self-declared `default_allowed_hosts` is no
  longer trusted.
- ✅ Substitution of `.wasm` or `.policy.toml` without re-signing is
  detected by the combined signature.
- ✅ Users can audit a plugin's claimed needs by reading the policy file
  before loading it — no need to reverse-engineer WASM bytes.

**What the sidecar does NOT fix:**

- ❌ A compromised signing key with full intent — the attacker can ship
  a policy with `allowed_hosts = ["*"]` and the host enforces it. The
  user can read the policy and refuse, but if they don't, it's
  accepted. This is the irreducible trust root.
- ❌ Plugin authors maliciously over-broadening their own policy — same
  as above.
- ❌ Bugs in the host's enforcement (e.g. `host_http` redirect handling).
  The policy is the host's *input*, not its enforcement.
- ❌ Provider-side data exfiltration via legitimate channels (e.g. a
  bitwarden provider sending data to `bitwarden.com` itself).

The user's superset model (extend always, optionally replace) gives up
"user can always lock down further than the policy" in exchange for
**simpler mental model** and **operational flexibility** (you can add a
proxy host or work around a domain change without re-issuing a plugin).
This is a deliberate trade-off — see issue #21 discussion.
