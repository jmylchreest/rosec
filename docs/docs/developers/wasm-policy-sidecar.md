---
sidebar_position: 5
title: WASM policy sidecar
---

# WASM policy sidecar

Status: **design accepted; implementation pending** (tracked in issue #21).

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
provider-name.wasm.minisig          # signs (BLAKE3(wasm) || BLAKE3(policy))
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
```

### Signature scheme

```
sigdata = blake3(wasm_bytes) || blake3(policy_bytes) || schema_version_byte
sig     = minisign(signing_key, sigdata)
```

Substituting either file invalidates the signature. A single `.minisig`
covers both, simplifying distribution.

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
2. `verify_plugin_and_policy(wasm, policy)` computes the combined BLAKE3
   hash and verifies the minisign signature.
3. `DiscoveredPlugin` gains `policy: PluginPolicy`.
4. `compute_wasi_allowed_paths` / `compute_allowed_files` in
   `rosecd/src/main.rs` are replaced by
   `policy.resolve(&user_options) -> ResolvedPolicy`. The
   `kind == "..."` hardcoded gate is removed.
5. `WasmProviderConfig.allowed_hosts` is the effective set per the table
   above.
6. `plugin_manifest()` is downgraded to informational. It can still
   declare `attribute_descriptors`, `auth_fields`, etc., but its
   `default_allowed_hosts` field is dropped from the trust path.

### Fallback behaviour

| `wasm_verify` | sidecar present | result |
|---|---|---|
| `required` (default) | yes | verify combined signature; load with policy |
| `required` (default) | no | reject with `"plugin missing required policy file"` |
| `disabled` (dev) | yes | load with policy, signature ignored |
| `disabled` (dev) | no | load with **manifest-declared** allow-lists, `warn!` loudly — `disabled` means "trust the wasm" |

### Required and unknown options

- **Missing required option** — refuse to load with
  `"provider 'X' (kind Y) requires option 'Z' per policy"`, pointing at
  the policy file.
- **Unknown user option** — `warn!` once at startup
  (`"unknown option 'foo' for kind X, ignored"`) and continue. Lenient
  mode: typos are common; the security cost of an ignored option is zero.

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

**Hard cutover** at the next minor release (likely 0.1.0). All in-tree
providers (bitwarden-pm, bitwarden-sm, keepassxc-file, gnome-keyring)
get policy files committed in this work and re-signed. Third-party
plugins must re-issue with a sidecar to remain loadable.

The user base is small enough that the disruption cost is low and the
"soft migration with deprecation warning" path would extend the
vulnerability window for too little gain.

## Code surface

- new `rosec-wasm/src/policy.rs` (~250 lines: parse, validate, resolve
  templates, combined-signature verification)
- `rosec-wasm/src/discovery.rs`: extend `VerifyOutcome`; require sidecar
  presence under `Required` mode; add `policy: PluginPolicy` to
  `DiscoveredPlugin`
- `rosecd/src/main.rs`: replace `compute_wasi_allowed_paths` /
  `compute_allowed_files` with `policy.resolve(&user_options)`;
  compute effective `allowed_hosts` from policy + user
  `allowed_hosts` / `additional_hosts`
- `rosec-wasm/src/provider.rs`: stop reading manifest's
  `default_allowed_hosts` for trust; treat as informational
- `rosec-core/src/config.rs`: add per-provider
  `allowed_hosts: Option<Vec<String>>` and
  `additional_hosts: Vec<String>` fields
- new `rosec-tools` crate containing:
  - `rosec-package-wasm` — for plugin authors: bundle wasm + policy →
    `.minisig`, validates schema first
  - `rosec-validate-plugin` — for users: verifies signature, prints
    policy summary, dry-runs template resolution against the current
    user config. Also exposed as `rosec provider validate <kind>` for
    discoverability
- in-tree provider repos: add `*.policy.toml` files, update CI to sign
  both files together
- documentation updates in `wasm-provider-guide.md` to replace
  "WASM author declares allowed_hosts" examples with "policy sidecar"
  examples

## Threat model

**What the sidecar fixes:**

- ✅ The brittle `kind == "..."` hardcoded gates in
  `compute_wasi_allowed_paths` and `compute_allowed_files` are replaced
  with a per-plugin declarative policy file.
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
