# CLI Reference

## Provider List

```bash
rosec provider list
```

Shows all configured providers with their status:

```
ID              NAME             KIND           CAPS     STATE     LAST SYNC
─────────────────────────────────────────────────────────────────────────────
local           My Vault         local          WsKP     unlocked  never
bitwarden       Bitwarden        bitwarden-pm   SsCN     unlocked  2m ago
gnome-keyring   GNOME Keyring    gnome-keyring           unlocked
```

The **CAPS** column packs each provider's capabilities into a single token (`WsKP`, `SsCN`, etc). Decoding rules and a per-provider matrix live in the [provider capabilities reference](./providers/capabilities). The same column is shown by `rosec status`.

## Provider Validate

```bash
rosec provider validate                    # every discovered WASM plugin
rosec provider validate keepassxc-file     # one kind
rosec provider validate --wasm ./foo.wasm  # a plugin file, before installing it
```

Audits a WASM provider plugin without starting the daemon: verifies the
combined `(wasm + policy)` signature against the public key embedded in this
build, pretty-prints the plugin's declared policy (network allow-list,
filesystem preopens, required/optional options), and dry-runs template
resolution against your `rosec.toml` — so you can see the effective sandbox,
including where your `allowed_hosts` replaced or `additional_hosts` extended
the policy, *before* enabling the provider.

Exits non-zero when a signature fails or a configured provider can't resolve
the policy (e.g. a missing required option). See the
[WASM policy sidecar](./developers/wasm-policy-sidecar#tooling) page for
details and the plugin-author packaging tool (`rosec-package-wasm`).

## Search

```bash
rosec search [key=value ...] [-s|--sync] [--format=table|kv|json|human]
```

Search for items across all providers. Attribute filters are `key=value` pairs; glob patterns (`*`, `?`, `[`) in values trigger glob matching.

The `-s` / `--sync` flag syncs all providers that support `Sync` before searching. Providers without the `Sync` capability are skipped silently.

To find all items that have a TOTP seed:

```bash
rosec search rosec:totp=true
```

Items with a TOTP seed have the public attribute `rosec:totp=true` stamped automatically by the daemon. This attribute can be used as a search filter by any client that calls `SearchItems({"rosec:totp": "true"})`.

## Sync

```bash
rosec sync
```

Triggers a sync on all providers that declare the `Sync` capability. Providers without it (e.g. `local`, `gnome-keyring`) are skipped.

## TOTP

`rosec totp [get|add]` reads and stores time-based one-time passwords. Codes are also exposed via the FUSE mount at `$XDG_RUNTIME_DIR/rosec/totp/` and the `GetTotpCode` D-Bus method. Full reference: [TOTP](./totp).

## Backup & migration (export / import)

`rosec item export` writes a single item — selected by ID or a `key=value` filter — to TOML on stdout, secrets included. `rosec item import` reads that format back, into the first writable provider (or `--provider`); `--force` overwrites an item with the same attributes.

```bash
rosec item export github > github.toml     # dump one item to TOML
rosec item import --force < github.toml     # restore it (secrets included)
```

Because export includes secret values, treat the output as sensitive.
