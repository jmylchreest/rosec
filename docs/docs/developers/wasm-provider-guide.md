---
sidebar_position: 1
---

# WASM Provider Guide

This guide is for **plugin authors** writing a new WASM-based rosec provider, or anyone curious about the boundary between the daemon and its sandboxed plugins. End-users setting up an existing provider should look in [Providers](../providers/capabilities) instead.

The contract below is what `rosec-wasm` (the host) expects of your `*.wasm` guest. Three reference implementations exist in the rosec repo (`rosec-bitwarden-pm`, `rosec-gnome-keyring`, `rosec-keepassxc-file`); skim them alongside this doc.

## Architecture overview

```
rosec-wasm (host)                     your-plugin.wasm (guest)
 WasmProvider                          #[plugin_fn] exports
  |                                      |
  |-- Plugin::call("func", json) ------->|  guest function runs
  |<-- json bytes / error ---------------|
  |                                      |
  |  readiness probes (native HTTP/TCP)  |  (not involved)
  |  plugin recreation after traps       |  (not involved)
```

The host manages the Extism `Plugin` instance.  Guest functions receive JSON
input and return JSON output through Extism byte buffers.  The guest runs on
`wasm32-wasip1` with Extism PDK.

## Guest function catalogue

| Function               | Input                  | Output                       | External I/O? | Readiness-gated? |
|------------------------|------------------------|------------------------------|---------------|------------------|
| `plugin_manifest`      | *(empty)*              | `PluginManifest`             | No            | No               |
| `init`                 | `InitRequest`          | `InitResponse`               | No            | No               |
| `status`               | *(empty)*              | `StatusResponse`             | No            | No               |
| `unlock`               | `UnlockRequest`        | `SimpleResponse`             | **Yes** [1]   | **Yes**          |
| `lock`                 | *(empty)*              | `SimpleResponse`             | No            | No               |
| `sync`                 | *(empty)*              | `SimpleResponse`             | **Yes**       | **Yes**          |
| `list_items`           | *(empty)*              | `ItemListResponse`           | No            | No               |
| `search`               | `SearchRequest`        | `ItemListResponse`           | No            | No               |
| `get_item_attributes`  | `ItemIdRequest`        | `ItemAttributesResponse`     | No            | No               |
| `get_secret_attr`      | `SecretAttrRequest`    | `SecretAttrResponse`         | No            | No               |
| `list_ssh_keys`        | *(empty)*              | `SshKeyListResponse`         | No            | No               |
| `get_ssh_private_key`  | `SshPrivateKeyRequest` | `SshPrivateKeyResponse`      | No            | No               |
| `check_remote_changed` | `CheckRemoteChangedRequest` | `CheckRemoteChangedResponse` | **Yes**  | **Yes**          |
| `readiness_probes`     | *(empty)*              | `ReadinessProbesResponse`    | No            | No               |
| `registration_info`    | *(empty)*              | `RegistrationInfoResponse`   | No            | No               |
| `auth_fields`          | *(empty)*              | `AuthFieldsResponse`         | No            | No               |
| `attribute_descriptors`| *(empty)*              | `AttributeDescriptorsResponse` | No          | No               |
| `capabilities`         | *(empty)*              | `CapabilitiesResponse`       | No            | No               |
| `export_cache`         | *(empty)*              | `ExportCacheResponse`        | No            | No               |
| `restore_cache`        | `RestoreCacheRequest`  | `SimpleResponse`             | No            | No               |
| `get_notification_config` | *(empty)*           | `NotificationConfigResponse` | **Yes**      | No               |
| `parse_notification`   | `NotificationFrame`    | `NotificationAction`         | No            | No               |

[1] "External I/O" means network calls (HTTP via Extism PDK) *or* file reads
that may block (e.g. gnome-keyring reads `.keyring` files from WASI during
unlock).  The readiness gate protects against both: HTTP probes catch network
outages, TCP probes catch unreachable file servers.

### Call categories

**Metadata (called once during construction, results cached):**
`plugin_manifest`, `init`, `capabilities`, `attribute_descriptors`,
`auth_fields`, `registration_info`, `readiness_probes`.
These run on a fresh plugin before any user interaction.  They must not
perform network I/O.

**Network-facing (readiness-gated):**
`unlock`, `sync`, `check_remote_changed`.
The host evaluates readiness probes *before* calling these.  If probes fail,
the host backs off with exponential delay (500ms initial, 30s cap, 8 attempts)
and returns `ProviderError::Unavailable` without calling the guest.

**Data-access (operate on cached state, not gated):**
`status`, `list_items`, `search`, `get_item_attributes`, `get_secret_attr`,
`list_ssh_keys`, `get_ssh_private_key`.
These read from in-memory state populated by `unlock`/`sync`.  They must not
make network calls or perform file I/O.  If the plugin was recreated after a
trap, the guest is in a locked state and should return an application-level
error (`ok: false`, `error_kind: Locked`).

**Cache (state serialization, not gated):**
`export_cache`, `restore_cache`.
These serialize/deserialize the guest's in-memory state for offline caching.
See the "Offline cache" section below for the full contract.

**Important:** some providers read files during `unlock` (e.g.
`rosec-gnome-keyring` reads `.keyring` files from disk as part of its unlock
flow).  File I/O in `unlock` is acceptable -- it's a network-gated function.
But data-access functions called *after* unlock must operate on the in-memory
cache built during unlock, not re-read files on every call.

**Teardown (never gated, never triggers recreation):**
`lock`.
Must always succeed quickly.  Should not make network calls.

## Error handling rules

### The cardinal rule: never panic in production paths

The `#[plugin_fn]` macro does **not** catch panics.  A panic in guest code
becomes a WASM `unreachable` trap that corrupts the plugin's internal state
(linear memory, globals, mutex guards).  The host will detect this and
recreate the plugin, but the current call fails and any unlocked vault state
is lost.

**Concrete rules:**

1. **Never use `.unwrap()` or `.expect()` on fallible operations.**
   Use `?` with proper error conversion, or return an error response.

2. **Always return application errors as `Ok(Json(Response { ok: false, ... }))`.**
   The host protocol distinguishes:
   - `Ok(Json(...))` with `ok: false` = application error (wrong password,
     not found, locked, etc.).  No trap, no recreation.
   - `Err` from `plugin.call()` = WASM-level failure.  Triggers plugin
     recreation.

3. **Handle all I/O errors explicitly.**
   File I/O through WASI returns `errno` codes that Rust's `std::fs` wraps
   in `io::Error`.  These are *not* traps.  But if you `.unwrap()` them,
   the panic *becomes* a trap.

### What causes traps (non-exhaustive)

| Source | Examples | Guest can prevent? |
|--------|----------|--------------------|
| Guest panic | `.unwrap()` on `None`/`Err`, array OOB, explicit `panic!()` | **Yes** |
| HTTP host function | DNS failure, TLS error, URL parse error, response too large | Partially (readiness probes prevent most) |
| Timeout | Extism epoch interrupt (60s default) | Avoid long computations |
| OOM | WASM linear memory exhausted | Avoid unbounded allocations |
| Variable store | `var_set` when store is full | Check capacity |

**Traps from HTTP are the most common cause of corruption in practice.**
The Extism PDK's `http::request()` calls an Extism host function that uses
`ureq`.  Any non-HTTP-status error (DNS, TLS, connection refused, timeout)
causes the host function to `bail!()`, which becomes a WASM trap.  The guest
never gets a chance to handle the error.

This is why readiness probes exist: they let the host check connectivity
*before* calling guest functions that would trigger HTTP.

## Readiness probes

### Purpose

Readiness probes are declarative connectivity checks that the host evaluates
natively (no WASM execution) before calling network-facing guest functions.
They prevent WASM traps caused by network unavailability (e.g. after
laptop resume from sleep before WiFi reconnects).

### How to declare them

Export a `readiness_probes` function that returns `ReadinessProbesResponse`:

```rust
#[plugin_fn]
pub fn readiness_probes(_input: ()) -> FnResult<Json<ReadinessProbesResponse>> {
    let guard = STATE.lock();
    let Some(state) = guard.as_ref() else {
        return Ok(Json(ReadinessProbesResponse { probes: vec![] }));
    };

    let url = format!(
        "{}/.well-known/openid-configuration",
        state.config.urls.identity_url
    );

    Ok(Json(ReadinessProbesResponse {
        probes: vec![ReadinessProbe::Http {
            url,
            method: "HEAD".to_string(),
            expected_status: 200,
            timeout_secs: 5,
        }],
    }))
}
```

### Probe types

```rust
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReadinessProbe {
    Http {
        url: String,
        method: String,          // default: "HEAD"
        expected_status: u16,    // default: 200
        timeout_secs: u32,       // default: 5
    },
    Tcp {
        host: String,
        port: u16,
        timeout_secs: u32,       // default: 5
    },
}
```

### When to declare probes

- **Your plugin makes HTTP calls** (most providers): declare an HTTP probe
  for the primary API endpoint.  Choose a lightweight health-check URL
  (e.g. `/.well-known/openid-configuration`, `/alive`, `/health`).

- **Your plugin accesses network-backed filesystems** (NFS, CIFS, FUSE):
  declare a TCP probe for the file server's host:port.  This catches
  "server unreachable" before a WASI `read()`/`write()` call hangs.

- **Your plugin only accesses local files on a guaranteed-local filesystem**:
  no probes needed.  WASI file errors return `errno` codes, not traps.

- **Your plugin accesses local files that *might* be on a network mount**:
  consider a TCP probe.  For example, `rosec-gnome-keyring` reads
  `~/.local/share/keyrings/*.keyring` via WASI.  On a typical desktop this
  is local ext4/btrfs and needs no probe.  But in enterprise environments
  the home directory may live on NFS/CIFS -- in that case, the file read
  during `unlock` would hang indefinitely if the server is unreachable
  (see "Network-backed filesystems" below).

### Security constraint

Probe targets are validated against the host's effective
`allowed_hosts` list (sourced from the policy sidecar's
`[network].allowed_hosts`, optionally extended or replaced by the user
via `rosec.toml`) using the same glob matching Extism uses. A probe
whose hostname doesn't match is rejected at evaluation time. This
prevents a malicious guest from probing arbitrary internal hosts. See
[WASM policy sidecar](./wasm-policy-sidecar.md) for how the
allow-list is sourced.

**Glob wildcard semantics:** The `glob` crate's `*` matches `.` characters,
so `*.example.com` is a _deep_ wildcard — it matches `foo.example.com`
**and** `foo.bar.example.com`.  Use exact hostnames where possible (e.g.
`vault.bitwarden.com`) and only use wildcards when the provider genuinely
needs to reach variable subdomains (e.g. self-hosted instances).  The host
performs an exact `glob::Pattern::matches()` check against the probe URL's
hostname.

## File I/O considerations

### WASI file access

Guest plugins access the filesystem through WASI, mediated by Extism's
`allowed_paths` manifest configuration.  Each allowed path maps a host
directory to a guest path.

**Error behaviour:**
- Permission denied, disk full, file not found: WASI returns an `errno`.
  The guest's Rust `std::fs` wraps this in `io::Error`.  **Not a trap.**
- Path outside `allowed_paths`: WASI returns `ENOTCAPABLE` or similar.
  **Not a trap.**

**The danger is `.unwrap()` on I/O errors, not the I/O errors themselves.**

### Network-backed filesystems (NFS, CIFS, FUSE)

If a guest accesses files on a network-backed mount via `allowed_paths`,
the failure mode is different from both HTTP errors and local file errors:

1. **Server unreachable**: the WASI `read()`/`write()` syscall blocks in
   host kernel code.  Extism's epoch-based timeout fires at WASM instruction
   boundaries, **but a blocked WASI syscall is executing host code, not WASM
   instructions**.  This means a hung NFS mount can block the plugin thread
   **indefinitely**, bypassing the timeout mechanism entirely.

2. **Server returns an error**: the kernel returns `EIO`, `ESTALE`, or
   similar.  WASI translates this to an `errno`.  The guest sees a normal
   `Err(io::Error)`.  **Not a trap** -- but only if the guest handles the
   error instead of panicking.

3. **Mitigation**: declare a TCP probe for the file server.  This catches
   "server completely down" before the guest attempts file I/O.  It does
   not protect against partial hangs (server accepts TCP connections but
   stalls on NFS read).

4. **Best practice**: if your provider needs network file access, consider
   using Extism's HTTP host function instead (which has the timeout) and
   have the host expose the file contents through a custom mechanism, rather
   than relying on WASI file I/O to a network mount.

**Example -- gnome-keyring on NFS home:**

The `rosec-gnome-keyring` plugin reads `~/.local/share/keyrings/*.keyring`
during `unlock` via `std::fs::read()`.  On a local filesystem this is fast
and reliable.  But if the home directory is NFS-mounted (common in
enterprise/university environments), resuming from sleep with the NFS
server unreachable would cause the `read()` to block the plugin thread
until the mount times out (which can be minutes with default NFS settings
like `timeo=600,retrans=2`).

The gnome-keyring plugin correctly handles `Err` from `std::fs::read()` --
it continues to the next keyring file and reports the error.  So if the
kernel eventually returns `EIO`/`ETIMEDOUT`, the plugin recovers.  But the
blocking period itself is uninterruptible by Extism.

For deployments on network mounts, a TCP probe for the file server (port
2049 for NFSv4, port 445 for CIFS) would prevent the blocking entirely by
failing fast at the readiness check stage.

### Path-scoped host imports (`host_file`, `host_watch`)

WASI's pre-open mechanism is directory-scoped, which is too broad for
providers that need a single user-configured file (e.g. a `.kdbx` database).
Two host imports give per-file scoping instead, registered in the
`extism:host/user` namespace:

| Import           | Args                | Returns                        | Purpose |
|------------------|---------------------|--------------------------------|---------|
| `file_read`      | `path: string`      | `bytes`                        | Read the entire file. Path must be in the per-provider allow-list. |
| `file_stat`      | `path: string`      | `{ mtime_secs, size }` JSON    | Stat without reading. Used for cheap mtime-poll cache invalidation. |
| `register_watch` | `path: string`      | `()`                           | Subscribe to inotify-style change events. Path must be in the same allow-list. |

The host populates the allow-list from the provider's config (e.g.
`path = "..."` and `key_file = "..."` for `keepassxc-file`); paths are
canonicalised, so symlinks and `..` traversal can't escape.

`register_watch` is asynchronous: the host runs a `notify::RecommendedWatcher`
per provider and dispatches change events back to the guest by calling its
`on_path_changed(WatchEvent)` plugin export. Events are coalesced inside a
500 ms quiet window so a single editor save (which often fires Modify +
Create + Chmod) only produces one guest call. The guest's handler should be
idempotent — typically just invalidate any cached state and let the next
`sync()` re-read.

The reference implementation is `rosec-keepassxc-file` in the rosec repo;
end-user setup is documented at [providers/keepassxc-file](../providers/keepassxc-file).

## Plugin lifecycle and recreation

### What happens after a trap

1. The host detects `plugin.call()` returned `Err` (any WASM-level failure).
2. The host creates a fresh `Plugin` from the stored `Manifest`.
3. The host calls `init` on the new plugin with the same configuration.
4. The new plugin starts in a **locked** state (no auth, no cached data).
5. The original error is returned to the caller.
6. The next `unlock` call will re-authenticate and re-sync.

**The guest does not need to do anything for recreation to work.**  The host
handles it transparently.  But the guest must be designed so that `init` can
be called on a fresh instance at any time and produce a valid starting state.

### What recreation does NOT do

- It does not retry the failed call.
- It does not preserve unlocked state (vault data, tokens).
- It does not preserve WASI file descriptors or in-memory caches.

## Global state management

### Recommended pattern

```rust
struct WasmCell<T>(Mutex<T>);

impl<T> WasmCell<T> {
    const fn new(val: T) -> Self { Self(Mutex::new(val)) }

    fn lock(&self) -> MutexGuard<'_, T> {
        // WASM guests are single-threaded.  Poison only occurs from
        // traps that kill execution without unwinding.  The data is
        // always consistent because there's no concurrent mutation.
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

static STATE: WasmCell<Option<GuestState>> = WasmCell::new(None);
```

WASM guests are single-threaded.  The `Mutex` provides interior mutability
for a `static`, not actual thread synchronisation.  Ignoring poison is
correct because there's never a second thread observing inconsistent state.

However, after a trap, the data behind the mutex *may* be inconsistent
(e.g. a field was being written when the trap fired).  This is acceptable
because the host will recreate the entire plugin instance after any trap.
The poisoned-but-recovered mutex in the old instance is never used again.

## Security requirements

1. **Secrets must not appear in error messages or logs.**
   Application error responses (`ok: false`) must not include passwords,
   tokens, or key material in the `error` string.

2. **Zeroize sensitive data.**
   Use `Zeroizing<String>` / `Zeroizing<Vec<u8>>` for passwords, tokens,
   and decryption keys.  Note that after a WASM trap, zeroization of
   in-flight data cannot be guaranteed (destructors don't run).  The host
   mitigates this by destroying the entire plugin instance.

3. **Do not store passwords.**
   The host handles credential persistence (`wasm_cred` module).  The guest
   receives passwords via `UnlockRequest` and must not write them to WASI
   files or Extism variables.

4. **Respect `allowed_hosts`.**
   Only make HTTP requests to hosts declared in your policy sidecar's
   `[network].allowed_hosts` (see
   [WASM policy sidecar](./wasm-policy-sidecar.md)).  The host
   enforces this at the host function level, but the guest should
   also validate URLs defensively.  Prefer exact hostnames over
   wildcards — `*` matches `.` so `*.example.com` matches arbitrary
   subdomain depth (see "Security constraint" above).

## Offline cache

### Overview

The offline cache lets WASM providers serve previously-synced secrets when
the network is unavailable (e.g. after laptop resume, on aircraft, on local
networks).  The guest exports an opaque blob of its state; the host wraps
it in authenticated encryption bound to the machine, password, and provider
ID, then writes it to disk.

The guest owns the **what** (blob contents); the host owns the **how**
(encryption, file management, key derivation, expiry).

### Capability and configuration

Offline caching requires **two gates** to be active:

1. **Guest gate:** The guest declares `Capability::OfflineCache` via its
   `capabilities` export (feature toggle — "I support this").
2. **Host gate:** The per-provider `offline_cache` config is `true`
   (default) — the user's toggle ("I want this").

Both must be true for the host to call `export_cache`, `restore_cache`, or
attempt offline unlock.  If the user sets `offline_cache = false` in the
provider's config, caching is disabled regardless of the guest's capability.

```toml
[[provider]]
id            = "bw1"
kind          = "bitwarden-pm"
offline_cache = false   # disable caching even though the plugin supports it
```

Guest capability declaration:

```rust
#[plugin_fn]
pub fn capabilities(_: ()) -> FnResult<Json<CapabilitiesResponse>> {
    Ok(Json(CapabilitiesResponse {
        capabilities: vec![
            "sync".to_string(),
            "offline_cache".to_string(),
        ],
    }))
}
```

Without the capability, the host never calls `export_cache` or
`restore_cache` — even if the config enables caching.

### `export_cache`

Called by the host after a successful `unlock` or `sync` to snapshot the
guest's current in-memory state.

```rust
#[plugin_fn]
pub fn export_cache(_: ()) -> FnResult<Json<ExportCacheResponse>> {
    let guard = STATE.lock();
    let Some(state) = guard.as_ref() else {
        return Ok(Json(ExportCacheResponse {
            ok: false,
            error: Some("not unlocked".to_string()),
            blob: None,
        }));
    };

    // Serialize vault state (the host cannot read this blob).
    let json = serde_json::to_vec(&state.vault)?;
    let encoded = BASE64_STANDARD.encode(&json);

    Ok(Json(ExportCacheResponse {
        ok: true,
        error: None,
        blob: Some(encoded),
    }))
}
```

**Rules:**
- The blob is opaque to the host.  The host encrypts and stores it as-is.
- Prefer a format you can deserialize in `restore_cache` (e.g. JSON, then
  base64-encoded to fit in the string field).
- **Session tokens (refresh tokens, protected keys) MAY be included** in the
  cache blob if your provider supports automatic session recovery.  When
  connectivity returns after an offline unlock, the host triggers a background
  sync.  If the blob contains a valid refresh token, the guest can
  transparently refresh its access token and sync — clearing the `cached`
  flag without requiring a full re-unlock.  If the refresh token has expired
  or been revoked, the sync fails with `AuthFailed` and the host locks the
  provider, triggering a normal re-unlock prompt.
  The host's AES-256-CBC + HMAC-SHA256 wrapper (bound to machine key +
  password + provider ID) protects tokens at rest — they are no more
  sensitive than the decrypted vault data already in the blob.
- If the guest is locked or has no data, return `ok: false`.

### `restore_cache`

Called by the host during an offline unlock when readiness probes fail.  The
host decrypts the cache file and passes the original blob back to the guest.

```rust
#[plugin_fn]
pub fn restore_cache(
    Json(req): Json<RestoreCacheRequest>,
) -> FnResult<Json<SimpleResponse>> {
    let json = BASE64_STANDARD.decode(&req.blob)
        .map_err(|e| Error::msg(format!("base64 decode: {e}")))?;
    let vault: VaultState = serde_json::from_slice(&json)
        .map_err(|e| Error::msg(format!("deserialize: {e}")))?;

    let mut guard = STATE.lock();
    let state = guard.as_mut()
        .ok_or_else(|| Error::msg("not initialised"))?;
    state.vault = Some(vault);

    Ok(Json(SimpleResponse {
        ok: true,
        error: None,
    }))
}
```

**Rules:**
- The blob is exactly what the guest returned from `export_cache`.  The host
  performs authenticated decryption before passing it -- if the MAC fails
  the host never calls `restore_cache`.
- After `restore_cache`, the guest should be in a state where data-access
  functions (`list_items`, `get_secret_attr`, etc.) work, but network
  operations are not expected to work.
- The guest must **not** make network calls during `restore_cache`.

### Lifecycle

```
Online unlock:
  host: readiness probes pass
  host: call guest unlock(password)
  guest: authenticates, syncs, populates state
  host: call guest export_cache()
  host: encrypt blob → write cache file

Offline unlock:
  host: readiness probes fail
  host: read cache file → decrypt blob
  host: call guest init(config)     [fresh plugin if needed]
  host: call guest restore_cache(blob)
  host: status.cached = true

Sync (online):
  host: call guest sync()
  guest: fetches remote, updates state
  host: call guest export_cache()
  host: encrypt blob → write cache file
  host: status.cached = false       [data confirmed fresh]

Sync (fails):
  host: call guest sync() → error
  host: status.cached = true        [data may be stale]

Lock:
  host: call guest lock()
  host: zeroize cache key from memory
  host: status.cached = false, last_cache_write unchanged
```

### Host-side encryption

The host wraps the guest blob with:
- **Key derivation:** `HKDF-SHA256(machine_key || password, salt=b"rosec-provider-cache-v1", info=provider_id, len=64)`
  producing 32 bytes AES key + 32 bytes HMAC key.
- **Encryption:** AES-256-CBC with PKCS7 padding + HMAC-SHA256 (encrypt-then-MAC).
- **File format:** `[version 1B][timestamp 8B BE][IV 16B][ct_len 4B BE][ciphertext...][MAC 32B]`

The guest does not need to know these details -- the blob it exports/imports
is plaintext from the guest's perspective.

### `ProviderStatus` fields

| Field              | Type                  | Meaning                                              |
|--------------------|-----------------------|------------------------------------------------------|
| `cached`           | `bool`                | Data-quality signal: true when data has not been confirmed against the remote (offline unlock, failed sync). |
| `offline_cache`    | `bool`                | Whether offline caching is active for this provider (both `Capability::OfflineCache` declared AND host `offline_cache` config enabled). |
| `last_cache_write` | `Option<SystemTime>`  | When the cache file was last written to disk (None = never). |

The CLI shows `cached` as `"unlocked (cached)"` in `rosec provider list`
and `rosec status` to alert the user that secrets may be stale.

## Packaging, signing, and distribution

Writing the plugin is half the job; rosec only loads it once it is a signed
**bundle** of three files sitting together in a provider directory:

| File | What it is |
|------|------------|
| `foo.wasm` | your compiled provider (`cargo build --target wasm32-wasip1 --release`) |
| `foo.wasm.policy.toml` | the policy sidecar declaring your network/filesystem needs and options — see the [WASM policy sidecar](./wasm-policy-sidecar.md) |
| `foo.wasm.minisig` | one minisign signature over `(wasm_bytes || policy_bytes)` — substituting either file invalidates it |

`rosec-package-wasm` (from the `rosec-tools` crate,
`cargo build -p rosec-tools` in the rosec repo) produces and checks these
bundles. It has three subcommands:

### `keygen` — create your signing keypair (once)

```console
$ rosec-package-wasm keygen --output-dir ~/keys --prefix acme-signing
```

Prompts for a password (`--no-password` for a key destined for a CI secret,
equivalent to `rsign generate -W`). Writes `acme-signing.key` (0600) and
`acme-signing.pub`, and prints the `[[service.wasm_trusted_key]]` snippet your
users will need (below). Keys are standard rsign/minisign format — if you
already have an rsign key, use it directly; the tools are interchangeable.

### `sign` — validate the policy and sign the bundle

```console
$ rosec-package-wasm sign --key ~/keys/acme-signing.key \
    target/wasm32-wasip1/release/acme_vault.wasm
```

The policy sidecar must sit next to the `.wasm` and is **schema-validated
before anything is signed** — a typo'd policy fails here, not on your users'
machines. `--output-dir dist/` stages a distributable copy of all three files
instead of signing in place. Non-interactive signing reads the key from the
`WASM_SIGNING_KEY` env var (file *contents*) and the password from
`WASM_SIGNING_KEY_PASSWORD`.

Key rotation is the same command with a new key pointed at existing bundles —
signing never rebuilds the wasm:

```console
$ rosec-package-wasm sign --key ~/keys/new-signing.key dist/
```

### `verify` — check bundles before shipping

```console
$ rosec-package-wasm verify --pubkey ~/keys/acme-signing.pub dist/
$ rosec-package-wasm verify dist/   # against the rosec release keys instead
```

### Getting users to trust your plugin

Stock rosec builds only load plugins signed by a rosec release key. Your
users have two options, in order of preference:

1. **Trust anchor** (recommended) — they add your public key to their
   `rosec.toml`, scoped to your plugin's kind. Verification stays on for
   everything else, and rosecd logs the extended trust at startup:

   ```toml
   [[service.wasm_trusted_key]]
   key   = "RWQ..."          # your .pub file's second line
   name  = "acme-corp"
   kinds = ["acme-vault"]
   ```

2. **`wasm_verify = "disabled"`** — development only; turns verification off
   for *all* plugins. Fine on your own machine while iterating (no `.minisig`
   needed, the policy sidecar is still required and enforced); never ask
   users to do this.

Either way, users can audit exactly what they are enabling before they enable
it:

```console
$ rosec provider validate --wasm ./acme_vault.wasm
```

shows your signature's provenance, your policy claim, and the resolved
sandbox against their config. Point your install instructions at it.

## Checklist for new providers

- [ ] All `#[plugin_fn]` exports return `Ok(Json(...))` for application errors
- [ ] No `.unwrap()` or `.expect()` on fallible operations in production paths
- [ ] All file I/O errors handled with `match`/`?`, never `.unwrap()`
- [ ] `init` is idempotent and can be called on a fresh instance at any time
- [ ] External I/O (network *and* file reads) confined to gated functions
      (`unlock`, `sync`, `check_remote_changed`)
- [ ] `readiness_probes` declared for all external endpoints the plugin contacts
      (HTTP for API servers, TCP for file servers on network mounts)
- [ ] `lock` drops all decrypted data, does not perform external I/O
- [ ] `status` reads only in-memory state, never performs external I/O
- [ ] Data-access functions (`list_items`, `search`, `get_item_attributes`,
      `get_secret_attr`, etc.) read from in-memory cache only -- no file
      re-reads, no network calls
- [ ] Sensitive data wrapped in `Zeroizing<T>`
- [ ] No passwords or tokens in error messages or logs
- [ ] If using WASI file I/O on storage that could be network-mounted
      (e.g. home directories), TCP probe declared for the file server
- [ ] If supporting offline cache: `capabilities` includes `"offline_cache"`,
      `export_cache` serializes in-memory state (optionally including session
      tokens for automatic recovery), `restore_cache` deserializes it and
      makes data-access functions work
- [ ] `*.wasm.policy.toml` sidecar written, declaring every host you contact
      and every path you touch (see [Packaging](#packaging-signing-and-distribution))
- [ ] Bundle signed with `rosec-package-wasm sign` and checked with
      `rosec provider validate --wasm` before distribution

## Capabilities reference

Every WASM provider exports a `capabilities` function that returns a list of
string identifiers.  These map to `Capability` enum variants in the host and
control which optional guest functions the host will call.

```rust
#[plugin_fn]
pub fn capabilities(_: ()) -> FnResult<Json<CapabilitiesResponse>> {
    Ok(Json(CapabilitiesResponse {
        capabilities: vec![
            "sync".to_string(),
            "ssh".to_string(),
            "offline_cache".to_string(),
            "notifications".to_string(),
        ],
    }))
}
```

The host parses these strings case-insensitively (both `"sync"` and `"Sync"`
are accepted).  Unknown strings are silently ignored.

If a capability is **not** declared, the host never calls the associated guest
functions — they can be omitted from the guest entirely.  Calling an optional
trait method without the capability returns `ProviderError::NotSupported`.

### `sync`

**String:** `"sync"` | **CLI code:** `S`

Declares that the provider can synchronise with a remote data source.  Enables
`rosec sync` and the `-s` flag on `rosec search`.

**Required guest functions:**

| Function | Input | Output | Purpose |
|---|---|---|---|
| `sync` | *(empty)* | `SimpleResponse` | Fetch the latest state from the remote and update the guest's in-memory cache. Network-facing; readiness-gated. |
| `check_remote_changed` | `CheckRemoteChangedRequest` | `CheckRemoteChangedResponse` | Lightweight check whether the remote has new data since the last sync (e.g. compare a revision counter or ETag). Returns `changed: true/false`. Network-facing; readiness-gated. |

**Behaviour:** The host calls `sync` on a configurable interval
(`refresh_interval_secs`) and after each successful unlock.
`check_remote_changed` is called before `sync` as an optimisation — if it
returns `false`, the full sync is skipped.

### `write`

**String:** `"write"` | **CLI code:** `W`

Declares that the provider supports creating, updating, and deleting items.
Required for `rosec item add`, `rosec item edit`, `rosec item import`,
`rosec item delete`, and the D-Bus `CreateItem`/`Delete` methods.

**Required guest functions:**

| Function | Input | Output | Purpose |
|---|---|---|---|
| `create_item` | `CreateItemRequest` | `CreateItemResponse` | Create a new item (or replace an existing one if `replace` is true). Returns the new item ID. |
| `update_item` | `UpdateItemRequest` | `SimpleResponse` | Update an existing item's label, attributes, or secret values. |
| `delete_item` | `DeleteItemRequest` | `SimpleResponse` | Permanently delete an item by ID. |

**Behaviour:** Without this capability, the provider is read-only.  The D-Bus
`CreateItem` call will route to another provider if the target collection maps
to a provider without write capability.

### `ssh`

**String:** `"ssh"` | **CLI code:** `s`

Declares that the provider exposes SSH keys to the built-in SSH agent.  Keys
are loaded automatically when the provider is unlocked and removed when locked.

**Required guest functions:**

| Function | Input | Output | Purpose |
|---|---|---|---|
| `list_ssh_keys` | *(empty)* | `SshKeyListResponse` | Return metadata for all SSH keys the provider can serve: item ID, item name, public key, fingerprint, `ssh_host` patterns, `ssh_user`, and `require_confirm` flag. |
| `get_ssh_private_key` | `SshPrivateKeyRequest` | `SshPrivateKeyResponse` | Return the PEM-encoded private key for a specific item. Called once per key during agent reload. |

**Behaviour:** After unlock and after each sync, the host calls
`list_ssh_keys` then `get_ssh_private_key` for each returned entry.  Keys are
parsed, loaded into the in-memory key store, and made available via the SSH
agent socket and FUSE filesystem.  Each key's metadata controls config snippet
generation (`ssh_host`, `ssh_user`) and signing confirmation (`require_confirm`).

### `key_wrapping`

**String:** `"key_wrapping"` | **CLI code:** `K`

Declares that the provider supports key wrapping — multiple passwords can
unlock the same vault.  Enables `rosec provider add-password`,
`remove-password`, and `list-passwords`.

**Required guest functions:**

| Function | Input | Output | Purpose |
|---|---|---|---|
| `add_password` | `AddPasswordRequest` | `AddPasswordResponse` | Add a new wrapping entry (password + optional label) that can unlock the vault. Returns the entry ID. |
| `remove_password` | `RemovePasswordRequest` | `SimpleResponse` | Remove a wrapping entry by ID. |
| `list_passwords` | *(empty)* | `ListPasswordsResponse` | List all wrapping entries (ID + optional label). Does not expose key material. |

**Behaviour:** Key wrapping is primarily used by local vaults to support PAM
auto-unlock when the login password differs from the master password.  Each
wrapping entry encrypts the same vault key with a different password-derived
wrapping key, so adding/removing passwords does not require re-encrypting data.

### `password_change`

**String:** `"password_change"` | **CLI code:** `P`

Declares that the provider supports changing the unlock password via
`rosec provider change-password`.

**Required guest functions:**

| Function | Input | Output | Purpose |
|---|---|---|---|
| `change_password` | `ChangePasswordRequest` | `SimpleResponse` | Change the primary unlock password. The guest receives both the old and new passwords, verifies the old one, and re-wraps the vault key. |

**Behaviour:** This is separate from key wrapping.  `change_password` replaces
the password for an existing wrapping entry (typically the primary one), while
`add_password`/`remove_password` manage additional entries.

### `offline_cache`

**String:** `"offline_cache"` | **CLI code:** `C`

Declares that the provider supports offline cache export/restore.  Previously
synced data is available after reboot or without network access.

**Required guest functions:**

| Function | Input | Output | Purpose |
|---|---|---|---|
| `export_cache` | *(empty)* | `ExportCacheResponse` | Serialize the guest's current in-memory state into an opaque blob. Called after successful unlock and sync. |
| `restore_cache` | `RestoreCacheRequest` | `SimpleResponse` | Deserialize a previously exported blob back into the guest's state. Called during offline unlock when readiness probes fail. |

**Behaviour:** Requires **both** the guest capability **and** the host-side
`offline_cache = true` config (default).  The host wraps the blob in
AES-256-CBC + HMAC-SHA256 encryption bound to the machine key, password, and
provider ID.  See the [Offline cache](#offline-cache) section above for the
full lifecycle and encryption details.

### `notifications`

**String:** `"notifications"` | **CLI code:** `N`

Declares that the provider supports real-time push notifications via a
WebSocket connection managed by the host.  Enables immediate sync when the
remote vault changes, rather than waiting for the polling interval.

**Required guest functions:**

| Function | Input | Output | Purpose |
|---|---|---|---|
| `get_notification_config` | *(empty)* | `NotificationConfigResponse` | Return a `WebSocketSubscription` containing the full WebSocket URL (including auth tokens), optional HTTP headers for the upgrade request, and an optional handshake message to send after connect. The guest performs any negotiate steps (e.g. SignalR negotiate) internally via HTTP before returning. |
| `parse_notification` | `NotificationFrame` | `NotificationAction` | Classify a received WebSocket text frame. Returns `action: "sync"` (trigger a sync), `action: "lock"` (lock the provider), or `action: "ignore"` (ping, ack, unknown frame). |

**Behaviour:** After a successful online unlock, the host calls
`get_notification_config` and establishes a persistent WebSocket connection.
Each received text frame is passed to `parse_notification`.  On disconnect,
the host reconnects with exponential backoff, calling
`get_notification_config` again to get a fresh URL/token.  The host handles
all connection lifecycle — the guest only provides the URL and frame parsing.

### Capability string reference

| String | Alternate | Enum variant | CLI code |
|---|---|---|:---:|
| `"sync"` | `"Sync"` | `Capability::Sync` | `S` |
| `"write"` | `"Write"` | `Capability::Write` | `W` |
| `"ssh"` | `"Ssh"` | `Capability::Ssh` | `s` |
| `"key_wrapping"` | `"KeyWrapping"` | `Capability::KeyWrapping` | `K` |
| `"password_change"` | `"PasswordChange"` | `Capability::PasswordChange` | `P` |
| `"offline_cache"` | `"OfflineCache"` | `Capability::OfflineCache` | `C` |
| `"notifications"` | `"Notifications"` | `Capability::Notifications` | `N` |
