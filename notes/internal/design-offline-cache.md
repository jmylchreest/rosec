# Design: Offline Cache for WASM Providers

## Overview

Enable WASM providers to serve previously-synced secrets when the network is
unavailable (aircraft, local-only networks, post-resume before WiFi).  The
guest exports an opaque cache blob; the host wraps it in an additional
encryption layer bound to the user's password, the machine, and the provider.
On offline unlock the host unwraps and feeds the blob back to the guest.

The in-memory state (held by the guest) is always authoritative.  The cache
file is a write-back persistence snapshot, never read during normal operation.

## Interfaces

### New Capability variant

```rust
// rosec-core/src/lib.rs
pub enum Capability {
    Sync,
    Write,
    Ssh,
    KeyWrapping,
    PasswordChange,
    OfflineCache,       // NEW — guest supports export_cache / restore_cache
}
```

### Extended ProviderStatus

```rust
// rosec-core/src/lib.rs
pub struct ProviderStatus {
    pub locked: bool,
    /// Last successful remote sync.
    pub last_sync: Option<SystemTime>,
    /// True when data has not been confirmed against the remote.
    ///
    /// Set on:
    ///   - offline unlock (restore_cache)
    ///   - failed sync() (network dropped, data is stale)
    /// Cleared on:
    ///   - successful online unlock
    ///   - successful sync()
    /// Reset on:
    ///   - lock() (no data at all)
    ///
    /// This is a data-quality signal, not a provenance signal.
    /// Combined with `last_sync`, consumers can assess staleness:
    ///   cached=true, last_sync=3h ago  -> briefly offline
    ///   cached=true, last_sync=8d ago  -> extended offline / cache restore
    pub cached: bool,
    /// Whether offline caching is active for this provider.
    ///
    /// This is the AND of two gates:
    ///   1. The guest declares `Capability::OfflineCache`
    ///   2. The host config has `offline_cache = true` (the default)
    ///
    /// Both must be true for any cache operations to occur.
    pub offline_cache: bool,
    /// When the cache file was last written to disk.
    pub last_cache_write: Option<SystemTime>,
}
```

### New guest functions

| Function        | Input                   | Output                   |
|-----------------|-------------------------|--------------------------|
| `export_cache`  | *(empty)*               | `ExportCacheResponse`    |
| `restore_cache` | `RestoreCacheRequest`   | `SimpleResponse`         |

### Protocol types (rosec-wasm/src/protocol.rs + guest protocol.rs)

```rust
/// Returned by `export_cache` — the guest serialises its current in-memory
/// state into an opaque blob.  The host will wrap this in an additional
/// encryption layer before persisting to disk.
///
/// The guest MAY pre-encrypt the blob (defense in depth) but is not
/// required to — the host wrapper provides confidentiality and integrity.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportCacheResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    /// Opaque cache blob, base64-encoded.  The host treats this as an
    /// opaque byte string — it never inspects or interprets the contents.
    #[serde(default)]
    pub blob_b64: Option<String>,
}

/// Sent to `restore_cache` — the host unwrapped the cache file and passes
/// the inner blob back to the guest to restore its in-memory state.
#[derive(Debug, Serialize, Deserialize)]
pub struct RestoreCacheRequest {
    /// The same opaque blob that was returned by `export_cache`, base64.
    pub blob_b64: String,
}
```

### Cache key derivation

```rust
// rosec-wasm/src/cache.rs (new module)

/// Derive a 64-byte cache key (32 enc + 32 mac) bound to the machine,
/// password, and provider.
///
/// cache_key = HKDF-SHA256(
///     ikm  = machine_key || password,
///     salt = b"rosec-provider-cache-v1",
///     info = provider_id,
///     len  = 64
/// )
fn derive_cache_key(
    machine_key: &[u8],       // 32 bytes from machine_key::load_or_create()
    password: &str,
    provider_id: &str,
) -> Result<Zeroizing<[u8; 64]>, ProviderError>
```

### Cache file format

```
Stored at: $XDG_DATA_HOME/rosec/cache/<provider-id>.bin
Permissions: 0600

Wire format (binary, not TOML):
┌─────────────────────────────────────────┐
│ version: u8 = 1                         │
│ timestamp: i64 (unix epoch seconds, BE) │
│ iv: [u8; 16]                            │
│ ciphertext_len: u32 (BE)                │
│ ciphertext: [u8; ciphertext_len]        │
│ mac: [u8; 32]                           │
└─────────────────────────────────────────┘

Encryption: AES-256-CBC(key = cache_key[..32], iv = random, data = blob)
MAC: HMAC-SHA256(key = cache_key[32..], data = version || timestamp || iv || ciphertext)
```

### WasmProvider struct changes

```rust
pub struct WasmProvider {
    // ... existing fields ...

    /// Cache encryption key — derived from password + machine_key + provider_id
    /// during unlock.  Held in memory while unlocked so that sync() can update
    /// the cache without needing the password again.  Zeroized on lock().
    cache_key: std::sync::Mutex<Option<Zeroizing<[u8; 64]>>>,

    /// Data-quality flag: true when data has not been confirmed against the
    /// remote.  Set on offline unlock and on failed sync.  Cleared on
    /// successful sync or successful online unlock.  Reset on lock.
    cached: std::sync::atomic::AtomicBool,

    /// Timestamp of the last successful cache write-back to disk.
    last_cache_write: std::sync::Mutex<Option<SystemTime>>,
}
```

## Data Flow

### Online unlock (happy path)

```
1. unlock(password) called
2. derive cache_key from password + machine_key + provider_id
3. store cache_key in self.cache_key
4. readiness probes pass
5. guest.unlock(password) -> network auth + sync -> Ok
6. cached = false
7. if offline_cache_enabled() (capability AND config):
      guest.export_cache() -> blob_b64
      host encrypts blob with cache_key -> writes cache file
      last_cache_write = now
8. ProviderStatus { locked: false, cached: false,
                     offline_cache: true, last_cache_write: now }
```

### Offline unlock (cache fallback)

```
1. unlock(password) called
2. derive cache_key from password + machine_key + provider_id
3. store cache_key in self.cache_key
4. readiness probes FAIL
5. check: offline_cache_enabled() (capability AND config)?
      NO -> Err(Unavailable)
6. read cache file from disk
7. verify MAC with cache_key -> FAIL -> Err(AuthFailed) [wrong password]
8. check timestamp: age > max_cache_age? -> Err(Unavailable("cache expired"))
9. decrypt ciphertext with cache_key -> inner blob
10. guest.restore_cache(blob) -> Ok
11. cached = true
12. ProviderStatus { locked: false, cached: true,
                     offline_cache: true, last_cache_write: <from file> }
    last_sync reflects timestamp embedded in cache file (the sync
    time when the cache was written, not "now")
```

### Sync succeeds (any starting state)

```
1. sync() called (cached may be true or false)
2. wait_for_readiness() -> PASS
3. guest.sync() -> Ok
4. cached = false              ← data confirmed live
5. if offline_cache_enabled() (capability AND config):
      guest.export_cache() -> blob
      host encrypts blob with cache_key -> overwrites cache file
      last_cache_write = now
6. ProviderStatus { locked: false, cached: false }
```

### Sync fails (network dropped)

```
1. sync() called
2. wait_for_readiness() -> FAIL -> Err(Unavailable)
   OR readiness passes but guest.sync() -> Err
3. cached = true               ← data is unconfirmed / stale
4. cache file NOT updated (in-memory state may differ from cache)
5. ProviderStatus { locked: false, cached: true }
   last_sync still reflects the last successful sync timestamp
```

This means `cached` can oscillate during a session:
- unlock online -> cached=false
- network drops, sync fails -> cached=true
- network returns, sync succeeds -> cached=false

### Lock

```
1. lock() called
2. guest.lock() -> drops decrypted state
3. cache_key = None (zeroized)
4. cached = false (reset — no data to serve)
5. last_cache_write unchanged (reflects last write, even after lock)
6. cache FILE stays on disk (it's encrypted, safe at rest)
```

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Encryption model | Hybrid (Option C) | Guest provides opaque blob, host wraps with password+machine_key+provider_id. Defense in depth — host layer always protects even if guest blob is plaintext. Machine-binding prevents stolen cache portability. |
| Cache key lifetime | In-memory while unlocked | sync() needs the key but doesn't receive a password. Same security model as vault key — exists only while decrypted data exists. Zeroized on lock(). |
| Cache staleness | 10 days default, configurable | Safety net against very stale data. Configurable per-provider. |
| `cached` semantics | Data-quality signal | `cached=true` means "data has not been confirmed against the remote." Set on offline unlock AND on failed sync. Cleared on successful sync. This is more useful to consumers than a provenance signal ("how did we bootstrap?"). Combined with `last_sync` timestamp, consumers can assess staleness severity. |
| Blob transport | Base64 over JSON | Consistent with existing get_secret_attr pattern (SecretAttrResponse.value_b64). Avoids binary framing in the JSON protocol. |
| Cache file location | $XDG_DATA_HOME/rosec/cache/<provider-id>.bin | Separate from credentials (oauth/) and vault data. Per-provider files. |
| Who decides blob content | Guest | The host never inspects the blob. For bitwarden-pm, the guest would serialize its VaultState (decrypted ciphers, folders, orgs). Other providers choose their own format. |

## Acceptance Criteria

### Core cache mechanics
- [ ] `Capability::OfflineCache` variant added to enum, parsed from guest
- [ ] `export_cache` guest function called after successful online unlock and sync
- [ ] `restore_cache` guest function called on offline unlock with cache blob
- [ ] Cache key derived from machine_key + password + provider_id via HKDF
- [ ] Cache file uses encrypt-then-MAC (AES-256-CBC + HMAC-SHA256)
- [ ] Wrong password produces HMAC failure, not a decryption of garbage
- [ ] Cache older than max_cache_age (default 10d) is rejected
- [ ] Cache file updated (write-back) after every successful sync
- [ ] `lock()` zeroizes cache_key, cache file remains on disk
- [ ] Provider without OfflineCache capability: no cache operations attempted
- [ ] Provider with `offline_cache = false` in host config: no cache operations attempted
- [ ] `rosec provider detach` deletes cache file

### Status model
- [ ] `ProviderStatus` extended with `cached`, `offline_cache`, `last_cache_write`
- [ ] `cached` set `true` on offline unlock (restore_cache path)
- [ ] `cached` set `true` on failed sync (data is unconfirmed)
- [ ] `cached` set `false` on successful online unlock
- [ ] `cached` set `false` on successful sync
- [ ] `cached` reset to `false` on lock (no data)
- [ ] `offline_cache` reflects the AND of two gates: guest declares `OfflineCache` capability AND host config has `offline_cache = true`
- [ ] `last_cache_write` updated on every successful cache file write
- [ ] Status fields propagated to D-Bus properties and `rosec status` CLI

## Files to Create/Modify

### New files
- `rosec-wasm/src/cache.rs` — cache key derivation, encrypt/decrypt, file I/O
- (test files for cache module)

### Modified files
- `rosec-core/src/lib.rs` — `Capability::OfflineCache`, `ProviderStatus.cached`
- `rosec-wasm/src/protocol.rs` — `ExportCacheResponse`, `RestoreCacheRequest`
- `rosec-wasm/src/provider.rs` — `WasmProvider` struct fields, unlock/sync/lock/status flows
- `rosec-wasm/src/lib.rs` — doc table update
- `rosec-bitwarden-pm/src/protocol.rs` — same protocol types (kept in sync)
- `rosec-bitwarden-pm/src/lib.rs` — `export_cache()`, `restore_cache()` plugin_fn exports, add `OfflineCache` to capabilities
- `docs/wasm-provider-guide.md` — document cache contract

### Dependencies
- `rosec-core/src/machine_key.rs` — first real consumer of `load_or_create()`
- `rosec-core/src/credential.rs` — may reuse `StorageKey` pattern for encrypt-then-MAC

## Configuration

```toml
# rosec.toml — per-provider
[[provider]]
kind = "bitwarden-pm"
# ...

# Offline cache settings (optional, defaults shown)
offline_cache = true    # default: true; set false to disable caching for
                        # this provider even if the guest declares
                        # Capability::OfflineCache
max_cache_age = 10      # days; default: 10, set to 0 to disable age check
```

## Out of Scope

- **Write-through to remote**: cached mode is read-only. No queuing of
  writes for later sync.
- **Partial/incremental cache**: the blob is a complete snapshot. Delta
  caching is a future optimisation.
- **Cache for non-WASM providers**: LocalVault already has disk state.
  Native providers could implement their own caching outside this system.
- **Cache sharing between machines**: machine_key binding intentionally
  prevents this. Each machine has its own cache.
- **~~Automatic background sync retry~~**: Implemented — the background sync
  loop uses accelerated retry intervals (~12–15s) when a provider is in
  cached mode, with auth failure detection that locks the provider if the
  refresh token has expired.

## Security Considerations

1. **Double encryption**: the host wrapper (AES-256-CBC + HMAC-SHA256)
   protects the blob regardless of what the guest puts in it. A well-behaved
   guest (bitwarden-pm) would also pre-encrypt with its own vault key for
   defense in depth, but this is not required by the protocol.

2. **Machine binding**: the machine_key is a 32-byte random seed unique to
   this installation. A cache file copied to another machine is useless
   because the different machine_key produces a different cache_key, failing
   the HMAC check.

3. **Password binding**: wrong password -> wrong HKDF output -> HMAC
   verification failure. The cache cannot be decrypted without the correct
   master password.

4. **No password storage**: the password is consumed during unlock() to
   derive the cache key. The cache key (not the password) is held in memory
   while unlocked, then zeroized on lock.

5. **Tamper detection**: encrypt-then-MAC. The HMAC covers
   version || timestamp || iv || ciphertext. Any modification is detected
   before decryption is attempted.

6. **Cache expiry**: 10-day default prevents indefinite use of stale data.
   Configurable per deployment.

7. **Swap/hibernate risk**: the cache key and decrypted guest state exist in
   process memory while unlocked. Same risk as any secrets daemon — mitigated
   by mlock() (future) or encrypted swap. The cache file on disk is always
   encrypted.
