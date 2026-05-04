//! Encrypted offline cache for WASM providers.
//!
//! The guest exports an opaque blob; this module wraps it in an additional
//! encryption layer bound to the user's password, the machine, and the
//! provider.  On offline unlock the host unwraps and feeds the blob back.
//!
//! # Key derivation
//!
//! ```text
//! cache_key = HKDF-SHA256(
//!     ikm  = machine_key || password,
//!     salt = b"rosec-provider-cache-v1",
//!     info = provider_id,
//!     len  = 64          // 32 enc + 32 mac
//! )
//! ```
//!
//! # File format (binary)
//!
//! ```text
//! version: u8 = 1
//! timestamp: i64 (unix epoch seconds, BE)
//! iv: [u8; 16]
//! ciphertext_len: u32 (BE)
//! ciphertext: [u8; ciphertext_len]
//! mac: [u8; 32]    // HMAC-SHA256(mac_key, version || timestamp || iv || ciphertext)
//! ```
//!
//! # Security
//!
//! - Encrypt-then-MAC: HMAC covers version, timestamp, IV, and ciphertext.
//! - Fresh random IV on every write.
//! - Machine-bound: different `machine_key` → different `cache_key` → HMAC failure.
//! - Password-bound: wrong password → wrong HKDF output → HMAC failure.
//! - Cache key is zeroized on drop via [`Zeroizing`].

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::Aes256;
use block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use hmac::{Hmac, Mac};
use rand::Rng;
use rosec_core::ProviderError;
use sha2::Sha256;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = Decryptor<Aes256>;
type Aes256CbcEnc = Encryptor<Aes256>;

/// Decrypted cache contents: `(plaintext_blob, cache_timestamp)`.
pub type CacheContents = (Zeroizing<Vec<u8>>, SystemTime);

/// Current cache file format version.
const CACHE_VERSION: u8 = 1;

/// HKDF salt — domain-separates cache keys from WASM credential keys.
const HKDF_SALT: &[u8] = b"rosec-provider-cache-v1";

/// Default maximum cache age (10 days).
pub const DEFAULT_MAX_CACHE_AGE: Duration = Duration::from_secs(10 * 24 * 60 * 60);

/// A 64-byte cache key: 32 bytes encryption + 32 bytes MAC.
///
/// Derived from `machine_key || password` via HKDF, scoped to a single
/// provider ID.  Held in memory while the provider is unlocked, zeroized
/// on lock.
pub struct CacheKey {
    data: Zeroizing<[u8; 64]>,
}

impl CacheKey {
    fn enc_key(&self) -> &[u8; 32] {
        self.data[..32]
            .try_into()
            .expect("enc_key slice is 32 bytes")
    }

    fn mac_key(&self) -> &[u8; 32] {
        self.data[32..]
            .try_into()
            .expect("mac_key slice is 32 bytes")
    }
}

impl std::fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CacheKey([redacted])")
    }
}

/// Derive a cache key from machine key, password, and provider ID.
///
/// The machine key binds the cache to this installation; the password binds
/// it to the user; the provider ID prevents cross-provider decryption.
pub fn derive_cache_key(
    machine_key: &[u8],
    password: &str,
    provider_id: &str,
) -> Result<CacheKey, ProviderError> {
    // Concatenate machine_key || password as IKM.
    let mut ikm = Zeroizing::new(Vec::with_capacity(machine_key.len() + password.len()));
    ikm.extend_from_slice(machine_key);
    ikm.extend_from_slice(password.as_bytes());

    let (_, hkdf) = hkdf::Hkdf::<Sha256>::extract(Some(HKDF_SALT), &ikm);

    let mut key_bytes = Zeroizing::new([0u8; 64]);
    hkdf.expand(provider_id.as_bytes(), key_bytes.as_mut())
        .map_err(|e| ProviderError::Other(anyhow::anyhow!("HKDF expand for cache key: {e}")))?;

    Ok(CacheKey { data: key_bytes })
}

/// Encrypt an opaque blob and write the cache file to disk.
///
/// Returns the write timestamp on success.
pub fn write_cache_file(
    provider_id: &str,
    key: &CacheKey,
    plaintext: &[u8],
) -> Result<SystemTime, ProviderError> {
    let path = cache_file_path(provider_id)?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ProviderError::Other(anyhow::anyhow!(
                "failed to create cache directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    let now = SystemTime::now();
    let timestamp = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;

    let mut iv = [0u8; 16];
    rand::rng().fill_bytes(&mut iv);

    let pad_len = 16 - (plaintext.len() % 16);
    let mut buf = Zeroizing::new(vec![0u8; plaintext.len() + pad_len]);
    buf[..plaintext.len()].copy_from_slice(plaintext);

    let encryptor = Aes256CbcEnc::new_from_slices(key.enc_key(), &iv)
        .map_err(|e| ProviderError::Other(anyhow::anyhow!("AES init: {e}")))?;
    let ciphertext = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|e| ProviderError::Other(anyhow::anyhow!("AES encrypt: {e}")))?;

    let ct_len = ciphertext.len() as u32;

    // Compute HMAC over version || timestamp || iv || ciphertext.
    let mac = compute_mac(key.mac_key(), CACHE_VERSION, timestamp, &iv, ciphertext)?;

    // Write to a temporary file then rename for atomicity.
    let tmp_path = path.with_extension("tmp");
    {
        let file = open_secret_file(&tmp_path)?;
        let mut writer = std::io::BufWriter::new(file);
        writer
            .write_all(&[CACHE_VERSION])
            .and_then(|()| writer.write_all(&timestamp.to_be_bytes()))
            .and_then(|()| writer.write_all(&iv))
            .and_then(|()| writer.write_all(&ct_len.to_be_bytes()))
            .and_then(|()| writer.write_all(ciphertext))
            .and_then(|()| writer.write_all(&mac))
            .and_then(|()| writer.flush())
            .map_err(|e| {
                ProviderError::Other(anyhow::anyhow!(
                    "failed to write cache file {}: {e}",
                    tmp_path.display()
                ))
            })?;
    }

    std::fs::rename(&tmp_path, &path).map_err(|e| {
        // Clean up temp file on rename failure.
        let _ = std::fs::remove_file(&tmp_path);
        ProviderError::Other(anyhow::anyhow!(
            "failed to rename cache file {} -> {}: {e}",
            tmp_path.display(),
            path.display()
        ))
    })?;

    info!(
        provider = %provider_id,
        path = %path.display(),
        size = ct_len,
        "wrote offline cache file"
    );

    Ok(now)
}

/// Read and decrypt the cache file.
///
/// Returns `(plaintext, cache_timestamp)` on success.
/// Returns `None` if no cache file exists.
///
/// # Errors
///
/// - `ProviderError::AuthFailed` — HMAC verification failed (wrong password
///   or tampered data).
/// - `ProviderError::Unavailable` — cache is older than `max_age`.
/// - `ProviderError::Other` — I/O or format errors.
pub fn read_cache_file(
    provider_id: &str,
    key: &CacheKey,
    max_age: Duration,
) -> Result<Option<CacheContents>, ProviderError> {
    let path = cache_file_path(provider_id)?;

    if !path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read(&path).map_err(|e| {
        ProviderError::Other(anyhow::anyhow!(
            "failed to read cache file {}: {e}",
            path.display()
        ))
    })?;

    // Minimum size: version(1) + timestamp(8) + iv(16) + ct_len(4) + mac(32) = 61
    if raw.len() < 61 {
        return Err(ProviderError::Other(anyhow::anyhow!(
            "cache file too small ({} bytes)",
            raw.len()
        )));
    }

    let version = raw[0];
    if version != CACHE_VERSION {
        return Err(ProviderError::Other(anyhow::anyhow!(
            "unsupported cache version {version} (expected {CACHE_VERSION})"
        )));
    }

    let timestamp = i64::from_be_bytes(raw[1..9].try_into().expect("8-byte timestamp slice"));
    let iv: [u8; 16] = raw[9..25].try_into().expect("16-byte IV slice");
    let ct_len = u32::from_be_bytes(raw[25..29].try_into().expect("4-byte ct_len slice")) as usize;

    let expected_total = 1 + 8 + 16 + 4 + ct_len + 32;
    if raw.len() != expected_total {
        return Err(ProviderError::Other(anyhow::anyhow!(
            "cache file length mismatch: expected {expected_total}, got {}",
            raw.len()
        )));
    }

    let ciphertext = &raw[29..29 + ct_len];
    let stored_mac = &raw[29 + ct_len..29 + ct_len + 32];

    // Verify HMAC before decrypting.
    let computed_mac = compute_mac(key.mac_key(), version, timestamp, &iv, ciphertext)?;
    if !constant_time_eq(&computed_mac, stored_mac) {
        warn!(
            provider = %provider_id,
            "cache HMAC verification failed (wrong password or tampered data)"
        );
        return Err(ProviderError::AuthFailed);
    }

    let cache_time = UNIX_EPOCH + Duration::from_secs(timestamp as u64);
    if max_age > Duration::ZERO {
        let age = SystemTime::now()
            .duration_since(cache_time)
            .unwrap_or(Duration::ZERO);
        if age > max_age {
            let days = age.as_secs() / 86400;
            let max_days = max_age.as_secs() / 86400;
            warn!(
                provider = %provider_id,
                age_days = days,
                max_days = max_days,
                "offline cache expired"
            );
            return Err(ProviderError::Unavailable(format!(
                "offline cache expired ({days} days old, max {max_days})"
            )));
        }
    }

    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let decryptor = Aes256CbcDec::new_from_slices(key.enc_key(), &iv)
        .map_err(|e| ProviderError::Other(anyhow::anyhow!("AES init: {e}")))?;
    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| ProviderError::Other(anyhow::anyhow!("AES decrypt: {e}")))?;

    let result = Zeroizing::new(plaintext.to_vec());

    debug!(
        provider = %provider_id,
        cache_age_secs = SystemTime::now()
            .duration_since(cache_time)
            .unwrap_or(Duration::ZERO)
            .as_secs(),
        "read offline cache file"
    );

    Ok(Some((result, cache_time)))
}

/// Delete the cache file for a provider.
///
/// Called when a provider is detached.  Returns `true` if a file was removed.
pub fn delete_cache_file(provider_id: &str) -> Result<bool, ProviderError> {
    let path = cache_file_path(provider_id)?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| {
            ProviderError::Other(anyhow::anyhow!(
                "failed to delete cache file {}: {e}",
                path.display()
            ))
        })?;
        debug!(provider = %provider_id, "deleted offline cache file");
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Return the path to the cache file for a provider.
fn cache_file_path(provider_id: &str) -> Result<PathBuf, ProviderError> {
    let base = if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(xdg)
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".local/share")
    } else {
        return Err(ProviderError::Other(anyhow::anyhow!(
            "cannot locate cache directory: neither XDG_DATA_HOME nor HOME is set"
        )));
    };
    Ok(base
        .join("rosec")
        .join("cache")
        .join(format!("{provider_id}.bin")))
}

/// Compute HMAC-SHA256(key, version || timestamp || iv || ciphertext).
fn compute_mac(
    mac_key: &[u8; 32],
    version: u8,
    timestamp: i64,
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<[u8; 32], ProviderError> {
    let mut hmac = HmacSha256::new_from_slice(mac_key)
        .map_err(|e| ProviderError::Other(anyhow::anyhow!("HMAC init: {e}")))?;
    hmac.update(&[version]);
    hmac.update(&timestamp.to_be_bytes());
    hmac.update(iv);
    hmac.update(ciphertext);
    Ok(hmac.finalize().into_bytes().into())
}

/// Constant-time comparison to prevent timing attacks on MAC verification.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Open a file for writing with mode 0600.
fn open_secret_file(path: &std::path::Path) -> Result<std::fs::File, ProviderError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                ProviderError::Other(anyhow::anyhow!(
                    "failed to create cache file {}: {e}",
                    path.display()
                ))
            })
    }
    #[cfg(not(unix))]
    {
        std::fs::File::create(path).map_err(|e| {
            ProviderError::Other(anyhow::anyhow!(
                "failed to create cache file {}: {e}",
                path.display()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_tmp_home(f: impl FnOnce()) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = std::env::temp_dir().join(format!("rosec-cache-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let _guard = crate::TEST_ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        f();
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        drop(_guard);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn test_machine_key() -> Vec<u8> {
        vec![0x42u8; 32]
    }

    #[test]
    fn derive_key_deterministic() {
        let k1 = derive_cache_key(&test_machine_key(), "hunter2", "my-provider").unwrap();
        let k2 = derive_cache_key(&test_machine_key(), "hunter2", "my-provider").unwrap();
        assert_eq!(k1.data.as_ref(), k2.data.as_ref());
    }

    #[test]
    fn derive_key_different_password() {
        let k1 = derive_cache_key(&test_machine_key(), "pass1", "prov").unwrap();
        let k2 = derive_cache_key(&test_machine_key(), "pass2", "prov").unwrap();
        assert_ne!(k1.data.as_ref(), k2.data.as_ref());
    }

    #[test]
    fn derive_key_different_provider() {
        let k1 = derive_cache_key(&test_machine_key(), "pass", "prov-a").unwrap();
        let k2 = derive_cache_key(&test_machine_key(), "pass", "prov-b").unwrap();
        assert_ne!(k1.data.as_ref(), k2.data.as_ref());
    }

    #[test]
    fn derive_key_different_machine() {
        let mk1 = vec![0x01u8; 32];
        let mk2 = vec![0x02u8; 32];
        let k1 = derive_cache_key(&mk1, "pass", "prov").unwrap();
        let k2 = derive_cache_key(&mk2, "pass", "prov").unwrap();
        assert_ne!(k1.data.as_ref(), k2.data.as_ref());
    }

    #[test]
    fn write_read_roundtrip() {
        with_tmp_home(|| {
            let key = derive_cache_key(&test_machine_key(), "pw", "test-prov").unwrap();
            let plaintext = b"opaque cache blob from guest";
            let write_time = write_cache_file("test-prov", &key, plaintext).unwrap();

            let (recovered, cache_time) = read_cache_file("test-prov", &key, DEFAULT_MAX_CACHE_AGE)
                .unwrap()
                .unwrap();
            assert_eq!(recovered.as_slice(), plaintext);
            // Cache time should be close to write time (within a second).
            let delta = write_time
                .duration_since(cache_time)
                .or_else(|_| cache_time.duration_since(write_time))
                .unwrap_or(Duration::ZERO);
            assert!(delta < Duration::from_secs(2));
        });
    }

    #[test]
    fn wrong_password_fails_hmac() {
        with_tmp_home(|| {
            let key_good = derive_cache_key(&test_machine_key(), "correct", "prov").unwrap();
            let key_bad = derive_cache_key(&test_machine_key(), "wrong", "prov").unwrap();
            write_cache_file("prov", &key_good, b"secret").unwrap();

            let err = read_cache_file("prov", &key_bad, DEFAULT_MAX_CACHE_AGE).unwrap_err();
            assert!(
                matches!(err, ProviderError::AuthFailed),
                "expected AuthFailed, got {err:?}"
            );
        });
    }

    #[test]
    fn different_machine_fails_hmac() {
        with_tmp_home(|| {
            let mk1 = vec![0x01u8; 32];
            let mk2 = vec![0x02u8; 32];
            let key1 = derive_cache_key(&mk1, "pw", "prov").unwrap();
            let key2 = derive_cache_key(&mk2, "pw", "prov").unwrap();
            write_cache_file("prov", &key1, b"data").unwrap();

            let err = read_cache_file("prov", &key2, DEFAULT_MAX_CACHE_AGE).unwrap_err();
            assert!(matches!(err, ProviderError::AuthFailed));
        });
    }

    #[test]
    fn expired_cache_rejected() {
        with_tmp_home(|| {
            let key = derive_cache_key(&test_machine_key(), "pw", "prov").unwrap();
            write_cache_file("prov", &key, b"old data").unwrap();

            // Read with zero max_age = no expiry check.
            let result = read_cache_file("prov", &key, Duration::ZERO);
            assert!(result.unwrap().is_some());

            // Read with 1-nanosecond max_age — should be expired immediately.
            let err = read_cache_file("prov", &key, Duration::from_nanos(1)).unwrap_err();
            assert!(
                matches!(err, ProviderError::Unavailable(_)),
                "expected Unavailable, got {err:?}"
            );
        });
    }

    #[test]
    fn tampered_ciphertext_fails_hmac() {
        with_tmp_home(|| {
            let key = derive_cache_key(&test_machine_key(), "pw", "prov").unwrap();
            write_cache_file("prov", &key, b"data").unwrap();

            // Tamper with the cache file.
            let path = cache_file_path("prov").unwrap();
            let mut raw = std::fs::read(&path).unwrap();
            // Flip a byte in the ciphertext region (after version+timestamp+iv+ct_len = 29 bytes).
            if raw.len() > 30 {
                raw[30] ^= 0xFF;
            }
            std::fs::write(&path, &raw).unwrap();

            let err = read_cache_file("prov", &key, DEFAULT_MAX_CACHE_AGE).unwrap_err();
            assert!(matches!(err, ProviderError::AuthFailed));
        });
    }

    #[test]
    fn missing_cache_returns_none() {
        with_tmp_home(|| {
            let key = derive_cache_key(&test_machine_key(), "pw", "prov").unwrap();
            assert!(
                read_cache_file("prov", &key, DEFAULT_MAX_CACHE_AGE)
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[test]
    fn delete_cache_file_removes_it() {
        with_tmp_home(|| {
            let key = derive_cache_key(&test_machine_key(), "pw", "prov").unwrap();
            write_cache_file("prov", &key, b"data").unwrap();
            assert!(delete_cache_file("prov").unwrap());
            assert!(
                read_cache_file("prov", &key, DEFAULT_MAX_CACHE_AGE)
                    .unwrap()
                    .is_none()
            );
            // Second delete returns false (already gone).
            assert!(!delete_cache_file("prov").unwrap());
        });
    }

    #[test]
    fn different_providers_isolated() {
        with_tmp_home(|| {
            let key_a = derive_cache_key(&test_machine_key(), "pw", "prov-a").unwrap();
            let key_b = derive_cache_key(&test_machine_key(), "pw", "prov-b").unwrap();
            write_cache_file("prov-a", &key_a, b"data-a").unwrap();
            write_cache_file("prov-b", &key_b, b"data-b").unwrap();

            let (a, _) = read_cache_file("prov-a", &key_a, DEFAULT_MAX_CACHE_AGE)
                .unwrap()
                .unwrap();
            let (b, _) = read_cache_file("prov-b", &key_b, DEFAULT_MAX_CACHE_AGE)
                .unwrap()
                .unwrap();
            assert_eq!(a.as_slice(), b"data-a");
            assert_eq!(b.as_slice(), b"data-b");
        });
    }

    #[test]
    fn large_blob_roundtrip() {
        with_tmp_home(|| {
            let key = derive_cache_key(&test_machine_key(), "pw", "prov").unwrap();
            // ~1 MB blob to simulate a real vault cache.
            let large = vec![0xABu8; 1_000_000];
            write_cache_file("prov", &key, &large).unwrap();
            let (recovered, _) = read_cache_file("prov", &key, DEFAULT_MAX_CACHE_AGE)
                .unwrap()
                .unwrap();
            assert_eq!(recovered.as_slice(), large.as_slice());
        });
    }
}
