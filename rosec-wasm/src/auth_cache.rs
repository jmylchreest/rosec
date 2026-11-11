//! Small, separately encrypted provider authentication records.
//!
//! This store never reads the offline vault cache. It reuses the authenticated
//! encryption envelope with a distinct KDF domain and directory. Guests own
//! their auth-only schema; the host enforces size and expiry bounds.

use crate::cache::{self, CacheKey, StoreKind};
use crate::protocol::ExportAuthStateResponse;
use rosec_core::ProviderError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub const MAX_AGE_SECS: u64 = 30 * 86400;
pub const MAX_STATE_B64_BYTES: usize = 16 * 1024;

pub(crate) fn derive_key(
    machine: &[u8],
    password: &str,
    id: &str,
) -> Result<CacheKey, ProviderError> {
    cache::derive_store_key(machine, password, id, StoreKind::Auth)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn load_for_unlock(
    id: &str,
    key: &CacheKey,
    max_age_secs: u64,
) -> Result<(bool, Option<Zeroizing<String>>), ProviderError> {
    let Some((bytes, written_at)) =
        cache::read_store_file(id, key, Duration::ZERO, StoreKind::Auth)?
    else {
        return Ok((false, None));
    };
    // Check age after authenticated decryption: expiry may then safely trigger
    // deletion even when the following login needs a fresh second factor.
    if max_age_secs == 0
        || !SystemTime::now()
            .duration_since(written_at)
            .ok()
            .is_some_and(|age| age.as_secs() < max_age_secs.min(MAX_AGE_SECS))
    {
        return Ok((true, None));
    }
    let record: ExportAuthStateResponse = serde_json::from_slice(&bytes)
        .map_err(|_| ProviderError::Unavailable("Invalid provider auth state".into()))?;
    let (Some(state), Some(expiry)) = (record.state_b64, record.expires_at_epoch_secs) else {
        return Err(ProviderError::Unavailable(
            "Incomplete provider auth state".into(),
        ));
    };
    if state.len() > MAX_STATE_B64_BYTES {
        return Err(ProviderError::Unavailable(
            "Provider auth state too large".into(),
        ));
    }
    if expiry <= now() {
        return Ok((true, None));
    }
    Ok((true, Some(state)))
}

pub(crate) fn save(
    id: &str,
    key: &CacheKey,
    record: &ExportAuthStateResponse,
    max_age_secs: u64,
) -> Result<(), ProviderError> {
    let Some(state) = &record.state_b64 else {
        clear(id)?;
        return Ok(());
    };
    let now = now();
    if state.is_empty()
        || state.len() > MAX_STATE_B64_BYTES
        || !record.expires_at_epoch_secs.is_some_and(|expiry| {
            expiry > now && expiry <= now.saturating_add(max_age_secs.min(MAX_AGE_SECS))
        })
    {
        return Err(ProviderError::Unavailable(
            "Invalid provider auth state bounds".into(),
        ));
    }
    let bytes = Zeroizing::new(
        serde_json::to_vec(record)
            .map_err(|_| ProviderError::Unavailable("Cannot encode provider auth state".into()))?,
    );
    cache::write_store_file(id, key, &bytes, StoreKind::Auth)?;
    Ok(())
}

/// Apply a guest update without allowing a failed password to erase credentials.
pub(crate) fn apply_update(
    id: &str,
    key: &CacheKey,
    record: &ExportAuthStateResponse,
    max_age_secs: u64,
    login_ok: bool,
    authenticated: bool,
) -> Result<(), ProviderError> {
    if !login_ok && (!authenticated || record.state_b64.is_some()) {
        return Ok(());
    }
    save(id, key, record, max_age_secs)
}

/// Remove only provider authentication state, leaving the offline vault untouched.
pub fn clear(id: &str) -> Result<bool, ProviderError> {
    cache::delete_store_file(id, StoreKind::Auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isolated(f: impl FnOnce()) {
        let _guard = crate::TEST_ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("XDG_DATA_HOME");
        unsafe {
            std::env::set_var("XDG_DATA_HOME", tmp.path());
        }
        f();
        unsafe {
            match previous {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }
    }
    fn load(
        id: &str,
        key: &CacheKey,
        max_age_secs: u64,
    ) -> Result<Option<Zeroizing<String>>, ProviderError> {
        load_for_unlock(id, key, max_age_secs).map(|(_, state)| state)
    }

    fn record() -> ExportAuthStateResponse {
        ExportAuthStateResponse {
            state_b64: Some(Zeroizing::new("auth-only-token".into())),
            expires_at_epoch_secs: Some(now() + 3600),
        }
    }

    #[test]
    fn independent_store_never_reads_or_changes_vault_data() {
        isolated(|| {
            let machine = [42; 32];
            let vault_key = cache::derive_cache_key(&machine, "pw", "provider").unwrap();
            let auth_key = derive_key(&machine, "pw", "provider").unwrap();
            cache::write_cache_file("provider", &vault_key, b"VAULT-PASSWORD-MARKER").unwrap();
            assert!(load("provider", &auth_key, MAX_AGE_SECS).unwrap().is_none());
            assert!(
                !load_for_unlock("provider", &auth_key, MAX_AGE_SECS)
                    .unwrap()
                    .0
            );
            save("provider", &auth_key, &record(), MAX_AGE_SECS).unwrap();
            assert_eq!(
                load("provider", &auth_key, MAX_AGE_SECS)
                    .unwrap()
                    .unwrap()
                    .as_str(),
                "auth-only-token"
            );
            // The KDF purposes differ even for identical provider/password/machine.
            assert!(
                cache::read_store_file("provider", &vault_key, Duration::ZERO, StoreKind::Auth)
                    .is_err()
            );
            assert!(cache::read_cache_file("provider", &auth_key, Duration::ZERO).is_err());
            clear("provider").unwrap();
            assert!(load("provider", &auth_key, MAX_AGE_SECS).unwrap().is_none());
            assert_eq!(
                cache::read_cache_file("provider", &vault_key, Duration::ZERO)
                    .unwrap()
                    .unwrap()
                    .0
                    .as_slice(),
                b"VAULT-PASSWORD-MARKER"
            );
        });
    }

    #[test]
    fn wrong_password_machine_provider_and_tampering_fail() {
        isolated(|| {
            let good = derive_key(&[42; 32], "pw", "a").unwrap();
            save("a", &good, &record(), MAX_AGE_SECS).unwrap();
            for bad in [
                derive_key(&[42; 32], "wrong", "a").unwrap(),
                derive_key(&[7; 32], "pw", "a").unwrap(),
                derive_key(&[42; 32], "pw", "b").unwrap(),
            ] {
                assert!(load("a", &bad, MAX_AGE_SECS).is_err());
            }
            // Failed reads did not erase the valid record.
            assert!(load("a", &good, MAX_AGE_SECS).unwrap().is_some());
            let path = cache::store_file_path("a", StoreKind::Auth).unwrap();
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[30] ^= 1;
            std::fs::write(path, bytes).unwrap();
            assert!(load("a", &good, MAX_AGE_SECS).is_err());
        });
    }

    #[test]
    fn expired_records_and_deletion_are_independent_of_login_success() {
        isolated(|| {
            let key = derive_key(&[42; 32], "pw", "a").unwrap();
            let expired = ExportAuthStateResponse {
                state_b64: Some(Zeroizing::new("expired".into())),
                expires_at_epoch_secs: Some(now() - 1),
            };
            let bytes = Zeroizing::new(serde_json::to_vec(&expired).unwrap());
            cache::write_store_file("a", &key, &bytes, StoreKind::Auth).unwrap();
            assert!(load("a", &key, MAX_AGE_SECS).unwrap().is_none());
            save(
                "a",
                &key,
                &ExportAuthStateResponse {
                    state_b64: None,
                    expires_at_epoch_secs: None,
                },
                MAX_AGE_SECS,
            )
            .unwrap();
            assert!(
                !cache::store_file_path("a", StoreKind::Auth)
                    .unwrap()
                    .exists()
            );
        });
    }

    #[test]
    fn size_expiry_and_file_permissions_are_bounded() {
        isolated(|| {
            let key = derive_key(&[42; 32], "pw", "a").unwrap();
            let mut r = record();
            r.expires_at_epoch_secs = Some(now() + MAX_AGE_SECS + 100);
            assert!(save("a", &key, &r, MAX_AGE_SECS).is_err());
            r = record();
            r.state_b64 = Some(Zeroizing::new("x".repeat(MAX_STATE_B64_BYTES + 1)));
            assert!(save("a", &key, &r, MAX_AGE_SECS).is_err());
            save("a", &key, &record(), MAX_AGE_SECS).unwrap();
            let path = cache::store_file_path("a", StoreKind::Auth).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
            file.set_len(25 * 1024).unwrap();
            assert!(load("a", &key, MAX_AGE_SECS).is_err());
        });
    }
    #[test]
    fn failed_login_deletes_rejected_token_but_wrong_password_cannot() {
        isolated(|| {
            let key = derive_key(&[42; 32], "pw", "a").unwrap();
            let wrong = derive_key(&[42; 32], "wrong", "a").unwrap();
            save("a", &key, &record(), MAX_AGE_SECS).unwrap();
            let clear = ExportAuthStateResponse {
                state_b64: None,
                expires_at_epoch_secs: None,
            };
            apply_update("a", &wrong, &clear, MAX_AGE_SECS, false, false).unwrap();
            assert!(load("a", &key, MAX_AGE_SECS).unwrap().is_some());
            let replacement = ExportAuthStateResponse {
                state_b64: Some(Zeroizing::new("replacement".into())),
                expires_at_epoch_secs: Some(now() + 60),
            };
            apply_update("a", &key, &replacement, MAX_AGE_SECS, false, true).unwrap();
            assert_eq!(
                load("a", &key, MAX_AGE_SECS).unwrap().unwrap().as_str(),
                "auth-only-token"
            );
            // A server rejection after an authenticated read must persist deletion,
            // even though the overall unlock response is a 2FA challenge.
            apply_update("a", &key, &clear, MAX_AGE_SECS, false, true).unwrap();
            assert!(load("a", &key, MAX_AGE_SECS).unwrap().is_none());
            // A successful fresh login can replace a corrupt/old-password record.
            apply_update("a", &key, &replacement, MAX_AGE_SECS, true, false).unwrap();
            assert_eq!(
                load("a", &key, MAX_AGE_SECS).unwrap().unwrap().as_str(),
                "replacement"
            );
        });
    }

    #[test]
    fn online_unlock_payload_excludes_offline_vault_and_redacts_auth_state() {
        isolated(|| {
            let key = derive_key(&[42; 32], "pw", "a").unwrap();
            // The offline cache is deliberately unreadable. Auth transport must
            // work independently and must not touch or send this sentinel.
            let vault_path = cache::store_file_path("a", StoreKind::Vault).unwrap();
            std::fs::create_dir_all(vault_path.parent().unwrap()).unwrap();
            std::fs::write(&vault_path, b"VAULT-PASSWORD-MARKER").unwrap();
            save("a", &key, &record(), MAX_AGE_SECS).unwrap();
            let req = crate::protocol::UnlockRequest {
                password: "master".into(),
                registration_fields: None,
                auth_fields: None,
                auth_state_b64: load("a", &key, MAX_AGE_SECS).unwrap(),
            };
            let wire = Zeroizing::new(serde_json::to_string(&req).unwrap());
            assert!(wire.contains("auth-only-token"));
            assert!(!wire.contains("VAULT-PASSWORD-MARKER"));
            assert!(!wire.contains("cache_blob_b64"));
            assert!(!format!("{req:?}").contains("auth-only-token"));
            assert_eq!(std::fs::read(vault_path).unwrap(), b"VAULT-PASSWORD-MARKER");
        });
    }
}
