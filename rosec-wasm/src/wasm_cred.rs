//! Host-side credential persistence for WASM providers.
//!
//! WASM guests cannot access the filesystem, so the host persists
//! registration credentials on their behalf.  All registration fields
//! (e.g. `access_token` for SM, `client_id`/`client_secret` for PM) are
//! serialised to JSON and encrypted as a single blob.  This avoids baking
//! any assumption about which field names a given provider uses.
//!
//! Version 2 uses Argon2id (64 MiB, three passes, one lane), a random
//! 16-byte salt, the installation machine key as a secret, and HKDF provider
//! binding. The version/salt are stored in the existing envelope's client_id.
//! Version 1 is read only for migration after successful decryption.
//! Passwords and plaintext values are scrubbed on every exit path.

use std::collections::HashMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use rand::Rng;
use rosec_core::credential::{self, StorageKey};
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF salt — domain-separates WASM credential keys from other rosec keys.
const HKDF_SALT: &[u8] = b"rosec-wasm-cred-v1";

/// Sentinel stored as `client_id` to identify the v1 generic-fields format.
const FIELDS_V1_SENTINEL: &str = "__fields_v1__";

/// Derive a 64-byte `StorageKey` from the user's password and the provider ID.
fn derive_legacy_key(password: &str, provider_id: &str) -> Result<StorageKey, String> {
    let (_, hkdf) = Hkdf::<Sha256>::extract(Some(HKDF_SALT), password.as_bytes());

    let mut key_material = Zeroizing::new(vec![0u8; 64]);
    hkdf.expand(provider_id.as_bytes(), &mut key_material)
        .map_err(|e| format!("HKDF expand: {e}"))?;

    StorageKey::from_bytes(&key_material)
}

const FIELDS_V2_PREFIX: &str = "__fields_v2__:";
// All callers run on blocking threads. Bound aggregate Argon2 scratch memory
// when several providers are unlocked concurrently.
static KDF_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn derive_key(password: &str, provider_id: &str, salt: &[u8]) -> Result<StorageKey, String> {
    let _kdf_guard = KDF_LOCK.lock().map_err(|_| "Credential KDF unavailable")?;
    let machine = rosec_core::machine_key::load_or_create()?;
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(64))
        .map_err(|_| "Invalid credential KDF parameters")?;
    let block_count = params.block_count();
    let argon = argon2::Argon2::new_with_secret(
        &machine,
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    )
    .map_err(|_| "Invalid credential KDF secret")?;
    let mut stretched = Zeroizing::new(vec![0u8; 64]);
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); block_count]);
    argon
        .hash_password_into_with_memory(
            password.as_bytes(),
            salt,
            &mut stretched,
            memory.as_mut_slice(),
        )
        .map_err(|_| "Credential key derivation failed")?;
    let hkdf = Hkdf::<Sha256>::new(Some(b"rosec-wasm-cred-v2"), &stretched);
    let mut key = Zeroizing::new(vec![0u8; 64]);
    hkdf.expand(provider_id.as_bytes(), &mut key)
        .map_err(|_| "Credential key expansion failed")?;
    StorageKey::from_bytes(&key)
}

// Deserialize directly into guarded values so earlier fields are scrubbed if
// a later field is malformed. Serde's errors must never echo plaintext values.
#[derive(serde::Deserialize)]
#[serde(transparent)]
struct SecretField(#[serde(deserialize_with = "read_secret")] Zeroizing<String>);
fn read_secret<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    use serde::Deserialize;
    String::deserialize(d).map(Zeroizing::new)
}

/// Save all registration fields, encrypted with a key derived from the password.
///
/// The entire `fields` map is serialised as JSON and stored as a single
/// encrypted blob — no assumption is made about which keys are present.
pub fn save(
    provider_id: &str,
    password: &str,
    fields: &HashMap<String, Zeroizing<String>>,
) -> Result<(), String> {
    if password.is_empty() {
        return Err("Local passphrase required".into());
    }
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let key = derive_key(password, provider_id, &salt)?;
    let format = format!("{FIELDS_V2_PREFIX}{}", STANDARD.encode(salt));

    // Convert Zeroizing<String> values to plain &str for serialisation.
    let plain_map: HashMap<&str, &str> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let json = Zeroizing::new(
        serde_json::to_string(&plain_map).map_err(|e| format!("JSON serialise fields: {e}"))?,
    );

    credential::encrypt_and_save(provider_id, &key, &format, json.as_str())
}

/// Load and decrypt stored registration fields.
///
/// Returns `None` if no credential file exists for this provider.
/// Returns `Err` if the file exists but decryption fails (wrong password
/// or tampered data).
pub fn load(
    provider_id: &str,
    password: &str,
) -> Result<Option<HashMap<String, Zeroizing<String>>>, String> {
    let Some((format, encrypted)) = rosec_core::oauth::load_encrypted_checked(provider_id)? else {
        return Ok(None);
    };
    let legacy = format == FIELDS_V1_SENTINEL;
    let key = if legacy {
        derive_legacy_key(password, provider_id)?
    } else if let Some(encoded) = format.strip_prefix(FIELDS_V2_PREFIX) {
        if encoded.len() != 24 {
            return Err("Invalid credential salt".into());
        }
        let salt = STANDARD
            .decode(encoded)
            .map_err(|_| "Invalid credential salt")?;
        if salt.len() != 16 {
            return Err("Invalid credential salt".into());
        }
        derive_key(password, provider_id, &salt)?
    } else {
        return Err("Unsupported credential format; re-register provider".into());
    };
    let plaintext = credential::decrypt(&key, &encrypted)?;
    let fields: HashMap<String, SecretField> =
        serde_json::from_slice(&plaintext).map_err(|_| "Invalid credential fields")?;
    let fields: HashMap<_, _> = fields.into_iter().map(|(k, v)| (k, v.0)).collect();
    if legacy {
        save(provider_id, password, &fields)?;
    }
    Ok(Some(fields))
}

/// Delete stored credentials for a provider.
///
/// Called when a provider is removed or its registration is explicitly reset.
#[allow(dead_code)]
pub fn clear(provider_id: &str) -> Result<bool, String> {
    rosec_core::oauth::clear(provider_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn with_tmp_home(f: impl FnOnce()) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = env::temp_dir().join(format!("rosec-wasm-cred-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let _guard = crate::TEST_ENV_MUTEX.lock().unwrap();
        unsafe { env::set_var("XDG_DATA_HOME", &tmp) };
        f();
        unsafe { env::remove_var("XDG_DATA_HOME") };
        drop(_guard);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn fields(pairs: &[(&str, &str)]) -> HashMap<String, Zeroizing<String>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
            .collect()
    }

    #[test]
    fn roundtrip_access_token() {
        with_tmp_home(|| {
            let f = fields(&[("access_token", "tok123")]);
            save("sm-prov", "hunter2", &f).unwrap();
            let loaded = load("sm-prov", "hunter2").unwrap().unwrap();
            assert_eq!(loaded["access_token"].as_str(), "tok123");
        });
    }

    #[test]
    fn roundtrip_client_id_secret() {
        with_tmp_home(|| {
            let f = fields(&[("client_id", "user.abc"), ("client_secret", "s3cr3t")]);
            save("pm-prov", "hunter2", &f).unwrap();
            let loaded = load("pm-prov", "hunter2").unwrap().unwrap();
            assert_eq!(loaded["client_id"].as_str(), "user.abc");
            assert_eq!(loaded["client_secret"].as_str(), "s3cr3t");
        });
    }

    #[test]
    fn wrong_password_fails() {
        with_tmp_home(|| {
            let f = fields(&[("access_token", "tok")]);
            save("test-prov", "correctpass", &f).unwrap();
            assert!(load("test-prov", "wrongpass").is_err());
        });
    }

    #[test]
    fn different_providers_isolated() {
        with_tmp_home(|| {
            save("prov-a", "pass", &fields(&[("access_token", "tok-a")])).unwrap();
            save("prov-b", "pass", &fields(&[("access_token", "tok-b")])).unwrap();
            let a = load("prov-a", "pass").unwrap().unwrap();
            let b = load("prov-b", "pass").unwrap().unwrap();
            assert_eq!(a["access_token"].as_str(), "tok-a");
            assert_eq!(b["access_token"].as_str(), "tok-b");
        });
    }

    #[test]
    fn load_missing_returns_none() {
        with_tmp_home(|| {
            assert!(load("no-such", "pass").unwrap().is_none());
        });
    }

    #[test]
    fn legacy_credentials_migrate_only_with_correct_password() {
        with_tmp_home(|| {
            let key = derive_legacy_key("pass", "legacy").unwrap();
            credential::encrypt_and_save(
                "legacy",
                &key,
                FIELDS_V1_SENTINEL,
                r#"{"personal_access_token":"synthetic"}"#,
            )
            .unwrap();
            assert!(load("legacy", "wrong").is_err());
            assert_eq!(
                rosec_core::oauth::load_encrypted("legacy").unwrap().0,
                FIELDS_V1_SENTINEL
            );
            assert_eq!(
                load("legacy", "pass").unwrap().unwrap()["personal_access_token"].as_str(),
                "synthetic"
            );
            assert!(
                rosec_core::oauth::load_encrypted("legacy")
                    .unwrap()
                    .0
                    .starts_with(FIELDS_V2_PREFIX)
            );
            assert!(load("legacy", "pass").unwrap().is_some());
        });
    }

    #[test]
    fn replacement_password_and_token_invalidate_old_password() {
        with_tmp_home(|| {
            save(
                "rotation",
                "old",
                &fields(&[("personal_access_token", "old-token")]),
            )
            .unwrap();
            save(
                "rotation",
                "new",
                &fields(&[("personal_access_token", "new-token")]),
            )
            .unwrap();
            assert!(load("rotation", "old").is_err());
            assert_eq!(
                load("rotation", "new").unwrap().unwrap()["personal_access_token"].as_str(),
                "new-token"
            );
        });
    }

    #[test]
    fn installation_key_and_provider_are_bound() {
        with_tmp_home(|| {
            save("source", "pass", &fields(&[("token", "synthetic")])).unwrap();
            let (format, encrypted) = rosec_core::oauth::load_encrypted("source").unwrap();
            rosec_core::oauth::save_encrypted("other", &format, &encrypted).unwrap();
            assert!(load("other", "pass").is_err());
            let key_path = std::path::PathBuf::from(env::var_os("XDG_DATA_HOME").unwrap())
                .join("rosec/machine-key");
            std::fs::write(key_path, [42u8; 32]).unwrap();
            assert!(load("source", "pass").is_err());
        });
    }

    #[test]
    fn clear_removes_credential() {
        with_tmp_home(|| {
            let f = fields(&[("access_token", "tok")]);
            save("test-prov", "pass", &f).unwrap();
            assert!(load("test-prov", "pass").unwrap().is_some());
            assert!(clear("test-prov").unwrap());
            assert!(load("test-prov", "pass").unwrap().is_none());
        });
    }
}
