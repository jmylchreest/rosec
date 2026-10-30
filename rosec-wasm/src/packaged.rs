//! Explicit package-manager trust, fixed when the host is compiled.
//!
//! No runtime environment variable or directory ownership grants trust. Both
//! files must match the embedded hashes at the exact embedded path. The package
//! manager authenticates the host and its dependencies as a single closure.

use crate::discovery::PluginBundle;
use sha2::{Digest, Sha256};

pub(crate) struct PackagedProvider<'a> {
    pub path: &'a str,
    pub wasm_sha256: &'a str,
    pub policy_sha256: &'a str,
}

pub(crate) const PROVIDERS: &[PackagedProvider<'static>] =
    include!(concat!(env!("OUT_DIR"), "/packaged_providers.rs"));

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn verify(
    bundle: &PluginBundle,
    entries: &[PackagedProvider<'_>],
) -> Result<bool, String> {
    let Some(entry) = entries
        .iter()
        .find(|entry| bundle.wasm_path == std::path::Path::new(entry.path))
    else {
        return Ok(false);
    };
    if sha256_hex(&bundle.wasm_bytes) != entry.wasm_sha256
        || sha256_hex(&bundle.policy_bytes) != entry.policy_sha256
    {
        return Err(format!(
            "packaged provider hash mismatch: {}",
            bundle.wasm_path.display()
        ));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_trust_binds_path_and_both_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.wasm");
        std::fs::write(&path, b"test wasm").unwrap();
        std::fs::write(
            crate::discovery::policy_path_for(&path),
            b"schema_version = 1\nkind = 'test'\nname = 'Test'\n",
        )
        .unwrap();
        let mut bundle = PluginBundle::load(&path).unwrap();
        let wasm_hash = sha256_hex(&bundle.wasm_bytes);
        let policy_hash = sha256_hex(&bundle.policy_bytes);
        let entries = [PackagedProvider {
            path: path.to_str().unwrap(),
            wasm_sha256: &wasm_hash,
            policy_sha256: &policy_hash,
        }];
        assert!(verify(&bundle, &entries).unwrap());
        assert!(!verify(&bundle, &[]).unwrap());
        bundle.wasm_bytes.push(0);
        assert!(verify(&bundle, &entries).is_err());
        bundle.wasm_bytes.pop();
        bundle.policy_bytes.push(b'\n');
        assert!(verify(&bundle, &entries).is_err());
        bundle.policy_bytes.pop();
        bundle.wasm_path = dir.path().join("copy.wasm");
        assert!(!verify(&bundle, &entries).unwrap());
        // A copy still requires a signature under the ordinary trust policy.
        assert!(bundle.verify_signature_trusted(&[]).is_err());
    }
}
