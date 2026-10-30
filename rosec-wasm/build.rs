use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=ROSEC_PACKAGED_PROVIDERS");
    let mut generated = String::from("&[\n");
    if let Some(path) = env::var_os("ROSEC_PACKAGED_PROVIDERS") {
        println!("cargo:rerun-if-changed={}", PathBuf::from(&path).display());
        let bytes = fs::read(path).expect("read ROSEC_PACKAGED_PROVIDERS manifest");
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&bytes)
            .expect("packaged provider manifest must be a JSON array");
        let mut paths = std::collections::HashSet::new();
        for entry in entries {
            let field = |name: &str| {
                entry[name]
                    .as_str()
                    .unwrap_or_else(|| panic!("packaged provider missing string field {name}"))
            };
            let path = field("path");
            assert!(
                PathBuf::from(path).is_absolute(),
                "provider path must be absolute"
            );
            assert!(paths.insert(path.to_owned()), "duplicate provider path");
            let wasm = field("wasm_sha256");
            let policy = field("policy_sha256");
            for digest in [wasm, policy] {
                assert!(
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "provider hashes must be lowercase SHA-256 hex"
                );
            }
            generated.push_str(&format!(
                "PackagedProvider {{ path: {path:?}, wasm_sha256: {wasm:?}, policy_sha256: {policy:?} }},\n"
            ));
        }
    }
    generated.push_str("]\n");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("packaged_providers.rs"),
        generated,
    )
    .expect("write packaged provider trust manifest");
}
