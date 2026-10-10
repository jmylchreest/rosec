//! Regenerate synthetic encrypted fixtures: cargo run --example totp_fixture
//! --manifest-path rosec-keepassxc-file/Cargo.toml --features fixture-generation
use std::{fs::File, path::Path};

use keepass::{Database, DatabaseKey, config::KdfConfig, db::fields};

fn main() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rosec-wasm/tests/fixtures");
    std::fs::create_dir_all(&directory).unwrap();
    let mut db = Database::new();
    // Synthetic data only; deliberately cheap KDF for tests.
    db.config.kdf_config = KdfConfig::Aes { rounds: 10 };
    let uri = "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=8&period=30";
    let mut ids = Vec::new();
    for protected in [true, false] {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, format!("TOTP {protected}"));
        if protected {
            entry.set_protected(fields::OTP, uri);
        } else {
            entry.set_unprotected(fields::OTP, uri);
        }
        ids.push(entry.id());
    }
    db.root_mut()
        .add_entry()
        .set_unprotected(fields::TITLE, "No TOTP");
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, "Steam");
        entry.set_protected(fields::OTP, "otpauth://totp/test?secret=63BEDWCQZKTQWPESARIERL5DTTQFCJTK&issuer=Valve&algorithm=SHA1&digits=5&period=30&encoder=steam");
    }
    for (name, updated) in [("totp.kdbx", false), ("totp-updated.kdbx", true)] {
        if updated {
            db.entry_mut(ids[0]).unwrap().set_protected(
                fields::OTP,
                "otpauth://totp/Test:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=60",
            );
        }
        db.save(
            &mut File::create(directory.join(name)).unwrap(),
            DatabaseKey::new().with_password("test-password"),
        )
        .unwrap();
    }
}
