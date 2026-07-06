//! `rosec-package-wasm` — author-side packaging for rosec WASM provider
//! plugins.
//!
//! A distributable plugin is a bundle of three files:
//!
//! - `foo.wasm` — the provider module
//! - `foo.wasm.policy.toml` — the signed policy sidecar (network/filesystem
//!   surface, required/optional options)
//! - `foo.wasm.minisig` — one minisign signature over
//!   `(wasm_bytes || policy_bytes)`, so substituting either file
//!   invalidates it
//!
//! This tool validates the policy schema, produces the combined signature
//! with an rsign/minisign secret key, and verifies existing bundles. Signing
//! never rebuilds the `.wasm`, so pointing `sign` at an existing bundle
//! directory with a new key is the key-rotation flow.
//!
//! See `docs/docs/developers/wasm-policy-sidecar.md` for the trust model.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use minisign::{KeyPair, PublicKey, SecretKey, SecretKeyBox};

use rosec_wasm::discovery::{PluginBundle, policy_path_for, signature_path_for};
use rosec_wasm::keys::WASM_SIGNING_PUBKEYS;
use rosec_wasm::policy;

/// Env var holding the *contents* of an rsign/minisign secret-key file
/// (same contract as the old `just sign-wasm` recipe / CI secret).
const KEY_ENV: &str = "WASM_SIGNING_KEY";

/// Env var holding the secret-key password for non-interactive signing.
/// An empty value means "no password" (keys generated with `--no-password`
/// or `rsign generate -W`).
const KEY_PASSWORD_ENV: &str = "WASM_SIGNING_KEY_PASSWORD";

#[derive(Parser)]
#[command(
    name = "rosec-package-wasm",
    version,
    about = "Package, sign, and verify rosec WASM provider plugins",
    long_about = "Package, sign, and verify rosec WASM provider plugin bundles \
                  (.wasm + .wasm.policy.toml + .wasm.minisig).\n\n\
                  The signature covers (wasm_bytes || policy_bytes): substituting \
                  either file invalidates it. Users verify with the public key \
                  embedded in their rosec build."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new minisign signing keypair
    #[command(after_long_help = "\
EXAMPLES:
    rosec-package-wasm keygen --output-dir ~/keys
    rosec-package-wasm keygen --output-dir . --no-password   # CI-friendly, like 'rsign generate -W'")]
    Keygen(KeygenArgs),

    /// Validate policy sidecars and sign .wasm bundles (also the key-rotation flow)
    #[command(after_long_help = "\
The policy sidecar <plugin>.wasm.policy.toml must sit next to each .wasm and
is schema-validated before anything is signed.

Signing re-signs existing artefacts without rebuilding them, so rotating to a
new key is just:

    rosec-package-wasm sign --key new.key dist/providers/

EXAMPLES:
    rosec-package-wasm sign --key rosec-wasm-signing.key target/wasm32-wasip1/release/foo.wasm
    rosec-package-wasm sign --key new.key dist/providers/            # key rotation over a directory
    WASM_SIGNING_KEY=\"$(cat signing.key)\" rosec-package-wasm sign --output-dir dist/providers foo.wasm")]
    Sign(SignArgs),

    /// Verify bundle signatures (defaults to the embedded rosec release key)
    #[command(after_long_help = "\
EXAMPLES:
    rosec-package-wasm verify dist/providers/
    rosec-package-wasm verify --pubkey my-signing.pub foo.wasm")]
    Verify(VerifyArgs),
}

#[derive(Parser)]
struct KeygenArgs {
    /// Directory to write the keypair into
    #[arg(long, default_value = ".")]
    output_dir: PathBuf,

    /// Basename for the generated files (<prefix>.key / <prefix>.pub)
    #[arg(long, default_value = "rosec-wasm-signing")]
    prefix: String,

    /// Generate an unencrypted secret key (no password prompt); equivalent
    /// to 'rsign generate -W'. Intended for keys stored in a CI secret.
    #[arg(long)]
    no_password: bool,

    /// Overwrite existing key files
    #[arg(long)]
    force: bool,
}

#[derive(Parser)]
struct SignArgs {
    /// Secret-key file (rsign/minisign format); falls back to the
    /// WASM_SIGNING_KEY env var holding the file's contents
    #[arg(long)]
    key: Option<PathBuf>,

    /// The secret key has no password (skip prompt); WASM_SIGNING_KEY_PASSWORD
    /// is consulted otherwise before prompting interactively
    #[arg(long)]
    no_password: bool,

    /// Stage signed bundles (.wasm + .wasm.policy.toml + .wasm.minisig)
    /// into this directory instead of signing in place
    #[arg(long)]
    output_dir: Option<PathBuf>,

    /// .wasm files or directories containing them (directories are scanned
    /// non-recursively, like the daemon's provider discovery)
    #[arg(required = true)]
    paths: Vec<PathBuf>,
}

#[derive(Parser)]
struct VerifyArgs {
    /// Public key to verify against: a .pub file path or the base64 key
    /// string itself. Defaults to the rosec release key embedded in this
    /// build — the same key the rosec daemon enforces.
    #[arg(long)]
    pubkey: Option<String>,

    /// .wasm files or directories containing them
    #[arg(required = true)]
    paths: Vec<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Keygen(args) => keygen(&args),
        Command::Sign(args) => sign(&args),
        Command::Verify(args) => verify(&args),
    };
    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn keygen(args: &KeygenArgs) -> Result<()> {
    let key_path = args.output_dir.join(format!("{}.key", args.prefix));
    let pub_path = args.output_dir.join(format!("{}.pub", args.prefix));
    if !args.force {
        for p in [&key_path, &pub_path] {
            if p.exists() {
                bail!("{} already exists (use --force to overwrite)", p.display());
            }
        }
    }
    std::fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("creating {}", args.output_dir.display()))?;

    let password = if args.no_password {
        String::new()
    } else {
        prompt_new_password()?
    };
    // An empty password produces an unencrypted (CI-friendly) key; the
    // "encrypted" generator is still required because it is the one that
    // writes the key checksum serialization depends on.
    let keypair = KeyPair::generate_encrypted_keypair(Some(password))
        .map_err(|e| anyhow::anyhow!("keypair generation failed: {e}"))?;

    let comment = format!("rosec WASM plugin signing key: {}", args.prefix);
    let sk_box = keypair
        .sk
        .to_box(Some(&comment))
        .map_err(|e| anyhow::anyhow!("serializing secret key: {e}"))?;
    let pk_box = keypair
        .pk
        .to_box()
        .map_err(|e| anyhow::anyhow!("serializing public key: {e}"))?;

    write_private(&key_path, sk_box.into_string().as_bytes())?;
    std::fs::write(&pub_path, pk_box.into_string())
        .with_context(|| format!("writing {}", pub_path.display()))?;

    println!("secret key: {}", key_path.display());
    println!(
        "public key: {}  ({})",
        pub_path.display(),
        keypair.pk.to_base64()
    );
    println!();
    println!("Sign plugin bundles with:");
    println!(
        "  rosec-package-wasm sign --key {} <plugin>.wasm",
        key_path.display()
    );
    println!();
    println!(
        "Note: stock rosec builds only load plugins signed by an embedded release key.\n\
         Users of your plugin must add your public key as a trust anchor in their\n\
         rosec config:\n\
         \n\
           [[service.wasm_trusted_key]]\n\
           key   = \"{}\"\n\
           name  = \"{}\"\n\
           kinds = [\"<your plugin kind>\"]",
        keypair.pk.to_base64(),
        args.prefix,
    );
    Ok(())
}

fn sign(args: &SignArgs) -> Result<()> {
    let sk = load_secret_key(args.key.as_deref(), args.no_password)?;
    let pk = PublicKey::from_secret_key(&sk)
        .map_err(|e| anyhow::anyhow!("deriving public key from secret key: {e}"))?;

    let wasm_files = collect_wasm_files(&args.paths)?;

    if let Some(dir) = &args.output_dir {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }

    for wasm_src in &wasm_files {
        // Validates policy presence + schema before anything is signed.
        let bundle = PluginBundle::load(wasm_src).map_err(anyhow::Error::msg)?;

        // Stage into --output-dir when given (release layout), else in place.
        let wasm_dst = match &args.output_dir {
            Some(dir) => {
                let file_name = wasm_src.file_name().context("wasm path has no file name")?;
                let dst = dir.join(file_name);
                std::fs::copy(wasm_src, &dst)
                    .with_context(|| format!("staging {}", dst.display()))?;
                std::fs::copy(&bundle.policy_path, policy_path_for(&dst))
                    .with_context(|| format!("staging {}", policy_path_for(&dst).display()))?;
                dst
            }
            None => wasm_src.clone(),
        };

        let trusted_comment = format!(
            "rosec-wasm-bundle kind={} version={} file={}",
            bundle.policy.kind,
            bundle.policy.version.as_deref().unwrap_or("unversioned"),
            wasm_dst
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
        let combined = policy::signature_input(&bundle.wasm_bytes, &bundle.policy_bytes);
        // Passing the public key makes minisign self-verify the fresh signature.
        let sig_box = minisign::sign(
            Some(&pk),
            &sk,
            combined.as_slice(),
            Some(&trusted_comment),
            None,
        )
        .map_err(|e| anyhow::anyhow!("signing {}: {e}", wasm_dst.display()))?;

        let sig_path = signature_path_for(&wasm_dst);
        std::fs::write(&sig_path, sig_box.to_string())
            .with_context(|| format!("writing {}", sig_path.display()))?;

        println!(
            "signed: {} (kind={}, policy={}, sig={})",
            wasm_dst.display(),
            bundle.policy.kind,
            policy_path_for(&wasm_dst).display(),
            sig_path.display(),
        );
    }

    if !WASM_SIGNING_PUBKEYS.contains(&pk.to_base64().as_str()) {
        eprintln!(
            "note: signed with a key that is NOT a rosec release key; stock rosec \
             builds will reject these bundles unless users add your public key \
             ({}) as a [[service.wasm_trusted_key]] entry in their rosec config.",
            pk.to_base64(),
        );
    }

    Ok(())
}

fn verify(args: &VerifyArgs) -> Result<()> {
    let (pubkey_base64, key_desc) = match &args.pubkey {
        Some(raw) => (Some(resolve_pubkey(raw)?), "supplied key"),
        None => (None, "embedded rosec release key(s)"),
    };

    let wasm_files = collect_wasm_files(&args.paths)?;
    let mut failures = 0usize;
    for wasm_path in &wasm_files {
        match PluginBundle::load(wasm_path).and_then(|b| {
            match &pubkey_base64 {
                Some(key) => b.verify_signature_with(key),
                None => b.verify_signature(),
            }
            .map(|()| b)
        }) {
            Ok(bundle) => println!(
                "ok: {} (kind={}, version={}) — signature valid against {key_desc}",
                wasm_path.display(),
                bundle.policy.kind,
                bundle.policy.version.as_deref().unwrap_or("unversioned"),
            ),
            Err(reason) => {
                failures += 1;
                eprintln!("FAILED: {} — {reason}", wasm_path.display());
            }
        }
    }

    if failures > 0 {
        bail!(
            "{failures} of {} bundle(s) failed verification",
            wasm_files.len()
        );
    }
    println!("{} bundle(s) verified", wasm_files.len());
    Ok(())
}

/// Expand the CLI path arguments into a sorted list of `.wasm` files.
/// Directories are scanned non-recursively, mirroring provider discovery.
fn collect_wasm_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for p in paths {
        if p.is_dir() {
            let mut found = Vec::new();
            for entry in std::fs::read_dir(p).with_context(|| format!("reading {}", p.display()))? {
                let path = entry?.path();
                if path.extension().and_then(|e| e.to_str()) == Some("wasm") {
                    found.push(path);
                }
            }
            if found.is_empty() {
                bail!("no .wasm files found in directory {}", p.display());
            }
            found.sort();
            files.extend(found);
        } else if p.extension().and_then(|e| e.to_str()) == Some("wasm") {
            files.push(p.clone());
        } else {
            bail!(
                "{} is not a .wasm file or a directory (policy/sig sidecars are \
                 located automatically from the .wasm path)",
                p.display()
            );
        }
    }
    Ok(files)
}

/// Load the signing key from `--key <file>` or the `WASM_SIGNING_KEY` env
/// var (file contents), decrypting with, in order: `--no-password`,
/// `WASM_SIGNING_KEY_PASSWORD`, or an interactive prompt.
fn load_secret_key(key_file: Option<&Path>, no_password: bool) -> Result<SecretKey> {
    let contents = match key_file {
        Some(p) => std::fs::read_to_string(p)
            .with_context(|| format!("reading secret key {}", p.display()))?,
        None => std::env::var(KEY_ENV).map_err(|_| {
            anyhow::anyhow!(
                "no --key given and {KEY_ENV} is not set; export {KEY_ENV}=\"$(cat \
                 path/to/signing.key)\" or pass --key"
            )
        })?,
    };
    let sk_box = SecretKeyBox::from_string(&contents)
        .map_err(|e| anyhow::anyhow!("parsing secret key: {e}"))?;

    let password = if no_password {
        Some(String::new())
    } else if let Ok(p) = std::env::var(KEY_PASSWORD_ENV) {
        Some(p)
    } else if std::io::stdin().is_terminal() {
        None // minisign prompts interactively
    } else {
        // Headless with no password source: try "no password" rather than
        // hanging on a prompt that can never be answered.
        Some(String::new())
    };

    sk_box
        .into_secret_key(password)
        .map_err(|e| anyhow::anyhow!("decrypting secret key: {e}"))
}

/// Accept either a `.pub` file path or a raw base64 minisign public key.
fn resolve_pubkey(raw: &str) -> Result<String> {
    let path = Path::new(raw);
    if path.exists() {
        let pk = PublicKey::from_file(path)
            .map_err(|e| anyhow::anyhow!("reading public key {}: {e}", path.display()))?;
        return Ok(pk.to_base64());
    }
    // Validate the base64 form early for a friendly error.
    PublicKey::from_base64(raw).map_err(|e| {
        anyhow::anyhow!(
            "'{raw}' is neither a readable file nor a valid base64 minisign public key: {e}"
        )
    })?;
    Ok(raw.to_string())
}

fn prompt_new_password() -> Result<String> {
    let password = rpassword::prompt_password("Password for the new secret key (empty for none): ")
        .context("reading password")?;
    if password.is_empty() {
        return Ok(password);
    }
    let confirm = rpassword::prompt_password("Confirm password: ").context("reading password")?;
    if password != confirm {
        bail!("passwords do not match");
    }
    Ok(password)
}

/// Write a secret-key file with owner-only permissions.
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut f = opts
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    std::io::Write::write_all(&mut f, contents)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_bundle(dir: &Path, stem: &str, kind: &str) -> PathBuf {
        let wasm = dir.join(format!("{stem}.wasm"));
        std::fs::write(&wasm, b"\0asm-fake-module").unwrap();
        std::fs::write(
            policy_path_for(&wasm),
            format!("schema_version = 1\nkind = \"{kind}\"\nname = \"Test\"\n"),
        )
        .unwrap();
        wasm
    }

    fn sign_bundle(wasm: &Path, sk: &SecretKey, pk: &PublicKey) {
        let bundle = PluginBundle::load(wasm).unwrap();
        let combined = policy::signature_input(&bundle.wasm_bytes, &bundle.policy_bytes);
        let sig = minisign::sign(Some(pk), sk, combined.as_slice(), None, None).unwrap();
        std::fs::write(signature_path_for(wasm), sig.to_string()).unwrap();
    }

    #[test]
    fn sign_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let wasm = write_bundle(dir.path(), "test_plugin", "test");
        let kp = KeyPair::generate_unencrypted_keypair().unwrap();
        sign_bundle(&wasm, &kp.sk, &kp.pk);

        let bundle = PluginBundle::load(&wasm).unwrap();
        bundle
            .verify_signature_with(&kp.pk.to_base64())
            .expect("fresh signature must verify");
    }

    #[test]
    fn tampered_policy_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let wasm = write_bundle(dir.path(), "test_plugin", "test");
        let kp = KeyPair::generate_unencrypted_keypair().unwrap();
        sign_bundle(&wasm, &kp.sk, &kp.pk);

        // Tamper: policy grants an extra host after signing.
        std::fs::write(
            policy_path_for(&wasm),
            "schema_version = 1\nkind = \"test\"\nname = \"Test\"\n[network]\nallowed_hosts = [\"evil.example\"]\n",
        )
        .unwrap();

        let bundle = PluginBundle::load(&wasm).unwrap();
        assert!(bundle.verify_signature_with(&kp.pk.to_base64()).is_err());
    }

    #[test]
    fn tampered_wasm_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let wasm = write_bundle(dir.path(), "test_plugin", "test");
        let kp = KeyPair::generate_unencrypted_keypair().unwrap();
        sign_bundle(&wasm, &kp.sk, &kp.pk);

        std::fs::write(&wasm, b"\0asm-DIFFERENT-module").unwrap();

        let bundle = PluginBundle::load(&wasm).unwrap();
        assert!(bundle.verify_signature_with(&kp.pk.to_base64()).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let wasm = write_bundle(dir.path(), "test_plugin", "test");
        let kp = KeyPair::generate_unencrypted_keypair().unwrap();
        sign_bundle(&wasm, &kp.sk, &kp.pk);

        let other = KeyPair::generate_unencrypted_keypair().unwrap();
        let bundle = PluginBundle::load(&wasm).unwrap();
        assert!(bundle.verify_signature_with(&other.pk.to_base64()).is_err());
    }

    #[test]
    fn invalid_policy_schema_blocks_signing() {
        let dir = tempfile::tempdir().unwrap();
        let wasm = dir.path().join("bad.wasm");
        std::fs::write(&wasm, b"\0asm").unwrap();
        std::fs::write(
            policy_path_for(&wasm),
            "schema_version = 99\nkind = \"bad\"\nname = \"Bad\"\n",
        )
        .unwrap();
        assert!(PluginBundle::load(&wasm).is_err());
    }

    #[test]
    fn collect_wasm_files_expands_directories() {
        let dir = tempfile::tempdir().unwrap();
        write_bundle(dir.path(), "b_plugin", "b");
        write_bundle(dir.path(), "a_plugin", "a");
        let files = collect_wasm_files(&[dir.path().to_path_buf()]).unwrap();
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["a_plugin.wasm", "b_plugin.wasm"]);
    }
}
