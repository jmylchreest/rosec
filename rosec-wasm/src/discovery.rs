//! Provider discovery — scan directories for `.wasm` provider plugins and build
//! a registry of available provider kinds.
//!
//! # Search paths
//!
//! Providers are discovered from two locations (in order):
//!
//! 1. **System-wide**: `/usr/lib/rosec/providers/` — for distro packages
//! 2. **User-local**: `$XDG_DATA_HOME/rosec/providers/` (default
//!    `~/.local/share/rosec/providers/`) — for user-installed providers
//!
//! If the same `kind` appears in both directories the user-local copy
//! takes precedence, allowing users to override system-installed providers.
//!
//! # Discovery protocol
//!
//! Each `.wasm` file is loaded as a temporary Extism plugin and its
//! `plugin_manifest` export is called (no `init` required).  The
//! returned [`PluginManifest`] describes the plugin's kind, name,
//! config requirements, and allowed hosts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::policy::{self, PluginPolicy};
use crate::protocol::{PluginManifest, PluginOptionDescriptor};
use extism::{Manifest, PluginBuilder, Wasm};
use minisign_verify::{PublicKey, Signature};
use rosec_core::{WasmPreference, WasmTrustedKey, WasmVerify};
use tracing::{debug, info, warn};

/// Bundle of files captured during scan: wasm bytes (after signature
/// verification) and the parsed policy sidecar. The policy is always
/// present — `disabled` mode only bypasses the cryptographic signature
/// check, never the declarative policy.
struct VerifiedPlugin {
    wasm_bytes: Vec<u8>,
    policy: PluginPolicy,
}

/// Maximum `.wasm` file size accepted during probing (10 MiB).
const MAX_WASM_SIZE_BYTES: u64 = 10 * 1024 * 1024;

/// Fuel limit for the `plugin_manifest` call during probing (per plugin instance).
/// 250K instructions — ~6× headroom over the most complex observed provider
/// (~37K instructions for bitwarden-pm).  Kills runaway code in the WASM
/// `start` section or `plugin_manifest` without affecting legitimate plugins.
const PROBE_FUEL_LIMIT: u64 = 250_000;

/// System-wide provider directory (for distro packages).
const SYSTEM_PLUGIN_DIR: &str = "/usr/lib/rosec/providers";

/// Subdirectory under `$XDG_DATA_HOME` for user-installed providers.
const USER_PLUGIN_SUBDIR: &str = "rosec/providers";

/// A discovered plugin: its manifest plus the resolved path to the
/// `.wasm` file.
#[derive(Debug, Clone)]
pub struct DiscoveredPlugin {
    /// Absolute path to the `.wasm` file.
    pub wasm_path: PathBuf,
    /// Raw `.wasm` bytes captured at discovery, after signature verification.
    /// Held in an `Arc` so the WasmProvider can share the same buffer without
    /// re-reading from disk (closing the verify-then-load TOCTOU window).
    pub wasm_bytes: Arc<Vec<u8>>,
    /// Signed policy sidecar declaring this plugin's network/filesystem
    /// surface. Always present — both `required` and `disabled` modes
    /// load the `.policy.toml`; `disabled` only skips the cryptographic
    /// signature check.
    pub policy: PluginPolicy,
    /// The manifest returned by `plugin_manifest()`.
    pub manifest: PluginManifest,
}

/// Registry of all discovered WASM plugins, keyed by kind.
#[derive(Debug, Clone, Default)]
pub struct PluginRegistry {
    plugins: HashMap<String, DiscoveredPlugin>,
}

impl PluginRegistry {
    pub fn get(&self, kind: &str) -> Option<&DiscoveredPlugin> {
        self.plugins.get(kind)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &DiscoveredPlugin)> {
        self.plugins.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Sorted for deterministic iteration.
    pub fn kinds(&self) -> Vec<&str> {
        let mut kinds: Vec<&str> = self.plugins.keys().map(String::as_str).collect();
        kinds.sort_unstable();
        kinds
    }

    pub fn contains_kind(&self, kind: &str) -> bool {
        self.plugins.contains_key(kind)
    }

    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

/// Which directory a discovered plugin came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PluginSource {
    System,
    User,
}

/// Scan the standard provider directories and return a registry of
/// discovered providers.
///
/// Search order:
/// 1. System-wide (`/usr/lib/rosec/providers/`)
/// 2. User-local (`$XDG_DATA_HOME/rosec/providers/`)
///
/// When the same kind appears in both directories, `preference` controls
/// which copy wins:
/// - `User` (default) — user-local always wins
/// - `System` — system copy always wins
/// - `Newest` — compare semver `version` fields; ties fall back to user-local
///
/// `verify` controls signature checking before probing each plugin.
/// `user_keys` are additional trust anchors from `[[service.wasm_trusted_key]]`,
/// consulted after the embedded release keys.
pub fn scan_plugins(
    preference: WasmPreference,
    verify: WasmVerify,
    user_keys: &[WasmTrustedKey],
) -> PluginRegistry {
    if verify == WasmVerify::Disabled {
        info!(
            "wasm_verify = \"disabled\" — WASM plugin signature verification is OFF. \
             Any .wasm in the provider directories will be loaded without authenticity \
             checks. Intended for local plugin development only."
        );
    }

    let mut registry = PluginRegistry::default();

    let system_dir = PathBuf::from(SYSTEM_PLUGIN_DIR);
    scan_directory(
        &system_dir,
        &mut registry,
        PluginSource::System,
        preference,
        verify,
        user_keys,
    );

    if let Some(user_dir) = user_plugin_dir() {
        scan_directory(
            &user_dir,
            &mut registry,
            PluginSource::User,
            preference,
            verify,
            user_keys,
        );
    }

    if registry.is_empty() {
        debug!("no WASM providers discovered");
    } else {
        info!(
            count = registry.len(),
            kinds = ?registry.kinds(),
            "discovered WASM providers",
        );
    }

    registry
}

/// Scan a single directory for `.wasm` files and register their manifests.
/// When a kind already exists in the registry, the preference policy decides
/// whether to replace it.
fn scan_directory(
    dir: &Path,
    registry: &mut PluginRegistry,
    source: PluginSource,
    preference: WasmPreference,
    verify: WasmVerify,
    user_keys: &[WasmTrustedKey],
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            // Missing directories are normal (no system packages installed,
            // or user hasn't created the providers dir yet).
            debug!(dir = %dir.display(), "plugin directory not readable: {e}");
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!("failed to read directory entry in {}: {e}", dir.display());
                continue;
            }
        };

        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("wasm") {
            continue;
        }

        // Step 1: signature verification (before loading into wasmtime).
        let wasm_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let (outcome, VerifiedPlugin { wasm_bytes, policy }) =
            match verify_plugin(&path, verify, user_keys) {
                Ok(v) => v,
                Err(reason) => {
                    warn!(
                        wasm = %wasm_name,
                        path = %path.display(),
                        ?source,
                        reason = %reason,
                        "skipping WASM plugin (signature check failed)",
                    );
                    continue;
                }
            };
        match &outcome {
            VerifyOutcome::Verified(VerifiedBy::ReleaseKey) => info!(
                wasm = %wasm_name,
                path = %path.display(),
                ?source,
                "WASM plugin signature verified",
            ),
            // Loud on purpose: the plugin loads on the strength of a trust
            // anchor the user added, not the rosec release key.
            VerifyOutcome::Verified(VerifiedBy::UserKey { name }) => warn!(
                wasm = %wasm_name,
                path = %path.display(),
                ?source,
                key = %name,
                "WASM plugin signature verified by user-trusted key, NOT the rosec release key",
            ),
            VerifyOutcome::NotVerified { reason } => debug!(
                wasm = %wasm_name,
                path = %path.display(),
                ?source,
                reason = %reason,
                "WASM plugin loaded without signature verification",
            ),
        }
        let wasm_bytes = Arc::new(wasm_bytes);

        // Step 2: probe the plugin (fuel-limited, size-capped) using the
        // bytes we just verified — never re-read from disk, so a swap between
        // verify and probe cannot smuggle in a different module.
        match probe_plugin(&path, &wasm_bytes) {
            Ok(manifest) => {
                let kind = manifest.kind.clone();

                // Catch policy/manifest kind mismatch — cheaper here than
                // discovering it later when WasmProvider tries to load.
                if policy.kind != kind {
                    warn!(
                        wasm = %wasm_name,
                        manifest_kind = %kind,
                        policy_kind = %policy.kind,
                        "policy declares a different kind than plugin_manifest, skipping"
                    );
                    continue;
                }

                if let Some(existing) = registry.plugins.get(&kind) {
                    let replace = should_replace(existing, &manifest, source, preference);
                    if replace {
                        info!(
                            kind = %kind,
                            path = %path.display(),
                            ?source,
                            ?preference,
                            "overriding previously discovered plugin",
                        );
                    } else {
                        debug!(
                            kind = %kind,
                            path = %path.display(),
                            ?source,
                            "keeping existing plugin, skipping",
                        );
                        continue;
                    }
                }
                debug!(
                    kind = %kind,
                    name = %manifest.name,
                    path = %path.display(),
                    "discovered plugin",
                );
                registry.plugins.insert(
                    kind,
                    DiscoveredPlugin {
                        wasm_path: path,
                        wasm_bytes,
                        policy,
                        manifest,
                    },
                );
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    "failed to probe plugin: {e}",
                );
            }
        }
    }
}

/// Decide whether the incoming plugin should replace the existing registry
/// entry, based on the configured preference.
fn should_replace(
    existing: &DiscoveredPlugin,
    incoming: &PluginManifest,
    source: PluginSource,
    preference: WasmPreference,
) -> bool {
    match preference {
        WasmPreference::User => source == PluginSource::User,
        WasmPreference::System => source == PluginSource::System,
        WasmPreference::Newest => {
            let zero = semver::Version::new(0, 0, 0);
            let existing_ver = existing.manifest.version.as_ref().unwrap_or(&zero);
            let incoming_ver = incoming.version.as_ref().unwrap_or(&zero);
            if incoming_ver > existing_ver {
                true
            } else if incoming_ver == existing_ver {
                // Tie-break: prefer user-local.
                source == PluginSource::User
            } else {
                false
            }
        }
    }
}

/// Outcome of signature verification on the success path. Failures are
/// returned as `Err(reason)` from [`verify_plugin`].
#[derive(Debug)]
enum VerifyOutcome {
    /// Signature present and verified by the given trust anchor.
    Verified(VerifiedBy),
    /// Verification was not performed (disabled). The plugin may still
    /// be loaded.
    NotVerified { reason: &'static str },
}

/// Path of the policy sidecar for a given `.wasm` file.
pub fn policy_path_for(wasm_path: &Path) -> PathBuf {
    wasm_path.with_extension("wasm.policy.toml")
}

/// Path of the detached signature for a given `.wasm` file.
pub fn signature_path_for(wasm_path: &Path) -> PathBuf {
    wasm_path.with_extension("wasm.minisig")
}

/// A `.wasm` + `.wasm.policy.toml` pair read from disk with the policy
/// parsed and schema-validated. The signature is NOT yet checked — call
/// [`PluginBundle::verify_signature`].
///
/// This is the shared load path for the daemon's discovery scan and the
/// out-of-daemon tooling (`rosec provider validate`, `rosec-package-wasm`),
/// so all consumers agree on sidecar naming and the signed byte layout.
#[derive(Debug, Clone)]
pub struct PluginBundle {
    pub wasm_path: PathBuf,
    pub policy_path: PathBuf,
    pub signature_path: PathBuf,
    pub wasm_bytes: Vec<u8>,
    pub policy_bytes: Vec<u8>,
    pub policy: PluginPolicy,
}

/// Which trust anchor accepted a bundle's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedBy {
    /// One of the release keys embedded in this build
    /// ([`crate::keys::WASM_SIGNING_PUBKEYS`]).
    ReleaseKey,
    /// A user-configured `[[service.wasm_trusted_key]]` entry; the label is
    /// the entry's `name`.
    UserKey { name: String },
}

impl std::fmt::Display for VerifiedBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReleaseKey => write!(f, "embedded rosec release key"),
            Self::UserKey { name } => write!(f, "user-trusted key '{name}'"),
        }
    }
}

impl PluginBundle {
    /// Read `wasm_path` and its mandatory `.wasm.policy.toml` sidecar,
    /// parsing (and schema-validating) the policy. The `Err` variant
    /// carries the rejection reason as a single human-readable string.
    pub fn load(wasm_path: &Path) -> Result<Self, String> {
        let wasm_bytes = std::fs::read(wasm_path)
            .map_err(|e| format!("failed to read WASM file '{}': {e}", wasm_path.display()))?;

        let policy_path = policy_path_for(wasm_path);
        let policy_bytes = std::fs::read(&policy_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                format!(
                    "policy file '{}' not found (required for all wasm_verify modes; \
                     disabled mode skips the signature check, not the policy)",
                    policy_path.display()
                )
            } else {
                format!(
                    "failed to read policy file '{}': {e}",
                    policy_path.display()
                )
            }
        })?;

        let policy = PluginPolicy::from_toml_bytes(&policy_bytes)
            .map_err(|e| format!("policy file '{}' parse failed: {e}", policy_path.display()))?;

        Ok(Self {
            signature_path: signature_path_for(wasm_path),
            wasm_path: wasm_path.to_path_buf(),
            policy_path,
            wasm_bytes,
            policy_bytes,
            policy,
        })
    }

    /// Verify the detached `.minisig` over `(wasm_bytes || policy_bytes)`
    /// against the embedded release keys.
    pub fn verify_signature(&self) -> Result<(), String> {
        self.verify_signature_trusted(&[]).map(|_| ())
    }

    /// Verify against the embedded release keys first, then any
    /// user-configured trust anchors, reporting which one accepted the
    /// signature. A user key is only consulted when its `kinds` scope is
    /// empty or contains this bundle's policy kind.
    pub fn verify_signature_trusted(
        &self,
        user_keys: &[WasmTrustedKey],
    ) -> Result<VerifiedBy, String> {
        self.verify_against(crate::keys::WASM_SIGNING_PUBKEYS, user_keys)
    }

    /// Trust-set verification with an explicit release-key set (separated
    /// from [`Self::verify_signature_trusted`] so tests can inject keys).
    fn verify_against(
        &self,
        release_keys: &[&str],
        user_keys: &[WasmTrustedKey],
    ) -> Result<VerifiedBy, String> {
        let mut reasons: Vec<String> = Vec::new();

        for key in release_keys {
            match self.verify_signature_with(key) {
                Ok(()) => return Ok(VerifiedBy::ReleaseKey),
                Err(reason) => reasons.push(format!("release key: {reason}")),
            }
        }

        for tk in user_keys {
            if !tk.kinds.is_empty() && !tk.kinds.iter().any(|k| k == &self.policy.kind) {
                reasons.push(format!(
                    "user key '{}' skipped: kind '{}' not in its kinds scope [{}]",
                    tk.name,
                    self.policy.kind,
                    tk.kinds.join(", "),
                ));
                continue;
            }
            match self.verify_signature_with(&tk.key) {
                Ok(()) => {
                    return Ok(VerifiedBy::UserKey {
                        name: tk.name.clone(),
                    });
                }
                Err(reason) => reasons.push(format!("user key '{}': {reason}", tk.name)),
            }
        }

        // Deduplicate: with several keys the dominant reason is usually the
        // same "different key" message repeated per candidate.
        reasons.dedup();
        Err(format!(
            "signature not accepted by any trusted key ({} release, {} user): {}",
            release_keys.len(),
            user_keys.len(),
            reasons.join("; "),
        ))
    }

    /// Verify against an arbitrary base64 minisign public key (the second
    /// line of a `.pub` file). Used by author tooling to check bundles
    /// signed with a non-release key.
    pub fn verify_signature_with(&self, pubkey_base64: &str) -> Result<(), String> {
        if !self.signature_path.exists() {
            return Err(format!(
                "signature file '{}' not found (set wasm_verify = \"disabled\" \
                 to load unsigned plugins for local development)",
                self.signature_path.display(),
            ));
        }

        let pk = PublicKey::from_base64(pubkey_base64)
            .map_err(|e| format!("invalid public key: {e}"))?;
        let signature = Signature::from_file(&self.signature_path).map_err(|e| {
            format!(
                "failed to read signature file '{}': {e}",
                self.signature_path.display()
            )
        })?;

        let combined = policy::signature_input(&self.wasm_bytes, &self.policy_bytes);
        pk.verify(&combined, &signature, false).map_err(|e| {
            format!(
                "combined signature verification failed for '{}' (policy '{}'): {e}",
                self.wasm_path.display(),
                self.policy_path.display(),
            )
        })
    }
}

/// Read wasm bytes + sidecar policy and verify the combined signature.
///
/// Closes the verify-then-load TOCTOU window by capturing wasm bytes
/// once for both probe and runtime load. The `Err` variant carries the
/// rejection reason as a single human-readable string.
///
/// # Behaviour by mode
///
/// The `.policy.toml` sidecar is **mandatory in both modes** — `disabled`
/// only bypasses the cryptographic signature check, never the declarative
/// policy. There is no manifest-declared fallback path.
///
/// - **`Required` (default)** — `.wasm.minisig` and `.wasm.policy.toml`
///   must both exist. The signature covers `(wasm_bytes || policy_bytes)`;
///   substitution of either file invalidates it.
/// - **`Disabled` (dev)** — `.wasm.policy.toml` must exist; the
///   `.minisig` is not required and any signature verification is
///   skipped. A loud `warn!` is logged at scan time.
fn verify_plugin(
    wasm_path: &Path,
    verify: WasmVerify,
    user_keys: &[WasmTrustedKey],
) -> Result<(VerifyOutcome, VerifiedPlugin), String> {
    let bundle = PluginBundle::load(wasm_path)?;

    if verify == WasmVerify::Disabled {
        warn!(
            wasm = %wasm_path.display(),
            "wasm_verify = \"disabled\" — loading without signature verification. \
             Policy from .wasm.policy.toml is still applied."
        );
        return Ok((
            VerifyOutcome::NotVerified { reason: "disabled" },
            VerifiedPlugin {
                wasm_bytes: bundle.wasm_bytes,
                policy: bundle.policy,
            },
        ));
    }

    let verified_by = bundle.verify_signature_trusted(user_keys)?;

    Ok((
        VerifyOutcome::Verified(verified_by),
        VerifiedPlugin {
            wasm_bytes: bundle.wasm_bytes,
            policy: bundle.policy,
        },
    ))
}

/// Load a `.wasm` file and call `plugin_manifest()` to extract its
/// metadata.  The plugin is discarded after probing.
///
/// Guards:
/// - File size capped at [`MAX_WASM_SIZE_BYTES`] before loading.
/// - Fuel-limited to [`PROBE_FUEL_LIMIT`] instructions to prevent
///   runaway execution in the WASM `start` section or `plugin_manifest`.
fn probe_plugin(wasm_path: &Path, wasm_bytes: &[u8]) -> Result<PluginManifest, anyhow::Error> {
    // Size cap — reject before handing to wasmtime.
    if wasm_bytes.len() as u64 > MAX_WASM_SIZE_BYTES {
        return Err(anyhow::anyhow!(
            "'{}' is {} bytes, exceeds limit of {MAX_WASM_SIZE_BYTES}",
            wasm_path.display(),
            wasm_bytes.len(),
        ));
    }

    let wasm = Wasm::data(wasm_bytes.to_vec());
    // No allowed hosts for probing — plugin_manifest must not make HTTP requests.
    let manifest = Manifest::new([wasm]);

    // Register the host_file and host_watch functions with empty allow-lists
    // so plugins that import them (e.g. keepassxc-file) link successfully
    // during the probe phase.  `plugin_manifest` is metadata-only and should
    // never actually call them — if it does, the empty allow-list rejects
    // the call and the probe fails cleanly.  The watch receiver is dropped
    // immediately, so any guest call to `register_watch` would push events
    // into a dead channel — also harmless.
    let mut host_fns = crate::host_file::build_file_host_functions(&[]);
    let (watch_fns, _watch_rx) = crate::host_watch::build_watch_host_functions(&[]);
    host_fns.extend(watch_fns);

    let mut plugin = PluginBuilder::new(manifest)
        .with_wasi(true)
        .with_fuel_limit(PROBE_FUEL_LIMIT)
        .with_functions(host_fns)
        .build()
        .map_err(|e| {
            anyhow::anyhow!("failed to load WASM plugin '{}': {e}", wasm_path.display())
        })?;

    if !plugin.function_exists("plugin_manifest") {
        return Err(anyhow::anyhow!(
            "'{}' does not export `plugin_manifest`",
            wasm_path.display(),
        ));
    }

    let output_bytes: &[u8] = plugin.call("plugin_manifest", &[] as &[u8]).map_err(|e| {
        anyhow::anyhow!(
            "plugin_manifest call failed for '{}': {e}",
            wasm_path.display(),
        )
    })?;

    let pm: PluginManifest = serde_json::from_slice(output_bytes).map_err(|e| {
        anyhow::anyhow!(
            "failed to deserialize plugin_manifest from '{}': {e}",
            wasm_path.display(),
        )
    })?;

    if pm.kind.is_empty() {
        return Err(anyhow::anyhow!(
            "plugin '{}' returned empty kind in manifest",
            wasm_path.display(),
        ));
    }

    Ok(pm)
}

/// Resolve the user-local provider directory.
///
/// Uses `$XDG_DATA_HOME/rosec/providers/` (default `~/.local/share/rosec/providers/`).
fn user_plugin_dir() -> Option<PathBuf> {
    if let Ok(data_home) = std::env::var("XDG_DATA_HOME")
        && !data_home.is_empty()
    {
        return Some(PathBuf::from(data_home).join(USER_PLUGIN_SUBDIR));
    }

    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return Some(
            PathBuf::from(home)
                .join(".local/share")
                .join(USER_PLUGIN_SUBDIR),
        );
    }

    warn!("cannot determine user provider directory: neither $XDG_DATA_HOME nor $HOME is set");
    None
}

/// Required options for a kind, or `None` if unknown.
pub fn required_options(
    registry: &PluginRegistry,
    kind: &str,
) -> Option<Vec<PluginOptionDescriptor>> {
    registry
        .get(kind)
        .map(|p| p.manifest.required_options.clone())
}

/// Optional options for a kind, or `None` if unknown.
pub fn optional_options(
    registry: &PluginRegistry,
    kind: &str,
) -> Option<Vec<PluginOptionDescriptor>> {
    registry
        .get(kind)
        .map(|p| p.manifest.optional_options.clone())
}

/// Return the ID derivation key for a discovered plugin kind.
///
/// Returns `None` if the kind is not in the registry or the plugin
/// did not specify a derivation key.
pub fn id_derivation_key(registry: &PluginRegistry, kind: &str) -> Option<String> {
    registry
        .get(kind)
        .and_then(|p| p.manifest.id_derivation_key.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_bundle(dir: &Path, kind: &str) -> PathBuf {
        let wasm = dir.join("test_plugin.wasm");
        std::fs::write(&wasm, b"\0asm-fake-module").unwrap();
        std::fs::write(
            policy_path_for(&wasm),
            format!("schema_version = 1\nkind = \"{kind}\"\nname = \"Test\"\n"),
        )
        .unwrap();
        wasm
    }

    fn signed_bundle(dir: &Path, kind: &str) -> (PluginBundle, String) {
        let wasm = write_bundle(dir, kind);
        let kp = minisign::KeyPair::generate_encrypted_keypair(Some(String::new())).unwrap();
        let unsigned = PluginBundle::load(&wasm).unwrap();
        let combined = policy::signature_input(&unsigned.wasm_bytes, &unsigned.policy_bytes);
        let sig = minisign::sign(Some(&kp.pk), &kp.sk, combined.as_slice(), None, None).unwrap();
        std::fs::write(signature_path_for(&wasm), sig.to_string()).unwrap();
        (PluginBundle::load(&wasm).unwrap(), kp.pk.to_base64())
    }

    fn other_key() -> String {
        minisign::KeyPair::generate_encrypted_keypair(Some(String::new()))
            .unwrap()
            .pk
            .to_base64()
    }

    fn user_key(name: &str, key: &str, kinds: &[&str]) -> WasmTrustedKey {
        WasmTrustedKey {
            key: key.to_string(),
            name: name.to_string(),
            kinds: kinds.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn release_key_set_selects_matching_key() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle, signer) = signed_bundle(dir.path(), "test");
        let old = other_key();
        // Rotation window: old key first, new (signing) key second.
        let verified = bundle.verify_against(&[&old, &signer], &[]).unwrap();
        assert_eq!(verified, VerifiedBy::ReleaseKey);
    }

    #[test]
    fn unknown_signer_rejected_by_all_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle, _signer) = signed_bundle(dir.path(), "test");
        let err = bundle.verify_against(&[&other_key()], &[]).unwrap_err();
        assert!(err.contains("not accepted by any trusted key"), "{err}");
    }

    #[test]
    fn user_key_accepted_with_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle, signer) = signed_bundle(dir.path(), "test");
        let verified = bundle
            .verify_against(&[&other_key()], &[user_key("acme", &signer, &[])])
            .unwrap();
        assert_eq!(
            verified,
            VerifiedBy::UserKey {
                name: "acme".into()
            }
        );
    }

    #[test]
    fn user_key_kind_scope_match_allows() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle, signer) = signed_bundle(dir.path(), "acme-vault");
        let verified = bundle
            .verify_against(&[], &[user_key("acme", &signer, &["acme-vault"])])
            .unwrap();
        assert!(matches!(verified, VerifiedBy::UserKey { .. }));
    }

    #[test]
    fn user_key_kind_scope_mismatch_skips_key() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle, signer) = signed_bundle(dir.path(), "impersonated-kind");
        let err = bundle
            .verify_against(&[], &[user_key("acme", &signer, &["acme-vault"])])
            .unwrap_err();
        assert!(err.contains("skipped"), "{err}");
        assert!(err.contains("kinds scope"), "{err}");
    }

    #[test]
    fn invalid_user_key_reported_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle, signer) = signed_bundle(dir.path(), "test");
        // A garbage key must not mask a later valid one.
        let verified = bundle
            .verify_against(
                &[],
                &[
                    user_key("broken", "not-base64!!", &[]),
                    user_key("acme", &signer, &[]),
                ],
            )
            .unwrap();
        assert_eq!(
            verified,
            VerifiedBy::UserKey {
                name: "acme".into()
            }
        );
    }
}
