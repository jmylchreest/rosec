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

use extism::{Manifest, PluginBuilder, Wasm};
use minisign_verify::{PublicKey, Signature};
use rosec_core::{WasmPreference, WasmVerify};
use tracing::{debug, info, warn};

use crate::keys::WASM_SIGNING_PUBKEY;
use crate::policy::{self, PluginPolicy};
use crate::protocol::{PluginManifest, PluginOptionDescriptor};

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
pub fn scan_plugins(preference: WasmPreference, verify: WasmVerify) -> PluginRegistry {
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
    );

    if let Some(user_dir) = user_plugin_dir() {
        scan_directory(
            &user_dir,
            &mut registry,
            PluginSource::User,
            preference,
            verify,
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
        let (outcome, VerifiedPlugin { wasm_bytes, policy }) = match verify_plugin(&path, verify) {
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
            VerifyOutcome::Verified => info!(
                wasm = %wasm_name,
                path = %path.display(),
                ?source,
                "WASM plugin signature verified",
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
    /// Signature present and verified.
    Verified,
    /// Verification was not performed (disabled). The plugin may still
    /// be loaded.
    NotVerified { reason: &'static str },
}

/// Path of the policy sidecar for a given `.wasm` file.
fn policy_path_for(wasm_path: &Path) -> PathBuf {
    wasm_path.with_extension("wasm.policy.toml")
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
) -> Result<(VerifyOutcome, VerifiedPlugin), String> {
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

    if verify == WasmVerify::Disabled {
        warn!(
            wasm = %wasm_path.display(),
            "wasm_verify = \"disabled\" — loading without signature verification. \
             Policy from .wasm.policy.toml is still applied."
        );
        return Ok((
            VerifyOutcome::NotVerified { reason: "disabled" },
            VerifiedPlugin { wasm_bytes, policy },
        ));
    }

    let sig_path = wasm_path.with_extension("wasm.minisig");
    if !sig_path.exists() {
        return Err(format!(
            "signature file '{}' not found (set wasm_verify = \"disabled\" \
             to load unsigned plugins for local development)",
            sig_path.display(),
        ));
    }

    let pk = PublicKey::from_base64(WASM_SIGNING_PUBKEY)
        .map_err(|e| format!("invalid embedded public key: {e}"))?;
    let signature = Signature::from_file(&sig_path).map_err(|e| {
        format!(
            "failed to read signature file '{}': {e}",
            sig_path.display()
        )
    })?;

    let combined = policy::signature_input(&wasm_bytes, &policy_bytes);
    pk.verify(&combined, &signature, false).map_err(|e| {
        format!(
            "combined signature verification failed for '{}' (policy '{}'): {e}",
            wasm_path.display(),
            policy_path.display(),
        )
    })?;

    Ok((
        VerifyOutcome::Verified,
        VerifiedPlugin { wasm_bytes, policy },
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
