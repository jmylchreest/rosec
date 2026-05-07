//! Plugin policy sidecar — signed declaration of what a WASM provider needs.
//!
//! Each `.wasm` file has a sibling `.policy.toml` that declares the plugin's
//! network allow-list, filesystem preopens, and required user options. The
//! single `.minisig` covers `(wasm_bytes || policy_bytes)` so substitution of
//! either file invalidates the signature.
//!
//! See `docs/developers/wasm-policy-sidecar` for the full design.
//!
//! # Trust model
//!
//! The policy is the **plugin author's claim** about what the plugin needs.
//! The user can extend it (`additional_hosts`) or replace the network section
//! entirely (`allowed_hosts` in their config). The policy text is plain TOML
//! — auditable by `cat`-ing the file before loading the binary.
//!
//! # Template variables
//!
//! Path templates resolve at provider construction:
//!
//! - `$option:KEY` — value of a user-supplied option (must appear in
//!   `[options].required` or `[options].optional`).
//! - `$home` — `$HOME`.
//! - `$xdg_data_home` — `$XDG_DATA_HOME` or `$HOME/.local/share`.
//! - `$xdg_config_home` — `$XDG_CONFIG_HOME` or `$HOME/.config`.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Highest schema version this binary understands. Forward-incompatible
/// policies are refused at load time so security policy is never silently
/// downgraded.
pub const MAX_SCHEMA_VERSION: u32 = 1;

/// Parsed `policy.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPolicy {
    pub schema_version: u32,
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub options: OptionsPolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub preopens: Vec<PreopenSpec>,
    #[serde(default)]
    pub allowed_files: Vec<AllowedFileSpec>,
}

/// A directory pre-opened into the WASI sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreopenSpec {
    /// Resolved against user options (e.g. `$home/.local/share/keyrings`).
    pub host_template: String,
    /// Path inside the WASI guest (e.g. `/keyrings`).
    pub guest_path: String,
    #[serde(default = "default_ro")]
    pub mode: AccessMode,
}

/// A specific file the guest may read via the `host_file` host imports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedFileSpec {
    pub host_template: String,
    #[serde(default = "default_ro")]
    pub mode: AccessMode,
    /// When `true`, a missing option in the template is silently skipped
    /// rather than rejected. Use for files like `key_file` that supplement
    /// a primary `path`.
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    Ro,
    Rw,
}

const fn default_ro() -> AccessMode {
    AccessMode::Ro
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OptionsPolicy {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub optional: Vec<String>,
    /// Default values for optional options, applied via
    /// [`PluginPolicy::apply_defaults`] before `resolve()` and before
    /// forwarding to the guest. Templates support `$home`, `$xdg_data_home`,
    /// `$xdg_config_home`; `$option:` refs are rejected to avoid dependency
    /// cycles between option resolution.
    ///
    /// Defaults must reference keys declared in `optional` — putting a
    /// default on a `required` key would mean it isn't really required.
    #[serde(default)]
    pub defaults: HashMap<String, String>,
}

/// Errors from policy load / parse / resolve.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy file I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("policy file parse: {0}")]
    Parse(#[from] toml::de::Error),
    #[error(
        "policy schema version {got} is newer than this rosec daemon supports (max {max}); upgrade rosec to load this plugin"
    )]
    SchemaVersionTooNew { got: u32, max: u32 },
    #[error("policy declares kind {expected} but plugin manifest reports {actual}")]
    KindMismatch { expected: String, actual: String },
    #[error("provider config is missing required option '{0}' per plugin policy")]
    MissingRequiredOption(String),
    #[error("policy template '{0}' references undeclared option '{1}'")]
    UndeclaredOptionRef(String, String),
    #[error("policy template '{0}' references unknown variable {1}")]
    UnknownTemplateVar(String, String),
    #[error("policy template '{0}' resolved to an empty path")]
    EmptyTemplate(String),
    #[error("[options.defaults] entry '{0}' is not declared in [options].optional")]
    DefaultOnUndeclaredOption(String),
    #[error(
        "[options.defaults] entry '{0}' is also declared required — defaults are only valid for optional options"
    )]
    DefaultOnRequiredOption(String),
}

/// Result of resolving templates against user options. Ready for
/// `WasmProviderConfig` consumption.
#[derive(Debug, Clone, Default)]
pub struct ResolvedPolicy {
    /// `(host_src, guest_dest)` pairs for `Manifest::with_allowed_path`.
    /// `host_src` is prefixed with `ro:` for read-only preopens.
    pub allowed_paths: Vec<(String, PathBuf)>,
    /// Per-file scoped reads via `host_file` host imports.
    pub allowed_files: Vec<PathBuf>,
}

impl PluginPolicy {
    /// Parse from TOML bytes; refuse forward-incompatible schema versions.
    pub fn from_toml_bytes(bytes: &[u8]) -> Result<Self, PolicyError> {
        let s = std::str::from_utf8(bytes).map_err(|e| {
            PolicyError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        let p: Self = toml::from_str(s)?;
        if p.schema_version == 0 || p.schema_version > MAX_SCHEMA_VERSION {
            return Err(PolicyError::SchemaVersionTooNew {
                got: p.schema_version,
                max: MAX_SCHEMA_VERSION,
            });
        }
        Ok(p)
    }

    /// Inject default values from `[options].defaults` for keys the user
    /// hasn't supplied. Call this before [`Self::resolve`] and before
    /// forwarding options to the guest, so both the policy resolver and
    /// the plugin see the defaulted values.
    ///
    /// Default templates may reference `$home`, `$xdg_data_home`, and
    /// `$xdg_config_home`; `$option:` refs are rejected so default
    /// resolution can't form cycles.
    pub fn apply_defaults(
        &self,
        options: &mut HashMap<String, serde_json::Value>,
    ) -> Result<(), PolicyError> {
        // Empty maps fed to `resolve_template` so `$option:` refs are
        // rejected inside default templates (cycle prevention). Allocated
        // once and reused across all defaults.
        let empty_opts = HashMap::new();
        let empty_known = HashSet::new();
        for (key, template) in &self.options.defaults {
            if self.options.required.contains(key) {
                return Err(PolicyError::DefaultOnRequiredOption(key.clone()));
            }
            if !self.options.optional.contains(key) {
                return Err(PolicyError::DefaultOnUndeclaredOption(key.clone()));
            }
            if options.contains_key(key) {
                continue;
            }
            let resolved = resolve_template(template, &empty_opts, &empty_known, false)?;
            options.insert(key.clone(), serde_json::Value::String(resolved));
        }
        Ok(())
    }

    /// Resolve filesystem templates against user-supplied options, validating
    /// required options and template references along the way.
    pub fn resolve(
        &self,
        options: &HashMap<String, serde_json::Value>,
    ) -> Result<ResolvedPolicy, PolicyError> {
        for req in &self.options.required {
            if !options.contains_key(req) {
                return Err(PolicyError::MissingRequiredOption(req.clone()));
            }
        }

        let known: HashSet<&str> = self
            .options
            .required
            .iter()
            .chain(self.options.optional.iter())
            .map(String::as_str)
            .collect();

        let mut allowed_paths = Vec::with_capacity(self.filesystem.preopens.len());
        for p in &self.filesystem.preopens {
            let src = resolve_template(&p.host_template, options, &known, false)?;
            if src.is_empty() {
                return Err(PolicyError::EmptyTemplate(p.host_template.clone()));
            }
            let prefix = match p.mode {
                AccessMode::Ro => "ro:",
                AccessMode::Rw => "",
            };
            allowed_paths.push((format!("{prefix}{src}"), PathBuf::from(&p.guest_path)));
        }

        let mut allowed_files = Vec::with_capacity(self.filesystem.allowed_files.len());
        for f in &self.filesystem.allowed_files {
            match resolve_template(&f.host_template, options, &known, f.optional) {
                Ok(path) if path.is_empty() => {
                    if !f.optional {
                        return Err(PolicyError::EmptyTemplate(f.host_template.clone()));
                    }
                }
                Ok(path) => allowed_files.push(PathBuf::from(path)),
                Err(PolicyError::MissingRequiredOption(_)) if f.optional => {}
                Err(e) => return Err(e),
            }
        }

        Ok(ResolvedPolicy {
            allowed_paths,
            allowed_files,
        })
    }

    /// Warn (via `tracing::warn`) about user-supplied options not declared in
    /// the policy. Lenient: typos and stale options don't block load.
    pub fn report_unknown_options(
        &self,
        provider_id: &str,
        options: &HashMap<String, serde_json::Value>,
    ) {
        let known: HashSet<&str> = self
            .options
            .required
            .iter()
            .chain(self.options.optional.iter())
            .map(String::as_str)
            .collect();
        for key in options.keys() {
            if !known.contains(key.as_str()) {
                tracing::warn!(
                    provider = %provider_id,
                    kind = %self.kind,
                    option = %key,
                    "unknown option for plugin kind, ignored (not declared in policy)"
                );
            }
        }
    }
}

/// Expand `$option:KEY`, `$home`, `$xdg_data_home`, `$xdg_config_home`.
///
/// Variable names match `[A-Za-z0-9_:]+`. `$option:KEY` is rejected if KEY
/// is not declared in the policy's `[options]` (catches typos in policy
/// authoring rather than silently passing garbage to wasmtime). Missing
/// optional values resolve to an empty string when `allow_missing_option`
/// is `true`, allowing the caller to skip optional file entries.
fn resolve_template(
    template: &str,
    options: &HashMap<String, serde_json::Value>,
    known_options: &HashSet<&str>,
    allow_missing_option: bool,
) -> Result<String, PolicyError> {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.char_indices();

    while let Some((i, c)) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }

        let var_start = i + 1;
        let mut var_end = template.len();
        let mut consumed: usize = 0;
        for (j, nc) in template[var_start..].char_indices() {
            if is_template_var_char(nc) {
                consumed += nc.len_utf8();
            } else {
                var_end = var_start + j;
                break;
            }
        }
        if var_end == template.len() {
            var_end = var_start + consumed;
        }

        let var = &template[var_start..var_end];
        for _ in 0..var.chars().count() {
            chars.next();
        }

        let resolved = if let Some(opt_key) = var.strip_prefix("option:") {
            if !known_options.contains(opt_key) {
                return Err(PolicyError::UndeclaredOptionRef(
                    template.to_string(),
                    opt_key.to_string(),
                ));
            }
            match options.get(opt_key).and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None if allow_missing_option => return Ok(String::new()),
                None => {
                    return Err(PolicyError::MissingRequiredOption(opt_key.to_string()));
                }
            }
        } else {
            match var {
                "home" => std::env::var("HOME").unwrap_or_default(),
                "xdg_data_home" => xdg_data_home(),
                "xdg_config_home" => xdg_config_home(),
                "" => {
                    return Err(PolicyError::UnknownTemplateVar(
                        template.to_string(),
                        "$".to_string(),
                    ));
                }
                _ => {
                    return Err(PolicyError::UnknownTemplateVar(
                        template.to_string(),
                        format!("${var}"),
                    ));
                }
            }
        };
        out.push_str(&resolved);
    }

    Ok(out)
}

fn is_template_var_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == ':'
}

fn xdg_data_home() -> String {
    std::env::var("XDG_DATA_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::env::var("HOME")
                .map(|h| format!("{h}/.local/share"))
                .unwrap_or_default()
        })
}

fn xdg_config_home() -> String {
    std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::env::var("HOME")
                .map(|h| format!("{h}/.config"))
                .unwrap_or_default()
        })
}

/// Compute the byte buffer that the `.minisig` covers: `wasm_bytes` then
/// `policy_bytes`, no separator. Substitution of either file invalidates
/// the signature.
pub fn signature_input(wasm_bytes: &[u8], policy_bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(wasm_bytes.len() + policy_bytes.len());
    buf.extend_from_slice(wasm_bytes);
    buf.extend_from_slice(policy_bytes);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn opts(pairs: &[(&str, &str)]) -> HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect()
    }

    #[test]
    fn parses_minimal_policy() {
        let toml = r#"
schema_version = 1
kind = "test"
name = "Test"
"#;
        let p = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap();
        assert_eq!(p.kind, "test");
        assert_eq!(p.network.allowed_hosts.len(), 0);
    }

    #[test]
    fn refuses_future_schema() {
        let toml = r#"
schema_version = 99
kind = "test"
name = "Test"
"#;
        let err = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap_err();
        assert!(matches!(err, PolicyError::SchemaVersionTooNew { .. }));
    }

    #[test]
    fn refuses_zero_schema() {
        let toml = r#"
schema_version = 0
kind = "test"
name = "Test"
"#;
        let err = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap_err();
        assert!(matches!(err, PolicyError::SchemaVersionTooNew { .. }));
    }

    #[test]
    fn resolves_option_template() {
        let toml = r#"
schema_version = 1
kind = "test"
name = "Test"
[[filesystem.allowed_files]]
host_template = "$option:path"
[options]
required = ["path"]
"#;
        let p = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap();
        let r = p.resolve(&opts(&[("path", "/tmp/foo.kdbx")])).unwrap();
        assert_eq!(r.allowed_files, vec![PathBuf::from("/tmp/foo.kdbx")]);
    }

    #[test]
    fn missing_required_rejects_load() {
        let toml = r#"
schema_version = 1
kind = "test"
name = "Test"
[options]
required = ["path"]
"#;
        let p = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap();
        let err = p.resolve(&opts(&[])).unwrap_err();
        assert!(matches!(err, PolicyError::MissingRequiredOption(ref k) if k == "path"));
    }

    #[test]
    fn optional_file_with_missing_option_skipped() {
        let toml = r#"
schema_version = 1
kind = "test"
name = "Test"
[[filesystem.allowed_files]]
host_template = "$option:path"
[[filesystem.allowed_files]]
host_template = "$option:key_file"
optional = true
[options]
required = ["path"]
optional = ["key_file"]
"#;
        let p = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap();
        let r = p.resolve(&opts(&[("path", "/tmp/foo.kdbx")])).unwrap();
        // Only `path` resolved; `key_file` skipped because absent + optional.
        assert_eq!(r.allowed_files, vec![PathBuf::from("/tmp/foo.kdbx")]);
    }

    #[test]
    fn rejects_undeclared_option_in_template() {
        let toml = r#"
schema_version = 1
kind = "test"
name = "Test"
[[filesystem.allowed_files]]
host_template = "$option:not_in_policy"
[options]
required = []
optional = []
"#;
        let p = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap();
        let err = p.resolve(&opts(&[])).unwrap_err();
        assert!(matches!(err, PolicyError::UndeclaredOptionRef(_, _)));
    }

    #[test]
    fn rejects_unknown_template_var() {
        let toml = r#"
schema_version = 1
kind = "test"
name = "Test"
[[filesystem.preopens]]
host_template = "$nope/foo"
guest_path = "/foo"
"#;
        let p = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap();
        let err = p.resolve(&opts(&[])).unwrap_err();
        assert!(matches!(err, PolicyError::UnknownTemplateVar(_, _)));
    }

    #[test]
    fn preopen_with_ro_prefix() {
        // SAFETY: tests run serial via TEST_ENV_MUTEX in rosec_core, but this
        // test reads HOME without mutating, which is fine.
        let toml = r#"
schema_version = 1
kind = "test"
name = "Test"
[[filesystem.preopens]]
host_template = "/etc/some/dir"
guest_path = "/dir"
mode = "ro"
"#;
        let p = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap();
        let r = p.resolve(&opts(&[])).unwrap();
        assert_eq!(r.allowed_paths.len(), 1);
        assert!(r.allowed_paths[0].0.starts_with("ro:"));
    }

    #[test]
    fn applies_default_for_missing_optional() {
        let toml = r#"
schema_version = 1
kind = "test"
name = "Test"
[options]
required = []
optional = ["dir"]
[options.defaults]
dir = "/var/lib/test"
"#;
        let p = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap();
        let mut o = opts(&[]);
        p.apply_defaults(&mut o).unwrap();
        assert_eq!(o.get("dir").and_then(|v| v.as_str()), Some("/var/lib/test"));
    }

    #[test]
    fn user_value_overrides_default() {
        let toml = r#"
schema_version = 1
kind = "test"
name = "Test"
[options]
required = []
optional = ["dir"]
[options.defaults]
dir = "/var/lib/test"
"#;
        let p = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap();
        let mut o = opts(&[("dir", "/custom/path")]);
        p.apply_defaults(&mut o).unwrap();
        assert_eq!(o.get("dir").and_then(|v| v.as_str()), Some("/custom/path"));
    }

    #[test]
    fn default_on_required_rejected() {
        let toml = r#"
schema_version = 1
kind = "test"
name = "Test"
[options]
required = ["dir"]
optional = []
[options.defaults]
dir = "/var/lib/test"
"#;
        let p = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap();
        let mut o = opts(&[]);
        let err = p.apply_defaults(&mut o).unwrap_err();
        assert!(matches!(err, PolicyError::DefaultOnRequiredOption(ref k) if k == "dir"));
    }

    #[test]
    fn default_on_undeclared_rejected() {
        let toml = r#"
schema_version = 1
kind = "test"
name = "Test"
[options]
required = []
optional = []
[options.defaults]
dir = "/var/lib/test"
"#;
        let p = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap();
        let mut o = opts(&[]);
        let err = p.apply_defaults(&mut o).unwrap_err();
        assert!(matches!(err, PolicyError::DefaultOnUndeclaredOption(ref k) if k == "dir"));
    }

    #[test]
    fn default_template_rejects_option_ref() {
        let toml = r#"
schema_version = 1
kind = "test"
name = "Test"
[options]
required = []
optional = ["a", "b"]
[options.defaults]
a = "$option:b"
"#;
        let p = PluginPolicy::from_toml_bytes(toml.as_bytes()).unwrap();
        let mut o = opts(&[]);
        // `$option:b` is rejected because the default-resolver passes
        // empty known_options.
        let err = p.apply_defaults(&mut o).unwrap_err();
        assert!(matches!(err, PolicyError::UndeclaredOptionRef(_, _)));
    }

    #[test]
    fn signature_input_concatenates() {
        let wasm = b"\0asm".to_vec();
        let policy = b"schema_version = 1".to_vec();
        let combined = signature_input(&wasm, &policy);
        assert_eq!(combined.len(), wasm.len() + policy.len());
        assert_eq!(&combined[..wasm.len()], &wasm[..]);
        assert_eq!(&combined[wasm.len()..], &policy[..]);
    }
}
