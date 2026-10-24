//! Explicit per-user configuration includes shared by the CLI and daemon.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use toml::Value;

use crate::config::Config;

const MAX_DEPTH: usize = 16;
const MAX_FILES: usize = 128;
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Effective configuration and directories to watch for edits or symlink changes.
#[derive(Debug)]
pub struct LoadedConfig {
    pub config: Config,
    pub watch_dirs: BTreeSet<PathBuf>,
}

/// Load a user config and its explicit `include = ["file.toml", ...]` files.
///
/// Includes are applied in order, before the containing file. Relative paths
/// use the containing file's lexical parent, including for symlinked files.
/// Tables merge recursively; arrays replace, except nonempty trusted-key lists
/// which append. An explicit empty trusted-key list clears inherited keys.
/// A missing root file uses defaults; missing includes and invalid files fail.
/// No system directories, environment substitutions or globs are consulted.
pub fn load(path: &Path) -> Result<LoadedConfig> {
    let path = std::path::absolute(path)?;
    let mut loader = Loader::default();
    let mut value = Value::Table(toml::Table::new());
    loader.file(&path, true, &mut value)?;
    let config = value.try_into().map_err(|_| {
        anyhow::anyhow!(
            "invalid configuration in {} (values omitted)",
            path.display()
        )
    })?;
    Ok(LoadedConfig {
        config,
        watch_dirs: loader.watch_dirs,
    })
}

#[derive(Default)]
struct Loader {
    stack: Vec<PathBuf>,
    count: usize,
    watch_dirs: BTreeSet<PathBuf>,
}

impl Loader {
    fn file(&mut self, path: &Path, optional: bool, merged: &mut Value) -> Result<()> {
        if self.stack.len() >= MAX_DEPTH || self.count >= MAX_FILES {
            bail!("configuration include limit exceeded at {}", path.display());
        }
        self.count += 1;
        if let Some(parent) = path.parent() {
            self.watch_dirs.insert(parent.to_path_buf());
        }
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(e) if optional && e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(e) => {
                return Err(e).with_context(|| format!("cannot read config {}", path.display()));
            }
        };
        if !file.metadata()?.is_file() {
            bail!("config must be a regular file: {}", path.display());
        }
        let canonical = path
            .canonicalize()
            .with_context(|| format!("cannot resolve config {}", path.display()))?;
        if self.stack.contains(&canonical) {
            bail!("configuration include cycle at {}", path.display());
        }
        if let Some(parent) = canonical.parent() {
            self.watch_dirs.insert(parent.to_path_buf());
        }
        let mut text = String::new();
        file.take(MAX_FILE_BYTES + 1)
            .read_to_string(&mut text)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        if text.len() as u64 > MAX_FILE_BYTES {
            bail!("config exceeds 1 MiB: {}", path.display());
        }
        // Parser diagnostics can echo credentials from the source line.
        let mut document: toml::Table = toml::from_str(&text)
            .map_err(|_| anyhow::anyhow!("invalid TOML in {} (values omitted)", path.display()))?;
        let includes = match document.remove("include") {
            None => Vec::new(),
            Some(Value::Array(entries)) => entries
                .into_iter()
                .map(|entry| match entry {
                    Value::String(path) if !path.is_empty() => Ok(path),
                    _ => bail!(
                        "include must contain nonempty file paths in {}",
                        path.display()
                    ),
                })
                .collect::<Result<Vec<_>>>()?,
            Some(_) => bail!(
                "include must be an array of file paths in {}",
                path.display()
            ),
        };
        // Validate every layer, even if a later file overrides the invalid value.
        let _: Config = toml::from_str(&text).map_err(|_| {
            anyhow::anyhow!(
                "invalid configuration in {} (values omitted)",
                path.display()
            )
        })?;
        self.stack.push(canonical);
        for include in includes {
            let parent = path.parent().context("config path has no parent")?;
            self.file(&parent.join(include), false, merged)?;
        }
        self.stack.pop();
        merge(merged, Value::Table(document), "");
        Ok(())
    }
}

fn merge(base: &mut Value, overlay: Value, path: &str) {
    match (base, overlay) {
        (Value::Table(base), Value::Table(overlay)) => {
            for (key, value) in overlay {
                let child_path = if path.is_empty() {
                    key.to_owned()
                } else {
                    format!("{path}.{key}")
                };
                if let Some(existing) = base.get_mut(&key) {
                    merge(existing, value, &child_path);
                } else {
                    base.insert(key, value);
                }
            }
        }
        (Value::Array(base), Value::Array(mut overlay))
            if path == "service.wasm_trusted_key" && !overlay.is_empty() =>
        {
            base.append(&mut overlay);
        }
        (base, overlay) => *base = overlay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn includes_merge_keys_and_main_overrides_settings() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("first.toml"),
            r#"
[service]
ssh_fuse = false
[[service.wasm_trusted_key]]
name = "vendor"
key = "public"
kinds = ["bitwarden-pm"]
"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("second.toml"),
            "[service]\nssh_fuse = true\ntotp_fuse = false",
        )
        .unwrap();
        let main = dir.path().join("config.toml");
        fs::write(
            &main,
            r#"
include = ["first.toml", "second.toml"]
[service]
ssh_fuse = false
[[service.wasm_trusted_key]]
name = "personal"
key = "another"
kinds = ["custom"]
"#,
        )
        .unwrap();
        let loaded = load(&main).unwrap();
        assert!(!loaded.config.service.ssh_fuse);
        assert!(!loaded.config.service.totp_fuse);
        assert_eq!(loaded.config.service.wasm_trusted_key.len(), 2);
        assert_eq!(loaded.config.service.wasm_trusted_key[0].name, "vendor");
        assert_eq!(loaded.config.service.wasm_trusted_key[1].kinds, ["custom"]);
    }

    #[test]
    fn missing_main_uses_defaults_but_missing_include_fails() {
        let dir = tempdir().unwrap();
        let main = dir.path().join("config.toml");
        assert!(load(&main).unwrap().config.provider.is_empty());
        fs::write(&main, "include = ['missing']").unwrap();
        assert!(load(&main).is_err());
    }

    #[test]
    fn nested_relative_paths_and_array_replacement() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("parts")).unwrap();
        fs::write(
            dir.path().join("config.toml"),
            "include = ['parts/extra.toml']\n[prompt]\nargs = ['main']",
        )
        .unwrap();
        fs::write(
            dir.path().join("parts/extra.toml"),
            "include = ['last.toml']",
        )
        .unwrap();
        fs::write(
            dir.path().join("parts/last.toml"),
            "[prompt]\nargs = ['fragment']\nbackend = 'custom'",
        )
        .unwrap();
        let cfg = load(&dir.path().join("config.toml")).unwrap().config;
        assert_eq!(cfg.prompt.args, ["main"]);
        assert_eq!(cfg.prompt.backend, "custom");
    }

    #[test]
    fn empty_keys_explicitly_clear_inherited_trust() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("keys"),
            "[[service.wasm_trusted_key]]\nkey = 'public'\nname = 'vendor'",
        )
        .unwrap();
        let main = dir.path().join("config.toml");
        fs::write(
            &main,
            "include = ['keys']\n[service]\nwasm_trusted_key = []",
        )
        .unwrap();
        assert!(
            load(&main)
                .unwrap()
                .config
                .service
                .wasm_trusted_key
                .is_empty()
        );
    }

    #[test]
    fn cycles_and_invalid_files_fail_without_secret_values() {
        let dir = tempdir().unwrap();
        let main = dir.path().join("config.toml");
        fs::write(&main, "include = ['config.toml']").unwrap();
        assert!(load(&main).unwrap_err().to_string().contains("cycle"));
        for content in [
            "[service]\nwasm_verify = 'TOP_SECRET'",
            "password = 'TOP_SECRET",
            "include = 'TOP_SECRET'",
        ] {
            fs::write(&main, content).unwrap();
            let error = format!("{:#}", load(&main).unwrap_err());
            assert!(!error.contains("TOP_SECRET"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn follows_home_manager_symlinks_and_detects_symlink_cycles() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("store")).unwrap();
        fs::write(dir.path().join("store/keys"), "[service]\nssh_fuse = false").unwrap();
        std::os::unix::fs::symlink("store/keys", dir.path().join("keys")).unwrap();
        let main = dir.path().join("config.toml");
        fs::write(&main, "include = ['keys']").unwrap();
        let loaded = load(&main).unwrap();
        assert!(!loaded.config.service.ssh_fuse);
        assert!(loaded.watch_dirs.contains(&dir.path().join("store")));
        fs::write(dir.path().join("store/keys"), "include = ['config.toml']").unwrap();
        assert!(load(&main).unwrap_err().to_string().contains("cycle"));
    }
    #[test]
    fn nested_clear_does_not_restore_previously_inherited_keys() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("old"),
            "[[service.wasm_trusted_key]]\nkey = 'old'\nname = 'old'",
        )
        .unwrap();
        fs::write(dir.path().join("clear"), "[service]\nwasm_trusted_key = []").unwrap();
        fs::write(
            dir.path().join("new"),
            "include = ['clear']\n[[service.wasm_trusted_key]]\nkey = 'new'\nname = 'new'",
        )
        .unwrap();
        fs::write(dir.path().join("config.toml"), "include = ['old', 'new']").unwrap();
        let cfg = load(&dir.path().join("config.toml")).unwrap().config;
        assert_eq!(cfg.service.wasm_trusted_key.len(), 1);
        assert_eq!(cfg.service.wasm_trusted_key[0].name, "new");
    }

    #[test]
    fn rejects_include_depth_file_count_and_size_limits() {
        let dir = tempdir().unwrap();
        for i in 0..=MAX_DEPTH {
            fs::write(
                dir.path().join(i.to_string()),
                format!("include = ['{}']", i + 1),
            )
            .unwrap();
        }
        assert!(
            load(&dir.path().join("0"))
                .unwrap_err()
                .to_string()
                .contains("limit")
        );
        fs::write(dir.path().join("empty"), "").unwrap();
        fs::write(
            dir.path().join("many"),
            format!("include = [{}]", vec!["'empty'"; MAX_FILES].join(",")),
        )
        .unwrap();
        assert!(
            load(&dir.path().join("many"))
                .unwrap_err()
                .to_string()
                .contains("limit")
        );
        fs::write(
            dir.path().join("big"),
            " ".repeat(MAX_FILE_BYTES as usize + 1),
        )
        .unwrap();
        assert!(
            load(&dir.path().join("big"))
                .unwrap_err()
                .to_string()
                .contains("1 MiB")
        );
    }

    #[test]
    fn cli_edits_preserve_includes_and_do_not_modify_fragments() {
        let dir = tempdir().unwrap();
        let fragment = dir.path().join("settings.toml");
        let content = "[service]\nrefresh_interval_secs = 10";
        fs::write(&fragment, content).unwrap();
        let main = dir.path().join("config.toml");
        fs::write(&main, "include = ['settings.toml']").unwrap();
        crate::config_edit::set_value(&main, "service.refresh_interval_secs", "20").unwrap();
        assert_eq!(
            load(&main).unwrap().config.service.refresh_interval_secs,
            Some(20)
        );
        assert_eq!(fs::read_to_string(fragment).unwrap(), content);
        assert!(fs::read_to_string(main).unwrap().contains("include"));
    }
}
