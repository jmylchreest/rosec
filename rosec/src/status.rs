//! `rosec status` — show daemon, providers, and component versions.

use std::path::PathBuf;

use anyhow::Result;

use crate::{ProviderEntry, config_path, conn, load_config, render_provider_table};

pub async fn run() -> Result<()> {
    let ver = format!("{} ({})", env!("ROSEC_VERSION"), env!("ROSEC_GIT_SHA"));
    let cfg_path = config_path();
    let cfg_display = cfg_path
        .strip_prefix(
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default(),
        )
        .map(|rel| format!("~/{}", rel.display()))
        .unwrap_or_else(|_| cfg_path.display().to_string());

    let socket_display = if std::env::var_os("ROSEC_SOCKET").is_some() {
        "private socket"
    } else {
        "session bus"
    };

    println!("  {:<14}{ver}", "Daemon");
    println!("  {:<14}{cfg_display}", "Config");
    println!("  {:<14}{socket_display}", "Socket");
    println!();

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let (cache_size,): (u32,) = proxy.call("Status", &()).await?;

    let cfg = load_config();
    let disabled: Vec<&rosec_core::config::ProviderEntry> =
        cfg.provider.iter().filter(|p| !p.enabled).collect();
    let providers: Vec<ProviderEntry> = proxy.call("ProviderList", &()).await?;

    println!("Providers");

    if providers.is_empty() && disabled.is_empty() {
        println!("  (none configured)");
    } else {
        let registry = rosec_wasm::discovery::scan_plugins(
            rosec_core::WasmPreference::default(),
            rosec_core::WasmVerify::default(),
            &cfg.service.wasm_trusted_key,
        );
        let is_experimental_kind = |k: &str| -> bool {
            registry
                .get(k)
                .map(|p| p.manifest.experimental)
                .unwrap_or(false)
        };

        // Indented two spaces to sit under the "Providers" heading.
        let any_experimental =
            render_provider_table(&providers, &disabled, &is_experimental_kind, "  ");
        if any_experimental {
            println!("  *: experimental provider — interfaces and behaviour may change");
        }
    }
    println!();

    println!("Daemon");
    println!("  {:<14}{cache_size} items", "Items");
    println!();

    println!("Components");
    println!("  {:<22}{ver}", "rosec");

    for bin in &["rosecd", "rosec-prompt"] {
        let bin_ver = probe_binary_version(bin).unwrap_or_else(|| "not found".to_string());
        println!("  {:<22}{bin_ver}", bin);
    }

    let pam_unlock_ver = probe_binary_version("rosec-pam-unlock")
        .or_else(|| probe_binary_version_at("/usr/lib/rosec/rosec-pam-unlock"));
    println!(
        "  {:<22}{}",
        "rosec-pam-unlock",
        pam_unlock_ver.unwrap_or_else(|| "not found".to_string())
    );

    let pam_so = std::path::Path::new("/usr/lib/security/pam_rosec.so");
    println!(
        "  {:<22}{}",
        "pam_rosec.so",
        if pam_so.exists() {
            "installed"
        } else {
            "not found"
        }
    );

    Ok(())
}

/// Run `<binary> --version` and return the first line of output, or `None`.
fn probe_binary_version(name: &str) -> Option<String> {
    let output = std::process::Command::new(name)
        .arg("--version")
        .output()
        .ok()?;
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        String::from_utf8_lossy(&output.stdout).to_string()
    };
    let line = text.lines().next()?.trim().to_string();
    let ver = line
        .strip_prefix(name)
        .map(|s| s.trim().to_string())
        .unwrap_or(line);
    if ver.is_empty() { None } else { Some(ver) }
}

/// Run a binary at an absolute path with `--version`.
fn probe_binary_version_at(path: &str) -> Option<String> {
    if !std::path::Path::new(path).exists() {
        return None;
    }
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()?;
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        String::from_utf8_lossy(&output.stdout).to_string()
    };
    let line = text.lines().next()?.trim().to_string();
    let bin_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let ver = line
        .strip_prefix(bin_name)
        .map(|s| s.trim().to_string())
        .unwrap_or(line);
    if ver.is_empty() { None } else { Some(ver) }
}
