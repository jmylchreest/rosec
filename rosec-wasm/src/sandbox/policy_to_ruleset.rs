//! Translate `PluginPolicy` + resolved option values into the path/port lists
//! `rosec_core::sandbox::landlock::apply_paths_and_ports` consumes.
//!
//! Pure function — no kernel calls, easily unit-tested.

use std::path::PathBuf;

use rosec_core::sandbox::landlock::{ConnectPort, FsMode, PathRule};
use url::Url;

use crate::policy::ResolvedPolicy;

/// Build the (paths, ports) tuple for a provider's Landlock ruleset.
///
/// `allowed_hosts` is the host-effective set the daemon computed (policy
/// baseline + user `allowed_hosts`/`additional_hosts`). We translate each
/// host to an HTTPS+HTTP port pair; the kernel-level rule is "TCP connect
/// to port 443/80 is allowed", with the user-space `host_http` allow-list
/// providing the host-name granularity that Landlock alone can't express.
#[allow(dead_code)] // wired into the worker in the next commit
pub(crate) fn policy_to_ruleset(
    resolved: &ResolvedPolicy,
    allowed_hosts: &[String],
) -> (Vec<PathRule>, Vec<ConnectPort>) {
    let mut paths = base_provider_paths();

    for (host_template, _guest_path) in &resolved.allowed_paths {
        let (path, mode) = strip_ro_prefix(host_template);
        paths.push(PathRule {
            path: PathBuf::from(path),
            mode,
        });
    }

    for file in &resolved.allowed_files {
        paths.push(PathRule::ro(file.clone()));
    }

    let ports = if allowed_hosts.is_empty() {
        Vec::new()
    } else {
        // Allow standard HTTP(S) and provider-declared explicit ports parsed
        // from any URL-shaped host strings. Most providers use port 443; some
        // self-hosted setups expose alternate ports (8443, etc.).
        let mut ports: Vec<u16> = vec![443, 80];
        for host in allowed_hosts {
            if let Some(p) = explicit_port_from_host(host)
                && !ports.contains(&p)
            {
                ports.push(p);
            }
        }
        ports.into_iter().map(ConnectPort).collect()
    };

    (paths, ports)
}

/// The minimum filesystem surface every WASM provider needs for libc /
/// wasmtime startup. wasmtime's signal-handling thread reads /proc/self,
/// and any host_http call goes through libc/dlopen for transitive
/// dependencies.
fn base_provider_paths() -> Vec<PathRule> {
    vec![
        PathRule::ro("/usr/lib"),
        PathRule::ro("/lib"),
        PathRule::ro("/usr/lib64"),
        PathRule::ro("/lib64"),
        PathRule::ro("/etc/ld.so.cache"),
        PathRule::ro("/etc/ld.so.preload"),
        PathRule::ro("/etc/ssl"),
        PathRule::ro("/etc/resolv.conf"),
        PathRule::ro("/etc/nsswitch.conf"),
        PathRule::ro("/etc/hosts"),
        // /proc/self for wasmtime/libc introspection.
        PathRule::ro("/proc/self"),
        // /sys/devices/system/cpu for libc thread-count detection used by
        // some allocators and TLS init.
        PathRule::ro("/sys/devices/system/cpu"),
    ]
}

/// `policy.resolve()` prefixes read-only host paths with `"ro:"`. Strip
/// that and return the corresponding [`FsMode`].
fn strip_ro_prefix(host_template: &str) -> (&str, FsMode) {
    if let Some(stripped) = host_template.strip_prefix("ro:") {
        (stripped, FsMode::Ro)
    } else {
        (host_template, FsMode::Rw)
    }
}

/// Extract an explicit port from a host string when it looks URL-shaped
/// (e.g. `"https://vault.example.com:8443"`). Returns `None` for plain
/// hostnames or wildcards.
fn explicit_port_from_host(host: &str) -> Option<u16> {
    if !host.contains("://") {
        // Try parsing as `host:port` for the bare form some providers use.
        if let Some((_, port)) = host.rsplit_once(':')
            && let Ok(p) = port.parse::<u16>()
        {
            return Some(p);
        }
        return None;
    }
    Url::parse(host).ok().and_then(|u| u.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_hosts_no_ports() {
        let resolved = ResolvedPolicy::default();
        let (paths, ports) = policy_to_ruleset(&resolved, &[]);
        assert!(ports.is_empty());
        // Still gets the base provider paths.
        assert!(paths.iter().any(|r| r.path.starts_with("/usr/lib")));
    }

    #[test]
    fn hosts_yield_default_https_ports() {
        let resolved = ResolvedPolicy::default();
        let hosts = vec!["api.bitwarden.com".to_string()];
        let (_paths, ports) = policy_to_ruleset(&resolved, &hosts);
        let port_values: Vec<u16> = ports.iter().map(|p| p.0).collect();
        assert!(port_values.contains(&443));
        assert!(port_values.contains(&80));
    }

    #[test]
    fn explicit_port_extracted() {
        assert_eq!(
            explicit_port_from_host("https://vault.example.com:8443"),
            Some(8443)
        );
        assert_eq!(
            explicit_port_from_host("vault.example.com:9443"),
            Some(9443)
        );
        assert_eq!(explicit_port_from_host("api.bitwarden.com"), None);
        assert_eq!(explicit_port_from_host("*.bitwarden.com"), None);
    }

    #[test]
    fn explicit_port_added_to_ruleset() {
        let resolved = ResolvedPolicy::default();
        let hosts = vec!["https://vault.example.com:8443".to_string()];
        let (_paths, ports) = policy_to_ruleset(&resolved, &hosts);
        let port_values: Vec<u16> = ports.iter().map(|p| p.0).collect();
        assert!(port_values.contains(&8443));
    }

    #[test]
    fn allowed_files_become_ro_paths() {
        let resolved = ResolvedPolicy {
            allowed_paths: vec![],
            allowed_files: vec![PathBuf::from("/home/user/test.kdbx")],
        };
        let (paths, _) = policy_to_ruleset(&resolved, &[]);
        let kdbx = paths
            .iter()
            .find(|r| r.path.as_path() == std::path::Path::new("/home/user/test.kdbx"));
        assert!(kdbx.is_some());
        assert_eq!(kdbx.unwrap().mode, FsMode::Ro);
    }

    #[test]
    fn ro_prefix_stripped_correctly() {
        let resolved = ResolvedPolicy {
            allowed_paths: vec![
                ("ro:/etc/some/dir".to_string(), PathBuf::from("/dir")),
                ("/var/state".to_string(), PathBuf::from("/state")),
            ],
            allowed_files: vec![],
        };
        let (paths, _) = policy_to_ruleset(&resolved, &[]);
        let etc = paths
            .iter()
            .find(|r| r.path.as_path() == std::path::Path::new("/etc/some/dir"));
        let var = paths
            .iter()
            .find(|r| r.path.as_path() == std::path::Path::new("/var/state"));
        assert_eq!(etc.unwrap().mode, FsMode::Ro);
        assert_eq!(var.unwrap().mode, FsMode::Rw);
    }
}
