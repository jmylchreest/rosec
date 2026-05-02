fn main() {
    println!("cargo:rerun-if-changed=../build_info.rs");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs/");

    let version = git_version().unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    let sha = git_sha().unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=ROSEC_VERSION={version}");
    println!("cargo:rustc-env=ROSEC_GIT_SHA={sha}");
}

/// Mirror the Justfile/GHA version derivation from `git describe`.
///
/// Pattern: `v{major}.{minor}.{patch}-{commits}-g{hash}`
///   - commits == 0  → `{major}.{minor}.{patch}`
///   - commits >  0  → `{major}.{minor}.{patch+1}-dev.{commits}+{hash}`
fn git_version() -> Option<String> {
    let output = std::process::Command::new("git")
        .args([
            "describe", "--tags", "--always", "--long", "--match", "v[0-9]*",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let describe = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let rest = describe.strip_prefix('v')?;
    let (before_hash, hash) = rest.rsplit_once("-g")?;
    let (semver, commits_str) = before_hash.rsplit_once('-')?;

    let mut parts = semver.splitn(3, '.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    let patch: u32 = parts.next()?.parse().ok()?;
    let commits: u32 = commits_str.parse().ok()?;

    if commits == 0 {
        Some(format!("{major}.{minor}.{patch}"))
    } else {
        let next_patch = patch + 1;
        Some(format!("{major}.{minor}.{next_patch}-dev.{commits}+{hash}"))
    }
}

fn git_sha() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let dirty = std::process::Command::new("git")
        .args(["diff", "--quiet", "HEAD"])
        .status()
        .ok()
        .is_some_and(|s| !s.success());

    if dirty {
        Some(format!("{sha}*"))
    } else {
        Some(sha)
    }
}
