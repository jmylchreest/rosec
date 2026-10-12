use std::process::{Command, Output};

fn run(path: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rosec"))
        .arg("--config")
        .arg(path)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn cli_reads_included_values_and_preserves_fragments_on_edit() {
    let dir = tempfile::tempdir().unwrap();
    let main = dir.path().join("config.toml");
    let fragment = dir.path().join("packaged.toml");
    let contents = "[service]\nrefresh_interval_secs = 17\n[[service.wasm_trusted_key]]\nname = 'packaged'\nkey = 'public'\nkinds = ['bitwarden-pm']";
    std::fs::write(&fragment, contents).unwrap();
    std::fs::write(&main, "include = ['packaged.toml']").unwrap();
    let get = run(&main, &["config", "get", "service.refresh_interval_secs"]);
    assert!(get.status.success(), "{:?}", get);
    assert_eq!(String::from_utf8_lossy(&get.stdout).trim(), "17");
    let show = run(&main, &["config", "show", "--show-defaults"]);
    assert!(show.status.success());
    assert!(String::from_utf8_lossy(&show.stdout).contains("packaged"));
    let set = run(
        &main,
        &["config", "set", "service.refresh_interval_secs", "23"],
    );
    assert!(set.status.success(), "{:?}", set);
    assert_eq!(std::fs::read_to_string(fragment).unwrap(), contents);
    assert!(std::fs::read_to_string(&main).unwrap().contains("include"));
    let get = run(&main, &["config", "get", "service.refresh_interval_secs"]);
    assert_eq!(String::from_utf8_lossy(&get.stdout).trim(), "23");
}

#[test]
fn cli_rejects_invalid_includes_instead_of_using_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let main = dir.path().join("config.toml");
    std::fs::write(&main, "include = ['missing.toml']").unwrap();
    for args in [
        vec!["config", "get", "service.refresh_interval_secs"],
        vec!["provider", "kinds"],
    ] {
        let output = run(&main, &args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("missing.toml"));
    }
}
