use std::process::{Command, Output};
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rosec"))
        .args(args)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent/rosec-cli-test",
        )
        .env("ROSEC_SOCKET", "/nonexistent/rosec-cli-test")
        .output()
        .unwrap()
}
#[test]
fn provider_first_help_and_collision_escape() {
    for args in [
        vec!["provider", "personal", "unlock", "--help"],
        vec!["provider", "personal", "password", "add", "--help"],
        vec!["provider", "--id", "auth", "unlock", "--help"],
    ] {
        let out = cli(&args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
#[test]
fn strict_deprecation_rejects_before_connecting_or_prompting() {
    for args in [
        vec!["--deny-deprecated", "provider", "auth", "personal"],
        vec!["provider", "add-password", "personal", "--deny-deprecated"],
        vec![
            "--deny-deprecated",
            "provider",
            "list-passwords",
            "personal",
        ],
    ] {
        let out = cli(&args);
        let error = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2));
        assert!(error.contains("deprecated command syntax"), "{error}");
        assert!(error.contains("rosec provider"));
        assert!(!error.contains("D-Bus"));
    }
}
#[test]
fn top_level_unlock_is_not_deprecated() {
    let out = cli(&["--deny-deprecated", "unlock", "--help"]);
    assert!(out.status.success());
}
#[test]
fn malformed_legacy_command_is_not_reinterpreted() {
    let out = cli(&["provider", "auth"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("<ID>"));
}
#[test]
fn captured_legacy_output_has_no_deprecation_warning() {
    let out = cli(&["provider", "list-passwords", "personal"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("deprecated"));
}

#[test]
fn vault_recovery_help_and_legacy_strict_mode() {
    let out = cli(&["vault", "snapshot", "restore", "--help"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("<SNAPSHOT>"));
    assert!(help.contains("--path"));
    assert!(help.contains("--yes"));
    let out = cli(&[
        "--deny-deprecated",
        "provider",
        "restore-snapshot",
        "--path",
        "vault",
        "--snapshot",
        "backup",
        "--yes",
    ]);
    assert_eq!(out.status.code(), Some(2));
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(error.contains("deprecated command syntax"));
    assert!(error.contains("rosec vault snapshot restore"));
}
#[test]
fn recovery_requires_explicit_acknowledgement() {
    let out = cli(&["vault", "snapshot", "restore", "backup", "--path", "vault"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--yes"));
}
