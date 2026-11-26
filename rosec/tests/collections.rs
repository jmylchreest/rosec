use std::{path::Path, process::Output};

fn run(path: &Path, args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_rosec"))
        .env_remove("ROSEC_SOCKET")
        .arg("--config")
        .arg(path)
        .arg("collection")
        .args(args)
        .output()
        .unwrap()
}

type ProviderEntry = (
    String,
    String,
    String,
    bool,
    bool,
    bool,
    u64,
    u64,
    Vec<String>,
);

struct Daemon;

#[zbus::interface(name = "org.rosec.Daemon")]
impl Daemon {
    fn provider_list(&self) -> Vec<ProviderEntry> {
        [("personal", true), ("work", true), ("external", false)]
            .into_iter()
            .map(|(id, writable)| {
                let caps = if writable {
                    vec!["Write".into()]
                } else {
                    vec![]
                };
                (
                    id.into(),
                    id.into(),
                    "fixture".into(),
                    false,
                    false,
                    false,
                    0,
                    0,
                    caps,
                )
            })
            .collect()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn configure_collection_and_alias_through_cli() {
    let _daemon = zbus::connection::Builder::session()
        .serve_at("/org/rosec/Daemon", Daemon)
        .name("org.freedesktop.secrets")
        .build()
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let main = dir.path().join("config.toml");
    let fragment = dir.path().join("packaged.toml");
    let included =
        "[[collection]]\nid = 'shared'\nproviders = ['external']\naliases = ['default']\n";
    std::fs::write(&fragment, included).unwrap();
    let root = "include = ['packaged.toml']\n\n# Keep this setting\n[service]\nrefresh_interval_secs = 12\n";
    std::fs::write(&main, root).unwrap();

    let failure = run(
        &main,
        &[
            "set",
            "work",
            "--provider",
            "work",
            "--provider",
            "personal",
        ],
    );
    assert!(!failure.status.success());
    assert!(String::from_utf8_lossy(&failure.stderr).contains("multiple writable providers"));
    assert_eq!(std::fs::read_to_string(&main).unwrap(), root);
    let failure = run(
        &main,
        &[
            "set",
            "work",
            "--provider",
            "external",
            "--write-provider",
            "external",
        ],
    );
    assert!(!failure.status.success());
    assert!(String::from_utf8_lossy(&failure.stderr).contains("must be a write-capable member"));

    for args in [
        vec![
            "set",
            "work",
            "--provider",
            "work",
            "--provider",
            "personal",
            "--write-provider",
            "work",
        ],
        vec!["alias", "default", "work"],
        vec!["alias", "login", "work"],
        vec!["alias", "login"],
        vec!["remove", "shared"],
    ] {
        let output = run(&main, &args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let config = rosec_core::config_load::load(&main).unwrap().config;
    assert_eq!(config.collection.len(), 1);
    assert_eq!(config.collection[0].aliases, ["default"]);
    assert_eq!(config.collection[0].write_provider.as_deref(), Some("work"));
    assert!(
        std::fs::read_to_string(&main)
            .unwrap()
            .contains("# Keep this setting")
    );
    assert_eq!(std::fs::read_to_string(fragment).unwrap(), included);

    let output = run(&main, &["list"]);
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("work: work, personal (write: work; aliases: default)")
    );
    assert!(run(&main, &["alias", "login", "all"]).status.success());
    let config = rosec_core::config_load::load(&main).unwrap().config;
    assert_eq!(
        config
            .collection
            .iter()
            .find(|entry| entry.id == "all")
            .unwrap()
            .aliases,
        ["login"]
    );
    assert!(run(&main, &["alias", "login"]).status.success());
    assert!(run(&main, &["remove", "work"]).status.success());
    assert!(
        rosec_core::config_load::load(&main)
            .unwrap()
            .config
            .collection
            .is_empty()
    );
}
