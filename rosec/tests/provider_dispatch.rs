//! Run under dbus-run-session; no real provider or credentials are used.
use std::sync::{Arc, Mutex};
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
struct Fixture {
    calls: Arc<Mutex<Vec<String>>>,
}
#[zbus::interface(name = "org.rosec.Daemon")]
impl Fixture {
    fn list_passwords(&self, id: &str) -> Vec<(String, String)> {
        self.calls.lock().unwrap().push(format!("passwords:{id}"));
        vec![("entry".into(), "laptop".into())]
    }
    fn provider_list(&self) -> Vec<ProviderEntry> {
        vec![
            (
                "personal".into(),
                "Personal".into(),
                "fixture".into(),
                false,
                false,
                false,
                0,
                0,
                vec!["Sync".into()],
            ),
            (
                "readonly".into(),
                "Readonly".into(),
                "fixture".into(),
                false,
                false,
                false,
                0,
                0,
                vec![],
            ),
        ]
    }
    fn sync_provider(&self, id: &str) -> u32 {
        self.calls.lock().unwrap().push(format!("sync:{id}"));
        7
    }
}
async fn run(args: &[&str]) -> std::process::Output {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_rosec"))
            .args(args)
            .env_remove("ROSEC_SOCKET")
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_spellings_dispatch_identically_and_scope_instance_operations() {
    let calls = Arc::new(Mutex::new(vec![]));
    let _server = zbus::connection::Builder::session()
        .name("org.freedesktop.secrets")
        .serve_at(
            "/org/rosec/Daemon",
            Fixture {
                calls: Arc::clone(&calls),
            },
        )
        .build()
        .await
        .unwrap();
    let old = run(&["provider", "list-passwords", "personal"]).await;
    let new = run(&["provider", "personal", "password", "list"]).await;
    assert!(old.status.success());
    assert_eq!(old.status.code(), new.status.code());
    assert_eq!(old.stdout, new.stdout);
    assert_eq!(old.stderr, new.stderr);
    let status = run(&["provider", "personal", "status"]).await;
    assert!(status.status.success());
    assert!(String::from_utf8_lossy(&status.stdout).contains("personal"));
    assert!(!String::from_utf8_lossy(&status.stdout).contains("readonly"));
    assert!(
        run(&["provider", "personal", "sync"])
            .await
            .status
            .success()
    );
    assert!(
        !run(&["provider", "readonly", "sync"])
            .await
            .status
            .success()
    );
    let old_recovery = run(&[
        "provider",
        "restore-snapshot",
        "--path",
        "unused",
        "--snapshot",
        "unused-backup",
        "--yes",
    ])
    .await;
    let new_recovery = run(&[
        "vault",
        "snapshot",
        "restore",
        "unused-backup",
        "--path",
        "unused",
        "--yes",
    ])
    .await;
    assert!(!old_recovery.status.success());
    assert_eq!(old_recovery.status.code(), new_recovery.status.code());
    assert_eq!(old_recovery.stderr, new_recovery.stderr);
    assert!(String::from_utf8_lossy(&new_recovery.stderr).contains("stop rosecd"));
    assert_eq!(
        *calls.lock().unwrap(),
        vec!["passwords:personal", "passwords:personal", "sync:personal"]
    );
}
