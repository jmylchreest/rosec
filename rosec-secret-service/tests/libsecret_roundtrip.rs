//! Opt-in real libsecret interoperability against a disposable native vault.
use rosec_core::{Provider, UnlockInput};
use std::sync::Arc;
pub async fn setup(
    providers: Vec<Arc<dyn Provider>>,
) -> (
    zbus::Connection,
    Arc<rosec_secret_service::state::ServiceState>,
) {
    let conn = zbus::Connection::session().await.unwrap();
    let router = Arc::new(rosec_core::router::Router::new(
        rosec_core::router::RouterConfig {
            dedup_strategy: rosec_core::DedupStrategy::Priority,
            dedup_time_fallback: rosec_core::DedupTimeFallback::None,
        },
    ));
    let state = rosec_secret_service::server::register_objects(
        &conn,
        providers,
        router,
        Arc::new(rosec_secret_service::session::SessionManager::new()),
    )
    .await
    .unwrap();
    (conn, state)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires private dbus-run-session and ROSEC_LIBSECRET_CLIENT"]
async fn native_vault_libsecret_roundtrip() {
    let root = std::env::var("ROSEC_LIBSECRET_FIXTURE").expect("isolated fixture directory");
    let vault = Arc::new(rosec_vault::LocalVault::new(
        "interop",
        format!("{root}/test.vault"),
    ));
    vault
        .unlock(UnlockInput::Password(zeroize::Zeroizing::new(
            "disposable-test-password".to_owned(),
        )))
        .await
        .unwrap();
    let (server, _state) = setup(vec![vault.clone()]).await;
    server
        .request_name("org.freedesktop.secrets")
        .await
        .unwrap();
    let client = std::env::var("ROSEC_LIBSECRET_CLIENT").unwrap();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("timeout")
            .args(["45", &client])
            .env("G_DBUS_DEBUG", "message")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let trace = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::write(format!("{root}/dbus-trace.log"), &trace).unwrap();
    assert!(output.status.success(), "libsecret failed: {trace}");
    assert!(
        trace.contains("dh-ietf1024-sha256-aes128-cbc-pkcs7"),
        "encrypted negotiation missing"
    );
    assert!(!trace.contains("('plain',"), "unexpected plain fallback");
    assert!(trace.contains("ROUNDTRIP PASS"));
    assert!(vault.list_items().await.unwrap().is_empty());
}
