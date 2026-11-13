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
async fn plain_individual_and_bulk_reads_preserve_selected_mime() {
    use rosec_core::{NewItem, SecretBytes};
    use std::collections::HashMap;
    use zbus::{OwnedObjectPath, OwnedVariant, Variant};
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(rosec_vault::LocalVault::new(
        "mime",
        dir.path().join("vault"),
    ));
    vault
        .unlock(UnlockInput::Password(zeroize::Zeroizing::new(
            "fixture-password".into(),
        )))
        .await
        .unwrap();
    vault
        .create_item(
            NewItem {
                label: "fixture".into(),
                item_type: None,
                attributes: HashMap::new(),
                secrets: HashMap::from([
                    ("secret".into(), SecretBytes::new(vec![0, 255, 128, 0])),
                    ("other".into(), SecretBytes::new(b"unrelated".to_vec())),
                ]),
                content_types: HashMap::from([(
                    "secret".into(),
                    "application/x-fixture; p=exact".into(),
                )]),
            },
            false,
        )
        .await
        .unwrap();
    let (server, state) = setup(vec![vault.clone()]).await;
    let entries = state.rebuild_cache().await.unwrap();
    let path = OwnedObjectPath::try_from(entries[0].0.clone()).unwrap();
    let client = zbus::Connection::session().await.unwrap();
    let destination = server.unique_name().unwrap().as_str();
    let service = zbus::Proxy::new(
        &client,
        destination,
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let (_, session): (OwnedVariant, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Variant::from("")))
        .await
        .unwrap();
    let item = zbus::Proxy::new(
        &client,
        destination,
        path.as_str(),
        "org.freedesktop.Secret.Item",
    )
    .await
    .unwrap();
    type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
    let (one,): (Secret,) = item.call("GetSecret", &(session.clone(),)).await.unwrap();
    let bulk: HashMap<OwnedObjectPath, Secret> = service
        .call("GetSecrets", &(vec![path.clone()], session.clone()))
        .await
        .unwrap();
    assert_eq!(one, bulk[&path]);
    assert_eq!(one.2, [0, 255, 128, 0]);
    assert_eq!(one.3, "application/x-fixture; p=exact");
    vault.lock().await.unwrap();
    assert!(item.call_method("GetSecret", &(session,)).await.is_err());
}
