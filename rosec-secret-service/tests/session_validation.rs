use std::{collections::HashMap, sync::Arc};

use rosec_core::router::{Router, RouterConfig};
use rosec_secret_service::{server::register_objects, session::SessionManager};
use zbus::{OwnedObjectPath, OwnedVariant, Variant};

#[tokio::test]
async fn missing_and_closed_sessions_are_rejected_before_secret_processing() {
    let server = zbus::Connection::session().await.unwrap();
    let destination = server.unique_name().unwrap().to_string();
    let sessions = Arc::new(SessionManager::new());
    let router = Arc::new(Router::new(RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    }));
    let _state = register_objects(&server, vec![], router, Arc::clone(&sessions))
        .await
        .unwrap();
    let client = zbus::Connection::session().await.unwrap();
    let service = zbus::Proxy::new(
        &client,
        destination.as_str(),
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let collection = zbus::Proxy::new(
        &client,
        destination.as_str(),
        "/org/freedesktop/secrets/collection/default",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let (_, closed): (OwnedVariant, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Variant::from("")))
        .await
        .unwrap();
    sessions.close_session(closed.as_str()).unwrap();
    for path in [
        OwnedObjectPath::try_from("/").unwrap(),
        OwnedObjectPath::try_from("/missing").unwrap(),
        closed,
    ] {
        let props = HashMap::<String, Variant<'static>>::new();
        let secret = (path.clone(), vec![0u8; 16], vec![1u8; 16], "text/plain");
        let err = collection
            .call_method("CreateItem", &(props, secret, false))
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("org.freedesktop.Secret.Error.NoSession:"),
            "{err}"
        );
        let err = service
            .call_method("GetSecrets", &(Vec::<OwnedObjectPath>::new(), path))
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("org.freedesktop.Secret.Error.NoSession:"),
            "{err}"
        );
    }
    let (_, plain): (OwnedVariant, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Variant::from("")))
        .await
        .unwrap();
    let result: HashMap<OwnedObjectPath, (OwnedObjectPath, Vec<u8>, Vec<u8>, String)> = service
        .call("GetSecrets", &(Vec::<OwnedObjectPath>::new(), plain))
        .await
        .unwrap();
    assert!(result.is_empty());
}
