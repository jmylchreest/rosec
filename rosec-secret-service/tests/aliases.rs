use rosec_core::router::{Router, RouterConfig};
use rosec_secret_service::{server::register_objects, session::SessionManager};
use std::{collections::HashMap, sync::Arc};
use zbus::{OwnedObjectPath, Variant};

#[tokio::test]
async fn advertised_aliases_expose_the_same_virtual_collection() {
    let server = zbus::Connection::session().await.unwrap();
    let router = Arc::new(Router::new(RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    }));
    let _state = register_objects(&server, vec![], router, Arc::new(SessionManager::new()))
        .await
        .unwrap();
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
    let canonical = "/org/freedesktop/secrets/collection/default";
    for alias in ["default", "login"] {
        let path: OwnedObjectPath = service.call("ReadAlias", &(alias,)).await.unwrap();
        assert_eq!(path.as_str(), canonical);
        let alias_path = format!("/org/freedesktop/secrets/aliases/{alias}");
        for path in [canonical, alias_path.as_str()] {
            let collection = zbus::Proxy::new(
                &client,
                destination,
                path,
                "org.freedesktop.Secret.Collection",
            )
            .await
            .unwrap();
            assert_eq!(
                collection.get_property::<String>("Label").await.unwrap(),
                "default"
            );
            assert!(
                collection
                    .get_property::<Vec<OwnedObjectPath>>("Items")
                    .await
                    .unwrap()
                    .is_empty()
            );
            let items: Vec<OwnedObjectPath> = collection
                .call("SearchItems", &(HashMap::<String, String>::new(),))
                .await
                .unwrap();
            assert!(items.is_empty());
        }
        service
            .call_method(
                "SetAlias",
                &(alias, OwnedObjectPath::try_from(canonical).unwrap()),
            )
            .await
            .unwrap();
    }
    // Preserve established startup shims: this fix only supplies the missing
    // object for the already-advertised login alias.
    for (alias, expected) in [
        ("default", canonical),
        ("", canonical),
        ("login", "/"),
        ("custom", "/"),
    ] {
        let (collection, prompt): (OwnedObjectPath, OwnedObjectPath) = service
            .call(
                "CreateCollection",
                &(HashMap::<String, Variant<'static>>::new(), alias),
            )
            .await
            .unwrap();
        assert_eq!(collection.as_str(), expected);
        assert_eq!(prompt.as_str(), "/");
    }
    let unknown: OwnedObjectPath = service.call("ReadAlias", &("custom",)).await.unwrap();
    assert_eq!(unknown.as_str(), "/");
}
