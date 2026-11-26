mod support;

use std::{collections::HashMap, sync::Arc, sync::atomic::Ordering};

use rosec_core::{
    Provider,
    config::{Config, PromptConfig},
    router::{Router, RouterConfig},
};
use rosec_secret_service::{
    server::{SERVICE_PATH, register_objects_with_full_config},
    session::SessionManager,
};
use support::MutableProvider;
use zbus::{OwnedObjectPath, OwnedVariant, Proxy, Variant};

#[tokio::test]
async fn collection_membership_aliases_and_write_ownership_over_dbus() {
    let server = zbus::Connection::session().await.unwrap();
    let client = zbus::Connection::session().await.unwrap();
    let primary = MutableProvider::new("primary");
    let secondary = MutableProvider::new("secondary");
    let external = MutableProvider::with_write("external", false);
    let unassigned = MutableProvider::new("unassigned");
    secondary.put("written", "secondary item");
    external.put("outside", "external item");
    unassigned.put("hidden", "unassigned item");
    // Deliberate duplicates used to collapse under global deduplication.
    for provider in [&secondary, &external] {
        provider.items.lock().unwrap()[0]
            .attributes
            .insert("account".into(), "same".into());
    }

    let config = collection_config();
    let providers: Vec<Arc<dyn Provider>> = vec![
        primary.clone(),
        secondary.clone(),
        external.clone(),
        unassigned.clone(),
    ];
    let state = register_objects_with_full_config(
        &server,
        providers,
        Arc::new(Router::new(RouterConfig {
            dedup_strategy: rosec_core::DedupStrategy::Priority,
            dedup_time_fallback: rosec_core::DedupTimeFallback::None,
        })),
        Arc::new(SessionManager::new()),
        HashMap::new(),
        HashMap::new(),
        PromptConfig::default(),
        config,
    )
    .await
    .unwrap();
    state.rebuild_cache().await.unwrap();
    let dest = server.unique_name().unwrap().as_str();
    let service = Proxy::new(
        &client,
        dest,
        SERVICE_PATH,
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let collections: Vec<OwnedObjectPath> = service.get_property("Collections").await.unwrap();
    assert_eq!(collections.len(), 4);
    for (alias, expected) in [
        ("default", "work"),
        ("login", "all"),
        ("shared", "external_only"),
    ] {
        let path: OwnedObjectPath = service.call("ReadAlias", &(alias,)).await.unwrap();
        assert_eq!(
            path.as_str(),
            format!("{SERVICE_PATH}/collection/{expected}")
        );
        let alias_view = Proxy::new(
            &client,
            dest,
            format!("{SERVICE_PATH}/aliases/{alias}"),
            "org.freedesktop.Secret.Collection",
        )
        .await
        .unwrap();
        assert_eq!(
            alias_view.get_property::<String>("Label").await.unwrap(),
            expected
        );
        let (from_create, prompt): (OwnedObjectPath, OwnedObjectPath) = service
            .call(
                "CreateCollection",
                &(HashMap::<String, Variant<'static>>::new(), alias),
            )
            .await
            .unwrap();
        assert_eq!(path, from_create);
        assert_eq!(prompt.as_str(), "/");
    }

    let work_path = collections
        .iter()
        .find(|path| path.as_str().ends_with("/work"))
        .unwrap();
    service
        .call::<_, _, ()>("SetAlias", &("default", work_path))
        .await
        .unwrap();
    let error = service
        .call_method("SetAlias", &("new_alias", work_path))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("org.freedesktop.DBus.Error.NotSupported:"),
        "{error}"
    );

    let (_, session): (OwnedVariant, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Variant::from("")))
        .await
        .unwrap();
    let secret = (session, Vec::<u8>::new(), b"fixture".to_vec(), "text/plain");
    let work = Proxy::new(
        &client,
        dest,
        format!("{SERVICE_PATH}/aliases/default"),
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let archive = Proxy::new(
        &client,
        dest,
        format!("{SERVICE_PATH}/collection/archive"),
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let readonly = Proxy::new(
        &client,
        dest,
        format!("{SERVICE_PATH}/aliases/shared"),
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();

    let attributes = HashMap::from([("account", "same")]);
    let archive_items: Vec<OwnedObjectPath> =
        archive.call("SearchItems", &(&attributes,)).await.unwrap();
    let external_items: Vec<OwnedObjectPath> =
        readonly.call("SearchItems", &(&attributes,)).await.unwrap();
    assert_eq!(archive_items.len(), 1);
    assert_eq!(external_items.len(), 1);
    let (items, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
        .call("SearchItems", &(HashMap::<String, String>::new(),))
        .await
        .unwrap();
    assert!(locked.is_empty());
    assert_eq!(
        items.len(),
        3,
        "the built-in collection includes unassigned providers"
    );

    use futures_util::StreamExt as _;
    let work_created = work.receive_signal("ItemCreated").await.unwrap();
    let archive_created = archive.receive_signal("ItemCreated").await.unwrap();

    let properties =
        |label| HashMap::from([("org.freedesktop.Secret.Item.Label", Variant::from(label))]);
    let (path, prompt): (OwnedObjectPath, OwnedObjectPath) = work
        .call("CreateItem", &(properties("new"), &secret, false))
        .await
        .unwrap();
    assert!(path.as_str().contains("/default/primary_"), "{path}");
    assert_eq!(prompt.as_str(), "/");
    assert_eq!(primary.items.lock().unwrap()[0].label, "new");
    let matches_path = |msg: &zbus::Message| {
        msg.body()
            .deserialize::<OwnedObjectPath>()
            .is_ok_and(|item| item == path)
    };
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            work_created
                .filter(|msg| std::future::ready(matches_path(msg)))
                .next()
        )
        .await
        .unwrap()
        .is_some()
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            archive_created
                .filter(|msg| std::future::ready(matches_path(msg)))
                .next()
        )
        .await
        .is_err()
    );

    let (replaced, _): (OwnedObjectPath, OwnedObjectPath) = work
        .call("CreateItem", &(properties("secondary item"), &secret, true))
        .await
        .unwrap();
    assert_eq!(
        replaced, archive_items[0],
        "replacement keeps the original owner and path"
    );

    for (collection, replace, label) in [(&work, true, "external item"), (&readonly, false, "new")]
    {
        let error = collection
            .call_method("CreateItem", &(properties(label), &secret, replace))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("org.freedesktop.DBus.Error.NotSupported:"),
            "{error}"
        );
    }
    let item = Proxy::new(
        &client,
        dest,
        external_items[0].clone(),
        "org.freedesktop.Secret.Item",
    )
    .await
    .unwrap();
    let error = item.call_method("Delete", &()).await.unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("org.freedesktop.DBus.Error.NotSupported:"),
        "{error}"
    );

    let all = Proxy::new(
        &client,
        dest,
        format!("{SERVICE_PATH}/aliases/login"),
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let mut props = properties("service-selected destination");
    props.insert(
        "org.freedesktop.Secret.Item.Attributes",
        Variant::from(HashMap::from([("account", "a new account")])),
    );
    let (path, prompt): (OwnedObjectPath, OwnedObjectPath) = all
        .call("CreateItem", &(props, &secret, false))
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    assert!(path.as_str().contains("/default/unassigned_"), "{path}");
    assert_eq!(
        unassigned.items.lock().unwrap()[0].label,
        "service-selected destination"
    );

    // Locking one collection acts on its own members, including any shared provider.
    let archive_path = collections
        .iter()
        .find(|path| path.as_str().ends_with("/archive"))
        .unwrap();
    let (_, _): (Vec<OwnedObjectPath>, OwnedObjectPath) =
        service.call("Lock", &(vec![archive_path],)).await.unwrap();
    assert!(secondary.locked.load(Ordering::SeqCst));
    assert!(!primary.locked.load(Ordering::SeqCst));
    assert!(!external.locked.load(Ordering::SeqCst));
    let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service
        .call("Unlock", &(vec![archive_path],))
        .await
        .unwrap();
    assert!(unlocked.is_empty());
    assert_ne!(prompt.as_str(), "/");

    secondary.locked.store(false, Ordering::SeqCst);
    primary.locked.store(true, Ordering::SeqCst);
    let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = work
        .call("CreateItem", &(properties("locked target"), &secret, false))
        .await
        .unwrap();
    assert_eq!(item.as_str(), "/");
    assert_ne!(prompt.as_str(), "/");
    assert_eq!(primary.items.lock().unwrap()[0].label, "new");

    // Reuse the same bus and alias proxy while applying new membership and writers.
    let mut next = collection_config();
    next.collection.remove(1);
    next.collection[0].providers = vec!["secondary".into(), "external".into()];
    next.collection[0].write_provider = Some("secondary".into());
    next.collection[0].aliases.clear();
    next.collection.push(rosec_core::config::CollectionConfig {
        id: "new_view".into(),
        providers: vec!["secondary".into()],
        write_provider: None,
        aliases: vec!["default".into()],
    });
    state.reload_collections(&next).await.unwrap();
    let default: OwnedObjectPath = service.call("ReadAlias", &("default",)).await.unwrap();
    assert!(default.as_str().ends_with("/new_view"));
    let items: Vec<OwnedObjectPath> = work
        .call("SearchItems", &(HashMap::<String, String>::new(),))
        .await
        .unwrap();
    assert_eq!(
        items, archive_items,
        "the original alias proxy sees the new view and stable item path"
    );
    assert!(
        archive
            .call_method("SearchItems", &(HashMap::<String, String>::new(),))
            .await
            .is_err()
    );

    let changed_work = Proxy::new(
        &client,
        dest,
        format!("{SERVICE_PATH}/collection/work"),
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let (written, prompt): (OwnedObjectPath, OwnedObjectPath) = changed_work
        .call("CreateItem", &(properties("after reload"), &secret, false))
        .await
        .unwrap();
    assert_eq!(written, archive_items[0]);
    assert_eq!(prompt.as_str(), "/");
    assert_eq!(secondary.items.lock().unwrap()[0].label, "after reload");

    next.collection[0].write_provider = Some("primary".into());
    assert!(state.reload_collections(&next).await.is_err());
    let default: OwnedObjectPath = service.call("ReadAlias", &("default",)).await.unwrap();
    assert!(default.as_str().ends_with("/new_view"));

    state.reload_collections(&Config::default()).await.unwrap();
    let default: OwnedObjectPath = service.call("ReadAlias", &("default",)).await.unwrap();
    assert!(default.as_str().ends_with("/default"));
    let items: Vec<OwnedObjectPath> = work
        .call("SearchItems", &(HashMap::<String, String>::new(),))
        .await
        .unwrap();
    assert!(items.contains(&written));
}

fn collection_config() -> Config {
    Config {
        service: rosec_core::config::ServiceConfig {
            write_provider: Some("unassigned".into()),
            ..Default::default()
        },
        all_collection_aliases: vec!["login".into()],
        collection: [
            (
                "work",
                vec!["primary", "secondary", "external"],
                Some("primary"),
                vec!["default"],
            ),
            ("archive", vec!["secondary"], None, vec![]),
            ("external_only", vec!["external"], None, vec!["shared"]),
        ]
        .into_iter()
        .map(
            |(id, providers, writer, aliases)| rosec_core::config::CollectionConfig {
                id: id.into(),
                providers: providers.into_iter().map(str::to_owned).collect(),
                write_provider: writer.map(str::to_owned),
                aliases: aliases.into_iter().map(str::to_owned).collect(),
            },
        )
        .collect(),
        ..Config::default()
    }
}
