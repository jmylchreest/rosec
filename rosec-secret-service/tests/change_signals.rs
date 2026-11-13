mod support;
use futures_util::StreamExt;
use std::time::Duration;
use support::{MutableProvider, setup};
use zbus::OwnedObjectPath;

#[tokio::test]
async fn refresh_signals_follow_visible_changes_and_deleted_objects_disappear() {
    let provider = MutableProvider::new("a");
    let (server, state) = setup(vec![provider.clone()]).await;
    let client = zbus::Connection::session().await.unwrap();
    let dest = server.unique_name().unwrap().as_str();
    let collection = zbus::Proxy::new(
        &client,
        dest,
        "/org/freedesktop/secrets/collection/default",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let alias = zbus::Proxy::new(
        &client,
        dest,
        "/org/freedesktop/secrets/aliases/login",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let mut created = collection.receive_signal("ItemCreated").await.unwrap();
    let mut changed = collection.receive_signal("ItemChanged").await.unwrap();
    let mut deleted = collection.receive_signal("ItemDeleted").await.unwrap();
    let mut alias_created = alias.receive_signal("ItemCreated").await.unwrap();
    provider.put("one", "original");
    state.rebuild_cache().await.unwrap();
    let event = tokio::time::timeout(Duration::from_secs(2), created.next())
        .await
        .unwrap()
        .unwrap();
    let (path,): (OwnedObjectPath,) = event.body().deserialize().unwrap();
    let alias_event = tokio::time::timeout(Duration::from_secs(2), alias_created.next())
        .await
        .unwrap()
        .unwrap();
    let (alias_path,): (OwnedObjectPath,) = alias_event.body().deserialize().unwrap();
    assert_eq!(path, alias_path);
    let item = zbus::Proxy::new(&client, dest, path.as_str(), "org.freedesktop.Secret.Item")
        .await
        .unwrap();
    assert_eq!(
        item.get_property::<String>("Label").await.unwrap(),
        "original"
    );
    let properties = zbus::Proxy::new(
        &client,
        dest,
        path.as_str(),
        "org.freedesktop.DBus.Properties",
    )
    .await
    .unwrap();
    let mut property_changes = properties
        .receive_signal("PropertiesChanged")
        .await
        .unwrap();
    provider.put("one", "renamed");
    state.rebuild_cache().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), changed.next())
        .await
        .unwrap()
        .unwrap();
    let event = tokio::time::timeout(Duration::from_secs(2), property_changes.next())
        .await
        .unwrap()
        .unwrap();
    let (interface, values, invalidated): (
        String,
        std::collections::HashMap<String, zbus::OwnedVariant>,
        Vec<String>,
    ) = event.body().deserialize().unwrap();
    assert_eq!(interface, "org.freedesktop.Secret.Item");
    assert!(values.is_empty());
    assert!(invalidated.contains(&"Label".to_owned()));
    provider.items.lock().unwrap().clear();
    state.rebuild_cache().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), deleted.next())
        .await
        .unwrap()
        .unwrap();
    assert!(
        properties
            .call_method("Get", &("org.freedesktop.Secret.Item", "Label"))
            .await
            .is_err()
    );
    state.rebuild_cache().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(80), deleted.next())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn direct_create_replace_delete_emit_the_same_lifecycle_as_refreshes() {
    use std::collections::HashMap;
    use zbus::{OwnedVariant, Variant};
    let provider = MutableProvider::new("a");
    let (server, _state) = setup(vec![provider]).await;
    let client = zbus::Connection::session().await.unwrap();
    let dest = server.unique_name().unwrap().as_str();
    let service = zbus::Proxy::new(
        &client,
        dest,
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let (_, session): (OwnedVariant, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Variant::from("")))
        .await
        .unwrap();
    let collection = zbus::Proxy::new(
        &client,
        dest,
        "/org/freedesktop/secrets/collection/default",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let mut created = collection.receive_signal("ItemCreated").await.unwrap();
    let mut changed = collection.receive_signal("ItemChanged").await.unwrap();
    let mut deleted = collection.receive_signal("ItemDeleted").await.unwrap();
    let secret = (session, Vec::<u8>::new(), b"secret".to_vec(), "text/plain");
    let mut props = HashMap::new();
    props.insert("org.freedesktop.Secret.Item.Label", Variant::from("first"));
    let (path, prompt): (OwnedObjectPath, OwnedObjectPath) = collection
        .call("CreateItem", &(props, &secret, false))
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    tokio::time::timeout(Duration::from_secs(2), created.next())
        .await
        .unwrap()
        .unwrap();
    let mut props = HashMap::new();
    props.insert("org.freedesktop.Secret.Item.Label", Variant::from("second"));
    let (replacement, _): (OwnedObjectPath, OwnedObjectPath) = collection
        .call("CreateItem", &(props, &secret, true))
        .await
        .unwrap();
    assert_eq!(path, replacement);
    tokio::time::timeout(Duration::from_secs(2), changed.next())
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), created.next())
            .await
            .is_err()
    );
    let item = zbus::Proxy::new(&client, dest, path.as_str(), "org.freedesktop.Secret.Item")
        .await
        .unwrap();
    let prompt: OwnedObjectPath = item.call("Delete", &()).await.unwrap();
    assert_eq!(prompt.as_str(), "/");
    tokio::time::timeout(Duration::from_secs(2), deleted.next())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn subscriber_recovers_after_journal_overflow_and_reports_final_lock_state() {
    let provider = MutableProvider::new("a");
    provider.put("one", "one");
    let (server, state) = setup(vec![provider.clone()]).await;
    let client = zbus::Connection::session().await.unwrap();
    let dest = server.unique_name().unwrap().as_str();
    let collection = zbus::Proxy::new(
        &client,
        dest,
        "/org/freedesktop/secrets/collection/default",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let mut created = collection.receive_signal("ItemCreated").await.unwrap();
    let entries = state.rebuild_cache().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), created.next())
        .await
        .unwrap()
        .unwrap();
    let properties = zbus::Proxy::new(
        &client,
        dest,
        entries[0].0.as_str(),
        "org.freedesktop.DBus.Properties",
    )
    .await
    .unwrap();
    let mut changed = properties
        .receive_signal("PropertiesChanged")
        .await
        .unwrap();
    let before = state.change_snapshot().0;
    // No await: deliberately outrun the adapter and the bounded journal.
    for _ in 0..300 {
        state.mark_provider_locked_in_cache("a");
        state.mark_provider_unlocked_in_cache("a");
    }
    provider
        .locked
        .store(true, std::sync::atomic::Ordering::SeqCst);
    state.mark_provider_locked_in_cache("a");
    assert!(matches!(
        state.changes_since(before),
        rosec_core::changes::ChangesSince::ResyncRequired { .. }
    ));
    tokio::time::timeout(Duration::from_secs(2), changed.next())
        .await
        .unwrap()
        .unwrap();
    let locked: zbus::OwnedVariant = properties
        .call("Get", &("org.freedesktop.Secret.Item", "Locked"))
        .await
        .unwrap();
    assert!(bool::try_from(locked).unwrap());
}

#[tokio::test]
async fn empty_collection_lock_change_invalidates_its_locked_property() {
    let provider = MutableProvider::new("a");
    let (server, state) = setup(vec![provider.clone()]).await;
    let client = zbus::Connection::session().await.unwrap();
    let dest = server.unique_name().unwrap().as_str();
    // Seed and observe one transition so the adapter has established its baseline.
    provider.put("one", "one");
    let collection = zbus::Proxy::new(
        &client,
        dest,
        "/org/freedesktop/secrets/collection/default",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let mut created = collection.receive_signal("ItemCreated").await.unwrap();
    state.rebuild_cache().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), created.next())
        .await
        .unwrap()
        .unwrap();
    let mut deleted = collection.receive_signal("ItemDeleted").await.unwrap();
    provider.items.lock().unwrap().clear();
    state.rebuild_cache().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), deleted.next())
        .await
        .unwrap()
        .unwrap();
    let properties = zbus::Proxy::new(
        &client,
        dest,
        "/org/freedesktop/secrets/collection/default",
        "org.freedesktop.DBus.Properties",
    )
    .await
    .unwrap();
    let mut changed = properties
        .receive_signal("PropertiesChanged")
        .await
        .unwrap();
    provider
        .locked
        .store(true, std::sync::atomic::Ordering::SeqCst);
    state.mark_provider_locked_in_cache("a");
    let event = tokio::time::timeout(Duration::from_secs(2), changed.next())
        .await
        .unwrap()
        .unwrap();
    let (_, _, names): (
        String,
        std::collections::HashMap<String, zbus::OwnedVariant>,
        Vec<String>,
    ) = event.body().deserialize().unwrap();
    assert!(names.iter().any(|name| name == "Locked"));
}

#[tokio::test]
async fn migration_rebuilds_objects_and_notifies_on_the_new_connection() {
    let provider = MutableProvider::new("a");
    provider.put("one", "one");
    let (_old, state) = setup(vec![provider.clone()]).await;
    state.rebuild_cache().await.unwrap();
    let new = zbus::Connection::session().await.unwrap();
    state.swap_conn(new.clone());
    rosec_secret_service::server::re_register_top_level_objects(&new, &state)
        .await
        .unwrap();
    let client = zbus::Connection::session().await.unwrap();
    let dest = new.unique_name().unwrap().as_str();
    let collection = zbus::Proxy::new(
        &client,
        dest,
        "/org/freedesktop/secrets/collection/default",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let mut changed = collection.receive_signal("ItemChanged").await.unwrap();
    state.clear_registered_items();
    let entries = state.rebuild_cache().await.unwrap();
    let properties = zbus::Proxy::new(
        &client,
        dest,
        entries[0].0.as_str(),
        "org.freedesktop.DBus.Properties",
    )
    .await
    .unwrap();
    let label: zbus::OwnedVariant = properties
        .call("Get", &("org.freedesktop.Secret.Item", "Label"))
        .await
        .unwrap();
    assert_eq!(String::try_from(label).unwrap(), "one");
    // Wait until this adapter has observed the new bus before changing metadata.
    // A no-op refresh must not be needed for the later mutation to reach it.
    let mut created = collection.receive_signal("ItemCreated").await.unwrap();
    provider.put("two", "two");
    state.rebuild_cache().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), created.next())
        .await
        .unwrap()
        .unwrap();
    provider.put("two", "renamed");
    state.rebuild_cache().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), changed.next())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn confirmed_content_changes_notify_even_when_public_metadata_is_identical() {
    let provider = MutableProvider::new("a");
    provider.put("one", "one");
    let (server, state) = setup(vec![provider]).await;
    let client = zbus::Connection::session().await.unwrap();
    let collection = zbus::Proxy::new(
        &client,
        server.unique_name().unwrap().as_str(),
        "/org/freedesktop/secrets/collection/default",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let mut created = collection.receive_signal("ItemCreated").await.unwrap();
    let mut changed = collection.receive_signal("ItemChanged").await.unwrap();
    state.rebuild_cache().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), created.next())
        .await
        .unwrap()
        .unwrap();
    let before = state.change_snapshot().0;
    state.note_provider_content_changed("a");
    assert_eq!(
        before,
        state.change_snapshot().0,
        "hint must not publish before reconciliation"
    );
    state.rebuild_cache().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), changed.next())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn readding_a_provider_under_the_same_id_rebinds_existing_objects() {
    let old = MutableProvider::new("a");
    old.put("one", "one");
    // Omit the background adapter to deterministically model a lagging subscriber.
    let server = zbus::Connection::session().await.unwrap();
    let state = std::sync::Arc::new(rosec_secret_service::ServiceState::new(
        vec![old],
        std::sync::Arc::new(rosec_core::router::Router::new(
            rosec_core::router::RouterConfig {
                dedup_strategy: rosec_core::DedupStrategy::Priority,
                dedup_time_fallback: rosec_core::DedupTimeFallback::None,
            },
        )),
        std::sync::Arc::new(rosec_secret_service::session::SessionManager::new()),
        server.clone(),
        tokio::runtime::Handle::current(),
    ));
    rosec_secret_service::server::re_register_top_level_objects(&server, &state)
        .await
        .unwrap();
    let path = state.rebuild_cache().await.unwrap()[0].0.clone();
    assert!(state.hotreload_remove_provider("a").await);
    let replacement = MutableProvider::new("a");
    replacement.put("one", "one");
    *replacement.secret.lock().unwrap() = b"replacement-secret".to_vec();
    state.hotreload_add_provider(replacement);
    state.rebuild_cache().await.unwrap();
    let client = zbus::Connection::session().await.unwrap();
    let dest = server.unique_name().unwrap().as_str();
    let service = zbus::Proxy::new(
        &client,
        dest,
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let (_, session): (zbus::OwnedVariant, OwnedObjectPath) = service
        .call("OpenSession", &("plain", zbus::Variant::from("")))
        .await
        .unwrap();
    let item = zbus::Proxy::new(&client, dest, path.as_str(), "org.freedesktop.Secret.Item")
        .await
        .unwrap();
    let (secret,): ((OwnedObjectPath, Vec<u8>, Vec<u8>, String),) =
        item.call("GetSecret", &(session,)).await.unwrap();
    assert_eq!(secret.2, b"replacement-secret");
    let collection = zbus::Proxy::new(
        &client,
        dest,
        "/org/freedesktop/secrets/collection/default",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    assert!(!collection.get_property::<bool>("Locked").await.unwrap());
}

#[tokio::test]
async fn adapter_recovers_on_a_new_connection_after_delivery_failure() {
    let provider = MutableProvider::new("a");
    provider.put("one", "one");
    let (server, state) = setup(vec![provider.clone()]).await;
    state.rebuild_cache().await.unwrap();
    server.clone().close().await.unwrap();
    state.mark_provider_locked_in_cache("a");
    // Give the adapter a chance to hit the closed connection and schedule retry.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let new = zbus::Connection::session().await.unwrap();
    rosec_secret_service::server::re_register_top_level_objects(&new, &state)
        .await
        .unwrap();
    let client = zbus::Connection::session().await.unwrap();
    let collection = zbus::Proxy::new(
        &client,
        new.unique_name().unwrap().as_str(),
        "/org/freedesktop/secrets/collection/default",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let mut created = collection.receive_signal("ItemCreated").await.unwrap();
    state.swap_conn(new.clone());
    state.clear_registered_items();
    state.rebuild_cache().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), created.next())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn delete_during_refresh_cannot_restore_a_deleted_item() {
    let provider = MutableProvider::new("a");
    provider.put("one", "one");
    let (server, state) = setup(vec![provider.clone()]).await;
    let path = state.rebuild_cache().await.unwrap()[0].0.clone();
    let client = zbus::Connection::session().await.unwrap();
    let item = zbus::Proxy::new(
        &client,
        server.unique_name().unwrap().as_str(),
        path.as_str(),
        "org.freedesktop.Secret.Item",
    )
    .await
    .unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (resume, wait) = tokio::sync::oneshot::channel();
    *provider.pause.lock().unwrap() = Some((started, wait));
    let refresh_state = state.clone();
    let task = tokio::spawn(async move { refresh_state.rebuild_cache().await.unwrap() });
    ready.await.unwrap();
    let _: OwnedObjectPath = item.call("Delete", &()).await.unwrap();
    resume.send(()).unwrap();
    assert!(task.await.unwrap().is_empty());
    assert!(state.change_snapshot().1.is_empty());
}

#[tokio::test]
async fn create_during_refresh_is_not_lost_to_the_older_listing() {
    let provider = MutableProvider::new("a");
    provider.put("one", "one");
    let (server, state) = setup(vec![provider.clone()]).await;
    state.rebuild_cache().await.unwrap();
    let client = zbus::Connection::session().await.unwrap();
    let dest = server.unique_name().unwrap().as_str();
    let service = zbus::Proxy::new(
        &client,
        dest,
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let (_, session): (zbus::OwnedVariant, OwnedObjectPath) = service
        .call("OpenSession", &("plain", zbus::Variant::from("")))
        .await
        .unwrap();
    let collection = zbus::Proxy::new(
        &client,
        dest,
        "/org/freedesktop/secrets/collection/default",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (resume, wait) = tokio::sync::oneshot::channel();
    *provider.pause.lock().unwrap() = Some((started, wait));
    let refresh_state = state.clone();
    let task = tokio::spawn(async move { refresh_state.rebuild_cache().await.unwrap() });
    ready.await.unwrap();
    let properties = std::collections::HashMap::<String, zbus::Variant<'_>>::new();
    let secret = (session, Vec::<u8>::new(), b"fixture".to_vec(), "text/plain");
    let (path, _): (OwnedObjectPath, OwnedObjectPath) = collection
        .call("CreateItem", &(properties, secret, false))
        .await
        .unwrap();
    resume.send(()).unwrap();
    assert!(
        task.await
            .unwrap()
            .iter()
            .any(|(key, _)| key == path.as_str())
    );
    assert!(
        state
            .change_snapshot()
            .1
            .iter()
            .any(|meta| meta.id == "written")
    );
}
