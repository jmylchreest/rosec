use rosec_core::router::{Router, RouterConfig};
use rosec_secret_service::{
    error::SecretServiceError, server::register_objects, session::SessionManager,
};
use std::{collections::HashMap, sync::Arc};
use zbus::{OwnedObjectPath, OwnedVariant, Variant};

struct ErrorProbe;
#[zbus::interface(name = "org.rosec.TestErrors")]
impl ErrorProbe {
    fn invalid_args(&self) -> Result<(), SecretServiceError> {
        Err(zbus::fdo::Error::InvalidArgs("fixture invalid argument".into()).into())
    }
    fn access_denied(&self) -> Result<(), SecretServiceError> {
        Err(zbus::fdo::Error::AccessDenied("fixture denied".into()).into())
    }
    fn locked(&self) -> Result<(), SecretServiceError> {
        Err(SecretServiceError::IsLocked("fixture locked".into()))
    }
}

#[tokio::test]
async fn standard_errors_keep_their_wire_names_and_algorithm_fallback_works() {
    let server = zbus::Connection::session().await.unwrap();
    let router = Arc::new(Router::new(RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    }));
    let _state = register_objects(&server, vec![], router, Arc::new(SessionManager::new()))
        .await
        .unwrap();
    server
        .object_server()
        .at("/probe", ErrorProbe)
        .await
        .unwrap();
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
    let error = service
        .call_method("OpenSession", &("unsupported-fixture", Variant::from("")))
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
    let collection = zbus::Proxy::new(
        &client,
        dest,
        "/org/freedesktop/secrets/collection/default",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let secret = (session, Vec::<u8>::new(), b"fixture".to_vec(), "text/plain");
    let error = collection
        .call_method(
            "CreateItem",
            &(HashMap::<String, Variant<'static>>::new(), secret, false),
        )
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("org.freedesktop.DBus.Error.NotSupported:"),
        "{error}"
    );
    let probe = zbus::Proxy::new(&client, dest, "/probe", "org.rosec.TestErrors")
        .await
        .unwrap();
    for (method, name) in [
        ("InvalidArgs", "org.freedesktop.DBus.Error.InvalidArgs"),
        ("AccessDenied", "org.freedesktop.DBus.Error.AccessDenied"),
        ("Locked", "org.freedesktop.Secret.Error.IsLocked"),
    ] {
        let error = probe.call_method(method, &()).await.unwrap_err();
        assert!(
            error.to_string().starts_with(&format!("{name}:")),
            "{error}"
        );
    }
}

#[tokio::test]
async fn malformed_dh_requests_report_invalid_args() {
    let server = zbus::Connection::session().await.unwrap();
    let router = Arc::new(Router::new(RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    }));
    let _state = register_objects(&server, vec![], router, Arc::new(SessionManager::new()))
        .await
        .unwrap();
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
    let algorithm = "dh-ietf1024-sha256-aes128-cbc-pkcs7";
    for input in [Variant::from("invalid"), Variant::from(vec![0u8])] {
        let error = service
            .call_method("OpenSession", &(algorithm, input))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("org.freedesktop.DBus.Error.InvalidArgs:"),
            "{error}"
        );
    }
    let (_, session): (OwnedVariant, OwnedObjectPath) = service
        .call("OpenSession", &(algorithm, Variant::from(vec![2u8])))
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
    let secret = (session, vec![0u8; 3], vec![0u8; 16], "text/plain");
    let error = collection
        .call_method(
            "CreateItem",
            &(HashMap::<String, Variant<'static>>::new(), secret, false),
        )
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("org.freedesktop.DBus.Error.InvalidArgs:"),
        "{error}"
    );
}

#[derive(Debug)]
struct ProbeProvider {
    id: &'static str,
    locked: std::sync::atomic::AtomicBool,
    deletes: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl rosec_core::Provider for ProbeProvider {
    fn id(&self) -> &str {
        self.id
    }
    fn name(&self) -> &str {
        self.id
    }
    fn kind(&self) -> &str {
        "probe"
    }
    async fn status(&self) -> Result<rosec_core::ProviderStatus, rosec_core::ProviderError> {
        Ok(rosec_core::ProviderStatus {
            locked: self.locked.load(std::sync::atomic::Ordering::SeqCst),
            last_sync: None,
            cached: false,
            offline_cache: false,
            last_cache_write: None,
        })
    }
    async fn unlock(
        &self,
        input: rosec_core::UnlockInput,
    ) -> Result<(), rosec_core::ProviderError> {
        if let rosec_core::UnlockInput::Password(password) = input
            && password.as_str() == format!("{}-password", self.id)
        {
            self.locked
                .store(false, std::sync::atomic::Ordering::SeqCst);
            return Ok(());
        }
        Err(rosec_core::ProviderError::Other(anyhow::anyhow!(
            "fixture password mismatch"
        )))
    }
    async fn lock(&self) -> Result<(), rosec_core::ProviderError> {
        Ok(())
    }
    async fn list_items(&self) -> Result<Vec<rosec_core::ItemMeta>, rosec_core::ProviderError> {
        Ok(vec![rosec_core::ItemMeta {
            id: "item".into(),
            provider_id: self.id.into(),
            label: self.id.into(),
            attributes: [("provider".into(), self.id.into())].into(),
            locked: self.locked.load(std::sync::atomic::Ordering::SeqCst),
            created: None,
            modified: None,
            attribute_hashes: None,
        }])
    }
    async fn search(
        &self,
        _: &rosec_core::Attributes,
    ) -> Result<Vec<rosec_core::ItemMeta>, rosec_core::ProviderError> {
        Ok(vec![])
    }
    async fn get_item_attributes(
        &self,
        _: &str,
    ) -> Result<rosec_core::ItemAttributes, rosec_core::ProviderError> {
        Err(rosec_core::ProviderError::NotFound)
    }
    async fn get_secret_attr(
        &self,
        _: &str,
        _: &str,
    ) -> Result<rosec_core::SecretBytes, rosec_core::ProviderError> {
        Err(rosec_core::ProviderError::NotFound)
    }
    async fn delete_item(&self, _: &str) -> Result<(), rosec_core::ProviderError> {
        self.deletes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn missing_and_locked_items_use_secret_service_errors() {
    let server = zbus::Connection::session().await.unwrap();
    let router = Arc::new(Router::new(RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    }));
    let provider = Arc::new(ProbeProvider {
        id: "fixture",
        locked: false.into(),
        deletes: 0.into(),
    });
    let state = register_objects(
        &server,
        vec![provider],
        router,
        Arc::new(SessionManager::new()),
    )
    .await
    .unwrap();
    let items = state.rebuild_cache().await.unwrap();
    let path = &items[0].0;
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
    let item = zbus::Proxy::new(&client, dest, path.as_str(), "org.freedesktop.Secret.Item")
        .await
        .unwrap();
    let error = item
        .call_method("GetSecret", &(&session,))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("org.freedesktop.Secret.Error.NoSuchObject:"),
        "{error}"
    );
    let error = item.call_method("Delete", &()).await.unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("org.freedesktop.DBus.Error.NotSupported:"),
        "{error}"
    );
    state
        .cache
        .items
        .lock()
        .unwrap()
        .get_mut(path)
        .unwrap()
        .locked = true;
    let error = item
        .call_method("GetSecret", &(&session,))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("org.freedesktop.Secret.Error.IsLocked:"),
        "{error}"
    );
}
