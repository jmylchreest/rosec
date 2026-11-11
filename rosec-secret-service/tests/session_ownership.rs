use rosec_core::router::{Router, RouterConfig};
use rosec_secret_service::{server::register_objects, session::SessionManager};
use std::{collections::HashMap, sync::Arc, time::Duration};
use zbus::{OwnedObjectPath, OwnedVariant, Variant};

#[tokio::test]
async fn sessions_belong_to_the_opening_client_and_end_on_disconnect() {
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
    let owner = zbus::Connection::session().await.unwrap();
    let foreign = zbus::Connection::session().await.unwrap();
    let service = zbus::Proxy::new(
        &owner,
        destination.as_str(),
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let (_, path): (OwnedVariant, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Variant::from("")))
        .await
        .unwrap();
    let foreign_service = zbus::Proxy::new(
        &foreign,
        destination.as_str(),
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let error = foreign_service
        .call_method("GetSecrets", &(Vec::<OwnedObjectPath>::new(), &path))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("org.freedesktop.Secret.Error.NoSession:"),
        "{error}"
    );
    let foreign_session = zbus::Proxy::new(
        &foreign,
        destination.as_str(),
        path.as_str(),
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    assert!(foreign_session.call_method("Close", &()).await.is_err());
    assert!(
        foreign_service
            .call_method("CloseSession", &(&path,))
            .await
            .is_err()
    );
    let collection = zbus::Proxy::new(
        &foreign,
        destination.as_str(),
        "/org/freedesktop/secrets/collection/default",
        "org.freedesktop.Secret.Collection",
    )
    .await
    .unwrap();
    let secret = (
        path.clone(),
        Vec::<u8>::new(),
        b"secret".to_vec(),
        "text/plain",
    );
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
            .starts_with("org.freedesktop.Secret.Error.NoSession:"),
        "{error}"
    );
    service
        .call_method("GetSecrets", &(Vec::<OwnedObjectPath>::new(), &path))
        .await
        .unwrap();
    let own_session = zbus::Proxy::new(
        &owner,
        destination.as_str(),
        path.as_str(),
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    own_session.call_method("Close", &()).await.unwrap();
    assert!(!sessions.is_valid(path.as_str()).unwrap());
    assert!(
        server
            .object_server()
            .interface::<_, rosec_secret_service::session_iface::SecretSession>(path.as_str())
            .await
            .is_err()
    );
    let (_, path): (OwnedVariant, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Variant::from("")))
        .await
        .unwrap();
    owner.clone().close().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while sessions.is_valid(path.as_str()).unwrap() {
            tokio::task::yield_now().await;
        }
        loop {
            if server
                .object_server()
                .interface::<_, rosec_secret_service::session_iface::SecretSession>(path.as_str())
                .await
                .is_err()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

struct PrivateBus(std::process::Child, String);
impl PrivateBus {
    fn new() -> Self {
        use std::io::BufRead;
        let mut child = std::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut address = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        Self(child, address.trim().to_string())
    }
    async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.1.as_str())
            .build()
            .await
            .unwrap()
    }
}
impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn migration_does_not_transfer_sessions_between_equal_unique_names() {
    use rosec_secret_service::{
        server::re_register_top_level_objects, session_iface::SecretSession,
    };
    let first = PrivateBus::new();
    let second = PrivateBus::new();
    let server_a = first.connect().await;
    let server_b = second.connect().await;
    let client_a = first.connect().await;
    let client_b = second.connect().await;
    assert_eq!(client_a.unique_name(), client_b.unique_name());
    assert_ne!(server_a.server_guid(), server_b.server_guid());
    let sessions = Arc::new(SessionManager::new());
    let router = Arc::new(Router::new(RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    }));
    let state = register_objects(&server_a, vec![], router, Arc::clone(&sessions))
        .await
        .unwrap();
    re_register_top_level_objects(&server_b, &state)
        .await
        .unwrap();
    state.swap_conn(server_b.clone());
    let service_a = zbus::Proxy::new(
        &client_a,
        server_a.unique_name().unwrap().as_str(),
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let service_b = zbus::Proxy::new(
        &client_b,
        server_b.unique_name().unwrap().as_str(),
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    // Even after state.conn migrates, a request on the old endpoint registers
    // its session object on that endpoint, not on the new bus.
    let (_, a): (OwnedVariant, OwnedObjectPath) = service_a
        .call("OpenSession", &("plain", Variant::from("")))
        .await
        .unwrap();
    assert!(
        server_a
            .object_server()
            .interface::<_, SecretSession>(a.as_str())
            .await
            .is_ok()
    );
    assert!(
        server_b
            .object_server()
            .interface::<_, SecretSession>(a.as_str())
            .await
            .is_err()
    );
    assert!(
        service_b
            .call_method("GetSecrets", &(Vec::<OwnedObjectPath>::new(), &a))
            .await
            .is_err()
    );
    assert!(service_b.call_method("CloseSession", &(&a,)).await.is_err());
    service_a
        .call_method("GetSecrets", &(Vec::<OwnedObjectPath>::new(), &a))
        .await
        .unwrap();
    let (_, b): (OwnedVariant, OwnedObjectPath) = service_b
        .call("OpenSession", &("plain", Variant::from("")))
        .await
        .unwrap();
    server_a.clone().close().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while sessions.is_valid(a.as_str()).unwrap() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(sessions.is_valid(b.as_str()).unwrap());
    service_b
        .call_method("GetSecrets", &(Vec::<OwnedObjectPath>::new(), &b))
        .await
        .unwrap();
}

#[tokio::test]
async fn disconnect_racing_open_does_not_leave_a_session() {
    let server = zbus::Connection::session().await.unwrap();
    let sessions = Arc::new(SessionManager::new());
    let router = Arc::new(Router::new(RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    }));
    let _state = register_objects(&server, vec![], router, Arc::clone(&sessions))
        .await
        .unwrap();
    for _ in 0..20 {
        let client = zbus::Connection::session().await.unwrap();
        let request = zbus::Message::method_call("/org/freedesktop/secrets", "OpenSession")
            .destination(server.unique_name().unwrap())
            .interface("org.freedesktop.Secret.Service")
            .build(&("plain", Variant::from("")))
            .unwrap();
        client.send(&request).await.unwrap();
        client.close().await.unwrap();
    }
    // Allow already-dispatched handlers to reach their liveness check; the
    // watcher must also release sessions created before the disconnect.
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while sessions.count().unwrap() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
