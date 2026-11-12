use futures_util::StreamExt as _;
use rosec_core::router::{Router, RouterConfig};
use rosec_secret_service::{server::register_objects, session::SessionManager};
use std::sync::Arc;
#[derive(Debug)]
struct ProbeProvider {
    id: &'static str,
    locked: bool,
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
            locked: self.locked,
            last_sync: None,
            cached: false,
            offline_cache: false,
            last_cache_write: None,
        })
    }
    async fn unlock(&self, _: rosec_core::UnlockInput) -> Result<(), rosec_core::ProviderError> {
        Ok(())
    }
    async fn lock(&self) -> Result<(), rosec_core::ProviderError> {
        Ok(())
    }
    async fn list_items(&self) -> Result<Vec<rosec_core::ItemMeta>, rosec_core::ProviderError> {
        Ok(vec![])
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
async fn only_initiating_caller_can_control_prompt_and_receive_completion() {
    let server = zbus::Connection::session().await.unwrap();
    let owner = zbus::Connection::session().await.unwrap();
    let foreign = zbus::Connection::session().await.unwrap();
    let dest = server.unique_name().unwrap().as_str();
    let router = Arc::new(Router::new(RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    }));
    let provider = Arc::new(ProbeProvider {
        id: "a",
        locked: true,
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
    let service = zbus::Proxy::new(
        &owner,
        dest,
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let mutex = state.prompts.mutex_for("a");
    let guard = mutex.lock().await;
    let (_, path): (Vec<zbus::OwnedObjectPath>, zbus::OwnedObjectPath) = service
        .call(
            "Unlock",
            &(vec![
                zbus::OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default")
                    .unwrap(),
            ],),
        )
        .await
        .unwrap();
    let theirs = zbus::Proxy::new(
        &foreign,
        dest,
        path.as_str(),
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    let ours = zbus::Proxy::new(&owner, dest, path.as_str(), "org.freedesktop.Secret.Prompt")
        .await
        .unwrap();
    let mut ours_completed = ours.receive_signal("Completed").await.unwrap();
    let mut theirs_completed = theirs.receive_signal("Completed").await.unwrap();
    assert!(theirs.call_method("Prompt", &("",)).await.is_err());
    assert!(theirs.call_method("Dismiss", &()).await.is_err());
    let management = zbus::Proxy::new(&foreign, dest, "/org/rosec/Daemon", "org.rosec.Daemon")
        .await
        .unwrap();
    let error = management
        .call_method("CancelPrompt", &(&path,))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("org.freedesktop.DBus.Error.AccessDenied:"),
        "{error}"
    );
    ours.call_method("Prompt", &("",)).await.unwrap();
    ours.call_method("Dismiss", &()).await.unwrap();
    drop(guard);
    let signal = tokio::time::timeout(std::time::Duration::from_secs(2), ours_completed.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        signal.header().destination().unwrap().as_str(),
        owner.unique_name().unwrap().as_str()
    );
    let (dismissed, _): (bool, zbus::OwnedVariant) = signal.body().deserialize().unwrap();
    assert!(dismissed);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            theirs_completed.next()
        )
        .await
        .is_err()
    );
    assert!(!state.prompts.contains_path(path.as_str()));
}

#[tokio::test]
async fn disconnect_cancels_a_queued_prompt() {
    let server = zbus::Connection::session().await.unwrap();
    let owner = zbus::Connection::session().await.unwrap();
    let router = Arc::new(Router::new(RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    }));
    let state = register_objects(
        &server,
        vec![Arc::new(ProbeProvider {
            id: "a",
            locked: true,
            deletes: 0.into(),
        })],
        router,
        Arc::new(SessionManager::new()),
    )
    .await
    .unwrap();
    let service = zbus::Proxy::new(
        &owner,
        server.unique_name().unwrap().as_str(),
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let mutex = state.prompts.mutex_for("a");
    let guard = mutex.lock().await;
    let (_, path): (Vec<zbus::OwnedObjectPath>, zbus::OwnedObjectPath) = service
        .call(
            "Unlock",
            &(vec![
                zbus::OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default")
                    .unwrap(),
            ],),
        )
        .await
        .unwrap();
    let prompt = zbus::Proxy::new(
        &owner,
        server.unique_name().unwrap().as_str(),
        path.as_str(),
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    prompt.call_method("Prompt", &("",)).await.unwrap();
    owner.clone().close().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while state.prompts.contains_path(path.as_str()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(guard);
    assert!(state.take_pending_operation(path.as_str()).is_none());
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
async fn migration_keeps_prompt_owner_and_completion_on_original_bus() {
    let a = PrivateBus::new();
    let b = PrivateBus::new();
    let server_a = a.connect().await;
    let server_b = b.connect().await;
    let owner_a = a.connect().await;
    let owner_b = b.connect().await;
    assert_eq!(owner_a.unique_name(), owner_b.unique_name());
    let router = Arc::new(Router::new(RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    }));
    let state = register_objects(
        &server_a,
        vec![Arc::new(ProbeProvider {
            id: "a",
            locked: true,
            deletes: 0.into(),
        })],
        router,
        Arc::new(SessionManager::new()),
    )
    .await
    .unwrap();
    rosec_secret_service::server::re_register_top_level_objects(&server_b, &state)
        .await
        .unwrap();
    state.swap_conn(server_b.clone());
    let service = zbus::Proxy::new(
        &owner_a,
        server_a.unique_name().unwrap().as_str(),
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let (_, path): (Vec<zbus::OwnedObjectPath>, zbus::OwnedObjectPath) = service
        .call(
            "Unlock",
            &(vec![
                zbus::OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default")
                    .unwrap(),
            ],),
        )
        .await
        .unwrap();
    assert!(
        server_a
            .object_server()
            .interface::<_, rosec_secret_service::prompt::SecretPrompt>(path.as_str())
            .await
            .is_ok()
    );
    assert!(
        server_b
            .object_server()
            .interface::<_, rosec_secret_service::prompt::SecretPrompt>(path.as_str())
            .await
            .is_err()
    );
    // Even if an object is exposed on the second bus, matching textual unique
    // names must not grant control of the original bus's prompt.
    server_b
        .object_server()
        .at(
            path.as_str(),
            rosec_secret_service::prompt::SecretPrompt::new(
                path.to_string(),
                "a".into(),
                state.clone(),
            ),
        )
        .await
        .unwrap();
    let foreign = zbus::Proxy::new(
        &owner_b,
        server_b.unique_name().unwrap().as_str(),
        path.as_str(),
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    assert!(foreign.call_method("Prompt", &("",)).await.is_err());
    assert!(foreign.call_method("Dismiss", &()).await.is_err());
    let ours = zbus::Proxy::new(
        &owner_a,
        server_a.unique_name().unwrap().as_str(),
        path.as_str(),
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    let mut completed = ours.receive_signal("Completed").await.unwrap();
    ours.call_method("Dismiss", &()).await.unwrap();
    let signal = tokio::time::timeout(std::time::Duration::from_secs(2), completed.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        signal.header().destination().unwrap().as_str(),
        owner_a.unique_name().unwrap().as_str()
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while server_a
            .object_server()
            .interface::<_, rosec_secret_service::prompt::SecretPrompt>(path.as_str())
            .await
            .is_ok()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
