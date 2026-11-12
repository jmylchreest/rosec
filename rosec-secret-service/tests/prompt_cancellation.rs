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

async fn run_deferred_prompt(cancel: bool) {
    let server = zbus::Connection::session().await.unwrap();
    let dest = server.unique_name().unwrap().to_string();
    let a = Arc::new(ProbeProvider {
        id: "a",
        locked: false,
        deletes: 0.into(),
    });
    let b = Arc::new(ProbeProvider {
        id: "b",
        locked: true,
        deletes: 0.into(),
    });
    let router = Arc::new(Router::new(RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    }));
    let state = register_objects(
        &server,
        vec![a.clone(), b.clone()],
        router,
        Arc::new(SessionManager::new()),
    )
    .await
    .unwrap();
    let client = zbus::Connection::session().await.unwrap();
    let mutex = state.prompts.mutex_for("a");
    let guard = mutex.lock().await;
    let prompt_path = state
        .register_prompt(
            &server,
            rosec_secret_service::session::SessionOwner {
                bus: server.server_guid().to_string(),
                name: client.unique_name().unwrap().to_string(),
            },
            "a".into(),
            rosec_secret_service::prompt::PendingOperation::DeleteItem {
                provider_id: "a".into(),
                item_id: "dummy".into(),
                item_path: "/dummy".into(),
            },
        )
        .await
        .unwrap();
    let p = zbus::Proxy::new(
        &client,
        dest.as_str(),
        prompt_path.as_str(),
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    let mut completed = p.receive_signal("Completed").await.unwrap();
    let _: () = p.call("Prompt", &("",)).await.unwrap();
    assert!(p.call_method("Prompt", &("",)).await.is_err());
    if cancel {
        let _: () = p.call("Dismiss", &()).await.unwrap();
    }
    assert_eq!(a.deletes.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(guard);
    let signal = tokio::time::timeout(std::time::Duration::from_secs(2), completed.next())
        .await
        .unwrap()
        .unwrap();
    let (dismissed, _result): (bool, zbus::OwnedVariant) = signal.body().deserialize().unwrap();
    assert_eq!(dismissed, cancel);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), completed.next())
            .await
            .is_err()
    );
    assert_eq!(
        a.deletes.load(std::sync::atomic::Ordering::SeqCst),
        usize::from(!cancel)
    );
    assert!(state.take_pending_operation(&prompt_path).is_none());
}

#[tokio::test]
async fn dismissed_queued_prompt_cannot_execute_deferred_delete() {
    run_deferred_prompt(true).await;
}

#[tokio::test]
async fn successful_prompt_still_executes_once() {
    run_deferred_prompt(false).await;
}
