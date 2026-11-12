use rosec_core::{
    Attributes, ItemAttributes, ItemMeta, Provider, ProviderError, ProviderStatus, SecretBytes,
    UnlockInput,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

pub struct MutableProvider {
    pub id: String,
    pub items: Mutex<Vec<ItemMeta>>,
    pub fail: AtomicBool,
    pub locked: AtomicBool,
    pub secret: Mutex<Vec<u8>>,
    pub pause: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
}
impl MutableProvider {
    pub fn new(id: &str) -> Arc<Self> {
        Arc::new(Self {
            id: id.into(),
            items: Mutex::new(vec![]),
            fail: AtomicBool::new(false),
            locked: AtomicBool::new(false),
            secret: Mutex::new(b"fixture-secret".to_vec()),
            pause: Mutex::new(None),
        })
    }
    pub fn put(&self, id: &str, label: &str) {
        *self.items.lock().unwrap() = vec![ItemMeta {
            id: id.into(),
            provider_id: self.id.clone(),
            label: label.into(),
            attributes: Attributes::new(),
            created: None,
            modified: None,
            locked: false,
            attribute_hashes: None,
        }];
    }
}
#[async_trait::async_trait]
impl Provider for MutableProvider {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.id
    }
    fn kind(&self) -> &str {
        "fixture"
    }
    fn capabilities(&self) -> &'static [rosec_core::Capability] {
        &[rosec_core::Capability::Write]
    }
    async fn create_item(
        &self,
        item: rosec_core::NewItem,
        _: bool,
    ) -> Result<String, ProviderError> {
        let id = "written".to_owned();
        *self.items.lock().unwrap() =
            vec![ItemMeta::from_new_item(id.clone(), self.id.clone(), &item)];
        Ok(id)
    }
    async fn delete_item(&self, id: &str) -> Result<(), ProviderError> {
        self.items.lock().unwrap().retain(|item| item.id != id);
        Ok(())
    }
    async fn status(&self) -> Result<ProviderStatus, ProviderError> {
        Ok(ProviderStatus {
            locked: self.locked.load(Ordering::SeqCst),
            last_sync: None,
            cached: false,
            offline_cache: false,
            last_cache_write: None,
        })
    }
    async fn unlock(&self, _: UnlockInput) -> Result<(), ProviderError> {
        self.locked.store(false, Ordering::SeqCst);
        Ok(())
    }
    async fn lock(&self) -> Result<(), ProviderError> {
        self.locked.store(true, Ordering::SeqCst);
        Ok(())
    }
    async fn list_items(&self) -> Result<Vec<ItemMeta>, ProviderError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ProviderError::Unavailable("fixture".into()));
        }
        if self.locked.load(Ordering::SeqCst) {
            return Err(ProviderError::Locked);
        }
        let snapshot = self.items.lock().unwrap().clone();
        let pause = self.pause.lock().unwrap().take();
        if let Some((started, resume)) = pause {
            let _ = started.send(());
            let _ = resume.await;
        }
        Ok(snapshot)
    }
    async fn search(&self, _: &Attributes) -> Result<Vec<ItemMeta>, ProviderError> {
        self.list_items().await
    }
    async fn get_item_attributes(&self, _: &str) -> Result<ItemAttributes, ProviderError> {
        Ok(ItemAttributes {
            public: Attributes::new(),
            secret_names: vec!["secret".into()],
        })
    }
    async fn get_secret_attr(&self, id: &str, _: &str) -> Result<SecretBytes, ProviderError> {
        if self.locked.load(Ordering::SeqCst) {
            return Err(ProviderError::Locked);
        }
        if !self.items.lock().unwrap().iter().any(|item| item.id == id) {
            return Err(ProviderError::NotFound);
        }
        Ok(SecretBytes::new(self.secret.lock().unwrap().clone()))
    }
}
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
