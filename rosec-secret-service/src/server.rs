use std::sync::Arc;

use rosec_core::router::Router;
use rosec_core::VaultBackend;
use zbus::Connection;

use crate::collection::{CollectionState, SecretCollection};
use crate::daemon::RosecDaemon;
use crate::prompt::SecretPrompt;
use crate::service::{SecretService, ServiceState};
use crate::session::SessionManager;

#[derive(Debug)]
pub struct ObjectPaths {
    pub service: String,
    pub collection_default: String,
}

impl ObjectPaths {
    pub fn new() -> Self {
        Self {
            service: "/org/freedesktop/secrets".to_string(),
            collection_default: "/org/freedesktop/secrets/collection/default".to_string(),
        }
    }
}

impl Default for ObjectPaths {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn register_objects(
    conn: &Connection,
    backend: Arc<dyn VaultBackend>,
    router: Arc<Router>,
    sessions: Arc<SessionManager>,
) -> zbus::Result<Arc<ServiceState>> {
    let paths = ObjectPaths::new();
    let state = Arc::new(ServiceState::new(backend.clone(), router, sessions, conn.clone()));
    let shared_items = Arc::clone(&state.items);

    let server = conn.object_server();
    server
        .at(paths.service.clone(), SecretService::new(Arc::clone(&state)))
        .await?;
    server
        .at("/org/rosec/Daemon", RosecDaemon::new(Arc::clone(&state)))
        .await?;

    let collection_state = CollectionState {
        label: "default".to_string(),
        items: shared_items,
        backend,
    };
    server
        .at(paths.collection_default.clone(), SecretCollection::new(collection_state))
        .await?;

    // Placeholder prompt path - created on demand later
    server
        .at(
            "/org/freedesktop/secrets/prompt/placeholder",
            SecretPrompt::new("/org/freedesktop/secrets/prompt/placeholder".to_string()),
        )
        .await?;

    Ok(state)
}
