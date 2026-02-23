use std::collections::HashMap;
use std::sync::Arc;

use rosec_core::router::Router;
use rosec_core::VaultBackend;
use zbus::Connection;

use crate::collection::{CollectionState, SecretCollection};
use crate::daemon::{RosecManagement, RosecSearch, RosecSecrets};
use crate::prompt::SecretPrompt;
use crate::service::SecretService;
use crate::session::SessionManager;
use crate::state::ServiceState;

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
    backends: Vec<Arc<dyn VaultBackend>>,
    router: Arc<Router>,
    sessions: Arc<SessionManager>,
) -> zbus::Result<Arc<ServiceState>> {
    register_objects_with_config(conn, backends, router, sessions, HashMap::new()).await
}

/// Like `register_objects`, but also accepts per-backend `return_attr` patterns
/// from the config.  `return_attr_map` maps backend ID → ordered glob patterns.
/// Backends not present in the map fall back to the service-level default.
pub async fn register_objects_with_config(
    conn: &Connection,
    backends: Vec<Arc<dyn VaultBackend>>,
    router: Arc<Router>,
    sessions: Arc<SessionManager>,
    return_attr_map: HashMap<String, Vec<String>>,
) -> zbus::Result<Arc<ServiceState>> {
    let paths = ObjectPaths::new();
    // Keep a reference to all backends for the CollectionState before consuming `backends`
    let backends_for_collection: Vec<Arc<dyn VaultBackend>> =
        backends.iter().map(Arc::clone).collect();
    let tokio_handle = tokio::runtime::Handle::current();
    let state = Arc::new(ServiceState::new_with_return_attr(
        backends,
        router,
        sessions,
        conn.clone(),
        tokio_handle,
        return_attr_map,
    ));
    let shared_items = Arc::clone(&state.items);

    let server = conn.object_server();
    server
        .at(paths.service.clone(), SecretService::new(Arc::clone(&state)))
        .await?;
    server
        .at("/org/rosec/Daemon", RosecManagement::new(Arc::clone(&state)))
        .await?;
    server
        .at("/org/rosec/Search", RosecSearch::new(Arc::clone(&state)))
        .await?;
    server
        .at("/org/rosec/Secrets", RosecSecrets::new(Arc::clone(&state)))
        .await?;

    let collection_state = CollectionState {
        label: "default".to_string(),
        items: shared_items,
        backends: backends_for_collection,
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
