use std::collections::HashMap;
use std::sync::Arc;

use rosec_core::Provider;
use rosec_core::config::{Config, PromptConfig};
use rosec_core::router::Router;
use zbus::Connection;

use crate::collection::{CollectionState, SecretCollection};
use crate::daemon::{RosecItems, RosecManagement, RosecSearch, RosecSecrets};
use crate::portal::PortalSecret;
use crate::service::SecretService;
use crate::session::SessionManager;
use crate::state::ServiceState;

/// Spec-defined D-Bus object paths the Secret Service implementation
/// registers under. Plain `&'static str` because the values are baked
/// into the protocol — there is nothing to configure.
pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";
pub const DEFAULT_COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/default";

pub async fn register_objects(
    conn: &Connection,
    providers: Vec<Arc<dyn Provider>>,
    router: Arc<Router>,
    sessions: Arc<SessionManager>,
) -> zbus::Result<Arc<ServiceState>> {
    register_objects_with_config(conn, providers, router, sessions, HashMap::new()).await
}

/// Like `register_objects`, but also accepts per-provider `return_attr` patterns
/// and `PromptConfig` from the config.
/// `return_attr_map` maps provider ID → ordered glob patterns.
/// Providers not present in the map fall back to the service-level default.
pub async fn register_objects_with_config(
    conn: &Connection,
    providers: Vec<Arc<dyn Provider>>,
    router: Arc<Router>,
    sessions: Arc<SessionManager>,
    return_attr_map: HashMap<String, Vec<String>>,
) -> zbus::Result<Arc<ServiceState>> {
    register_objects_with_full_config(
        conn,
        providers,
        router,
        sessions,
        return_attr_map,
        HashMap::new(),
        PromptConfig::default(),
        Config::default(),
    )
    .await
}

/// Full constructor used by `rosecd` — passes `return_attr_map`, `collection_map`,
/// `PromptConfig`, and the full `Config` for live hot-reload support.
#[allow(clippy::too_many_arguments)]
pub async fn register_objects_with_full_config(
    conn: &Connection,
    providers: Vec<Arc<dyn Provider>>,
    router: Arc<Router>,
    sessions: Arc<SessionManager>,
    return_attr_map: HashMap<String, Vec<String>>,
    collection_map: HashMap<String, String>,
    prompt_config: PromptConfig,
    initial_config: Config,
) -> zbus::Result<Arc<ServiceState>> {
    let tokio_handle = tokio::runtime::Handle::current();
    let state = Arc::new(ServiceState::new_with_config(
        providers,
        router,
        sessions,
        conn.clone(),
        tokio_handle,
        return_attr_map,
        collection_map,
        prompt_config,
        initial_config,
    ));

    register_all_objects(conn, &state).await?;

    Ok(state)
}

/// Register all top-level D-Bus objects on `conn` using an **existing**
/// `ServiceState`.  Used during private→session bus migration to re-register
/// the same service handlers on the new connection.
///
/// Does **not** re-register dynamic `SecretItem` objects — call
/// `state.clear_registered_items()` + `state.rebuild_cache()` after swapping
/// the connection for that.
pub async fn re_register_top_level_objects(
    conn: &Connection,
    state: &Arc<ServiceState>,
) -> zbus::Result<()> {
    register_all_objects(conn, state).await
}

/// Shared registration logic — single source of truth for all D-Bus object
/// paths.  Both initial registration and bus-migration re-registration go
/// through this function, so adding a new interface only requires changing
/// one place.
async fn register_all_objects(conn: &Connection, state: &Arc<ServiceState>) -> zbus::Result<()> {
    let server = conn.object_server();

    server
        .at(SERVICE_PATH, SecretService::new(Arc::clone(state)))
        .await?;
    server
        .at("/org/rosec/Daemon", RosecManagement::new(Arc::clone(state)))
        .await?;
    server
        .at("/org/rosec/Search", RosecSearch::new(Arc::clone(state)))
        .await?;
    server
        .at("/org/rosec/Secrets", RosecSecrets::new(Arc::clone(state)))
        .await?;
    server
        .at("/org/rosec/Items", RosecItems::new(Arc::clone(state)))
        .await?;
    server
        .at(
            "/org/freedesktop/portal/desktop",
            PortalSecret::new(Arc::clone(state)),
        )
        .await?;

    let collection_state = CollectionState {
        label: "default".to_string(),
        items: Arc::clone(&state.cache.items),
        providers: state.providers_ordered(),
        service_state: Arc::clone(state),
        sessions: Arc::clone(&state.sessions),
        tokio_handle: tokio::runtime::Handle::current(),
    };
    server
        .at(
            DEFAULT_COLLECTION_PATH,
            SecretCollection::new(collection_state.clone()),
        )
        .await?;

    // Per the Secret Service spec, /org/freedesktop/secrets/aliases/default
    // must resolve to the default collection.  Most clients (including
    // secret-tool from libsecret) access the default collection via this
    // alias path rather than calling ReadAlias first.
    server
        .at(
            "/org/freedesktop/secrets/aliases/default",
            SecretCollection::new(collection_state),
        )
        .await?;

    Ok(())
}
