use std::collections::HashMap;
use std::sync::Arc;

use tracing::debug;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::message::Header;
use zvariant::OwnedObjectPath;

use crate::service::to_object_path;
use crate::state::ServiceState;

/// Log the D-Bus caller at debug level for a search method.
fn log_caller(method: &str, header: &Header<'_>) {
    let sender = header.sender().map(|s| s.as_str()).unwrap_or("<unknown>");
    debug!(method, sender, "D-Bus search call");
}

pub struct RosecSearch {
    pub(super) state: Arc<ServiceState>,
}

impl RosecSearch {
    pub fn new(state: Arc<ServiceState>) -> Self {
        Self { state }
    }
}

#[interface(name = "org.rosec.Search")]
impl RosecSearch {
    /// Search items using glob patterns on their public attributes.
    ///
    /// A rosec-specific alternative to the spec's `SearchItems` that supports
    /// wildcard patterns (`*`, `?`, `[…]`) in attribute values.  All patterns
    /// are ANDed together.  The special key `"name"` matches the item label.
    ///
    /// Returns `(unlocked_paths, locked_paths)` — identical shape to the
    /// Secret Service spec's `SearchItems` so callers can use the paths with
    /// any spec-compliant method afterwards.
    ///
    /// Reads from the persistent metadata cache which survives lock/unlock
    /// cycles: items from locked backends are returned in the `locked` list
    /// rather than causing an error.
    async fn search_items_glob(
        &self,
        attrs: HashMap<String, String>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), FdoError> {
        log_caller("SearchItemsGlob", &header);
        let (unlocked, locked) = self.state.search_metadata_cache_glob(&attrs)?;
        Ok((
            unlocked.into_iter().map(|s| to_object_path(&s)).collect(),
            locked.into_iter().map(|s| to_object_path(&s)).collect(),
        ))
    }
}
