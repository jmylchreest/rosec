use std::sync::Arc;

use rosec_core::BackendError;
use tracing::debug;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::message::Header;

use crate::state::{ServiceState, map_backend_error};

/// Log the D-Bus caller at debug level for a secrets-extension method.
fn log_caller(method: &str, header: &Header<'_>) {
    let sender = header
        .sender()
        .map(|s| s.as_str())
        .unwrap_or("<unknown>");
    debug!(method, sender, "D-Bus secrets-extension call");
}

pub struct RosecSecrets {
    pub(super) state: Arc<ServiceState>,
}

impl RosecSecrets {
    pub fn new(state: Arc<ServiceState>) -> Self {
        Self { state }
    }
}

#[interface(name = "org.rosec.Secrets")]
impl RosecSecrets {
    /// Return the names of all sensitive attributes available for an item.
    ///
    /// The names returned here can be passed to `GetSecretAttribute` to
    /// retrieve the raw value of any individual sensitive field (e.g.
    /// `"password"`, `"totp"`, `"notes"`, `"custom.my_field"`).
    ///
    /// This is a rosec-specific extension — it is not part of the standard
    /// `org.freedesktop.Secret.Service` interface.
    async fn get_secret_attribute_names(
        &self,
        item_path: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<String>, FdoError> {
        log_caller("GetSecretAttributeNames", &header);
        self.state.touch_activity();

        let (backend, item_id) = self.state.backend_and_id_for_path(item_path)?;

        let item_attrs = self
            .state
            .run_on_tokio(async move { backend.get_item_attributes(&item_id).await })
            .await?
            .map_err(map_backend_error)?;

        Ok(item_attrs.secret_names)
    }

    /// Retrieve a single sensitive attribute value by name for an item.
    ///
    /// `item_path` is the D-Bus object path of the item (as returned by
    /// `SearchItems`).  `attr_name` is one of the names from
    /// `GetSecretAttributeNames` (e.g. `"password"`, `"custom.token"`).
    ///
    /// Returns the raw attribute bytes, or a D-Bus error if not found.
    ///
    /// This is a rosec-specific extension — it is not part of the standard
    /// `org.freedesktop.Secret.Service` interface.
    async fn get_secret_attribute(
        &self,
        item_path: &str,
        attr_name: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<u8>, FdoError> {
        log_caller("GetSecretAttribute", &header);
        self.state.touch_activity();

        let (backend, item_id) = self.state.backend_and_id_for_path(item_path)?;
        let attr_name = attr_name.to_string();
        let attr_name_for_err = attr_name.clone();

        let secret = self
            .state
            .run_on_tokio(async move {
                backend.get_secret_attr(&item_id, &attr_name).await
            })
            .await?
            .map_err(|e| match e {
                BackendError::NotFound => FdoError::Failed(format!(
                    "attribute '{attr_name_for_err}' not found"
                )),
                other => map_backend_error(other),
            })?;

        Ok(secret.as_slice().to_vec())
    }
}
