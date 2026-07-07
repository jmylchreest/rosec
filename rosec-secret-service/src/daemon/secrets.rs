use std::sync::Arc;

use rosec_core::{Capability, ProviderError};
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::message::Header;

use super::log_dbus_caller;
use crate::state::{ServiceState, map_provider_error};

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
        item_path: zvariant::ObjectPath<'_>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<String>, FdoError> {
        log_dbus_caller("secrets", "GetSecretAttributeNames", &header);
        self.state.touch_activity();

        let (provider, item_id) = self.state.provider_and_id_for_path(item_path.as_str())?;

        let item_attrs = self
            .state
            .run_on_tokio(async move { provider.get_item_attributes(&item_id).await })
            .await?
            .map_err(map_provider_error)?;

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
        item_path: zvariant::ObjectPath<'_>,
        attr_name: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<u8>, FdoError> {
        log_dbus_caller("secrets", "GetSecretAttribute", &header);
        self.state.touch_activity();

        let (provider, item_id) = self.state.provider_and_id_for_path(item_path.as_str())?;
        let attr_name = attr_name.to_string();
        let attr_name_for_err = attr_name.clone();

        let secret = self
            .state
            .run_on_tokio(async move { provider.get_secret_attr(&item_id, &attr_name).await })
            .await?
            .map_err(|e| match e {
                ProviderError::NotFound => {
                    FdoError::Failed(format!("attribute '{attr_name_for_err}' not found"))
                }
                other => map_provider_error(other),
            })?;

        Ok(secret.as_slice().to_vec())
    }

    /// Generate a TOTP code for an item that has a TOTP seed.
    ///
    /// Returns `(code, seconds_remaining)` where `code` is the current
    /// time-based one-time password and `seconds_remaining` is the number
    /// of seconds until it expires.
    ///
    /// Errors if the item has no TOTP seed, the provider is locked, or the
    /// provider does not declare the `Totp` capability.
    async fn get_totp_code(
        &self,
        item_path: zvariant::ObjectPath<'_>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(String, u32), FdoError> {
        log_dbus_caller("secrets", "GetTotpCode", &header);
        self.state.touch_activity();

        let (provider, item_id) = self.state.provider_and_id_for_path(item_path.as_str())?;

        rosec_core::require(provider.as_ref(), Capability::Totp).map_err(|_| {
            FdoError::NotSupported("provider does not support TOTP code generation".to_string())
        })?;

        let attr_name = "totp".to_string();
        let secret = self
            .state
            .run_on_tokio(async move { provider.get_secret_attr(&item_id, &attr_name).await })
            .await?
            .map_err(|e| match e {
                ProviderError::NotFound => FdoError::Failed("item has no TOTP seed".to_string()),
                other => map_provider_error(other),
            })?;

        let params = rosec_core::totp::parse_totp_input(secret.as_slice())
            .map_err(|e| FdoError::Failed(format!("failed to parse TOTP seed: {e}")))?;

        let now = std::time::SystemTime::now();
        let code = rosec_core::totp::generate_code(&params, now)
            .map_err(|e| FdoError::Failed(format!("TOTP generation failed: {e}")))?;
        let remaining = rosec_core::totp::time_remaining_at(&params, now) as u32;

        Ok((code.to_string(), remaining))
    }
}
