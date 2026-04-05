//! WASM plugin host for rosec providers.
//!
//! This crate provides `WasmProvider`, which wraps an Extism WASM plugin
//! and exposes it as a native `rosec_core::Provider`.  Each Provider method
//! calls the corresponding guest function with JSON-serialized input and
//! deserializes the JSON response.
//!
//! # Guest function contract
//!
//! | Guest function           | Input type               | Output type                  |
//! |--------------------------|--------------------------|------------------------------|
//! | `plugin_manifest`        | *(empty)*                | `PluginManifest`             |
//! | `init`                   | `InitRequest`            | `InitResponse`               |
//! | `status`                 | *(empty)*                | `StatusResponse`             |
//! | `unlock`                 | `UnlockRequest`          | `SimpleResponse`             |
//! | `lock`                   | *(empty)*                | `SimpleResponse`             |
//! | `sync`                   | *(empty)*                | `SimpleResponse`             |
//! | `list_items`             | *(empty)*                | `ItemListResponse`           |
//! | `search`                 | `SearchRequest`          | `ItemListResponse`           |
//! | `get_item_attributes`    | `ItemIdRequest`          | `ItemAttributesResponse`     |
//! | `get_secret_attr`        | `SecretAttrRequest`      | `SecretAttrResponse`         |
//! | `list_ssh_keys`          | *(empty)*                | `SshKeyListResponse`         |
//! | `get_ssh_private_key`    | `SshPrivateKeyRequest`   | `SshPrivateKeyResponse`      |
//! | `registration_info`      | *(empty)*                | `RegistrationInfoResponse`   |
//! | `auth_fields`            | *(empty)*                | `AuthFieldsResponse`         |
//! | `attribute_descriptors`  | *(empty)*                | `AttributeDescriptorsResponse` |
//! | `readiness_probes`       | *(empty)*                | `ReadinessProbesResponse`    |
//! | `capabilities`           | *(empty)*                | `CapabilitiesResponse`       |
//! | `export_cache`           | *(empty)*                | `ExportCacheResponse`        |
//! | `restore_cache`          | `RestoreCacheRequest`    | `SimpleResponse`             |
//! | `get_notification_config`| *(empty)*                | `NotificationConfigResponse` |
//! | `parse_notification`     | `NotificationFrame`      | `NotificationAction`         |

pub mod cache;
pub mod discovery;
pub(crate) mod host_http;
pub mod keys;
pub mod notifications;
pub mod protocol;
mod provider;
mod wasm_cred;

pub use discovery::PluginRegistry;
pub use provider::{WasmProvider, WasmProviderConfig};

/// Crate-wide test mutex for serializing tests that manipulate environment
/// variables (e.g. `XDG_DATA_HOME`).  All test modules in this crate should
/// use this instead of a module-local mutex to prevent cross-module races.
#[cfg(test)]
pub(crate) static TEST_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
