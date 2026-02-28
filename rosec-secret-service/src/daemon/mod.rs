//! rosec D-Bus extension objects.
//!
//! Splits the rosec-specific daemon interface into three focused objects:
//!
//! | Path                | Interface          | Purpose                                    |
//! |---------------------|--------------------|--------------------------------------------|
//! | `/org/rosec/Daemon` | `org.rosec.Daemon` | Management & auth (Status, Sync, AuthBackend, …) |
//! | `/org/rosec/Search` | `org.rosec.Search` | Glob item search (SearchItemsGlob)         |
//! | `/org/rosec/Secrets`| `org.rosec.Secrets`| Attribute-model extensions (GetSecretAttribute*) |

pub mod management;
pub mod search;
pub mod secrets;

// Flat re-exports so callers can use short names.
pub use management::{
    AuthFieldInfo, BackendInfo, BackendListEntry, DaemonStatus, RosecManagement, VaultPasswordEntry,
};
pub use search::RosecSearch;
pub use secrets::RosecSecrets;
