use std::sync::Arc;
use std::time::SystemTime;

use zbus::fdo::Error as FdoError;
use zbus::interface;

use crate::service::ServiceState;

pub struct RosecDaemon {
    state: Arc<ServiceState>,
}

impl RosecDaemon {
    pub fn new(state: Arc<ServiceState>) -> Self {
        Self { state }
    }
}

#[interface(name = "org.rosec.Daemon")]
impl RosecDaemon {
    fn status(&self) -> Result<DaemonStatus, FdoError> {
        let cache_size = self
            .state
            .items
            .lock()
            .map(|items| items.len())
            .unwrap_or(0);

        let last_refresh = self
            .state
            .last_refresh
            .lock()
            .ok()
            .and_then(|guard| *guard)
            .map(|time| {
                time.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            })
            .unwrap_or(0);

        let sessions_active = self
            .state
            .sessions
            .count()
            .unwrap_or(0);

        Ok(DaemonStatus {
            backend_id: self.state.backend.id().to_string(),
            backend_name: self.state.backend.name().to_string(),
            cache_size: cache_size as u32,
            last_refresh_epoch: last_refresh,
            sessions_active: sessions_active as u32,
        })
    }

    async fn refresh(&self) -> Result<u32, FdoError> {
        let entries = self.state.refresh_items().await?;
        Ok(entries.len() as u32)
    }

    fn backend_info(&self) -> Result<BackendInfo, FdoError> {
        Ok(BackendInfo {
            id: self.state.backend.id().to_string(),
            name: self.state.backend.name().to_string(),
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct DaemonStatus {
    pub backend_id: String,
    pub backend_name: String,
    pub cache_size: u32,
    pub last_refresh_epoch: u64,
    pub sessions_active: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct BackendInfo {
    pub id: String,
    pub name: String,
}
