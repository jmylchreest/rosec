//! SSH agent session and listener.

use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::Context as _;
use signature::Signer as _;
use ssh_agent_lib::agent::{Session, listen};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::{HashAlg, Signature};
use tracing::{debug, warn};

use crate::keystore::KeyStore;

/// Top-level SSH agent.  Cloned per incoming connection by `ssh_agent_lib`.
#[derive(Clone, Debug)]
pub struct SshAgent {
    store: Arc<RwLock<KeyStore>>,
    socket_path: PathBuf,
}

impl SshAgent {
    pub fn new(store: Arc<RwLock<KeyStore>>, socket_path: PathBuf) -> Self {
        Self { store, socket_path }
    }

    /// Bind the Unix socket and start accepting connections.
    pub async fn listen(self) -> anyhow::Result<()> {
        let listener = tokio::net::UnixListener::bind(&self.socket_path)
            .with_context(|| format!("bind SSH agent socket {:?}", self.socket_path))?;

        std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {:?}", self.socket_path))?;

        listen(listener, self).await.context("SSH agent listener")
    }
}

fn other_err(msg: impl Into<String>) -> AgentError {
    AgentError::other(io::Error::other(msg.into()))
}

#[ssh_agent_lib::async_trait]
impl Session for SshAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let store = self
            .store
            .read()
            .map_err(|_| other_err("key store lock poisoned"))?;

        let identities: Vec<Identity> = store
            .unique_keys()
            .map(|entry| Identity {
                pubkey: entry.private_key.public_key().clone().into(),
                comment: entry.item_name.clone(),
            })
            .collect();

        debug!(count = identities.len(), "request_identities");
        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let fingerprint = request.pubkey.fingerprint(HashAlg::Sha256).to_string();

        let store = self
            .store
            .read()
            .map_err(|_| other_err("key store lock poisoned"))?;

        let entry = store
            .get_by_fingerprint(&fingerprint)
            .ok_or_else(|| other_err("key not found"))?;

        if entry.require_confirm {
            warn!(
                fingerprint = %fingerprint,
                item = %entry.item_name,
                "sign request for key with ssh_confirm=true (confirmation not yet implemented, allowing)"
            );
        }

        debug!(
            fingerprint = %fingerprint,
            item = %entry.item_name,
            data_len = request.data.len(),
            "sign"
        );

        let signature = entry
            .private_key
            .try_sign(&request.data)
            .map_err(|e| other_err(format!("signing failed: {e}")))?;

        Ok(signature)
    }
}
