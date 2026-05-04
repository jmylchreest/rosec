//! SSH agent session and listener.

use std::future::Future;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use anyhow::Context as _;
use signature::Signer as _;
use ssh_agent_lib::agent::{Session, listen};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, Request, Response, SignRequest};
use ssh_key::{HashAlg, Signature};
use tracing::{debug, info, warn};

use crate::keystore::KeyStore;

/// Callback invoked when an SSH key with `require_confirm` is used in a sign
/// request.  Receives the key fingerprint and the vault item name.
///
/// Returns `true` to allow the signing operation, `false` to deny it.
pub type ConfirmCallback =
    Arc<dyn Fn(String, String) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;

/// Top-level SSH agent.  Cloned per incoming connection by `ssh_agent_lib`.
#[derive(Clone)]
pub struct SshAgent {
    store: Arc<RwLock<KeyStore>>,
    socket_path: PathBuf,
    /// Optional callback for interactive sign confirmation.
    ///
    /// When set and a key has `require_confirm = true`, the agent calls this
    /// before signing.  When `None`, confirmable keys are allowed with a
    /// warning (preserving headless / fallback behaviour).
    confirm: Option<ConfirmCallback>,
}

impl std::fmt::Debug for SshAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshAgent")
            .field("socket_path", &self.socket_path)
            .field("confirm", &self.confirm.as_ref().map(|_| "…"))
            .finish_non_exhaustive()
    }
}

impl SshAgent {
    pub fn new(store: Arc<RwLock<KeyStore>>, socket_path: PathBuf) -> Self {
        Self {
            store,
            socket_path,
            confirm: None,
        }
    }

    /// Set the interactive confirmation callback for sign requests.
    pub fn with_confirm(mut self, cb: ConfirmCallback) -> Self {
        self.confirm = Some(cb);
        self
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

        // Read the key entry under a short-lived lock.  We extract what we
        // need (confirm flag, item name) then drop the guard so the async
        // confirmation callback can run without holding the lock.
        let (require_confirm, item_name) = {
            let store = self
                .store
                .read()
                .map_err(|_| other_err("key store lock poisoned"))?;

            let entry = store
                .get_by_fingerprint(&fingerprint)
                .ok_or_else(|| other_err("key not found"))?;

            (entry.require_confirm, entry.item_name.clone())
        };

        // Interactive confirmation for keys with ssh_confirm / ssh-confirm.
        if require_confirm {
            if let Some(ref cb) = self.confirm {
                info!(
                    fingerprint = %fingerprint,
                    item = %item_name,
                    "sign request requires confirmation"
                );
                let allowed = cb(fingerprint.clone(), item_name.clone()).await;
                if !allowed {
                    warn!(
                        fingerprint = %fingerprint,
                        item = %item_name,
                        "sign request denied by user"
                    );
                    return Err(other_err("sign request denied by user"));
                }
                info!(
                    fingerprint = %fingerprint,
                    item = %item_name,
                    "sign request confirmed by user"
                );
            } else {
                warn!(
                    fingerprint = %fingerprint,
                    item = %item_name,
                    "sign request for key with ssh_confirm=true but no confirmation callback set, denying"
                );
                return Err(other_err(
                    "sign request denied: no confirmation callback configured",
                ));
            }
        }

        debug!(
            fingerprint = %fingerprint,
            item = %item_name,
            data_len = request.data.len(),
            "sign"
        );

        // Re-acquire the lock for signing (the key must still be present).
        let store = self
            .store
            .read()
            .map_err(|_| other_err("key store lock poisoned"))?;

        let entry = store
            .get_by_fingerprint(&fingerprint)
            .ok_or_else(|| other_err("key removed during confirmation"))?;

        let signature = entry
            .private_key
            .try_sign(&request.data)
            .map_err(|e| other_err(format!("signing failed: {e}")))?;

        Ok(signature)
    }

    /// Override the default `handle()` to intercept extension requests.
    ///
    /// The default `Session::extension()` returns `Err(UnsupportedCommand)`,
    /// which `handle_socket()` in `ssh_agent_lib` logs at ERROR level.
    /// Extension probes (command 27 = `SSH_AGENTC_EXTENSION`) are normal —
    /// SSH clients and forwarding tools send them to discover capabilities.
    /// We return `SSH_AGENT_FAILURE` directly, bypassing the error log path.
    async fn handle(&mut self, message: Request) -> Result<Response, AgentError> {
        match message {
            Request::Extension(ext) => {
                debug!(
                    extension = %ext.name,
                    "extension request (unsupported, returning failure)"
                );
                Ok(Response::Failure)
            }
            Request::RequestIdentities => {
                Ok(Response::IdentitiesAnswer(self.request_identities().await?))
            }
            Request::SignRequest(request) => Ok(Response::SignResponse(self.sign(request).await?)),
            _ => Err(AgentError::from(
                ssh_agent_lib::proto::ProtoError::UnsupportedCommand { command: 0 },
            )),
        }
    }
}
