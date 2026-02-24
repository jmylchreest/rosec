use std::collections::HashMap;
use std::sync::Arc;

use rosec_core::{BackendError, SecretBytes};
use tracing::debug;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::message::Header;
use zvariant::OwnedObjectPath;

use crate::crypto::aes128_cbc_encrypt;
use crate::prompt::SecretPrompt;
use crate::session_iface::SecretSession;
use crate::state::{ServiceState, map_backend_error, map_zbus_error};

/// Log the D-Bus caller at debug level for a given method name.
fn log_caller(method: &str, header: &Header<'_>) {
    let sender = header.sender().map(|s| s.as_str()).unwrap_or("<unknown>");
    debug!(method, sender, "D-Bus call");
}

pub struct SecretService {
    state: Arc<ServiceState>,
}

impl SecretService {
    pub fn new(state: Arc<ServiceState>) -> Self {
        Self { state }
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl SecretService {
    #[zbus(property)]
    fn collections(&self) -> Vec<String> {
        vec!["/org/freedesktop/secrets/collection/default".to_string()]
    }

    async fn open_session(
        &self,
        algorithm: &str,
        input: zvariant::Value<'_>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(zvariant::Value<'static>, String), FdoError> {
        log_caller("OpenSession", &header);
        let (output, path) = self
            .state
            .sessions
            .open_session(algorithm, &input)
            .map_err(map_backend_error)?;

        // Register the org.freedesktop.Secret.Session object at the session path
        let session_obj = SecretSession::new(path.clone(), Arc::clone(&self.state.sessions));
        let server = self.state.conn.object_server();
        server
            .at(path.clone(), session_obj)
            .await
            .map_err(map_zbus_error)?;

        Ok((output, path))
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(Vec<String>, Vec<String>), FdoError> {
        log_caller("SearchItems", &header);
        self.state.touch_activity();
        // Per the Secret Service spec, SearchItems is a metadata-only operation
        // that MUST never error when backends are locked.  Items from locked
        // backends are returned in the `locked` list.  Read from the persistent
        // metadata_cache which survives lock/unlock cycles.
        self.state.search_metadata_cache(&attributes)
    }

    async fn get_secrets(
        &self,
        items: Vec<String>,
        session: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<HashMap<String, zvariant::Value<'static>>, FdoError> {
        log_caller("GetSecrets", &header);
        self.state.touch_activity();
        self.state.ensure_session(session)?;
        let aes_key = self
            .state
            .sessions
            .get_session_key(session)
            .map_err(map_backend_error)?;
        let resolved = self.state.resolve_items(None, Some(&items)).await?;
        let mut secrets = HashMap::new();
        for (path, item) in resolved {
            if item.locked {
                continue;
            }
            let backend = self
                .state
                .backend_by_id(&item.backend_id)
                .or_else(|| self.state.backends_ordered().into_iter().next())
                .ok_or_else(|| {
                    FdoError::Failed(format!(
                        "no backend for item backend_id '{}'",
                        item.backend_id
                    ))
                })?;
            let item_id = item.id.clone();
            let state = Arc::clone(&self.state);
            let secret_result = self
                .state
                .run_on_tokio(async move { state.resolve_primary_secret(backend, &item_id).await })
                .await?;
            // Skip items that have no primary secret (e.g. login without
            // password, empty secure note) rather than failing the entire
            // batch.  The Secret Service spec says GetSecrets returns a map --
            // omitting an item is valid.
            let secret = match secret_result {
                Ok(s) => s,
                Err(BackendError::Other(_)) => continue,
                Err(BackendError::NotFound) => continue,
                Err(BackendError::Locked) => continue,
                Err(e) => return Err(map_backend_error(e)),
            };
            let value = build_secret_value(session, &secret, aes_key.as_deref())?;
            secrets.insert(path, value);
        }
        Ok(secrets)
    }

    fn close_session(
        &self,
        session: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FdoError> {
        log_caller("CloseSession", &header);
        self.state
            .sessions
            .close_session(session)
            .map_err(map_backend_error)
    }

    fn read_alias(
        &self,
        name: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<String, FdoError> {
        log_caller("ReadAlias", &header);
        if name == "default" {
            Ok("/org/freedesktop/secrets/collection/default".to_string())
        } else {
            Ok("/".to_string())
        }
    }

    fn set_alias(
        &self,
        _name: &str,
        _collection: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FdoError> {
        log_caller("SetAlias", &header);
        Err(FdoError::NotSupported("read-only".to_string()))
    }

    async fn lock(
        &self,
        objects: Vec<String>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(Vec<String>, String), FdoError> {
        log_caller("Lock", &header);
        for backend in self.state.backends_ordered() {
            let bid = backend.id().to_string();
            self.state
                .run_on_tokio(async move { backend.lock().await })
                .await?
                .map_err(map_backend_error)?;
            self.state.mark_backend_locked_in_cache(&bid);
        }
        self.state.mark_locked();
        // Return the requested objects as "locked" and no prompt needed
        Ok((objects, "/".to_string()))
    }

    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), FdoError> {
        log_caller("Unlock", &header);

        // Iterate backends in order.  All backends require interactive unlock.
        // Return the first locked backend so the client allocates a Prompt and
        // calls Prompt.Prompt(); if all are unlocked, return "/" immediately.
        let state = Arc::clone(&self.state);
        let state2 = Arc::clone(&state);
        let prompt_path_opt: Option<String> = state
            .run_on_tokio(async move {
                let mut first_locked: Option<String> = None;
                for backend in state2.backends_ordered() {
                    let status = backend.status().await.map_err(map_backend_error)?;
                    if status.locked {
                        first_locked = Some(backend.id().to_string());
                        break;
                    }
                }
                Ok::<Option<String>, FdoError>(first_locked)
            })
            .await??;

        // Helper to build an OwnedObjectPath, falling back to "/" on parse error.
        // "/" is a well-known valid D-Bus object path; the second try_from cannot
        // fail, but we handle the unreachable error path explicitly to stay
        // consistent with the no-naked-unwrap policy.
        let make_path = |s: &str| {
            OwnedObjectPath::try_from(s.to_string()).unwrap_or_else(|_| {
                OwnedObjectPath::try_from("/".to_string())
                    .unwrap_or_else(|_| unreachable!("'/' is always a valid D-Bus object path"))
            })
        };

        match prompt_path_opt {
            None => {
                // All backends unlocked — no prompt needed.
                Ok((objects, make_path("/")))
            }
            Some(backend_id) => {
                // Allocate a unique prompt path and register the object.
                let prompt_path = self.state.allocate_prompt(&backend_id);
                let prompt_obj =
                    SecretPrompt::new(prompt_path.clone(), backend_id, Arc::clone(&self.state));
                self.state
                    .conn
                    .object_server()
                    .at(prompt_path.clone(), prompt_obj)
                    .await
                    .map_err(map_zbus_error)?;
                // Return empty unlocked list + the prompt path.
                Ok((vec![], make_path(&prompt_path)))
            }
        }
    }

    fn create_collection(
        &self,
        _properties: HashMap<String, zvariant::Value<'_>>,
        _alias: String,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(String, String), FdoError> {
        log_caller("CreateCollection", &header);
        Err(FdoError::NotSupported("read-only".to_string()))
    }
}

/// Build a Secret struct per the D-Bus Secret Service spec:
/// `(ObjectPath session, Array<Byte> parameters, Array<Byte> value, String content_type)`
///
/// When `aes_key` is `Some`, the secret is encrypted with AES-128-CBC-PKCS7 and
/// a random IV is placed in the `parameters` field.  For plain sessions
/// (`aes_key` is `None`), `parameters` is empty and `value` is plaintext.
///
/// # Security note
///
/// Even for encrypted sessions the plaintext briefly exists as a plain `Vec<u8>`
/// because `zvariant::Value` requires owned, non-zeroizing types.  This is an
/// inherent limitation of the zbus/zvariant API.  With DH session encryption the
/// plaintext is only visible inside this process for the duration of the call.
pub(crate) fn build_secret_value(
    session_path: &str,
    secret: &SecretBytes,
    aes_key: Option<&[u8; 16]>,
) -> Result<zvariant::Value<'static>, FdoError> {
    let session = zvariant::OwnedObjectPath::try_from(session_path.to_string())
        .map_err(|_| FdoError::Failed("invalid session path".to_string()))?;

    let (parameters, value) = if let Some(key) = aes_key {
        // DH-encrypted session: AES-128-CBC with random IV
        let (iv, ciphertext) =
            aes128_cbc_encrypt(key, secret.as_slice()).map_err(map_backend_error)?;
        (iv, ciphertext)
    } else {
        // Plain session: no parameters, raw plaintext value
        (Vec::new(), secret.as_slice().to_vec())
    };

    let secret_tuple: (zvariant::OwnedObjectPath, Vec<u8>, Vec<u8>, String) =
        (session, parameters, value, "text/plain".to_string());
    Ok(zvariant::Value::from(secret_tuple))
}
