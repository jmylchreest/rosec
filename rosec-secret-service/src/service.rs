use std::collections::HashMap;
use std::sync::Arc;

use rosec_core::{ProviderError, SecretBytes};
use zbus::OwnedObjectPath;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::message::Header;

use crate::crypto::aes128_cbc_encrypt;
use crate::daemon::log_dbus_caller;

use crate::session_iface::SecretSession;
use crate::state::{ServiceState, map_provider_error, map_zbus_error};

/// The Secret Service spec `Secret` struct: `(oayays)` =
/// `(ObjectPath, Array<Byte>, Array<Byte>, String)`.
///
/// Fields: `(session, parameters, value, content_type)`.
pub(crate) type SecretStruct = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

/// Convert a string to an `OwnedObjectPath`, falling back to `"/"` on parse
/// error.  `"/"` is always a valid D-Bus object path so the fallback cannot
/// fail.
pub(crate) fn to_object_path(s: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(s.to_string()).unwrap_or_else(|_| {
        OwnedObjectPath::try_from("/".to_string())
            .unwrap_or_else(|_| unreachable!("'/' is always a valid D-Bus object path"))
    })
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
    fn collections(&self) -> Vec<OwnedObjectPath> {
        vec![to_object_path(
            "/org/freedesktop/secrets/collection/default",
        )]
    }

    async fn open_session(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        algorithm: &str,
        input: zbus::Variant<'_>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(zbus::Variant<'static>, OwnedObjectPath), FdoError> {
        log_dbus_caller("service", "OpenSession", &header);
        let owner = crate::session::SessionOwner::from_request(conn, &header)
            .map_err(|e| FdoError::Failed(e.to_string()))?;
        let (output, path) = self
            .state
            .sessions
            .open_session_for(algorithm, &input, owner.clone())
            .map_err(map_provider_error)?;

        // Register the org.freedesktop.Secret.Session object at the session path
        let session_obj = SecretSession::new(path.clone(), Arc::clone(&self.state.sessions));
        let server = conn.object_server();
        if let Err(error) = server.at(path.clone(), session_obj).await {
            let _ = self.state.sessions.close_session(&path);
            return Err(map_zbus_error(error));
        }
        // The watcher may have processed a disconnect before insertion or
        // registration. Check after registration, then let the watcher own
        // subsequent disconnects. Both cleanup paths are idempotent.
        let live = match zbus::fdo::DBusProxy::new(conn).await {
            Ok(proxy) => proxy
                .name_has_owner(
                    owner
                        .name
                        .as_str()
                        .try_into()
                        .map_err(|e: zbus::Error| FdoError::Failed(e.to_string()))?,
                )
                .await
                .unwrap_or(false),
            Err(_) => false,
        };
        if !live
            || !self
                .state
                .sessions
                .is_valid(&path)
                .map_err(map_provider_error)?
        {
            let _ = self.state.sessions.close_session(&path);
            let _ = server.remove::<SecretSession, _>(path.as_str()).await;
            return Err(FdoError::Failed("session owner disconnected".into()));
        }
        Ok((output, to_object_path(&path)))
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), FdoError> {
        log_dbus_caller("service", "SearchItems", &header);
        self.state.touch_activity();
        // Per the Secret Service spec, SearchItems is a metadata-only operation
        // that MUST never error when providers are locked.  Items from locked
        // providers are returned in the `locked` list.  Read from the persistent
        // metadata_cache which survives lock/unlock cycles.
        let (unlocked, locked) = self.state.search_items_partition(&attributes)?;
        Ok((
            unlocked.into_iter().map(|s| to_object_path(&s)).collect(),
            locked.into_iter().map(|s| to_object_path(&s)).collect(),
        ))
    }

    async fn get_secrets(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        items: Vec<OwnedObjectPath>,
        session: zbus::ObjectPath<'_>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<HashMap<OwnedObjectPath, SecretStruct>, zbus::BoxDBusError> {
        log_dbus_caller("service", "GetSecrets", &header);
        self.state.touch_activity();
        let owner = crate::session::SessionOwner::from_request(conn, &header)
            .map_err(|e| Box::new(e) as zbus::BoxDBusError)?;
        let session = session.as_str();
        let encoding = self
            .state
            .sessions
            .lookup_for(session, &owner)
            .map_err(|error| Box::new(error) as zbus::BoxDBusError)?;
        let item_paths: Vec<String> = items.iter().map(|p| p.as_str().to_string()).collect();
        let resolved = self.state.resolve_items(None, Some(&item_paths)).await?;
        let mut secrets = HashMap::new();
        for (path, item) in resolved {
            if item.locked {
                continue;
            }
            let provider = self
                .state
                .provider_by_id(&item.provider_id)
                .or_else(|| self.state.providers_ordered().into_iter().next())
                .ok_or_else(|| {
                    FdoError::Failed(format!(
                        "no provider for item provider_id '{}'",
                        item.provider_id
                    ))
                })?;
            let item_id = item.id.clone();
            let state = Arc::clone(&self.state);
            let secret_result = self
                .state
                .run_on_tokio(async move { state.resolve_primary_secret(provider, &item_id).await })
                .await?;
            // Skip items that have no primary secret (e.g. login without
            // password, empty secure note) rather than failing the entire
            // batch.  The Secret Service spec says GetSecrets returns a map --
            // omitting an item is valid.
            let secret = match secret_result {
                Ok(s) => s,
                Err(ProviderError::Other(_)) => continue,
                Err(ProviderError::NotFound) => continue,
                Err(ProviderError::Locked) => continue,
                Err(e) => return Err(map_provider_error(e).into()),
            };
            let value = build_secret_value(session, &secret, encoding.aes_key())?;
            secrets.insert(to_object_path(&path), value);
        }
        Ok(secrets)
    }

    async fn close_session(
        &self,
        session: zbus::ObjectPath<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), crate::error::SecretServiceError> {
        let owner = crate::session::SessionOwner::from_request(conn, &header)?;
        self.state.sessions.close_for(session.as_str(), &owner)?;
        let _ = conn
            .object_server()
            .remove::<SecretSession, _>(session.as_str())
            .await;
        Ok(())
    }

    fn read_alias(
        &self,
        name: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<OwnedObjectPath, FdoError> {
        log_dbus_caller("service", "ReadAlias", &header);
        // Map "login" to "default" for gnome-keyring compatibility.
        // Many applications (e.g. Chrome, NetworkManager) request the
        // "login" alias which gnome-keyring uses for its auto-unlock
        // keyring.
        if name == "default" || name == "login" {
            Ok(to_object_path(
                "/org/freedesktop/secrets/collection/default",
            ))
        } else {
            Ok(to_object_path("/"))
        }
    }

    fn set_alias(
        &self,
        _name: &str,
        _collection: zbus::ObjectPath<'_>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FdoError> {
        log_dbus_caller("service", "SetAlias", &header);
        // No-op: we always serve a single default collection and do not support
        // mutable aliases.  Returning NotSupported breaks clients (e.g. GNOME
        // apps) that call SetAlias as part of normal startup — silently succeed.
        Ok(())
    }

    async fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), FdoError> {
        log_dbus_caller("service", "Lock", &header);
        for provider in self.state.providers_ordered() {
            let pid = provider.id().to_string();
            self.state
                .run_on_tokio(async move { provider.lock().await })
                .await?
                .map_err(map_provider_error)?;
            self.state.mark_provider_locked_in_cache(&pid);
        }
        self.state.mark_locked();
        // Return the requested objects as "locked" and no prompt needed
        Ok((objects, to_object_path("/")))
    }

    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), FdoError> {
        log_dbus_caller("service", "Unlock", &header);

        let paths: Vec<String> = objects.iter().map(|path| path.to_string()).collect();
        let state = Arc::clone(&self.state);
        let plan = self
            .state
            .run_on_tokio(async move { crate::unlock_plan::resolve(&state, &paths).await })
            .await??;
        let unlocked = plan
            .unlocked
            .iter()
            .map(|path| to_object_path(path))
            .collect();
        let Some(provider_id) = plan.next_provider else {
            return Ok((unlocked, to_object_path("/")));
        };
        let owner = crate::session::SessionOwner::from_request(conn, &header)
            .map_err(|e| FdoError::AccessDenied(e.to_string()))?;
        let prompt_path = self
            .state
            .register_prompt(
                conn,
                owner,
                provider_id,
                crate::prompt::PendingOperation::UnlockTargets(plan.pending),
            )
            .await?;
        Ok((unlocked, to_object_path(&prompt_path)))
    }

    fn create_collection(
        &self,
        _properties: HashMap<String, zbus::Variant<'_>>,
        alias: String,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), FdoError> {
        log_dbus_caller("service", "CreateCollection", &header);
        // We don't support creating new collections, but returning NotSupported
        // breaks clients that call CreateCollection("", "default") at startup.
        // Return the existing default collection with no prompt needed, which
        // is spec-compliant behaviour for when the requested alias already exists.
        let collection = if alias == "default" || alias.is_empty() {
            to_object_path("/org/freedesktop/secrets/collection/default")
        } else {
            // For named aliases we don't support, return "/" + no prompt —
            // the client can inspect the returned "/" path to know it failed.
            to_object_path("/")
        };
        Ok((collection, to_object_path("/")))
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
/// because `zbus::Variant` requires owned, non-zeroizing types.  This is an
/// inherent limitation of the zbus/zvariant API.  With DH session encryption the
/// plaintext is only visible inside this process for the duration of the call.
pub(crate) fn build_secret_value(
    session_path: &str,
    secret: &SecretBytes,
    aes_key: Option<&[u8; 16]>,
) -> Result<SecretStruct, FdoError> {
    let session = OwnedObjectPath::try_from(session_path.to_string())
        .map_err(|_| FdoError::Failed("invalid session path".to_string()))?;

    let (parameters, value) = if let Some(key) = aes_key {
        // DH-encrypted session: AES-128-CBC with random IV
        let (iv, ciphertext) =
            aes128_cbc_encrypt(key, secret.as_slice()).map_err(map_provider_error)?;
        (iv, ciphertext)
    } else {
        // Plain session: no parameters, raw plaintext value
        (Vec::new(), secret.as_slice().to_vec())
    };

    Ok((session, parameters, value, "text/plain".to_string()))
}
