//! D-Bus projection of committed domain changes. Failed delivery retries from
//! a current snapshot; notifications are invalidations, not an audit log.
use crate::{
    collection::SecretCollection,
    service::to_object_path,
    state::{ServiceState, make_item_path},
};
use rosec_core::{
    ItemMeta,
    changes::{ChangesSince, ItemIdentity},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};
use zbus::object_server::SignalEmitter;
use zbus::{Connection, Variant};

const COLLECTIONS: [&str; 3] = [
    "/org/freedesktop/secrets/collection/default",
    "/org/freedesktop/secrets/aliases/default",
    "/org/freedesktop/secrets/aliases/login",
];

pub(crate) fn start(state: &Arc<ServiceState>) {
    let mut wake = state.subscribe_changes();
    let weak = Arc::downgrade(state);
    tokio::spawn(async move {
        let mut view = View::default();
        let mut retry = Duration::from_millis(100);
        loop {
            wake.borrow_and_update();
            let Some(state) = weak.upgrade() else {
                break;
            };
            let result = view.reconcile(&state).await;
            drop(state);
            if let Err(error) = result {
                tracing::warn!(%error, "change notification failed; retrying current snapshot");
                tokio::select! {
                    changed = wake.changed() => if changed.is_err() { break; },
                    _ = tokio::time::sleep(retry) => {},
                }
                retry = (retry * 2).min(Duration::from_secs(5));
            } else {
                retry = Duration::from_millis(100);
                if wake.changed().await.is_err() {
                    break;
                }
            }
        }
    });
}

#[derive(Default)]
struct View {
    revision: u64,
    bus: Option<(String, String)>,
    items: BTreeMap<ItemIdentity, ItemMeta>,
    collection_locked: Option<bool>,
}
impl View {
    async fn reconcile(&mut self, state: &Arc<ServiceState>) -> zbus::Result<()> {
        let (conn, revision, snapshot) = state.reconcile_item_objects().await?;
        let bus = (
            conn.server_guid().to_string(),
            conn.unique_name()
                .map(ToString::to_string)
                .unwrap_or_default(),
        );
        if self.bus.as_ref() != Some(&bus) {
            self.items.clear();
            self.collection_locked = None;
            self.revision = 0;
            self.bus = Some(bus);
        }
        let current: BTreeMap<_, _> = snapshot
            .into_iter()
            .map(|meta| (ItemIdentity::from(&meta), meta))
            .collect();
        let changes = state.changes_since(self.revision);
        let mut invalidated = BTreeSet::new();
        match changes {
            ChangesSince::Batches(batches) => {
                for batch in batches.into_iter().filter(|b| b.revision <= revision) {
                    invalidated.extend(batch.changed);
                }
            }
            ChangesSince::ResyncRequired { .. } => {
                invalidated.extend(current.keys().cloned());
            }
        }
        let added: Vec<_> = current
            .keys()
            .filter(|key| !self.items.contains_key(*key))
            .collect();
        let removed: Vec<_> = self
            .items
            .keys()
            .filter(|key| !current.contains_key(*key))
            .collect();
        let changed: Vec<_> = current
            .iter()
            .filter(|(key, meta)| {
                self.items
                    .get(*key)
                    .is_some_and(|old| old != *meta || invalidated.contains(*key))
            })
            .map(|(key, _)| key)
            .collect();
        for key in &changed {
            invalidate(
                &conn,
                &make_item_path(&key.provider_id, &key.item_id),
                "org.freedesktop.Secret.Item",
                &["Label", "Attributes", "Locked", "Created", "Modified"],
            )
            .await?;
        }
        let mut locked = true;
        for provider in state.providers_ordered() {
            if provider.status().await.is_ok_and(|status| !status.locked) {
                locked = false;
                break;
            }
        }
        for path in COLLECTIONS {
            let emitter = SignalEmitter::new(&conn, path)?;
            for key in &removed {
                SecretCollection::item_deleted(
                    &emitter,
                    to_object_path(&make_item_path(&key.provider_id, &key.item_id)),
                )
                .await?;
            }
            for key in &added {
                SecretCollection::item_created(
                    &emitter,
                    to_object_path(&make_item_path(&key.provider_id, &key.item_id)),
                )
                .await?;
            }
            for key in &changed {
                SecretCollection::item_changed(
                    &emitter,
                    to_object_path(&make_item_path(&key.provider_id, &key.item_id)),
                )
                .await?;
            }
            let mut properties = Vec::new();
            if !added.is_empty() || !removed.is_empty() {
                properties.push("Items");
            }
            if self.collection_locked.is_some_and(|old| old != locked) {
                properties.push("Locked");
            }
            if !properties.is_empty() {
                invalidate(
                    &conn,
                    path,
                    "org.freedesktop.Secret.Collection",
                    &properties,
                )
                .await?;
            }
        }
        self.items = current;
        self.revision = revision;
        self.collection_locked = Some(locked);
        Ok(())
    }
}
async fn invalidate(
    conn: &Connection,
    path: &str,
    interface: &str,
    properties: &[&str],
) -> zbus::Result<()> {
    conn.emit_signal(
        None::<&str>,
        path,
        "org.freedesktop.DBus.Properties",
        "PropertiesChanged",
        &(interface, HashMap::<&str, Variant<'_>>::new(), properties),
    )
    .await
}
