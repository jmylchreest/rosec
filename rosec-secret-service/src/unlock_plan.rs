//! Resolve the requested virtual collection/item projection without parsing IDs
//! out of object paths. Provider locks remain global and provider-wide.
use crate::state::{ServiceState, map_provider_error};

pub(crate) struct UnlockPlan {
    pub unlocked: Vec<String>,
    pub pending: Vec<String>,
    pub next_provider: Option<String>,
}

pub(crate) async fn resolve(
    state: &ServiceState,
    paths: &[String],
) -> zbus::fdo::Result<UnlockPlan> {
    let mut targets = Vec::new();
    for path in paths {
        if targets.iter().any(|(known, _)| known == path) {
            continue;
        }
        if matches!(
            path.as_str(),
            "/org/freedesktop/secrets/collection/default"
                | "/org/freedesktop/secrets/aliases/default"
                | "/org/freedesktop/secrets/aliases/login"
        ) {
            targets.push((path.clone(), None));
        } else if let Ok((provider, _)) = state.provider_and_id_for_path(path) {
            targets.push((path.clone(), Some(provider.id().to_string())));
        }
        // Unknown objects are omitted, never reported as unlocked or used to
        // select an unrelated provider for a credential prompt.
    }
    let collection_requested = targets.iter().any(|(_, provider)| provider.is_none());
    let mut statuses = Vec::new();
    for provider in state.providers_ordered() {
        if collection_requested
            || targets
                .iter()
                .any(|(_, id)| id.as_deref() == Some(provider.id()))
        {
            statuses.push((
                provider.id().to_string(),
                provider.status().await.map_err(map_provider_error)?.locked,
            ));
        }
    }
    let collection_unlocked = statuses.iter().any(|(_, locked)| !locked);
    let mut plan = UnlockPlan {
        unlocked: Vec::new(),
        pending: Vec::new(),
        next_provider: None,
    };
    let mut collection_pending = false;
    for (path, provider) in targets {
        let unlocked = match &provider {
            Some(id) => statuses.iter().any(|(pid, locked)| pid == id && !locked),
            None => collection_unlocked,
        };
        if unlocked {
            plan.unlocked.push(path);
        } else {
            plan.pending.push(path);
            if let Some(id) = provider {
                if plan.next_provider.is_none() {
                    plan.next_provider = Some(id);
                }
            } else {
                collection_pending = true;
            }
        }
    }
    // A requested item already makes its provider relevant to the collection.
    // Only choose the first provider for a collection-only unlock.
    if plan.next_provider.is_none() && collection_pending {
        plan.next_provider = statuses
            .into_iter()
            .find(|(_, locked)| *locked)
            .map(|(id, _)| id);
    }
    Ok(plan)
}
